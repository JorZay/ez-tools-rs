//! Many event logs into one timeline: every chunk of every file is parsed in parallel, rows are sorted by time
//! (in memory, or in temporary files past a memory limit), and with merging, copies of the same log collapse into
//! one row per event.
//!
//! Merging works at three levels: files with the same bytes are read once; a chunk with the same bytes as one
//! already read is not parsed again (old and new copies of a log share most of their chunks); and rows for the
//! same event (same time, computer, channel, record number and rendered content) are written once, with every file
//! that held it in SourceFile. Where a row was (chunk number, offsets) is not part of what makes it the same event.

pub mod discover;
mod row;
mod sort;

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

pub use row::Row;
use sort::{RowCmp, Sorter};

use crate::chunk::ParseOptions;
use crate::error::Error;
use crate::file::{EvtxFile, FileHeader};
use crate::maps::MapSet;
use crate::time::{TICKS_PER_SECOND, Timestamp};
use crate::{Diagnostic, Level};

/// The order rows are written in
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// As read: file by file, records in file order (as EvtxECmd writes them). Rows are written as they are parsed.
    File,
    /// By TimeCreated, then as read
    Time,
}

/// Which events are written. EvtxECmd's --inc, --exc, --sd and --ed.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    /// Only these event ids (overrides `exclude`)
    pub include: HashSet<i32>,
    pub exclude: HashSet<i32>,
    /// Events older than this are dropped
    pub start: Option<Timestamp>,
    /// Events newer than this are dropped
    pub end: Option<Timestamp>,
}

impl Filter {
    pub fn keep_event_id(&self, id: i32) -> bool {
        if !self.include.is_empty() {
            self.include.contains(&id)
        } else {
            !self.exclude.contains(&id)
        }
    }

    pub fn keep(&self, id: i32, time: Timestamp) -> bool {
        self.keep_event_id(id) && self.start.is_none_or(|s| time >= s) && self.end.is_none_or(|e| time <= e)
    }
}

pub struct Options<'a> {
    pub maps: Option<&'a MapSet>,
    pub order: Order,
    /// Collapse copies of the same log into one row per event (needs [`Order::Time`])
    pub merge: bool,
    /// Read files with the same bytes once (EvtxECmd's --dedupe)
    pub skip_identical_files: bool,
    /// Keep each event's full JSON (EvtxECmd's --fj)
    pub full_json: bool,
    pub filter: Filter,
    /// Rows kept in memory before they are sorted into a temporary file
    pub memory_limit: usize,
    /// Where temporary files go (the system's temporary folder when None)
    pub temp_dir: Option<PathBuf>,
    /// Seconds a record's time may go back from the one before it without a warning (EvtxECmd's --tdt)
    pub time_discrepancy_threshold: i64,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            maps: None,
            order: Order::Time,
            merge: false,
            skip_identical_files: true,
            full_json: false,
            filter: Filter::default(),
            memory_limit: 256 << 20,
            temp_dir: None,
            time_discrepancy_threshold: 1,
        }
    }
}

/// Why a file was not read
#[derive(Debug)]
pub enum SkipReason {
    /// Same bytes as a file read already
    IdenticalTo(PathBuf),
    /// Not an event log (the message says why)
    NotEventLog(String),
    /// Could not be opened or read
    Unreadable(io::Error),
}

/// What was found in a file
#[derive(Debug, Clone)]
pub struct FileStats {
    pub header: FileHeader,
    /// 64 KB blocks after the header block
    pub blocks: usize,
    /// Chunks parsed
    pub chunks_parsed: usize,
    /// Chunks with the same bytes as one read already (merging), not parsed again
    pub chunks_duplicate: usize,
    /// Records in the chunks parsed
    pub records: usize,
    /// Records the filter dropped
    pub dropped: usize,
    /// Records that could not be read: record number and message
    pub errors: Vec<(i64, String)>,
    /// The earliest and latest record header times
    pub earliest: Option<Timestamp>,
    pub latest: Option<Timestamp>,
    /// Records per event id (dropped ones included)
    pub event_ids: BTreeMap<i32, usize>,
}

/// Progress and messages while a timeline is built
pub trait Observer {
    fn file_started(&mut self, _path: &Path, _header: &FileHeader, _blocks: usize) {}
    fn file_skipped(&mut self, _path: &Path, _reason: &SkipReason) {}
    fn diagnostic(&mut self, _path: &Path, _diagnostic: &Diagnostic) {}
    fn file_finished(&mut self, _path: &Path, _stats: &FileStats) {}
    /// All files are read; `rows` are being sorted (`temp_files` of them were written)
    fn sorting(&mut self, _rows: u64, _temp_files: usize) {}
}

/// An observer that ignores everything
pub struct Quiet;

impl Observer for Quiet {}

/// Where rows go. `sources` are the files the event was in (one, unless merged).
pub trait RowSink {
    fn write_row(&mut self, row: &Row, sources: &[&Path]) -> io::Result<()>;
}

impl<F: FnMut(&Row, &[&Path]) -> io::Result<()>> RowSink for F {
    fn write_row(&mut self, row: &Row, sources: &[&Path]) -> io::Result<()> {
        self(row, sources)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub files: usize,
    pub files_processed: usize,
    pub files_identical: usize,
    pub files_not_event_logs: usize,
    pub files_unreadable: usize,
    pub records: u64,
    pub record_errors: u64,
    pub rows_written: u64,
    pub rows_dropped: u64,
    pub chunks_duplicate: u64,
    /// Rows collapsed into another row for the same event
    pub events_merged: u64,
    /// Rows collapsed, by computer and channel
    pub merged_by_log: BTreeMap<(String, String), u64>,
    pub temp_files: usize,
}

enum Outcome {
    NoSignature,
    /// Merging: the same bytes as a chunk read already
    Duplicate(u128),
    Failed(String),
    Parsed(Box<Parsed>),
}

struct Parsed {
    hash: u128,
    records: usize,
    dropped: usize,
    event_ids: Vec<i32>,
    earliest: Option<Timestamp>,
    latest: Option<Timestamp>,
    /// Record number and TimeCreated of each record, for the time-went-backwards check
    times: Vec<(i64, Timestamp)>,
    rows: Vec<Row>,
    errors: Vec<(i64, String)>,
    diagnostics: Vec<Diagnostic>,
}

fn by_time(a: &Row, b: &Row) -> Ordering {
    a.time_created.cmp(&b.time_created).then(a.seq.cmp(&b.seq))
}

/// Copies of the same event sort next to each other
fn by_event(a: &Row, b: &Row) -> Ordering {
    a.time_created
        .cmp(&b.time_created)
        .then_with(|| a.computer.cmp(&b.computer))
        .then_with(|| a.channel.cmp(&b.channel))
        .then(a.record_number.cmp(&b.record_number))
        .then(a.content_hash.cmp(&b.content_hash))
        .then(a.seq.cmp(&b.seq))
}

fn parse_block(file: &EvtxFile, block: usize, options: &Options, seen: &HashMap<u128, u32>) -> Outcome {
    let data = file.block(block);
    if !data.has_signature() {
        return Outcome::NoSignature;
    }
    let hash = if options.merge { xxhash_rust::xxh3::xxh3_128(&data.bytes) } else { 0 };
    if options.merge && seen.contains_key(&hash) {
        return Outcome::Duplicate(hash);
    }
    let chunk = match data.parse(ParseOptions { maps: options.maps }) {
        Ok(c) => c,
        Err(e) => return Outcome::Failed(e.message),
    };
    let mut p = Parsed {
        hash,
        records: chunk.records.len(),
        dropped: 0,
        event_ids: Vec::with_capacity(chunk.records.len()),
        earliest: None,
        latest: None,
        times: Vec::with_capacity(chunk.records.len()),
        rows: Vec::with_capacity(chunk.records.len()),
        errors: chunk.errors,
        diagnostics: chunk.diagnostics,
    };
    for r in &chunk.records {
        p.event_ids.push(r.event_id);
        p.earliest = Some(p.earliest.map_or(r.timestamp, |e| e.min(r.timestamp)));
        p.latest = Some(p.latest.map_or(r.timestamp, |l| l.max(r.timestamp)));
        p.times.push((r.record_number, r.time_created));
        if !options.filter.keep(r.event_id, r.time_created) {
            p.dropped += 1;
            continue;
        }
        let mut row = Row::from_record(r, options.full_json);
        if options.merge {
            row.content_hash = r.content_hash();
        }
        p.rows.push(row);
    }
    Outcome::Parsed(Box::new(p))
}

struct Current {
    index: usize,
    stats: FileStats,
    last_seen: i64,
}

/// Builds a timeline from event log files (see [`discover::find_event_logs`]) and writes its rows to `sink`.
/// Damaged files and records are reported to `observer` and skipped; the error is for a row that could not be
/// written (or a temporary file).
pub fn run(files: &[PathBuf], options: &Options, observer: &mut dyn Observer, sink: &mut dyn RowSink) -> io::Result<Summary> {
    use rayon::prelude::*;

    let merge = options.merge && options.order == Order::Time;
    let mut summary = Summary { files: files.len(), ..Default::default() };

    // file index -> later files with the same bytes
    let mut copies: HashMap<u32, Vec<u32>> = HashMap::new();
    let identical =
        if options.skip_identical_files { discover::identical_files(files) } else { vec![None; files.len()] };
    // a file is unmapped once all its chunks are read (None)
    let mut opened: Vec<(usize, Option<EvtxFile>)> = Vec::new();
    for (i, path) in files.iter().enumerate() {
        if let Some(j) = identical[i] {
            copies.entry(j as u32).or_default().push(i as u32);
            observer.file_skipped(path, &SkipReason::IdenticalTo(files[j].clone()));
            summary.files_identical += 1;
            continue;
        }
        match EvtxFile::open(path) {
            Ok(f) => opened.push((i, Some(f))),
            Err(Error::Parse(e)) => {
                observer.file_skipped(path, &SkipReason::NotEventLog(e.message));
                summary.files_not_event_logs += 1;
            }
            Err(Error::Io(e)) => {
                observer.file_skipped(path, &SkipReason::Unreadable(e));
                summary.files_unreadable += 1;
            }
        }
    }

    let work: Vec<(usize, usize)> =
        opened.iter().enumerate().flat_map(|(o, (_, f))| (0..f.as_ref().unwrap().block_count()).map(move |b| (o, b))).collect();
    let window = (rayon::current_num_threads() * 4).max(16);

    // the files that held each chunk read
    let mut chunk_files: Vec<Vec<u32>> = Vec::new();
    let mut seen: HashMap<u128, u32> = HashMap::new();
    let mut sorter = (options.order == Order::Time)
        .then(|| Sorter::new(if merge { by_event as RowCmp } else { by_time as RowCmp }, options.memory_limit, options.temp_dir.clone()));
    let mut seq: u64 = 0;
    let mut current: Option<Current> = None;
    let threshold = TICKS_PER_SECOND * options.time_discrepancy_threshold;

    let finish_file = |current: &mut Option<Current>, observer: &mut dyn Observer, summary: &mut Summary| {
        if let Some(c) = current.take() {
            summary.files_processed += 1;
            summary.record_errors += c.stats.errors.len() as u64;
            observer.file_finished(&files[c.index], &c.stats);
        }
    };
    // files without blocks are still reported
    let mut next_open = 0;

    let mut released = 0;
    for batch in work.chunks(window) {
        let outcomes: Vec<Outcome> =
            batch.par_iter().map(|&(o, b)| parse_block(opened[o].1.as_ref().unwrap(), b, options, &seen)).collect();

        for (&(o, b), outcome) in batch.iter().zip(outcomes) {
            let (index, file) = (&opened[o].0, opened[o].1.as_ref().unwrap());
            let path = &files[*index];
            if current.as_ref().is_none_or(|c| c.index != *index) {
                finish_file(&mut current, observer, &mut summary);
                while next_open < o {
                    // files before this one with no blocks
                    let (i, f) = (&opened[next_open].0, opened[next_open].1.as_ref().unwrap());
                    observer.file_started(&files[*i], f.header(), 0);
                    observer.file_finished(&files[*i], &empty_stats(f));
                    summary.files_processed += 1;
                    next_open += 1;
                }
                next_open = o + 1;
                observer.file_started(path, file.header(), file.block_count());
                current = Some(Current { index: *index, stats: empty_stats(file), last_seen: 0 });
            }
            let c = current.as_mut().unwrap();
            let offset = file.block(b).offset;

            let p = match outcome {
                Outcome::NoSignature => {
                    let d = Diagnostic {
                        level: Level::Trace,
                        message: format!("Skipping chunk at 0x{offset:X} as it does not have correct signature"),
                    };
                    observer.diagnostic(path, &d);
                    continue;
                }
                Outcome::Failed(m) => {
                    let d = Diagnostic { level: Level::Error, message: format!("Chunk at 0x{offset:X} could not be read: {m}") };
                    observer.diagnostic(path, &d);
                    continue;
                }
                Outcome::Duplicate(hash) => {
                    add_file(&mut chunk_files[seen[&hash] as usize], *index as u32);
                    c.stats.chunks_duplicate += 1;
                    summary.chunks_duplicate += 1;
                    continue;
                }
                Outcome::Parsed(p) => p,
            };
            if merge {
                // the same chunk earlier in this batch
                if let Some(&uid) = seen.get(&p.hash) {
                    add_file(&mut chunk_files[uid as usize], *index as u32);
                    c.stats.chunks_duplicate += 1;
                    summary.chunks_duplicate += 1;
                    continue;
                }
                seen.insert(p.hash, chunk_files.len() as u32);
            }
            let uid = chunk_files.len() as u32;
            chunk_files.push(vec![*index as u32]);

            let s = &mut c.stats;
            s.chunks_parsed += 1;
            s.records += p.records;
            s.dropped += p.dropped;
            summary.records += p.records as u64;
            summary.rows_dropped += p.dropped as u64;
            for id in &p.event_ids {
                *s.event_ids.entry(*id).or_default() += 1;
            }
            if let Some(e) = p.earliest {
                s.earliest = Some(s.earliest.map_or(e, |x| x.min(e)));
            }
            if let Some(l) = p.latest {
                s.latest = Some(s.latest.map_or(l, |x| x.max(l)));
            }
            for (n, m) in p.errors {
                match s.errors.iter_mut().find(|(k, _)| *k == n) {
                    Some(e) => e.1 = m,
                    None => s.errors.push((n, m)),
                }
            }
            for d in &p.diagnostics {
                observer.diagnostic(path, d);
            }
            for (record_number, tc) in &p.times {
                if c.last_seen > 0 && c.last_seen - threshold > tc.0 {
                    let d = Diagnostic {
                        level: Level::Warning,
                        message: format!(
                            "Record #: {record_number} (timestamp: {tc}): Warning! Time just went backwards! Last seen time before change: {}",
                            Timestamp(c.last_seen)
                        ),
                    };
                    observer.diagnostic(path, &d);
                }
                c.last_seen = tc.0;
            }

            for mut row in p.rows {
                row.chunk = uid;
                row.seq = seq;
                seq += 1;
                match &mut sorter {
                    Some(s) => s.push(row)?,
                    None => {
                        sink.write_row(&row, &[path.as_path()])?;
                        summary.rows_written += 1;
                    }
                }
            }
        }
        // the files before the current one are done: unmap them
        let done = next_open.saturating_sub(1);
        for f in &mut opened[released.min(done)..done] {
            f.1 = None;
        }
        released = released.max(done);
    }
    finish_file(&mut current, observer, &mut summary);
    for (i, f) in &opened[next_open.min(opened.len())..] {
        let f = f.as_ref().unwrap();
        observer.file_started(&files[*i], f.header(), 0);
        observer.file_finished(&files[*i], &empty_stats(f));
        summary.files_processed += 1;
    }

    let Some(sorter) = sorter else {
        return Ok(summary);
    };
    summary.temp_files = sorter.run_count();
    observer.sorting(seq, sorter.run_count());
    let sorted = sorter.finish()?;

    let mut write = |row: Row, chunks: &[u32], summary: &mut Summary| -> io::Result<()> {
        let mut ids: Vec<u32> = chunks.iter().flat_map(|c| chunk_files[*c as usize].iter().copied()).collect();
        if merge {
            // files skipped as byte-for-byte copies held the event too
            let n = ids.len();
            for k in 0..n {
                ids.extend(copies.get(&ids[k]).into_iter().flatten().copied());
            }
        }
        ids.sort_unstable();
        ids.dedup();
        let sources: Vec<&Path> = ids.iter().map(|&i| files[i as usize].as_path()).collect();
        sink.write_row(&row, &sources)?;
        summary.rows_written += 1;
        Ok(())
    };

    let mut pending: Option<(Row, Vec<u32>)> = None;
    for row in sorted {
        let row = row?;
        if merge {
            if let Some((p, chunks)) = &mut pending {
                if p.same_event(&row) {
                    p.hidden_record |= row.hidden_record;
                    if !chunks.contains(&row.chunk) {
                        chunks.push(row.chunk);
                    }
                    summary.events_merged += 1;
                    let key = (row.computer.clone().unwrap_or_default(), row.channel.clone().unwrap_or_default());
                    *summary.merged_by_log.entry(key).or_default() += 1;
                    continue;
                }
            }
            if let Some((p, chunks)) = pending.take() {
                write(p, &chunks, &mut summary)?;
            }
            let chunk = row.chunk;
            pending = Some((row, vec![chunk]));
        } else {
            let chunk = row.chunk;
            write(row, &[chunk], &mut summary)?;
        }
    }
    if let Some((p, chunks)) = pending.take() {
        write(p, &chunks, &mut summary)?;
    }
    Ok(summary)
}

fn add_file(files: &mut Vec<u32>, index: u32) {
    if !files.contains(&index) {
        files.push(index);
    }
}

fn empty_stats(f: &EvtxFile) -> FileStats {
    FileStats {
        header: f.header().clone(),
        blocks: f.block_count(),
        chunks_parsed: 0,
        chunks_duplicate: 0,
        records: 0,
        dropped: 0,
        errors: Vec::new(),
        earliest: None,
        latest: None,
        event_ids: BTreeMap::new(),
    }
}
