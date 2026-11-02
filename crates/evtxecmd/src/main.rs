//! evtxecmd: event logs from forensic extractions into one CSV or JSON timeline, as EvtxECmd writes them.

mod log;
mod output;
#[cfg(feature = "sync")]
mod sync;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;
use evtx_ez::timeline::{self, FileStats, Filter, Observer, Order, SkipReason, discover};
use evtx_ez::{Diagnostic, FileHeader, Level, MapSet, Timestamp};

use log::Logger;

include!(concat!(env!("OUT_DIR"), "/maps.rs"));

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parses Windows event logs (EVTX) from forensic extractions into one CSV or JSON timeline, with EvtxECmd's
/// columns, formats and maps.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  evtxecmd -d /cases/host1/Logs --csv out/\n  evtxecmd -f Security.evtx -f old/Security.evtx --merge --csv timeline.csv\n  evtxecmd -d extraction1 -d extraction2 --merge --json out/ --inc 4624,4625,4688"
)]
struct Args {
    /// An event log to process (repeat for more)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    files: Vec<PathBuf>,

    /// A folder to search recursively for *.evtx (repeat for more)
    #[arg(short = 'd', long = "dir", value_name = "DIR")]
    dirs: Vec<PathBuf>,

    /// CSV output: a file, or a folder for <timestamp>_EvtxECmd_Output.csv, or - for standard output
    #[arg(long, value_name = "PATH")]
    csv: Option<PathBuf>,

    /// JSON lines output: a file, or a folder for <timestamp>_EvtxECmd_Output.json, or - for standard output
    #[arg(long, value_name = "PATH")]
    json: Option<PathBuf>,

    /// Write each event's full XML as JSON instead of the record's fields (EvtxECmd's --fj)
    #[arg(long)]
    fj: bool,

    /// Merge copies of the same logs: chunks and events found in more than one file are written once, with every
    /// file that held them in SourceFile
    #[arg(long)]
    merge: bool,

    /// Write rows as they are read (file by file, in file order) instead of sorted by time. Fastest; no merging
    #[arg(long, conflicts_with = "merge")]
    unsorted: bool,

    /// Read files even when they have the same bytes as one read already
    #[arg(long)]
    keep_identical: bool,

    /// A folder of *.map files to use instead of the built-in maps
    #[arg(long, value_name = "DIR")]
    maps: Option<PathBuf>,

    /// Do not use maps (the mapped columns stay empty)
    #[arg(long, conflicts_with = "maps")]
    no_maps: bool,

    /// .NET date and time format for TimeCreated and messages
    #[arg(long, value_name = "FORMAT", default_value = "yyyy-MM-dd HH:mm:ss.fffffff")]
    dt: String,

    /// Event ids to include; all others are dropped. Overrides --exc. Format: 4624,4625,5410,5500-5600
    #[arg(long, value_name = "IDS")]
    inc: Option<String>,

    /// Event ids to drop. Format: 4624,4625,5410,5500-5600
    #[arg(long, value_name = "IDS")]
    exc: Option<String>,

    /// Drop events older than this (UTC unless an offset is given), e.g. 2024-01-31 or "2024-01-31 13:45:00"
    #[arg(long, value_name = "DATE")]
    sd: Option<String>,

    /// Drop events newer than this (UTC unless an offset is given)
    #[arg(long, value_name = "DATE")]
    ed: Option<String>,

    /// Seconds a record's time may go back from the one before it without a warning
    #[arg(long, value_name = "SECONDS", default_value_t = 1)]
    tdt: i64,

    /// Do not show event id counts per file
    #[arg(long)]
    no_metrics: bool,

    /// Memory for sorting, in MB; past it, sorted rows go to temporary files
    #[arg(long, value_name = "MB", default_value_t = 256)]
    mem: usize,

    /// Folder for temporary files (default: the system's)
    #[arg(long, value_name = "DIR")]
    temp: Option<PathBuf>,

    /// Threads to parse with (default: one per CPU)
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Do not save console messages to <timestamp>_EvtxECmd_<version>_ConsoleLog.txt next to the output
    #[arg(long)]
    no_log: bool,

    /// Only show warnings, errors and the summary
    #[arg(short, long)]
    quiet: bool,

    /// Show debug messages (map values not found are listed)
    #[arg(long)]
    debug: bool,

    /// Show trace messages
    #[arg(long)]
    trace: bool,

    /// Download the latest maps from github.com/EricZimmerman/evtx into this folder, then exit
    #[cfg(feature = "sync")]
    #[arg(long, value_name = "DIR")]
    sync: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("Error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// "4624,4625,5500-5600"
fn event_ids(s: &str) -> Result<HashSet<i32>, String> {
    let mut ids = HashSet::new();
    for seg in s.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = seg.split_once('-') {
            let a: i32 = a.trim().parse().map_err(|_| format!("{a} is not an integer"))?;
            let b: i32 = b.trim().parse().map_err(|_| format!("{b} is not an integer"))?;
            ids.extend(a..=b);
        } else if let Ok(id) = seg.parse() {
            ids.insert(id);
        }
    }
    Ok(ids)
}

fn run(args: Args) -> Result<ExitCode, String> {
    let start = Instant::now();
    let now = output::utc_now();

    #[cfg(feature = "sync")]
    if let Some(dir) = &args.sync {
        let mut log = Logger::new(Level::Info, &args.dt);
        sync::sync_maps(dir, &mut log).map_err(|e| format!("There was an error checking for updates: {e}"))?;
        return Ok(ExitCode::SUCCESS);
    }

    if args.files.is_empty() && args.dirs.is_empty() {
        return Err("-f or -d is required (see --help)".into());
    }
    if args.csv.is_none() && args.json.is_none() {
        return Err("--csv or --json is required (see --help)".into());
    }
    if args.csv.as_deref() == Some(Path::new("-")) && args.json.as_deref() == Some(Path::new("-")) {
        return Err("only one of --csv and --json can be standard output".into());
    }
    if let Some(n) = args.threads {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().map_err(|e| e.to_string())?;
    }

    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else if args.quiet {
        Level::Warning
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &args.dt);

    let csv_path = args.csv.as_deref().map(|p| output::resolve(p, now, "csv"));
    let json_path = args.json.as_deref().map(|p| output::resolve(p, now, "json"));
    if !args.no_log {
        let dir = [&csv_path, &json_path].into_iter().flatten().find(|p| p.as_os_str() != "-").and_then(|p| p.parent().map(Path::to_path_buf));
        if let Some(dir) = dir {
            let dir = if dir.as_os_str().is_empty() { PathBuf::from(".") } else { dir };
            let path = dir.join(format!("{}_EvtxECmd_{VERSION}_ConsoleLog.txt", now.format("yyyyMMddHHmmss")));
            std::fs::create_dir_all(&dir).map_err(|e| format!("Unable to create directory {}: {e}", dir.display()))?;
            log.open_file(&path).map_err(|e| format!("Unable to open {}: {e}", path.display()))?;
        }
    }

    log.info(&format!(
        "evtxecmd version {VERSION} (a Rust port of EvtxECmd)\n\nEvtxECmd: Eric Zimmerman (saericzimmerman@gmail.com)\nhttps://github.com/EricZimmerman/evtx\n"
    ));
    log.info(&format!("Command line: {}\n", std::env::args().skip(1).collect::<Vec<_>>().join(" ")));
    if let Some(p) = log.file_path() {
        log.info(&format!("Console log: {}\n", p.display()));
    }

    // filters
    let mut filter = Filter::default();
    if let Some(exc) = &args.exc {
        filter.exclude = event_ids(exc)?;
    }
    if let Some(inc) = &args.inc {
        filter.exclude.clear();
        filter.include = event_ids(inc)?;
    }
    for (arg, value, slot, name) in
        [("--sd", &args.sd, &mut filter.start, "Start"), ("--ed", &args.ed, &mut filter.end, "End")]
    {
        if let Some(s) = value {
            match Timestamp::parse(s) {
                Some(t) => {
                    *slot = Some(t);
                    log.info(&format!("Setting {name} date to {}", t.format(&args.dt)));
                }
                None => {
                    log.warning(&format!("Could not parse {arg} {s} to a valid datetime! Events will not be filtered by {name} date!"))
                }
            }
        }
    }

    // maps
    let maps = if args.no_maps {
        None
    } else {
        let (set, report) = match &args.maps {
            Some(dir) => {
                log.debug(&format!("Loading maps from {}", dir.display()));
                MapSet::load_dir(dir).map_err(|e| format!("Unable to read maps from {}: {e}", dir.display()))?
            }
            None => MapSet::from_sources(EMBEDDED_MAPS.iter().copied()),
        };
        for w in &report.warnings {
            log.warning(w);
        }
        if report.has_errors() {
            for (file, errors) in &report.errors {
                log.error(&format!("{file} had errors"));
                for e in errors {
                    log.error(&format!("  {e}"));
                }
            }
            return Err("The maps above had errors. Correct them and try again".into());
        }
        log.info(&format!("Maps loaded: {}", output::n0(set.len() as u64)));
        Some(set)
    };

    // inputs
    let found = discover::find_event_logs(&args.files, &args.dirs);
    let mut failed = false;
    for (path, e) in &found.errors {
        log.error(&format!("Unable to read {}: {e}", path.display()));
        failed = true;
    }
    log.info(&format!("\nFound {} event log file(s)", output::n0(found.files.len() as u64)));

    let mut sink = output::Writer::create(csv_path.as_deref(), json_path.as_deref(), &args.dt, args.fj)?;
    if let Some(p) = &csv_path {
        log.info(&format!("CSV output will be saved to {}", p.display()));
    }
    if let Some(p) = &json_path {
        log.info(&format!("JSON output will be saved to {}", p.display()));
    }

    let options = timeline::Options {
        maps: maps.as_ref(),
        order: if args.unsorted { Order::File } else { Order::Time },
        merge: args.merge,
        skip_identical_files: !args.keep_identical,
        full_json: args.fj,
        filter: filter.clone(),
        memory_limit: args.mem.max(16) << 20,
        temp_dir: args.temp.clone(),
        time_discrepancy_threshold: args.tdt,
    };
    let mut observer = ConsoleObserver { log: &mut log, filter: &filter, metrics: !args.no_metrics, map_warnings: 0, failed: false };
    let result = timeline::run(&found.files, &options, &mut observer, &mut sink);
    let map_warnings = observer.map_warnings;
    failed |= observer.failed;

    let summary = match result.and_then(|s| sink.finish().map(|_| s)) {
        Ok(s) => s,
        // the reader of standard output stopped (e.g. | head)
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(ExitCode::SUCCESS),
        Err(e) => {
            log.error(&format!("Unable to write the output: {e}"));
            return Ok(ExitCode::FAILURE);
        }
    };

    log.info("");
    if map_warnings > 0 {
        log.info(&format!("Map values not found (replaced with empty strings): {} (--debug lists them)", output::n0(map_warnings)));
    }
    if summary.files_identical > 0 {
        log.info(&format!("Files skipped as identical to another file: {}", output::n0(summary.files_identical as u64)));
    }
    if summary.files_not_event_logs > 0 {
        log.info(&format!("Files that are not event logs: {}", output::n0(summary.files_not_event_logs as u64)));
    }
    if args.merge {
        log.info(&format!(
            "Merged: {} chunks were already read in another file; {} duplicate events were removed",
            output::n0(summary.chunks_duplicate),
            output::n0(summary.events_merged)
        ));
        for ((computer, channel), n) in &summary.merged_by_log {
            log.info(&format!("  {computer} / {channel}: {}", output::n0(*n)));
        }
    }
    if summary.temp_files > 0 {
        log.debug(&format!("Sorted with {} temporary files", summary.temp_files));
    }
    log.info(&format!(
        "Processed {} {} in {:.4} seconds: {} records, {} rows written, {} dropped, {} errors",
        output::n0(summary.files_processed as u64),
        if summary.files_processed == 1 { "file" } else { "files" },
        start.elapsed().as_secs_f64(),
        output::n0(summary.records),
        output::n0(summary.rows_written),
        output::n0(summary.rows_dropped),
        output::n0(summary.record_errors)
    ));

    Ok(if failed || summary.files_unreadable > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

struct ConsoleObserver<'a> {
    log: &'a mut Logger,
    filter: &'a Filter,
    metrics: bool,
    map_warnings: u64,
    failed: bool,
}

impl Observer for ConsoleObserver<'_> {
    fn file_started(&mut self, path: &Path, header: &FileHeader, _blocks: usize) {
        self.log.info(&format!("\nProcessing {}...", path.display()));
        self.log.info(&format!("Chunk count: {}, Iterating records...", output::n0(header.chunk_count as u64)));
    }

    fn file_skipped(&mut self, path: &Path, reason: &SkipReason) {
        match reason {
            SkipReason::IdenticalTo(other) => {
                self.log.info(&format!("\nSkipping {} as it has the same bytes as {}", path.display(), other.display()))
            }
            SkipReason::NotEventLog(m) => {
                self.log.info(&format!("\n{} is not an evtx file! Message: {m} Skipping...", path.display()))
            }
            SkipReason::Unreadable(e) => {
                self.log.error(&format!("\n{} could not be read: {e}. Skipping", path.display()));
                self.failed = true;
            }
        }
    }

    fn diagnostic(&mut self, _path: &Path, d: &Diagnostic) {
        if d.level == Level::Warning && d.message.contains(" not found! Replacing with empty string") {
            self.map_warnings += 1;
            self.log.log(Level::Debug, &d.message);
            return;
        }
        self.log.log(d.level, &d.message);
    }

    fn file_finished(&mut self, _path: &Path, s: &FileStats) {
        let fmt_time = |t: Option<Timestamp>| t.map(|t| t.to_string()).unwrap_or_default();
        let included = s.records - s.dropped;
        let mut text = format!(
            "\nEvent log details\nFlags: {}\nChunk count: {}\nStored/Calculated CRC: {:X}/{:X}\nEarliest timestamp: {}\nLatest timestamp:   {}\nTotal event log records found: {}\n",
            s.header.flags_text(),
            s.header.chunk_count,
            s.header.crc,
            s.header.calculated_crc,
            fmt_time(s.earliest),
            fmt_time(s.latest),
            output::n0(s.records as u64)
        );
        if s.chunks_duplicate > 0 {
            text.push_str(&format!(
                "Chunks already read in another file (not parsed again): {}\n",
                output::n0(s.chunks_duplicate as u64)
            ));
        }
        text.push_str(&format!(
            "\nRecords included: {} Errors: {} Events dropped: {}",
            output::n0(included as u64),
            output::n0(s.errors.len() as u64),
            output::n0(s.dropped as u64)
        ));
        self.log.info(&text);
        if !s.errors.is_empty() {
            self.log.info("\nErrors");
            for (n, m) in &s.errors {
                self.log.info(&format!("Record #{n}: Error: {m}"));
            }
        }
        if self.metrics && !s.event_ids.is_empty() {
            let mut text = String::from("\nMetrics (including dropped events)\nEvent ID\tCount");
            for (id, n) in &s.event_ids {
                if self.filter.keep_event_id(*id) {
                    text.push_str(&format!("\n{id}\t\t{}", output::n0(*n as u64)));
                }
            }
            self.log.info(&text);
        }
    }

    fn sorting(&mut self, rows: u64, temp_files: usize) {
        if temp_files > 0 {
            self.log.info(&format!("\nSorting {} rows ({temp_files} temporary files)...", output::n0(rows)));
        }
    }
}
