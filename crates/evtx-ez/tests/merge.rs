//! Merging copies of the same log: an older copy (fewer chunks, its last one only partly written), a byte-for-byte
//! copy, and a copy whose chunks are in another order (a log that wrapped around).

use std::io::Read;
use std::path::{Path, PathBuf};

use evtx_ez::timeline::{self, Options, Order, Quiet, Row};

const HEADER: usize = 0x1000;
const CHUNK: usize = 0x10000;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rust-evtx").join(format!("{name}.gz"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap()).read_to_end(&mut out).unwrap();
    out
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// The log as it was earlier: the first `chunks` chunks, the last of them cut after `keep` records (as Windows had
/// written it then: its header says so, and the rest of the chunk is empty)
fn older_copy(log: &[u8], chunks: usize, keep: usize) -> Vec<u8> {
    let mut b = log[..HEADER + chunks * CHUNK].to_vec();
    let c = HEADER + (chunks - 1) * CHUNK;
    let mut pos = 0x200;
    let mut last_offset = pos;
    let mut last_id = 0i64;
    for _ in 0..keep {
        last_offset = pos;
        last_id = i64::from_le_bytes(b[c + pos + 8..c + pos + 16].try_into().unwrap());
        pos += u32_at(&b, c + pos + 4) as usize;
    }
    b[c + pos..c + CHUNK].fill(0);
    b[c + 0x10..c + 0x18].copy_from_slice(&last_id.to_le_bytes());
    b[c + 0x20..c + 0x28].copy_from_slice(&last_id.to_le_bytes());
    b[c + 0x2C..c + 0x30].copy_from_slice(&(last_offset as u32).to_le_bytes());
    b[c + 0x30..c + 0x34].copy_from_slice(&(pos as u32).to_le_bytes());
    b
}

/// The same chunks, in another order
fn rotated_copy(log: &[u8], by: usize) -> Vec<u8> {
    let n = (log.len() - HEADER) / CHUNK;
    let mut b = log[..HEADER].to_vec();
    for i in 0..n {
        let j = (i + by) % n;
        b.extend_from_slice(&log[HEADER + j * CHUNK..HEADER + (j + 1) * CHUNK]);
    }
    b
}

fn run(files: &[PathBuf], merge: bool) -> (Vec<(Row, Vec<PathBuf>)>, timeline::Summary) {
    let options = Options { merge, order: Order::Time, ..Default::default() };
    let mut rows = Vec::new();
    let mut sink = |row: &Row, sources: &[&Path]| {
        rows.push((row.clone(), sources.iter().map(|p| p.to_path_buf()).collect()));
        Ok(())
    };
    let summary = timeline::run(files, &options, &mut Quiet, &mut sink).unwrap();
    (rows, summary)
}

#[test]
fn copies_of_a_log_merge_into_one_row_per_event() {
    let dir = tempfile::tempdir().unwrap();
    let log = fixture("security.evtx");
    let new = dir.path().join("new/Security.evtx");
    let old = dir.path().join("old/Security.evtx");
    let same = dir.path().join("copy/Security.evtx");
    let wrapped = dir.path().join("wrapped/Security.evtx");
    for (p, bytes) in [(&new, log.clone()), (&old, older_copy(&log, 11, 40)), (&same, log.clone()), (&wrapped, rotated_copy(&log, 7))] {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    let (alone, _) = run(std::slice::from_ref(&new), false);
    assert_eq!(alone.len(), 2261);

    let files = vec![new.clone(), old.clone(), same.clone(), wrapped.clone()];
    let (merged, summary) = run(&files, true);
    assert_eq!(summary.files_identical, 1, "the byte-for-byte copy is read once");
    assert_eq!(merged.len(), alone.len(), "one row per event");
    // the old copy's first 10 chunks and the wrapped copy's chunks are the new copy's: not parsed again
    assert_eq!(summary.chunks_duplicate, 10 + 26);

    // the same rows, in the same order, as the new copy alone (but for SourceFile)
    for ((a, _), (m, _)) in alone.iter().zip(&merged) {
        assert_eq!((a.time_created, a.event_record_id.as_deref(), &a.payload), (m.time_created, m.event_record_id.as_deref(), &m.payload));
    }

    // events in the old copy list both files (and the wrapped copy); the rest, the new one and the wrapped one
    let old_ids: std::collections::HashSet<String> = {
        let (rows, _) = run(std::slice::from_ref(&old), false);
        rows.into_iter().map(|(r, _)| r.event_record_id.unwrap()).collect()
    };
    assert!(old_ids.len() > 40 && old_ids.len() < 2261);
    for (row, sources) in &merged {
        let id = row.event_record_id.as_deref().unwrap();
        if old_ids.contains(id) {
            assert_eq!(sources, &vec![new.clone(), old.clone(), wrapped.clone()], "record {id}");
        } else {
            assert_eq!(sources, &vec![new.clone(), wrapped.clone()], "record {id}");
        }
    }
    // only the records of the old copy's partly written chunk were parsed twice; the other copies' chunks were
    // recognized as chunks already read
    assert_eq!(summary.events_merged, 40);
}

#[test]
fn without_merge_every_copy_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let log = fixture("security.evtx");
    let a = dir.path().join("a.evtx");
    let b = dir.path().join("b.evtx");
    std::fs::write(&a, &log).unwrap();
    std::fs::write(&b, rotated_copy(&log, 3)).unwrap();
    let (rows, summary) = run(&[a, b], false);
    assert_eq!(rows.len(), 2 * 2261);
    assert_eq!(summary.events_merged, 0);
    // sorted by time
    assert!(rows.windows(2).all(|w| w[0].0.time_created <= w[1].0.time_created));
}

#[test]
fn sorting_through_temporary_files_gives_the_same_rows() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("system.evtx");
    std::fs::write(&p, fixture("system.evtx")).unwrap();
    let files = vec![p];
    let (in_memory, _) = run(&files, false);
    let options = Options { memory_limit: 64 * 1024, temp_dir: Some(dir.path().to_path_buf()), ..Default::default() };
    let mut spilled = Vec::new();
    let mut sink = |row: &Row, _: &[&Path]| {
        spilled.push(row.clone());
        Ok(())
    };
    let summary = timeline::run(&files, &options, &mut Quiet, &mut sink).unwrap();
    assert!(summary.temp_files > 5);
    assert_eq!(spilled, in_memory.into_iter().map(|(r, _)| r).collect::<Vec<_>>());
    // the temporary files are gone
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
