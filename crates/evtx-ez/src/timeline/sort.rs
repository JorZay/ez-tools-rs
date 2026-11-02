//! Sorting more rows than fit in memory: sorted runs are written (LZ4 compressed) to temporary files when the rows
//! in memory pass a limit, then merged.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use rayon::slice::ParallelSliceMut;

use super::Row;

pub(crate) type RowCmp = fn(&Row, &Row) -> Ordering;

pub(crate) struct Sorter {
    buf: Vec<Row>,
    bytes: usize,
    limit: usize,
    cmp: RowCmp,
    temp_root: Option<PathBuf>,
    dir: Option<tempfile::TempDir>,
    runs: Vec<PathBuf>,
    pub spilled_rows: u64,
}

impl Sorter {
    pub fn new(cmp: RowCmp, limit: usize, temp_root: Option<PathBuf>) -> Sorter {
        Sorter { buf: Vec::new(), bytes: 0, limit, cmp, temp_root, dir: None, runs: Vec::new(), spilled_rows: 0 }
    }

    pub fn push(&mut self, row: Row) -> io::Result<()> {
        self.bytes += row.heap_size();
        self.buf.push(row);
        if self.bytes > self.limit {
            self.spill()?;
        }
        Ok(())
    }

    /// The number of temporary files written
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    fn spill(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let cmp = self.cmp;
        self.buf.par_sort_by(cmp);
        if self.dir.is_none() {
            let mut b = tempfile::Builder::new();
            b.prefix("evtxecmd-sort-");
            self.dir = Some(match &self.temp_root {
                Some(root) => b.tempdir_in(root)?,
                None => b.tempdir()?,
            });
        }
        let path = self.dir.as_ref().unwrap().path().join(format!("run{}.lz4", self.runs.len()));
        let mut w = lz4_flex::frame::FrameEncoder::new(BufWriter::with_capacity(1 << 20, File::create(&path)?));
        for row in self.buf.drain(..) {
            row.encode(&mut w)?;
            self.spilled_rows += 1;
        }
        w.finish().map_err(io::Error::other)?.flush()?;
        self.runs.push(path);
        self.bytes = 0;
        Ok(())
    }

    /// The rows in order. The temporary files are deleted when the iterator is dropped.
    pub fn finish(mut self) -> io::Result<Sorted> {
        let cmp = self.cmp;
        if self.runs.is_empty() {
            self.buf.par_sort_by(cmp);
            return Ok(Sorted::Memory(std::mem::take(&mut self.buf).into_iter()));
        }
        self.spill()?;
        let mut readers = Vec::new();
        let mut heap = BinaryHeap::new();
        for (i, path) in self.runs.iter().enumerate() {
            let mut r = open(path)?;
            if let Some(row) = Row::decode(&mut r)? {
                heap.push(HeapItem { row, run: i, cmp });
            }
            readers.push(r);
        }
        Ok(Sorted::Merge { readers, heap, _dir: self.dir.take() })
    }
}

type RunReader = lz4_flex::frame::FrameDecoder<BufReader<File>>;

fn open(path: &Path) -> io::Result<RunReader> {
    Ok(lz4_flex::frame::FrameDecoder::new(BufReader::with_capacity(1 << 20, File::open(path)?)))
}

pub(crate) struct HeapItem {
    row: Row,
    run: usize,
    cmp: RowCmp,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        Ord::cmp(self, other) == Ordering::Equal
    }
}

impl Eq for HeapItem {}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for HeapItem {
    /// Reversed: BinaryHeap is a max-heap, and the smallest row comes first
    fn cmp(&self, other: &Self) -> Ordering {
        (self.cmp)(&other.row, &self.row).then_with(|| other.run.cmp(&self.run))
    }
}

pub(crate) enum Sorted {
    Memory(std::vec::IntoIter<Row>),
    Merge { readers: Vec<RunReader>, heap: BinaryHeap<HeapItem>, _dir: Option<tempfile::TempDir> },
}

impl Iterator for Sorted {
    type Item = io::Result<Row>;

    fn next(&mut self) -> Option<io::Result<Row>> {
        match self {
            Sorted::Memory(it) => it.next().map(Ok),
            Sorted::Merge { readers, heap, .. } => {
                let HeapItem { row, run, cmp } = heap.pop()?;
                match Row::decode(&mut readers[run]) {
                    Ok(Some(next)) => heap.push(HeapItem { row: next, run, cmp }),
                    Ok(None) => {}
                    Err(e) => return Some(Err(e)),
                }
                Some(Ok(row))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;

    fn by_time(a: &Row, b: &Row) -> Ordering {
        a.time_created.cmp(&b.time_created).then(a.seq.cmp(&b.seq))
    }

    #[test]
    fn spills_and_merges_in_order() {
        let mut s = Sorter::new(by_time, 4096, None);
        let mut expected = Vec::new();
        for i in 0..2000u64 {
            let t = (i * 7919) % 1000;
            expected.push((t, i));
            s.push(Row { time_created: Timestamp(t as i64), seq: i, payload: "x".repeat(20), ..Default::default() }).unwrap();
        }
        assert!(s.run_count() > 5);
        expected.sort();
        let got: Vec<(u64, u64)> = s.finish().unwrap().map(|r| r.unwrap()).map(|r| (r.time_created.0 as u64, r.seq)).collect();
        assert_eq!(got, expected);
    }
}
