//! The output files: CSV and JSON lines, UTF-8 with a BOM as EvtxECmd writes them.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use evtx_ez::Timestamp;
use evtx_ez::output::table::{CSV_HEADER, CSV_NEW_LINE, write_csv_row, write_json_row};
use evtx_ez::timeline::{Row, RowSink};

const BOM: &[u8] = "\u{FEFF}".as_bytes();

pub fn utc_now() -> Timestamp {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    // ticks from 0001-01-01 to 1970-01-01
    Timestamp(621_355_968_000_000_000 + (d.as_nanos() / 100) as i64)
}

/// A number with thousands separators (.NET's N0)
pub fn n0(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// An output path: "-", a file, or a folder (existing, or ending with a separator) for EvtxECmd's file name
pub fn resolve(p: &Path, now: Timestamp, ext: &str) -> PathBuf {
    if p.as_os_str() == "-" {
        return p.to_path_buf();
    }
    let s = p.to_string_lossy();
    if p.is_dir() || s.ends_with('/') || s.ends_with(std::path::MAIN_SEPARATOR) {
        return p.join(format!("{}_EvtxECmd_Output.{ext}", now.format("yyyyMMddHHmmss")));
    }
    p.to_path_buf()
}

fn open(p: &Path) -> Result<Box<dyn Write>, String> {
    if p.as_os_str() == "-" {
        return Ok(Box::new(BufWriter::with_capacity(1 << 20, io::stdout().lock())));
    }
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("Unable to create directory {}: {e}", dir.display()))?;
    }
    let f = File::create(p).map_err(|e| format!("Unable to open {}: {e}", p.display()))?;
    Ok(Box::new(BufWriter::with_capacity(1 << 20, f)))
}

pub struct Writer {
    csv: Option<Box<dyn Write>>,
    json: Option<Box<dyn Write>>,
    date_format: String,
    full_json: bool,
    buf: String,
}

impl Writer {
    pub fn create(csv: Option<&Path>, json: Option<&Path>, date_format: &str, full_json: bool) -> Result<Writer, String> {
        let mut w = Writer { csv: None, json: None, date_format: date_format.to_string(), full_json, buf: String::new() };
        if let Some(p) = csv {
            let mut f = open(p)?;
            let header = format!("{CSV_HEADER}{CSV_NEW_LINE}");
            f.write_all(BOM).and_then(|_| f.write_all(header.as_bytes())).map_err(|e| e.to_string())?;
            w.csv = Some(f);
        }
        if let Some(p) = json {
            let mut f = open(p)?;
            f.write_all(BOM).map_err(|e| e.to_string())?;
            w.json = Some(f);
        }
        Ok(w)
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(f) = &mut self.csv {
            f.flush()?;
        }
        if let Some(f) = &mut self.json {
            f.flush()?;
        }
        Ok(())
    }
}

impl RowSink for Writer {
    fn write_row(&mut self, row: &Row, sources: &[&Path]) -> io::Result<()> {
        let source = match sources {
            [one] => one.to_string_lossy().into_owned(),
            many => many.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>().join("|"),
        };
        if let Some(f) = &mut self.csv {
            self.buf.clear();
            write_csv_row(&mut self.buf, row, &source, &self.date_format);
            f.write_all(self.buf.as_bytes())?;
        }
        if let Some(f) = &mut self.json {
            self.buf.clear();
            write_json_row(&mut self.buf, row, &source, self.full_json);
            f.write_all(self.buf.as_bytes())?;
        }
        Ok(())
    }
}
