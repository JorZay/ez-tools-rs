//! What the command line tools share: the console log, output files and their names.

pub mod log;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::time::Timestamp;

/// UTF-8's byte order mark, which EZ tools write at the start of their CSV and JSON files
pub const BOM: &[u8] = "\u{FEFF}".as_bytes();

pub fn utc_now() -> Timestamp {
    Timestamp::now()
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

pub fn open(p: &Path) -> Result<Box<dyn Write>, String> {
    if p.as_os_str() == "-" {
        return Ok(Box::new(BufWriter::with_capacity(1 << 20, io::stdout().lock())));
    }
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("Unable to create directory {}: {e}", dir.display()))?;
    }
    let f = File::create(p).map_err(|e| format!("Unable to open {}: {e}", p.display()))?;
    Ok(Box::new(BufWriter::with_capacity(1 << 20, f)))
}
