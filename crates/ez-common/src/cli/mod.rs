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

/// Path.GetFullPath: `.` and `..` are resolved, and a separator at the end is kept
pub fn full_path(p: &str) -> String {
    use std::path::Component;
    let abs = std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p));
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    let mut text = out.to_string_lossy().into_owned();
    if p.ends_with('/') && !text.ends_with('/') {
        text.push('/');
    }
    text
}

/// What the exception .NET throws says for a path that can't be created or written
pub fn io_message(path: &Path, e: &io::Error) -> String {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    match e.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::IsADirectory => format!("Access to the path '{}' is denied.", full.display()),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => format!("Could not find a part of the path '{}'.", full.display()),
        io::ErrorKind::AlreadyExists => format!("The file '{}' already exists.", full.display()),
        _ => e.to_string(),
    }
}

/// The type of that exception
pub fn io_exception(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::IsADirectory => "System.UnauthorizedAccessException",
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => "System.IO.DirectoryNotFoundException",
        _ => "System.IO.IOException",
    }
}

/// TempFolder.Prepare: the folder for the copies of the databases (the one given, or Temp next to the program), whether
/// this run created it, or why it can't be used
pub fn prepare_temp(given: Option<&str>, tool: &str) -> Result<(String, bool), String> {
    let folder = match given {
        Some(f) => full_path(f),
        None => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            exe.parent().unwrap_or(Path::new(".")).join("Temp").to_string_lossy().into_owned()
        }
    };
    let created = !Path::new(&folder).is_dir();
    let attempt = || -> io::Result<()> {
        std::fs::create_dir_all(&folder)?;
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let probe = Path::new(&folder).join(format!("{tool}-write-test-{stamp:032x}{:08x}", std::process::id()));
        std::fs::write(&probe, [])?;
        std::fs::remove_file(&probe)
    };
    match attempt() {
        Ok(()) => Ok((folder, created)),
        Err(e) => Err(format!("{folder}: {}", io_message(Path::new(&folder), &e))),
    }
}

/// TempFolder.RemoveIfEmpty: only if this run created it (another run may still be using it)
pub fn remove_temp_if_empty(folder: &str, created: bool) {
    if created {
        let _ = std::fs::remove_dir(folder);
    }
}
