//! What the command line tools share: the console log, output files and their names.

pub mod log;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::time::Timestamp;

/// The command line, by the rules of the original tools' parser, which clap's alone don't give: an option with a value can
/// only be given once and a flag can be repeated, a flag can be given a value (`--co false`, in any case), though not twice, and
/// bad arguments exit with 1. An error or help is printed: the result is then the exit code
pub fn parse_args<T: clap::Parser>() -> Result<T, std::process::ExitCode> {
    use clap::ArgAction;
    use std::process::ExitCode;
    let command = T::command().args_override_self(true);
    let mut args: Vec<String> = Vec::new();
    let mut given: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let raw: Vec<String> = std::env::args().collect();
    args.extend(raw.first().cloned());
    let mut next = 1;
    while let Some(token) = raw.get(next).cloned() {
        next += 1;
        let (name, inline) = match token.split_once(['=', ':']) {
            Some((name, value)) if name.starts_with('-') => (name.to_string(), Some(value.to_string())),
            _ => (token.clone(), None),
        };
        let option = command.get_arguments().find(|a| {
            name.strip_prefix("--").map_or_else(|| name.strip_prefix('-').is_some_and(|s| a.get_short().is_some_and(|c| s.len() == c.len_utf8() && s.starts_with(c))), |l| a.get_long() == Some(l))
        });
        let Some(option) = option else {
            args.push(token);
            continue;
        };
        let flag = matches!(option.get_action(), ArgAction::SetTrue) || option.get_num_args().is_some_and(|n| n.min_values() == 0);
        let is_bool = |s: &str| s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("false");
        let mut value = inline;
        let mut consumed = value.is_some();
        if value.is_none() {
            if let Some(following) = raw.get(next).filter(|f| !flag || is_bool(f)) {
                next += 1;
                value = Some(following.clone());
                consumed = true;
            }
        }
        if consumed && matches!(option.get_action(), ArgAction::Set | ArgAction::SetTrue) {
            let count = given.entry(name.clone()).or_default();
            *count += 1;
            if *count > 1 {
                eprintln!("Option '{name}' expects a single argument but {count} were provided.");
                return Err(ExitCode::FAILURE);
            }
        }
        match (option.get_action(), value) {
            // a plain flag takes no value in clap: only `true` sets it
            (ArgAction::SetTrue, Some(v)) => {
                if v.eq_ignore_ascii_case("true") {
                    args.push(name);
                } else if !v.eq_ignore_ascii_case("false") {
                    eprintln!("Cannot parse argument '{v}' for option '{name}' as expected type 'System.Boolean'.");
                    return Err(ExitCode::FAILURE);
                }
            }
            (_, Some(v)) => {
                args.push(name);
                args.push(if flag && is_bool(&v) { v.to_ascii_lowercase() } else { v });
            }
            (_, None) => args.push(name),
        }
    }
    let result = command.try_get_matches_from(args).and_then(|matches| T::from_arg_matches(&matches));
    result.map_err(|e| {
        let _ = e.print();
        if e.use_stderr() { ExitCode::FAILURE } else { ExitCode::SUCCESS }
    })
}

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
