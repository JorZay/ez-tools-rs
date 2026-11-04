//! Windows Amcache data as AmcacheParser (Eric Zimmerman's) reads it: the old format of Amcache.hve (Windows 7 and 8,
//! `Root\File` and `Root\Programs`), the new format (Windows 10 and 11, `Root\Inventory*`) and the `Inventory*.db`
//! SQLite databases that replace those keys from Windows 11 26H1 on. Nothing is printed: messages go to an observer.

mod databases;
mod new;
mod old;
pub mod parse;

use std::cell::RefCell;
use std::path::Path;

use ez_common::Level;
use ez_common::dotnet::upper_invariant;
use registry_ez::Hive;
use registry_ez::replay::LogFile;

pub use databases::{DatabaseTable, Value, database_files, from_file_time_value, has_databases};
pub use new::{AmcacheNew, DeviceContainer, DevicePnp, DriverBinary, DriverPackage, FileEntryNew, ProgramsEntryNew, Shortcut};
pub use old::{AmcacheOld, FileEntryOld, ProgramsEntryOld};

/// Receives the messages of the original's log, in order
pub type Observer<'a> = &'a mut dyn FnMut(Level, &str);

/// An exception that stops reading a hive
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    /// The file could not be accessed or read, or a dirty hive has no logs: the tool's failure, not a damaged file
    pub could_not_process: bool,
}

impl From<String> for Error {
    fn from(message: String) -> Error {
        let could_not_process = message.contains("transaction logs were not found");
        Error { message, could_not_process }
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Error {
        message.to_string().into()
    }
}

const DIRTY_NO_LOGS: &str = "Sequence numbers do not match and transaction logs were not found in the same directory as the hive. Aborting";
const DIRTY_ABORT: &str =
    "Registry hive is dirty and no transaction logs were found in the same directory! LOGs should have same base name as the hive. Aborting!!";
const DIRTY_CONTINUE: &str = "Registry hive is dirty and no transaction logs were found in the same directory. Data may be missing! Continuing anyways...";
const DIRTY_NL: &str =
    "Registry hive is dirty and transaction logs were found in the same directory, but --nl was provided. Data may be missing! Continuing anyways...";

/// The observer, shareable between the readers
pub(crate) struct Sink<'a>(RefCell<Observer<'a>>);

impl<'a> Sink<'a> {
    pub(crate) fn new(observer: Observer<'a>) -> Sink<'a> {
        Sink(RefCell::new(observer))
    }

    pub(crate) fn log(&self, level: Level, message: &str) {
        (self.0.borrow_mut())(level, message);
    }

    pub(crate) fn drain(&self, hive: &Hive) {
        for d in hive.take_messages() {
            self.log(d.level, &d.message);
        }
    }
}

/// What .NET's file classes say for a path that can't be read
pub(crate) fn read_error(path: &str, e: &std::io::Error) -> Error {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.into());
    let message = match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!("Access to the path '{}' is denied.", full.display()),
        std::io::ErrorKind::NotFound => format!("Could not find file '{}'.", full.display()),
        _ => e.to_string(),
    };
    Error { message, could_not_process: true }
}

/// Helper.LogFiles: the hive's transaction logs next to it that aren't empty: .LOG (Windows 8 and earlier), .LOG1 and
/// .LOG2, in any case
pub fn log_files(directory: &str, hive_name: &str) -> Vec<String> {
    let directory = if directory.is_empty() { "." } else { directory };
    let mut logs = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else { return logs };
    let prefix = upper_invariant(&format!("{hive_name}.LOG"));
    let base_len = hive_name.encode_utf16().count();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = Path::new(directory).join(&name);
        if !path.is_file() {
            continue;
        }
        let upper_name = upper_invariant(&name);
        if name.encode_utf16().count() > base_len + 5 || !upper_name.starts_with(&prefix) {
            continue;
        }
        let suffix = &upper_name[prefix.len()..];
        if matches!(suffix, "" | "1" | "2") && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > 0 {
            logs.push(path.to_string_lossy().into_owned());
        }
    }
    logs.sort_by_key(|a| upper_invariant(a));
    logs
}

fn parent_and_name(path: &str) -> (String, String) {
    let p = Path::new(path);
    (
        p.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default(),
        p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    )
}

fn apply_logs(hive: &mut Hive, logs: &[String], sink: &Sink) -> Result<(), Error> {
    let mut files = Vec::with_capacity(logs.len());
    for name in logs {
        let bytes = std::fs::read(name).map_err(|e| read_error(name, &e))?;
        files.push(LogFile { name: name.clone(), bytes });
    }
    let result = hive.process_transaction_logs(files);
    sink.drain(hive);
    result.map_err(Error::from)
}

/// Opening a hive, as each class of the original does it: the logs are applied to a dirty hive before it is parsed
fn open_hive(path: &str, no_logs: bool, checking_format: bool, sink: &Sink) -> Result<Hive, Error> {
    let bytes = std::fs::read(path).map_err(|e| read_error(path, &e))?;
    // RegistryHive(path) checks the signature with the path in its message
    if bytes.len() >= 4 && bytes[..4] != *b"regf" {
        let message = format!("{path} is not a Registry hive (bad signature)");
        sink.log(Level::Error, &message);
        return Err(message.into());
    }
    let mut hive = Hive::new(bytes, path).map_err(Error::from)?;
    hive.recover_deleted = true;
    sink.drain(&hive);

    let (directory, name) = parent_and_name(path);
    let logs = log_files(&directory, &name);
    let differ = hive.header.primary_sequence_number != hive.header.secondary_sequence_number;
    if differ || !hive.header.checksum_ok() && !logs.is_empty() {
        if logs.is_empty() || (no_logs && checking_format) {
            if !no_logs {
                sink.log(Level::Warning, DIRTY_ABORT);
                return Err(DIRTY_NO_LOGS.into());
            }
            sink.log(Level::Warning, DIRTY_CONTINUE);
        } else if no_logs {
            sink.log(Level::Warning, DIRTY_NL);
        } else {
            apply_logs(&mut hive, &logs, sink)?;
        }
    }

    let parsed = hive.parse();
    sink.drain(&hive);
    parsed.map_err(Error::from)?;
    Ok(hive)
}

/// Helper.IsNewFormat: whether the hive has `Root\InventoryApplicationFile`. Any error is false, after its messages
pub fn is_new_format(path: &str, no_logs: bool, observer: Observer) -> bool {
    let sink = Sink::new(observer);
    match open_hive(path, no_logs, true, &sink) {
        Ok(hive) => hive.get_key("Root\\InventoryApplicationFile").is_some(),
        Err(_) => false,
    }
}
