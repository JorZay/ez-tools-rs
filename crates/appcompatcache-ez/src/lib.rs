//! The AppCompatCache (ShimCache) value of a SYSTEM hive as AppCompatCacheParser (Eric Zimmerman's) reads it, Windows XP to
//! 11. Nothing is printed: messages go to an observer. Hives are opened with registry-ez, with the transaction logs of a
//! dirty hive replayed.

mod bytes;
mod formats;

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;

use ez_common::dotnet::upper_invariant;
use ez_common::{Level, Timestamp};
use registry_ez::replay::LogFile;
use registry_ez::{Hive, KeyId, VkId};

/// Receives the messages of the original's log, in order
pub type Observer<'a> = &'a mut dyn FnMut(Level, &str);

/// AppCompatCacheParseException: a value that can't be parsed
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParseError(pub String);

pub(crate) type Result<T> = std::result::Result<T, ParseError>;

/// What stops reading a hive or a value
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The value is too small or not a known format (AppCompatCacheParseException)
    Parse,
    /// The hive could not be accessed or read, is dirty without its logs, or the ControlSet isn't there: the tool's failure
    CouldNotProcess,
    /// A damaged hive
    Other,
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Error {
        Error { message: e.0, kind: ErrorKind::Parse }
    }
}

impl From<String> for Error {
    fn from(message: String) -> Error {
        let kind = if message.contains("transaction logs were not found") || message.contains("Could not find ControlSet") {
            ErrorKind::CouldNotProcess
        } else {
            ErrorKind::Other
        };
        Error { message, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Execute {
    #[default]
    Yes,
    No,
    NA,
}

impl Execute {
    pub fn name(self) -> &'static str {
        match self {
            Execute::Yes => "Yes",
            Execute::No => "No",
            Execute::NA => "NA",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystemVersion {
    WindowsXP,
    WindowsVistaWin2k3Win2k8,
    Windows7x86,
    Windows7x64_Windows2008R2,
    Windows80_Windows2012,
    Windows81_Windows2012R2,
    Windows10,
    Windows10C_11,
    Unknown,
}

impl OperatingSystemVersion {
    pub fn name(self) -> &'static str {
        match self {
            OperatingSystemVersion::WindowsXP => "WindowsXP",
            OperatingSystemVersion::WindowsVistaWin2k3Win2k8 => "WindowsVistaWin2k3Win2k8",
            OperatingSystemVersion::Windows7x86 => "Windows7x86",
            OperatingSystemVersion::Windows7x64_Windows2008R2 => "Windows7x64_Windows2008R2",
            OperatingSystemVersion::Windows80_Windows2012 => "Windows80_Windows2012",
            OperatingSystemVersion::Windows81_Windows2012R2 => "Windows81_Windows2012R2",
            OperatingSystemVersion::Windows10 => "Windows10",
            OperatingSystemVersion::Windows10C_11 => "Windows10C_11",
            OperatingSystemVersion::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CacheEntry {
    pub cache_entry_position: i32,
    pub data: Vec<u8>,
    pub executed: Execute,
    pub data_size: i32,
    pub last_modified_time_utc: Option<Timestamp>,
    /// Windows XP only: when the entry was last updated (the LRU array orders entries by it)
    pub last_update_time_utc: Option<Timestamp>,
    pub path: String,
    pub path_size: i32,
    pub signature: String,
    pub control_set: i32,
    /// Recovered from the slack of the value's cell, so no longer in the cache
    pub from_slack: bool,
}

/// DateTimeOffset.ToFileTime's ticks since 1601
const FILETIME_EPOCH_TICKS: i64 = 504911232000000000;

impl CacheEntry {
    /// GetKey: what makes an entry the same as another
    pub fn key(&self) -> String {
        let time = self.last_modified_time_utc.map_or(0, |t| t.ticks() - FILETIME_EPOCH_TICKS);
        format!("{time}{}", upper_invariant(&self.path))
    }
}

/// One control set's cache
#[derive(Debug, Clone)]
pub struct Cache {
    pub entries: Vec<CacheEntry>,
    /// Entries recovered from the slack of the value's cell (Windows 8 to 11) that are no longer in the cache
    pub slack_entries: Vec<CacheEntry>,
    /// The total number of entries to expect; -1 when not available (Windows 8.x/10)
    pub entry_count: i32,
    pub control_set: i32,
    /// Entries that could not be read (the ones before them are in `entries`)
    pub parse_errors: Vec<String>,
}

/// The observer, shareable between the readers
pub(crate) struct Sink<'a>(RefCell<Observer<'a>>);

impl Sink<'_> {
    pub(crate) fn log(&self, level: Level, message: &str) {
        (self.0.borrow_mut())(level, message);
    }

    fn drain(&self, hive: &Hive) {
        for d in hive.take_messages() {
            self.log(d.level, &d.message);
        }
    }
}

pub struct AppCompatCache {
    pub caches: Vec<Cache>,
    /// The format of the (last) cache
    pub operating_system: OperatingSystemVersion,
}

const CACHE_KEY: &str = "Control\\Session Manager\\AppCompatCache";
/// Windows XP
const CACHE_KEY_XP: &str = "Control\\Session Manager\\AppCompatibility";

/// `{n:000}` in C#: at least three digits, not counting a sign
fn three_digits(n: i32) -> String {
    if n < 0 { format!("-{:03}", n.unsigned_abs()) } else { format!("{n:03}") }
}

fn cache_key_for(hive: &Hive, control_set: i32) -> Option<KeyId> {
    let id = three_digits(control_set);
    hive.get_key(&format!("ControlSet{id}\\{CACHE_KEY}")).or_else(|| hive.get_key(&format!("ControlSet{id}\\{CACHE_KEY_XP}")))
}

/// The value of a key by name. Reading a name that is damaged is an error
fn find_value(hive: &Hive, key: KeyId, name: &str) -> std::result::Result<Option<VkId>, String> {
    for &v in &hive.keys[key].values {
        if hive.vks[v].name()? == name {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// int.TryParse
fn try_parse_int(s: &str) -> Option<i32> {
    let is_white = |c: char| matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ');
    s.trim_start_matches(is_white).trim_end_matches('\0').trim_end_matches(is_white).parse().ok()
}

/// What .NET's file classes say for a path that can't be read
fn read_error(path: &str, e: &std::io::Error) -> Error {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.into());
    let message = match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!("Access to the path '{}' is denied.", full.display()),
        _ => e.to_string(),
    };
    Error { message, kind: ErrorKind::CouldNotProcess }
}

/// FindLogs: the hive's transaction logs (SYSTEM.LOG, .LOG1, .LOG2, in any case) next to it that aren't empty
pub fn find_logs(directory: &str, hive_name: &str) -> Vec<String> {
    let names: Vec<String> = [".LOG", ".LOG1", ".LOG2"].iter().map(|t| upper_invariant(&format!("{hive_name}{t}"))).collect();
    let Ok(entries) = std::fs::read_dir(directory) else { return vec![] };
    let mut logs: Vec<String> = entries
        .flatten()
        .filter(|e| names.contains(&upper_invariant(&e.file_name().to_string_lossy())))
        .filter(|e| e.path().is_file() && e.metadata().map(|m| m.len()).unwrap_or(0) > 0)
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect();
    logs.sort_by_key(|p| upper_invariant(p));
    logs
}

/// The hive, with its transaction logs replayed when it is dirty
fn load_hive(filename: &str, no_logs: bool, sink: &Sink) -> std::result::Result<Hive, Error> {
    let bytes = std::fs::read(filename).map_err(|e| read_error(filename, &e))?;
    // RegistryHive(path) checks the signature with the path in its message
    if bytes.len() >= 4 && bytes[..4] != *b"regf" {
        let message = format!("{filename} is not a Registry hive (bad signature)");
        sink.log(Level::Error, &message);
        return Err(message.into());
    }
    let mut hive = Hive::new(bytes, filename)?;
    hive.recover_deleted = false;
    sink.drain(&hive);

    if hive.header.primary_sequence_number != hive.header.secondary_sequence_number {
        if no_logs {
            sink.log(Level::Warning, "Registry hive is dirty, but --nl was provided, so its transaction logs are not replayed. Data may be missing! Continuing anyways...");
        } else {
            let full = std::path::absolute(filename).unwrap_or_else(|_| filename.into());
            let directory = full.parent().map_or(".".to_string(), |p| p.to_string_lossy().into_owned());
            let name = Path::new(filename).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let logs = find_logs(&directory, &name);
            if logs.is_empty() {
                sink.log(Level::Warning, "Registry hive is dirty and no transaction logs were found in the same directory! LOGs should have same base name as the hive. Aborting!!");
                return Err("Sequence numbers do not match and transaction logs were not found in the same directory as the hive. Aborting".to_string().into());
            }
            let mut files = Vec::with_capacity(logs.len());
            for log in logs {
                let bytes = std::fs::read(&log).map_err(|e| read_error(&log, &e))?;
                files.push(LogFile { name: log, bytes });
            }
            let applied = hive.process_transaction_logs(files);
            sink.drain(&hive);
            applied?;
        }
    }
    let parsed = hive.parse();
    sink.drain(&hive);
    parsed?;
    Ok(hive)
}

/// Whether the system is 32 bit: PROCESSOR_ARCHITECTURE in the current control set. When the hive doesn't say, 64 bit; the
/// Windows 7 and Vista layouts are also checked against the data
fn is_32_bit(filename: &str, hive: &Hive, sink: &Sink) -> std::result::Result<bool, String> {
    let text = |key: KeyId, name: &str| -> std::result::Result<Option<String>, String> {
        let Some(v) = find_value(hive, key, name)? else { return Ok(None) };
        let data = hive.value_data(v)?.text(hive.date_culture);
        sink.drain(hive);
        Ok(Some(data))
    };
    let current = match hive.get_key("Select") {
        Some(k) => text(k, "Current")?,
        None => None,
    };
    if let Some(id) = current.as_deref().and_then(try_parse_int) {
        if let Some(key) = hive.get_key(&format!("ControlSet{}\\Control\\Session Manager\\Environment", three_digits(id))) {
            if let Some(arch) = text(key, "PROCESSOR_ARCHITECTURE")? {
                return Ok(arch == "x86");
            }
        }
    }
    sink.log(Level::Warning, &format!("Unable to determine the CPU architecture of '{filename}' (no Select\\Current or PROCESSOR_ARCHITECTURE). Assuming 64 bit"));
    Ok(false)
}

/// The control sets' numbers under the root that have a cache, for ^ControlSet(\d{3})$ in any case
fn control_sets(hive: &Hive) -> Vec<i32> {
    let mut ids = Vec::new();
    let Some(root) = hive.root else { return ids };
    for &key in &hive.keys[root].subkeys {
        let name = hive.key_name(key);
        if name.len() == 13 && name.is_char_boundary(10) && name[..10].eq_ignore_ascii_case("ControlSet") && name[10..].bytes().all(|b| b.is_ascii_digit()) {
            let id: i32 = name[10..].parse().unwrap_or(0);
            if cache_key_for(hive, id).is_some() {
                ids.push(id);
            }
        }
    }
    ids.sort();
    ids
}

impl AppCompatCache {
    /// A raw AppCompatCache value
    pub fn from_bytes(raw: &[u8], control_set: i32, is32: bool, observer: Observer) -> std::result::Result<AppCompatCache, Error> {
        let sink = Sink(RefCell::new(observer));
        let mut am = AppCompatCache { caches: vec![], operating_system: OperatingSystemVersion::Unknown };
        let cache = am.init(raw, is32, control_set, &sink)?;
        am.caches.push(cache);
        Ok(am)
    }

    /// A SYSTEM hive. `control_set` is the ControlSet00x to read, or -1 for all of them
    pub fn open(filename: &str, control_set: i32, no_logs: bool, observer: Observer) -> std::result::Result<AppCompatCache, Error> {
        let sink = Sink(RefCell::new(observer));
        let hive = load_hive(filename, no_logs, &sink)?;
        let mut am = AppCompatCache { caches: vec![], operating_system: OperatingSystemVersion::Unknown };

        let ids = if control_set == -1 {
            let ids = control_sets(&hive);
            if ids.len() > 1 {
                let list = ids.iter().map(i32::to_string).collect::<Vec<_>>().join(",");
                sink.log(Level::Warning, &format!("***The following ControlSet00x keys will be exported: {list}. Use -c to process keys individually"));
            }
            ids
        } else {
            if cache_key_for(&hive, control_set).is_none() {
                return Err(format!("Could not find ControlSet00{control_set}").into());
            }
            vec![control_set]
        };

        let is32 = is_32_bit(filename, &hive, &sink)?;
        sink.log(Level::Debug, &format!("**** Found {} ids to process", ids.len()));
        for id in ids {
            sink.log(Level::Debug, &format!("**** Processing id {id}"));
            let value = match cache_key_for(&hive, id) {
                Some(k) => find_value(&hive, k, "AppCompatCache")?,
                None => None,
            };
            let Some(value) = value else {
                sink.log(Level::Error, &format!("'AppCompatCache' value not found for 'ControlSet{}'! Skipping", three_digits(id)));
                continue;
            };
            let raw = hive.value_raw(value)?;
            let mut cache = am.init(&raw, is32, id, &sink)?;
            // only what isn't still in the cache (the slack usually holds an older copy of entries that still are)
            let live: HashSet<String> = cache.entries.iter().map(CacheEntry::key).collect();
            let slack = hive.value_slack(value)?;
            let mut recovered: Vec<CacheEntry> = formats::recover_slack(&slack, am.operating_system, id, &sink).into_iter().filter(|e| !live.contains(&e.key())).collect();
            for (i, entry) in recovered.iter_mut().enumerate() {
                entry.cache_entry_position = (cache.entries.len() + i) as i32;
            }
            cache.slack_entries = recovered;
            am.caches.push(cache);
        }
        Ok(am)
    }

    fn init(&mut self, raw: &[u8], is32: bool, control_set: i32, sink: &Sink) -> Result<Cache> {
        use OperatingSystemVersion as Os;
        self.operating_system = Os::Unknown;
        if raw.len() < 8 {
            return Err(ParseError(format!("The AppCompatCache value is too small ({} bytes)", raw.len())));
        }
        let sig_num = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let signature = bytes::ascii(raw, 128, 4);
        sink.log(Level::Debug, &format!("**** Signature {signature}, Sig num 0x{sig_num:X}"));

        if sig_num == 0xDEADBEEF {
            self.operating_system = Os::WindowsXP;
            return formats::windows_xp(raw, control_set, sink);
        }
        if sig_num == 0xBADC0FFE {
            self.operating_system = Os::WindowsVistaWin2k3Win2k8;
            return formats::vista(raw, is32, control_set, sink);
        }
        if sig_num == 0xBADC0FEE {
            let (cache, used_32) = formats::windows_7(raw, is32, control_set, sink)?;
            self.operating_system = if used_32 { Os::Windows7x86 } else { Os::Windows7x64_Windows2008R2 };
            return Ok(cache);
        }
        if signature == "00ts" {
            self.operating_system = Os::Windows80_Windows2012;
            return Ok(formats::windows_8(raw, Os::Windows80_Windows2012, control_set, sink));
        }
        if signature == "10ts" {
            self.operating_system = Os::Windows81_Windows2012R2;
            return Ok(formats::windows_8(raw, Os::Windows81_Windows2012R2, control_set, sink));
        }
        if sig_num >= 0x30 && (sig_num as usize) < raw.len() && bytes::ascii(raw, sig_num as i64, 4) == "10ts" {
            // Windows 10 and 11: the header size, then the entries
            self.operating_system = if sig_num == 0x34 { Os::Windows10C_11 } else { Os::Windows10 };
            return formats::windows_10(raw, control_set, sink);
        }
        let start = ez_common::net::hex(&raw[..raw.len().min(16)]);
        Err(ParseError(format!(
            "Unable to determine operating system! The AppCompatCache value ({} bytes) starts with {start}. If it is a valid cache, please send the hive to saericzimmerman@gmail.com",
            ez_common::dotnet::n0(raw.len() as u64)
        )))
    }
}
