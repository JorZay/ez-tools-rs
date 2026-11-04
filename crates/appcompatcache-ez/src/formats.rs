//! The value's layouts (libyal's winreg-kb, Application-compatibility-cache.md).

use std::collections::HashSet;

use ez_common::Level;

use crate::bytes::*;
use crate::{Cache, CacheEntry, Execute, OperatingSystemVersion, ParseError, Result, Sink};

/// InsertFlag.Executed
const EXECUTED: u32 = 2;

/// EntryTable: a table of fixed size entries whose paths are elsewhere in the value (Windows 2003 to 7)
struct Layout {
    entry_size: i64,
    path_offset_at: i64,
    path_offset_64: bool,
    time_at: i64,
    flags_at: i64,
    /// Data size and offset (Windows 7)
    data_at: Option<i64>,
}

const VISTA_32: Layout = Layout { entry_size: 24, path_offset_at: 4, path_offset_64: false, time_at: 8, flags_at: 16, data_at: None };
const VISTA_64: Layout = Layout { entry_size: 32, path_offset_at: 8, path_offset_64: true, time_at: 16, flags_at: 24, data_at: None };
const WIN7_X86: Layout = Layout { entry_size: 32, path_offset_at: 4, path_offset_64: false, time_at: 8, flags_at: 16, data_at: Some(24) };
const WIN7_X64: Layout = Layout { entry_size: 48, path_offset_at: 8, path_offset_64: true, time_at: 16, flags_at: 24, data_at: Some(32) };

impl Layout {
    /// Reads a number that is 8 bytes in the 64 bit layout and 4 in the 32 bit one
    fn size_field(&self, b: &[u8], at: i64, field: &str) -> Result<i64> {
        if self.path_offset_64 { i64_at(b, at, field) } else { u32_at(b, at, field).map(i64::from) }
    }

    fn plausible(&self, b: &[u8], table_start: i64, count: i32) -> bool {
        if count == 0 || !fits(b, table_start, self.entry_size) {
            return false;
        }
        let u16_of = |at: i64| u16::from_le_bytes(b[at as usize..at as usize + 2].try_into().unwrap());
        let size = u16_of(table_start);
        let max = u16_of(table_start + 2);
        let Ok(offset) = self.size_field(b, table_start + self.path_offset_at, "") else { return false };
        let table_end = table_start + count as i64 * self.entry_size;
        size % 2 == 0 && max >= size && offset >= table_end && fits(b, offset, size as i64)
    }
}

/// The layout for the hive's architecture when the first entry makes sense with it, else the other one when that one does
/// (the architecture value can be missing or wrong), else the hive's
fn is_32_bit(b: &[u8], table_start: i64, count: i32, hint: bool, l32: &Layout, l64: &Layout, sink: &Sink) -> bool {
    let (hinted, other) = if hint { (l32, l64) } else { (l64, l32) };
    if hinted.plausible(b, table_start, count) || !other.plausible(b, table_start, count) {
        return hint;
    }
    sink.log(Level::Warning, &format!("The AppCompatCache entries are laid out as on {} bit Windows, which is how they will be read", if hint { 64 } else { 32 }));
    !hint
}

fn table_entry(b: &[u8], at: i64, n: i32, l: &Layout, control_set: i32, flags_mean_executed: bool) -> Result<CacheEntry> {
    let mut ce = CacheEntry { cache_entry_position: n, control_set, ..Default::default() };
    ce.path_size = u16_at(b, at, "Path size")? as i32;
    let offset = l.size_field(b, at + l.path_offset_at, "Path offset")?;
    ce.path = clean_path(&utf16(b, offset, ce.path_size as i64, "Path")?);
    ce.last_modified_time_utc = file_time(i64_at(b, at + l.time_at, "Last modified time")?);
    let flags = u32_at(b, at + l.flags_at, "Insertion flags")?;
    if let Some(data_at) = l.data_at {
        let data_size = l.size_field(b, at + data_at, "Data size")?;
        let second = if l.path_offset_64 { 8 } else { 4 };
        let data_offset = l.size_field(b, at + data_at + second, "Data offset")?;
        if data_size > 0 && fits(b, data_offset, data_size) {
            ce.data_size = data_size as i32;
            ce.data = slice(b, data_offset, data_size, "Data")?;
        }
    }
    ce.executed = if !flags_mean_executed {
        Execute::NA
    } else if flags & EXECUTED == EXECUTED {
        Execute::Yes
    } else {
        Execute::No
    };
    Ok(ce)
}

/// Entries 0 to count - 1; one that can't be read goes to the errors and the rest are still read
fn read_table(b: &[u8], table_start: i64, count: i32, l: &Layout, control_set: i32, flags_mean_executed: bool, errors: &mut Vec<String>, sink: &Sink) -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    for n in 0..count.max(0) {
        let at = table_start + n as i64 * l.entry_size;
        if !fits(b, at, l.entry_size) {
            errors.push(format!("Entries {n} to {} are past the end of the data (0x{:X} bytes)", count - 1, b.len()));
            break;
        }
        match table_entry(b, at, n, l, control_set, flags_mean_executed) {
            Ok(ce) => entries.push(ce),
            Err(ParseError(m)) => {
                sink.log(Level::Error, &format!("Error parsing cache entry. Position: {n} Index: 0x{at:X}, Error: {m}"));
                errors.push(format!("Entry {n} at offset 0x{at:X}: {m}"));
            }
        }
    }
    entries
}

/// Windows 7 and 2008 R2 (signature 0xBADC0FEE): a 128 byte header with the number of entries at 4, then 32 byte (32 bit)
/// or 48 byte (64 bit) entries. Insertion flag 0x2 means executed. Also says whether the 32 bit layout was used
pub(crate) fn windows_7(b: &[u8], hint: bool, control_set: i32, sink: &Sink) -> Result<(Cache, bool)> {
    let count = u32_at(b, 4, "Number of entries")? as i32;
    let is32 = is_32_bit(b, 128, count, hint, &WIN7_X86, &WIN7_X64, sink);
    let mut errors = Vec::new();
    let entries = read_table(b, 128, count, if is32 { &WIN7_X86 } else { &WIN7_X64 }, control_set, true, &mut errors, sink);
    Ok((Cache { entries, slack_entries: vec![], entry_count: count, control_set, parse_errors: errors }, is32))
}

/// Windows 2003, Vista and 2008 (signature 0xBADC0FFE): an 8 byte header with the number of entries at 4, then 24 byte
/// (32 bit) or 32 byte (64 bit) entries. On 64 bit Windows, insertion flag 0x2 means executed (Windows 2003 has the file
/// size there instead)
pub(crate) fn vista(b: &[u8], hint: bool, control_set: i32, sink: &Sink) -> Result<Cache> {
    let count = u32_at(b, 4, "Number of entries")? as i32;
    let is32 = is_32_bit(b, 8, count, hint, &VISTA_32, &VISTA_64, sink);
    let mut errors = Vec::new();
    let entries = read_table(b, 8, count, if is32 { &VISTA_32 } else { &VISTA_64 }, control_set, !is32, &mut errors, sink);
    Ok(Cache { entries, slack_entries: vec![], entry_count: count, control_set, parse_errors: errors })
}

/// Windows XP (signature 0xDEADBEEF; 64 bit XP uses the Windows 2003 format): a 400 byte header (number of slots, number of
/// entries in the LRU array, the LRU array of slot numbers, most recently used first), then 96 slots of 552 bytes: a 528
/// byte UTF-16 path, last modified FILETIME, file size, last update FILETIME. Entries are returned in LRU order
pub(crate) fn windows_xp(b: &[u8], control_set: i32, sink: &Sink) -> Result<Cache> {
    const HEADER_SIZE: i64 = 400;
    const SLOT_SIZE: i64 = 552;
    let mut errors = Vec::new();
    let slots = u32_at(b, 4, "Number of slots")? as i32;
    let mut count = u32_at(b, 8, "Number of LRU entries")? as i32;
    sink.log(Level::Debug, &format!("**** Slots: {slots}, entries in the LRU array: {count}"));
    // the LRU array is in the header, after these 16 bytes
    let lru_max = ((HEADER_SIZE - 16) / 4) as i32;
    if count > lru_max {
        errors.push(format!("The LRU array has {count} entries, but there is room for {lru_max}"));
        count = lru_max;
    }
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for position in 0..count.max(0) {
        let slot = u32_at(b, 16 + position as i64 * 4, "LRU array")?;
        let at = HEADER_SIZE + slot as i64 * SLOT_SIZE;
        let read = || -> Result<CacheEntry> {
            need(b, at, SLOT_SIZE, &format!("Slot {slot}"))?;
            let path = utf16(b, at, 528, "Path")?;
            let path = path.split('\0').next().unwrap_or("").trim();
            Ok(CacheEntry {
                path_size: 528,
                path: clean_path(path),
                last_modified_time_utc: file_time(i64_at(b, at + 528, "Last modified time")?),
                last_update_time_utc: file_time(i64_at(b, at + 544, "Last update time")?),
                cache_entry_position: position,
                control_set,
                executed: Execute::NA,
                ..Default::default()
            })
        };
        let result = if seen.insert(slot) { read() } else { Err(ParseError(format!("Slot {slot} is in the LRU array more than once"))) };
        match result {
            Ok(ce) => entries.push(ce),
            Err(ParseError(m)) => {
                sink.log(Level::Error, &format!("Error parsing cache entry. Position: {position} Slot: {slot}, Error: {m}"));
                errors.push(format!("Entry {position} (slot {slot}): {m}"));
            }
        }
    }
    Ok(Cache { entries, slack_entries: vec![], entry_count: count, control_set, parse_errors: errors })
}

/// The start of an entry with a signature, as far as Windows 8 and 10 share it: returns the entry so far, where the data
/// after the path is, and where the next entry starts
fn entry_start(b: &[u8], index: i64, signature: &str, position: i32, control_set: i32) -> Result<(CacheEntry, i64, i64)> {
    let entry_size = u32_at(b, index + 8, "Entry size")? as i64;
    let next = index + 12 + entry_size;
    need(b, index + 12, entry_size, "Entry")?;
    let mut ce = CacheEntry { signature: signature.to_string(), cache_entry_position: position, control_set, ..Default::default() };
    let mut i = index + 12;
    ce.path_size = u16_at(b, i, "Path size")? as i32;
    i += 2;
    if i + ce.path_size as i64 > next {
        return Err(ParseError(format!("Path size 0x{:X} is past the end of the entry", ce.path_size)));
    }
    ce.path = clean_path(&utf16(b, i, ce.path_size as i64, "Path")?);
    i += ce.path_size as i64;
    Ok((ce, i, next))
}

fn time_and_data(b: &[u8], mut i: i64, next: i64, ce: &mut CacheEntry) -> Result<()> {
    ce.last_modified_time_utc = file_time(i64_at(b, i, "Last modified time")?);
    i += 8;
    ce.data_size = u32_at(b, i, "Data size")? as i32;
    i += 4;
    if ce.data_size < 0 || i + ce.data_size as i64 > next {
        return Err(ParseError(format!("Data size 0x{:X} is past the end of the entry", ce.data_size)));
    }
    ce.data = slice(b, i, ce.data_size as i64, "Data")?;
    Ok(())
}

/// A Windows 8 entry: path, package data, insertion flags, shim flags, last modified FILETIME, data
pub(crate) fn windows_8_entry(b: &[u8], index: i64, signature: &str, position: i32, control_set: i32) -> Result<(CacheEntry, i64)> {
    let (mut ce, mut i, next) = entry_start(b, index, signature, position, control_set)?;
    let package_len = u16_at(b, i, "Package data size")? as i64;
    i += 2 + package_len;
    let flags = u32_at(b, i, "Insertion flags")?;
    i += 4;
    // shim flags
    i += 4;
    time_and_data(b, i, next, &mut ce)?;
    ce.executed = if flags & EXECUTED == EXECUTED { Execute::Yes } else { Execute::No };
    Ok((ce, next))
}

/// A Windows 10 or 11 entry: path, last modified FILETIME, data. Executed means data tag 0x100 is there
pub(crate) fn windows_10_entry(b: &[u8], index: i64, position: i32, control_set: i32) -> Result<(CacheEntry, i64)> {
    let (mut ce, i, next) = entry_start(b, index, "10ts", position, control_set)?;
    time_and_data(b, i, next, &mut ce)?;
    ce.executed = if has_tag(&ce.data, EXECUTED_TAG) { Execute::Yes } else { Execute::No };
    Ok((ce, next))
}

const EXECUTED_TAG: u32 = 0x100;

/// The data of a Windows 10/11 entry: 4 byte aligned records of a tag, a size and that many bytes of value. Stops at the
/// first record that doesn't fit
fn has_tag(data: &[u8], tag: u32) -> bool {
    let mut i = 0i64;
    while i + 8 <= data.len() as i64 {
        let at = i as usize;
        let found = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(data[at + 4..at + 8].try_into().unwrap()) as i64;
        if i + 8 + size > data.len() as i64 {
            return false;
        }
        if found == tag {
            return true;
        }
        i += 8 + ((size + 3) & !3);
    }
    false
}

/// Entries one after the other: each has its size, which is what gets to the next one, so the rest can't be found after a
/// damaged one
fn sequence(b: &[u8], start: i64, signature: &str, sink: &Sink, read: impl Fn(i64, i32) -> Result<(CacheEntry, i64)>) -> (Vec<CacheEntry>, Vec<String>) {
    let (mut entries, mut errors) = (Vec::new(), Vec::new());
    let mut index = start;
    let mut position = 0;
    while index + 12 <= b.len() as i64 {
        if ascii(b, index, 4) != signature {
            break;
        }
        match read(index, position) {
            Ok((ce, next)) => {
                entries.push(ce);
                position += 1;
                index = next;
            }
            Err(ParseError(m)) => {
                sink.log(Level::Error, &format!("Error parsing cache entry. Position: {position} Index: 0x{index:X}, Error: {m}"));
                errors.push(format!("Entry {position} at offset 0x{index:X}: {m}"));
                break;
            }
        }
    }
    (entries, errors)
}

/// Windows 8.0 ("00ts" entries) and 8.1 ("10ts"): a 128 byte header, then the entries
pub(crate) fn windows_8(b: &[u8], os: OperatingSystemVersion, control_set: i32, sink: &Sink) -> Cache {
    let signature = if os == OperatingSystemVersion::Windows81_Windows2012R2 { "10ts" } else { "00ts" };
    let (entries, parse_errors) = sequence(b, 128, signature, sink, |index, position| windows_8_entry(b, index, signature, position, control_set));
    Cache { entries, slack_entries: vec![], entry_count: -1, control_set, parse_errors }
}

/// Windows 10 and 11: a header (0x30 bytes, or 0x34 from the Creators Update on), then "10ts" entries
pub(crate) fn windows_10(b: &[u8], control_set: i32, sink: &Sink) -> Result<Cache> {
    let offset_to_records = u32_at(b, 0, "Header size")? as i32;
    u32_at(b, if offset_to_records == 0x34 { 0x28 } else { 0x24 }, "Number of entries")?;
    let (entries, parse_errors) = sequence(b, offset_to_records as i64, "10ts", sink, |index, position| windows_10_entry(b, index, position, control_set));
    Ok(Cache { entries, slack_entries: vec![], entry_count: -1, control_set, parse_errors })
}

/// Slack.Recover: entries left in the slack of the value's cell: entries that dropped out of the cache. Only the Windows 8
/// to 11 formats can be found there, since their entries have a signature and say how big they are
pub(crate) fn recover_slack(slack: &[u8], os: OperatingSystemVersion, control_set: i32, sink: &Sink) -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    if slack.len() < 12 {
        return entries;
    }
    let signature = match os {
        OperatingSystemVersion::Windows80_Windows2012 => "00ts",
        OperatingSystemVersion::Windows81_Windows2012R2 | OperatingSystemVersion::Windows10 | OperatingSystemVersion::Windows10C_11 => "10ts",
        _ => return entries,
    };
    let windows10 = matches!(os, OperatingSystemVersion::Windows10 | OperatingSystemVersion::Windows10C_11);
    let mut i = 0i64;
    while i + 12 <= slack.len() as i64 {
        if slack[i as usize] != signature.as_bytes()[0] || ascii(slack, i, 4) != signature {
            i += 1;
            continue;
        }
        let position = entries.len() as i32;
        let read = if windows10 { windows_10_entry(slack, i, position, control_set) } else { windows_8_entry(slack, i, signature, position, control_set) };
        match read {
            // a path without control characters
            Ok((mut ce, next)) if !ce.path.is_empty() && ce.path_size % 2 == 0 && ce.path.chars().all(|c| c as u32 >= 0x20 || c == '\t') => {
                ce.from_slack = true;
                entries.push(ce);
                i = next;
            }
            // a signature that isn't the start of a whole entry (or an entry cut off at the end)
            _ => i += 1,
        }
    }
    sink.log(Level::Debug, &format!("**** Recovered {} entries from slack", entries.len()));
    entries
}
