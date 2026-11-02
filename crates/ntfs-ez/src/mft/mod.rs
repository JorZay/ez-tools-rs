//! $MFT: FILE records, attributes, and paths.
//!
//! The original loads every record into memory (about 1.6 times the $MFT's size). Here the file is memory mapped
//! and read twice: a first pass, in parallel, keeps only what paths and extension records need; records are
//! parsed again when they are written. The result is the same: records in use, then free ones, in file order, with
//! extension records' attributes joined to their base records.

pub mod attributes;
pub mod export;
pub mod record;
pub mod security;
pub mod sid_types;

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use rayon::prelude::*;

use attributes::NAME_TYPE_DOS;
pub use record::{FileRecord, Key};

/// An entry and sequence number (a file reference: 48 bit entry, 16 bit sequence)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MftEntryInfo {
    pub entry: u64,
    pub sequence: u16,
}

impl MftEntryInfo {
    pub fn parse(b: &[u8]) -> MftEntryInfo {
        let low = u32::from_le_bytes(b[0..4].try_into().unwrap()) as u64;
        let high = u16::from_le_bytes([b[4], b[5]]) as u64;
        MftEntryInfo { entry: low | (high << 32), sequence: u16::from_le_bytes([b[6], b[7]]) }
    }

    pub fn key(&self) -> Key {
        Key { entry: self.entry, sequence: self.sequence as i32 }
    }
}

impl fmt::Display for MftEntryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Entry/seq: 0x{:X}-0x{:X}", self.entry, self.sequence)
    }
}

/// Where a timestamp is, for the invalid timestamp warnings (TimestampSource)
#[derive(Debug, Clone, Default)]
pub struct TimestampSource {
    attribute: Option<&'static str>,
    entry: Option<u32>,
    sequence: Option<u16>,
    offset: Option<i64>,
    lsn: Option<u64>,
}

impl TimestampSource {
    pub fn file_record(entry: u32, sequence: u16, offset: i64, lsn: u64) -> TimestampSource {
        if lsn > 0 {
            TimestampSource { entry: Some(entry), sequence: Some(sequence), lsn: Some(lsn), ..Default::default() }
        } else {
            TimestampSource { entry: Some(entry), sequence: Some(sequence), offset: Some(offset), ..Default::default() }
        }
    }

    pub fn index_entry(offset: i64, entry: u32, from_slack: bool) -> TimestampSource {
        TimestampSource {
            attribute: Some(if from_slack { "slack index entry" } else { "index entry" }),
            entry: (entry > 0).then_some(entry),
            offset: Some(offset),
            ..Default::default()
        }
    }

    pub fn log_record(lsn: u64) -> TimestampSource {
        TimestampSource { lsn: Some(lsn), ..Default::default() }
    }

    pub fn with_attribute(&self, attribute: &'static str) -> TimestampSource {
        TimestampSource { attribute: Some(attribute), ..self.clone() }
    }
}

impl fmt::Display for TimestampSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.attribute.unwrap_or("unknown location"))?;
        if let Some(e) = self.entry {
            write!(f, " of FILE record {e}")?;
            if let Some(s) = self.sequence {
                write!(f, "-{s}")?;
            }
        }
        if let Some(o) = self.offset {
            let at = if self.entry.is_some() && self.sequence.is_none() { " at record offset 0x" } else { " at offset 0x" };
            write!(f, "{at}{o:X}")?;
        }
        if let Some(l) = self.lsn {
            write!(f, " in $LogFile record LSN 0x{l:X}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bad,
    Uninitialized,
    Free,
    InUse,
}

/// What the first pass keeps of a record
#[derive(Debug, Clone)]
struct Summary {
    kind: Kind,
    key: Key,
    base: MftEntryInfo,
    is_dir: bool,
    attribute_count: usize,
    /// Non-DOS $FILE_NAMEs (name, parent), for directories and extension records only
    names: Vec<(String, Key)>,
    has_parse_errors: bool,
    warnings: Vec<String>,
}

impl Summary {
    fn is_extension(&self) -> bool {
        self.base.entry > 0 && self.base.sequence > 0
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

enum Data {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

/// A loaded $MFT
/// How a $MFT is loaded
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// --rs: look for index entries in the slack of FILE records (they are reported as warnings)
    pub recover_slack: bool,
    /// The date format of those warnings
    pub date_format: String,
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions { recover_slack: false, date_format: "yyyy-MM-dd HH:mm:ss.fffffff".into() }
    }
}

pub struct Mft {
    data: Data,
    pub record_size: usize,
    /// Records in use (block indices), in file order; a key seen twice keeps the first
    pub in_use: Vec<u32>,
    /// Free records, in file order
    pub free: Vec<u32>,
    pub bad: Vec<u32>,
    pub uninitialized: Vec<u32>,
    /// Extension records joined to each base record (by block index), in order
    extensions: HashMap<u32, Vec<u32>>,
    /// Directory key -> (name, parent key)
    dir_map: HashMap<Key, (String, Key)>,
    /// Directory key -> full path
    paths: HashMap<Key, String>,
    /// Records in use or free whose attributes could not all be parsed
    pub damaged: Vec<u32>,
    /// Messages the original logs while loading (fixups, timestamps, duplicate keys), in file order
    pub warnings: Vec<String>,
}

const INVALID_HEADER: &str = "Invalid header! Expected 'FILE' Signature.";

impl Mft {
    pub fn open(path: impl AsRef<Path>) -> Result<Mft, Error> {
        Self::open_with(path, &LoadOptions::default())
    }

    pub fn open_with(path: impl AsRef<Path>, options: &LoadOptions) -> Result<Mft, Error> {
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let data = if len == 0 {
            Data::Owned(Vec::new())
        } else {
            // SAFETY: the file is only read, and evidence files are not changed while they are parsed
            Data::Mapped(unsafe { memmap2::Mmap::map(&file)? })
        };
        Self::load(data, options)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Mft, Error> {
        Self::load(Data::Owned(bytes), &LoadOptions::default())
    }

    pub fn bytes(&self) -> &[u8] {
        match &self.data {
            Data::Mapped(m) => m,
            Data::Owned(v) => v,
        }
    }

    pub fn file_size(&self) -> u64 {
        self.bytes().len() as u64
    }

    fn load(data: Data, options: &LoadOptions) -> Result<Mft, Error> {
        let b: &[u8] = match &data {
            Data::Mapped(m) => m,
            Data::Owned(v) => v,
        };
        if b.len() < 0x20 || &b[0..4] != b"FILE" {
            return Err(Error::Invalid(INVALID_HEADER.into()));
        }
        let block = i32::from_le_bytes(b[0x1c..0x20].try_into().unwrap());
        if !(0x100..=0x10000).contains(&block) || block & (block - 1) != 0 {
            return Err(Error::Invalid(format!(
                "Invalid FILE record size 0x{block:X} in the first record (expected a power of two such as 0x400)"
            )));
        }
        let size = block as usize;
        let count = b.len().div_ceil(size);

        let summaries: Vec<Summary> = (0..count)
            .into_par_iter()
            .map(|i| {
                let r = parse_block_with(b, size, i, options);
                let is_ext = r.is_extension();
                let kind = if r.is_bad {
                    Kind::Bad
                } else if r.is_uninitialized {
                    Kind::Uninitialized
                } else if r.is_deleted() {
                    Kind::Free
                } else {
                    Kind::InUse
                };
                let keep_names = r.is_directory() || is_ext;
                Summary {
                    kind,
                    key: if matches!(kind, Kind::Bad | Kind::Uninitialized) { Key::default() } else { r.key() },
                    base: r.base_record,
                    is_dir: r.is_directory(),
                    attribute_count: r.attributes.len(),
                    names: if keep_names {
                        r.file_names()
                            .filter(|(_, f)| f.name_type != NAME_TYPE_DOS)
                            .map(|(_, f)| (f.file_name.clone(), f.parent.key()))
                            .collect()
                    } else {
                        Vec::new()
                    },
                    has_parse_errors: !r.parse_errors.is_empty(),
                    warnings: r.warnings,
                }
            })
            .collect();

        let mut m = Mft {
            data: Data::Owned(Vec::new()),
            record_size: size,
            in_use: Vec::new(),
            free: Vec::new(),
            bad: Vec::new(),
            uninitialized: Vec::new(),
            extensions: HashMap::new(),
            dir_map: HashMap::new(),
            paths: HashMap::new(),
            damaged: Vec::new(),
            warnings: Vec::new(),
        };

        let mut in_use_keys: HashMap<Key, u32> = HashMap::new();
        let mut free_keys: HashMap<Key, u32> = HashMap::new();
        // base key -> extension records, in the order base keys are first seen
        let mut ext_order: Vec<Key> = Vec::new();
        let mut ext_groups: HashMap<Key, Vec<u32>> = HashMap::new();
        for (i, s) in summaries.iter().enumerate() {
            let i = i as u32;
            m.warnings.extend(s.warnings.iter().cloned());
            let offset = i as u64 * size as u64;
            match s.kind {
                Kind::Bad => m.bad.push(i),
                Kind::Uninitialized => m.uninitialized.push(i),
                Kind::Free => {
                    if free_keys.contains_key(&s.key) {
                        m.warnings.push(format!(
                            "At offset 0x{offset:X}, a free FILE record with key '{}' already exists! You may want to review this manually. Skipping...",
                            s.key
                        ));
                    } else {
                        free_keys.insert(s.key, i);
                        m.free.push(i);
                    }
                }
                Kind::InUse => {
                    if in_use_keys.contains_key(&s.key) {
                        m.warnings.push(format!(
                            "At offset 0x{offset:X}, a FILE record with key '{}' already exists! You may want to review this manually. Skipping...",
                            s.key
                        ));
                    } else {
                        in_use_keys.insert(s.key, i);
                        m.in_use.push(i);
                    }
                }
            }
            if matches!(s.kind, Kind::Free | Kind::InUse) && s.is_extension() {
                let k = s.base.key();
                ext_groups.entry(k).or_insert_with(|| {
                    ext_order.push(k);
                    Vec::new()
                });
                ext_groups.get_mut(&k).unwrap().push(i);
            }
        }

        let mut unassociated: Vec<Vec<u32>> = Vec::new();
        for k in &ext_order {
            let group = ext_groups.remove(k).unwrap();
            let base = in_use_keys.get(k).or_else(|| free_keys.get(k));
            match base {
                Some(&b) => m.extensions.entry(b).or_default().extend(group),
                None => unassociated.push(group),
            }
        }

        // the directory map: records in use, then free ones, then unassociated extension records
        for &i in m.in_use.iter().chain(m.free.iter()) {
            let s = &summaries[i as usize];
            if s.is_extension() {
                continue;
            }
            let exts = m.extensions.get(&i).map(Vec::as_slice).unwrap_or(&[]);
            let count = s.attribute_count + exts.iter().map(|&e| summaries[e as usize].attribute_count).sum::<usize>();
            if count == 0 || !s.is_dir {
                continue;
            }
            let names = s.names.iter().chain(exts.iter().flat_map(|&e| summaries[e as usize].names.iter()));
            if let Some((name, parent)) = names.into_iter().next() {
                m.dir_map.entry(s.key).or_insert_with(|| (name.clone(), *parent));
            }
        }
        for group in &unassociated {
            for &e in group {
                let s = &summaries[e as usize];
                if !s.is_dir {
                    continue;
                }
                if let Some((name, parent)) = s.names.first() {
                    m.dir_map.entry(s.base.key()).or_insert_with(|| (name.clone(), *parent));
                }
            }
        }

        for &i in m.in_use.iter().chain(m.free.iter()) {
            if summaries[i as usize].has_parse_errors {
                m.damaged.push(i);
            }
        }

        let keys: Vec<Key> = m.dir_map.keys().copied().collect();
        let paths: Vec<(Key, String)> = keys.par_iter().map(|k| (*k, m.walk_path(*k))).collect();
        m.paths = paths.into_iter().collect();
        m.data = data;
        Ok(m)
    }

    /// GetFullParentPath: the names from the root (".") to the directory, or `.\PathUnknown\Directory with ID 0x...`
    /// where the chain breaks
    fn walk_path(&self, key: Key) -> String {
        let mut stack: Vec<&str> = Vec::new();
        let mut seen: Vec<Key> = Vec::new();
        let mut k = key;
        while let Some((name, parent)) = self.dir_map.get(&k) {
            if seen.contains(&k) {
                break;
            }
            seen.push(k);
            stack.push(name);
            if k == Key::ROOT {
                break;
            }
            k = *parent;
        }
        let unknown;
        if k != Key::ROOT {
            unknown = format!(".\\PathUnknown\\Directory with ID 0x{k}");
            stack.push(&unknown);
        }
        stack.reverse();
        stack.join("\\")
    }

    /// The full path of a directory (the ParentPath of the files in it)
    pub fn full_path(&self, key: Key) -> std::borrow::Cow<'_, str> {
        match self.paths.get(&key) {
            Some(p) => std::borrow::Cow::Borrowed(p),
            None => std::borrow::Cow::Owned(self.walk_path(key)),
        }
    }

    /// The record in a block, parsed (without its extension records' attributes)
    pub fn record(&self, block: u32) -> FileRecord {
        parse_block(self.bytes(), self.record_size, block as usize, true)
    }

    /// The record in a block with its extension records' attributes appended, as the original has it
    pub fn full_record(&self, block: u32) -> FileRecord {
        let mut r = self.record(block);
        if let Some(exts) = self.extensions.get(&block) {
            for &e in exts {
                r.attributes.extend(self.record(e).attributes);
            }
        }
        r
    }

    pub fn block_count(&self) -> usize {
        self.bytes().len().div_ceil(self.record_size)
    }
}

/// A block of the $MFT parsed as a FILE record (the last one padded with zeros)
fn parse_block(b: &[u8], size: usize, i: usize, fixups: bool) -> FileRecord {
    let start = i * size;
    let end = (start + size).min(b.len());
    let mut buf = vec![0u8; size];
    buf[..end - start].copy_from_slice(&b[start..end]);
    FileRecord::parse(&mut buf, start as i64, fixups, 0)
}

/// parse_block, then (--rs) the index entries in the record's slack, as warnings
fn parse_block_with(b: &[u8], size: usize, i: usize, options: &LoadOptions) -> FileRecord {
    let start = i * size;
    let end = (start + size).min(b.len());
    let mut buf = vec![0u8; size];
    buf[..end - start].copy_from_slice(&b[start..end]);
    let mut r = FileRecord::parse(&mut buf, start as i64, true, 0);
    if !options.recover_slack || r.is_bad || r.is_uninitialized {
        return r;
    }
    let slack = &buf[r.slack_start..];
    let mut w = Vec::new();
    let found = crate::i30::slack_entries(slack, 0, r.slack_start as i32, r.entry_number, &mut w);
    r.warnings.append(&mut w);
    if found.is_empty() {
        return r;
    }
    let dt = |raw: i64| crate::time::Timestamp::from_filetime(raw).filter(|_| raw > 0).map(|t| t.format(&options.date_format)).unwrap_or_else(|| "null".into());
    r.warnings.push(String::new());
    r.warnings.push(format!("Found {} Index entries found in slack space!", ez_common::dotnet::n0(found.len() as u64)));
    for e in &found {
        let fi = e.file_info.as_ref().unwrap();
        let hex = |v: Option<u64>| v.map(|v| format!("0x{v:X}")).unwrap_or_else(|| "0x".into());
        r.warnings.push(format!(
            "Name: {}, Index Flag: {}, Offset: 0x{:X} MFT Entry/seq: {}/{}",
            fi.file_name,
            ez_common::net::enum_name(e.flag as i64, crate::i30::ENTRY_FLAG_NAMES),
            e.absolute_offset,
            hex(e.mft_reference_self.map(|m| m.entry)),
            hex(e.mft_reference_self.map(|m| m.sequence as u64))
        ));
        r.warnings.push(format!(
            "File flags: {}, Parent MFT Entry/seq: 0x{:X}/0x{:X}",
            ez_common::net::flags_name(fi.flags as i64, attributes::SI_FLAG_NAMES),
            fi.parent.entry,
            fi.parent.sequence
        ));
        r.warnings.push(format!("Created on:          {}", dt(fi.created)));
        r.warnings.push(format!("Content Modified on: {}", dt(fi.content_modified)));
        r.warnings.push(format!("Record Modified on:  {}", dt(fi.record_modified)));
        r.warnings.push(format!("Last Accessed on:    {}", dt(fi.last_accessed)));
        r.warnings.push(String::new());
    }
    r
}
