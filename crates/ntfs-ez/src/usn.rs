//! $UsnJrnl:$J: the change journal. USN_RECORD_V2 and V3 records are parsed (V4 range records are skipped); zeros
//! are skipped 8 bytes at a time, and anything else that is not a record skips to the next page. A sparse $J's
//! data is found first.
//!
//! [`rewind_parent_paths`] gives each record's parent path as it was when the record was written (MFTECmd's
//! UsnRewind, issue #56; Yogesh Khatri's technique).

use std::collections::{HashMap, HashSet};

use ez_common::net;

use crate::mft::{Key, Mft};

const PAGE_SIZE: u64 = 0x1000;
const MAX_RECORD_SIZE: u32 = 0x260;
const MIN_RECORD_SIZE: u32 = 0x38;
const MAX_FILETIME: i64 = 2_650_467_743_999_999_999;

pub const REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;

pub const UPDATE_REASON_NAMES: &[(&str, i64)] = &[
    ("BasicInfoChange", 0x00008000),
    ("Close", 0x80000000),
    ("CompressionChange", 0x00020000),
    ("DataExtend", 0x00000002),
    ("DataOverwrite", 0x00000001),
    ("DataTruncation", 0x00000004),
    ("EaChange", 0x00000400),
    ("EncryptionChange", 0x00040000),
    ("FileCreate", 0x00000100),
    ("FileDelete", 0x00000200),
    ("HardLinkChange", 0x00010000),
    ("IndexableChange", 0x00004000),
    ("IntegrityChange", 0x00800000),
    ("NamedDataExtend", 0x00000020),
    ("NamedDataOverwrite", 0x00000010),
    ("NamedDataTruncation", 0x00000040),
    ("ObjectIdChange", 0x00080000),
    ("RenameNewName", 0x00002000),
    ("RenameOldName", 0x00001000),
    ("ReparsePointChange", 0x00100000),
    ("SecurityChange", 0x00000800),
    ("StreamChange", 0x00200000),
    ("TransactedChange", 0x00400000),
];

pub const FILE_ATTRIBUTE_NAMES: &[(&str, i64)] = &[
    ("ReadOnly", 0x01),
    ("Hidden", 0x02),
    ("System", 0x04),
    ("VolumeLabel", 0x08),
    ("Directory", 0x010),
    ("Archive", 0x020),
    ("Device", 0x040),
    ("Normal", 0x080),
    ("Temporary", 0x0100),
    ("SparseFile", 0x0200),
    ("ReparsePoint", 0x0400),
    ("Compressed", 0x0800),
    ("Offline", 0x01000),
    ("NotContentIndexed", 0x02000),
    ("Encrypted", 0x04000),
    ("IntegrityStream", 0x08000),
    ("Virtual", 0x010000),
    ("NoScrubData", 0x020000),
    ("HasEa", 0x040000),
    ("IsDirectory", 0x10000000),
    ("IsIndexView", 0x20000000),
];

/// A file reference (MftInformation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftInformation {
    pub entry_number: u64,
    pub sequence_number: u32,
}

impl MftInformation {
    fn parse(b: &[u8]) -> MftInformation {
        let low = u32::from_le_bytes(b[0..4].try_into().unwrap()) as u64;
        let high = u16::from_le_bytes([b[4], b[5]]) as u64;
        MftInformation { entry_number: low | (high << 32), sequence_number: u16::from_le_bytes([b[6], b[7]]) as u32 }
    }
}

#[derive(Debug, Clone)]
pub struct UsnEntry {
    pub size: i32,
    pub major_version: i16,
    pub minor_version: i16,
    pub file_reference: MftInformation,
    pub parent_file_reference: MftInformation,
    pub update_sequence_number: u64,
    /// The FILETIME; None when it is not valid (the original's DateTimeOffset.MinValue)
    pub update_timestamp: Option<i64>,
    pub update_reasons: u32,
    pub update_sources: u32,
    pub security_descriptor_id: i32,
    pub file_attributes: i32,
    pub name_size: i16,
    pub name_offset: i16,
    pub name: String,
    pub offset_to_data: i64,
}

impl UsnEntry {
    pub fn parse(raw: &[u8], offset: i64) -> Result<UsnEntry, String> {
        let i16_at = |o: usize| i16::from_le_bytes([raw[o], raw[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let major = i16_at(4);
        let extra = match major {
            2 => 0,
            3 => 16,
            _ => return Err(format!("USN record version {major} is not a V2 or V3 record")),
        };
        if raw.len() < 0x3C + extra {
            return Err(format!("USN record is 0x{:X} bytes, shorter than its fixed part", raw.len()));
        }
        let ref_size = 8 + extra / 2;
        let ts = i64::from_le_bytes(raw[32 + extra..40 + extra].try_into().unwrap());
        let name_size = i16_at(56 + extra);
        let name_offset = i16_at(58 + extra);
        let name = if name_offset >= 0 && name_offset as usize <= raw.len() {
            let n = (name_size as i64).min(raw.len() as i64 - name_offset as i64).max(0) as usize;
            net::utf16(&raw[name_offset as usize..name_offset as usize + n - n % 2])
        } else {
            String::new()
        };
        Ok(UsnEntry {
            size: u32_at(0) as i32,
            major_version: major,
            minor_version: i16_at(6),
            file_reference: MftInformation::parse(&raw[8..16]),
            parent_file_reference: MftInformation::parse(&raw[8 + ref_size..16 + ref_size]),
            update_sequence_number: u64::from_le_bytes(raw[24 + extra..32 + extra].try_into().unwrap()),
            update_timestamp: (0..=MAX_FILETIME).contains(&ts).then_some(ts),
            update_reasons: u32_at(40 + extra),
            update_sources: u32_at(44 + extra),
            security_descriptor_id: u32_at(48 + extra) as i32,
            file_attributes: u32_at(52 + extra) as i32,
            name_size,
            name_offset,
            name,
            offset_to_data: offset,
        })
    }
}

pub struct Usn {
    pub entries: Vec<UsnEntry>,
    pub parse_errors: Vec<String>,
}

impl Usn {
    /// Parses a $J (from where its data starts, when the beginning is sparse)
    pub fn parse(b: &[u8]) -> Usn {
        let start = if b.first().copied().unwrap_or(0) != 0 { 0 } else { find_starting_offset(b) };
        Self::parse_from(b, start)
    }

    pub fn parse_from(b: &[u8], start: u64) -> Usn {
        let mut u = Usn { entries: Vec::new(), parse_errors: Vec::new() };
        let len = b.len() as u64;
        let mut position = start;
        while position + 8 <= len {
            let p = position as usize;
            let size = u32::from_le_bytes(b[p..p + 4].try_into().unwrap());
            let major = i16::from_le_bytes([b[p + 4], b[p + 5]]);
            if size == 0 {
                position += 8;
                continue;
            }
            let valid = (MIN_RECORD_SIZE..=MAX_RECORD_SIZE).contains(&size)
                && size % 8 == 0
                && matches!(major, 2..=4)
                && position + size as u64 <= len;
            if !valid {
                position = (position / PAGE_SIZE + 1) * PAGE_SIZE;
                continue;
            }
            if major == 4 {
                position += size as u64;
                continue;
            }
            match UsnEntry::parse(&b[p..p + size as usize], position as i64) {
                Ok(e) => {
                    if e.update_timestamp.is_none() {
                        u.parse_errors.push(format!("Record at 0x{position:X} has an invalid timestamp"));
                    }
                    u.entries.push(e);
                }
                Err(m) => u.parse_errors.push(format!("Record at 0x{position:X} could not be parsed: {m}")),
            }
            position += size as u64;
        }
        u
    }
}

/// UsnFile.FindStartingOffset: where the data of a sparse $J starts (a binary search for the first non-zero
/// 0x90 bytes, then past the zeros)
pub fn find_starting_offset(b: &[u8]) -> u64 {
    if b.first().copied().unwrap_or(0) != 0 {
        return 0;
    }
    let len = b.len() as i64;
    let all_zeros = |at: i64| b[at as usize..((at + 0x90).min(len)) as usize].iter().all(|&x| x == 0);
    let mut last_checked: i64 = 0;
    let mut last_data: i64 = 0;
    let mut current = len / 2;
    let start;
    loop {
        if last_data > 0 && last_data - last_checked < 300 {
            start = last_checked;
            break;
        }
        if current >= len {
            // all zeros (the original does not stop here)
            return len as u64;
        }
        if !all_zeros(current) {
            last_data = current;
            current = last_checked + (current - last_checked) / 2;
        } else {
            if current == last_checked && last_checked + 1 >= len {
                return len as u64;
            }
            last_checked = current;
            let next = current + (len - current) / 2;
            current = if next == current { len } else { next };
        }
    }
    let mut s = start;
    while s < len && b[s as usize] == 0 {
        s += 1;
    }
    s as u64
}

/// UsnRewind's packed key: entry << 16 | sequence
fn key(entry: u64, sequence: u32) -> u64 {
    (entry << 16) | (sequence as u64 & 0xFFFF)
}

const ROOT_KEY: u64 = (5 << 16) | 5;

fn key_to_mft(k: u64) -> Key {
    Key { entry: k >> 16, sequence: (k & 0xFFFF) as i32 }
}

/// Each record's parent path as it was when the record was written: the $MFT's directories are the starting state,
/// and the records are walked newest to oldest (in USN order), undoing renames and moves
pub fn rewind_parent_paths(mft: &Mft, entries: &[UsnEntry]) -> Vec<String> {
    let mut state: HashMap<u64, (String, u64)> = HashMap::new();
    for (k, name, parent) in mft.directory_names() {
        state.insert(key(k.entry, k.sequence as u32), (name.to_string(), key(parent.entry, parent.sequence as u32)));
    }
    let mut cache: HashMap<u64, String> = HashMap::new();
    let mut used: HashSet<u64> = HashSet::new();
    let mut missing: HashSet<u64> = HashSet::new();
    let mut paths = vec![String::new(); entries.len()];

    for i in (0..entries.len()).rev() {
        let e = &entries[i];
        let k = key(e.file_reference.entry_number, e.file_reference.sequence_number);
        let parent_key = key(e.parent_file_reference.entry_number, e.parent_file_reference.sequence_number);
        let mut changed = false;
        if e.update_reasons & REASON_RENAME_OLD_NAME == REASON_RENAME_OLD_NAME {
            if state.get(&k).is_none_or(|(n, p)| *n != e.name || *p != parent_key) {
                state.insert(k, (e.name.clone(), parent_key));
                changed = true;
            }
        } else if !state.contains_key(&k) {
            state.insert(k, (e.name.clone(), parent_key));
            changed = true;
        }
        if changed && (used.contains(&k) || missing.contains(&k)) {
            cache.clear();
            used.clear();
            missing.clear();
        }
        if let Some(p) = cache.get(&parent_key) {
            paths[i] = p.clone();
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut cur = parent_key;
        loop {
            if cur == ROOT_KEY {
                used.insert(cur);
                names.push(".".into());
                break;
            }
            let value = if seen.insert(cur) { state.get(&cur) } else { None };
            let Some((name, parent)) = value else {
                missing.insert(cur);
                let mk = key_to_mft(cur);
                let known = mft.full_path(mk);
                names.push(if known.contains("PathUnknown") {
                    format!(".\\PathUnknown\\Directory with ID 0x{mk}")
                } else {
                    known.into_owned()
                });
                break;
            };
            used.insert(cur);
            names.push(name.clone());
            cur = *parent;
        }
        names.reverse();
        let path = names.join("\\");
        cache.insert(parent_key, path.clone());
        paths[i] = path;
    }
    paths
}
