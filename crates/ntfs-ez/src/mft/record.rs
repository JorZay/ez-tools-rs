//! A FILE record: fixups (the last 2 bytes of each 512 byte sector), the header, then attributes until the end
//! marker, within the allocated size.

use super::attributes::{Attribute, AttributeBody, FileInfo, NAME_TYPE_DOS, types};
use super::{MftEntryInfo, TimestampSource};

const BAAD_SIG: i32 = 0x44414142;
const FILE_SIG: i32 = 0x454c4946;
const HEADER_SIZE: usize = 0x30;
const MIN_ATTRIBUTE_SIZE: i32 = 0x18;

pub mod entry_flags {
    pub const IN_USE: i16 = 0x1;
    pub const IS_DIRECTORY: i16 = 0x2;
    pub const IS_METADATA_RECORD: i16 = 0x4;
    pub const IS_INDEX_VIEW: i16 = 0x8;
}

pub const ENTRY_FLAG_NAMES: &[(&str, i64)] =
    &[("IsFree", 0), ("InUse", 1), ("IsDirectory", 2), ("IsMetaDataRecord", 4), ("IsIndexView", 8)];

#[derive(Debug, Clone, Default)]
pub struct FileRecord {
    /// Where the record is in the $MFT
    pub offset: i64,
    pub is_bad: bool,
    pub is_uninitialized: bool,
    pub fixup_offset: i16,
    pub fixup_entry_count: i16,
    pub entry_flags: i16,
    /// The fixup array as stored (expected value, then the original sector ends)
    pub fixup_raw: Vec<u8>,
    pub fixup_ok: bool,
    pub log_sequence_number: i64,
    pub sequence_number: u16,
    pub reference_count: i16,
    pub first_attribute_offset: i16,
    pub actual_record_size: i32,
    pub allocated_record_size: i32,
    /// For an extension record, its base record
    pub base_record: MftEntryInfo,
    pub first_available_attribute_id: i16,
    pub entry_number: u32,
    pub attributes: Vec<Attribute>,
    /// Problems in the record; the attributes that parsed are kept
    pub parse_errors: Vec<String>,
    /// Messages the original logs as warnings (fixup mismatches, invalid timestamps)
    pub warnings: Vec<String>,
    /// Where the slack after the attributes starts
    pub slack_start: usize,
}

impl FileRecord {
    /// Parses a record (`raw` is changed: the fixups are applied to it)
    pub fn parse(raw: &mut [u8], offset: i64, apply_fixups: bool, log_lsn: u64) -> FileRecord {
        let mut r = FileRecord { offset, ..Default::default() };
        if raw.len() < HEADER_SIZE {
            r.parse_errors.push(format!("Record is only 0x{:X} bytes; the header needs 0x{HEADER_SIZE:X}", raw.len()));
            r.is_bad = true;
            return r;
        }
        match i32::from_le_bytes(raw[0..4].try_into().unwrap()) {
            FILE_SIG => {}
            BAAD_SIG => {
                r.is_bad = true;
                return r;
            }
            _ => {
                r.is_uninitialized = true;
                return r;
            }
        }
        let rd16 = |b: &[u8], o: usize| i16::from_le_bytes([b[o], b[o + 1]]);
        r.fixup_offset = rd16(raw, 0x4);
        r.fixup_entry_count = rd16(raw, 0x6);
        r.entry_flags = rd16(raw, 0x16);
        let fixup_total = r.fixup_entry_count as i64 * 2;

        if !apply_fixups {
            r.fixup_raw = vec![0, 0];
            r.fixup_ok = true;
        } else if r.fixup_offset < 0 || r.fixup_entry_count < 1 || r.fixup_offset as i64 + fixup_total > raw.len() as i64 {
            r.parse_errors.push(format!(
                "Fixup array at 0x{:X} with 0x{:X} entries does not fit in the record; fixups not applied",
                r.fixup_offset, r.fixup_entry_count
            ));
            r.fixup_raw = vec![0, 0];
        } else {
            let fo = r.fixup_offset as usize;
            let buffer = raw[fo..fo + fixup_total as usize].to_vec();
            let expected = i16::from_le_bytes([buffer[0], buffer[1]]);
            r.fixup_ok = true;
            let mut counter = 512usize;
            let mut actual = 2usize;
            while actual + 2 <= buffer.len() {
                let at = counter - 2;
                if at + 2 > raw.len() {
                    break;
                }
                let found = rd16(raw, at);
                if found != expected && r.entry_flags != 0 {
                    r.fixup_ok = false;
                    r.warnings.push(format!(
                        "Offset: 0x{:X} Entry/seq: 0x{:X}/0x{:X} Fixup values do not match at 0x{at:X}. Expected: 0x{:02X}, actual: 0x{:02X}",
                        offset,
                        u32::from_le_bytes(raw[0x2c..0x30].try_into().unwrap()),
                        u16::from_le_bytes([raw[0x10], raw[0x11]]),
                        expected,
                        found
                    ));
                }
                raw[at..at + 2].copy_from_slice(&buffer[actual..actual + 2]);
                counter += 512;
                actual += 2;
            }
            r.fixup_raw = buffer;
        }

        r.log_sequence_number = i64::from_le_bytes(raw[0x8..0x10].try_into().unwrap());
        r.sequence_number = u16::from_le_bytes([raw[0x10], raw[0x11]]);
        r.reference_count = rd16(raw, 0x12);
        r.first_attribute_offset = rd16(raw, 0x14);
        r.actual_record_size = i32::from_le_bytes(raw[0x18..0x1c].try_into().unwrap());
        r.allocated_record_size = i32::from_le_bytes(raw[0x1c..0x20].try_into().unwrap());
        r.base_record = MftEntryInfo::parse(&raw[0x20..0x28]);
        r.first_available_attribute_id = rd16(raw, 0x28);
        r.entry_number = if r.fixup_offset as usize >= HEADER_SIZE && r.fixup_offset >= 0 {
            u32::from_le_bytes(raw[0x2c..0x30].try_into().unwrap())
        } else {
            (offset / raw.len() as i64) as u32
        };

        let len = raw.len() as i64;
        let end = if r.allocated_record_size > 0 && r.allocated_record_size as i64 <= len { r.allocated_record_size as i64 } else { len };
        let used = if r.actual_record_size > 0 && r.actual_record_size as i64 <= end { r.actual_record_size as i64 } else { end };
        let source = TimestampSource::file_record(r.entry_number, r.sequence_number, offset, log_lsn);

        let mut index = r.first_attribute_offset as i64;
        if index < HEADER_SIZE as i64 - 8 || index > end {
            r.parse_errors.push(format!("First attribute offset 0x{:X} is outside the record", r.first_attribute_offset));
            index = end;
        }
        while index + 8 <= end {
            let i = index as usize;
            let attr_type = i32::from_le_bytes(raw[i..i + 4].try_into().unwrap());
            let attr_size = i32::from_le_bytes(raw[i + 4..i + 8].try_into().unwrap());
            if attr_size == 0 || attr_type == types::END_OF_ATTRIBUTES {
                index += 8;
                break;
            }
            let past_used = index >= used;
            if attr_size < MIN_ATTRIBUTE_SIZE || attr_size as i64 > end - index {
                if !past_used {
                    r.parse_errors.push(format!(
                        "Attribute {} at 0x{index:X} has size 0x{attr_size:X}; 0x{:X} bytes are left in the record",
                        super::attributes::attribute_type_name(attr_type),
                        end - index
                    ));
                }
                break;
            }
            let raw_attr = &raw[i..i + attr_size as usize];
            let mut warnings = Vec::new();
            match Attribute::parse(attr_type, raw_attr, &source, &mut warnings) {
                Ok(Some(a)) => {
                    r.warnings.append(&mut warnings);
                    r.attributes.push(a);
                }
                Ok(None) => {
                    if past_used {
                        break;
                    }
                    r.parse_errors.push(format!("Unknown attribute type 0x{attr_type:X} at 0x{index:X}; skipped"));
                }
                Err(e) => {
                    r.warnings.append(&mut warnings);
                    if past_used {
                        break;
                    }
                    r.parse_errors.push(format!(
                        "Attribute {} at 0x{index:X} could not be parsed: {e}",
                        super::attributes::attribute_type_name(attr_type)
                    ));
                }
            }
            index += attr_size as i64;
        }
        r.slack_start = index.clamp(0, len) as usize;
        r
    }

    pub fn is_deleted(&self) -> bool {
        self.entry_flags & entry_flags::IN_USE != entry_flags::IN_USE
    }

    pub fn is_directory(&self) -> bool {
        self.entry_flags & entry_flags::IS_DIRECTORY == entry_flags::IS_DIRECTORY
    }

    /// An extension record (the original's test: base entry and sequence both above 0)
    pub fn is_extension(&self) -> bool {
        self.base_record.entry > 0 && self.base_record.sequence > 0
    }

    /// The record's key: entry and sequence number (a deleted record's sequence number - 1)
    pub fn key(&self) -> Key {
        Key { entry: self.entry_number as u64, sequence: self.sequence_number as i32 - self.is_deleted() as i32 }
    }

    pub fn file_names(&self) -> impl Iterator<Item = (&Attribute, &FileInfo)> {
        self.attributes.iter().filter_map(|a| a.file_name().map(|f| (a, f)))
    }

    /// GetReferenceCount: the distinct names (not DOS names) and parents
    pub fn name_count(&self) -> i32 {
        let mut seen: Vec<(&str, Key)> = Vec::new();
        for (_, f) in self.file_names() {
            if f.name_type == NAME_TYPE_DOS {
                continue;
            }
            let k = (f.file_name.as_str(), f.parent.key());
            if !seen.contains(&k) {
                seen.push(k);
            }
        }
        seen.len() as i32
    }

    /// GetFileSize: 0 for directories; the first $DATA's size, else the first $FILE_NAME's logical size
    pub fn file_size(&self) -> u64 {
        if self.is_directory() {
            return 0;
        }
        if let Some(d) = self.attributes.iter().find_map(|a| match &a.body {
            AttributeBody::Data(d) => Some(d),
            _ => None,
        }) {
            return match (&d.resident, &d.non_resident) {
                (Some(r), _) => r.len() as u64,
                (None, Some(n)) => n.actual_size,
                _ => 0,
            };
        }
        self.file_names().next().map(|(_, f)| f.logical_size).unwrap_or(0)
    }
}

/// A record key, as the original writes it: `{entry:X8}-{sequence:X8}`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Key {
    pub entry: u64,
    pub sequence: i32,
}

impl Key {
    pub const ROOT: Key = Key { entry: 5, sequence: 5 };
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08X}-{:08X}", self.entry, self.sequence)
    }
}
