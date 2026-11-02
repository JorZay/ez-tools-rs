//! $LogFile: the NTFS transaction log (the MFT.LogFile library).
//!
//! Two restart pages, then copies of recent log pages (2 tail pages in LFS 1.1, 32 fast pages in LFS 2.0), then
//! the circular log area. A record is accepted only where its own LSN maps, which keeps stale data out while still
//! finding records from earlier passes. Operations on open attributes are resolved through the checkpoints' open
//! attribute tables.

use std::collections::{HashMap, HashSet};

use crate::mft::attributes::Attribute;
use crate::mft::record::FileRecord;
use crate::mft::{MftEntryInfo, TimestampSource};

const FAST_PAGES: i64 = 32;
const TAIL_PAGES: i64 = 2;
pub const RECORD_HEADER_SIZE: usize = 0x30;
const NTFS_HEADER_SIZE: usize = 0x20;
const NTFS_RESTART_MIN: usize = 0x40;
const GAP_PAGES: u64 = 64;
pub const DEFAULT_FILE_RECORD_SIZE: i64 = 1024;
const MAX_FILETIME: i64 = 2_650_467_743_999_999_999;

pub const RECORD_TYPE_CLIENT: u32 = 1;
pub const RECORD_TYPE_RESTART: u32 = 2;

pub const OPERATION_NAMES: [&str; 0x26] = [
    "Noop",
    "CompensationLogRecord",
    "InitializeFileRecordSegment",
    "DeallocateFileRecordSegment",
    "WriteEndOfFileRecordSegment",
    "CreateAttribute",
    "DeleteAttribute",
    "UpdateResidentValue",
    "UpdateNonresidentValue",
    "UpdateMappingPairs",
    "DeleteDirtyClusters",
    "SetNewAttributeSizes",
    "AddIndexEntryRoot",
    "DeleteIndexEntryRoot",
    "AddIndexEntryAllocation",
    "DeleteIndexEntryAllocation",
    "WriteEndOfIndexBuffer",
    "SetIndexEntryVcnRoot",
    "SetIndexEntryVcnAllocation",
    "UpdateFileNameRoot",
    "UpdateFileNameAllocation",
    "SetBitsInNonresidentBitMap",
    "ClearBitsInNonresidentBitMap",
    "HotFix",
    "EndTopLevelAction",
    "PrepareTransaction",
    "CommitTransaction",
    "ForgetTransaction",
    "OpenNonresidentAttribute",
    "OpenAttributeTableDump",
    "AttributeNamesDump",
    "DirtyPageTableDump",
    "TransactionTableDump",
    "UpdateRecordDataRoot",
    "UpdateRecordDataAllocation",
    "UpdateRelativeDataInIndex",
    "UpdateRelativeDataInIndex2",
    "ZeroEndOfFileRecord",
];

pub mod op {
    pub const NOOP: u16 = 0x00;
    pub const COMPENSATION_LOG_RECORD: u16 = 0x01;
    pub const INITIALIZE_FILE_RECORD_SEGMENT: u16 = 0x02;
    pub const DEALLOCATE_FILE_RECORD_SEGMENT: u16 = 0x03;
    pub const WRITE_END_OF_FILE_RECORD_SEGMENT: u16 = 0x04;
    pub const CREATE_ATTRIBUTE: u16 = 0x05;
    pub const DELETE_ATTRIBUTE: u16 = 0x06;
    pub const UPDATE_RESIDENT_VALUE: u16 = 0x07;
    pub const UPDATE_MAPPING_PAIRS: u16 = 0x09;
    pub const SET_NEW_ATTRIBUTE_SIZES: u16 = 0x0B;
    pub const ADD_INDEX_ENTRY_ROOT: u16 = 0x0C;
    pub const DELETE_INDEX_ENTRY_ROOT: u16 = 0x0D;
    pub const ADD_INDEX_ENTRY_ALLOCATION: u16 = 0x0E;
    pub const DELETE_INDEX_ENTRY_ALLOCATION: u16 = 0x0F;
    pub const SET_INDEX_ENTRY_VCN_ROOT: u16 = 0x11;
    pub const UPDATE_FILE_NAME_ROOT: u16 = 0x13;
    pub const UPDATE_FILE_NAME_ALLOCATION: u16 = 0x14;
    pub const END_TOP_LEVEL_ACTION: u16 = 0x18;
    pub const PREPARE_TRANSACTION: u16 = 0x19;
    pub const COMMIT_TRANSACTION: u16 = 0x1A;
    pub const FORGET_TRANSACTION: u16 = 0x1B;
    pub const OPEN_NONRESIDENT_ATTRIBUTE: u16 = 0x1C;
    pub const OPEN_ATTRIBUTE_TABLE_DUMP: u16 = 0x1D;
    pub const ATTRIBUTE_NAMES_DUMP: u16 = 0x1E;
    pub const DIRTY_PAGE_TABLE_DUMP: u16 = 0x1F;
    pub const TRANSACTION_TABLE_DUMP: u16 = 0x20;
    pub const UPDATE_RECORD_DATA_ROOT: u16 = 0x21;
    pub const ZERO_END_OF_FILE_RECORD: u16 = 0x25;
}

pub fn operation_name(o: u16) -> String {
    OPERATION_NAMES.get(o as usize).map(|s| s.to_string()).unwrap_or_else(|| o.to_string())
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Fixups.Apply: the update sequence array onto the sector ends; false when they did not match
fn apply_fixups(page: &mut [u8]) -> bool {
    let usa_offset = u16_at(page, 4) as usize;
    let usa_count = u16_at(page, 6) as usize;
    if usa_count < 2 || usa_offset < 8 || usa_offset + usa_count * 2 > page.len() {
        return false;
    }
    let usn = u16_at(page, usa_offset);
    let mut ok = true;
    let mut i = 1;
    while i < usa_count && i * 512 <= page.len() {
        let end = i * 512 - 2;
        if u16_at(page, end) != usn {
            ok = false;
        }
        page[end] = page[usa_offset + i * 2];
        page[end + 1] = page[usa_offset + i * 2 + 1];
        i += 1;
    }
    ok
}

#[derive(Debug, Clone)]
pub struct RestartArea {
    pub current_lsn: u64,
    pub log_clients: u16,
    pub flags: u16,
    pub sequence_number_bits: i32,
    pub file_size: i64,
    pub log_page_data_offset: u16,
}

impl RestartArea {
    pub fn clean_dismount(&self) -> bool {
        self.flags & 0x2 == 0x2
    }
}

#[derive(Debug, Clone)]
pub struct RestartPage {
    pub offset: i64,
    pub signature: String,
    pub fixup_ok: bool,
    pub log_page_size: i32,
    pub major_version: i16,
    pub minor_version: i16,
    pub restart_area: Option<RestartArea>,
}

impl RestartPage {
    fn parse(mut page: Vec<u8>, offset: i64) -> RestartPage {
        let signature = ez_common::net::ascii(&page[0..4]);
        let fixup_ok = apply_fixups(&mut page);
        let restart_offset = u16_at(&page, 24) as usize;
        let restart_area = (restart_offset >= 0x1E && restart_offset + 0x30 <= page.len()).then(|| {
            let o = restart_offset;
            RestartArea {
                current_lsn: u64_at(&page, o),
                log_clients: u16_at(&page, o + 8),
                flags: u16_at(&page, o + 14),
                sequence_number_bits: u32_at(&page, o + 16) as i32,
                file_size: u64_at(&page, o + 24) as i64,
                log_page_data_offset: u16_at(&page, o + 38),
            }
        });
        RestartPage {
            offset,
            signature,
            fixup_ok,
            log_page_size: u32_at(&page, 20) as i32,
            minor_version: u16_at(&page, 26) as i16,
            major_version: u16_at(&page, 28) as i16,
            restart_area,
        }
    }

    pub fn is_valid(&self) -> bool {
        (self.signature == "RSTR" || self.signature == "CHKD") && self.restart_area.is_some()
    }
}

/// An NTFS restart area in a client restart record (a checkpoint)
#[derive(Debug, Clone)]
pub struct NtfsRestartArea {
    pub major_version: u32,
    pub minor_version: u32,
    pub open_attribute_table_lsn: u64,
    pub attribute_names_lsn: u64,
}

/// An entry of the open attribute table (from a checkpoint dump, or an OpenNonresidentAttribute record)
#[derive(Debug, Clone)]
pub struct OpenAttribute {
    pub index: u16,
    pub file_reference: MftEntryInfo,
    pub attribute_type: i32,
    pub attribute_name: Option<String>,
    pub defined_at_lsn: u64,
    pub from_checkpoint: bool,
}

const ENTRY_SIZE_V1: usize = 0x28;
const ENTRY_SIZE_V0: usize = 0x2C;

impl OpenAttribute {
    fn parse(index: u16, d: &[u8], o: usize, entry_size: usize, lsn: u64, from_checkpoint: bool) -> OpenAttribute {
        let (reference, attribute_type) = if entry_size >= ENTRY_SIZE_V0 {
            (MftEntryInfo::parse(&d[o + 8..o + 16]), u32_at(d, o + 0x1C) as i32)
        } else {
            (MftEntryInfo::parse(&d[o + 0x10..o + 0x18]), u32_at(d, o + 8) as i32)
        };
        OpenAttribute { index, file_reference: reference, attribute_type, attribute_name: None, defined_at_lsn: lsn, from_checkpoint }
    }

    fn parse_table(d: &[u8], lsn: u64, errors: &mut Vec<String>) -> Vec<OpenAttribute> {
        let mut entries = Vec::new();
        if d.len() < 0x18 {
            return entries;
        }
        let entry_size = u16_at(d, 0) as usize;
        let count = u16_at(d, 2) as usize;
        if entry_size != ENTRY_SIZE_V1 && entry_size != ENTRY_SIZE_V0 {
            errors.push(format!("LSN {lsn}: open attribute table entries of 0x{entry_size:X} bytes are not known"));
            return entries;
        }
        for i in 0..count {
            let o = 0x18 + i * entry_size;
            if o + entry_size > d.len() || o > u16::MAX as usize {
                errors.push(format!("LSN {lsn}: open attribute table has {count} entries, but only {i} fit in 0x{:X} bytes", d.len()));
                break;
            }
            if u32_at(d, o) == 0xFFFF_FFFF {
                entries.push(OpenAttribute::parse(o as u16, d, o, entry_size, lsn, true));
            }
        }
        entries
    }

    fn from_open_record(index: u16, redo: &[u8], undo: &[u8], lsn: u64) -> Option<OpenAttribute> {
        if redo.len() != ENTRY_SIZE_V1 && redo.len() != ENTRY_SIZE_V0 {
            return None;
        }
        let mut e = OpenAttribute::parse(index, redo, 0, redo.len(), lsn, false);
        if redo.len() == ENTRY_SIZE_V1 {
            e.attribute_name = Some(if undo.len() >= 2 { ez_common::net::utf16(&undo[..undo.len() & !1]) } else { String::new() });
        }
        Some(e)
    }

    fn parse_names(d: &[u8]) -> HashMap<u16, String> {
        let mut names = HashMap::new();
        let mut at = 0;
        while at + 4 <= d.len() {
            let index = u16_at(d, at);
            let length = u16_at(d, at + 2) as usize;
            if index == 0 && length == 0 {
                break;
            }
            if at + 4 + length > d.len() {
                break;
            }
            names.insert(index, ez_common::net::utf16(&d[at + 4..at + 4 + (length & !1)]));
            at += 4 + length + 2;
        }
        names
    }
}

/// An index entry in a log record (its key is a $FILE_NAME for $I30 indexes)
#[derive(Debug, Clone)]
pub struct LoggedIndexEntry {
    pub mft_reference: MftEntryInfo,
    pub file_info: Option<crate::mft::attributes::FileInfo>,
}

#[derive(Debug, Clone)]
pub struct LoggedFileNameUpdate {
    pub created: Option<i64>,
    pub content_modified: Option<i64>,
    pub record_modified: Option<i64>,
    pub last_accessed: Option<i64>,
    pub allocated_size: u64,
    pub real_size: u64,
    pub file_attributes: i32,
}

/// NtfsLogRecord.FileTime: a FILETIME, None when not positive or past DateTime's range
pub fn file_time(d: &[u8], o: usize) -> Option<i64> {
    let raw = i64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    (raw > 0 && raw <= MAX_FILETIME).then_some(raw)
}

/// An NTFS client record's data
#[derive(Debug, Clone)]
pub struct NtfsLogRecord {
    pub redo_operation: u16,
    pub undo_operation: u16,
    pub redo_length: u16,
    pub undo_length: u16,
    pub target_attribute: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub cluster_block_offset: u16,
    pub target_block_size: u16,
    pub target_vcn: i64,
    pub lcns: Vec<i64>,
    pub redo_data: Vec<u8>,
    pub undo_data: Vec<u8>,
    pub target_mft_entry: Option<i64>,
    pub file_record: Option<FileRecord>,
    pub redo_attribute: Option<Attribute>,
    pub undo_attribute: Option<Attribute>,
    pub redo_index_entry: Option<LoggedIndexEntry>,
    pub undo_index_entry: Option<LoggedIndexEntry>,
    pub redo_file_name_update: Option<LoggedFileNameUpdate>,
    pub undo_file_name_update: Option<LoggedFileNameUpdate>,
    /// Indices into the log's open attributes
    pub open_attribute_table: Option<Vec<usize>>,
    pub attribute_names: Option<HashMap<u16, String>>,
    pub opened_attribute: Option<usize>,
    pub target_open_attribute: Option<usize>,
    pub target_open_attribute_inferred: bool,
}

const FILE_RECORD_OPERATIONS: [u16; 14] = [
    op::INITIALIZE_FILE_RECORD_SEGMENT,
    op::DEALLOCATE_FILE_RECORD_SEGMENT,
    op::WRITE_END_OF_FILE_RECORD_SEGMENT,
    op::CREATE_ATTRIBUTE,
    op::DELETE_ATTRIBUTE,
    op::UPDATE_RESIDENT_VALUE,
    op::UPDATE_MAPPING_PAIRS,
    op::SET_NEW_ATTRIBUTE_SIZES,
    op::ADD_INDEX_ENTRY_ROOT,
    op::DELETE_INDEX_ENTRY_ROOT,
    op::SET_INDEX_ENTRY_VCN_ROOT,
    op::UPDATE_FILE_NAME_ROOT,
    op::UPDATE_RECORD_DATA_ROOT,
    op::ZERO_END_OF_FILE_RECORD,
];

fn slice(d: &[u8], offset: usize, length: usize, what: &str, errors: &mut Vec<String>, lsn: u64) -> Vec<u8> {
    if length == 0 || offset >= d.len() {
        return Vec::new();
    }
    let mut length = length;
    if offset + length > d.len() {
        errors.push(format!("LSN {lsn}: {what} data at 0x{offset:X} (0x{length:X} bytes) is cut off at 0x{:X}", d.len()));
        length = d.len() - offset;
    }
    d[offset..offset + length].to_vec()
}

impl NtfsLogRecord {
    fn parse(d: &[u8], cluster_size: i64, errors: &mut Vec<String>, warnings: &mut Vec<String>, lsn: u64, opens: &mut Vec<OpenAttribute>) -> NtfsLogRecord {
        let redo_offset = u16_at(d, 4) as usize;
        let undo_offset = u16_at(d, 8) as usize;
        let lcns_to_follow = u16_at(d, 14);
        let mut r = NtfsLogRecord {
            redo_operation: u16_at(d, 0),
            undo_operation: u16_at(d, 2),
            redo_length: u16_at(d, 6),
            undo_length: u16_at(d, 10),
            target_attribute: u16_at(d, 12),
            record_offset: u16_at(d, 16),
            attribute_offset: u16_at(d, 18),
            cluster_block_offset: u16_at(d, 20),
            target_block_size: u16_at(d, 22),
            target_vcn: u64_at(d, 24) as i64,
            lcns: Vec::new(),
            redo_data: Vec::new(),
            undo_data: Vec::new(),
            target_mft_entry: None,
            file_record: None,
            redo_attribute: None,
            undo_attribute: None,
            redo_index_entry: None,
            undo_index_entry: None,
            redo_file_name_update: None,
            undo_file_name_update: None,
            open_attribute_table: None,
            attribute_names: None,
            opened_attribute: None,
            target_open_attribute: None,
            target_open_attribute_inferred: false,
        };
        for i in 0..lcns_to_follow as usize {
            let at = NTFS_HEADER_SIZE + i * 8;
            if at + 8 > d.len() {
                errors.push(format!("LSN {lsn}: {lcns_to_follow} LCNs do not fit in 0x{:X} bytes of client data", d.len()));
                break;
            }
            r.lcns.push(u64_at(d, at) as i64);
        }
        r.redo_data = slice(d, redo_offset, r.redo_length as usize, "redo", errors, lsn);
        r.undo_data = slice(d, undo_offset, r.undo_length as usize, "undo", errors, lsn);
        if FILE_RECORD_OPERATIONS.contains(&r.redo_operation) || FILE_RECORD_OPERATIONS.contains(&r.undo_operation) {
            let record_size = if r.target_block_size > 0 { r.target_block_size as i64 * 512 } else { DEFAULT_FILE_RECORD_SIZE };
            r.target_mft_entry =
                Some(r.target_vcn.wrapping_mul(cluster_size).wrapping_add(r.cluster_block_offset as i64 * 512) / record_size);
        }
        if let Err(m) = r.decode(errors, warnings, lsn, opens) {
            errors.push(format!(
                "LSN {lsn}: {}/{} data could not be decoded: {m}",
                operation_name(r.redo_operation),
                operation_name(r.undo_operation)
            ));
        }
        r
    }

    fn decode(&mut self, errors: &mut Vec<String>, warnings: &mut Vec<String>, lsn: u64, opens: &mut Vec<OpenAttribute>) -> Result<(), String> {
        match self.redo_operation {
            op::OPEN_ATTRIBUTE_TABLE_DUMP => {
                let table = OpenAttribute::parse_table(&self.redo_data, lsn, errors);
                let start = opens.len();
                opens.extend(table);
                self.open_attribute_table = Some((start..opens.len()).collect());
                return Ok(());
            }
            op::ATTRIBUTE_NAMES_DUMP => {
                self.attribute_names = Some(OpenAttribute::parse_names(&self.redo_data));
                return Ok(());
            }
            op::OPEN_NONRESIDENT_ATTRIBUTE => {
                if let Some(o) = OpenAttribute::from_open_record(self.target_attribute, &self.redo_data, &self.undo_data, lsn) {
                    opens.push(o);
                    self.opened_attribute = Some(opens.len() - 1);
                }
                return Ok(());
            }
            _ => {}
        }
        if self.redo_operation == op::INITIALIZE_FILE_RECORD_SEGMENT
            && self.redo_data.len() >= 0x30
            && u32_at(&self.redo_data, 0) == 0x454c4946
        {
            let mut record = vec![0u8; self.redo_data.len().max(DEFAULT_FILE_RECORD_SIZE as usize)];
            record[..self.redo_data.len()].copy_from_slice(&self.redo_data);
            let mut fr = FileRecord::parse(&mut record, self.target_mft_entry.unwrap_or(0), false, lsn);
            warnings.append(&mut fr.warnings);
            self.file_record = Some(fr);
        }
        if self.redo_operation == op::CREATE_ATTRIBUTE {
            self.redo_attribute = parse_attribute(&self.redo_data, lsn, warnings)?;
        }
        if self.undo_operation == op::CREATE_ATTRIBUTE {
            self.undo_attribute = parse_attribute(&self.undo_data, lsn, warnings)?;
        }
        let index_op = |o: u16| o == op::ADD_INDEX_ENTRY_ROOT || o == op::ADD_INDEX_ENTRY_ALLOCATION;
        if index_op(self.redo_operation) && self.redo_data.len() >= 0x10 {
            self.redo_index_entry = Some(index_entry(&self.redo_data, lsn, warnings)?);
        }
        if index_op(self.undo_operation) && self.undo_data.len() >= 0x10 {
            self.undo_index_entry = Some(index_entry(&self.undo_data, lsn, warnings)?);
        }
        let name_op = |o: u16| o == op::UPDATE_FILE_NAME_ROOT || o == op::UPDATE_FILE_NAME_ALLOCATION;
        if name_op(self.redo_operation) && self.redo_data.len() >= 0x38 {
            self.redo_file_name_update = Some(file_name_update(&self.redo_data));
        }
        if name_op(self.undo_operation) && self.undo_data.len() >= 0x38 {
            self.undo_file_name_update = Some(file_name_update(&self.undo_data));
        }
        Ok(())
    }
}

fn parse_attribute(d: &[u8], lsn: u64, warnings: &mut Vec<String>) -> Result<Option<Attribute>, String> {
    if d.len() < 0x18 {
        return Ok(None);
    }
    let mut size = u32_at(d, 4) as i32;
    if size < 0x18 || size as usize > d.len() {
        size = d.len() as i32;
    }
    Attribute::parse(u32_at(d, 0) as i32, &d[..size as usize], &TimestampSource::log_record(lsn), warnings)
}

fn index_entry(d: &[u8], lsn: u64, warnings: &mut Vec<String>) -> Result<LoggedIndexEntry, String> {
    let reference = MftEntryInfo::parse(&d[0..8]);
    let key_length = u16_at(d, 10) as usize;
    let mut file_info = None;
    if key_length >= 0x42 && 0x10 + key_length <= d.len() {
        let source = TimestampSource::log_record(lsn).with_attribute("index entry");
        file_info = Some(crate::mft::attributes::FileInfo::parse(&d[0x10..0x10 + key_length], &source, warnings)?);
    }
    Ok(LoggedIndexEntry { mft_reference: reference, file_info })
}

fn file_name_update(d: &[u8]) -> LoggedFileNameUpdate {
    LoggedFileNameUpdate {
        created: file_time(d, 0),
        content_modified: file_time(d, 8),
        record_modified: file_time(d, 16),
        last_accessed: file_time(d, 24),
        allocated_size: u64_at(d, 32),
        real_size: u64_at(d, 40),
        file_attributes: u32_at(d, 48) as i32,
    }
}

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub file_offset: i64,
    pub lsn: u64,
    pub client_previous_lsn: u64,
    pub client_undo_next_lsn: u64,
    pub client_data_length: u32,
    pub record_type: u32,
    pub transaction_id: u32,
    pub client_data: Vec<u8>,
    pub truncated: bool,
    pub ntfs: Option<NtfsLogRecord>,
    pub restart: Option<NtfsRestartArea>,
    pub transaction_first_lsn: u64,
}

impl LogRecord {
    pub fn record_type_name(&self) -> String {
        match self.record_type {
            RECORD_TYPE_CLIENT => "ClientRecord".into(),
            RECORD_TYPE_RESTART => "ClientRestart".into(),
            t => t.to_string(),
        }
    }
}

pub struct LogFile {
    pub cluster_size: i64,
    pub page_size: i64,
    pub major_version: i16,
    pub minor_version: i16,
    pub sequence_number_bits: i32,
    pub restart_area: RestartArea,
    pub records: Vec<LogRecord>,
    /// Entries of the open attribute tables (NtfsLogRecord's indices point here)
    pub open_attributes: Vec<OpenAttribute>,
    pub parse_errors: Vec<String>,
    /// Invalid timestamp warnings from logged records
    pub warnings: Vec<String>,
    page_data: HashMap<i64, Vec<u8>>,
    log_start: i64,
    log_end: i64,
    data_offset: i64,
}

/// .NET's List.BinarySearch (the index of a match, or the complement of where it would go)
fn net_binary_search(list: &[u64], value: u64) -> i64 {
    let (mut lo, mut hi) = (0i64, list.len() as i64 - 1);
    while lo <= hi {
        let i = lo + ((hi - lo) >> 1);
        match list[i as usize].cmp(&value) {
            std::cmp::Ordering::Equal => return i,
            std::cmp::Ordering::Less => lo = i + 1,
            std::cmp::Ordering::Greater => hi = i - 1,
        }
    }
    !lo
}

impl LogFile {
    pub fn parse(bytes: &[u8], cluster_size: i64) -> Result<LogFile, String> {
        let read = bytes.len() as i64;
        if read > i32::MAX as i64 {
            return Err(format!("$LogFile is 0x{read:X} bytes; at most 2 GB is supported"));
        }
        if read < 0x1000 {
            return Err(format!("$LogFile is only 0x{read:X} bytes"));
        }
        if bytes[..0x1000].iter().all(|&b| b == 0xFF) {
            return Err("$LogFile has not been initialized (all 0xFF)".into());
        }
        let page_size_at = |o: i64| -> i64 {
            let s = u32_at(bytes, o as usize + 20) as i32;
            if (0x200..=0x10000).contains(&s) && s & (s - 1) == 0 { s as i64 } else { 0x1000 }
        };
        let mut restart_pages = Vec::new();
        for offset in [0, page_size_at(0)] {
            if offset + 0x200 > read {
                continue;
            }
            let len = page_size_at(offset).min(read - offset) as usize;
            restart_pages.push(RestartPage::parse(bytes[offset as usize..offset as usize + len].to_vec(), offset));
        }
        let current = restart_pages
            .iter()
            .filter(|t| {
                t.is_valid()
                    && (0x200..=0x10000).contains(&t.log_page_size)
                    && t.log_page_size & (t.log_page_size - 1) == 0
                    && (4..64).contains(&t.restart_area.as_ref().unwrap().sequence_number_bits)
            })
            .fold(None::<&RestartPage>, |best, t| match best {
                Some(b) if b.restart_area.as_ref().unwrap().current_lsn >= t.restart_area.as_ref().unwrap().current_lsn => Some(b),
                _ => Some(t),
            })
            .cloned()
            .ok_or("No valid restart page ('RSTR' or 'CHKD') found")?;
        let mut parse_errors = Vec::new();
        for rp in restart_pages.iter().filter(|t| !t.fixup_ok) {
            parse_errors.push(format!("Restart page at 0x{:X}: fixups do not match (torn write)", rp.offset));
        }
        let area = current.restart_area.clone().unwrap();
        let page_size = current.log_page_size as i64;
        let mut data_offset = area.log_page_data_offset as i64;
        if data_offset < 0x28 || data_offset >= page_size - RECORD_HEADER_SIZE as i64 {
            parse_errors.push(format!("Log page data offset 0x{data_offset:X} is not usable; using 0x40"));
            data_offset = 0x40;
        }
        let copies = if current.major_version >= 2 { FAST_PAGES } else { TAIL_PAGES };
        let log_start = (2 + copies) * page_size;
        let mut log_size = area.file_size;
        if log_size < log_start + page_size || log_size > i32::MAX as i64 {
            log_size = read;
        }
        let log_end = log_size - (log_size - log_start).max(0) % page_size;
        if read < log_end {
            parse_errors.push(format!(
                "$LogFile is 0x{read:X} bytes, but the log is 0x{log_end:X}; the pages after the end of the file are missing"
            ));
        }
        let mut log = LogFile {
            cluster_size,
            page_size,
            major_version: current.major_version,
            minor_version: current.minor_version,
            sequence_number_bits: area.sequence_number_bits,
            restart_area: area,
            records: Vec::new(),
            open_attributes: Vec::new(),
            parse_errors,
            warnings: Vec::new(),
            page_data: HashMap::new(),
            log_start,
            log_end,
            data_offset,
        };
        log.read_pages(bytes, copies);

        let mut records: HashMap<u64, LogRecord> = HashMap::new();
        let mut visited: HashSet<i64> = HashSet::new();
        let mut pages: Vec<i64> = log.page_data.keys().copied().collect();
        pages.sort_unstable();
        for &p in &pages {
            log.walk(p + data_offset, &mut visited, &mut records);
        }
        for &p in &pages {
            let mut at = data_offset;
            while at + RECORD_HEADER_SIZE as i64 <= page_size {
                let lsn = u64_at(&log.page_data[&p], at as usize);
                if !visited.contains(&(p + at)) && log.lsn_to_offset(lsn) == p + at {
                    log.walk(p + at, &mut visited, &mut records);
                }
                at += 8;
            }
        }
        let mut list: Vec<LogRecord> = records.into_values().collect();
        list.sort_by_key(|r| r.lsn);

        let mut errors = std::mem::take(&mut log.parse_errors);
        let mut warnings = Vec::new();
        let mut opens = Vec::new();
        for r in list.iter_mut() {
            if r.record_type == RECORD_TYPE_CLIENT && r.client_data.len() >= NTFS_HEADER_SIZE {
                r.ntfs = Some(NtfsLogRecord::parse(&r.client_data, cluster_size, &mut errors, &mut warnings, r.lsn, &mut opens));
            }
        }
        for r in list.iter_mut() {
            if r.record_type == RECORD_TYPE_RESTART && r.client_data.len() >= NTFS_RESTART_MIN {
                let d = &r.client_data;
                r.restart = Some(NtfsRestartArea {
                    major_version: u32_at(d, 0),
                    minor_version: u32_at(d, 4),
                    open_attribute_table_lsn: u64_at(d, 0x10),
                    attribute_names_lsn: u64_at(d, 0x18),
                });
            }
        }
        log.parse_errors = errors;
        log.warnings = warnings;
        log.records = list;
        log.open_attributes = opens;
        log.resolve_open_attributes();
        log.group_transactions();
        log.page_data.clear();
        Ok(log)
    }

    pub fn lsn_to_offset(&self, lsn: u64) -> i64 {
        let bits = self.sequence_number_bits as u32;
        ((lsn << bits) >> (bits - 3)) as i64
    }

    fn lsn_to_sequence(&self, lsn: u64) -> u64 {
        lsn >> (64 - self.sequence_number_bits as u32)
    }

    fn read_pages(&mut self, bytes: &[u8], copies: i64) {
        let read = bytes.len() as i64;
        let ps = self.page_size;
        // offset -> (is a record page, last LSN or file offset, last end LSN)
        let mut by_offset: HashMap<i64, (bool, u64, u64)> = HashMap::new();
        let mut page = self.log_start;
        while page + ps <= read.min(self.log_end) {
            let mut data = bytes[page as usize..(page + ps) as usize].to_vec();
            if &data[0..4] == b"RCRD" {
                let ok = apply_fixups(&mut data);
                by_offset.insert(page, (true, u64_at(&data, 8), u64_at(&data, 32)));
                if !ok {
                    self.parse_errors.push(format!("Log page at 0x{page:X}: fixups do not match (torn write)"));
                }
                self.page_data.insert(page, data);
            } else {
                by_offset.insert(page, (false, 0, 0));
            }
            page += ps;
        }
        for i in 0..copies {
            let offset = (2 + i) * ps;
            if offset + ps > read.min(self.log_start) {
                break;
            }
            let mut data = bytes[offset as usize..(offset + ps) as usize].to_vec();
            if &data[0..4] != b"RCRD" {
                continue;
            }
            apply_fixups(&mut data);
            let (last_lsn, last_end) = (u64_at(&data, 8), u64_at(&data, 32));
            if last_end == 0 {
                continue;
            }
            let target = self.lsn_to_offset(last_end) / ps * ps;
            if target < self.log_start || target >= self.log_end {
                continue;
            }
            if let Some(&(true, e_last, e_end)) = by_offset.get(&target) {
                let newer = if self.major_version >= 2 { last_lsn > e_last } else { last_end > e_end };
                if !newer {
                    continue;
                }
            }
            by_offset.insert(target, (true, last_lsn, last_end));
            self.page_data.insert(target, data);
        }
    }

    fn next_page(&self, page: i64) -> i64 {
        let next = page + self.page_size;
        if next >= self.log_end { self.log_start } else { next }
    }

    fn walk(&mut self, mut position: i64, visited: &mut HashSet<i64>, records: &mut HashMap<u64, LogRecord>) {
        let ps = self.page_size;
        loop {
            let page = position / ps * ps;
            let at = (position - page) as usize;
            let Some(data) = self.page_data.get(&page) else { return };
            if ps - (at as i64) < RECORD_HEADER_SIZE as i64 || !visited.insert(position) {
                return;
            }
            let lsn = u64_at(data, at);
            if lsn == 0 || self.lsn_to_offset(lsn) != position {
                visited.remove(&position);
                return;
            }
            let h = &data[at..at + RECORD_HEADER_SIZE];
            let mut record = LogRecord {
                file_offset: position,
                lsn,
                client_previous_lsn: u64_at(h, 8),
                client_undo_next_lsn: u64_at(h, 16),
                client_data_length: u32_at(h, 24),
                record_type: u32_at(h, 32),
                transaction_id: u32_at(h, 36),
                client_data: Vec::new(),
                truncated: false,
                ntfs: None,
                restart: None,
                transaction_first_lsn: 0,
            };
            let _ = self.lsn_to_sequence(lsn);
            if !matches!(record.record_type, RECORD_TYPE_CLIENT | RECORD_TYPE_RESTART)
                || record.client_data_length as i64 > self.log_end - self.log_start
            {
                return;
            }
            let total = record.client_data_length as usize;
            let mut client = Vec::with_capacity(total);
            let mut data_page = page;
            let mut data_at = at + RECORD_HEADER_SIZE;
            let mut cur = data;
            while client.len() < total {
                let available = (ps as usize - data_at).min(total - client.len());
                if available > 0 {
                    client.extend_from_slice(&cur[data_at..data_at + available]);
                    data_at += available;
                }
                if client.len() == total {
                    break;
                }
                data_page = self.next_page(data_page);
                match self.page_data.get(&data_page) {
                    Some(d) if data_page != page => cur = d,
                    _ => {
                        record.truncated = true;
                        break;
                    }
                }
                data_at = self.data_offset as usize;
            }
            if record.truncated {
                self.parse_errors.push(format!(
                    "LSN {lsn} at 0x{position:X}: 0x{:X} bytes of client data, only 0x{:X} could be read",
                    record.client_data_length,
                    client.len()
                ));
            }
            record.client_data = client;
            let truncated = record.truncated;
            records.entry(lsn).or_insert(record);
            if truncated {
                return;
            }
            let next = ((data_at + 7) & !7) as i64;
            position = if ps - next < RECORD_HEADER_SIZE as i64 { self.next_page(data_page) + self.data_offset } else { data_page + next };
        }
    }

    fn resolve_open_attributes(&mut self) {
        let records = &self.records;
        let names_by_lsn: HashMap<u64, &HashMap<u16, String>> =
            records.iter().filter_map(|t| t.ntfs.as_ref()?.attribute_names.as_ref().map(|n| (t.lsn, n))).collect();
        let mut names_for: HashMap<u64, u64> = HashMap::new();
        for t in records {
            if let Some(r) = &t.restart {
                if r.open_attribute_table_lsn != 0 {
                    names_for.entry(r.open_attribute_table_lsn).or_insert(r.attribute_names_lsn);
                }
            }
        }
        let mut name_dumps: Vec<u64> = names_by_lsn.keys().copied().collect();
        name_dumps.sort_unstable();
        let mut boundaries: Vec<u64> = records
            .iter()
            .filter(|t| t.record_type == RECORD_TYPE_RESTART && t.restart.as_ref().is_none_or(|r| r.open_attribute_table_lsn == 0))
            .map(|t| t.lsn)
            .collect();
        let gap = self.page_size as u64 * GAP_PAGES / 8;
        for w in records.windows(2) {
            if w[1].lsn - w[0].lsn > gap {
                boundaries.push(w[1].lsn);
            }
        }
        boundaries.sort_unstable();
        let mount = |lsn: u64| -> i64 {
            let at = net_binary_search(&boundaries, lsn);
            if at >= 0 { at + 1 } else { !at }
        };

        let mut definitions: HashMap<(i64, u16), Vec<usize>> = HashMap::new();
        let mut by_index: HashMap<u16, Vec<usize>> = HashMap::new();
        let mut named: Vec<(usize, Option<String>)> = Vec::new();
        for t in records.iter() {
            let Some(n) = &t.ntfs else { continue };
            if let Some(table) = &n.open_attribute_table {
                let mut names: Option<&HashMap<u16, String>> = None;
                match names_for.get(&t.lsn) {
                    Some(&nl) if nl != 0 => names = names_by_lsn.get(&nl).copied(),
                    _ => {
                        let next = name_dumps.iter().copied().find(|&x| x > t.lsn).unwrap_or(0);
                        if next != 0 && mount(next) == mount(t.lsn) {
                            names = Some(names_by_lsn[&next]);
                        }
                    }
                }
                for &i in table {
                    let e = &self.open_attributes[i];
                    let name = names.map(|m| m.get(&e.index).cloned().unwrap_or_default());
                    named.push((i, name));
                    definitions.entry((mount(e.defined_at_lsn), e.index)).or_default().push(i);
                    by_index.entry(e.index).or_default().push(i);
                }
            }
            if let Some(i) = n.opened_attribute {
                let e = &self.open_attributes[i];
                definitions.entry((mount(e.defined_at_lsn), e.index)).or_default().push(i);
                by_index.entry(e.index).or_default().push(i);
            }
        }
        for (i, name) in named {
            self.open_attributes[i].attribute_name = name;
        }
        let lists: Vec<Vec<usize>> = definitions.values().cloned().collect();
        for list in &lists {
            for (k, &i) in list.iter().enumerate() {
                if self.open_attributes[i].attribute_name.is_some() {
                    continue;
                }
                let me = self.open_attributes[i].clone();
                let same = list[k + 1..].iter().map(|&j| &self.open_attributes[j]).find(|t| {
                    t.from_checkpoint
                        && t.attribute_name.is_some()
                        && t.file_reference.entry == me.file_reference.entry
                        && t.file_reference.sequence == me.file_reference.sequence
                        && t.attribute_type == me.attribute_type
                });
                let name = same.and_then(|s| s.attribute_name.clone());
                self.open_attributes[i].attribute_name = name;
            }
        }
        const NO_TARGET: [u16; 10] = [
            op::NOOP,
            op::COMPENSATION_LOG_RECORD,
            op::END_TOP_LEVEL_ACTION,
            op::PREPARE_TRANSACTION,
            op::COMMIT_TRANSACTION,
            op::FORGET_TRANSACTION,
            op::OPEN_ATTRIBUTE_TABLE_DUMP,
            op::ATTRIBUTE_NAMES_DUMP,
            op::DIRTY_PAGE_TABLE_DUMP,
            op::TRANSACTION_TABLE_DUMP,
        ];
        let opens = &self.open_attributes;
        for t in self.records.iter_mut() {
            let lsn = t.lsn;
            let Some(n) = t.ntfs.as_mut() else { continue };
            if n.target_attribute == 0 || NO_TARGET.contains(&n.redo_operation) {
                continue;
            }
            match definitions.get(&(mount(lsn), n.target_attribute)) {
                None => {
                    if let Some(all) = by_index.get(&n.target_attribute) {
                        n.target_open_attribute =
                            Some(all.iter().rev().copied().find(|&i| opens[i].defined_at_lsn <= lsn).unwrap_or(all[0]));
                        n.target_open_attribute_inferred = true;
                    }
                }
                Some(list) => {
                    let mut found = None;
                    for &i in list {
                        if opens[i].defined_at_lsn > lsn {
                            break;
                        }
                        found = Some(i);
                    }
                    n.target_open_attribute = Some(found.unwrap_or(list[0]));
                }
            }
        }
    }

    fn group_transactions(&mut self) {
        let mut first: HashMap<u64, u64> = HashMap::new();
        for r in self.records.iter_mut() {
            let start = if r.client_previous_lsn == 0 || r.client_previous_lsn >= r.lsn {
                r.lsn
            } else {
                first.get(&r.client_previous_lsn).copied().unwrap_or(r.client_previous_lsn)
            };
            first.insert(r.lsn, start);
            r.transaction_first_lsn = start;
        }
    }
}
