//! $LogFile rows as MFTECmd writes them (LogFileRows, LogFileOut): one per log record, ordered by LSN.

use std::collections::HashMap;

use ez_common::csv::{NEW_LINE, field};
use ez_common::json::ServiceStackObject;
use ez_common::net::{enum_name, flags_name};

use crate::logfile::{LogFile, LogRecord, LoggedFileNameUpdate, NtfsLogRecord, OpenAttribute, RECORD_TYPE_RESTART, file_time, op, operation_name};
use crate::mft::attributes::{ATTRIBUTE_TYPE_NAMES, AttributeBody, FileInfo, NAME_TYPE_DOS, SI_FLAG_NAMES, StandardInfo};
use crate::mft::record::{ENTRY_FLAG_NAMES, FileRecord};
use crate::mft::{Key, Mft};
use crate::time::Timestamp;

const RESIDENT_HEADER_SIZE: i64 = 0x18;
const DEFAULT_FIRST_ATTRIBUTE_OFFSET: i64 = 0x38;
const SI_TIMESTAMP_NAMES: [&str; 4] = ["Created", "Modified", "Record changed", "Accessed"];

#[derive(Debug, Clone, Default)]
pub struct LogFileRow {
    pub lsn: u64,
    pub transaction_id: u32,
    pub transaction_first_lsn: u64,
    pub redo_operation: Option<String>,
    pub undo_operation: Option<String>,
    pub target_entry_number: Option<u64>,
    pub target_sequence_number: Option<u32>,
    pub target_attribute_type: Option<String>,
    pub target_attribute_name: Option<String>,
    pub target_path: Option<String>,
    pub entry_number: Option<u64>,
    pub sequence_number: Option<u32>,
    pub file_name: Option<String>,
    pub parent_entry_number: Option<u64>,
    pub parent_sequence_number: Option<u32>,
    pub parent_path: Option<String>,
    pub created_on: Option<i64>,
    pub content_modified_on: Option<i64>,
    pub record_modified_on: Option<i64>,
    pub last_accessed_on: Option<i64>,
    pub file_size: Option<u64>,
    pub file_attributes: Option<String>,
    pub attribute_type: Option<String>,
    pub details: Option<String>,
    pub previous_lsn: u64,
    pub undo_next_lsn: u64,
    pub record_type: String,
    pub target_attribute: Option<u16>,
    pub target_inferred: bool,
    pub target_vcn: Option<i64>,
    pub lcns: Option<String>,
    pub record_offset: Option<u16>,
    pub attribute_offset: Option<u16>,
    pub cluster_block_offset: Option<u16>,
    pub redo_length: Option<u16>,
    pub undo_length: Option<u16>,
    pub truncated: bool,
    pub file_offset: i64,
    pub source_file: String,
}

pub struct LogFileRows<'a> {
    log: &'a LogFile,
    mft: Option<&'a Mft>,
    source_file: String,
    /// Entry number -> block (free records first, then records in use, which win)
    by_entry: HashMap<u64, u32>,
    first_attribute_offset: i64,
    records: HashMap<u32, FileRecord>,
    target_paths: HashMap<i64, Option<String>>,
}

fn opt(t: Option<i64>) -> Option<i64> {
    t.filter(|&r| r > 0)
}

impl<'a> LogFileRows<'a> {
    pub fn new(log: &'a LogFile, mft: Option<&'a Mft>, source_file: &str) -> LogFileRows<'a> {
        let mut by_entry = HashMap::new();
        if let Some(m) = mft {
            for &b in m.free.iter().chain(m.in_use.iter()) {
                by_entry.insert(m.block_keys[b as usize].entry, b);
            }
        }
        // the first attribute offset most logged FILE records have (ties: the one seen first)
        let mut counts: Vec<(i64, usize)> = Vec::new();
        for r in &log.records {
            if let Some(fr) = r.ntfs.as_ref().and_then(|n| n.file_record.as_ref()) {
                if fr.first_attribute_offset > 0 {
                    let o = fr.first_attribute_offset as i64;
                    match counts.iter_mut().find(|(k, _)| *k == o) {
                        Some(c) => c.1 += 1,
                        None => counts.push((o, 1)),
                    }
                }
            }
        }
        let mut best: Option<(i64, usize)> = None;
        for c in counts {
            if best.is_none_or(|b| c.1 > b.1) {
                best = Some(c);
            }
        }
        LogFileRows {
            log,
            mft,
            source_file: source_file.to_string(),
            by_entry,
            first_attribute_offset: best.map(|b| b.0).unwrap_or(DEFAULT_FIRST_ATTRIBUTE_OFFSET),
            records: HashMap::new(),
            target_paths: HashMap::new(),
        }
    }

    fn record(&mut self, block: u32) -> &FileRecord {
        let mft = self.mft.unwrap();
        self.records.entry(block).or_insert_with(|| mft.full_record(block))
    }

    pub fn row(&mut self, record: &LogRecord) -> LogFileRow {
        let mut row = LogFileRow {
            lsn: record.lsn,
            previous_lsn: record.client_previous_lsn,
            undo_next_lsn: record.client_undo_next_lsn,
            transaction_id: record.transaction_id,
            transaction_first_lsn: record.transaction_first_lsn,
            record_type: record.record_type_name(),
            truncated: record.truncated,
            file_offset: record.file_offset,
            source_file: self.source_file.clone(),
            ..Default::default()
        };
        let Some(n) = &record.ntfs else {
            if record.record_type == RECORD_TYPE_RESTART {
                row.details = Some(match &record.restart {
                    Some(r) if r.open_attribute_table_lsn != 0 => format!(
                        "Checkpoint (NTFS restart area {}.{}): open attribute table at LSN {}, attribute names at LSN {}",
                        r.major_version, r.minor_version, r.open_attribute_table_lsn, r.attribute_names_lsn
                    ),
                    _ => "Checkpoint (NTFS restart area), without tables".into(),
                });
            }
            return row;
        };
        row.redo_operation = Some(operation_name(n.redo_operation));
        row.undo_operation = Some(operation_name(n.undo_operation));
        row.target_entry_number = n.target_mft_entry.map(|e| e as u64);
        row.target_attribute = Some(n.target_attribute);
        row.target_vcn = Some(n.target_vcn);
        row.lcns = Some(n.lcns.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("|"));
        row.record_offset = Some(n.record_offset);
        row.attribute_offset = Some(n.attribute_offset);
        row.cluster_block_offset = Some(n.cluster_block_offset);
        row.redo_length = Some(n.redo_length);
        row.undo_length = Some(n.undo_length);
        if let Some(e) = n.target_mft_entry {
            row.target_path = self.target_path(e);
        } else if let Some(i) = n.target_open_attribute {
            let target = self.log.open_attributes[i].clone();
            self.set_open_attribute(&mut row, &target);
            row.target_inferred = n.target_open_attribute_inferred;
        }
        self.decode(n, &mut row);
        row
    }

    fn decode(&mut self, n: &NtfsLogRecord, row: &mut LogFileRow) {
        if let Some(fr) = &n.file_record {
            row.entry_number = Some(fr.entry_number as u64);
            row.sequence_number = Some(fr.sequence_number as u32);
            row.details = Some(format!("FILE record written ({})", flags_name(fr.entry_flags as i64, ENTRY_FLAG_NAMES).replace(", ", "|")));
            let names: Vec<&FileInfo> = fr.file_names().map(|(_, f)| f).collect();
            if let Some(f) = names.iter().find(|f| f.name_type != NAME_TYPE_DOS).or(names.first()) {
                self.set_file_info(row, f);
            }
            if let Some(si) = fr.attributes.iter().find_map(|a| match &a.body {
                AttributeBody::StandardInfo(s) => Some(s),
                _ => None,
            }) {
                set_standard_info(row, si);
            }
            if !fr.is_directory() {
                row.file_size = Some(fr.file_size());
            }
            return;
        }
        if let Some(t) = &n.open_attribute_table {
            row.details = Some(format!("Checkpoint: open attribute table ({} attributes)", ez_common::dotnet::n0(t.len() as u64)));
            return;
        }
        if let Some(names) = &n.attribute_names {
            row.details = Some(format!("Checkpoint: attribute names ({})", ez_common::dotnet::n0(names.len() as u64)));
            return;
        }
        if n.opened_attribute.is_some() {
            row.details = Some("Attribute opened".into());
            return;
        }
        match n.redo_operation {
            op::DEALLOCATE_FILE_RECORD_SEGMENT => row.details = Some("FILE record freed".into()),
            op::CREATE_ATTRIBUTE if n.redo_attribute.is_some() => {
                self.set_attribute(row, n.redo_attribute.as_ref().unwrap(), n.target_mft_entry, "Attribute created")
            }
            op::DELETE_ATTRIBUTE if n.undo_attribute.is_some() => {
                self.set_attribute(row, n.undo_attribute.as_ref().unwrap(), n.target_mft_entry, "Attribute deleted")
            }
            op::ADD_INDEX_ENTRY_ROOT | op::ADD_INDEX_ENTRY_ALLOCATION if n.redo_index_entry.is_some() => {
                self.set_index_entry(row, n.redo_index_entry.as_ref().unwrap(), "Index entry added")
            }
            op::DELETE_INDEX_ENTRY_ROOT | op::DELETE_INDEX_ENTRY_ALLOCATION if n.undo_index_entry.is_some() => {
                self.set_index_entry(row, n.undo_index_entry.as_ref().unwrap(), "Index entry deleted")
            }
            op::UPDATE_FILE_NAME_ROOT | op::UPDATE_FILE_NAME_ALLOCATION if n.redo_file_name_update.is_some() => {
                set_file_name_update(row, n.redo_file_name_update.as_ref().unwrap(), n.undo_file_name_update.as_ref())
            }
            op::UPDATE_RESIDENT_VALUE => self.set_resident_value(row, n),
            _ => {}
        }
    }

    fn set_open_attribute(&mut self, row: &mut LogFileRow, target: &OpenAttribute) {
        let r = target.file_reference;
        row.target_entry_number = Some(r.entry);
        row.target_sequence_number = Some(r.sequence as u32);
        row.target_attribute_type = Some(enum_name(target.attribute_type as i64, ATTRIBUTE_TYPE_NAMES));
        row.target_attribute_name = target.attribute_name.clone();
        let Some(mft) = self.mft else { return };
        let Some(block) = mft.find(r.key()) else { return };
        let ty = target.attribute_type;
        let path = {
            let fr = self.record(block);
            if row.target_attribute_name.is_none() {
                let mut names: Vec<String> = Vec::new();
                for a in fr.attributes.iter().filter(|a| a.header.attribute_type == ty) {
                    if !names.contains(&a.header.name) {
                        names.push(a.header.name.clone());
                    }
                }
                if names.len() == 1 {
                    row.target_attribute_name = Some(names.remove(0));
                }
            }
            if r.entry == 5 { Some(".".to_string()) } else { path_of(mft, fr) }
        };
        row.target_path = path;
    }

    fn target_path(&mut self, entry: i64) -> Option<String> {
        let mft = self.mft?;
        if let Some(p) = self.target_paths.get(&entry) {
            return p.clone();
        }
        let path = match self.by_entry.get(&(entry as u64)).copied() {
            Some(b) if entry >= 0 => {
                let fr = self.record(b);
                if entry == 5 { Some(".".to_string()) } else { path_of(mft, fr) }
            }
            _ => None,
        };
        self.target_paths.insert(entry, path.clone());
        path
    }

    fn set_attribute(&mut self, row: &mut LogFileRow, a: &crate::mft::attributes::Attribute, entry: Option<i64>, what: &str) {
        row.attribute_type = Some(enum_name(a.header.attribute_type as i64, ATTRIBUTE_TYPE_NAMES));
        row.details = Some(if a.header.name.is_empty() { what.to_string() } else { format!("{what} (named '{}')", a.header.name) });
        if let Some(e) = entry {
            row.entry_number = Some(e as u64);
        }
        match &a.body {
            AttributeBody::FileName(f) => self.set_file_info(row, f),
            AttributeBody::StandardInfo(si) => set_standard_info(row, si),
            AttributeBody::Data(d) => {
                if a.header.resident {
                    if let Some(r) = &d.resident {
                        row.file_size = Some(r.len() as u64);
                    }
                } else if let Some(n) = &d.non_resident {
                    row.file_size = Some(n.actual_size);
                }
            }
            _ => {}
        }
    }

    fn set_index_entry(&mut self, row: &mut LogFileRow, e: &crate::logfile::LoggedIndexEntry, what: &str) {
        let Some(fi) = &e.file_info else {
            row.details = Some(format!("{what} (not a file name index)"));
            return;
        };
        row.details = Some(what.to_string());
        row.entry_number = Some(e.mft_reference.entry);
        row.sequence_number = Some(e.mft_reference.sequence as u32);
        row.attribute_type = Some("FileName".into());
        self.set_file_info(row, fi);
    }

    fn set_resident_value(&mut self, row: &mut LogFileRow, n: &NtfsLogRecord) {
        let Some(entry) = n.target_mft_entry else { return };
        if n.record_offset as i64 != self.first_attribute_offset_of(entry) || (n.attribute_offset as i64) < RESIDENT_HEADER_SIZE {
            return;
        }
        let value_offset = n.attribute_offset as i64 - RESIDENT_HEADER_SIZE;
        let mut changed = Vec::new();
        let mut previous = Vec::new();
        let mut values: [Option<i64>; 4] = [None; 4];
        for (i, value) in values.iter_mut().enumerate() {
            let at = i as i64 * 8 - value_offset;
            if at < 0 || at + 8 > n.redo_data.len() as i64 {
                continue;
            }
            *value = file_time(&n.redo_data, at as usize);
            changed.push(SI_TIMESTAMP_NAMES[i]);
            if at + 8 <= n.undo_data.len() as i64 {
                let before = file_time(&n.undo_data, at as usize)
                    .and_then(Timestamp::from_filetime)
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "(none)".into());
                previous.push(format!("{} {before}", SI_TIMESTAMP_NAMES[i]));
            }
        }
        if changed.is_empty() {
            return;
        }
        row.attribute_type = Some("StandardInformation".into());
        row.created_on = values[0];
        row.content_modified_on = values[1];
        row.record_modified_on = values[2];
        row.last_accessed_on = values[3];
        row.entry_number = Some(entry as u64);
        let mut details = format!("$STANDARD_INFORMATION timestamps changed: {}", changed.join(", "));
        if !previous.is_empty() {
            details.push_str(&format!("; previous: {}", previous.join(", ")));
        }
        row.details = Some(details);
    }

    fn first_attribute_offset_of(&mut self, entry: i64) -> i64 {
        if entry >= 0 {
            if let Some(&b) = self.by_entry.get(&(entry as u64)) {
                if self.mft.is_some() {
                    let o = self.record(b).first_attribute_offset as i64;
                    if o > 0 {
                        return o;
                    }
                }
            }
        }
        self.first_attribute_offset
    }

    fn set_file_info(&self, row: &mut LogFileRow, f: &FileInfo) {
        row.file_name = Some(f.file_name.clone());
        row.parent_entry_number = Some(f.parent.entry);
        row.parent_sequence_number = Some(f.parent.sequence as u32);
        row.created_on = opt(Some(f.created));
        row.content_modified_on = opt(Some(f.content_modified));
        row.record_modified_on = opt(Some(f.record_modified));
        row.last_accessed_on = opt(Some(f.last_accessed));
        row.file_size = Some(f.logical_size);
        row.file_attributes = Some(si_flags(f.flags));
        if let Some(m) = self.mft {
            row.parent_path = Some(m.full_path(f.parent.key()).into_owned());
        }
    }
}

fn si_flags(f: i32) -> String {
    flags_name(f as i64, SI_FLAG_NAMES).replace(", ", "|")
}

fn set_standard_info(row: &mut LogFileRow, si: &StandardInfo) {
    row.created_on = opt(Some(si.created));
    row.content_modified_on = opt(Some(si.content_modified));
    row.record_modified_on = opt(Some(si.record_modified));
    row.last_accessed_on = opt(Some(si.last_accessed));
    row.file_attributes = Some(si_flags(si.flags));
}

fn set_file_name_update(row: &mut LogFileRow, redo: &LoggedFileNameUpdate, undo: Option<&LoggedFileNameUpdate>) {
    row.attribute_type = Some("FileName".into());
    row.created_on = redo.created;
    row.content_modified_on = redo.content_modified;
    row.record_modified_on = redo.record_modified;
    row.last_accessed_on = redo.last_accessed;
    row.file_size = Some(redo.real_size);
    row.file_attributes = Some(si_flags(redo.file_attributes));
    let mut details = String::from("Directory entry updated");
    if let Some(u) = undo {
        let mut previous = Vec::new();
        let mut add = |name: &str, before: Option<i64>, after: Option<i64>| {
            if before != after {
                let b = before.and_then(Timestamp::from_filetime).map(|t| t.to_string()).unwrap_or_else(|| "(none)".into());
                previous.push(format!("{name} {b}"));
            }
        };
        add("Created", u.created, redo.created);
        add("Modified", u.content_modified, redo.content_modified);
        add("Record changed", u.record_modified, redo.record_modified);
        add("Accessed", u.last_accessed, redo.last_accessed);
        if u.real_size != redo.real_size {
            previous.push(format!("Size {}", u.real_size));
        }
        if !previous.is_empty() {
            details.push_str(&format!("; previous: {}", previous.join(", ")));
        }
    }
    row.details = Some(details);
}

/// PathOf: a record's parent path and name (its first name that is not a DOS name)
fn path_of(mft: &Mft, fr: &FileRecord) -> Option<String> {
    let names: Vec<&FileInfo> = fr.file_names().map(|(_, f)| f).collect();
    let f = names.iter().find(|f| f.name_type != NAME_TYPE_DOS).or(names.first())?;
    Some(format!("{}\\{}", mft.full_path(Key { entry: f.parent.entry, sequence: f.parent.sequence as i32 }), f.file_name))
}

pub const CSV_HEADER: &str = "Lsn,TransactionId,TransactionFirstLsn,RedoOperation,UndoOperation,TargetEntryNumber,TargetSequenceNumber,TargetAttributeType,TargetAttributeName,TargetPath,EntryNumber,SequenceNumber,FileName,ParentEntryNumber,ParentSequenceNumber,ParentPath,CreatedOn,ContentModifiedOn,RecordModifiedOn,LastAccessedOn,FileSize,FileAttributes,AttributeType,Details,PreviousLsn,UndoNextLsn,RecordType,TargetAttribute,TargetInferred,TargetVcn,Lcns,RecordOffset,AttributeOffset,ClusterBlockOffset,RedoLength,UndoLength,Truncated,FileOffset,SourceFile\r\n";

/// Appends a CSV line
pub fn write_csv(out: &mut String, r: &LogFileRow, dt: &str) {
    let t = |v: Option<i64>| v.and_then(Timestamp::from_filetime).map(|t| t.format(dt)).unwrap_or_default();
    let n = |v: Option<String>| v.unwrap_or_default();
    let fields: [String; 39] = [
        r.lsn.to_string(),
        r.transaction_id.to_string(),
        r.transaction_first_lsn.to_string(),
        n(r.redo_operation.clone()),
        n(r.undo_operation.clone()),
        n(r.target_entry_number.map(|v| v.to_string())),
        n(r.target_sequence_number.map(|v| v.to_string())),
        n(r.target_attribute_type.clone()),
        n(r.target_attribute_name.clone()),
        n(r.target_path.clone()),
        n(r.entry_number.map(|v| v.to_string())),
        n(r.sequence_number.map(|v| v.to_string())),
        n(r.file_name.clone()),
        n(r.parent_entry_number.map(|v| v.to_string())),
        n(r.parent_sequence_number.map(|v| v.to_string())),
        n(r.parent_path.clone()),
        t(r.created_on),
        t(r.content_modified_on),
        t(r.record_modified_on),
        t(r.last_accessed_on),
        n(r.file_size.map(|v| v.to_string())),
        n(r.file_attributes.clone()),
        n(r.attribute_type.clone()),
        n(r.details.clone()),
        r.previous_lsn.to_string(),
        r.undo_next_lsn.to_string(),
        r.record_type.clone(),
        n(r.target_attribute.map(|v| v.to_string())),
        if r.target_inferred { "True" } else { "False" }.into(),
        n(r.target_vcn.map(|v| v.to_string())),
        n(r.lcns.clone()),
        n(r.record_offset.map(|v| v.to_string())),
        n(r.attribute_offset.map(|v| v.to_string())),
        n(r.cluster_block_offset.map(|v| v.to_string())),
        n(r.redo_length.map(|v| v.to_string())),
        n(r.undo_length.map(|v| v.to_string())),
        if r.truncated { "True" } else { "False" }.into(),
        r.file_offset.to_string(),
        r.source_file.clone(),
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        field(out, f);
    }
    out.push_str(NEW_LINE);
}

/// Appends a JSON line
pub fn write_json(out: &mut String, r: &LogFileRow) {
    let mut j = ServiceStackObject::new();
    let num = |j: &mut ServiceStackObject, name: &str, v: Option<String>| {
        if let Some(v) = v {
            j.raw(name, &v);
        }
    };
    j.number("Lsn", r.lsn).number("TransactionId", r.transaction_id).number("TransactionFirstLsn", r.transaction_first_lsn);
    j.string("RedoOperation", r.redo_operation.as_deref()).string("UndoOperation", r.undo_operation.as_deref());
    num(&mut j, "TargetEntryNumber", r.target_entry_number.map(|v| v.to_string()));
    num(&mut j, "TargetSequenceNumber", r.target_sequence_number.map(|v| v.to_string()));
    j.string("TargetAttributeType", r.target_attribute_type.as_deref())
        .string("TargetAttributeName", r.target_attribute_name.as_deref())
        .string("TargetPath", r.target_path.as_deref());
    num(&mut j, "EntryNumber", r.entry_number.map(|v| v.to_string()));
    num(&mut j, "SequenceNumber", r.sequence_number.map(|v| v.to_string()));
    j.string("FileName", r.file_name.as_deref());
    num(&mut j, "ParentEntryNumber", r.parent_entry_number.map(|v| v.to_string()));
    num(&mut j, "ParentSequenceNumber", r.parent_sequence_number.map(|v| v.to_string()));
    j.string("ParentPath", r.parent_path.as_deref());
    for (name, v) in [
        ("CreatedOn", r.created_on),
        ("ContentModifiedOn", r.content_modified_on),
        ("RecordModifiedOn", r.record_modified_on),
        ("LastAccessedOn", r.last_accessed_on),
    ] {
        num(&mut j, name, v.and_then(Timestamp::from_filetime).map(|t| format!("\"{}\"", t.to_json_string())));
    }
    num(&mut j, "FileSize", r.file_size.map(|v| v.to_string()));
    j.string("FileAttributes", r.file_attributes.as_deref())
        .string("AttributeType", r.attribute_type.as_deref())
        .string("Details", r.details.as_deref())
        .number("PreviousLsn", r.previous_lsn)
        .number("UndoNextLsn", r.undo_next_lsn)
        .string("RecordType", Some(&r.record_type));
    num(&mut j, "TargetAttribute", r.target_attribute.map(|v| v.to_string()));
    j.bool("TargetInferred", r.target_inferred);
    num(&mut j, "TargetVcn", r.target_vcn.map(|v| v.to_string()));
    j.string("Lcns", r.lcns.as_deref());
    num(&mut j, "RecordOffset", r.record_offset.map(|v| v.to_string()));
    num(&mut j, "AttributeOffset", r.attribute_offset.map(|v| v.to_string()));
    num(&mut j, "ClusterBlockOffset", r.cluster_block_offset.map(|v| v.to_string()));
    num(&mut j, "RedoLength", r.redo_length.map(|v| v.to_string()));
    num(&mut j, "UndoLength", r.undo_length.map(|v| v.to_string()));
    j.bool("Truncated", r.truncated).number("FileOffset", r.file_offset).string("SourceFile", Some(&r.source_file));
    out.push_str(&j.finish());
    out.push('\n');
}
