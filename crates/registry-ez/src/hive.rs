//! RegistryHive: a hive's keys and values, with deleted keys and values recovered and transaction logs applied, as
//! the Registry library (2026.10.1) builds them.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use ez_common::net::{self, NetResult};
use ez_common::{Diagnostic, Level, Timestamp};
use indexmap::IndexMap;

use crate::cells::*;
use crate::header::{HiveType, Header, REGF_SIGNATURE};
use crate::replay::{self, LogFile};

/// A key: an index into [`Hive::keys`]
pub type KeyId = usize;
/// A value record: an index into [`Hive::vks`]
pub type VkId = usize;

pub const KEY_DELETED: u8 = 1;
pub const KEY_HAS_ACTIVE_PARENT: u8 = 2;

/// RegistryKey
#[derive(Debug)]
pub struct Key {
    pub nk: usize,
    pub parent: Option<KeyId>,
    pub subkeys: Vec<KeyId>,
    pub values: Vec<VkId>,
    pub flags: u8,
    pub path: String,
    pub class_name: String,
}

/// What CellRecords holds at an offset
#[derive(Debug, Clone, Copy)]
enum CellRef {
    Nk(usize),
    Vk(usize),
    /// sk and lk records (only their presence matters here)
    Other,
}

/// A record HBinRecord.Process makes
enum Record {
    Nk(Nk),
    Vk(Vk),
    Other(i64),
    List(i64, List),
}

/// KeyValue.ValueData's object: bytes, text, a time stamp or an unsigned number
#[derive(Debug, Clone)]
pub enum ValueObj {
    Bytes(Vec<u8>),
    Text(String),
    FileTime(Timestamp),
    UInt(u64),
}

impl ValueObj {
    /// KeyValue.ValueData: bytes as BitConverter.ToString writes them, anything else as ToString() (en-US)
    pub fn text(&self) -> String {
        match self {
            ValueObj::Bytes(b) => net::hex(b),
            ValueObj::Text(s) => s.clone(),
            ValueObj::FileTime(t) => en_us_date(*t),
            ValueObj::UInt(v) => v.to_string(),
        }
    }
}

/// A key name or path in the form OrdinalIgnoreCase compares them (simple uppercase mapping)
pub fn fold(s: &str) -> String {
    s.chars().map(upper_char).collect()
}

pub use ez_common::dotnet::{lower_invariant_char as lower_char, upper_invariant_char as upper_char};

/// string.ToLowerInvariant
pub fn lower(s: &str) -> String {
    s.chars().map(lower_char).collect()
}

/// string.ToUpperInvariant
pub fn upper(s: &str) -> String {
    fold(s)
}

/// IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0
pub fn contains_ignore_case(haystack: &str, term: &str) -> bool {
    fold(haystack).contains(&fold(term))
}

/// Helpers.StripRootKeyNameFromKeyPath: the path after the first backslash (all of it when there is none)
pub fn strip_root(path: &str) -> &str {
    match path.find('\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

pub struct Hive {
    pub bytes: Vec<u8>,
    pub path: String,
    pub header: Header,
    pub hive_type: HiveType,
    pub recover_deleted: bool,
    pub nks: Vec<Nk>,
    pub vks: Vec<Vk>,
    pub keys: Vec<Key>,
    pub root: Option<KeyId>,
    cells: IndexMap<i64, CellRef>,
    lists: IndexMap<i64, List>,
    offset_map: HashMap<i64, KeyId>,
    /// _keyPathKeyMap: the folded path, the path as first added, the key
    path_map: IndexMap<String, (String, KeyId)>,
    total_bytes_read: i64,
    messages: RefCell<Vec<Diagnostic>>,
}

/// An error from opening a hive (the message of the exception the Registry library throws)
pub type HiveError = String;

impl Hive {
    /// RegistryHive(bytes, path): checks the signature and reads the base block
    pub fn new(bytes: Vec<u8>, path: &str) -> Result<Hive, HiveError> {
        let messages = RefCell::new(Vec::new());
        let sig = net::i32_at(&bytes, 0)?;
        if sig != REGF_SIGNATURE {
            messages.borrow_mut().push(Diagnostic {
                level: Level::Error,
                message: "Data in byte array is not a Registry hive (bad signature)".into(),
            });
            return Err("Data in byte array is not a Registry hive (bad signature)".into());
        }
        let header = Header::parse(read_bytes(&bytes, 0, 4096))?;
        let hive_type = HiveType::from_file_name(&header.file_name);
        Ok(Hive {
            bytes,
            path: path.to_string(),
            header,
            hive_type,
            recover_deleted: false,
            nks: vec![],
            vks: vec![],
            keys: vec![],
            root: None,
            cells: IndexMap::new(),
            lists: IndexMap::new(),
            offset_map: HashMap::new(),
            path_map: IndexMap::new(),
            total_bytes_read: 0,
            messages,
        })
    }

    fn log(&self, level: Level, message: String) {
        self.messages.borrow_mut().push(Diagnostic { level, message });
    }

    /// The messages logged since the last call
    pub fn take_messages(&self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.messages.borrow_mut())
    }

    /// ProcessTransactionLogs(log files, true), before ParseHive. `logs` are the non-empty logs' names and bytes.
    pub fn process_transaction_logs(&mut self, logs: Vec<LogFile>) -> Result<(), HiveError> {
        if logs.is_empty() {
            return Err("No logs were supplied".into());
        }
        if self.header.primary_sequence_number == self.header.secondary_sequence_number && self.header.checksum_ok() {
            return Err("Sequence numbers match! Hive is not dirty".into());
        }
        for log in logs.iter().filter(|l| l.bytes.len() >= 4096) {
            let sig = net::i32_at(&log.bytes, 0)?;
            if sig != REGF_SIGNATURE {
                self.log(Level::Error, "Data in byte array is not a Registry transaction log (bad signature)".into());
                return Err("Data in byte array is not a Registry transaction log (bad signature)".into());
            }
            let h = Header::parse(read_bytes(&log.bytes, 0, 4096))?;
            let t = HiveType::from_file_name(&h.file_name);
            if t != self.hive_type {
                return Err(format!(
                    "Transaction log contains a type ({}) that is different from the Registry hive ({})",
                    t.name(),
                    self.hive_type.name()
                ));
            }
        }
        let result = replay::replay(&self.bytes, &logs);
        for (level, m) in result.debug {
            self.log(level, m);
        }
        for m in result.messages {
            self.log(Level::Info, m);
        }
        let Some(bytes) = result.bytes.filter(|_| result.recovered) else {
            self.log(Level::Warning, "No transaction log could be applied. The hive is used as it is".into());
            return Ok(());
        };
        let names: Vec<&str> = result.logs_applied.iter().map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n)).collect();
        let seq = result.last_sequence_number.unwrap_or(self.header.primary_sequence_number);
        let checksum = u32::from_le_bytes(bytes[0x1FC..0x200].try_into().unwrap());
        self.log(
            Level::Info,
            format!(
                "Transaction logs applied: {}. Sequence numbers have been updated to 0x{seq:04X}. New Checksum: 0x{checksum:X}",
                names.join(", ")
            ),
        );
        self.bytes = bytes;
        self.header = Header::parse(read_bytes(&self.bytes, 0, 4096))?;
        self.hive_type = HiveType::from_file_name(&self.header.file_name);
        Ok(())
    }

    // ---- ParseHive ----

    /// ParseHive: reads the hbins, builds the tree from the root and (with recover_deleted) the deleted keys
    pub fn parse(&mut self) -> Result<(), HiveError> {
        self.total_bytes_read = 4096;
        let file_len = self.bytes.len() as i64;
        let mut hive_length = self.header.length as i64 + 0x1000;
        if hive_length < file_len {
            self.log(Level::Debug, "Header length is smaller than the size of the file.".into());
            hive_length = file_len;
        }
        if self.header.primary_sequence_number != self.header.secondary_sequence_number {
            self.log(
                Level::Warning,
                "Sequence numbers do not match! Hive is dirty and the transaction logs should be reviewed for relevant data!".into(),
            );
        }
        if hive_length > file_len {
            self.log(
                Level::Warning,
                format!(
                    "The hive is truncated: its header says 0x{:X} bytes of hive bins, but the file has 0x{:X} after the header. Reading what is there",
                    self.header.length,
                    file_len - 0x1000
                ),
            );
            hive_length = file_len;
        }
        let mut offset: i64 = 4096;
        while offset + 0x20 <= hive_length {
            let hbin_size = u32::from_le_bytes(read_bytes(&self.bytes, offset + 8, 4).try_into().unwrap());
            if hbin_size == 0 {
                self.log(Level::Debug, format!("Found hbin with size 0 at absolute offset 0x{offset:X}. Skipping 0x1000 bytes..."));
                offset += 4096;
                self.total_bytes_read += 4096;
                continue;
            }
            let sig = i32::from_le_bytes(read_bytes(&self.bytes, offset, 4).try_into().unwrap());
            if sig != HBIN {
                self.log(
                    Level::Warning,
                    format!(
                        "hbin header incorrect at absolute offset 0x{offset:X}!!! Percent done: {}",
                        percent(offset as f64 / hive_length as f64)
                    ),
                );
                break;
            }
            if hbin_size < 0x20 || hbin_size > i32::MAX as u32 {
                self.log(Level::Warning, format!("hbin at absolute offset 0x{offset:X} has an invalid size (0x{hbin_size:X}). Stopping"));
                break;
            }
            if offset + hbin_size as i64 > file_len {
                self.log(
                    Level::Warning,
                    format!("hbin at absolute offset 0x{offset:X} (0x{hbin_size:X} bytes) goes past the end of the file. Reading what is there"),
                );
            }
            match self.process_hbin(offset, hbin_size) {
                Ok(records) => {
                    for r in records {
                        match r {
                            Record::Nk(nk) => {
                                let o = nk.relative_offset;
                                if !self.cells.contains_key(&o) {
                                    self.nks.push(nk);
                                    self.cells.insert(o, CellRef::Nk(self.nks.len() - 1));
                                }
                            }
                            Record::Vk(vk) => {
                                let o = vk.relative_offset;
                                if !self.cells.contains_key(&o) {
                                    self.vks.push(vk);
                                    self.cells.insert(o, CellRef::Vk(self.vks.len() - 1));
                                }
                            }
                            Record::Other(o) => {
                                self.cells.entry(o).or_insert(CellRef::Other);
                            }
                            Record::List(o, l) => {
                                self.lists.entry(o).or_insert(l);
                            }
                        }
                    }
                }
                Err(e) => self.log(Level::Error, format!("Error processing hbin at absolute offset 0x{offset:X}\n{e}")),
            }
            offset += hbin_size as i64;
        }

        self.log(Level::Debug, "Initial processing complete. Building tree...".into());
        let root_cell = self.header.root_cell_offset as i64;
        let mut root_nk = match self.cells.get(&root_cell) {
            Some(CellRef::Nk(i)) => Some(*i),
            _ => None,
        };
        if root_nk.is_none() {
            self.log(
                Level::Warning,
                "Unable to find root key based on flag HiveEntryRootKey. Looking for root key via Header.RootCellOffset value...".into(),
            );
            root_nk = self.cells.values().find_map(|c| match c {
                CellRef::Nk(i) if self.nks[*i].flags & KEY_HIVE_ENTRY_ROOT != 0 => Some(*i),
                _ => None,
            });
        }
        let Some(root_nk) = root_nk else {
            return Err("Root nk record not found!".into());
        };
        self.nks[root_nk].referenced.set(true);
        self.log(Level::Debug, "Found root node! Getting subkeys...".into());
        let name = self.nks[root_nk].name.clone()?;
        self.keys.push(Key { nk: root_nk, parent: None, subkeys: vec![], values: vec![], flags: 0, path: name, class_name: String::new() });
        self.root = Some(0);
        self.log(Level::Debug, "Created root node object. Getting subkeys.".into());
        let subkeys = self.sub_keys_and_values(0)?;
        self.keys[0].subkeys.extend(subkeys);
        self.log(Level::Debug, "Hive processing complete!".into());

        if self.recover_deleted && file_len != self.total_bytes_read {
            let remaining = read_bytes(&self.bytes, self.total_bytes_read, (file_len - self.total_bytes_read) as i32);
            if remaining.iter().any(|&b| b != 0) {
                self.log(
                    Level::Warning,
                    format!(
                        "Extra, non-zero data found beyond hive length! Check for erroneous data starting at 0x{:X}!",
                        self.total_bytes_read
                    ),
                );
            }
            if self.header.length as i64 != self.total_bytes_read - 0x1000 {
                self.log(
                    Level::Warning,
                    format!(
                        "Hive length (0x{file_len:X}) does not equal bytes read (0x{:X})!! Check the end of the hive for erroneous data",
                        self.total_bytes_read
                    ),
                );
            }
        }
        if self.recover_deleted {
            self.build_deleted_keys()?;
        }
        self.log(Level::Debug, "Flushing record lists...".into());
        self.lists.clear();
        Ok(())
    }

    /// HBinRecord.Process: the records of an hbin, with what is carved from free cells and slack
    fn process_hbin(&mut self, hbin_offset: i64, hbin_size: u32) -> Result<Vec<Record>, String> {
        let relative = hbin_offset - 0x1000;
        let raw_len = read_bytes(&self.bytes, hbin_offset, hbin_size as i32).len();
        let mut records = Vec::new();
        let mut pos: usize = 0x20;
        self.total_bytes_read += 0x20;
        let recover = self.recover_deleted;
        while (pos as u64) < hbin_size as u64 {
            let hb = &self.bytes[hbin_offset as usize..hbin_offset as usize + raw_len];
            let record_size = net::u32_at(hb, pos as i64)?;
            let mut read_size = record_size as i32;
            if !recover && read_size > 0 {
                pos = (pos as i64 + read_size as i64) as usize;
                continue;
            }
            read_size = abs_size(read_size);
            if read_size < 8 || pos as i64 + read_size as i64 > raw_len as i64 {
                self.log(
                    Level::Warning,
                    format!(
                        "Cell at absolute offset 0x{:X} has an invalid size (0x{record_size:X}). Skipping the rest of the hbin",
                        pos as i64 + relative + 0x1000
                    ),
                );
                break;
            }
            let rs = read_size as usize;
            self.total_bytes_read += rs as i64;
            let mut sig = i16::from_le_bytes([hb[pos + 4], hb[pos + 5]]);
            if sig == LK && rs < 0x50 {
                sig = 0;
            }
            let needs_copy = match sig {
                NK | VK => false,
                LF | LH | LI | RI | DB | LK | SK => true,
                _ => recover,
            };
            if !needs_copy && sig != NK && sig != VK {
                pos += rs;
                continue;
            }
            let cell_offset = pos as i64 + relative;
            let cell_abs = hbin_offset as usize + pos;
            let raw = &self.bytes[cell_abs..cell_abs + rs];
            let is_free = i32::from_le_bytes(raw[0..4].try_into().unwrap()) > 0;
            let cell_sig = net::ascii(&raw[4..6]);
            enum Made {
                Cell(Record, bool),
                List(List),
                Data,
                Nothing,
            }
            let made: Result<Made, String> = match sig {
                LF | LH | LI | RI | DB => Ok(Made::List(List::new(sig, raw))),
                LK => lk_check(raw).map(|_| Made::Cell(Record::Other(cell_offset), is_free)),
                NK => {
                    if rs >= 0x30 {
                        let nk = Nk::new(&self.bytes, rs, cell_offset);
                        let free = nk.is_free();
                        Ok(Made::Cell(Record::Nk(nk), free))
                    } else {
                        Ok(Made::Nothing)
                    }
                }
                SK => {
                    if rs >= 0x14 {
                        net::u32_at(raw, 0x14).map(|_| Made::Cell(Record::Other(cell_offset), is_free))
                    } else {
                        Ok(Made::Nothing)
                    }
                }
                VK => {
                    if rs >= 0x18 {
                        let vk = Vk::new(&self.bytes, rs, cell_offset);
                        let free = vk.is_free();
                        Ok(Made::Cell(Record::Vk(vk), free))
                    } else {
                        Ok(Made::Nothing)
                    }
                }
                _ => Ok(Made::Data),
            };
            let made = match made {
                Ok(m) => m,
                Err(e) => {
                    let size = i32::from_le_bytes(raw[0..4].try_into().unwrap());
                    let at = format!("0x{:X}", cell_offset + 4096);
                    if size < 0 {
                        self.log(
                            Level::Error,
                            format!(
                                "Hard error processing record with cell signature {cell_sig} at Absolute Offset: {at} with raw data: {}\n{e}",
                                net::hex(raw)
                            ),
                        );
                    } else {
                        self.log(
                            Level::Warning,
                            format!(
                                "Soft error processing record with cell signature {cell_sig} at Absolute Offset: {at} with raw data: {}",
                                net::hex(raw)
                            ),
                        );
                    }
                    Made::Nothing
                }
            };
            let mut carved = Vec::new();
            match made {
                Made::Cell(record, free) => {
                    if free {
                        carved = self.extract_from_slack(read_bytes(&self.bytes, cell_offset + 4096, rs as i32), cell_offset);
                    } else {
                        records.push(record);
                    }
                }
                Made::List(list) => {
                    if recover {
                        carved = self.extract_from_slack(raw, cell_offset);
                    }
                    records.push(Record::List(cell_offset, list));
                }
                Made::Data => {
                    if recover {
                        carved = self.extract_from_slack(raw, cell_offset);
                    }
                }
                Made::Nothing => {}
            }
            records.extend(carved);
            pos += rs;
        }
        Ok(records)
    }

    /// ExtractRecordsFromSlack: nk and vk records in free cells and in the slack of lists and data
    fn extract_from_slack(&self, data: &[u8], relative_offset: i64) -> Vec<Record> {
        let mut starts = Vec::new();
        for i in 5..data.len() {
            if data[i] == 0x6b && (data[i - 1] == 0x6e || data[i - 1] == 0x76) && (data[i - 2] == 0 || data[i - 2] == 0xFF) {
                starts.push(i - 5);
            }
        }
        let mut records = Vec::new();
        for start in starts {
            let size = i32::from_le_bytes(data[start..start + 4].try_into().unwrap());
            let declared = abs_size(size);
            if declared <= 3 {
                continue;
            }
            let past_cell = ((data.len() - start) as i64) < declared as i64;
            let raw: &[u8] = if past_cell {
                let absolute = relative_offset + start as i64 + 0x1000;
                if absolute + declared as i64 > self.bytes.len() as i64 || declared > 0x10000 {
                    continue;
                }
                read_bytes(&self.bytes, absolute, declared)
            } else {
                &data[start..start + declared as usize]
            };
            if raw.len() < 6 {
                continue;
            }
            let sig = i16::from_le_bytes([raw[4], raw[5]]);
            let rec_offset = relative_offset + start as i64;
            match sig {
                NK => {
                    if raw.len() <= 0x30
                        || (past_cell && (raw.len() <= 0x50 || 0x50 + u16::from_le_bytes([raw[0x4C], raw[0x4D]]) as usize > raw.len()))
                    {
                        continue;
                    }
                    let nk = Nk::new(&self.bytes, raw.len(), rec_offset);
                    match nk.last_write() {
                        Ok(t) if t.parts().year > 1900 => records.push(Record::Nk(nk)),
                        Ok(_) => {}
                        Err(e) => self.log(
                            Level::Debug,
                            format!(
                                "When recovering from slack at absolute offset 0x{:08X}, an error happened! raw Length: 0x{:X}\n{e}",
                                rec_offset + 0x1000,
                                raw.len()
                            ),
                        ),
                    }
                }
                VK => {
                    if raw.len() < 0x18 || (past_cell && 0x18 + u16::from_le_bytes([raw[6], raw[7]]) as usize > raw.len()) {
                        continue;
                    }
                    records.push(Record::Vk(Vk::new(&self.bytes, raw.len(), rec_offset)));
                }
                _ => {}
            }
        }
        records
    }

    /// GetDataNodeFromOffset: the data of the cell at a relative offset (without its size)
    fn data_node(&self, relative: i64) -> Option<&[u8]> {
        let len = read_bytes(&self.bytes, relative + 4096, 4);
        if len.len() < 4 {
            return None;
        }
        let size = abs_size(i32::from_le_bytes(len.try_into().unwrap()));
        if size < 4 {
            return None;
        }
        Some(&read_bytes(&self.bytes, relative + 4096, size)[4..])
    }

    pub fn key_name(&self, k: KeyId) -> &str {
        self.nks[self.keys[k].nk].name.as_deref().unwrap_or("")
    }

    /// GetSubKeysAndValues
    fn sub_keys_and_values(&mut self, k: KeyId) -> Result<Vec<KeyId>, HiveError> {
        let nk_i = self.keys[k].nk;
        let nk_off = self.nks[nk_i].relative_offset;
        self.offset_map.insert(nk_off, k);
        let path = self.keys[k].path.clone();
        let folded = fold(&path);
        if self.path_map.contains_key(&folded) {
            // a new key never has HasActiveParent yet
            self.log(
                Level::Warning,
                format!(
                    "Key {path} at absolute offset 0x{:X} appears to be an old reference as one was already found with HasActiveParent set. Ignoring...",
                    nk_off + 4096
                ),
            );
        } else {
            self.path_map.insert(folded, (path.clone(), k));
        }
        self.keys[k].flags = KEY_HAS_ACTIVE_PARENT;

        let nk = &self.nks[nk_i];
        let (class_cell, class_len, value_list, value_count, subkey_list) =
            (nk.class_cell, nk.class_length, nk.value_list, nk.value_count, nk.subkey_list);
        if class_cell > 0 {
            if let Some(d) = self.data_node(class_cell as i64) {
                let n = (class_len as usize).min(d.len()) / 2 * 2;
                self.keys[k].class_name = net::utf16(&d[..n]);
            }
        }
        let mut offsets: Vec<u32> = Vec::new();
        if value_list > 0 {
            let data = self.data_node(value_list as i64).unwrap_or(&[]).to_vec();
            if value_count as u64 * 4 > data.len() as u64 {
                self.log(
                    Level::Warning,
                    format!(
                        "The value list of {path} has room for {} of its {} values",
                        ez_common::dotnet::n0((data.len() / 4) as u64),
                        ez_common::dotnet::n0(value_count as u64)
                    ),
                );
            }
            let mut last_i = 0usize;
            let mut i = 0usize;
            while (i as u64) < value_count as u64 && i * 4 + 4 <= data.len() {
                offsets.push(u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap()));
                last_i = i;
                i += 1;
            }
            if self.recover_deleted {
                let mut index = (last_i + 1) * 4;
                while index + 4 <= data.len() {
                    let os = u32::from_le_bytes(data[index..index + 4].try_into().unwrap());
                    if os < 8 || os % 8 != 0 {
                        break;
                    }
                    if !offsets.contains(&os) {
                        offsets.push(os);
                    }
                    index += 4;
                }
            }
        }
        let mut index = 0u64;
        for &os in &offsets {
            match self.cells.get(&(os as i64)) {
                Some(CellRef::Vk(v)) => {
                    let v = *v;
                    if index >= value_count as u64 && !self.vks[v].is_free() {
                        continue;
                    }
                    self.vks[v].referenced.set(true);
                    self.keys[k].values.push(v);
                }
                Some(_) => continue,
                None => {
                    if index < value_count as u64 {
                        self.log(Level::Warning, format!("An expected value was not found at offset 0x{os:X}. Key: {path}"));
                    }
                }
            }
            index += 1;
        }
        if self.keys[k].values.len() as u64 != value_count as u64 {
            self.log(
                Level::Debug,
                format!(
                    "{path}: Value count mismatch! ValueListCount is {} but NKRecord.ValueOffsets.Count is {}",
                    ez_common::dotnet::n0(value_count as u64),
                    ez_common::dotnet::n0(offsets.len() as u64)
                ),
            );
        }

        let mut keys = Vec::new();
        if let Some(list) = self.lists.get_index_of(&(subkey_list as i64)) {
            self.add_list(k, list, 0, &mut keys)?;
        }
        Ok(keys)
    }

    fn add_list(&mut self, k: KeyId, list: usize, depth: u32, keys: &mut Vec<KeyId>) -> Result<(), HiveError> {
        enum Kind {
            Leaf(Vec<u32>),
            Root(Vec<u32>),
            Unexpected(&'static str),
        }
        let kind = match self.lists.get_index(list).unwrap().1 {
            List::Lx(o, _) | List::Li(o) => Kind::Leaf(o.clone()),
            List::Ri(o) if depth == 0 => Kind::Root(o.clone()),
            other => Kind::Unexpected(other.signature()),
        };
        match kind {
            Kind::Leaf(offsets) => {
                for os in offsets {
                    self.add_sub_key(k, os as i64, keys)?;
                }
            }
            Kind::Root(offsets) => {
                for os in offsets {
                    match self.lists.get_index_of(&(os as i64)) {
                        Some(leaf) => self.add_list(k, leaf, depth + 1, keys)?,
                        None => {
                            let p = &self.keys[k].path;
                            self.log(
                                Level::Warning,
                                format!("Subkey list at relative offset 0x{os:X} (in the index root of {p}) missing! Skipping"),
                            )
                        }
                    }
                }
            }
            Kind::Unexpected(sig) => {
                let p = &self.keys[k].path;
                self.log(Level::Warning, format!("Unexpected subkey list type {sig} for {p}. Skipping"));
            }
        }
        Ok(())
    }

    fn add_sub_key(&mut self, k: KeyId, offset: i64, keys: &mut Vec<KeyId>) -> Result<(), HiveError> {
        let nk_i = match self.cells.get(&offset) {
            Some(CellRef::Nk(i)) => *i,
            _ => {
                self.log(Level::Warning, format!("NK record at relative offset 0x{offset:X} missing! Skipping"));
                return Ok(());
            }
        };
        if self.offset_map.contains_key(&offset) {
            let name = self.nks[nk_i].name.clone()?;
            let p = self.keys[k].path.clone();
            self.log(
                Level::Warning,
                format!("NK record at relative offset 0x{offset:X} ({name}) is referenced more than once (under {p}). Skipping"),
            );
            return Ok(());
        }
        self.nks[nk_i].referenced.set(true);
        let name = self.nks[nk_i].name.clone()?;
        let path = format!("{}\\{}", self.keys[k].path, name);
        self.keys.push(Key { nk: nk_i, parent: Some(k), subkeys: vec![], values: vec![], flags: 0, path, class_name: String::new() });
        let child = self.keys.len() - 1;
        let sks = self.sub_keys_and_values(child)?;
        self.keys[child].subkeys.extend(sks);
        keys.push(child);
        Ok(())
    }

    /// BuildDeletedRegistryKeys
    fn build_deleted_keys(&mut self) -> Result<(), HiveError> {
        self.log(Level::Debug, "Associating deleted keys and values...".into());
        let unreferenced: Vec<usize> = self
            .cells
            .values()
            .filter_map(|c| match c {
                CellRef::Nk(i) if !self.nks[*i].referenced.get() => Some(*i),
                _ => None,
            })
            .collect();
        let mut associated: HashSet<i64> = HashSet::new();
        let mut deleted: IndexMap<i64, KeyId> = IndexMap::new();
        for nk_i in unreferenced {
            let nk = &self.nks[nk_i];
            if nk.value_count > 10000 {
                continue;
            }
            nk.deleted.set(true);
            if (nk.size() as i64) < 0x50 + nk.name_length as i64 {
                continue;
            }
            let Ok(name) = nk.name.clone() else { continue };
            let mut offsets: Vec<u32> = Vec::new();
            if nk.value_list > 0 {
                let size = read_bytes(&self.bytes, nk.value_list as i64 + 4096, 4);
                let Ok(size_num) = net::u32_at(size, 0) else { continue };
                let size_num = (size_num as i64).min(nk.value_count as i64 * 4 + 4);
                let raw = read_bytes(&self.bytes, nk.value_list as i64 + 4096, size_num as i32);
                if raw.len() >= 4 {
                    let data = &raw[4..];
                    let mut last_i = 0usize;
                    for i in 0..nk.value_count as usize {
                        match net::u32_at(data, i as i64 * 4) {
                            Ok(os) => {
                                offsets.push(os);
                                last_i = i;
                            }
                            Err(_) => break,
                        }
                    }
                    let mut index = (last_i + 1) * 4;
                    let mut failed = false;
                    while index < data.len() {
                        let Ok(os) = net::u32_at(data, index as i64) else {
                            failed = true;
                            break;
                        };
                        if os < 8 || os % 8 != 0 {
                            break;
                        }
                        if !offsets.contains(&os) {
                            offsets.push(os);
                        }
                        index += 4;
                    }
                    if failed {
                        // the exception leaves this key out
                        continue;
                    }
                }
            }
            let mut values = Vec::new();
            for os in offsets {
                if let Some(CellRef::Vk(v)) = self.cells.get(&(os as i64)) {
                    let vk = &self.vks[*v];
                    if !(!vk.is_free() && vk.referenced.get()) {
                        associated.insert(vk.relative_offset);
                        values.push(*v);
                    }
                }
            }
            self.keys.push(Key { nk: nk_i, parent: None, subkeys: vec![], values, flags: KEY_DELETED, path: name, class_name: String::new() });
            deleted.insert(self.nks[nk_i].relative_offset, self.keys.len() - 1);
        }

        self.log(Level::Debug, "Building tree of key/subkeys for deleted keys".into());
        loop {
            let mut to_remove = Vec::new();
            for (_, &k) in deleted.iter() {
                let parent_offset = self.nks[self.keys[k].nk].parent as i64;
                if let Some(&p) = deleted.get(&parent_offset) {
                    self.keys[k].path = format!("{}\\{}", self.keys[p].path, self.key_name(k));
                    self.keys[p].subkeys.push(k);
                    to_remove.push(self.nks[self.keys[k].nk].relative_offset);
                }
            }
            if to_remove.is_empty() {
                break;
            }
            for o in to_remove {
                deleted.shift_remove(&o);
            }
        }

        self.log(Level::Debug, "Associating top level deleted keys to active Registry keys".into());
        let top: Vec<KeyId> = deleted.values().copied().collect();
        for k in top {
            let parent_offset = self.nks[self.keys[k].nk].parent as i64;
            let Some(CellRef::Nk(p)) = self.cells.get(&parent_offset) else { continue };
            let parent_nk = &self.nks[*p];
            if parent_nk.referenced.get() && !parent_nk.is_free() {
                let Some(&pk) = self.offset_map.get(&parent_offset) else { continue };
                self.keys[k].path = format!("{}\\{}", self.keys[pk].path, self.key_name(k));
                self.keys[k].flags |= KEY_HAS_ACTIVE_PARENT;
                self.update_child_paths(k)?;
                self.keys[pk].subkeys.push(k);
                let off = self.nks[self.keys[k].nk].relative_offset;
                if self.offset_map.insert(off, k).is_some() {
                    return Err(format!("An item with the same key has already been added. Key: {off}"));
                }
                let folded = fold(&self.keys[k].path);
                if !self.path_map.contains_key(&folded) {
                    self.path_map.insert(folded, (self.keys[k].path.clone(), k));
                }
            }
        }
        self.log(Level::Debug, "Iterating unreferenced VK records".into());
        Ok(())
    }

    fn update_child_paths(&mut self, k: KeyId) -> Result<(), HiveError> {
        let subkeys = self.keys[k].subkeys.clone();
        for sk in subkeys {
            self.keys[sk].path = format!("{}\\{}", self.keys[k].path, self.key_name(sk));
            let off = self.nks[self.keys[sk].nk].relative_offset;
            if self.offset_map.insert(off, sk).is_some() {
                return Err(format!("An item with the same key has already been added. Key: {off}"));
            }
            let folded = fold(&self.keys[sk].path);
            if !self.path_map.contains_key(&folded) {
                self.path_map.insert(folded, (self.keys[sk].path.clone(), sk));
            }
            self.update_child_paths(sk)?;
        }
        Ok(())
    }

    // ---- lookups ----

    pub fn nk(&self, k: KeyId) -> &Nk {
        &self.nks[self.keys[k].nk]
    }

    pub fn is_deleted(&self, k: KeyId) -> bool {
        self.keys[k].flags & KEY_DELETED != 0
    }

    /// The keys in _keyPathKeyMap's order (what the searches go through)
    pub fn mapped_keys(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.path_map.values().map(|(_, k)| *k)
    }

    /// GetKey(path): the path, else the path under the root key
    pub fn get_key(&self, key_path: &str) -> Option<KeyId> {
        let p = key_path.trim_matches(['\\', '/']);
        if let Some((_, k)) = self.path_map.get(&fold(p)) {
            return Some(*k);
        }
        let root = self.root?;
        let with_root = format!("{}\\{}", self.key_name(root), p);
        self.path_map.get(&fold(&with_root)).map(|(_, k)| *k)
    }

    /// ExpandKeyPath: the (lowercase) paths a path with * matches
    pub fn expand_key_path(&self, wildcard: &str) -> Vec<String> {
        let mut out: IndexMap<String, ()> = IndexMap::new();
        let mut w = lower(wildcard.trim_matches(['\\', '/']));
        if !w.contains('*') {
            out.insert(w, ());
            return out.into_keys().collect();
        }
        let root_name = self.root.map(|r| self.key_name(r).to_string()).unwrap_or_default();
        if !upper(&w).starts_with(&upper(&root_name)) {
            w = format!("{root_name}\\{w}");
        }
        let w = lower(&w);
        if self.path_map.contains_key(&fold(&w)) {
            out.insert(w.clone(), ());
        }
        let pattern = format!("(?im)^{}$", fancy_regex::escape(&w).replace("\\*", "[^\\\\]*?"));
        if let Ok(re) = fancy_regex::Regex::new(&pattern) {
            for (original, _) in self.path_map.values() {
                if re.is_match(original).unwrap_or(false) {
                    out.insert(lower(original), ());
                }
            }
        }
        out.into_keys().collect()
    }

    // ---- values ----

    /// The data block of a value and where its data starts (ReadDataBlock)
    pub fn data_block(&self, v: VkId) -> NetResult<(&[u8], u32)> {
        let vk = &self.vks[v];
        if vk.block.get().is_none() {
            let b = self.read_data_block(vk)?;
            let _ = vk.block.set(b);
        }
        let (b, o) = vk.block.get().unwrap();
        Ok((b.as_slice(), *o))
    }

    fn read_data_block(&self, vk: &Vk) -> NetResult<(Vec<u8>, u32)> {
        let file = &self.bytes;
        if vk.resident {
            let raw = read_bytes(file, vk.absolute_offset(), vk.raw_len as i32);
            return Ok((slice(raw, 0xC, vk.length_internal.min(4) as i64)?.to_vec(), 0));
        }
        let free = vk.is_free();
        // uint arithmetic in the original: a damaged offset wraps around to the start of the file
        let data_abs = 4096u32.wrapping_add(vk.offset_to_data) as i64;
        let size_raw = read_bytes(file, data_abs, 4);
        let mut block_size: i32 = 0;
        if size_raw.len() == 4 {
            block_size = abs_size(i32::from_le_bytes(size_raw.try_into().unwrap()));
        }
        if free && block_size as i64 > vk.data_length as i64 * 100 {
            let v = (vk.data_length as f64 / 8.0).ceil() * 8.0 + 32.0;
            block_size = if v > i32::MAX as f64 { i32::MIN } else { v as i32 };
        }
        if free && block_size as i64 == vk.data_length as i64 {
            block_size = block_size.wrapping_add(4);
        }
        let block = read_bytes(file, data_abs, block_size).to_vec();
        if vk.length_internal > 16344 && self.header.minor_version > 3 {
            if block.is_empty() {
                return Ok((vec![], 4));
            }
            let db_size = net::i32_at(&block, 0)?;
            if abs_size(db_size) == 0 {
                return Ok((vec![], 4));
            }
            let offset_to_offsets = net::u32_at(&block, 8)?;
            let list_abs = 4096 + offset_to_offsets as i64;
            match net::i32_at(read_bytes(file, list_abs, 4), 0) {
                Ok(s) => block_size = s,
                Err(e) => {
                    if free {
                        return Ok((vec![], 4));
                    }
                    self.log(Level::Error, format!("Error getting data block: {e}\n{e}"));
                }
            }
            let list = read_bytes(file, list_abs, abs_size(block_size));
            let mut big = Vec::with_capacity(vk.length_internal.min(0x1000000) as usize);
            let mut i = 1i64;
            while i <= net::u16_at(&block, 6)? as i64 {
                let os = net::u32_at(list, i * 4)?;
                let chunk_abs = 4096 + os as i64;
                match net::i32_at(read_bytes(file, chunk_abs, 4), 0) {
                    Ok(s) => {
                        let d = read_bytes(file, chunk_abs, abs_size(s));
                        if d.len() > 4 {
                            big.extend_from_slice(&d[4..4 + 16344.min(d.len() - 4)]);
                        }
                    }
                    Err(e) => {
                        if free {
                            return Ok((vec![], 4));
                        }
                        self.log(Level::Error, format!("Error getting data block: {e}\n{e}"));
                    }
                }
                i += 1;
            }
            return Ok((big, 0));
        }
        Ok((block, 4))
    }

    /// ValueDataRaw
    pub fn value_raw(&self, v: VkId) -> NetResult<Vec<u8>> {
        let vk = &self.vks[v];
        let (block, off) = self.data_block(v)?;
        let len = vk.length_internal as i64;
        if len + off as i64 > block.len() as i64 {
            if !block.is_empty() {
                return Ok(slice(block, off as i64, block.len() as i64 - off as i64).map(|s| s.to_vec()).unwrap_or_default());
            }
            return Ok(vec![]);
        }
        Ok(slice(block, off as i64, len)?.to_vec())
    }

    /// ValueDataSlack
    pub fn value_slack(&self, v: VkId) -> NetResult<Vec<u8>> {
        let vk = &self.vks[v];
        let (block, off) = self.data_block(v)?;
        let start = vk.length_internal as i64 + off as i64;
        if block.len() as i64 > start {
            return Ok(block[start as usize..].to_vec());
        }
        Ok(vec![])
    }

    /// ValueData. The errors of non-free values are logged, as the Registry library does, and their data is then
    /// the data block's bytes. Err only when the value's name (which the message has) cannot be read.
    pub fn value_data(&self, v: VkId) -> NetResult<ValueObj> {
        let vk = &self.vks[v];
        let (block, off) = match self.data_block(v) {
            Ok(b) => b,
            Err(e) => {
                if !vk.is_free() {
                    let name = vk.name()?;
                    self.log(Level::Error, format!("Error getting ValueData for {name}. Error message: {e}\n{e}"));
                }
                return Ok(ValueObj::Bytes(vec![]));
            }
        };
        if vk.is_free() && (block.len() as u64) < vk.length_internal as u64 {
            return Ok(ValueObj::Bytes(block.to_vec()));
        }
        match decode(vk, block, off as i64) {
            Ok(Some(o)) => Ok(o),
            Ok(None) => {
                vk.data_type.set(REG_UNKNOWN);
                Ok(ValueObj::Bytes(block.to_vec()))
            }
            Err(e) => {
                if !vk.is_free() {
                    let name = vk.name()?;
                    self.log(Level::Error, format!("Error getting ValueData for {name}. Error message: {e}\n{e}"));
                }
                Ok(ValueObj::Bytes(block.to_vec()))
            }
        }
    }

    // ---- searches ----

    pub fn find_in_key_name(&self, term: &str, regex: Option<&fancy_regex::Regex>) -> Vec<SearchHit> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            let name = self.key_name(k);
            let m = match regex {
                Some(re) => re.is_match(name).unwrap_or(false),
                None => contains_ignore_case(name, term),
            };
            if m {
                hits.push(SearchHit { key: k, value: None, hit: term.to_string(), location: HitType::KeyName });
            }
        }
        hits
    }

    pub fn find_in_value_name(&self, term: &str, regex: Option<&fancy_regex::Regex>) -> NetResult<Vec<SearchHit>> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            for &v in &self.keys[k].values {
                let name = self.vks[v].name()?;
                let m = match regex {
                    Some(re) => re.is_match(name).unwrap_or(false),
                    None => contains_ignore_case(name, term),
                };
                if m {
                    hits.push(SearchHit { key: k, value: Some(v), hit: term.to_string(), location: HitType::ValueName });
                }
            }
        }
        Ok(hits)
    }

    /// FindInValueData. `term_regex` is the term as a case-insensitive regex (None when it is not a valid one).
    pub fn find_in_value_data(
        &self,
        term: &str,
        regex: Option<&fancy_regex::Regex>,
        literal: bool,
        term_regex: Option<&fancy_regex::Regex>,
    ) -> NetResult<Vec<SearchHit>> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            for &v in &self.keys[k].values {
                let data = self.value_data(v)?.text();
                if let Some(re) = regex {
                    if re.is_match(&data).unwrap_or(false) {
                        hits.push(SearchHit { key: k, value: Some(v), hit: term.to_string(), location: HitType::ValueData });
                    }
                    continue;
                }
                if contains_ignore_case(&data, term) {
                    hits.push(SearchHit { key: k, value: Some(v), hit: term.to_string(), location: HitType::ValueData });
                }
                if literal {
                    continue;
                }
                if self.vks[v].data_type.get() == REG_BINARY {
                    let raw = self.value_raw(v)?;
                    self.decoded_hits(&raw, term_regex, k, v, HitType::ValueData, &mut hits);
                }
            }
        }
        Ok(hits)
    }

    pub fn find_in_value_slack(
        &self,
        term: &str,
        regex: Option<&fancy_regex::Regex>,
        literal: bool,
        term_regex: Option<&fancy_regex::Regex>,
    ) -> NetResult<Vec<SearchHit>> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            for &v in &self.keys[k].values {
                let slack = self.value_slack(v)?;
                if let Some(re) = regex {
                    if re.is_match(&net::hex(&slack)).unwrap_or(false) {
                        hits.push(SearchHit { key: k, value: Some(v), hit: term.to_string(), location: HitType::ValueSlack });
                    }
                } else if literal {
                    if contains_ignore_case(&net::hex(&slack), term) {
                        hits.push(SearchHit { key: k, value: Some(v), hit: term.to_string(), location: HitType::ValueSlack });
                    }
                } else {
                    self.decoded_hits(&slack, term_regex, k, v, HitType::ValueSlack, &mut hits);
                }
            }
        }
        Ok(hits)
    }

    /// The term found in bytes read as Windows-1252 and as UTF-16: hits with the bytes of what matched
    fn decoded_hits(&self, raw: &[u8], term_regex: Option<&fancy_regex::Regex>, k: KeyId, v: VkId, location: HitType, hits: &mut Vec<SearchHit>) {
        let Some(re) = term_regex else { return };
        let ascii = net::cp1252(raw);
        if let Ok(Some(m)) = re.find(&ascii) {
            if !m.as_str().is_empty() {
                let bytes = cp1252_bytes(m.as_str());
                hits.push(SearchHit { key: k, value: Some(v), hit: net::hex(&bytes), location });
            }
        }
        let unicode = net::utf16(raw);
        if let Ok(Some(m)) = re.find(&unicode) {
            if !m.as_str().is_empty() {
                let bytes: Vec<u8> = m.as_str().encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                hits.push(SearchHit { key: k, value: Some(v), hit: net::hex(&bytes), location });
            }
        }
    }

    /// FindByValueSize
    pub fn find_by_value_size(&self, min: i32) -> NetResult<Vec<(KeyId, VkId)>> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            for &v in &self.keys[k].values {
                if self.value_raw(v)?.len() as i64 >= min as i64 {
                    hits.push((k, v));
                }
            }
        }
        Ok(hits)
    }

    /// FindBase64
    pub fn find_base64(&self, min: i32) -> NetResult<Vec<(KeyId, VkId)>> {
        let mut hits = Vec::new();
        for k in self.mapped_keys() {
            for &v in &self.keys[k].values {
                let data = self.value_data(v)?.text();
                if (data.trim().encode_utf16().count() as i64) < min as i64 {
                    continue;
                }
                if is_base64(&data) {
                    hits.push((k, v));
                }
            }
        }
        Ok(hits)
    }
}

/// IsBase64String2
fn is_base64(value: &str) -> bool {
    let chars: Vec<u16> = value.encode_utf16().collect();
    if chars.is_empty() || chars.len() % 4 != 0 || value.contains([' ', '\t', '\r', '\n']) {
        return false;
    }
    let mut index = chars.len() as i64 - 1;
    if chars[index as usize] == b'=' as u16 {
        index -= 1;
    }
    if index >= 0 && chars[index as usize] == b'=' as u16 {
        index -= 1;
    }
    (0..=index).all(|i| {
        let c = chars[i as usize];
        (48..=57).contains(&c) || (65..=90).contains(&c) || (97..=122).contains(&c) || c == 43 || c == 47
    })
}

/// Windows-1252's GetBytes ('?' for what it cannot encode)
fn cp1252_bytes(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| {
            let u = c as u32;
            if u < 0x80 || (0xA0..=0xFF).contains(&u) {
                return u as u8;
            }
            (0x80u8..0xA0).find(|&b| net::cp1252(&[b]).starts_with(c)).unwrap_or(b'?')
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitType {
    KeyName,
    ValueName,
    ValueData,
    ValueSlack,
}

/// SearchHit
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub key: KeyId,
    pub value: Option<VkId>,
    /// HitString
    pub hit: String,
    pub location: HitType,
}

/// LkCellRecord's constructor throws when its (UTF-16) name goes past the record
fn lk_check(raw: &[u8]) -> NetResult<()> {
    let flags = u16::from_le_bytes([raw[6], raw[7]]);
    let name_length = u16::from_le_bytes([raw[0x4c], raw[0x4d]]) as i64;
    if flags & 0x20 == 0 {
        net::unicode_string(raw, 0x50, name_length)?;
    }
    Ok(())
}

/// The P format with the en-US culture (ICU): 3 decimals
fn percent(v: f64) -> String {
    format!("{}%", ez_common::dotnet::number_n(v * 100.0, 3))
}

/// ValueData's switch on the type. Ok(None) for a type without a name (it becomes RegUnknown).
fn decode(vk: &Vk, b: &[u8], off: i64) -> NetResult<Option<ValueObj>> {
    let len = vk.length_internal;
    let t = vk.data_type.get();
    let f32_at = |o: i64| -> NetResult<String> { net::u32_at(b, o).map(|x| float_text(f32::from_bits(x) as f64, true)) };
    let f64_at = |o: i64| -> NetResult<String> { net::u64_at(b, o).map(|x| float_text(f64::from_bits(x), false)) };
    let bool_at = |o: i64| -> NetResult<&'static str> {
        if o < 0 || o >= b.len() as i64 {
            return Err(
                "Index was out of range. Must be non-negative and less than the size of the collection. (Parameter 'startIndex')".into(),
            );
        }
        Ok(if b[o as usize] != 0 { "True" } else { "False" })
    };
    let char_at = |o: i64| -> NetResult<String> {
        net::u16_at(b, o).map(|u| char::from_u32(u as u32).map(|c| c.to_string()).unwrap_or_else(|| "\u{FFFD}".into()))
    };
    // (int)(_dataLengthInternal - 8) / n, and new T[that]
    let records = |n: i32| -> NetResult<i64> {
        let r = (len.wrapping_sub(8) as i32) / n;
        if r < 0 { Err(net::OVERFLOW.into()) } else { Ok(r as i64) }
    };
    let array_copy = |o: i64, n: i64| -> NetResult<&[u8]> {
        if o < 0 || o + n > b.len() as i64 {
            return Err("Source array was not long enough. Check the source index, length, and the array's lower bounds. (Parameter 'sourceArray')".into());
        }
        Ok(&b[o as usize..(o + n) as usize])
    };
    let joined = |n: i64, size: i64, f: &dyn Fn(i64) -> NetResult<String>| -> NetResult<String> {
        let mut parts = Vec::with_capacity(n as usize);
        for i in 0..n {
            parts.push(f(off + i * size)?);
        }
        Ok(format!("[{}]", parts.join(",")))
    };
    let text = |s: String| Ok(Some(ValueObj::Text(s)));
    match t {
        REG_FILETIME => {
            let ts = net::u64_at(b, off)?;
            Ok(Some(ValueObj::FileTime(filetime(ts as i64)?)))
        }
        REG_EXPAND_SZ | REG_MULTI_SZ | REG_SZ => {
            let s = net::unicode_string(b, off, len as i32 as i64)?;
            let v = match s.find("\0\0") {
                Some(i) => s[..i].split('\0').collect::<Vec<_>>().join(" "),
                None => s,
            };
            text(v.trim_matches('\0').to_string())
        }
        0 | REG_BINARY | 0xA | 8 | 9 => Ok(Some(ValueObj::Bytes(slice(b, off, len as i32 as i64)?.to_vec()))),
        REG_DWORD => Ok(Some(ValueObj::UInt(if len == 4 { net::u32_at(b, 0)? as u64 } else { 0 }))),
        REG_DWORD_BE => {
            let mut be = 0u32;
            for &x in &b[..b.len().min(4)] {
                be = (be << 8) | x as u32;
            }
            Ok(Some(ValueObj::UInt(be as u64)))
        }
        REG_QWORD => Ok(Some(ValueObj::UInt(if len == 8 { net::u64_at(b, off)? } else { 0 }))),
        REG_LINK => text(net::unicode_string(b, off, len as i32 as i64)?.replace('\0', " ").trim().to_string()),
        257 => text(format!("0x{:02X}", net::byte_at(b, off)?)),
        258 => text(net::i16_at(b, off)?.to_string()),
        259 => text(net::u16_at(b, off)?.to_string()),
        260 => text(net::i32_at(b, off)?.to_string()),
        261 => text(net::u32_at(b, off)?.to_string()),
        262 => text(net::i64_at(b, off)?.to_string()),
        263 => text(net::u64_at(b, off)?.to_string()),
        264 => text(f32_at(off)?),
        265 => text(f64_at(off)?),
        266 => text(char_at(off)?),
        267 => text(bool_at(off)?.to_string()),
        268 => {
            let mut end = off;
            while end + 1 < b.len() as i64 {
                if b[end as usize] == 0 && b[end as usize + 1] == 0 {
                    break;
                }
                end += 2;
            }
            text(net::unicode_string(b, off, end - off)?)
        }
        269 | 276 => {
            let n = records(1)?;
            let bytes = array_copy(off, n)?;
            text(format!("[{}]", bytes.iter().map(|x| format!("0x{x:02X}")).collect::<Vec<_>>().join(", ")))
        }
        270 => text(net::i64_at(b, off)?.to_string()),
        271 => text(timespan(net::i64_at(b, off)?)),
        272 => text(net::guid(array_copy(off, 16)?.try_into().unwrap())),
        273 => text(format!("X: {}, Y: {}", f32_at(off)?, f32_at(off + 4)?)),
        274 => text(format!("Width: {}, Height: {}", f32_at(off)?, f32_at(off + 4)?)),
        275 => text(format!("X: {}, Y: {}, Width: {}, Height: {}", f32_at(off)?, f32_at(off + 4)?, f32_at(off + 8)?, f32_at(off + 12)?)),
        277 => text(joined(records(2)?, 2, &|o| net::i16_at(b, o).map(|x| x.to_string()))?),
        278 => text(joined(records(2)?, 2, &|o| net::u16_at(b, o).map(|x| x.to_string()))?),
        279 => text(joined(records(4)?, 4, &|o| net::i32_at(b, o).map(|x| x.to_string()))?),
        280 => text(joined(records(4)?, 4, &|o| net::u32_at(b, o).map(|x| x.to_string()))?),
        281 => text(joined(records(8)?, 8, &|o| net::i64_at(b, o).map(|x| x.to_string()))?),
        282 => text(joined(records(8)?, 8, &|o| net::u64_at(b, o).map(|x| x.to_string()))?),
        283 => text(joined(records(4)?, 4, &|o| f32_at(o))?),
        284 => text(joined(records(8)?, 8, &|o| f64_at(o))?),
        285 => text(joined(records(2)?, 2, &|o| char_at(o))?),
        286 => text(joined(records(1)?, 1, &|o| bool_at(o).map(|s| s.to_string()))?),
        287 => {
            let mut check: i32 = off as i32;
            let data_len = len.wrapping_sub(8) as i64;
            let mut parts = Vec::new();
            while (check as i64) < data_len {
                let mut l = net::i32_at(b, check as i64)?;
                if check as i64 + 4 + l as i64 > b.len() as i64 {
                    l = b.len() as i32 - (check + 4);
                    if l < 0 {
                        break;
                    }
                }
                parts.push(net::unicode_string(b, check as i64 + 4, l as i64 - 2)?);
                check = check.wrapping_add(l).wrapping_add(4);
            }
            text(format!("[{}]", parts.join(",")))
        }
        288 => text(joined(records(8)?, 8, &|o| net::i64_at(b, o).map(|x| x.to_string()))?),
        289 => text(joined(records(8)?, 8, &|o| net::i64_at(b, o).map(timespan))?),
        290 => {
            let n = records(16)?;
            let mut parts = Vec::new();
            for i in 0..n {
                parts.push(net::guid(array_copy(off + i * 16, 16)?.try_into().unwrap()));
            }
            text(format!("[{}]", parts.join(",")))
        }
        291 => text(joined(records(8)?, 8, &|o| Ok(format!("{{X: {}, Y: {}}}", f32_at(o)?, f32_at(o + 4)?)))?),
        292 => text(joined(records(8)?, 8, &|o| Ok(format!("{{Width: {}, Height: {}}}", f32_at(o)?, f32_at(o + 4)?)))?),
        293 => {
            // the offsets step by 8, as the library's do
            let n = records(16)?;
            let mut parts = Vec::new();
            for i in 0..n {
                let o = off + i * 8;
                parts.push(format!(
                    "{{X: {}, Y: {}, Width: {}, Height: {}}}",
                    f32_at(o)?,
                    f32_at(o + 4)?,
                    f32_at(o + 8)?,
                    f32_at(o + 12)?
                ));
            }
            text(format!("[{}]", parts.join(",")))
        }
        REG_UNKNOWN => Ok(Some(ValueObj::Bytes(b.to_vec()))),
        _ => Ok(None),
    }
}
