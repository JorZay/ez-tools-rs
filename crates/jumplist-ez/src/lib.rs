//! Windows jump lists (`*.automaticDestinations-ms`, `*.customDestinations-ms`), as Eric Zimmerman's JumpList reads them: what
//! can't be read at all is an error, and a damaged entry or LNK is kept in `parse_errors`. Nothing here prints or exits.

use std::collections::HashMap;
use std::path::Path;

use ez_common::Timestamp;
use ez_common::dotnet::{equals_invariant_ignore_case, lower_invariant};
use ez_common::json::Value;
use ez_common::net::{guid, unicode_string};
use lnk_ez::LnkFile;
use olecf_ez::{DirectoryEntry, OleCfFile, TYPE_ROOT_STORAGE, TYPE_STREAM};
use shellitems_ez::sheet::PropertySheet;
use shellitems_ez::utils::guid_name;

/// An exception out of a jump list
#[derive(Clone, Debug)]
pub struct JumpListError {
    pub message: String,
    /// Its type, as the log shows it
    pub exception: &'static str,
    /// It means the file couldn't be read, as opposed to a damaged one
    pub read_error: bool,
}

impl JumpListError {
    fn parse(message: impl Into<String>) -> JumpListError {
        JumpListError { message: message.into(), exception: "JumpList.JumpListParseException", read_error: false }
    }

    fn ole(message: String) -> JumpListError {
        JumpListError { message, exception: "OleCf.OleCfParseException", read_error: false }
    }
}

/// AppIdList: descriptions of AppIds, the built-in ones and any added
pub struct AppIdList {
    ids: HashMap<String, String>,
}

impl Default for AppIdList {
    fn default() -> Self {
        let mut list = AppIdList { ids: HashMap::new() };
        list.iterate(include_str!("../data/AppIDs.txt").split('\n'));
        list
    }
}

impl AppIdList {
    fn iterate<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> u64 {
        let mut added = 0;
        for line in lines {
            let segments: Vec<&str> = line.split('|').collect();
            if segments.len() != 2 {
                continue;
            }
            let id = lower_invariant(segments[0].trim()).trim_matches('"').to_string();
            let description = segments[1].trim().trim_matches('"').to_string();
            if self.ids.insert(id, description).is_none() {
                added += 1;
            }
        }
        added
    }

    /// GetDescriptionFromId
    pub fn description(&self, id: &str) -> String {
        self.ids.get(&lower_invariant(id)).cloned().unwrap_or_else(|| "Unknown AppId".to_string())
    }

    /// LoadAppListFromFile: how many are new. File.ReadAllLines' line ends and encodings
    pub fn load_file(&mut self, path: &str) -> std::io::Result<u64> {
        let bytes = std::fs::read(path)?;
        let text = read_text(&bytes);
        Ok(self.iterate(text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).flat_map(|l| l.split('\r'))))
    }
}

/// File.ReadAllLines' decoding: UTF-8 unless a byte order mark says otherwise
fn read_text(bytes: &[u8]) -> String {
    let utf16 = |rest: &[u8], big: bool| -> String {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| if big { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) }).collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0xff, 0xfe, rest @ ..] => utf16(rest, false),
        [0xfe, 0xff, rest @ ..] => utf16(rest, true),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn app_id(source_file: &str) -> String {
    let name = source_file.rsplit('/').next().unwrap_or(source_file);
    name.split('.').next().unwrap_or_default().to_string()
}

fn app_id_value(id: &str, description: &str) -> Value {
    Value::object(vec![("AppId", Value::text(id)), ("Description", Value::text(description))])
}

/// The DestList stream's entry
#[derive(Clone, Debug)]
pub struct DestListEntry {
    pub entry_number: i32,
    pub mru_position: i32,
    pub file_birth_droid: String,
    pub file_droid: String,
    pub volume_birth_droid: String,
    pub volume_droid: String,
    pub hostname: String,
    pub last_modified: Timestamp,
    pub path: String,
    pub pinned: bool,
    pub interaction_count: i32,
    pub creation_time: Timestamp,
    pub mac_address: String,
    pub sps: Option<PropertySheet>,
    pub lnk: Option<LnkFile>,
    pub parse_errors: Vec<String>,
}

/// DestListEntry.NoMacAddress
pub const NO_MAC_ADDRESS: &str = "00:00:00:00:00:00";
const NO_GUID: &str = "00000000-0000-0000-0000-000000000000";

/// A Guid column: nothing for an empty one
pub fn droid_text(droid: &str) -> &str {
    if droid == NO_GUID { "" } else { droid }
}

fn gregorian_start() -> Timestamp {
    Timestamp::from_parts(1582, 10, 15, 0, 0, 0, 0).expect("a valid date")
}

/// Path's GUIDs, as a `::` path's parts are given names
fn name_guids(path: &str) -> String {
    let regex = fancy_regex::Regex::new(r"(?i)\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b|\(\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b\)|\{\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b\}").expect("a valid pattern");
    let parts: Vec<String> = path
        .split('\\')
        .map(|part| match regex.find(part) {
            Ok(Some(m)) => guid_name(m.as_str().trim_matches(['{', '}', '(', ')'])),
            _ => part.to_string(),
        })
        .collect();
    format!("{path} ==> {}", parts.join("\\"))
}

impl DestListEntry {
    fn read(raw: &[u8], version: i32, mru_position: i32, sps_size: i32) -> DestListEntry {
        let path_offset: usize = if version > 1 { 128 } else { 112 };
        let i32_at = |at: usize| i32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let droid = |at: usize| guid(raw[at..at + 16].try_into().unwrap());
        let mut errors = Vec::new();
        let hostname = if raw[73] == 0 {
            unicode_string(raw, 72, 16).unwrap_or_default()
        } else {
            raw[72..88].iter().map(|b| if *b < 0x80 { *b as char } else { '?' }).collect()
        };
        let hostname = hostname.split('\0').next().unwrap_or_default().to_string();
        let modified = i64::from_le_bytes(raw[100..108].try_into().unwrap());
        let last_modified = Timestamp::from_filetime(modified).unwrap_or_else(|| {
            errors.push(format!("Last modified time is out of range (0x{modified:016X})"));
            Timestamp::MIN
        });
        let interaction_count = if version > 1 { i32_at(116) } else { 0 };
        let mut path_chars = i32::from(i16::from_le_bytes([raw[path_offset], raw[path_offset + 1]]));
        let available = ((raw.len() - path_offset - 2) / 2) as i32;
        if path_chars < 0 || path_chars > available {
            errors.push(format!("Path length is {path_chars} characters, but only {available} are available"));
            path_chars = path_chars.min(available).max(0);
        }
        let mut path = unicode_string(raw, path_offset as i64 + 2, i64::from(path_chars) * 2).unwrap_or_default();
        if path.starts_with("knownfolder") {
            let id = path.rsplit('{').next().unwrap_or_default().trim_end_matches('}').to_string();
            path = format!("{path} ==> {}", guid_name(&id));
        }
        if path.starts_with("::") {
            path = name_guids(&path);
        }
        let file_droid = droid(24);
        let (mac_address, creation_time) = if raw[24 + 7] >> 4 == 1 {
            let node = file_droid.rsplit('-').next().unwrap_or_default();
            let mac: Vec<&str> = node.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&raw[24..32]);
            bytes[7] &= 0x0f;
            (mac.join(":"), Timestamp(gregorian_start().ticks() + i64::from_le_bytes(bytes)))
        } else {
            (NO_MAC_ADDRESS.to_string(), gregorian_start())
        };
        let mut sps = None;
        if sps_size > 0 {
            match PropertySheet::read(&raw[raw.len() - sps_size as usize..]) {
                Ok(sheet) => sps = Some(sheet),
                Err(e) => errors.push(format!("Unable to parse property store ({sps_size} bytes): {e}")),
            }
        }
        DestListEntry {
            entry_number: i32_at(88),
            mru_position,
            file_birth_droid: droid(56),
            file_droid,
            volume_birth_droid: droid(40),
            volume_droid: droid(8),
            hostname,
            last_modified,
            path,
            pinned: i32_at(108) != -1,
            interaction_count,
            creation_time,
            mac_address,
            sps,
            lnk: None,
            parse_errors: errors,
        }
    }

    /// EntryNumber.ToString("X")
    pub fn entry_number_hex(&self) -> String {
        format!("{:X}", self.entry_number)
    }

    fn to_value(&self) -> Value {
        Value::object(vec![
            ("Hostname", Value::text(self.hostname.as_str())),
            ("VolumeDroid", Value::guid(&self.volume_droid)),
            ("VolumeBirthDroid", Value::guid(&self.volume_birth_droid)),
            ("FileDroid", Value::guid(&self.file_droid)),
            ("FileBirthDroid", Value::guid(&self.file_birth_droid)),
            ("EntryNumber", Value::number(self.entry_number)),
            ("MRUPosition", Value::number(self.mru_position)),
            ("InteractionCount", Value::number(self.interaction_count)),
            ("CreatedOn", Value::time(self.creation_time)),
            ("LastModified", Value::required_time(self.last_modified)),
            ("Pinned", Value::Bool(self.pinned)),
            ("Sps", self.sps.as_ref().map_or(Value::Null, PropertySheet::to_value)),
            ("Path", Value::text(self.path.as_str())),
            ("MacAddress", Value::text(self.mac_address.as_str())),
            ("Lnk", self.lnk.as_ref().map_or(Value::Null, LnkFile::to_value)),
        ])
    }
}

struct DestList {
    version: i32,
    number_of_entries: i32,
    number_of_pinned: i32,
    last_entry_number: i32,
    entries: Vec<DestListEntry>,
    parse_errors: Vec<String>,
}

const DEST_LIST_HEADER_SIZE: usize = 32;

impl DestList {
    fn read(raw: &[u8]) -> Result<DestList, JumpListError> {
        if raw.len() < DEST_LIST_HEADER_SIZE {
            return Err(JumpListError::parse(format!("The DestList is {} bytes, smaller than its {DEST_LIST_HEADER_SIZE} byte header", raw.len())));
        }
        let at = |o: usize| i32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let mut list = DestList { version: at(0), number_of_entries: at(4), number_of_pinned: at(8), last_entry_number: at(16), entries: Vec::new(), parse_errors: Vec::new() };
        let path_offset: i64 = if list.version == 1 { 112 } else { 128 };
        let mut index = DEST_LIST_HEADER_SIZE;
        let mut mru = 0;
        while index < raw.len() && (list.version != 1 || (list.entries.len() as i64) < i64::from(list.number_of_entries)) {
            let remaining = (raw.len() - index) as i64;
            if remaining < path_offset + 2 {
                list.parse_errors.push(format!("{remaining} trailing byte(s) at 0x{index:X} are too short for a DestList entry"));
                break;
            }
            let at_path = index + path_offset as usize;
            let path_size = i64::from(i16::from_le_bytes([raw[at_path], raw[at_path + 1]]));
            let entry_size = path_offset + 2 + path_size * 2;
            if path_size < 0 || entry_size > remaining {
                list.parse_errors.push(format!("DestList entry at 0x{index:X} has a path of {path_size} characters, but only {remaining} bytes remain. Stopping"));
                break;
            }
            let (mut sps_size, mut stride) = (0i32, entry_size);
            if list.version != 1 {
                if remaining < entry_size + 4 {
                    list.parse_errors.push(format!("DestList entry at 0x{index:X} is missing its property store size. Stopping"));
                    break;
                }
                let at_sps = index + entry_size as usize;
                sps_size = i32::from_le_bytes(raw[at_sps..at_sps + 4].try_into().unwrap());
                if sps_size < 0 || i64::from(sps_size) > remaining - entry_size - 4 {
                    list.parse_errors.push(format!("DestList entry at 0x{index:X} has a property store of {sps_size} bytes, but only {} remain. Stopping", remaining - entry_size - 4));
                    break;
                }
                stride = entry_size + 4 + i64::from(sps_size);
            }
            let entry = DestListEntry::read(&raw[index..index + stride as usize], list.version, mru, sps_size);
            for e in &entry.parse_errors {
                list.parse_errors.push(format!("DestList entry {} at 0x{index:X}: {e}", entry.entry_number));
            }
            list.entries.push(entry);
            index += stride as usize;
            mru += 1;
        }
        Ok(list)
    }
}

/// `new LnkFile(bytes, name, codepage)`
fn read_lnk(bytes: &[u8], name: &str, code_page: i32) -> Result<LnkFile, String> {
    lnk_ez::from_bytes(bytes, Some(name), code_page).map_err(|e| e.message)
}

pub struct AutomaticDestination {
    pub source_file: String,
    pub app_id: String,
    pub app_id_description: String,
    pub directory: Vec<DirectoryEntry>,
    streams: Vec<Result<Option<Vec<u8>>, String>>,
    pub dest_list_count: i32,
    pub pinned_dest_list_count: i32,
    pub last_used_entry_number: i32,
    pub dest_list_version: i32,
    pub has_sps: bool,
    pub dest_list_property_store: Option<PropertySheet>,
    pub empty_dest_list_property_store: bool,
    pub entries: Vec<DestListEntry>,
    pub parse_errors: Vec<String>,
    code_page: i32,
}

impl AutomaticDestination {
    /// new AutomaticDestination
    pub fn new(raw: &[u8], source_file: &str, code_page: i32, app_ids: &AppIdList) -> Result<AutomaticDestination, JumpListError> {
        if raw.is_empty() {
            return Err(JumpListError::parse("Empty file"));
        }
        let id = app_id(source_file);
        let mut ole = OleCfFile::new(raw, source_file).map_err(JumpListError::ole)?;
        let mut parse_errors: Vec<String> = ole.parse_errors.iter().map(|e| format!("OLE container: {e}")).collect();
        let mut streams = Vec::with_capacity(ole.directory.len());
        for i in 0..ole.directory.len() {
            if ole.directory[i].entry_type == TYPE_ROOT_STORAGE {
                streams.push(Ok(None));
            } else {
                streams.push(ole.payload(i));
            }
        }
        let directory = ole.directory.clone();
        let mut out = AutomaticDestination {
            source_file: source_file.to_string(),
            app_id_description: app_ids.description(&id),
            app_id: id,
            directory,
            streams,
            dest_list_count: 0,
            pinned_dest_list_count: 0,
            last_used_entry_number: 0,
            dest_list_version: 0,
            has_sps: false,
            dest_list_property_store: None,
            empty_dest_list_property_store: false,
            entries: Vec::new(),
            parse_errors: Vec::new(),
            code_page,
        };
        let mut dest_list = None;
        if let Some(i) = out.directory.iter().position(|d| lower_invariant(&d.name) == "destlist").filter(|&i| out.directory[i].size > 0) {
            match &out.streams[i] {
                Ok(Some(bytes)) => match DestList::read(bytes) {
                    Ok(list) => {
                        parse_errors.extend(list.parse_errors.iter().map(|e| format!("DestList: {e}")));
                        dest_list = Some(list);
                    }
                    Err(e) => parse_errors.push(format!("DestList: {}", e.message)),
                },
                Ok(None) => {}
                Err(e) => parse_errors.push(format!("DestList: {e}")),
            }
        }
        if let Some(i) = out.directory.iter().position(|d| d.name == "DestListPropertyStore").filter(|&i| out.directory[i].size > 0) {
            match &out.streams[i] {
                Err(e) => parse_errors.push(format!("DestListPropertyStore: {e}")),
                Ok(bytes) => {
                    out.empty_dest_list_property_store = true;
                    if let Some(bytes) = bytes.as_ref().filter(|b| b.len() >= 4 && i32::from_le_bytes(b[..4].try_into().unwrap()) > 0) {
                        out.empty_dest_list_property_store = false;
                        match PropertySheet::read(&bytes[4..]) {
                            Ok(sheet) => out.dest_list_property_store = Some(sheet),
                            Err(e) => parse_errors.push(format!("DestListPropertyStore: {e}")),
                        }
                    }
                }
            }
        }
        if let Some(list) = dest_list {
            out.dest_list_count = list.number_of_entries;
            out.pinned_dest_list_count = list.number_of_pinned;
            out.dest_list_version = list.version;
            out.last_used_entry_number = list.last_entry_number;
            for mut entry in list.entries {
                let hex = entry.entry_number_hex();
                if let Some(i) = out.directory.iter().position(|d| equals_invariant_ignore_case(&d.name, &hex)) {
                    entry.lnk = out.read_entry_lnk(i, &mut parse_errors);
                }
                if entry.sps.is_some() {
                    out.has_sps = true;
                }
                out.entries.push(entry);
            }
        }
        out.parse_errors = parse_errors;
        Ok(out)
    }

    fn lnk_name(&self, directory_name: &str) -> String {
        format!("{}_Directory name_{directory_name}", self.source_file)
    }

    fn read_entry_lnk(&self, index: usize, errors: &mut Vec<String>) -> Option<LnkFile> {
        let name = &self.directory[index].name;
        let bytes = match &self.streams[index] {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("Stream {name}: unable to parse LNK: {e}"));
                return None;
            }
        };
        let Some(bytes) = bytes.as_ref().filter(|b| !b.is_empty()) else {
            errors.push(format!("Stream {name} is empty"));
            return None;
        };
        match read_lnk(bytes, &self.lnk_name(name), self.code_page) {
            Ok(lnk) => Some(lnk),
            Err(e) => {
                errors.push(format!("Stream {name}: unable to parse LNK: {e}"));
                None
            }
        }
    }

    /// GetLnkFromDirectoryName: Ok(None) when there is no such stream or it's the root entry
    pub fn lnk_from_directory_name(&self, name: &str) -> Result<Option<LnkFile>, JumpListError> {
        let Some(i) = self.directory.iter().position(|d| equals_invariant_ignore_case(&d.name, name)) else { return Ok(None) };
        if self.directory[i].entry_type == TYPE_ROOT_STORAGE {
            return Ok(None);
        }
        let bytes = match &self.streams[i] {
            Ok(b) => b,
            Err(e) => return Err(JumpListError::ole(e.clone())),
        };
        let Some(bytes) = bytes else {
            return Err(JumpListError { message: "Value cannot be null. (Parameter 'rawBytes')".to_string(), exception: "System.ArgumentNullException", read_error: false });
        };
        match lnk_ez::from_bytes(bytes, Some(&self.lnk_name(&self.directory[i].name)), self.code_page) {
            Ok(lnk) => Ok(Some(lnk)),
            Err(e) => Err(JumpListError { message: e.message, exception: "Lnk.LnkParseException", read_error: false }),
        }
    }

    /// DumpAllLnkFiles: the streams that start as an LNK does
    pub fn dump_all_lnk_files(&self, folder: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(folder)?;
        for (d, stream) in self.directory.iter().zip(&self.streams) {
            let lower = lower_invariant(&d.name);
            if lower == "root entry" || lower == "destlist" || d.entry_type != TYPE_STREAM {
                continue;
            }
            let Ok(Some(bytes)) = stream else { continue };
            if bytes.first() != Some(&0x4c) {
                continue;
            }
            std::fs::write(folder.join(format!("AppId_{}_DirName_{}.lnk", self.app_id, d.name)), bytes)?;
        }
        Ok(())
    }

    /// The properties ServiceStack serializes
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("ParseErrors", Value::strings(&self.parse_errors)),
            ("Directory", Value::List(self.directory.iter().map(DirectoryEntry::to_value).collect())),
            ("AppId", app_id_value(&self.app_id, &self.app_id_description)),
            ("DestListCount", Value::number(self.dest_list_count)),
            ("PinnedDestListCount", Value::number(self.pinned_dest_list_count)),
            ("LastUsedEntryNumber", Value::number(self.last_used_entry_number)),
            ("DestListVersion", Value::number(self.dest_list_version)),
            ("SourceFile", Value::text(self.source_file.as_str())),
            ("HasSps", Value::Bool(self.has_sps)),
            ("DestListPropertyStore", self.dest_list_property_store.as_ref().map_or(Value::Null, PropertySheet::to_value)),
            ("EmptyDestListPropertyStore", Value::Bool(self.empty_dest_list_property_store)),
            ("DestListEntries", Value::List(self.entries.iter().map(DestListEntry::to_value).collect())),
        ])
    }
}

const FOOTER: [u8; 4] = [0xab, 0xfb, 0xbf, 0xba];
const FILE_HEADER_SIZE: usize = 12;
const CLASS_ID_SIZE: usize = 16;
/// The LNK header's size (0x4C) and class id, which is also the class id before each shell object
const LNK_HEADER: [u8; 20] = [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];

/// CustomDestination.ByteSearch
fn byte_search(data: &[u8], pattern: &[u8], start: usize) -> Option<usize> {
    if start > data.len().saturating_sub(pattern.len()) || data.len() < pattern.len() {
        return None;
    }
    data[start..].windows(pattern.len()).position(|w| w == pattern).map(|p| p + start)
}

/// One category of a custom destinations jump list
pub struct Entry {
    pub name: String,
    pub unknown0: i32,
    pub rank: f32,
    pub unknown2: i32,
    pub category_type: i32,
    pub known_category_id: i32,
    pub number_of_entries: i32,
    pub lnk_files: Vec<LnkFile>,
    pub parse_errors: Vec<String>,
    lnk_bytes: Vec<(String, Vec<u8>)>,
}

impl Entry {
    fn new(raw: &[u8], entry_offset: usize, code_page: i32, category_offset: usize) -> Entry {
        let i32_at = |at: usize| i32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let mut entry = Entry {
            name: String::new(),
            unknown0: i32_at(0),
            rank: f32::from_le_bytes(raw[4..8].try_into().unwrap()),
            unknown2: i32_at(8),
            category_type: i32_at(category_offset),
            known_category_id: 0,
            number_of_entries: 0,
            lnk_files: Vec::new(),
            parse_errors: Vec::new(),
            lnk_bytes: Vec::new(),
        };
        let mut field = category_offset + 4;
        if entry.category_type == 0 && raw.len() >= field + 2 {
            let mut length = i32::from(i16::from_le_bytes([raw[field], raw[field + 1]]));
            let available = ((raw.len() - field - 2) / 2) as i32;
            if length < 0 || length > available {
                entry.parse_errors.push(format!("Category name length is {length} characters, but only {available} are available"));
                length = length.min(available).max(0);
            }
            let name = unicode_string(raw, field as i64 + 2, i64::from(length) * 2).unwrap_or_default();
            entry.name = name.split('\0').next().unwrap_or_default().to_string();
            field += 2 + length as usize * 2;
            if raw.len() >= field + 4 {
                entry.number_of_entries = i32_at(field);
            }
        } else if entry.category_type == 1 && raw.len() >= field + 4 {
            entry.known_category_id = i32_at(field);
        } else if entry.category_type == 2 && raw.len() >= field + 4 {
            entry.number_of_entries = i32_at(field);
        }
        let footer = byte_search(raw, &FOOTER, 0).unwrap_or(raw.len());
        let mut offsets = Vec::new();
        let mut index = 0;
        while index < raw.len() {
            match byte_search(raw, &LNK_HEADER, index) {
                Some(found) if found < footer => {
                    offsets.push(found);
                    index = found + 1;
                }
                _ => break,
            }
        }
        for (counter, &start) in offsets.iter().enumerate() {
            let end = match offsets.get(counter + 1) {
                None => footer,
                Some(&next) => {
                    // the next shell object starts with its 16 byte class id, which isn't part of this LNK
                    if next >= CLASS_ID_SIZE && next - CLASS_ID_SIZE > start && raw[next - CLASS_ID_SIZE..next] == LNK_HEADER[4..] { next - CLASS_ID_SIZE } else { next }
                }
            };
            let bytes = raw[start..end].to_vec();
            let name = format!("Offset_0x{:X}.lnk", entry_offset + start);
            match read_lnk(&bytes, &name, code_page) {
                Ok(lnk) => entry.lnk_files.push(lnk),
                Err(e) => entry.parse_errors.push(format!("{name}: unable to parse LNK: {e}")),
            }
            entry.lnk_bytes.push((name, bytes));
        }
        entry
    }

    /// DumpAllLnkFiles
    pub fn dump_all_lnk_files(&self, folder: &Path, app_id: &str) -> std::io::Result<()> {
        for (name, bytes) in &self.lnk_bytes {
            if bytes.first() == Some(&0x4c) {
                std::fs::write(folder.join(format!("AppId_{app_id}_{name}")), bytes)?;
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::object(vec![
            ("Name", Value::text(self.name.as_str())),
            ("Unknown0", Value::number(self.unknown0)),
            ("Rank", Value::Float(self.rank)),
            ("Unknown2", Value::number(self.unknown2)),
            ("HeaderType", Value::number(self.category_type)),
            ("CategoryType", Value::number(self.category_type)),
            ("KnownCategoryId", Value::number(self.known_category_id)),
            ("NumberOfEntries", Value::number(self.number_of_entries)),
            ("LnkFiles", Value::List(self.lnk_files.iter().map(LnkFile::to_value).collect())),
            ("ParseErrors", Value::strings(&self.parse_errors)),
        ])
    }
}

pub struct CustomDestination {
    pub source_file: String,
    pub app_id: String,
    pub app_id_description: String,
    pub version: i32,
    pub number_of_categories: i32,
    pub entries: Vec<Entry>,
    pub parse_errors: Vec<String>,
}

/// What a custom jump list with no categories gives
pub const EMPTY_CUSTOM: &str = "Empty custom destinations jump list";

impl CustomDestination {
    /// new CustomDestination
    pub fn new(raw: &[u8], source_file: &str, code_page: i32, app_ids: &AppIdList) -> Result<CustomDestination, JumpListError> {
        if raw.is_empty() {
            return Err(JumpListError::parse("Empty file"));
        }
        if raw.len() <= 24 {
            return Err(JumpListError::parse(EMPTY_CUSTOM));
        }
        if raw[raw.len() - 4..] != FOOTER {
            return Err(JumpListError::parse("Invalid signature (footer missing)"));
        }
        let id = app_id(source_file);
        let at = |o: usize| i32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let mut out = CustomDestination {
            source_file: source_file.to_string(),
            app_id_description: app_ids.description(&id),
            app_id: id,
            version: at(0),
            number_of_categories: at(4),
            entries: Vec::new(),
            parse_errors: Vec::new(),
        };
        let mut footers = Vec::new();
        let mut index = 0;
        while let Some(found) = byte_search(raw, &FOOTER, index) {
            footers.push(found);
            index = found + FOOTER.len();
        }
        let mut chunk_start = 0;
        for footer in footers {
            let size = footer - chunk_start + 4;
            let bytes = &raw[chunk_start..chunk_start + size];
            if bytes.len() > 30 {
                let entry = Entry::new(bytes, chunk_start, code_page, if chunk_start == 0 { FILE_HEADER_SIZE } else { 0 });
                out.parse_errors.extend(entry.parse_errors.iter().map(|e| format!("Category at 0x{chunk_start:X}: {e}")));
                out.entries.push(entry);
            }
            chunk_start += size;
        }
        Ok(out)
    }

    /// The properties ServiceStack serializes
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("SourceFile", Value::text(self.source_file.as_str())),
            ("AppId", app_id_value(&self.app_id, &self.app_id_description)),
            ("Version", Value::number(self.version)),
            ("NumberOfCategories", Value::number(self.number_of_categories)),
            ("Entries", Value::List(self.entries.iter().map(Entry::to_value).collect())),
            ("ParseErrors", Value::strings(&self.parse_errors)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids_are_found_whatever_their_case() {
        let list = AppIdList::default();
        assert_eq!(list.description("0A1D19AFE5A80F80"), "FileZilla 2.2.32");
        assert_eq!(list.description("0a1d19afe5a80f80"), "FileZilla 2.2.32");
        assert_eq!(list.description("nope"), "Unknown AppId");
    }

    #[test]
    fn a_custom_list_needs_its_footer() {
        let list = AppIdList::default();
        assert_eq!(CustomDestination::new(&[], "a.customDestinations-ms", 1252, &list).err().unwrap().message, "Empty file");
        assert_eq!(CustomDestination::new(&[0; 20], "a.customDestinations-ms", 1252, &list).err().unwrap().message, EMPTY_CUSTOM);
        assert_eq!(CustomDestination::new(&[0; 40], "a.customDestinations-ms", 1252, &list).err().unwrap().message, "Invalid signature (footer missing)");
    }

    #[test]
    fn guids_in_a_shell_path_get_their_names() {
        let named = name_guids("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\x");
        assert!(named.starts_with("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\x ==> "));
        assert!(named.ends_with("\\x"));
    }
}
