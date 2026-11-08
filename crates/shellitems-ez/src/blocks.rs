//! The 0xbeefXXXX extension blocks: `BeefBase` and its classes.

use ez_common::Timestamp;
use ez_common::json::Value;
use ez_common::net::{NetResult, i16_at, u16_at, u32_at, u64_at, unicode_string};

use crate::items::{self, ShellItem};
use crate::sheet::PropertyStore;
use crate::utils::{self, LIST_INDEX, dos_time, from_file_time, guid_name, guid_text, n0, skip, skip_take, strings_from_multistring, time_text};

/// MFTInformation
#[derive(Clone, Debug, Default)]
pub struct MftInformation {
    pub entry_number: Option<u64>,
    pub sequence_number: Option<i32>,
    pub note: String,
}

impl MftInformation {
    fn read(raw: &[u8]) -> NetResult<MftInformation> {
        if raw.len() != 8 {
            return Err("rawMFTInfo must be 8 bytes long!".to_string());
        }
        let sequence = u16_at(raw, 6)?;
        let low = u64::from(u32_at(raw, 0)?);
        let high = u64::from(u16_at(raw, 4)?);
        let entry = if high == 0 { low } else { low + high * 16_777_216 };
        let mut note = String::new();
        if entry > 0 && sequence > 0 {
            note = "NTFS".into();
        }
        if entry > 0 && sequence == 0 {
            note = "FAT/CDFS".into();
        }
        if entry == 0 && sequence == 0 {
            note = "Network/special item".into();
        }
        Ok(MftInformation { entry_number: Some(entry), sequence_number: (sequence != 0).then_some(i32::from(sequence)), note })
    }
}

/// What differs from one class to another
#[derive(Clone, Debug)]
pub enum BlockKind {
    /// A class with nothing of its own: only the base's text
    Plain,
    /// The base's text followed by one more empty line (Beef0014)
    PlainExtraLine,
    /// BeefPlaceHolder: skipped in lists
    PlaceHolder,
    Guid1 { guid: Option<String>, folder: Option<String> },
    Guids { guid1: Option<String>, folder1: Option<String>, guid2: Option<String>, folder2: Option<String> },
    Beef0004 { created: Option<Timestamp>, last_access: Option<Timestamp>, identifier: i32, mft: MftInformation, long_name: String, localised_name: String },
    Beef0005 { internal_bags: Vec<ShellItem> },
    UserName(String),
    Beef0008 { timestamp: Timestamp, original_path: String, recycle_bin_path: String },
    Beef000b { file_strings: Vec<String>, string_date: Timestamp },
    Beef000e { bags: Vec<ShellItem> },
    /// Sheet #n lines of a store
    Sheets(PropertyStore),
    /// Beef0016
    Value(String),
    Beef0017 { details: String },
    /// Beef001a and Beef001b
    FileDocumentType(String),
    /// Beef001c
    Information(String),
    Executable(String),
    PinType(String),
    Beef0025 { file_time1: Timestamp, file_time2: Timestamp },
    Beef0026 { store: Option<PropertyStore>, created: Option<Timestamp>, modified: Option<Timestamp>, accessed: Option<Timestamp> },
}

/// An extension block
#[derive(Clone, Debug)]
pub struct Block {
    /// Its class's name, as LECmd shows it
    pub class: &'static str,
    pub size: i32,
    pub version: i32,
    pub signature: u32,
    pub version_offset: i32,
    pub message: String,
    pub kind: BlockKind,
    /// BeefParseError's RawBytes
    pub raw: Option<Vec<u8>>,
}

const UNSUPPORTED: &str = "Unsupported Extension block. Please report to Report to saericzimmerman@gmail.com to get it added!";
const PURPOSE_UNKNOWN: &str = "The purpose of this extension block is unknown";

fn header(class: &'static str, raw: &[u8]) -> NetResult<Block> {
    Ok(Block { class, size: i32::from(u16_at(raw, 0)?), version: i32::from(u16_at(raw, 2)?), signature: u32_at(raw, 4)?, version_offset: 0, message: String::new(), kind: BlockKind::Plain, raw: None })
}

/// The check at the start of most classes
fn checked(class: &'static str, raw: &[u8], wanted: u32, name: &str) -> NetResult<Block> {
    let block = header(class, raw)?;
    if block.signature != wanted {
        return Err(format!("Signature mismatch! Should be {name} but is 0x{:X}", block.signature));
    }
    Ok(block)
}

fn with_message(class: &'static str, raw: &[u8], message: &str) -> NetResult<Block> {
    let mut block = header(class, raw)?;
    block.message = message.to_string();
    Ok(block)
}

/// The 0x beef block with the terminated Unicode string at `start`: the string and where it ends
fn terminated(raw: &[u8], start: i64) -> NetResult<(String, i64)> {
    let mut len = 0i64;
    while ez_common::net::byte_at(raw, start + len)? != 0 || ez_common::net::byte_at(raw, start + len + 1)? != 0 {
        len += 2;
    }
    Ok((unicode_string(raw, start, len)?, start + len + 2))
}

fn store_block(class: &'static str, raw: &[u8], wanted: u32, name: &str, from: usize) -> NetResult<Block> {
    let mut block = checked(class, raw, wanted, name)?;
    let store = PropertyStore::read(skip(raw, from))?;
    block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
    block.kind = BlockKind::Sheets(store);
    Ok(block)
}

fn beef0004(raw: &[u8]) -> NetResult<Block> {
    let mut block = checked("Beef0004", raw, 0xbeef0004, "0xbeef0004")?;
    let created = dos_time(skip_take(raw, 8, 4))?;
    let last_access = dos_time(skip_take(raw, 12, 4))?;
    let identifier = i32::from(i16_at(raw, 16)?);
    let mut index = 18usize;
    let mut mft = MftInformation::default();
    if block.version >= 7 {
        index += 2;
        mft = MftInformation::read(skip_take(raw, index, 8))?;
        index += 16;
    }
    if block.version >= 3 {
        index += 2;
    }
    if block.version >= 9 {
        index += 4;
    }
    if block.version >= 8 {
        index += 4;
    }
    let long_size = raw.len() as i64 - index as i64;
    let pieces = strings_from_multistring(if long_size > 0 { skip(raw, index) } else { &[] })?;
    let long_name = pieces.first().cloned().ok_or(LIST_INDEX)?;
    let localised_name = pieces.get(1).cloned().unwrap_or_default();
    let mut at = index as i64 + long_size - 2;
    if at > raw.len() as i64 {
        at = raw.len() as i64 - 2;
    }
    block.version_offset = i32::from(u16_at(raw, at)?);
    block.kind = BlockKind::Beef0004 { created, last_access, identifier, mft, long_name, localised_name };
    Ok(block)
}

fn beef0005(raw: &[u8]) -> NetResult<Block> {
    let mut block = checked("Beef0005", raw, 0xbeef0005, "0xbeef0005")?;
    guid_text(skip_take(raw, 8, 16))?;
    let mut index = 24i64;
    let mut chunks = Vec::new();
    while index + 2 <= raw.len() as i64 {
        let size = i16_at(raw, index)?;
        if size <= 2 {
            break;
        }
        chunks.push(skip_take(raw, index as usize, size as usize));
        index += i64::from(size);
    }
    let mut bags = Vec::new();
    for chunk in chunks {
        let made = match ez_common::net::byte_at(chunk, 2)? {
            0x1f => items::new_0x1f(chunk),
            0x2f => items::new_0x2f(chunk),
            0x2e => items::new_0x2e(chunk),
            0x31 => items::new_0x31(chunk),
            _ => items::new_unknown(chunk),
        };
        bags.push(match made {
            Ok(item) => item,
            Err(_) => items::new_parse_error(chunk)?,
        });
    }
    block.version_offset = i32::from(i16_at(raw, 12)?);
    block.kind = BlockKind::Beef0005 { internal_bags: bags };
    Ok(block)
}

fn beef0008(raw: &[u8]) -> NetResult<Block> {
    let mut block = header("Beef0008", raw)?;
    let timestamp = from_file_time(ez_common::net::i64_at(raw, 0x10)?);
    let index = 0x10 + 8 + 4;
    let text = unicode_string(raw, index, raw.len() as i64 - index - 2)?;
    let strings = utils::split_nul_no_empty(&text);
    let index_error = || "Index was outside the bounds of the array.".to_string();
    block.kind = BlockKind::Beef0008 { timestamp, original_path: strings.first().ok_or_else(index_error)?.to_string(), recycle_bin_path: strings.get(1).ok_or_else(index_error)?.to_string() };
    Ok(block)
}

fn beef000b(raw: &[u8]) -> NetResult<Block> {
    let mut block = checked("Beef000b", raw, 0xbeef000b, "0xbeef000b")?;
    let text = utils::unicode(raw);
    let strings: Vec<&str> = text.split('\0').collect();
    let mut file_strings: Vec<String> = Vec::new();
    for s in &strings {
        if s.encode_utf16().count() < 5 {
            continue;
        }
        let good = s.strip_prefix('\u{1}').unwrap_or(s).to_string();
        if !file_strings.contains(&good) {
            file_strings.push(good);
        }
    }
    let string_date = match strings.get(13) {
        Some(s) => {
            let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            if bytes.len() >= 8 { from_file_time(ez_common::net::i64_at(&bytes, 0)?) } else { Timestamp::MIN }
        }
        None => Timestamp::MIN,
    };
    block.version_offset = i32::from(i16_at(raw, 12)?);
    block.kind = BlockKind::Beef000b { file_strings, string_date };
    Ok(block)
}

fn beef000e(raw: &[u8]) -> NetResult<Block> {
    let mut block = checked("Beef000e", raw, 0xbeef000e, "0xbeef000e")?;
    let mut index = 8i64;
    while ez_common::net::byte_at(raw, index)? != 0x14 {
        index += 1;
    }
    let mut chunks = Vec::new();
    let mut size = i16_at(raw, index)?;
    while size > 0 {
        chunks.push(ez_common::net::copy(raw, index, i64::from(size))?);
        index += i64::from(size);
        size = i16_at(raw, index)?;
    }
    let mut bags = Vec::new();
    for chunk in chunks {
        let id = ez_common::net::byte_at(chunk, 2)?;
        bags.push(items::by_type_or_unknown(id, chunk)?);
    }
    block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
    block.kind = BlockKind::Beef000e { bags };
    Ok(block)
}

fn beef0017(raw: &[u8]) -> NetResult<Block> {
    let mut block = with_message("Beef0017", raw, PURPOSE_UNKNOWN)?;
    let mut index = if raw.len() > 40 { 40i64 } else { 6 };
    i16_at(raw, index)?;
    index += 2;
    let mut size = i16_at(raw, index)?;
    let mut details = String::new();
    while size > 2 && index + i64::from(size) <= raw.len() as i64 {
        let bytes = &raw[index as usize..(index + i64::from(size)) as usize];
        index += i64::from(size);
        let id = ez_common::net::byte_at(bytes, 2)?;
        let made = match id {
            0x1f => items::new_0x1f(bytes),
            0x2f => items::new_0x2f(bytes),
            0x31 => items::new_0x31(bytes),
            0x74 => items::new_cfsf(bytes),
            _ => items::new_unknown(bytes),
        };
        match made {
            Ok(item) => {
                details.push_str(&item.to_text());
                details.push_str("\r\n");
            }
            Err(e) => {
                details.push_str(&format!("Shell item 0x{id:02X} could not be parsed: {e}\r\n"));
            }
        }
        size = if index + 2 <= raw.len() as i64 { i16_at(raw, index)? } else { 0 };
    }
    block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
    block.kind = BlockKind::Beef0017 { details };
    Ok(block)
}

fn beef0026(raw: &[u8]) -> NetResult<Block> {
    let mut block = checked("Beef0026", raw, 0xbeef0026, "Beef0026")?;
    let first = ez_common::net::byte_at(raw, 8)?;
    if matches!(first, 0x11 | 0x10 | 0x12 | 0x34 | 0x31) {
        let time = |at: i64| -> NetResult<Timestamp> { Ok(from_file_time(u64_at(raw, at)? as i64)) };
        block.kind = BlockKind::Beef0026 { store: None, created: Some(time(12)?), modified: Some(time(20)?), accessed: Some(time(28)?) };
        return Ok(block);
    }
    let size = u16_at(raw, 8)?;
    if i64::from(size) > raw.len() as i64 - 8 {
        block.kind = BlockKind::Beef0026 { store: None, created: None, modified: None, accessed: None };
        return Ok(block);
    }
    let store = PropertyStore::read(skip_take(raw, 8, usize::from(size)))?;
    block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 4)?);
    block.kind = BlockKind::Beef0026 { store: Some(store), created: None, modified: None, accessed: None };
    Ok(block)
}

/// new BeefPlaceHolder(null)
pub fn place_holder() -> Block {
    Block { class: "BeefPlaceHolder", size: 0, version: 0, signature: 0, version_offset: 0, message: String::new(), kind: BlockKind::PlaceHolder, raw: None }
}

/// Utils.GetExtensionBlockFromBytes
pub fn from_bytes(signature: i64, raw: &[u8]) -> NetResult<Block> {
    match signature {
        0xbeef0000 => {
            let mut block = checked("Beef0000", raw, 0xbeef0000, "0xbeef0000")?;
            if raw.len() == 0xe {
                block.kind = BlockKind::Guids { guid1: None, folder1: None, guid2: None, folder2: None };
                return Ok(block);
            }
            let guid1 = guid_text(skip_take(raw, 8, 16))?;
            let folder1 = guid_name(&guid1);
            if raw.len() == 0x18 {
                block.kind = BlockKind::Guids { guid1: Some(guid1), folder1: Some(folder1), guid2: Some("(Not found)".into()), folder2: Some("(NA)".into()) };
                return Ok(block);
            }
            let guid2 = guid_text(skip_take(raw, 24, 16))?;
            let folder2 = guid_name(&guid2);
            block.version_offset = i32::from(i16_at(raw, 40)?);
            block.kind = BlockKind::Guids { guid1: Some(guid1), folder1: Some(folder1), guid2: Some(guid2), folder2: Some(folder2) };
            Ok(block)
        }
        0xbeef0001 => with_message("Beef0001", raw, UNSUPPORTED),
        0xbeef0002 => with_message("Beef0002", raw, UNSUPPORTED),
        0xbeef0009 => with_message("Beef0009", raw, UNSUPPORTED),
        0xbeef000c => with_message("Beef000c", raw, UNSUPPORTED),
        0xbeef0014 => {
            let mut block = with_message("Beef0014", raw, UNSUPPORTED)?;
            block.kind = BlockKind::PlainExtraLine;
            Ok(block)
        }
        0xbeef0003 => {
            let mut block = checked("Beef0003", raw, 0xbeef0003, "0xbeef0003")?;
            let guid = guid_text(skip_take(raw, 8, 16))?;
            let folder = guid_name(&guid);
            block.version_offset = i32::from(i16_at(raw, 24)?);
            block.kind = BlockKind::Guid1 { guid: Some(guid), folder: Some(folder) };
            Ok(block)
        }
        0xbeef0004 => beef0004(raw),
        0xbeef0005 => beef0005(raw),
        0xbeef0006 => {
            let mut block = checked("Beef0006", raw, 0xbeef0006, "0xbeef0006")?;
            let (name, end) = terminated(raw, 8)?;
            block.version_offset = i32::from(i16_at(raw, end)?);
            block.kind = BlockKind::UserName(name);
            Ok(block)
        }
        0xbeef0008 => beef0008(raw),
        0xbeef000a => {
            let mut block = checked("Beef000a", raw, 0xbeef000a, "0xbeef000a")?;
            block.message = format!("The purpose of this extension block is unknown. Bytes: {}", ez_common::net::hex(raw));
            block.version_offset = i32::from(i16_at(raw, 12)?);
            Ok(block)
        }
        0xbeef000b => beef000b(raw),
        0xbeef000e => beef000e(raw),
        0xbeef0010 => store_block("Beef0010", raw, 0xbeef0010, "0xbeef0010", 16),
        0xbeef0013 => {
            let mut block = checked("Beef0013", raw, 0xbeef0013, "0xbeef0013")?;
            block.message = PURPOSE_UNKNOWN.to_string();
            block.version_offset = i32::from(i16_at(raw, 40)?);
            Ok(block)
        }
        0xbeef0015 | 0xbeef0029 => {
            let (class, name, wanted) = if signature == 0xbeef0015 { ("Beef0015", "0xbeef0015", 0xbeef0015) } else { ("Beef0029", "0xbeef0029", 0xbeef0029) };
            let mut block = checked(class, raw, wanted, name)?;
            block.message = PURPOSE_UNKNOWN.to_string();
            block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
            Ok(block)
        }
        0xbeef0016 => {
            let mut block = checked("Beef0016", raw, 0xbeef0016, "0xbeef0016")?;
            let value = unicode_string(raw, 10, raw.len() as i64 - 14)?;
            block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
            block.kind = BlockKind::Value(value);
            Ok(block)
        }
        0xbeef0017 => beef0017(raw),
        0xbeef0019 => {
            let mut block = checked("Beef0019", raw, 0xbeef0019, "0xbeef0019")?;
            let guid1 = guid_text(skip_take(raw, 8, 16))?;
            let folder1 = guid_name(&guid1);
            let guid2 = guid_text(skip_take(raw, 24, 16))?;
            let folder2 = guid_name(&guid2);
            block.version_offset = i32::from(i16_at(raw, 40)?);
            block.kind = BlockKind::Guids { guid1: Some(guid1), folder1: Some(folder1), guid2: Some(guid2), folder2: Some(folder2) };
            Ok(block)
        }
        0xbeef001a | 0xbeef001b => {
            let (class, name, wanted) = if signature == 0xbeef001a { ("Beef001a", "Beef001a", 0xbeef001a) } else { ("Beef001b", "Beef001b", 0xbeef001b) };
            let mut block = checked(class, raw, wanted, name)?;
            let (text, end) = terminated(raw, 10)?;
            block.version_offset = i32::from(i16_at(raw, end)?);
            block.kind = BlockKind::FileDocumentType(text);
            Ok(block)
        }
        0xbeef001c => {
            let mut block = checked("Beef001c", raw, 0xbeef001c, "Beef001c")?;
            let (text, end) = terminated(raw, 10)?;
            block.version_offset = i32::from(i16_at(raw, end)?);
            block.kind = BlockKind::Information(text);
            Ok(block)
        }
        0xbeef001d | 0xbeef001e => {
            let (class, name, wanted) = if signature == 0xbeef001d { ("Beef001d", "Beef001d", 0xbeef001d) } else { ("Beef001e", "Beef001e", 0xbeef001e) };
            let mut block = checked(class, raw, wanted, name)?;
            let text = unicode_string(raw, 10, raw.len() as i64 - 12)?.trim_matches('\0').to_string();
            block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 2)?);
            block.kind = if signature == 0xbeef001d { BlockKind::Executable(text) } else { BlockKind::PinType(text) };
            Ok(block)
        }
        0xbeef0021 => store_block("Beef0021", raw, 0xbeef0021, "0xbeef0021", 8),
        0xbeef0022 => store_block("Beef0022", raw, 0xbeef0022, "0xbeef0022", 8),
        0xbeef0024 => store_block("Beef0024", raw, 0xbeef0024, "0xbeef0024", 8),
        0xbeef0027 => store_block("Beef0027", raw, 0xbeef0027, "0xbeef0027", 8),
        0xbeef0025 => {
            let mut block = checked("Beef0025", raw, 0xbeef0025, "Beef0025")?;
            let file_time1 = from_file_time(u64_at(raw, 12)? as i64);
            let file_time2 = from_file_time(u64_at(raw, 20)? as i64);
            block.version_offset = i32::from(i16_at(raw, raw.len() as i64 - 4)?);
            block.kind = BlockKind::Beef0025 { file_time1, file_time2 };
            Ok(block)
        }
        0xbeef0026 => beef0026(raw),
        _ => with_message("BeefUnknown", raw, "********UNKNOWN Extension block. Please report to Report to saericzimmerman@gmail.com to get it added!"),
    }
}

/// Utils.GetExtensionBlockFromBytesOrError: the type from its own signature byte, and a BeefParseError for what can't be read
pub fn from_bytes_or_error(raw: &[u8]) -> Block {
    if raw.len() < 8 {
        let mut block = Block { class: "BeefParseError", size: 0, version: 0, signature: 0, version_offset: 0, message: String::new(), kind: BlockKind::Plain, raw: Some(raw.to_vec()) };
        block.message = format!("Extension block could not be parsed: only {} bytes", raw.len());
        return block;
    }
    match from_bytes(0xbeef0000 | i64::from(raw[4]), raw) {
        Ok(block) => block,
        Err(e) => {
            let mut block = header("BeefParseError", raw).expect("8 bytes are there");
            block.message = format!("Extension block could not be parsed: {e}");
            block.raw = Some(raw.to_vec());
            block
        }
    }
}

impl Block {
    fn base_text(&self) -> String {
        let mut s = format!("Signature: 0x{:08x}\r\nSize: {}\r\nVersion: {}\r\nVersion Offset: 0x{:02X}\r\n", self.signature, n0(i64::from(self.size)), n0(i64::from(self.version)), self.version_offset);
        if !self.message.is_empty() {
            s.push_str(&format!("\r\nMessage: {}\r\n", self.message));
        }
        s
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        if matches!(self.kind, BlockKind::PlaceHolder) {
            return "This is a placeholder bag to account for additional extension blocks inside internal ShellBags\r\n".to_string();
        }
        let mut s = self.base_text();
        s.push_str("\r\n");
        let opt = |o: &Option<String>| o.clone().unwrap_or_default();
        match &self.kind {
            BlockKind::Plain | BlockKind::PlaceHolder => {}
            BlockKind::PlainExtraLine => s.push_str("\r\n"),
            BlockKind::Guid1 { guid, folder } => {
                s.push_str(&format!("\r\nGUID 1: {}\r\nGUID 1 Folder: {}\r\n", opt(guid), opt(folder)));
            }
            BlockKind::Guids { guid1, folder1, guid2, folder2 } => {
                s.push_str(&format!("\r\nGUID 1: {}\r\nGUID 1 Folder: {}\r\nGUID 2: {}\r\nGUID 2 Folder: {}\r\n", opt(guid1), opt(folder1), opt(guid2), opt(folder2)));
            }
            BlockKind::Beef0004 { created, last_access, identifier, mft, long_name, localised_name } => {
                let os = match identifier {
                    0x14 => "Windows XP, 2003",
                    0x26 => "Windows Vista",
                    0x2a => "Windows 2008, 7, 8",
                    0x2e => "Windows 8.1/Windows 10",
                    _ => "Unknown operating system",
                };
                s.push_str(&format!("Identifier: {identifier:02X} ({os})\r\n"));
                if let Some(t) = created {
                    s.push_str(&format!("\r\nCreated On: {}\r\n", time_text(*t)));
                }
                if let Some(t) = last_access {
                    s.push_str(&format!("Last Access: {}\r\n", time_text(*t)));
                }
                s.push_str(&format!("\r\nLong Name: {long_name}\r\n"));
                if !localised_name.is_empty() {
                    s.push_str(&format!("Localised Name: {localised_name}\r\n"));
                }
                if let Some(e) = mft.entry_number {
                    s.push_str(&format!("\r\nMFT Entry Number: {e}\r\n"));
                }
                if let Some(q) = mft.sequence_number {
                    s.push_str(&format!("MFT Sequence Number: {q}\r\n"));
                }
                s.push_str("\r\n");
                let mut note = mft.note.clone();
                if let (Some(e), Some(q)) = (mft.entry_number, mft.sequence_number) {
                    if e > 0 && q > 0 {
                        note = "NTFS".into();
                    }
                }
                if mft.entry_number.is_some() && mft.sequence_number.is_none() {
                    if let Some(t) = last_access {
                        let p = t.parts();
                        note = if p.minute == 0 && p.second == 0 && p.fraction / 10_000 == 0 { "FAT".into() } else { "exFAT".into() };
                    }
                }
                if !note.is_empty() {
                    s.push_str(&format!("File system hint: {note}\r\n"));
                }
            }
            BlockKind::Beef0005 { internal_bags } => {
                for bag in internal_bags {
                    s.push_str(&bag.to_text());
                    s.push_str("\r\n\r\n");
                }
            }
            BlockKind::UserName(name) => s.push_str(&format!("\r\nUser Name: {name}\r\n")),
            BlockKind::Beef0008 { timestamp, original_path, recycle_bin_path } => {
                s.push_str(&format!("\r\nTimestamp: {}\r\nOriginal path: {original_path}\r\nRecycle Bin path {recycle_bin_path}\r\n", time_text(*timestamp)));
            }
            BlockKind::Beef000b { file_strings, string_date } => {
                s.push_str("\r\n");
                for f in file_strings {
                    s.push_str(&format!("File: {f}\r\n"));
                }
                s.push_str(&format!("String date: {}\r\n", time_text(*string_date)));
            }
            BlockKind::Beef000e { bags } => {
                if !bags.is_empty() {
                    s.push_str(&format!("\r\nInternal ShellBags found: {}\r\n", bags.len()));
                    for (i, bag) in bags.iter().enumerate() {
                        s.push_str(&format!("---------------------- Bag {} ----------------------\r\n{}\r\n", n0(i as i64), bag.to_text()));
                    }
                    s.push_str("--------------------------------------------------\r\n");
                }
            }
            BlockKind::Sheets(store) => {
                for (i, sheet) in store.sheets.iter().enumerate() {
                    s.push_str(&format!("Sheet #{i} => {}\r\n", sheet.to_text()));
                }
            }
            BlockKind::Value(value) => s.push_str(&format!("Value: {value}\r\n")),
            BlockKind::Beef0017 { details } => {
                if !details.is_empty() {
                    s.push_str(&format!("Sub shell items detail:\r\n\r\n{details}\r\n"));
                }
            }
            BlockKind::FileDocumentType(text) => s.push_str(&format!("\r\nFile Document Type String: {text}\r\n")),
            BlockKind::Information(text) => s.push_str(&format!("\r\nFile name: {text}\r\n")),
            BlockKind::Executable(text) => s.push_str(&format!("\r\nExecutable: {text}\r\n")),
            BlockKind::PinType(text) => s.push_str(&format!("\r\nPin Type: {text}\r\n")),
            BlockKind::Beef0025 { file_time1, file_time2 } => {
                s.push_str(&format!("\r\nFileTime 1: {}\r\nFileTime 2: {}\r\n", time_text(*file_time1), time_text(*file_time2)));
            }
            BlockKind::Beef0026 { store, created, modified, accessed } => {
                const FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";
                s.push_str("\r\n");
                if let Some(t) = created {
                    s.push_str(&format!("Created: {}\r\n", t.format(FORMAT)));
                }
                if let Some(t) = modified {
                    s.push_str(&format!("Last modified: {}\r\n", t.format(FORMAT)));
                }
                if let Some(t) = accessed {
                    s.push_str(&format!("Last accessed: {}\r\n", t.format(FORMAT)));
                }
                if let Some(store) = store {
                    if !store.sheets.is_empty() {
                        s.push_str(&format!("Property Sheets\r\n{}\r\n\r\n", store.to_text()));
                    }
                }
            }
        }
        s
    }

    /// The properties ServiceStack serializes, with the type name it adds for an IExtensionBlock
    pub fn to_value(&self) -> Value {
        let opt = |o: &Option<String>| Value::opt_text(o.as_deref());
        let guids = |g1: &Option<String>, f1: &Option<String>| vec![("GUID1", opt(g1)), ("GUID1Folder", opt(f1))];
        let mut own: Vec<(&'static str, Value)> = match &self.kind {
            BlockKind::Plain | BlockKind::PlainExtraLine | BlockKind::PlaceHolder => Vec::new(),
            BlockKind::Guid1 { guid, folder } => guids(guid, folder),
            BlockKind::Guids { guid1, folder1, guid2, folder2 } => {
                let mut list = guids(guid1, folder1);
                list.push(("GUID2", opt(guid2)));
                list.push(("GUID2Folder", opt(folder2)));
                list
            }
            BlockKind::Beef0004 { created, last_access, identifier, mft, long_name, localised_name } => vec![
                ("CreatedOnTime", Value::opt_time(*created)),
                ("LastAccessTime", Value::opt_time(*last_access)),
                ("Identifier", Value::number(identifier)),
                (
                    "MFTInformation",
                    Value::object(vec![
                        ("MFTEntryNumber", mft.entry_number.map_or(Value::Null, Value::number)),
                        ("MFTSequenceNumber", mft.sequence_number.map_or(Value::Null, Value::number)),
                        // read from bytes, it's only set when it says something; a block without these bytes has it empty
                        ("Note", if mft.entry_number.is_some() && mft.note.is_empty() { Value::Null } else { Value::text(mft.note.as_str()) }),
                    ]),
                ),
                ("LongName", Value::text(long_name.as_str())),
                ("LocalisedName", Value::text(localised_name.as_str())),
            ],
            BlockKind::Beef0005 { internal_bags } => vec![("InternalBags", Value::List(internal_bags.iter().map(ShellItem::to_value).collect()))],
            BlockKind::UserName(name) => vec![("UserName", Value::text(name.as_str()))],
            BlockKind::Beef0008 { timestamp, original_path, recycle_bin_path } => {
                vec![("RecycleBinPath", Value::text(recycle_bin_path.as_str())), ("OriginalPath", Value::text(original_path.as_str())), ("Timestamp", Value::time(*timestamp))]
            }
            BlockKind::Beef000b { file_strings, string_date } => vec![("FileStrings", Value::strings(file_strings)), ("StringDate", Value::required_time(*string_date))],
            BlockKind::Beef000e { .. } => vec![("ExtensionBlocks", Value::List(Vec::new())), ("PropertyStores", Value::List(Vec::new()))],
            BlockKind::Sheets(store) => vec![("PropertyStore", store.to_value())],
            BlockKind::Value(value) => vec![("Value", Value::text(value.as_str()))],
            BlockKind::Beef0017 { details } => vec![("SubShellDetails", Value::text(details.as_str()))],
            BlockKind::FileDocumentType(text) => vec![("FileDocumentTypeString", Value::text(text.as_str()))],
            BlockKind::Information(text) => vec![("Information", Value::text(text.as_str()))],
            BlockKind::Executable(text) => vec![("Executable", Value::text(text.as_str()))],
            BlockKind::PinType(text) => vec![("PinType", Value::text(text.as_str()))],
            BlockKind::Beef0025 { file_time1, file_time2 } => vec![("FileTime1", Value::time(*file_time1)), ("FileTime2", Value::time(*file_time2))],
            BlockKind::Beef0026 { store, created, modified, accessed } => vec![
                ("PropertyStore", store.as_ref().map_or(Value::Null, PropertyStore::to_value)),
                ("CreatedOn", Value::opt_time(*created)),
                ("LastModified", Value::opt_time(*modified)),
                ("LastAccessed", Value::opt_time(*accessed)),
            ],
        };
        if let Some(raw) = &self.raw {
            own.push(("RawBytes", Value::bytes(raw)));
        }
        let mut properties = vec![("__type", Value::text(format!("ExtensionBlocks.{}, ExtensionBlocks", self.class)))];
        properties.extend(own);
        // a place holder's base constructor returned at once, leaving the message null
        properties.push(("Message", if self.is_place_holder() { Value::Null } else { Value::text(self.message.as_str()) }));
        properties.push(("Size", Value::number(self.size)));
        properties.push(("Version", Value::number(self.version)));
        properties.push(("Signature", Value::number(self.signature)));
        properties.push(("VersionOffset", Value::number(self.version_offset)));
        Value::object(properties)
    }

    pub fn is_place_holder(&self) -> bool {
        matches!(self.kind, BlockKind::PlaceHolder)
    }
}

