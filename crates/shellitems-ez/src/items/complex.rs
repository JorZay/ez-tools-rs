//! The shell item classes with most to read: files and folders, property views.

use ez_common::Timestamp;
use ez_common::net::{NetResult, byte_at, copy, i16_at, i32_at, i64_at, u16_at, u32_at, u64_at, unicode_string};

use super::simple::block_at;
use super::*;
use crate::utils::{ansi, ansi_at, array_copy, from_file_time, guid_name, guid_text, index_of, skip_take, split_nul_no_empty};

/// A null where the original goes on to use a store that was never set
const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";

/// Splits the blocks at the end of an item, as 0x31 and 0x32 do: separators are skipped, a block longer than what is left is read
/// as far as it goes
fn block_chunks(raw: &[u8], mut index: i64) -> NetResult<Vec<&[u8]>> {
    let mut chunks = Vec::new();
    while index < raw.len() as i64 {
        let size = i16_at(raw, index)?;
        if size == 0 {
            index += 2;
        }
        if size == 1 {
            index += 2;
        } else if size > 0 {
            let length = i64::from(size).min(raw.len() as i64 - index);
            chunks.push(&raw[index as usize..(index + length) as usize]);
            index += i64::from(size);
        } else if size < 0 {
            break;
        }
    }
    Ok(chunks)
}

/// new ShellBag0X31
pub fn new_0x31(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X31", "Directory", raw);
    let mut index = 8i64;
    let modified = dos_time_at(raw, index)?;
    item.last_modification = modified;
    index += 4 + 2;
    let beef_position = index_of(raw, &BEEF0004_SIGNATURE, index + 4).max(0);
    let before = |short: &str| {
        let mut s = String::new();
        if !short.is_empty() {
            s.push_str(&format!("Short name: {short}\n"));
        }
        s.push_str(&time_line("Modified", modified));
        s.push('\n');
        s
    };
    if beef_position == 0 {
        let text = ansi_at(raw, index, raw.len() as i64 - index)?;
        let short = split_nul_no_empty(&text).join("|");
        item.value = short.clone();
        item.set_before_line(Some(before(&short)));
        item.short_name = Some(short);
        return Ok(item);
    }
    let beef_position = beef_position - 4;
    let unicode_name = matches!(byte_at(raw, 2)?, 0x35 | 0x36);
    let mut len = 0i64;
    if unicode_name {
        len = beef_position - index;
    } else {
        while index + len < raw.len() as i64 && raw[(index + len) as usize] != 0 {
            len += 1;
        }
    }
    let name_bytes = array_copy(raw, index, len)?;
    let short = if unicode_name { crate::utils::unicode(name_bytes) } else { ansi(name_bytes)? };
    item.value = short.clone();
    item.set_before_line(Some(before(&short)));
    item.short_name = Some(short);
    for bytes in block_chunks(raw, beef_position)? {
        i16_at(bytes, 0)?;
        u32_at(bytes, 4)?;
        let block = crate::blocks::from_bytes_or_error(bytes);
        let is_beef00 = format!("{:X}", block.signature).starts_with("BEEF00");
        let long_name = if let crate::blocks::BlockKind::Beef0004 { long_name, .. } = &block.kind { Some(long_name.clone()) } else { None };
        let bags = if let crate::blocks::BlockKind::Beef0005 { internal_bags } = &block.kind { internal_bags.len() } else { 0 };
        if is_beef00 {
            item.extension_blocks.push(block);
        }
        if let Some(name) = long_name.filter(|n| !n.is_empty()) {
            item.value = name;
        }
        for _ in 0..bags {
            item.extension_blocks.push(crate::blocks::place_holder());
        }
    }
    Ok(item)
}

fn dos_time_at(raw: &[u8], index: i64) -> NetResult<Option<Timestamp>> {
    crate::utils::dos_time(skip_take(raw, index as usize, 4))
}

fn wrapper(class: &'static str, raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = new_0x31(raw)?;
    item.class = class;
    Ok(item)
}

pub fn new_0x35(raw: &[u8]) -> NetResult<ShellItem> {
    wrapper("ShellBag0X35", raw)
}
pub fn new_0x36(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = wrapper("ShellBag0X36", raw)?;
    item.friendly_name = "File".to_string();
    Ok(item)
}
pub fn new_0x39(raw: &[u8]) -> NetResult<ShellItem> {
    wrapper("ShellBag0X39", raw)
}
pub fn new_0x3d(raw: &[u8]) -> NetResult<ShellItem> {
    wrapper("ShellBag0X3D", raw)
}
pub fn new_0xb1(raw: &[u8]) -> NetResult<ShellItem> {
    wrapper("ShellBag0XB1", raw)
}
pub fn new_0xb5(raw: &[u8]) -> NetResult<ShellItem> {
    wrapper("ShellBag0XB5", raw)
}

fn has_beef0004(raw: &[u8]) -> bool {
    raw.windows(4).any(|w| w == BEEF0004_SIGNATURE)
}

/// new ShellBag0X32
pub fn new_0x32(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X32", "File", raw);
    let text_before = |short: &str, size: i32, modified: Option<Timestamp>| {
        let mut s = String::new();
        if !short.is_empty() {
            s.push_str(&format!("Short name: {short}\n"));
        }
        if size > 0 {
            s.push_str(&format!("\nFile size: {}\n", crate::utils::n0(i64::from(size))));
        }
        s.push_str(&time_line("Modified On", modified));
        s.push('\n');
        s
    };
    if byte_at(raw, 4)? == 0x10 && !has_beef0004(raw) {
        item.friendly_name = "ZipFileContents".to_string();
        let modified = Some(from_file_time(i64_at(raw, 16)?));
        item.last_modification = modified;
        let len1 = i32::from(i16_at(raw, 28)?);
        let len2 = i32::from(i16_at(raw, 30)?);
        let length = ((len1 + len2) * 2).max(0).min((raw.len() as i32 - 32).max(0));
        item.value = unicode_string(raw, 32, i64::from(length))?.replace('\0', "");
        item.short_name = Some(String::new());
        item.set_before_line(Some(text_before("", 0, modified)));
        return Ok(item);
    }
    let size = u32_at(raw, 4)? as i32;
    let modified = crate::utils::dos_time(array_copy(raw, 8, 4)?)?;
    item.last_modification = modified;
    let mut index = 14i64;
    let mut len = 0i64;
    while index + len < raw.len() as i64 && raw[(index + len) as usize] != 0 {
        len += 1;
    }
    let short = ansi(array_copy(raw, index, len)?)?;
    index += len;
    let beef_position = index_of(raw, &BEEF0004_SIGNATURE, index).max(0);
    if beef_position == 0 {
        let text = ansi_at(raw, index, raw.len() as i64 - index)?;
        let joined = split_nul_no_empty(&text).join("|");
        item.value = joined.clone();
        item.set_before_line(Some(text_before(&joined, size, modified)));
        item.short_name = Some(joined);
        return Ok(item);
    }
    item.set_before_line(Some(text_before(&short, size, modified)));
    item.short_name = Some(short);
    for bytes in block_chunks(raw, beef_position - 4)? {
        i16_at(bytes, 0)?;
        u32_at(bytes, 4)?;
        let block = crate::blocks::from_bytes_or_error(bytes);
        if let crate::blocks::BlockKind::Beef0004 { long_name, .. } = &block.kind {
            item.value = long_name.clone();
        }
        item.extension_blocks.push(block);
    }
    Ok(item)
}

/// The "32" sheets' hack: the blocks inside a property store. What can't be read ends it quietly
fn blocks_in_store(raw: &[u8], out: &mut Vec<crate::blocks::Block>) {
    for offset in crate::utils::find_extension_block_signatures(raw) {
        let at = offset - 4;
        let Ok(size) = i16_at(raw, at) else { return };
        let bytes = if size >= 0 { skip_take(raw, at as usize, size as usize) } else { &[] };
        if u32_at(bytes, 4).is_err() {
            return;
        }
        out.push(crate::blocks::from_bytes_or_error(bytes));
    }
}

fn has_key(store: &PropertyStore, key: &str) -> bool {
    store.sheets.iter().any(|s| s.property_names.iter().any(|(k, _)| k == key))
}

/// The value of a property view: property 10, or all of them
fn view_value(store: &PropertyStore, nothing: &str) -> String {
    let first = store.sheets.iter().flat_map(|s| &s.property_names).find(|(k, _)| k == "10").map(|(_, v)| v.clone());
    let value = first.unwrap_or_else(|| store.sheets.iter().flat_map(|s| &s.property_names).map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("::"));
    if value.is_empty() { nothing.to_string() } else { value }
}

/// The blocks after a property view, and the terminator after them
fn view_blocks(item: &mut ShellItem, raw: &[u8], mut index: i64) -> NetResult<()> {
    let mut size = i16_at(raw, index)?;
    while size > 0 {
        let bytes = skip_take(raw, index as usize, size as usize);
        index += i64::from(size);
        u32_at(bytes, 4)?;
        item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
        size = i16_at(raw, index)?;
    }
    let terminator = i32::from(i16_at(raw, index)?);
    if terminator > 0 {
        return Err(format!("Expected terminator of 0, but got {terminator}"));
    }
    Ok(())
}

/// ProcessPropertyViewDefault, as 0x1F (no GUIDs, an empty store from the start) and 0x4D, 0x71, 0x74 (two GUIDs, and no store
/// unless one is read) have it. The text shows the store's sheets
pub(super) fn property_view(item: &mut ShellItem, raw: &[u8], guids: bool) -> NetResult<()> {
    item.friendly_name = "Variable: Users property view".to_string();
    let mut index = 10i64;
    let list_size = i16_at(raw, index)?;
    index += 2;
    let identifier_size = i16_at(raw, index)?;
    index += 2;
    array_copy(raw, index, i64::from(identifier_size))?;
    index += i64::from(identifier_size);
    if list_size > 0 {
        let bytes = skip_take(raw, index as usize, list_size as usize);
        let store = PropertyStore::read(bytes)?;
        if has_key(&store, "32") {
            blocks_in_store(bytes, &mut item.extension_blocks);
        }
        item.property_store = Some(store);
    }
    index += i64::from(list_size) + 2;
    if guids {
        guid_text(if index >= 0 { skip_take(raw, index as usize, 16) } else { raw })?;
        index += 16;
        let name = guid_name(&guid_text(if index >= 0 { skip_take(raw, index as usize, 16) } else { raw })?);
        item.value = name;
        index += 16;
    }
    view_blocks(item, raw, index)?;
    let store = if guids { item.property_store.as_ref().ok_or(NULL_REFERENCE)? } else { item.property_store.get_or_insert_with(PropertyStore::default) };
    let value = view_value(store, "No Property sheets found");
    item.value = value;
    store_part(item);
    Ok(())
}

/// The store's sheets in the text, when there are any
fn store_part(item: &mut ShellItem) {
    if let Some(store) = &item.property_store {
        if !store.sheets.is_empty() {
            item.parts.push(Part::Store("Property Sheets\n".to_string(), store.clone()));
        }
    }
}

fn process_guid(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Root folder: GUID".to_string();
    item.value = guid_name(&guid_text(array_copy(raw, 4, 16)?)?);
    Ok(())
}

fn windows_backup(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Windows Backup".to_string();
    let backup = from_file_time(i64_at(raw, 0xc)?);
    let modified = from_file_time(i64_at(raw, 0x14)?);
    let created = from_file_time(i64_at(raw, 0x1c)?);
    let unknown = from_file_time(i64_at(raw, 0x24)?);
    let mut index = 0x24i64 + 8 + 12;
    let name_length = i64::from(i16_at(raw, index)?);
    index += 2;
    item.value = unicode_string(raw, index, name_length * 2)?;
    index += name_length * 2 + 4;
    guid_text(copy(raw, index, 16)?)?;
    index += 16;
    guid_text(copy(raw, index, 16)?)?;
    item.parts.push(Part::Text(format!(
        "Modified Date From Backup: {}\n\nCreated Date From Backup: {}\n\nBackup Date Time: {}\n\nBackup Unknown Date Time: {}\n\n",
        crate::utils::time_text(modified),
        crate::utils::time_text(created),
        crate::utils::time_text(backup),
        crate::utils::time_text(unknown)
    )));
    Ok(())
}

/// A small reader over an item, as the BinaryReader of 0x1F and 0x79
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

const END_OF_STREAM: &str = "Unable to read beyond the end of the stream.";

impl<'a> Reader<'a> {
    fn bytes(&mut self, count: usize) -> &'a [u8] {
        let end = (self.at + count).min(self.raw.len());
        let out = &self.raw[self.at.min(end)..end];
        self.at = end;
        out
    }

    fn u16(&mut self) -> NetResult<u16> {
        if self.at + 2 > self.raw.len() {
            self.at = self.raw.len();
            return Err(END_OF_STREAM.to_string());
        }
        let v = u16::from_le_bytes([self.raw[self.at], self.raw[self.at + 1]]);
        self.at += 2;
        Ok(v)
    }

    fn u32(&mut self) -> NetResult<u32> {
        if self.at + 4 > self.raw.len() {
            self.at = self.raw.len();
            return Err(END_OF_STREAM.to_string());
        }
        self.at += 4;
        Ok(u32::from_le_bytes(self.raw[self.at - 4..self.at].try_into().unwrap()))
    }
}

/// 0x1F and 0x79: they only differ in how careful they are with the blocks at the end
fn root_item(class: &'static str, raw: &[u8], careful: bool) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, "", raw);
    item.property_store = Some(PropertyStore::default());
    if byte_at(raw, 0)? == 0x14 {
        process_guid(&mut item, raw)?;
        return Ok(item);
    }
    if byte_at(raw, 4)? == 0x2f {
        item.value = ansi_at(raw, 13, 3)?;
        item.friendly_name = "Users property view: Drive letter".to_string();
        return Ok(item);
    }
    match byte_at(raw, 3)? & 0x70 {
        0x00 | 0x60 => {}
        0x40 => {
            process_guid(&mut item, raw)?;
            let mut index = 20i64;
            let mut size = i16_at(raw, index)?;
            while size > 0 {
                item.extension_blocks.push(block_at(raw, index)?);
                index += i64::from(size);
                if index == raw.len() as i64 {
                    return Ok(item);
                }
                size = i16_at(raw, index)?;
            }
            if index != raw.len() as i64 {
                i16_at(raw, index)?;
            }
            return Ok(item);
        }
        0x70 => {
            process_guid(&mut item, raw)?;
            return Ok(item);
        }
        other => return Err(format!("unknown off3bitmask: 0x{other:02X}")),
    }
    let signature = u32_at(raw, 6)?;
    if signature == 0xbeebee00 {
        property_view(&mut item, raw, false)?;
        return Ok(item);
    }
    if signature == 0x4c644970 {
        windows_backup(&mut item, raw)?;
        return Ok(item);
    }
    if raw[0] == 50 || raw[0] == 58 {
        process_guid(&mut item, raw)?;
        let size = i16_at(raw, 20)?;
        if size > 0 {
            item.extension_blocks.push(block_at(raw, 20)?);
        }
        return Ok(item);
    }
    item.friendly_name = "Users property view".to_string();
    let mut reader = Reader { raw, at: 0 };
    reader.bytes(3);
    reader.bytes(1);
    reader.u16()?;
    reader.u32()?;
    let store_size = reader.u16()?;
    let identifier_size = reader.u16()?;
    if identifier_size > 0 {
        reader.bytes(usize::from(identifier_size));
    }
    if store_size > 0 {
        item.property_store = Some(PropertyStore::read(reader.bytes(usize::from(store_size)))?);
    }
    reader.bytes(2);
    store_part(&mut item);
    if reader.at == raw.len() {
        item.value = guid_name(&guid_text(copy(raw, 4, 16)?)?);
        let size = i16_at(raw, 20)?;
        let bytes = if size >= 0 { skip_take(raw, 20, size as usize) } else { &[] };
        u32_at(bytes, 4)?;
        item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
        return Ok(item);
    }
    guid_text(reader.bytes(16))?;
    let name = guid_name(&guid_text(reader.bytes(16))?);
    if careful {
        let first = if raw.len() - reader.at >= 2 { reader.u16()? } else { 0 };
        if first > 0 {
            reader.at -= 2;
            while raw.len() - reader.at >= 2 {
                let size = reader.u16()?;
                if size < 8 || i64::from(size) > (raw.len() - reader.at) as i64 + 2 {
                    break;
                }
                reader.at -= 2;
                let bytes = reader.bytes(usize::from(size));
                u32_at(bytes, 4)?;
                item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
            }
        }
    } else {
        let first = reader.u16()?;
        if first > 0 {
            reader.at -= 2;
            while reader.at != raw.len() {
                let size = reader.u16()?;
                if size == 0 {
                    break;
                }
                reader.at -= 2;
                let bytes = reader.bytes(usize::from(size));
                u32_at(bytes, 4)?;
                item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
            }
        }
    }
    item.value = name;
    Ok(item)
}

pub fn new_0x1f(raw: &[u8]) -> NetResult<ShellItem> {
    root_item("ShellBag0X1F", raw, false)
}
pub fn new_0x79(raw: &[u8]) -> NetResult<ShellItem> {
    root_item("ShellBag0X79", raw, true)
}

const FTP_FOLDER_SIGNATURE: u32 = 0x00030005;
const FTP_FILE_SIGNATURE: u32 = 0x00030009;

/// FtpNames: the length of the ANSI name, where the Unicode one starts, and its length
fn ftp_names(raw: &[u8], size: i64) -> NetResult<Option<(i64, i64, i64)>> {
    const ANSI_START: i64 = 0x26;
    let mut ansi_length = 0i64;
    while ANSI_START + ansi_length < size && byte_at(raw, ANSI_START + ansi_length)? != 0 {
        ansi_length += 1;
    }
    let unicode_start = ANSI_START + (ansi_length + 1 + 3) / 4 * 4;
    if ANSI_START + ansi_length >= size || unicode_start + 2 > size {
        return Ok(None);
    }
    let mut unicode_length = 0i64;
    while unicode_start + unicode_length * 2 + 2 <= size && u16_at(raw, unicode_start + unicode_length * 2)? != 0 {
        unicode_length += 1;
    }
    Ok((unicode_start + unicode_length * 2 + 2 <= size).then_some((ansi_length, unicode_start, unicode_length)))
}

/// ShellBag0X00.IsFtpItem
pub fn is_ftp_item(raw: &[u8]) -> NetResult<bool> {
    if raw.len() < 0x2c {
        return Ok(false);
    }
    let signature = u32_at(raw, 6)?;
    if signature != FTP_FOLDER_SIGNATURE && signature != FTP_FILE_SIGNATURE {
        return Ok(false);
    }
    let size = i64::from(u16_at(raw, 0)?);
    let attributes = u32_at(raw, 0x0a)?;
    if size < 0x2c || size > raw.len() as i64 || attributes == 0 || attributes > 0xffff {
        return Ok(false);
    }
    let modified = i64_at(raw, 0x16)?;
    if modified != 0 && from_file_time(modified) == Timestamp::MIN {
        return Ok(false);
    }
    let Some((ansi_length, start, length)) = ftp_names(raw, size)? else { return Ok(false) };
    if ansi_length == 0 || length == 0 {
        return Ok(false);
    }
    for i in 0..length {
        if u16_at(raw, start + i * 2)? < 0x20 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Uri.UnescapeDataString: %XX sequences that make valid UTF-8 are decoded
fn unescape_data_string(text: &str) -> String {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let mut run = Vec::new();
        let mut j = i;
        while j + 2 < b.len() + 0 && b[j] == b'%' {
            let (Some(h), Some(l)) = ((b[j + 1] as char).to_digit(16), (b[j + 2] as char).to_digit(16)) else { break };
            run.push((h * 16 + l) as u8);
            j += 3;
        }
        if run.is_empty() {
            out.push(b'%');
            i += 1;
            continue;
        }
        let mut k = 0;
        while k < run.len() {
            match std::str::from_utf8(&run[k..]) {
                Ok(s) => {
                    out.extend_from_slice(s.as_bytes());
                    k = run.len();
                }
                Err(e) => {
                    out.extend_from_slice(&run[k..k + e.valid_up_to()]);
                    k += e.valid_up_to();
                    let bad = e.error_len().unwrap_or(run.len() - k);
                    for byte in &run[k..k + bad] {
                        out.extend_from_slice(format!("%{byte:02X}").as_bytes());
                    }
                    k += bad;
                }
            }
        }
        i = j;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// What 0x00's text has before the shared part
#[derive(Default)]
struct Zero {
    short_name: String,
    ftp_time: Option<Timestamp>,
    is_ftp_file: bool,
    file_size: i32,
    full_url: Option<String>,
    modified: Option<Timestamp>,
}

fn url_container(item: &mut ShellItem, zero: &mut Zero, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Variable: HTTP URI".to_string();
    let mut index = 0x14i64;
    let size = u32_at(raw, index)?;
    index += 4;
    let url = unicode_string(raw, index, i64::from(size as i32))?;
    index += i64::from(size as i32);
    item.value = unescape_data_string(&url.replace('\0', ""));
    for gap in [16i64, 4] {
        if index + gap + 4 > raw.len() as i64 {
            continue;
        }
        let size = u32_at(raw, index + gap)?;
        if size == 0 || i64::from(size) > raw.len() as i64 - (index + gap + 4) {
            continue;
        }
        zero.full_url = Some(unicode_string(raw, index + gap + 4, i64::from(size as i32))?.replace('\0', ""));
        break;
    }
    Ok(())
}

fn ftp_sub_item(item: &mut ShellItem, zero: &mut Zero, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Variable: FTP URI".to_string();
    if u32_at(raw, 6)? == FTP_FILE_SIGNATURE {
        item.friendly_name = "Variable: FTP file".to_string();
        zero.is_ftp_file = true;
        let size = u64_at(raw, 0x0e)?;
        zero.file_size = if size > i32::MAX as u64 { i32::MAX } else { size as i32 };
    }
    let time = from_file_time(u64_at(raw, 0x16)? as i64);
    if time.parts().year > 1601 {
        zero.ftp_time = Some(time);
    }
    let size = i64::from(u16_at(raw, 0)?).min(raw.len() as i64);
    let Some((ansi_length, start, length)) = ftp_names(raw, size)? else {
        return Err("The names of an FTP folder item don't end within the item".to_string());
    };
    zero.short_name = ansi_at(raw, 0x26, ansi_length)?;
    item.value = unicode_string(raw, start, length * 2)?;
    Ok(())
}

fn zero_property_view(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Variable: Users property view".to_string();
    let mut index = 10i64;
    let list_size = i16_at(raw, index)?;
    index += 2;
    let identifier_size = i16_at(raw, index)?;
    index += 2;
    if i64::from(identifier_size) > raw.len() as i64 {
        let text = ansi_at(raw, 0xc, raw.len() as i64 - 0xc)?;
        let strings: Vec<&str> = text.split('\0').collect();
        item.value = format!("{} ({})", strings[0], strings[1..].join(","));
        return Ok(());
    }
    array_copy(raw, index, i64::from(identifier_size))?;
    index += i64::from(identifier_size);
    if list_size > 0 {
        let bytes = skip_take(raw, index as usize, list_size as usize);
        let store = PropertyStore::read(bytes)?;
        if has_key(&store, "32") {
            for offset in crate::utils::find_extension_block_signatures(bytes) {
                let at = offset - 4;
                if at < 0 {
                    continue;
                }
                let size = i16_at(bytes, at)?;
                let block_bytes = if size >= 0 { skip_take(bytes, at as usize, size as usize) } else { &[] };
                item.delegate_extension_blocks.push(crate::blocks::from_bytes_or_error(block_bytes));
            }
        }
        item.property_stores.push(store);
    } else {
        if raw.len() > 0x28 && (raw[0x28] == 0x2f || (raw[0x24] == 0x4e && raw[0x26] == 0x2f && raw[0x28] == 0x41)) {
            let zip = new_zip_contents(raw)?;
            item.friendly_name = zip.friendly_name;
            item.value = zip.value;
            return Ok(());
        }
        if raw.len() > 8 && raw[4..8] == *b"AugM" {
            let cd = new_cd_burn(raw)?;
            item.friendly_name = cd.friendly_name;
            item.value = cd.value;
            return Ok(());
        }
        item.value = "No Property sheets found".to_string();
    }
    index += i64::from(list_size) + 2;
    if list_size > 0 && index + 2 <= raw.len() as i64 {
        let mut size = i16_at(raw, index)?;
        while size > 0 {
            let bytes = skip_take(raw, index as usize, size as usize);
            index += i64::from(size);
            item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
            if index + 2 > raw.len() as i64 {
                break;
            }
            size = i16_at(raw, index)?;
        }
    }
    if let Some(first) = item.property_stores.first() {
        item.value = view_value(first, "No Property sheet value found");
    }
    Ok(())
}

fn zero_view_guid(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    let mut index = 4i64;
    u16_at(raw, index)?;
    index += 6;
    let store_size = u16_at(raw, index)?;
    index += 2;
    let identifier_size = u16_at(raw, index)?;
    index += 2;
    if identifier_size > 0 {
        item.value = guid_name(&guid_text(array_copy(raw, index, 16)?)?);
        index += 16;
    }
    if store_size > 0 {
        let size = i16_at(raw, index)?;
        item.property_stores.push(PropertyStore::read(copy(raw, index, i64::from(size))?)?);
        index += i64::from(size);
    }
    index += 2;
    if index == raw.len() as i64 {
        return Ok(());
    }
    let mut size = i16_at(raw, index)?;
    while size > 0 {
        let bytes = skip_take(raw, index as usize, size as usize);
        index += i64::from(size);
        u32_at(bytes, 4)?;
        item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
        if raw.len() as i64 == index {
            return Ok(());
        }
        size = i16_at(raw, index)?;
    }
    let terminator = i32::from(i16_at(raw, index)?);
    if terminator > 0 {
        return Err(format!("Expected terminator of 0, but got {terminator}"));
    }
    Ok(())
}

fn zero_parts(item: &mut ShellItem, zero: &Zero) {
    let mut s = String::new();
    if !zero.short_name.is_empty() {
        s.push_str(&format!("Short name: {}\n", zero.short_name));
    }
    if let Some(t) = zero.ftp_time {
        s.push_str(&format!("\nFTP {} time: {}\n", if zero.is_ftp_file { "file" } else { "folder" }, crate::utils::time_text(t)));
    }
    if zero.is_ftp_file {
        s.push_str(&format!("File size: {}\n", crate::utils::n0(i64::from(zero.file_size))));
    }
    if let Some(url) = &zero.full_url {
        s.push_str(&format!("Full URL: {url}\n"));
    }
    s.push_str(&time_line("Modified On", zero.modified));
    let mut parts = Vec::new();
    if !item.property_stores.is_empty() {
        s.push_str(&format!("\nProperty stores found: {}\n", item.property_stores.len()));
        parts.push(Part::Text(std::mem::take(&mut s)));
        for (n, store) in item.property_stores.iter().enumerate() {
            if !store.sheets.is_empty() {
                parts.push(Part::Store(format!("Property Sheets for Property store {}\n", crate::utils::n0(n as i64)), store.clone()));
            }
        }
    }
    s.push('\n');
    parts.push(Part::Text(s));
    item.parts = parts;
    item.short_name = Some(zero.short_name.clone());
}

/// new ShellBag0X00
pub fn new_0x00(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X00", "Variable", raw);
    let mut zero = Zero::default();
    match u32_at(raw, 4)? {
        0x94606aeb => {
            item.value = ansi_at(raw, 0x14, 0x40)?;
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        0xc001b000 => {
            url_container(&mut item, &mut zero, raw)?;
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        0x49534647 => {
            item.friendly_name = "Variable: Game folder".to_string();
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        0x10 => {
            item.friendly_name = "ZipFileContents".to_string();
            let zip = new_0x65(raw)?;
            item.value = zip.value;
            zero.modified = if byte_at(raw, 4)? == 0x10 { Some(from_file_time(i64_at(raw, 16)?)) } else { None };
            item.last_modification = zero.modified;
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        0xffffff38 => return Err("Send this hive to saericzimmerman@gmail.com so support can be added!".to_string()),
        _ => {}
    }
    u16_at(raw, 0)?;
    u16_at(raw, 4)?;
    let signature = u32_at(raw, 6)?;
    u16_at(raw, 10)?;
    match signature {
        0x0a291cf0 => {
            let mut index = 0xai64;
            let mut size = i32_at(raw, index)?;
            while size != 0 {
                item.property_stores.push(PropertyStore::read(copy(raw, index, i64::from(size))?)?);
                index += i64::from(size);
                size = i32_at(raw, index)?;
            }
        }
        FTP_FOLDER_SIGNATURE | FTP_FILE_SIGNATURE | 0x00000005 => ftp_sub_item(&mut item, &mut zero, raw)?,
        0x23febbee => {
            zero_view_guid(&mut item, raw)?;
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        0x04152004 => {
            let text = unicode_string(raw, 0x76, raw.len() as i64 - 0x76)?;
            item.value = text.split('\0').next().unwrap_or_default().to_string();
            zero_parts(&mut item, &zero);
            return Ok(item);
        }
        _ => {
            if raw.len() <= 0x60 {
                item.friendly_name = "Server name".to_string();
                item.value = unicode_string(raw, 6, raw.len() as i64 - 6)?.replace('\0', "");
            } else {
                zero_property_view(&mut item, raw)?;
            }
        }
    }
    zero_parts(&mut item, &zero);
    Ok(item)
}

