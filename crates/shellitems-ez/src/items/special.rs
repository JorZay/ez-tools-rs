//! Shell item classes found by signature or layout, and the remaining types.

use ez_common::Timestamp;
use ez_common::json::Value;
use ez_common::net::{NetResult, byte_at, copy, i16_at, i32_at, i64_at, u16_at, u32_at, u64_at, unicode_string};

use super::*;
use crate::utils::{ansi, ansi_at, array_copy, from_file_time, guid_name, guid_text, n0, skip, skip_take, time_text};

/// `size * 2` in C#'s 32 bits
fn twice(size: i32) -> i64 {
    i64::from(size.wrapping_mul(2))
}

/// DateTimeOffset.ToString() in en-US
fn default_time(t: Timestamp) -> String {
    t.format("M/d/yyyy h:mm:ss\u{202f}tt K")
}

fn user_profile(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "User profile".to_string();
    item.bag_type = "User";
    let last_access = if raw.len() >= 14 { crate::utils::dos_time(skip_take(raw, raw.len() - 14, 4))? } else { crate::utils::dos_time(skip_take(raw, 0, 4))? };
    item.last_access = last_access;
    let text = crate::utils::unicode(skip(raw, 10));
    let first = text.split('\0').next().unwrap_or_default();
    item.value = if first.is_empty() { "(None)".to_string() } else { first.to_string() };
    item.set_before_line(Some(format!("{}\n", time_line("Accessed On", last_access))).filter(|_| last_access.is_some()));
    Ok(())
}

fn guid_0x2e(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Root folder: GUID".to_string();
    item.bag_type = "Guid";
    let folder = guid_name(&guid_text(array_copy(raw, 4, 16)?)?);
    item.value = folder;
    let mut index = 20i64;
    if index == raw.len() as i64 {
        return Ok(());
    }
    let mut size = i16_at(raw, index)?;
    if size == 0 {
        index += 2;
    }
    while index < raw.len() as i64 {
        u32_at(raw, index + 4)?;
        item.extension_blocks.push(crate::blocks::from_bytes_or_error(skip(raw, index as usize)));
        if size <= 0 {
            break;
        }
        index += i64::from(size);
        if index != raw.len() as i64 {
            size = i16_at(raw, index)?;
            if size == 0 {
                index += 2;
            }
        }
    }
    Ok(())
}

fn view_0x2e(item: &mut ShellItem, raw: &[u8]) -> NetResult<()> {
    item.friendly_name = "Users property view".to_string();
    item.bag_type = "User";
    let mut index = 10i64;
    let list_size = i16_at(raw, index)?;
    index += 2;
    let identifier_size = i16_at(raw, index)?;
    index += 2;
    if identifier_size < 0 || i64::from(identifier_size) > raw.len() as i64 - index {
        return Err(format!("Invalid identifier size ({identifier_size}): only {} bytes are left", raw.len() as i64 - index));
    }
    if list_size < 0 || i64::from(list_size) > raw.len() as i64 - index - i64::from(identifier_size) {
        return Err(format!("Invalid property sheet list size ({list_size}): only {} bytes are left", raw.len() as i64 - index - i64::from(identifier_size)));
    }
    index += i64::from(identifier_size);
    if list_size > 0 {
        let bytes = skip_take(raw, index as usize, list_size as usize);
        let store = PropertyStore::read(bytes)?;
        if store.sheets.iter().any(|s| s.property_names.iter().any(|(k, _)| k == "32")) {
            for offset in crate::utils::find_extension_block_signatures(bytes) {
                let at = offset - 4;
                let Ok(size) = i16_at(bytes, at) else { break };
                let block = if size >= 0 { skip_take(bytes, at as usize, size as usize) } else { &[] };
                if u32_at(block, 4).is_err() {
                    break;
                }
                item.extension_blocks.push(crate::blocks::from_bytes_or_error(block));
            }
        }
        item.property_store = Some(store);
    } else {
        index += i64::from(list_size);
    }
    index += 2;
    guid_text(skip_take(raw, index as usize, 16))?;
    index += 16;
    item.value = guid_name(&guid_text(skip_take(raw, index as usize, 16))?);
    index += 16;
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
    if let Some(store) = &item.property_store {
        if !store.sheets.is_empty() {
            item.parts.push(Part::Store("Property Sheets\n".to_string(), store.clone()));
        }
    }
    Ok(())
}

pub fn new_0x2e(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X2E", "", raw);
    if byte_at(raw, 3)? == 0x80 || raw.len() == 0x16 || raw.len() == 0x14 || (raw.len() >= 0x1c && u16_at(raw, 0x1a)? == 0xbeef) {
        guid_0x2e(&mut item, raw)?;
        return Ok(item);
    }
    let post = u64_at(raw, raw.len() as i64 - 8)?;
    if post == 0x0000ee306bfe9555 || post == 0xee306bfe9555c589 {
        user_profile(&mut item, raw)?;
        return Ok(item);
    }
    if i32_at(raw, 5)? >= 0x15032601 && raw.len() >= 0x116 + 0x22 {
        item.friendly_name = "Control panel category".to_string();
        let device_path = unicode_string(raw, 0x12, 0x48 * 2)?.trim_matches('\0').to_string();
        let end = raw.len() as i64 - 0x22;
        item.value = unicode_string(raw, 0x116, end - 0x116)?.trim_matches('\0').to_string();
        guid_text(copy(raw, end, 16)?)?;
        let category = guid_name(&guid_text(copy(raw, end + 16, 16)?)?);
        item.set("Category", Value::text(category.as_str()));
        item.set("DevicePath", Value::text(device_path.as_str()));
        item.set_before_line(Some(format!("Category: {category}\n\nDevice Path: {device_path}\n\n")));
        return Ok(item);
    }
    view_0x2e(&mut item, raw)?;
    Ok(item)
}

pub fn new_0x50(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X50", "Nokia sub folder", raw);
    let kind = byte_at(raw, 0xa)?;
    if kind == 6 {
        let mut index = 0x22i64;
        let size = i32_at(raw, index)?;
        index += 4;
        let buffer = copy(raw, index, i64::from(size))?;
        index += i64::from(size);
        let first = crate::utils::unicode(buffer);
        let s1: Vec<&str> = first.split('\0').collect();
        let second = unicode_string(raw, index, raw.len() as i64 - index)?;
        let s2 = second.split('\0').next().unwrap_or_default();
        let name = s1.get(2).ok_or(ez_common::net::ARRAY_INDEX)?;
        item.value = format!("{} ({name}): {s2}", s1[0]);
        return Ok(item);
    }
    if kind == 0xc {
        let text = unicode_string(raw, 0x3e, raw.len() as i64 - 0x3e)?;
        item.value = text.split('\0').next().unwrap_or_default().to_string();
        return Ok(item);
    }
    let index = 0x26i64;
    let size = i32_at(raw, index)?;
    let buffer = copy(raw, index, i64::from(size))?;
    let text = unicode_string(buffer, 8, buffer.len() as i64 - 8)?;
    item.value = text.split('\0').next().unwrap_or_default().to_string();
    let time = from_file_time(i64_at(raw, index + i64::from(size))?);
    item.set("FileTime1", Value::time(time));
    item.set_before_line(Some(format!("Timestamp: {}\n\n", default_time(time))));
    Ok(item)
}

/// The ModifiedOn line and the zip name of 0x52, 0x61, 0x69
fn zip_name(item: &mut ShellItem, raw: &[u8]) -> NetResult<Timestamp> {
    item.friendly_name = "ZipFileContents".to_string();
    item.bag_type = "ZipFileContents";
    let modified = from_file_time(i64_at(raw, 16)?);
    item.set("ModifiedOn", Value::time(modified));
    let len1 = i64::from(i16_at(raw, 28)?);
    let len2 = i64::from(i16_at(raw, 30)?);
    item.value = unicode_string(raw, 32, (len1 + len2) * 2)?.replace('\0', "");
    Ok(modified)
}

pub fn new_0x52(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X52", "Acronis", raw);
    if byte_at(raw, 4)? == 0x10 {
        let modified = zip_name(&mut item, raw)?;
        item.set_before_line(Some(format!("Modified On: {}\n\n", time_text(modified))));
        return Ok(item);
    }
    let length = i32_at(raw, 46)?;
    item.value = unicode_string(raw, 50, i64::from(length.wrapping_mul(2).wrapping_sub(2)))?;
    Ok(item)
}

pub fn new_0x61(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X61", "URI", raw);
    if byte_at(raw, 4)? == 0x10 {
        let modified = zip_name(&mut item, raw)?;
        item.set_before_line(Some(format!("URI: \n\nModified On: {}\n\n", time_text(modified))));
        return Ok(item);
    }
    let size = u16_at(raw, 4)?;
    if size == 0 {
        let uri = unicode_string(raw, 8, raw.len() as i64 - 8)?.trim_matches('\0').to_string();
        item.value = uri.split('\0').next().unwrap_or_default().to_string();
        item.set("URI", Value::text(uri.as_str()));
        item.set_before_line(Some(format!("URI: {uri}\n\n")));
        return Ok(item);
    }
    let mut index = 14i64;
    let connect = from_file_time(u64_at(raw, index)? as i64);
    item.set("FileTime1", Value::time(connect));
    index += 8 + 4 + 12 + 4;
    let mut length = i64::from(u32_at(raw, index)? as i32);
    index += 4;
    item.value = ansi_at(raw, index, length)?.replace('\0', "");
    index += length;
    length = i64::from(u32_at(raw, index)? as i32);
    index += 4;
    let mut user = String::new();
    if u32_at(raw, index - 4)? > 0 {
        user = ansi_at(raw, index, length)?.replace('\0', "");
        item.set("UserName", Value::text(user.as_str()));
        index += length;
    }
    length = i64::from(u32_at(raw, index)? as i32);
    index += 4;
    if u32_at(raw, index - 4)? > 0 {
        ansi_at(raw, index, length)?;
        index += length;
    }
    let mut len = 0i64;
    while index + len < raw.len() as i64 && raw[(index + len) as usize] != 0 {
        len += 1;
    }
    let uri = ansi_at(raw, index, len)?;
    item.set("URI", Value::text(uri.as_str()));
    let mut before = format!("URI: {uri}\n\nConnect time: {}\n\n", time_text(connect));
    if !user.is_empty() {
        before.push_str(&format!("Username: {user}\n\n"));
    }
    item.set_before_line(Some(before));
    Ok(item)
}

pub fn new_0x64(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X64", "History folder", raw);
    item.value = unicode_string(raw, 4, raw.len() as i64 - 4)?.replace('\0', "");
    Ok(item)
}

pub fn new_0x69(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X69", "History folder", raw);
    let name = unicode_string(raw, 4, raw.len() as i64 - 4)?.replace('\0', "");
    if byte_at(raw, 4)? == 0x10 {
        let modified = zip_name(&mut item, raw)?;
        item.set_before_line(Some(format!("Modified On: {}\n\n", time_text(modified))));
        return Ok(item);
    }
    item.value = name;
    Ok(item)
}

pub fn new_0x78(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X78", "Users property view", raw);
    let mut at = 2usize + 2;
    let read_u16 = |at: &mut usize| -> NetResult<u16> {
        if *at + 2 > raw.len() {
            *at = raw.len();
            return Err("Unable to read beyond the end of the stream.".to_string());
        }
        *at += 2;
        Ok(u16::from_le_bytes([raw[*at - 2], raw[*at - 1]]))
    };
    read_u16(&mut at)?;
    if at + 4 > raw.len() {
        return Err("Unable to read beyond the end of the stream.".to_string());
    }
    at += 4;
    let store_size = usize::from(read_u16(&mut at)?);
    let identifier_size = usize::from(read_u16(&mut at)?);
    at = (at + identifier_size).min(raw.len());
    if store_size > 0 {
        let end = (at + store_size).min(raw.len());
        let bytes = &raw[at..end];
        at = end;
        let store = PropertyStore::read(bytes)?;
        if store.sheets.iter().any(|s| s.property_names.iter().any(|(k, _)| k == "AutoList")) {
            for offset in crate::utils::find_extension_block_signatures(bytes) {
                let start = offset - 4;
                let Ok(size) = i16_at(bytes, start) else { break };
                let block = if size >= 0 { skip_take(bytes, start as usize, size as usize) } else { &[] };
                if u32_at(block, 4).is_err() {
                    break;
                }
                item.extension_blocks.push(crate::blocks::from_bytes_or_error(block));
            }
        }
        if !store.sheets.is_empty() {
            item.parts.push(Part::Store("Property Sheets\n".to_string(), store.clone()));
        }
        item.property_store = Some(store);
    }
    at = (at + 2).min(raw.len());
    guid_text(skip_take(raw, at, 16))?;
    at = (at + 16).min(raw.len());
    let name = guid_name(&guid_text(skip_take(raw, at, 16))?);
    at = (at + 16).min(raw.len());
    let first = if raw.len() - at >= 2 { read_u16(&mut at)? } else { 0 };
    if first > 0 {
        at -= 2;
        while raw.len() - at >= 2 {
            let size = read_u16(&mut at)?;
            if size < 8 || i64::from(size) > (raw.len() - at) as i64 + 2 {
                break;
            }
            at -= 2;
            let end = (at + usize::from(size)).min(raw.len());
            let bytes = &raw[at..end];
            at = end;
            u32_at(bytes, 4)?;
            item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
        }
    }
    item.value = name;
    Ok(item)
}

/// ShellBagArchiveContents.IsArchiveContents
pub fn is_archive_contents(raw: &[u8]) -> NetResult<bool> {
    if raw.len() < 0x24 {
        return Ok(false);
    }
    let size = i64::from(u16_at(raw, 0)?);
    let attributes = u32_at(raw, 4)?;
    if size > raw.len() as i64 || attributes & 0x10 == 0 || attributes > 0xffff {
        return Ok(false);
    }
    let name_length = i64::from(u16_at(raw, 0x1c)?);
    let parent_length = i64::from(u16_at(raw, 0x1e)?);
    let end = 0x20 + (name_length + parent_length) * 2;
    if name_length == 0 || end + 2 > size || u16_at(raw, end)? != 0 {
        return Ok(false);
    }
    let mut i = 0x20;
    while i < end {
        if u16_at(raw, i)? == 0 {
            return Ok(false);
        }
        i += 2;
    }
    if parent_length > 0 && u16_at(raw, 0x20 + (parent_length - 1) * 2)? != u16::from(b'\\') {
        return Ok(false);
    }
    let modified = i64_at(raw, 0x10)?;
    Ok(modified == 0 || from_file_time(modified) != Timestamp::MIN)
}

pub fn new_archive_contents(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagArchiveContents", "Archive contents", raw);
    let attributes = u32_at(raw, 4)?;
    let size = u64_at(raw, 8)?;
    let modified = i64_at(raw, 0x10)?;
    let name_length = i64::from(u16_at(raw, 0x1c)?);
    let parent_length = u16_at(raw, 0x1e)?;
    let path = unicode_string(raw, 0x20, (name_length + i64::from(parent_length)) * 2)?;
    let units: Vec<u16> = path.encode_utf16().collect();
    item.value = String::from_utf16_lossy(&units[usize::from(parent_length).min(units.len())..]);
    item.set("FileAttributes", Value::number(attributes));
    item.set("FileSize", Value::number(size));
    if modified > 0 {
        item.set("ModifiedOn", Value::time(from_file_time(modified)));
    }
    item.set("ArchivePath", Value::text(path.as_str()));
    let mut before = format!("Archive path: {path}\nFile attributes: 0x{attributes:X}\n");
    if size > 0 {
        before.push_str(&format!("File size: {}\n", ez_common::dotnet::n0(size)));
    }
    if modified > 0 {
        before.push_str(&format!("Modified On: {}\n", time_text(from_file_time(modified))));
    }
    before.push('\n');
    item.set_before_line(Some(before));
    item.after = "\n".to_string();
    Ok(item)
}

/// The blocks at the end of the classes that split them the way 0x31 does
fn split_blocks(raw: &[u8], mut index: i64) -> NetResult<Vec<&[u8]>> {
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

pub fn new_cd_burn(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagCDBurn", "CDBurn", raw);
    item.value_is_null = true;
    if i32_at(raw, 4)? != 0x4d677541 {
        return Err("Invalid signature!".to_string());
    }
    // the index is 32 bits, and can wrap around
    let count = i32_at(raw, 8)?.max(0);
    let index = i64::from(12i32.wrapping_add(count.wrapping_mul(2)));
    let (mut short, mut size, mut modified) = (String::new(), 0i32, None);
    for bytes in split_blocks(raw, index)? {
        let kind = byte_at(bytes, 2)?;
        size = i32_at(bytes, 4)?;
        modified = crate::utils::dos_time(copy(bytes, 8, 4)?)?;
        let mut at = 14i64;
        let beef_start = i64::from(i16_at(bytes, bytes.len() as i64 - 2)?);
        let length = beef_start - 0xe;
        short = if kind == 0x35 { unicode_string(bytes, at, length)? } else { ansi_at(bytes, at, length)? }.trim_matches('\0').to_string();
        at += length;
        while at < bytes.len() as i64 {
            let block_size = i16_at(bytes, at)?;
            if block_size == 0 {
                at += 2;
                continue;
            }
            let buffer = copy(bytes, at, i64::from(block_size))?;
            u32_at(bytes, at + 4)?;
            let block = crate::blocks::from_bytes_or_error(buffer);
            if let crate::blocks::BlockKind::Beef0004 { long_name, created, last_access, .. } = &block.kind {
                item.value = long_name.clone();
                item.value_is_null = false;
                item.set("CreatedOnTime", Value::opt_time(*created));
                item.last_access = *last_access;
            }
            item.extension_blocks.push(block);
            at += i64::from(block_size);
        }
    }
    let mut before = String::new();
    if !short.is_empty() {
        before.push_str(&format!("Short name: {short}\n"));
    }
    if size > 0 {
        before.push_str(&format!("File size: {}\n", n0(i64::from(size))));
    }
    if let Some(t) = modified {
        before.push_str(&format!("Modified On: {}\n", default_time(t)));
    }
    before.push('\n');
    item.set_before_line(Some(before));
    item.set("FileSize", Value::number(size));
    item.short_name = Some(short);
    item.last_modification = modified;
    Ok(item)
}

pub fn new_cfsf(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagCFSF", "Users Files Folder", raw);
    item.value_is_null = true;
    u16_at(raw, 4)?;
    if i32_at(raw, 6)? != 0x46534643 {
        return Err("Invalid signature at offset 0x06! Should be CFSF!".to_string());
    }
    let mut index = 10i64;
    u16_at(raw, index)?;
    index += 2;
    byte_at(raw, index)?;
    index += 2;
    let size = u32_at(raw, index)? as i32;
    item.set("FileSize", Value::number(size));
    index += 4;
    let modified = crate::utils::dos_time(array_copy(raw, index, 4)?)?;
    item.last_modification = modified;
    index += 4 + 2;
    let mut len = 0i64;
    while byte_at(raw, index + len)? != 0 {
        len += 1;
    }
    ansi(array_copy(raw, index, len)?)?;
    index += len;
    while byte_at(raw, index)? == 0 {
        index += 1;
    }
    let delegate = guid_text(array_copy(raw, index, 16)?)?;
    if delegate != "5e591a74-df96-48d3-8d67-1733bcee28ba" {
        return Err(format!("Delegate guid not expected value of 5e591a74-df96-48d3-8d67-1733bcee28ba. Actual value: {delegate}"));
    }
    index += 16;
    guid_text(array_copy(raw, index, 16)?)?;
    index += 16;
    for bytes in split_blocks(raw, index)? {
        i16_at(bytes, 0)?;
        u32_at(bytes, 4)?;
        let block = crate::blocks::from_bytes_or_error(bytes);
        if let crate::blocks::BlockKind::Beef0004 { long_name, .. } = &block.kind {
            item.value = long_name.clone();
            item.value_is_null = false;
        }
        item.extension_blocks.push(block);
    }
    let mut before = String::new();
    if size > 0 {
        before.push_str(&format!("File size: {}\n", n0(i64::from(size))));
    }
    if let Some(t) = modified {
        before.push_str(&format!("Modified On: {}\n\n", default_time(t)));
    }
    item.set_before_line(Some(before));
    Ok(item)
}

/// ShellBagDocumentDrive.IsDocumentDrive
pub fn is_document_drive(raw: &[u8]) -> NetResult<bool> {
    if raw.len() < 0x2c || raw[3] != 0x55 {
        return Ok(false);
    }
    Ok(raw[2] == 0xfc || (raw[2] == 0xff && raw.len() > 0xd4 && raw[0xd1] == 5))
}

fn terminated_string(raw: &[u8], offset: i64) -> NetResult<String> {
    let mut end = offset;
    while end + 1 < raw.len() as i64 && (raw[end as usize] != 0 || raw[end as usize + 1] != 0) {
        end += 2;
    }
    unicode_string(raw, offset, end.min(raw.len() as i64) - offset)
}

fn positive_file_time(raw: &[u8], offset: i64) -> NetResult<Option<Timestamp>> {
    let value = i64_at(raw, offset)?;
    if value <= 0 {
        return Ok(None);
    }
    let time = from_file_time(value);
    Ok((time != Timestamp::MIN).then_some(time))
}

pub fn new_document_drive(raw: &[u8]) -> NetResult<ShellItem> {
    let folder = byte_at(raw, 2)? == 0xff;
    let mut item = ShellItem::new("ShellBagDocumentDrive", if folder { "Document drive folder" } else { "Document drive file" }, raw);
    item.bag_type = if folder { "Directory" } else { "File" };
    let mut before = String::new();
    let time_offset = if folder {
        let (id, parent) = (terminated_string(raw, 0x79)?, terminated_string(raw, 0xa5)?);
        before.push_str(&format!("Item ID: {id}\nParent ID: {parent}\n\n"));
        item.set("ItemId", Value::text(id));
        item.set("ParentId", Value::text(parent));
        item.value = terminated_string(raw, 0xd2)?;
        0x13
    } else {
        item.value = terminated_string(raw, 0x29)?;
        0x09
    };
    let (created, modified, accessed) = (positive_file_time(raw, time_offset)?, positive_file_time(raw, time_offset + 8)?, positive_file_time(raw, time_offset + 16)?);
    item.set("CreatedOn", Value::opt_time(created));
    item.set("ModifiedOn", Value::opt_time(modified));
    item.set("AccessedOn", Value::opt_time(accessed));
    before.push_str(&time_line("Created On", created));
    before.push_str(&time_line("Modified On", modified));
    before.push_str(&time_line("Accessed On", accessed));
    before.push('\n');
    item.set_before_line(Some(before));
    item.after = "\n".to_string();
    Ok(item)
}

const FIND_DATA_GUID: &str = "1ca7ea69-e26a-44c9-9182-a9128722c66f";

fn is_string(raw: &[u8], offset: i64, length: i64, size: i64) -> NetResult<bool> {
    let end = offset + length * 2;
    if end + 2 > size || u16_at(raw, end)? != 0 {
        return Ok(false);
    }
    let mut i = offset;
    while i < end {
        if u16_at(raw, i)? == 0 {
            return Ok(false);
        }
        i += 2;
    }
    Ok(true)
}

/// ShellBagFindData.IsFindData
pub fn is_find_data(raw: &[u8]) -> NetResult<bool> {
    if raw.len() < 0x6c {
        return Ok(false);
    }
    let size = i64::from(u16_at(raw, 0)?);
    if size < 0x6c || size > raw.len() as i64 {
        return Ok(false);
    }
    if guid_text(&raw[4..20])? != FIND_DATA_GUID {
        return Ok(false);
    }
    let name_length = i64::from(u16_at(raw, 0x14)?);
    let second_length = i64::from(u16_at(raw, 0x16)?);
    let name_offset = i64::from(u16_at(raw, 0x18)?);
    let second_offset = i64::from(u16_at(raw, 0x1a)?);
    if name_length == 0 || name_offset < 0x68 || second_offset < name_offset + (name_length + 1) * 2 {
        return Ok(false);
    }
    Ok(is_string(raw, name_offset, name_length, size)? && is_string(raw, second_offset, second_length, size)?)
}

pub fn new_find_data(raw: &[u8]) -> NetResult<ShellItem> {
    let attributes = u32_at(raw, 0x20)?;
    let mut item = ShellItem::new("ShellBagFindData", if attributes & 0x10 != 0 { "Directory" } else { "File" }, raw);
    let created = positive_file_time(raw, 0x24)?;
    let accessed = positive_file_time(raw, 0x2c)?;
    let modified = positive_file_time(raw, 0x34)?;
    let size = u64_at(raw, 0x3c)?;
    let name_length = i64::from(u16_at(raw, 0x14)?);
    let second_length = i64::from(u16_at(raw, 0x16)?);
    item.value = unicode_string(raw, i64::from(u16_at(raw, 0x18)?), name_length * 2)?;
    let second = unicode_string(raw, i64::from(u16_at(raw, 0x1a)?), second_length * 2)?;
    item.bag_type = if attributes & 0x10 != 0 { "Directory" } else { "File" };
    item.set("FileAttributes", Value::number(attributes));
    item.set("FileSize", Value::number(size));
    item.set("CreatedOn", Value::opt_time(created));
    item.set("AccessedOn", Value::opt_time(accessed));
    item.set("ModifiedOn", Value::opt_time(modified));
    item.set("SecondName", Value::text(second.as_str()));
    let mut before = String::new();
    if second != item.value {
        before.push_str(&format!("Second name: {second}\n"));
    }
    before.push_str(&format!("Item GUID: {FIND_DATA_GUID}\nFile attributes: 0x{attributes:X}\n"));
    if size > 0 {
        before.push_str(&format!("File size: {}\n", ez_common::dotnet::n0(size)));
    }
    before.push_str(&time_line("Created On", created));
    before.push_str(&time_line("Modified On", modified));
    before.push_str(&time_line("Accessed On", accessed));
    before.push('\n');
    item.set_before_line(Some(before));
    item.after = "\n".to_string();
    Ok(item)
}

pub fn new_mtp_device(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagMTPDevice", "MTP device", raw);
    i16_at(raw, 0)?;
    byte_at(raw, 2)?;
    let mut index = 0x1ei64;
    let name_size = twice(i32_at(raw, index)?);
    index += 4;
    let path_size = twice(i32_at(raw, index)?);
    index += 4 + 2;
    item.set("DeviceName", Value::text(unicode_string(raw, index, name_size)?.trim_matches('\0')));
    index += name_size;
    let path = unicode_string(raw, index, path_size)?.trim_matches('\0').to_string();
    index += path_size + 4;
    let guid_here = |index: &mut i64| -> NetResult<String> {
        let g = guid_text(copy(raw, *index, 16)?)?;
        *index += 16;
        Ok(g)
    };
    let class_id = guid_name(&guid_here(&mut index)?);
    index += 4;
    let props = guid_here(&mut index)?;
    index += 8;
    let unicode_size = i64::from(i32_at(raw, index)?);
    index += 4;
    item.value = unicode_string(raw, index, unicode_size)?.trim_matches('\0').to_string();
    index += unicode_size;
    let functional_object = guid_here(&mut index)?;
    index += 8;
    let functional_category = guid_here(&mut index)?;
    index += 2;
    let delegate_folder = guid_here(&mut index)?;
    let portable = guid_name(&guid_here(&mut index)?);
    item.set("ClassId", Value::text(class_id.as_str()));
    item.set("DevicePath", Value::text(path.as_str()));
    item.set("DevicePropsGuid", Value::guid(&props));
    item.set("FunctionalObjectGuid", Value::guid(&functional_object));
    item.set("FunctionalCategoryGuid", Value::guid(&functional_category));
    item.set("DelegateFolderGuid", Value::guid(&delegate_folder));
    item.set("PortableDeviceId", Value::text(portable.as_str()));
    item.set_before_line(Some(format!(
        "Class Id: {class_id}\nDevice path: {path}\nDevice properties GUID: {props}\nFunctional object GUID: {functional_object}\nFunctional category GUID: {functional_category}\nDelegate folder GUID: {delegate_folder}\nPortable device Id: {portable}\n\n"
    )));
    Ok(item)
}

/// OlePropertyType's names
fn ole_type_name(kind: i32) -> String {
    const NAMES: &[(i32, &str)] = &[
        (0x00, "Empty"), (0x01, "Null"), (0x02, "Int16Signed"), (0x03, "Int32Signed"), (0x04, "Float32Bit"), (0x05, "Float64Bit"), (0x06, "Currency"), (0x07, "OleDate"),
        (0x08, "BinaryString"), (0x09, "Dispatch"), (0x0a, "Error"), (0x0b, "Boolean"), (0x0c, "Variant"), (0x0d, "Unknown"), (0x0e, "Decimal"), (0x0f, "Unknown2"),
        (0x10, "Int8Signed"), (0x11, "Int8Unsigned"), (0x12, "Int16Unsigned"), (0x13, "Int32Unsigned"), (0x14, "Int64Signed"), (0x15, "Int64Unsigned"), (0x16, "IntSigned"),
        (0x17, "IntUnsigned"), (0x18, "Void"), (0x19, "StandardReturn"), (0x1a, "Pointer"), (0x1b, "SafeArray"), (0x1c, "CAarray"), (0x1d, "UserDefined"), (0x1e, "AsciiString"),
        (0x1f, "UnicodeString"), (0x20, "Unknown3"), (0x21, "Unknown4"), (0x22, "Unknown5"), (0x23, "Unknown6"), (0x24, "BRecord"), (0x25, "Int16Or32Signed"), (0x26, "Int16Or32Unsigned"),
        (0x28, "Unknown10"), (0x2b, "Unknown11"), (0x2c, "Unknown12"), (0x2e, "Unknown13"), (0x2f, "Unknown14"), (0x30, "Unknown15"), (0x31, "Unknown16"), (0x33, "Unknown17"),
        (0x35, "Unknown18"), (0x36, "Unknown19"), (0x38, "Unknown20"), (0x3f, "Unknown21"), (0x40, "FileTime"), (0x41, "Blob"), (0x42, "Stream"), (0x43, "Storage"), (0x44, "StreamedObject"),
        (0x45, "StoragedObject"), (0x46, "BlobObject"), (0x47, "Clipboard"), (0x48, "Guid"), (0x49, "VersionedStream"), (0x4a, "Unknown22"), (0x4b, "Unknown23"), (0x6f, "Unknown24"),
        (0x74, "Unknown25"), (0x75, "Unknown26"), (0x7f, "Unknown27"), (0x81, "Unknown28"), (0x92, "Unknown29"), (0x9f, "Unknown30"), (0xe8, "Unknown31"),
    ];
    NAMES.iter().find(|(k, _)| *k == kind).map_or_else(|| kind.to_string(), |(_, n)| (*n).to_string())
}

/// The property's name, in words; the enum's number for one it doesn't have
fn property_id_name(guid: &str, id: i32) -> Option<String> {
    let table: &[(i32, &str)] = match guid {
        "01a3057a-74d6-4e80-bea7-dc4c212ce50a" => &[
            (2, "Storage Type"), (3, "Storage File System"), (4, "Storage Capacity"), (5, "Storage Free Space Bytes"), (6, "Storage Free Space Objects"), (7, "Storage Description"),
            (8, "Storage Serial Number"), (9, "Storage Max Object Size"), (0xa, "Storage Capacity In Objects"), (0xb, "Storage Access Capability"),
        ],
        "2ed8ba05-0ad3-42dc-b0d0-bc95ac396ac8" => &[
            (2, "Media Bitrate"), (3, "Media Bit Rate Type"), (4, "Media Copyright"), (5, "Media Subscription Content Id"), (6, "Media Use Count"), (7, "Media Skip Count"), (8, "Media Last Accessed Time"),
            (9, "Media Parental Rating"), (0xa, "Media Meta Genre"), (0xb, "Media Composer"), (0xc, "Media Effective Rating"), (0xd, "Media Sub Title"), (0xe, "Media Release Date"), (0xf, "Media Sample Rate"),
            (0x10, "Media Star Rating"), (0x11, "Media User Effective Rating"), (0x12, "Media Title"), (0x13, "Media Duration"), (0x14, "Media Buy Now"), (0x15, "Media Encoding Profile"), (0x16, "Media Width"),
            (0x17, "Media Height"), (0x18, "Media Artist"), (0x19, "Media Album Artist"), (0x1a, "Media Owner"), (0x1b, "Media Managing Editor"), (0x1c, "Media Webmaster"), (0x1d, "Media Source Url"),
            (0x1e, "Media Destination Url"), (0x1f, "Media Description"), (0x20, "Media Genre"), (0x21, "Media Time Bookmark"), (0x22, "Media Object Bookmark"), (0x23, "Media Last Build Date"),
            (0x24, "Media Byte Bookmark"), (0x25, "Media Time To Live"), (0x26, "Media Guid"), (0x27, "Media Sub Description"), (0x31, "Media Audio Encoding Profile"),
        ],
        "8f052d93-abca-4fc5-a5ac-b01df4dbe598" => &[(2, "Wpd Functional Object Category")],
        "ef6b490d-5cd8-437a-affc-da8b60ee4a3c" => &[
            (2, "Object Id"), (3, "Object Parent"), (4, "Object Name"), (5, "Object Persistent Unique Id"), (6, "Object Format"), (7, "Object Content Type"), (9, "Object Hidden"), (0xa, "Object Is System"),
            (0xb, "Object Size"), (0xc, "Object Original File Name"), (0xd, "Object Non Consumable"), (0xe, "Object References"), (0xf, "Object Keywords"), (0x10, "Object Sync Id"), (0x11, "Object Is Drm Protected"),
            (0x12, "Object Created On"), (0x13, "Object Modified On"), (0x14, "Object Authored On"), (0x15, "Object Back References"), (0x17, "Object Container Functional Object Id"),
            (0x18, "Object Generate Thumbnail From Resource"), (0x19, "Object Hint Location Display Name"), (0x1a, "Object Can Delete"), (0x1b, "Object Language Locale"),
        ],
        _ => return None,
    };
    Some(table.iter().find(|(k, _)| *k == id).map_or_else(|| id.to_string(), |(_, n)| (*n).to_string()))
}

/// PropertyArray: a line of an MTP item's text
fn property_line(guid: &str, id: i32, kind: i32, bytes: &[u8]) -> String {
    let description = match guid {
        "4d545058-4fce-4578-95c8-8698a9bc0f49" => {
            if id == 0xdc4e { "Timestamp".to_string() } else { format!("Unknown Description (TypeId: {})", ole_type_name(kind)) }
        }
        _ => property_id_name(guid, id).unwrap_or_else(|| "Unknown".to_string()),
    };
    let value = || -> NetResult<String> {
        Ok(match kind {
            0x0d => {
                if bytes.is_empty() {
                    "(No data present)".to_string()
                } else {
                    let g = guid_text(copy(bytes, 0, 16)?)?;
                    format!("Guid: {g} ({}) Items: {}", guid_name(&g), i32_at(bytes, 16)?)
                }
            }
            0x07 => time_text(super::simple::from_oa_date(f64::from_le_bytes(ez_common::net::bytes_at::<8>(bytes, 0)?))?),
            0x0b => (if i16_at(bytes, 0)? != 0 { "True" } else { "False" }).to_string(),
            0x48 => {
                let g = guid_text(bytes)?;
                format!("Guid: {g} ({})", guid_name(&g))
            }
            0x1f => crate::utils::unicode(bytes).trim_matches('\0').to_string(),
            0x12 => n0(i64::from(u16_at(bytes, 0)?)),
            0x13 | 0x0a => n0(i64::from(u32_at(bytes, 0)?)),
            0x03 => n0(i64::from(i32_at(bytes, 0)?)),
            0x15 => ez_common::dotnet::n0(u64_at(bytes, 0)?),
            0x11 => byte_at(bytes, 0)?.to_string(),
            other => return Err(format!("Unhandled PropertyType: {}", ole_type_name(other))),
        })
    };
    let text = value().unwrap_or_else(|e| format!("(could not be shown: {e})"));
    format!("{description}: {text}\n")
}

/// PropertyArray's serialized properties
fn property_array(guid: &str, id: i32, kind: i32, bytes: &[u8]) -> Value {
    Value::object(vec![("FormatClassId", Value::guid(guid)), ("PropertyId", Value::number(id)), ("PropertyType", Value::text(ole_type_name(kind))), ("PropertyBytes", Value::bytes(bytes))])
}

/// The fixed size types of an MTP item's properties
fn fixed_size(kind: i32) -> Option<i64> {
    Some(match kind {
        0x07 | 0x15 => 8,
        0x0b | 0x12 => 2,
        0x48 => 16,
        0x13 | 0x0a => 4,
        _ => return None,
    })
}

pub fn new_mtp_folder(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagMTPFolder", "MTP folder", raw);
    i16_at(raw, 0)?;
    byte_at(raw, 2)?;
    i16_at(raw, 4)?;
    i64_at(raw, 0x1a)?;
    i64_at(raw, 0x22)?;
    let mut index = 0x2ai64;
    guid_text(copy(raw, index, 16)?)?;
    index += 16;
    i32_at(raw, index)?; // subshellSize, read and not used
    index += 4;
    let len1 = twice(i32_at(raw, index)?);
    index += 4;
    let len2 = twice(i32_at(raw, index)?);
    index += 4;
    let len3 = twice(i32_at(raw, index)?);
    index += 4;
    let name = unicode_string(raw, index, len1)?.trim_matches('\0').to_string();
    index += len1;
    let name2 = unicode_string(raw, index, len2)?.trim_matches('\0').to_string();
    index += len2;
    unicode_string(raw, index, len3)?;
    index += len3;
    item.value = name2.clone();
    item.set("FolderName", Value::text(name.as_str()));
    item.set("FolderName2", Value::text(name2.as_str()));
    index += 4;
    guid_text(copy(raw, index, 16)?)?;
    index += 16;
    i32_at(raw, index)?;
    index += 4;
    let mut lines = String::new();
    let mut arrays = Vec::new();
    while index < raw.len() as i64 {
        if index + 4 >= raw.len() as i64 {
            break;
        }
        if i32_at(raw, index)? == 0 {
            index += 4;
            continue;
        }
        if i16_at(raw, index)? == 0 {
            index += 2;
            let size = i16_at(raw, index)?;
            item.extension_blocks.push(crate::blocks::from_bytes(0xbeef0010, copy(raw, index, i64::from(size))?)?);
            break;
        }
        let guid = guid_text(copy(raw, index, 16)?)?;
        index += 16;
        let id = i32_at(raw, index)?;
        index += 4;
        let kind = i32_at(raw, index)?;
        index += 4;
        match kind {
            0x0d => {
                let g = copy(raw, index, 16)?;
                index += 16;
                let count = i32_at(raw, index)?;
                index += 4;
                let length = count.wrapping_mul(0x10);
                if length < 0 {
                    return Err(ez_common::net::OVERFLOW.to_string());
                }
                let mut data = g.to_vec();
                data.extend_from_slice(&count.to_le_bytes());
                if count > 0 {
                    data.extend_from_slice(copy(raw, index, i64::from(length))?);
                    index += i64::from(count) * 0x10;
                }
                arrays.push(property_array(&guid, id, kind, &data));
                lines.push_str(&property_line(&guid, id, kind, &data));
            }
            0x1f => {
                let size = i64::from(i32_at(raw, index)?);
                index += 4;
                arrays.push(property_array(&guid, id, kind, copy(raw, index, size)?));
                lines.push_str(&property_line(&guid, id, kind, copy(raw, index, size)?));
                index += size;
            }
            0x11 => {
                arrays.push(property_array(&guid, id, kind, copy(raw, index, 1)?));
                lines.push_str(&property_line(&guid, id, kind, copy(raw, index, 1)?));
                index += 1;
            }
            other => {
                let Some(size) = fixed_size(other) else { return Err(format!("unhandled for {}", ole_type_name(other))) };
                arrays.push(property_array(&guid, id, kind, copy(raw, index, size)?));
                lines.push_str(&property_line(&guid, id, kind, copy(raw, index, size)?));
                index += size;
            }
        }
    }
    item.set("PropertyArrays", Value::List(arrays));
    let mut before = format!("Folder name: {name}\n");
    if name2 != name {
        before.push_str(&format!("Folder name 2: {name2}\n"));
    }
    before.push_str(&format!("\nProperty arrays (Description: Value)\n{lines}\n"));
    item.set_before_line(Some(before));
    Ok(item)
}

pub fn new_mtp_storage(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagMTPStorage", "MTP storage", raw);
    i16_at(raw, 0)?;
    byte_at(raw, 2)?;
    let mut index = 0x26i64;
    let name_size = twice(i32_at(raw, index)?);
    index += 4;
    let id_size = twice(i32_at(raw, index)?);
    index += 4;
    let system_size = twice(i32_at(raw, index)?);
    index += 4;
    let handlers = i32_at(raw, index)?;
    index += 4;
    let name = unicode_string(raw, index, name_size)?.trim_matches('\0').to_string();
    index += name_size;
    item.value = name.clone();
    let unique = unicode_string(raw, index, id_size)?.trim_matches('\0').to_string();
    index += id_size;
    let file_system = unicode_string(raw, index, system_size)?.trim_matches('\0').to_string();
    index += system_size;
    let handler_size = i64::from(handlers.wrapping_mul(78));
    let handler_text = unicode_string(raw, index, handler_size)?;
    let handler_list = crate::utils::split_nul_no_empty(&handler_text).join(",");
    item.set("StorageName", Value::text(name.as_str()));
    item.set("PersistentUniqueId", Value::text(unique.as_str()));
    item.set("FileSystemName", Value::text(file_system.as_str()));
    item.set("WpdEventHandlers", Value::List(crate::utils::split_nul_no_empty(&handler_text).into_iter().map(Value::text).collect()));
    index += handler_size + 4;
    guid_text(copy(raw, index, 16)?)?;
    index += 16;
    i32_at(raw, index)?;
    index += 4;
    let mut lines = String::new();
    let mut arrays = Vec::new();
    let mut serial = String::new();
    while index < raw.len() as i64 {
        if index + 4 >= raw.len() as i64 {
            break;
        }
        if i32_at(raw, index)? == 0 {
            index += 4;
            continue;
        }
        let guid = guid_text(copy(raw, index, 16)?)?;
        index += 16;
        let id = i32_at(raw, index)?;
        index += 4;
        let kind = i32_at(raw, index)?;
        index += 4;
        match kind {
            0x0d => {
                copy(raw, index, 16)?;
                index += 16;
                let count = i32_at(raw, index)?;
                index += 4;
                if count > 0 {
                    index += i64::from(count.wrapping_mul(0x10));
                }
                arrays.push(property_array(&guid, id, kind, &[]));
                lines.push_str(&property_line(&guid, id, kind, &[]));
            }
            0x1f => {
                let size = i64::from(i32_at(raw, index)?);
                index += 4;
                let bytes = copy(raw, index, size)?;
                index += size;
                arrays.push(property_array(&guid, id, kind, bytes));
                lines.push_str(&property_line(&guid, id, kind, bytes));
                if guid == "01a3057a-74d6-4e80-bea7-dc4c212ce50a" && id == 8 {
                    serial = crate::utils::unicode(bytes).trim_matches('\0').to_string();
                    item.set("StorageSerialNumber", Value::text(serial.as_str()));
                }
            }
            0x03 => {
                arrays.push(property_array(&guid, id, kind, copy(raw, index, 4)?));
                lines.push_str(&property_line(&guid, id, kind, copy(raw, index, 4)?));
                index += 4;
            }
            other => {
                let Some(size) = fixed_size(other) else { return Err(format!("unhandled for {}", ole_type_name(other))) };
                arrays.push(property_array(&guid, id, kind, copy(raw, index, size)?));
                lines.push_str(&property_line(&guid, id, kind, copy(raw, index, size)?));
                index += size;
            }
        }
    }
    item.set("PropertyArrays", Value::List(arrays));
    item.set_before_line(Some(format!(
        "Storage name: {name}\nStorage serial number: {serial}\n\nFile system name: {file_system}\n\nPersistent Unique Id: {unique}\n\nWPD Event Handlers {handler_list}\n\nProperty arrays (Description: Value)\n{lines}\n"
    )));
    Ok(item)
}

/// DateTimeOffset.TryParse, for the dates zip contents have: en-US's month first form
fn parse_date(text: &str) -> Option<Timestamp> {
    let mut parts = text.split_whitespace();
    let (date, time) = (parts.next()?, parts.next());
    if parts.next().is_some() {
        return Timestamp::parse(text);
    }
    let numbers: Vec<&str> = date.split('/').collect();
    if numbers.len() == 2 && time.is_none() {
        // month and day, of this year
        let (m, d) = (numbers[0].parse::<u32>().ok()?, numbers[1].parse::<u32>().ok()?);
        return Timestamp::from_parts(Timestamp::now().parts().year, m, d, 0, 0, 0, 0);
    }
    if numbers.len() == 3 {
        let (m, d, y) = (numbers[0].parse::<u32>().ok()?, numbers[1].parse::<u32>().ok()?, numbers[2].parse::<i32>().ok()?);
        let (mut hour, mut minute, mut second) = (0, 0, 0);
        if let Some(t) = time {
            let fields: Vec<&str> = t.split(':').collect();
            if fields.len() < 2 || fields.len() > 3 {
                return None;
            }
            hour = fields[0].parse().ok()?;
            minute = fields[1].parse().ok()?;
            if let Some(s) = fields.get(2) {
                second = s.parse().ok()?;
            }
        }
        return Timestamp::from_parts(y, m, d, hour, minute, second, 0);
    }
    Timestamp::parse(text)
}

pub fn new_zip_contents(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagZipContents", "Zip file contents", raw);
    let first = crate::utils::unicode(skip_take(raw, 0x24, 40));
    let mut date_text = first.split('\0').next().unwrap_or_default().to_string();
    let mut date = parse_date(&date_text);
    if date.is_none() {
        let second = crate::utils::unicode(skip_take(raw, 0x18, 40));
        date_text = second.split('\0').next().unwrap_or_default().to_string();
        date = parse_date(&date_text);
    }
    item.last_access = date;
    item.set("LastAccessTimeString", Value::text(date_text.as_str()));
    let mut index = if byte_at(raw, 0x14)? == 0x10 { 60i64 } else { 84 };
    let mut parent = None;
    let mut has_value = false;
    let attempt = (|| -> NetResult<()> {
        let size1 = i64::from(u16_at(raw, index)?);
        index += 4;
        let size2 = i64::from(u16_at(raw, index)?);
        index += 4;
        item.value = "!!!Unable to determine value!!!".to_string();
        has_value = true;
        if size1 > 0 {
            item.value = unicode_string(raw, index, size1 * 2)?;
            index += size1 * 2 + 2;
        }
        if size2 > 0 {
            parent = Some(unicode_string(raw, index, size2 * 2)?);
        }
        Ok(())
    })();
    if attempt.is_err() {
        let mut index = 60i64;
        let size1 = i64::from(u16_at(raw, index)?);
        index += 4;
        let size2 = i64::from(u16_at(raw, index)?);
        index += 4;
        if size1 > 0 {
            item.value = unicode_string(raw, index, size1 * 2)?;
            has_value = true;
            index += size1 * 2 + 2;
        }
        if size2 > 0 {
            unicode_string(raw, index, size2 * 2)?;
        }
    }
    item.value_is_null = !has_value;
    let mut before = String::new();
    item.set("ParentFolder", Value::opt_text(parent.as_deref()));
    if let Some(p) = parent.filter(|p| !p.is_empty()) {
        before.push_str(&format!("Folder in the zip file: {p}\n\n"));
    }
    if date_text != "N/A" {
        before.push_str(&format!("Last access internal value: {date_text}\n\n"));
    }
    item.set_before_line(Some(before));
    Ok(item)
}

pub fn new_0x04(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X04", "Directory", raw);
    let text = unicode_string(raw, 6, raw.len() as i64 - 6)?;
    item.value = text.split('\0').next().unwrap_or_default().to_string();
    Ok(item)
}

pub fn new_0x45(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X45", "Directory", raw);
    if byte_at(raw, 2)? == 0x45 && byte_at(raw, 4)? == 0x41 && byte_at(raw, 6)? == 0x53 && byte_at(raw, 8)? == 0x59 {
        let clean = |s: String| super::simple::net_trim(s.trim_matches('\0'));
        let mut strings = vec![clean(unicode_string(raw, 0x18, 0x46)?)];
        let mut index = 0x5ei64;
        while index < raw.len() as i64 {
            if raw.len() as i64 - index < 4 {
                break;
            }
            let size = i64::from(i32_at(raw, index)?);
            index += 4;
            strings.push(clean(crate::utils::unicode(copy(raw, index, size)?)));
            index += size;
            if byte_at(raw, index)? == 2 {
                index += 6;
            }
            if byte_at(raw, index)? == 2 {
                index = raw.len() as i64;
            }
        }
        item.value = strings.join(", ");
        return Ok(item);
    }
    let text = unicode_string(raw, 4, raw.len() as i64 - 4 - 0x54)?;
    item.value = crate::utils::split_nul_no_empty(&text).join(", ");
    Ok(item)
}
