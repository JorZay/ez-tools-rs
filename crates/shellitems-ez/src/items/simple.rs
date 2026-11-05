//! The shell item classes with little of their own.

use ez_common::Timestamp;
use ez_common::json::Value;
use ez_common::net::{NetResult, byte_at, copy, i16_at, i64_at, u32_at, unicode_string};

use super::*;
use crate::blocks::Block;
use crate::utils::{ansi_at, array_copy, from_file_time, guid_name, guid_text, skip_take, time_text};

pub fn new_0x01(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X01", "Control Panel Category", raw);
    item.drive_letter = Some(String::new());
    if byte_at(raw, 8)? == 0x3a && byte_at(raw, 9)? == 0 {
        item.friendly_name = "Hyper-V storage volume".into();
        item.bag_type = "HyperVResource";
        let letter = unicode_string(raw, 6, 4)?.replace('\0', "");
        item.value = unicode_string(raw, 0x32, raw.len() as i64 - 0x32)?.replace('\0', "");
        item.set_before_line(if letter.is_empty() { None } else { Some(format!("Drive Letter: {letter}\n\n")) });
        item.drive_letter = Some(letter);
        return Ok(item);
    }
    if u32_at(raw, 4)? != 0x39de2184 {
        item.value = unicode_string(raw, 14, raw.len() as i64 - 14)?.replace('\0', "");
        return Ok(item);
    }
    let category = raw[8];
    item.value = match category {
        0x00 => "All Control Panel Items".to_string(),
        0x01 => "Appearance and Personalization".to_string(),
        0x02 => "Hardware and Sound".to_string(),
        0x03 => "Network and Internet".to_string(),
        0x04 => "Sound, Speech and Audio Devices".to_string(),
        0x05 => "System and Security".to_string(),
        0x06 => "Clock, Language, and Region".to_string(),
        0x07 => "Ease of Access".to_string(),
        0x08 => "Programs".to_string(),
        0x09 => "User Accounts".to_string(),
        0x10 => "Security Center".to_string(),
        0x11 => "Mobile PC".to_string(),
        other => format!("Unknown category! Category ID: {other}"),
    };
    Ok(item)
}

pub fn new_0x02(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X02", "Hyper-V Directory", raw);
    let mut index = 22i64;
    let created = from_file_time(i64_at(raw, index)?);
    index += 8;
    let accessed = from_file_time(i64_at(raw, index)?);
    let accessed = (accessed.parts().year != 1601).then_some(accessed);
    index += 8;
    let modified = from_file_time(i64_at(raw, index)?);
    index += 8 + 4;
    let value = unicode_string(raw, index, raw.len() as i64 - index)?;
    item.value = net_trim(&value.replace('\0', " "));
    let mut before = format!("Created On: {}\nModified: {}\n", time_text(created), time_text(modified));
    if let Some(t) = accessed {
        before.push_str(&format!("Last Access: {}\n", time_text(t)));
    }
    before.push('\n');
    item.set_before_line(Some(before));
    item.last_modification = Some(modified);
    item.last_access = accessed;
    item.set("CreatedOnTime", Value::time(created));
    Ok(item)
}

pub fn new_0x03(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X03", "Unknown (Unconfirmed purpose)", raw);
    let mut index = 0x2a;
    if raw.len() > 0x2d && raw[0x2c] == 0xe4 && raw[0x2d] == 0x40 {
        index = 0x2e;
    }
    let text = if raw.len() > index { crate::utils::unicode(&raw[index..]) } else { String::new() };
    let strings: Vec<&str> = if raw.len() > index { text.split('\0').collect() } else { Vec::new() };
    let get = |i: usize| strings.get(i).copied().unwrap_or("");
    let (s1, s2, s3) = (get(0), get(2), get(4));
    let mut date = None;
    if raw.len() >= 0x1e + 8 {
        let v = f64::from_le_bytes(raw[0x1e..0x26].try_into().unwrap());
        date = from_oa_date(v).ok();
    }
    item.value = match date.filter(|d| d.parts().year > 1900) {
        Some(d) => format!("{s1} {s2} {s3} Timestamp: {}", d.format("M/d/yyyy h:mm:ss\u{202f}tt")),
        None => format!("{s1} {s2} {s3} (No date found)"),
    };
    Ok(item)
}

/// 0x09, 0x0F, 0x10, 0x18, 0x2B: a FILETIME and an ANSI string
fn time_and_name(class: &'static str, raw: &[u8], time_at: i64, name_at: i64) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, "Directory", raw);
    let time = from_file_time(i64_at(raw, time_at)?);
    let text = ansi_at(raw, name_at, raw.len() as i64 - name_at)?;
    item.value = text.split('\0').next().unwrap_or_default().to_string();
    item.set_before_line(Some(format!("Timestamp: {}\n", time_text(time))));
    item.set("Timestamp", Value::time(time));
    Ok(item)
}

pub fn new_0x09(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X09", raw, 4, 0x18)
}
pub fn new_0x0f(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X0F", raw, 4, 0x18)
}
pub fn new_0x10(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X10", raw, 4, 0x18)
}
pub fn new_0x18(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X18", raw, 0x16, 0x26)
}
pub fn new_0x2b(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X2B", raw, 0x16, 0x26)
}

pub fn new_0x0a(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X0A", "Directory", raw);
    let mut index = 0x0ei64;
    let trimmed = |index: i64, size: i16| -> NetResult<String> { Ok(unicode_string(raw, index, i64::from(size))?.trim_matches('\0').to_string()) };
    let mut size = i16_at(raw, index)?;
    index += 2;
    let s1 = trimmed(index, size)?;
    index += i64::from(size) + 4;
    size = i16_at(raw, index)?;
    index += 2;
    let s2 = trimmed(index, size)?;
    index += i64::from(size) + 4 + 2;
    let t1 = from_oa_date(f64::from_le_bytes(ez_common::net::bytes_at::<8>(raw, index)?))?;
    index += 8 + 4 + 2;
    let t2 = from_oa_date(f64::from_le_bytes(ez_common::net::bytes_at::<8>(raw, index)?))?;
    item.set("Timestamp", Value::time(t1));
    item.set("Timestamp2", Value::time(t2));
    index += 8 + 0x18;
    size = i16_at(raw, index)?;
    index += 2;
    item.set_before_line(Some(format!("Timestamp: {}\r\nTimestamp2: {}\n", time_text(t1), time_text(t2))));
    if size == 0 {
        item.value = format!("{s1}: {s2}");
        return Ok(item);
    }
    let s3 = trimmed(index, size)?;
    index += i64::from(size) + 4 + 2 + 5;
    size = i16_at(raw, index)?;
    index += 2;
    let s4 = trimmed(index, size)?;
    item.value = format!("{s1}: {s2} // {s3}: {s4}");
    Ok(item)
}

pub fn new_0x11(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X11", "Directory", raw);
    let t1 = from_file_time(i64_at(raw, 0x0e)?);
    let t2 = from_file_time(i64_at(raw, 0x16)?);
    let text = unicode_string(raw, 0x2e, raw.len() as i64 - 0x2e)?;
    item.value = text.split('\0').next().unwrap_or_default().to_string();
    item.set_before_line(Some(format!("Timestamp: {}Timestamp2: {}\n", time_text(t1), time_text(t2))));
    item.set("Timestamp", Value::time(t1));
    item.set("Timestamp2", Value::time(t2));
    Ok(item)
}

pub fn new_0x1a(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X1A", "Directory", raw);
    if byte_at(raw, 3)? == 0 {
        let time = from_file_time(i64_at(raw, 0x16)?);
        let text = ansi_at(raw, 0x26, raw.len() as i64 - 0x26)?;
        item.value = text.split('\0').next().unwrap_or_default().to_string();
        item.set_before_line(Some(format!("Timestamp: {}", time_text(time))));
        item.set("Timestamp", Value::time(time));
        return Ok(item);
    }
    item.value = ansi_at(raw, 0xb8, raw.len() as i64 - 0xb8)?.trim_matches('\0').to_string();
    Ok(item)
}

pub fn new_0x1e(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X1E", "Directory", raw);
    if byte_at(raw, 5)? != 0x14 {
        let index = 0x26i64;
        let mut len = 0i64;
        while byte_at(raw, index + len)? != 0 {
            len += 1;
        }
        item.value = ansi_at(raw, index, len)?;
        return Ok(item);
    }
    let mut index = 0x14i64;
    let mut chunks = Vec::new();
    while index < raw.len() as i64 {
        let size = i16_at(raw, index)?;
        if size == 0 {
            index += 2;
            continue;
        }
        chunks.push(copy(raw, index, i64::from(size))?);
        index += i64::from(size);
    }
    let mut values = Vec::new();
    for chunk in chunks {
        let made = match byte_at(chunk, 2)? {
            0x1f => new_0x1f(chunk)?,
            0x2e => new_0x2e(chunk)?,
            0x2f => new_0x2f(chunk)?,
            0x31 => new_0x31(chunk)?,
            0x00 => new_0x00(chunk)?,
            0xc3 => new_0xc3(chunk)?,
            0x74 => {
                if u32_at(chunk, 6)? == 0x46534643 { new_cfsf(chunk)? } else { new_0x74(chunk)? }
            }
            other => return Err(format!("Unknown type id 0x{other:02X}")),
        };
        values.push(made.value);
        item.extension_blocks.extend(made.extension_blocks);
    }
    item.value = values.join(" | ");
    Ok(item)
}

pub fn new_0x21(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X21", "GUID (Unconfirmed purpose)", raw);
    item.value = guid_name(&guid_text(array_copy(raw, 0x19, 16)?)?);
    Ok(item)
}

/// 0x23, 0x25, 0x2A, 0x2F: a drive letter
fn drive_letter(class: &'static str, raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, "Drive letter", raw);
    item.value = ansi_at(raw, 3, 2)?;
    if raw.len() > 0x30 {
        item.extension_blocks.push(block_at(raw, 0x19)?);
    }
    Ok(item)
}

pub fn new_0x23(raw: &[u8]) -> NetResult<ShellItem> {
    drive_letter("ShellBag0X23", raw)
}
pub fn new_0x25(raw: &[u8]) -> NetResult<ShellItem> {
    drive_letter("ShellBag0X25", raw)
}
pub fn new_0x2a(raw: &[u8]) -> NetResult<ShellItem> {
    drive_letter("ShellBag0X2A", raw)
}
pub fn new_0x2f(raw: &[u8]) -> NetResult<ShellItem> {
    drive_letter("ShellBag0X2F", raw)
}

pub fn new_0x2c(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X2C", "Search? (Unconfirmed)", raw);
    item.value = unicode_string(raw, 0x28, raw.len() as i64 - 0x28 - 0x10)?.trim_matches('\0').to_string();
    Ok(item)
}

pub fn new_0x3a(raw: &[u8]) -> NetResult<ShellItem> {
    if crate::utils::index_of(raw, &BEEF0004_SIGNATURE, 0) >= 0 {
        let mut entry = new_0x31(raw)?;
        // its text is the base's alone
        entry.class = "ShellBag0X3A";
        entry.parts.clear();
        return Ok(entry);
    }
    let mut item = ShellItem::new("ShellBag0X3A", "Directory", raw);
    let size = i64::from(byte_at(raw, 0xa)?);
    let index = if byte_at(raw, 0xb)? == 1 { 0xc } else { 0xb };
    let text = ansi_at(raw, index, size)?;
    item.value = text.split('|').next_back().unwrap_or_default().to_string();
    Ok(item)
}

/// 0x41, 0x42, 0x43, 0x46, 0x47: network locations
fn network(class: &'static str, friendly_name: &str, raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, friendly_name, raw);
    let (location, description) = crate::utils::network_location(raw)?;
    item.value = location;
    item.set("Description", Value::opt_text(description.as_deref()));
    item.set_before_line(description.map(|d| format!("Description: {d}\n")));
    Ok(item)
}

pub fn new_0x41(raw: &[u8]) -> NetResult<ShellItem> {
    network("ShellBag0X41", "Domain/Workgroup name", raw)
}
pub fn new_0x42(raw: &[u8]) -> NetResult<ShellItem> {
    network("ShellBag0X42", "Server UNC path", raw)
}
pub fn new_0x43(raw: &[u8]) -> NetResult<ShellItem> {
    network("ShellBag0X43", "Share UNC path", raw)
}
pub fn new_0x46(raw: &[u8]) -> NetResult<ShellItem> {
    network("ShellBag0X46", "Microsoft Windows Network", raw)
}
pub fn new_0x47(raw: &[u8]) -> NetResult<ShellItem> {
    network("ShellBag0X47", "Entire Network", raw)
}

pub fn new_0x4c(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X4C", "Sharepoint directory", raw);
    let mut index = 0x1ci64;
    let mut len = i64::from(i16_at(raw, index)?);
    index += 2;
    let name = unicode_string(raw, index, len * 2)?.trim_matches('\0').to_string();
    index += len * 2 + 2;
    len = i64::from(i16_at(raw, index)?);
    index += 2;
    let mut second = unicode_string(raw, index, len * 2)?.trim_matches('\0').to_string();
    if second.is_empty() {
        second = "URL not specified".to_string();
    }
    item.value = format!("{name} ({second})");
    Ok(item)
}

/// 0x4D and 0x71: a GUID, or a property view
fn control_panel(class: &'static str, raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, "GUID: Control panel", raw);
    if u32_at(raw, 6)? == 0xbeebee00 {
        property_view(&mut item, raw, true)?;
        return Ok(item);
    }
    let mut index = 14i64;
    if byte_at(raw, 2)? == 0x4d {
        index -= 10;
    }
    if raw.len() == 0x16 {
        index = 4;
    }
    item.value = guid_name(&guid_text(array_copy(raw, index, 16)?)?);
    if raw.len() > 32 {
        item.extension_blocks.push(block_at(raw, 0x1e)?);
    }
    Ok(item)
}

pub fn new_0x4d(raw: &[u8]) -> NetResult<ShellItem> {
    control_panel("ShellBag0X4D", raw)
}
pub fn new_0x71(raw: &[u8]) -> NetResult<ShellItem> {
    control_panel("ShellBag0X71", raw)
}

pub fn new_0x4e(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X4E", "Root folder: GUID", raw);
    let mut index = 4i64;
    let folder = guid_name(&guid_text(array_copy(raw, index, 16)?)?);
    index += 16;
    let size = i16_at(raw, index)?;
    if size == 0 {
        index += 2;
    }
    if index < raw.len() as i64 {
        item.extension_blocks.push(block_at(raw, index)?);
    }
    item.value = folder;
    Ok(item)
}

pub fn new_0x53(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X53", "Root folder: GUID", raw);
    guid_text(skip_take(raw, 20, 16))?;
    item.value = guid_name(&guid_text(skip_take(raw, 36, 16))?);
    Ok(item)
}

/// 0x54 and 0x65: a name, or zip contents. Their text has one more empty line
fn name_or_zip(class: &'static str, raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new(class, "Directory", raw);
    let mut name = unicode_string(raw, 4, raw.len() as i64 - 6)?.replace('\0', "");
    if byte_at(raw, 4)? == 0x10 {
        item.friendly_name = "ZipFileContents".into();
        item.bag_type = "ZipFileContents";
        let modified = from_file_time(i64_at(raw, 16)?);
        item.set("ModifiedOn", Value::time(modified));
        let len1 = i64::from(i16_at(raw, 28)?);
        let len2 = i64::from(i16_at(raw, 30)?);
        name = unicode_string(raw, 32, (len1 + len2) * 2)?.replace('\0', "");
        item.set_before_line(Some(format!("Modified On: {}\n\n", time_text(modified))));
    }
    item.value = name;
    item.after = "\n".to_string();
    Ok(item)
}

pub fn new_0x54(raw: &[u8]) -> NetResult<ShellItem> {
    name_or_zip("ShellBag0X54", raw)
}
pub fn new_0x65(raw: &[u8]) -> NetResult<ShellItem> {
    name_or_zip("ShellBag0X65", raw)
}

pub fn new_0x5c(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X5C", "Directory", raw);
    let mut len = 0i64;
    while byte_at(raw, 3 + len)? != 0 {
        len += 1;
    }
    item.value = ansi_at(raw, 3, len)?;
    let mut index = raw.len() as i64 - 5;
    let mut zeros = 0;
    while zeros < 2 {
        index -= 1;
        if byte_at(raw, index)? == 0 {
            zeros += 1;
        }
    }
    index += 1;
    let text = ansi_at(raw, index, raw.len() as i64 - index - 4)?;
    let parts = crate::utils::split_nul_no_empty(&text);
    let (Some(a), Some(b)) = (parts.first(), parts.get(1)) else { return Err(ez_common::net::ARRAY_INDEX.to_string()) };
    item.set_before_line(Some(format!("Description: {a} ({b})\n")));
    item.set("Description", Value::text(format!("{a} ({b})")));
    Ok(item)
}

pub fn new_0x63(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = new_0x5c(raw)?;
    item.class = "ShellBag0X63";
    Ok(item)
}

pub fn new_0x67(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X67", "History folder", raw);
    item.value = unicode_string(raw, 8, raw.len() as i64 - 8)?.replace('\0', "");
    Ok(item)
}

pub fn new_0x70(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X70", "GUID", raw);
    item.value = guid_name(&guid_text(array_copy(raw, 4, 16)?)?);
    Ok(item)
}

/// The extension block at an index of an item
pub(super) fn block_at(raw: &[u8], index: i64) -> NetResult<Block> {
    u32_at(raw, index + 4)?;
    Ok(crate::blocks::from_bytes_or_error(crate::utils::skip(raw, index as usize)))
}

/// DateTime.FromOADate; the result as a time at offset 0
pub fn from_oa_date(value: f64) -> NetResult<Timestamp> {
    const MILLIS_PER_DAY: i64 = 86_400_000;
    const DOUBLE_DATE_OFFSET_MILLIS: i64 = 59_926_435_200_000;
    const MAX_MILLIS: i64 = 315_537_897_600_000;
    let illegal = || "Not a legal OleAut date.".to_string();
    if value.is_nan() || value >= 2_958_466.0 || value <= -657_435.0 {
        return Err(illegal());
    }
    let mut millis = (value * 86_400_000.0 + if value >= 0.0 { 0.5 } else { -0.5 }) as i64;
    if millis < 0 {
        millis -= (millis % MILLIS_PER_DAY) * 2;
    }
    millis += DOUBLE_DATE_OFFSET_MILLIS;
    if !(0..MAX_MILLIS).contains(&millis) {
        return Err(illegal());
    }
    Ok(Timestamp(millis * 10_000))
}

/// string.Trim(): white space at both ends
pub fn net_trim(s: &str) -> String {
    s.trim_matches(char::is_whitespace).to_string()
}

pub fn new_0x80(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = name_or_zip("ShellBag0X80", raw)?;
    item.after.clear();
    Ok(item)
}
pub fn new_0x87(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X87", raw, 0x16, 0x26)
}
pub fn new_0x94(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0X94", raw, 0x16, 0x26)
}
pub fn new_0xb2(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XB2", raw, 0x16, 0x26)
}
pub fn new_0xb6(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XB6", raw, 0x16, 0x26)
}
pub fn new_0xb8(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XB8", raw, 0x16, 0x26)
}
pub fn new_0xbd(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XBD", raw, 0x16, 0x26)
}
pub fn new_0xc0(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XC0", raw, 0x16, 0x26)
}
pub fn new_0xc6(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XC6", raw, 0x16, 0x26)
}
pub fn new_0xca(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XCA", raw, 0x16, 0x26)
}
pub fn new_0xf3(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XF3", raw, 0x16, 0x26)
}
pub fn new_0xf4(raw: &[u8]) -> NetResult<ShellItem> {
    time_and_name("ShellBag0XF4", raw, 0x16, 0x26)
}

pub fn new_0x74(raw: &[u8]) -> NetResult<ShellItem> {
    control_panel("ShellBag0X74", raw)
}

pub fn new_0xc3(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0XC3", "Network location", raw);
    u16_of(raw, 0)?;
    let index = 5i64;
    byte_at(raw, 2)?;
    byte_at(raw, 3)?;
    byte_at(raw, 4)?;
    let mut sep = index;
    while i16_at(raw, sep)? != 2 {
        sep += 1;
        if sep + 1 == raw.len() as i64 {
            sep = -1;
            break;
        }
    }
    let index_error = || ez_common::net::ARRAY_INDEX.to_string();
    let mut description: Option<String> = None;
    if sep == -1 {
        let text = ansi_at(raw, index, raw.len() as i64 - index)?;
        let parts = crate::utils::split_nul_no_empty(&text);
        item.value = parts.first().ok_or_else(index_error)?.to_string();
        if let Some(d) = parts.get(1) {
            description = Some(d.to_string());
        }
        item.set("LocationDescription", Value::opt_text(description.as_deref()));
        item.set_before_line(Some(format!("Location description: {}\r\n\n", description.unwrap_or_default())));
        return Ok(item);
    }
    let text = ansi_at(raw, index, sep - 5 - 1)?;
    let parts = crate::utils::split_nul_no_empty(&text);
    let mut at = sep + 2;
    item.value = parts.first().ok_or_else(index_error)?.to_string();
    item.set("LocationDescription", Value::text(parts[1..].join(", ")));
    item.set_before_line(Some(format!("Location description: {}\r\n\n", parts[1..].join(", "))));
    if at == raw.len() as i64 {
        return Ok(item);
    }
    let mut size = i16_at(raw, at)?;
    while size > 0 {
        let bytes = skip_take(raw, at as usize, size as usize);
        at += i64::from(size);
        u32_at(bytes, 4)?;
        item.extension_blocks.push(crate::blocks::from_bytes_or_error(bytes));
        if at == raw.len() as i64 {
            return Ok(item);
        }
        size = i16_at(raw, at)?;
    }
    Ok(item)
}

fn u16_of(raw: &[u8], at: i64) -> NetResult<u16> {
    ez_common::net::u16_at(raw, at)
}

pub fn new_0xe1(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0XE1", "", raw);
    let mut index = 0x14i64;
    while ez_common::net::i32_at(raw, index)? != 0x2e572e53 {
        index += 1;
    }
    let position = index;
    item.value = unicode_string(raw, 0x14, position - 0x14)?.trim_matches('\0').to_string();
    match byte_at(raw, position + 7)? {
        1 => {
            item.friendly_name = "Directory".into();
            item.bag_type = "Directory";
        }
        2 => {
            item.friendly_name = "File".into();
            item.bag_type = "File";
        }
        _ => {}
    }
    Ok(item)
}

pub fn new_0xe8(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0XE8", "Directory", raw);
    let len = i64::from(u16_of(raw, 4)?);
    item.value = unicode_string(raw, 6, len * 2)?.trim_matches('\0').to_string();
    Ok(item)
}

pub fn new_0x16(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = new_0x11(raw)?;
    item.class = "ShellBag0X16";
    Ok(item)
}

pub fn new_0x1d(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBag0X1D", "URI", raw);
    let time = from_file_time(i64_at(raw, 0x16)?);
    item.set("FileTime1", Value::time(time));
    let mut len = 0i64;
    while byte_at(raw, 0x26 + len)? != 0 {
        len += 1;
    }
    item.value = ansi_at(raw, 0x26, len)?;
    item.set_before_line(Some(format!("Time stamp: {}\n\n", time.format("M/d/yyyy h:mm:ss\u{202f}tt K"))));
    Ok(item)
}
