//! PropertyStore and PropertySheet: "1SPS" serialized property storage.

use ez_common::dotnet::{dotnet_f32, dotnet_f64};
use ez_common::net::{NetResult, byte_at, copy, hex, i16_at, i32_at, i64_at, u16_at, u32_at, u64_at, unicode_string};

use ez_common::json::{Value, base64};

use crate::items::{self, ShellItem};
use crate::utils::{array_copy, description_from_guid_and_key, file_time_invariant, guid_name, guid_text};

/// A line of a sheet's extra data, made only when its text is asked for, as LazyText does
#[derive(Clone, Debug)]
enum Lazy {
    Text(String),
    Store(PropertyStore),
    Item(ShellItem),
    Make(fn(&[u8]) -> NetResult<ShellItem>, Vec<u8>),
}

impl Lazy {
    fn line(&self) -> String {
        let text = match self {
            Lazy::Text(t) => Ok(t.clone()),
            Lazy::Store(s) => Ok(s.to_text()),
            Lazy::Item(i) => Ok(i.to_text()),
            Lazy::Make(make, bytes) => make(bytes).map(|i| i.to_text()),
        };
        text.unwrap_or_else(|e| format!("(could not be shown: {e})"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SheetType {
    Named,
    Numeric,
}

#[derive(Clone, Debug)]
pub struct PropertySheet {
    pub size: i32,
    pub version: String,
    pub guid: String,
    pub sheet_type: SheetType,
    /// In the order they were read
    pub property_names: Vec<(String, String)>,
    extra: Vec<Vec<Lazy>>,
}

fn add(names: &mut Vec<(String, String)>, key: &str, value: String) -> NetResult<()> {
    if names.iter().any(|(k, _)| k == key) {
        return Err(format!("An item with the same key has already been added. Key: {key}"));
    }
    names.push((key.to_string(), value));
    Ok(())
}

const STREAM_MTP_DEVICE: u32 = 0x08312006;
const STREAM_MTP_STORAGE: u32 = 0x10312005;
const STREAM_MTP_FOLDER: u32 = 0x07192006;
const STREAM_CFSF: u32 = 0x46534643;

/// The values of a sheet, each with its size at the start
fn split_values(contents: &[u8], start: i64, block_copy: bool) -> NetResult<(Vec<&[u8]>, i64)> {
    let mut values = Vec::new();
    let mut index = start;
    while index < contents.len() as i64 {
        let size = i32_at(contents, index)?;
        if size == 0 {
            break;
        }
        values.push(if block_copy { copy(contents, index, i64::from(size))? } else { array_copy(contents, index, i64::from(size))? });
        index += i64::from(size);
    }
    Ok((values, index))
}

/// Type 0x0041 of a named sheet
fn named_blob(value: &[u8], index: i64) -> NetResult<Vec<Lazy>> {
    i32_at(value, index)?;
    let index = index + 4;
    let rest_length = value.len() as i64 - index;
    if rest_length < 0 {
        return Err(ez_common::net::OVERFLOW.to_string());
    }
    let rest = &value[index as usize..];
    let mut at = 2i64;
    let mut chunks = Vec::new();
    while at < rest.len() as i64 {
        let size = i16_at(rest, at)?;
        if size == 0 {
            break;
        }
        chunks.push(copy(rest, at, i64::from(size))?);
        at += i64::from(size);
    }
    let mut lines = Vec::new();
    for chunk in chunks {
        let id = byte_at(chunk, 2)?;
        let make: fn(&[u8]) -> NetResult<ShellItem> = match id {
            0x1f => items::new_0x1f,
            0x2e => items::new_0x2e,
            0x2f => items::new_0x2f,
            0x31 => items::new_0x31,
            0x32 => items::new_0x32,
            0x00 => items::new_0x00,
            0x35 => items::new_0x35,
            0xc3 => items::new_0xc3,
            _ => return Err(format!("Unknown type id 0x{id:02X}")),
        };
        lines.push(Lazy::Make(make, chunk.to_vec()));
    }
    Ok(lines)
}

/// Type 0x0042 of a named sheet, AutoList: the chunks after its header
fn stream_chunks<'a>(value: &'a [u8], start: i64) -> NetResult<Vec<&'a [u8]>> {
    let mut index = start;
    let name_size = i32_at(value, index)?;
    index += 4;
    unicode_string(value, index, i64::from(name_size))?;
    index += i64::from(name_size);
    index += 2 + 4;
    copy(value, index, 16)?;
    index += 16 + 4;
    let another_guid = i32_at(value, index)?;
    index += 4;
    if another_guid == 1 {
        copy(value, index, 16)?;
        index += 16;
    } else {
        index += 0x18;
    }
    let extra_blocks = i32_at(value, index)?;
    index += 4;
    let mut chunks = Vec::new();
    if extra_blocks == 1 {
        let mut size = i16_at(value, index)?;
        if size == 2 {
            index += 4;
            size = i16_at(value, index)?;
        }
        chunks.push(copy(value, index, i64::from(size))?);
        index += i64::from(size) + 2;
        let mut more = i16_at(value, index)?;
        if more == 1 {
            index += 0x1c;
        }
        while more != 0 {
            size = i16_at(value, index)?;
            chunks.push(copy(value, index, i64::from(size))?);
            index += i64::from(size) + 2;
            more = i16_at(value, index)?;
            if more == 1 {
                index += 0xc;
                more = 0;
            }
            // a size of 0 would read the same place for ever: the original would too, until it ran out of memory
            if size == 0 {
                return Err(ez_common::net::OVERFLOW.to_string());
            }
        }
        if more == 0 {
            index += 0x10;
        }
    } else {
        let mut size = i16_at(value, index)?;
        if size > 0 {
            chunks.push(copy(value, index, i64::from(size))?);
            index += i64::from(size) + 2;
            let mut more = i32_at(value, index)?;
            while more != 0 {
                index += 16;
                size = i16_at(value, index)?;
                if size > 0 {
                    chunks.push(copy(value, index, i64::from(size))?);
                    index += i64::from(size);
                }
                index += 2;
                more = i32_at(value, index)?;
            }
            index += 0x20;
        }
    }
    i32_at(value, index)?;
    Ok(chunks)
}

fn stream_lines(chunks: Vec<&[u8]>) -> NetResult<Vec<Lazy>> {
    let mut lines = Vec::new();
    for chunk in chunks {
        if chunk.len() == 2 {
            continue;
        }
        let mut sub_chunks = Vec::new();
        if chunk.len() == 0x14 {
            sub_chunks.push(chunk);
        } else if i32_at(chunk, 4)? == 0x53505331 {
            lines.push(Lazy::Store(PropertyStore::read(chunk)?));
        } else {
            let mut at = 2i64;
            let mut size = i16_at(chunk, at)?;
            while at != chunk.len() as i64 {
                if size <= 0 {
                    break;
                }
                sub_chunks.push(copy(chunk, at, i64::from(size))?);
                at += i64::from(size);
                if at == chunk.len() as i64 {
                    break;
                }
                size = i16_at(chunk, at)?;
            }
        }
        for sub in sub_chunks {
            let id = byte_at(sub, 2)?;
            let make: Option<fn(&[u8]) -> NetResult<ShellItem>> = match u32_at(sub, 6)? {
                STREAM_MTP_DEVICE => Some(items::new_mtp_device),
                STREAM_MTP_STORAGE => Some(items::new_mtp_storage),
                STREAM_MTP_FOLDER => Some(items::new_mtp_folder),
                STREAM_CFSF => Some(items::new_cfsf),
                _ => match id {
                    0x1f => Some(items::new_0x1f),
                    0x2f => Some(items::new_0x2f),
                    0x2e => Some(items::new_0x2e),
                    0x32 => Some(items::new_0x32),
                    0xc3 => Some(items::new_0xc3),
                    0x31 => Some(items::new_0x31),
                    0x35 => Some(items::new_0x35),
                    0x39 => Some(items::new_0x39),
                    0x01 => Some(items::new_0x01),
                    0x71 => Some(items::new_0x71),
                    0x61 => Some(items::new_0x61),
                    0xb1 => Some(items::new_0xb1),
                    0x1e => Some(items::new_0x1e),
                    _ => None,
                },
            };
            if let Some(make) = make {
                lines.push(Lazy::Make(make, sub.to_vec()));
                continue;
            }
            if id == 0x00 {
                // made here, not when the text is: a 0x00 item that can't be read gets this message
                match items::new_0x00(sub) {
                    Ok(item) => lines.push(Lazy::Item(item)),
                    Err(_) => {
                        let possible = unicode_string(sub, 6, sub.len() as i64 - 6)?;
                        lines.push(Lazy::Text(format!(
                            "******************* Error parsing shell item. Possible false positive when parsing a property store. String data: {} Hex data: {} *******************",
                            possible.trim_matches('\0'),
                            hex(sub)
                        )));
                    }
                }
                continue;
            }
            let possible = unicode_string(sub, 4, sub.len() as i64 - 4)?;
            let possible = possible.trim_matches('\0');
            if possible.starts_with("StickyNotes:") {
                lines.push(Lazy::Text(possible.to_string()));
            } else {
                lines.push(Lazy::Text(format!("******************* Unknown type id in 0x0042 stream: 0x{id:02X}. Possible string: {possible} Hex data: {} *******************", hex(sub))));
            }
        }
    }
    Ok(lines)
}

/// Type 0x1011 of a numeric sheet
fn vector_lines(value: &[u8]) -> NetResult<Vec<Lazy>> {
    let mut at = 0x11i64;
    let mut lines = Vec::new();
    while at != value.len() as i64 {
        let size = i16_at(value, at)?;
        if size == 0 {
            break;
        }
        let item = copy(value, at, i64::from(size))?;
        at += i64::from(size);
        let id = byte_at(item, 2)?;
        let make: fn(&[u8]) -> NetResult<ShellItem> = if u32_at(item, 6)? == STREAM_CFSF {
            items::new_cfsf
        } else {
            match id {
                0x00 => items::new_0x00,
                0x1f => items::new_0x1f,
                0x2f => items::new_0x2f,
                0x31 => items::new_0x31,
                0x32 => items::new_0x32,
                0xc3 => items::new_0xc3,
                0x2e => items::new_0x2e,
                0xb1 => items::new_0xb1,
                0x35 => items::new_0x35,
                0x36 => items::new_0x36,
                _ => {
                    return Err(format!("Unsupported ShellBag type 0x{id:02X} in vector data. Raw bytes: {}", base64(item)));
                }
            }
        };
        lines.push(Lazy::Make(make, item.to_vec()));
    }
    Ok(lines)
}

impl PropertySheet {
    pub fn read(contents: &[u8]) -> NetResult<PropertySheet> {
        let size = i32_at(contents, 0)?;
        let version = u32_at(contents, 4)?;
        if version != 0x53505331 {
            return Err(format!("Version mismatch! {} != 31-53-50-53", hex(&contents[4..8])));
        }
        let version_text = hex(&contents[4..8]);
        let guid = guid_text(array_copy(contents, 8, 16)?)?;
        let mut sheet = PropertySheet { size, version: version_text, guid: guid.clone(), sheet_type: SheetType::Numeric, property_names: Vec::new(), extra: Vec::new() };
        let end = if guid == "d5cdd505-2e9c-101b-9397-08002b2cf9ae" {
            sheet.sheet_type = SheetType::Named;
            let (values, end) = split_values(contents, 24, false)?;
            for value in values {
                sheet.read_named(value)?;
            }
            end
        } else {
            let (values, end) = split_values(contents, 24, true)?;
            for value in values {
                sheet.read_numeric(value)?;
            }
            end
        };
        let terminator = i32_at(contents, end)?;
        if terminator != 0 {
            return Err(format!("Expected terminator of 0, but got {terminator}"));
        }
        Ok(sheet)
    }

    fn read_named(&mut self, value: &[u8]) -> NetResult<()> {
        i32_at(value, 0)?;
        let name_size = i32_at(value, 4)?;
        let mut index = 4i64 + 4 + 1;
        let name = unicode_string(value, index, i64::from(name_size.wrapping_sub(2)))?;
        index += i64::from(name_size);
        let kind = u16_at(value, index)?;
        index += 4;
        let names = &mut self.property_names;
        match kind {
            0x000b => add(names, &name, (if i32_at(value, index)? > 0 { "True" } else { "False" }).to_string())?,
            0x0 | 0x1 => add(names, &name, String::new())?,
            0x0002 => add(names, &name, i16_at(value, index)?.to_string())?,
            0x0003 | 0x0016 => add(names, &name, i32_at(value, index)?.to_string())?,
            0x0004 => add(names, &name, dotnet_f32(f32::from_le_bytes(ez_common::net::bytes_at::<4>(value, index)?)))?,
            0x0005 => add(names, &name, dotnet_f64(f64::from_le_bytes(ez_common::net::bytes_at::<8>(value, index)?)))?,
            0x0008 => {
                let length = i32_at(value, index)?;
                add(names, &name, unicode_string(value, index + 4, i64::from(length.wrapping_sub(2)))?)?;
            }
            0x000a | 0x0013 | 0x0017 => add(names, &name, u32_at(value, index)?.to_string())?,
            0x0014 => add(names, &name, i64_at(value, index)?.to_string())?,
            0x0015 => add(names, &name, u64_at(value, index)?.to_string())?,
            0x001f => {
                let length = i32_at(value, index)?;
                add(names, &name, unicode_string(value, index + 4, i64::from(length.wrapping_mul(2).wrapping_sub(2)))?)?;
            }
            0x0040 => add(names, &name, file_time_invariant(i64_at(value, index)?)?)?,
            0x0041 => {
                let lines = named_blob(value, index)?;
                add(&mut self.property_names, &name, "VT_BLOB data (See ExtraData for details)".to_string())?;
                self.extra.push(lines);
            }
            0x0042 => {
                if byte_at(value, 4)? == 0x12 {
                    let lines = stream_lines(stream_chunks(value, index)?)?;
                    add(&mut self.property_names, &name, "VT_STREAM 0x0042 (AutoList) (See ExtraData for details)".to_string())?;
                    self.extra.push(lines);
                } else {
                    add(names, &name, "VT_STREAM 0x0042 (Non-AutoList) not implemented (yet)".to_string())?;
                }
            }
            0x0048 => add(names, &name, guid_text(copy(value, index, 16)?)?)?,
            _ => return Err(format!("Unknown property type: {kind:02X}")),
        }
        Ok(())
    }

    fn read_numeric(&mut self, value: &[u8]) -> NetResult<()> {
        i32_at(value, 0)?;
        let id = i32_at(value, 4)?.to_string();
        let index = 4i64 + 4 + 1;
        let kind = u16_at(value, index)?;
        let index = index + 4;
        let names = &mut self.property_names;
        match kind {
            0x1048 => add(names, &id, "VT_VECTOR data not implemented (yet)".to_string())?,
            0x001e => {
                let length = i32_at(value, index)?;
                let text = unicode_string(value, index + 4, i64::from(length))?;
                add(names, &id, text.split('\0').next().unwrap_or_default().to_string())?;
            }
            0x0002 => add(names, &id, i16_at(value, index)?.to_string())?,
            0x001f => {
                let length = i32_at(value, index)?;
                if length == 0 {
                    add(names, &id, "(None)".to_string())?;
                } else {
                    add(names, &id, unicode_string(value, index + 4, i64::from(length.wrapping_mul(2).wrapping_sub(2)))?)?;
                }
            }
            0x000b => add(names, &id, (if i32_at(value, index)? > 0 { "True" } else { "False" }).to_string())?,
            0x0003 => add(names, &id, i32_at(value, index)?.to_string())?,
            0x0015 => add(names, &id, u64_at(value, index)?.to_string())?,
            0x0042 => {
                let name_size = i32_at(value, index)?;
                if name_size == 0 {
                    add(names, &id, "VT_STREAM: Name: (NONE)), Data: (NA)".to_string())?;
                } else {
                    let mut at = index + 4;
                    let name = unicode_string(value, at, i64::from(name_size))?;
                    let name = name.trim_matches('\0').to_string();
                    at += i64::from(name_size) + 10;
                    let size = i32_at(value, at)?;
                    let store = PropertyStore::read(copy(value, at, i64::from(size))?)?;
                    add(names, &id, format!("VT_STREAM: Name: {name}, Data: {}", store.to_text()))?;
                }
            }
            0x0013 => add(names, &id, u32_at(value, index)?.to_string())?,
            0x0001 => add(names, &id, "Null".to_string())?,
            0x101f => {
                let at = index + 4;
                if at == value.len() as i64 {
                    add(names, &id, "Null".to_string())?;
                } else {
                    let length = i32_at(value, at)?;
                    add(names, &id, unicode_string(value, at + 4, i64::from(length.wrapping_mul(2).wrapping_sub(2)))?)?;
                }
            }
            0x0048 => {
                let guid = guid_text(array_copy(value, index, 16)?)?;
                add(names, &id, guid_name(&guid))?;
            }
            0x1011 => {
                let lines = vector_lines(value)?;
                add(&mut self.property_names, &id, "VT_VECTOR data (See ExtraData for details)".to_string())?;
                self.extra.push(lines);
            }
            0x0040 => add(names, &id, file_time_invariant(i64_at(value, index)?)?)?,
            0x0008 => {
                let length = i32_at(value, index)?;
                add(names, &id, unicode_string(value, index + 4, i64::from(length.wrapping_sub(2)))?)?;
            }
            _ => return Err(format!("Unknown property type: {kind:02X}")),
        }
        Ok(())
    }

    /// ExtraData
    pub fn extra_data(&self) -> String {
        let mut out = String::new();
        for lines in &self.extra {
            out.push_str("\r\n");
            for line in lines {
                out.push_str(&line.line());
                out.push_str("\r\n");
            }
        }
        out
    }

    /// The properties ServiceStack serializes
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("Size", Value::number(self.size)),
            ("Version", Value::text(self.version.as_str())),
            ("GUID", Value::text(self.guid.as_str())),
            ("PropertyNames", Value::Object(self.property_names.iter().map(|(k, v)| (k.clone().into(), Value::text(v.as_str()))).collect())),
            ("ExtraData", Value::text(self.extra_data())),
            ("PropertySheetType", Value::text(if self.sheet_type == SheetType::Named { "Named" } else { "Numeric" })),
        ])
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        let pairs: Vec<String> = self
            .property_names
            .iter()
            .map(|(k, v)| {
                let name = match (&self.sheet_type, k.parse::<i32>()) {
                    (SheetType::Numeric, Ok(key)) => description_from_guid_and_key(&self.guid, key),
                    _ => k.clone(),
                };
                format!("Guid: {}, Key: {k} ==> {name}, Value: {v}", self.guid)
            })
            .collect();
        let mut s = pairs.join("; ");
        let extra = self.extra_data();
        if !extra.is_empty() {
            s.push_str(&format!("\r\n\r\nExtra data: {extra}\r\n"));
        }
        s
    }
}

#[derive(Clone, Debug, Default)]
pub struct PropertyStore {
    pub sheets: Vec<PropertySheet>,
    /// Damaged sheets that were left out
    pub parse_errors: Vec<String>,
}

impl PropertyStore {
    pub fn read(raw: &[u8]) -> NetResult<PropertyStore> {
        let mut store = PropertyStore::default();
        if raw.len() < 4 {
            return Ok(store);
        }
        let mut lists = Vec::new();
        let mut index = 0i64;
        while index + 4 <= raw.len() as i64 {
            let size = i32_at(raw, index)?;
            if size == 0 {
                break;
            }
            if size < 0 || i64::from(size) > raw.len() as i64 - index {
                store.parse_errors.push(format!("Property sheet at offset 0x{index:X} has a size of {size}, but only {} bytes are left", raw.len() as i64 - index));
                break;
            }
            lists.push(&raw[index as usize..(index + i64::from(size)) as usize]);
            index += i64::from(size);
        }
        for (slot, list) in lists.iter().enumerate() {
            match PropertySheet::read(list) {
                Ok(sheet) => store.sheets.push(sheet),
                Err(e) => store.parse_errors.push(format!("Property sheet #{slot} could not be parsed: {e}")),
            }
        }
        if store.sheets.is_empty() {
            if let Some(first) = store.parse_errors.first() {
                return Err(first.clone());
            }
        }
        Ok(store)
    }

    /// The properties ServiceStack serializes
    pub fn to_value(&self) -> Value {
        Value::object(vec![("Sheets", Value::List(self.sheets.iter().map(PropertySheet::to_value).collect())), ("ParseErrors", Value::strings(&self.parse_errors))])
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for (i, sheet) in self.sheets.iter().enumerate() {
            s.push_str(&format!("Sheet #{i} => {}\r\n", sheet.to_text()));
        }
        for e in &self.parse_errors {
            s.push_str(&format!("Parse error: {e}\r\n"));
        }
        s
    }
}
