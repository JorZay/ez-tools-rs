//! Plugins that read shell items (NTUSER.DAT): LastVisitedPidlMRU, OpenSavePidlMRU, Taskband, RecentDocs.

use ez_common::Timestamp;
use ez_common::dotnet::compare_culture;
use ez_common::net::{self, NetResult};
use registry_ez::hive::lower;
use registry_ez::{Hive, KeyId};
use shellitems_ez::blocks;
use shellitems_ez::{BlockKind, ShellItem, create_item};

use crate::helpers::{OUT_OF_BOUNDS, last_write, path, row, subkey, subkeys, time, try_parse_i32, try_parse_u32, utf16_len, value, values};
use crate::{Output, ValuesOut};

const END_OF_STREAM: &str = "Unable to read beyond the end of the stream.";

/// MRUListEx, 0xFFFFFFFF left out; a size that isn't a multiple of 4 is an error
fn mru_list(raw: &[u8]) -> NetResult<Vec<i32>> {
    let mut list = Vec::new();
    let mut index = 0i64;
    while index < raw.len() as i64 {
        let position = net::i32_at(raw, index)?;
        index += 4;
        if position != -1 {
            list.push(position);
        }
    }
    Ok(list)
}

/// A value's place in MRUListEx: -1 when its name isn't a number or isn't in the list
fn mru_of(list: &[i32], name: &str) -> i32 {
    try_parse_i32(name).and_then(|n| list.iter().position(|p| *p == n)).map_or(-1, |p| p as i32)
}

/// `Encoding.Unicode.GetString(raw).Split('\0')[0]`
fn first_string(raw: &[u8]) -> String {
    let text = net::utf16(raw);
    text.split('\0').next().unwrap_or_default().to_string()
}

/// The shell items that follow each other from `index`: what is listed, and the path they make
struct ReadItems {
    details: String,
    absolute_path: String,
}

fn read_items(raw: &[u8], mut index: i64, key_name: &str, value_name: &str, out: &mut Output) -> NetResult<ReadItems> {
    let mut details = String::new();
    let length = raw.len() as i64;
    let mut items: Vec<&[u8]> = Vec::new();
    while index + 2 <= length {
        let size = i64::from(net::u16_at(raw, index)?);
        if size == 0 {
            break;
        }
        if size < 3 || index + size > length {
            let message = format!("Key: {key_name}, Value name: {value_name}, Message: shell item at offset 0x{index:X} has size {size}, past the end of the value ({length} bytes)");
            details.push_str(&message);
            details.push('\n');
            out.errors.push(message);
            break;
        }
        items.push(&raw[index as usize..(index + size) as usize]);
        index += size;
    }
    let mut parts: Vec<String> = Vec::new();
    for bytes in items {
        let item = match create_item(bytes) {
            Ok(item) => item,
            Err(e) => {
                let message = format!("Key: {key_name}, Value name: {value_name}, Message: shell item 0x{:02x} could not be parsed: {e}", bytes[2]);
                details.push_str(&message);
                details.push('\n');
                out.errors.push(message);
                continue;
            }
        };
        if item.class == "ShellBagUnknown" {
            let message = format!("Key: {key_name}, Value name: {value_name}, Message: **** Unsupported ShellID: 0x{:02x}. Send this ID to saericzimmerman@gmail.com so support can be added!! ****", bytes[2]);
            details.push_str(&message);
            details.push('\n');
            out.errors.push(message);
            continue;
        }
        details.push_str(&item.to_text());
        details.push('\n');
        parts.push(item.value);
    }
    Ok(ReadItems { details, absolute_path: parts.join("\\") })
}

fn sorted_rows(mut list: Vec<(i32, ValuesOut)>, out: &mut Output) {
    list.sort_by_key(|(mru, _)| *mru);
    out.rows.extend(list.into_iter().map(|(_, r)| r));
}

pub fn last_visited_pidl_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let key_name = hive.key_name(key).to_string();
    let mut list: Vec<(i32, ValuesOut)> = Vec::new();
    let mut read = |out: &mut Output| -> NetResult<()> {
        let order = match value(hive, key, "MRUListEx")? {
            Some(v) => mru_list(&hive.value_raw(v)?)?,
            None => vec![],
        };
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUListEx" {
                continue;
            }
            let mru = mru_of(&order, &name);
            let one = |out: &mut Output| -> NetResult<ValuesOut> {
                let raw = hive.value_raw(v)?;
                let executable = first_string(&raw);
                let items = read_items(&raw, utf16_len(&executable) as i64 * 2 + 2, &key_name, &name, out)?;
                let opened_on: Option<Timestamp> = if mru == 0 { Some(last_write(hive, key)?) } else { None };
                Ok(row(
                    vec![
                        ("ValueName", name.as_str().into()),
                        ("MruPosition", mru.into()),
                        ("Executable", executable.as_str().into()),
                        ("AbsolutePath", items.absolute_path.as_str().into()),
                        ("OpenedOn", opened_on.into()),
                        ("Details", items.details.as_str().into()),
                    ],
                    Some(path(hive, key)),
                    Some(name.clone()),
                    format!("Exe: {executable} Folder: {executable} Absolute path: {}", items.absolute_path),
                    Some(format!("Opened: {}", time(opened_on))),
                    Some(format!("MRU: {mru} Details: {}", items.details)),
                ))
            };
            match one(out) {
                Ok(r) => list.push((mru, r)),
                Err(e) => out.errors.push(format!("Key: {key_name}, Value name: {name}, message: {e}")),
            }
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        // (the original's text, though this is the other plugin)
        out.errors.push(format!("Error processing OpenSavePidlMRU subkey {key_name}: {e}"));
    }
    sorted_rows(list, out);
    Ok(())
}

pub fn open_save_pidl_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list: Vec<(i32, ValuesOut)> = Vec::new();
    let mut current_key = String::new();
    let mut read = |out: &mut Output, current_key: &mut String| -> NetResult<()> {
        for &sub in subkeys(hive, key) {
            let key_name = hive.key_name(sub).to_string();
            current_key.clone_from(&key_name);
            let order = match value(hive, sub, "MRUListEx")? {
                Some(v) => mru_list(&hive.value_raw(v)?)?,
                None => vec![],
            };
            for &v in values(hive, sub) {
                let name = hive.vks[v].name()?.to_string();
                if name == "MRUListEx" {
                    continue;
                }
                let mru = mru_of(&order, &name);
                let opened_on: Option<Timestamp> = if mru == 0 { Some(last_write(hive, sub)?) } else { None };
                let one = |out: &mut Output| -> NetResult<ValuesOut> {
                    let raw = hive.value_raw(v)?;
                    let items = read_items(&raw, 0, &key_name, &name, out)?;
                    Ok(row(
                        vec![
                            ("Extension", key_name.as_str().into()),
                            ("ValueName", name.as_str().into()),
                            ("MruPosition", mru.into()),
                            ("AbsolutePath", items.absolute_path.as_str().into()),
                            ("OpenedOn", opened_on.into()),
                            ("Details", items.details.as_str().into()),
                        ],
                        Some(path(hive, sub)),
                        Some(name.clone()),
                        format!("Extension: {key_name} Absolute path: {}", items.absolute_path),
                        Some(format!("Opened: {}", time(opened_on))),
                        Some(format!("MRU: {mru} Details: {}", items.details)),
                    ))
                };
                match one(out) {
                    Ok(r) => list.push((mru, r)),
                    Err(e) => out.errors.push(format!("Key: {key_name}, Value name: {name}, message: {e}")),
                }
            }
        }
        Ok(())
    };
    if let Err(e) = read(out, &mut current_key) {
        out.errors.push(format!("Error processing OpenSavePidlMRU subkey {current_key}: {e}"));
    }
    sorted_rows(list, out);
    Ok(())
}

/// BinaryReader over a value
struct Reader<'a> {
    raw: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.position)
    }

    fn peek_i32(&self) -> NetResult<i32> {
        if self.remaining() < 4 {
            return Err(END_OF_STREAM.to_string());
        }
        net::i32_at(self.raw, self.position as i64)
    }

    /// ReadBytes: what is left, when that is less
    fn bytes(&mut self, count: i64) -> NetResult<&'a [u8]> {
        if count < 0 {
            return Err(format!("count ('{count}') must be a non-negative value. (Parameter 'count')\nActual value was {count}."));
        }
        if count > 0x7FFF_FFC7 {
            return Err("Array dimensions exceeded supported range.".to_string());
        }
        let start = self.position.min(self.raw.len());
        let end = start + (count as usize).min(self.raw.len() - start);
        self.position = end;
        Ok(&self.raw[start..end])
    }
}

fn taskband_items(raw: &[u8]) -> NetResult<Vec<&[u8]>> {
    let mut reader = Reader { raw, position: 0 };
    if raw.is_empty() {
        return Err(END_OF_STREAM.to_string());
    }
    reader.position = 1;
    let mut chunks = Vec::new();
    while reader.position < raw.len() {
        let size = reader.peek_i32()?;
        chunks.push(reader.bytes(i64::from(size))?);
        reader.bytes(5)?;
    }
    let mut items = Vec::new();
    for chunk in chunks {
        let mut reader = Reader { raw: chunk, position: 0 };
        reader.peek_i32()?;
        reader.position = 4;
        while reader.remaining() >= 2 {
            let size = net::u16_at(chunk, reader.position as i64)?;
            if size < 3 {
                break;
            }
            items.push(reader.bytes(i64::from(size))?);
        }
    }
    Ok(items)
}

fn taskband_row(hive: &Hive, key: KeyId, value_name: &str, item: &ShellItem) -> ValuesOut {
    let mut executable = "(unknown)".to_string();
    let mut pin_type = "(unknown)".to_string();
    if let Some(text) = item.extension_blocks.iter().find_map(|b| if let BlockKind::Executable(t) = &b.kind { Some(t) } else { None }) {
        executable.clone_from(text);
    }
    if let Some(text) = item.extension_blocks.iter().find_map(|b| if let BlockKind::PinType(t) = &b.kind { Some(t) } else { None }) {
        pin_type.clone_from(text);
    }
    if item.friendly_name == "Directory" {
        executable = "(Directory)".to_string();
        pin_type = "(Directory)".to_string();
    }
    let lnk_name = (!item.value_is_null).then(|| item.value.clone());
    row(
        vec![("LnkName", lnk_name.into()), ("Executable", executable.as_str().into()), ("PinType", pin_type.as_str().into())],
        Some(path(hive, key)),
        Some(value_name.to_string()),
        format!("Lnk Name: {}", if item.value_is_null { "" } else { &item.value }),
        Some(format!("Executable: {executable}")),
        Some(format!("Pin Type: {pin_type}")),
    )
}

pub fn taskband(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let read = |out: &mut Output| -> NetResult<Vec<ValuesOut>> {
        let Some(v) = value(hive, key, "Favorites")? else { return Ok(vec![]) };
        let name = hive.vks[v].name()?.to_string();
        let raw = hive.value_raw(v)?;
        let mut items = Vec::new();
        for bytes in taskband_items(&raw)? {
            match create_item(bytes) {
                Ok(item) if item.class == "ShellBagUnknown" => out.errors.push(format!(
                    "Key: {}, Value name: {name}, Message: **** Unsupported ShellID: 0x{:02x}. Send this ID to saericzimmerman@gmail.com so support can be added!! ****",
                    hive.key_name(key),
                    bytes[2]
                )),
                Ok(item) => items.push(item),
                Err(e) => out.errors.push(format!("Error processing Favorites value '': {e}")),
            }
        }
        Ok(items.iter().map(|item| taskband_row(hive, key, &name, item)).collect())
    };
    match read(out) {
        Ok(rows) => out.rows.extend(rows),
        Err(e) => out.errors.push(format!("Error processing Favorites value '': {e}")),
    }
    Ok(())
}

/// Path.GetExtension as on Windows, where `\` and `:` end a file name too
fn extension(name: &str) -> &str {
    for (i, c) in name.char_indices().rev() {
        match c {
            '.' => return if i + 1 == name.len() { "" } else { &name[i..] },
            '\\' | '/' | ':' => return "",
            _ => {}
        }
    }
    ""
}

/// The name of the document in the first shell item of a RecentDocs value: 0xbeef0004's long name, or the item's own
fn recent_doc_name(remaining: &[u8]) -> NetResult<String> {
    if remaining.is_empty() {
        return Err("Index was out of range. Must be non-negative and less than the size of the collection. (Parameter 'index')".to_string());
    }
    let length = if remaining.len() >= 2 { usize::from(net::u16_at(remaining, 0)?) } else { 0 };
    let chunk = &remaining[..length.min(remaining.len())];
    let kind = *chunk.get(2).ok_or(OUT_OF_BOUNDS)?;
    let rest = chunk.get(14..).unwrap_or_default();
    let (name, mut index) = if kind == 36 {
        let name = first_string(rest);
        let index = 14 + utf16_len(&name) as i64 * 2;
        (name, index)
    } else {
        let text = net::cp1252(rest);
        let name = text.split('\0').next().unwrap_or_default().to_string();
        let index = 14 + utf16_len(&name) as i64;
        (name, index)
    };
    let mut found = false;
    while index <= chunk.len() as i64 - 4 {
        if net::u32_at(chunk, index)? == 0xbeef0004 {
            found = true;
            break;
        }
        index += 1;
    }
    if found && index >= 4 {
        let block = blocks::from_bytes(0xbeef0004, &chunk[(index - 4) as usize..])?;
        if let BlockKind::Beef0004 { long_name, .. } = block.kind {
            return Ok(long_name);
        }
    }
    Ok(name)
}

/// When the last document the subkey for this extension lists is this one, that key's last write
fn extension_last_opened(hive: &Hive, key: KeyId, target: &str) -> NetResult<Option<Timestamp>> {
    let ext = lower(extension(target));
    let sub = if ext.is_empty() { subkey(hive, key, "Folder") } else { subkeys(hive, key).iter().copied().find(|&k| lower(hive.key_name(k)) == ext) };
    let Some(sub) = sub else { return Ok(None) };
    let mut last = String::new();
    if let Some(list) = value(hive, sub, "MRUListEx")? {
        let raw = hive.value_raw(list)?;
        if raw.len() >= 4 {
            let position = net::i32_at(&raw, 0)?;
            if let Some(v) = value(hive, sub, &position.to_string())? {
                last = first_string(&hive.value_raw(v)?);
            }
        }
    }
    if last == target { Ok(Some(last_write(hive, sub)?)) } else { Ok(None) }
}

struct RecentDoc {
    extension: String,
    mru: i32,
    row: ValuesOut,
}

fn recent_key(hive: &Hive, key: KeyId, out: &mut Output) -> Vec<RecentDoc> {
    let key_name = hive.key_name(key).to_string();
    let key_path = path(hive, key);
    let mut docs: Vec<RecentDoc> = Vec::new();
    let mut read = |out: &mut Output| -> NetResult<()> {
        // up to 0xFFFFFFFF or the end of the value; a position seen before keeps its first place
        let mut positions: Vec<(u32, i32)> = Vec::new();
        if let Some(v) = value(hive, key, "MRUListEx")? {
            let raw = hive.value_raw(v)?;
            let mut count = 0;
            for bytes in raw.chunks_exact(4) {
                let position = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if position == 0xFFFF_FFFF {
                    break;
                }
                if !positions.iter().any(|(p, _)| *p == position) {
                    positions.push((position, count));
                }
                count += 1;
            }
        }
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUListEx" || name == "ViewStream" {
                continue;
            }
            let Some(number) = try_parse_u32(&name) else { continue };
            let one = || -> NetResult<RecentDoc> {
                let mru = positions.iter().find(|(p, _)| *p == number).map_or(-1, |(_, m)| *m);
                let raw = hive.value_raw(v)?;
                let target = first_string(&raw);
                let start = utf16_len(&target) * 2 + 2;
                let lnk_name = recent_doc_name(raw.get(start..).unwrap_or_default())?;
                let opened_on: Option<Timestamp> = if mru == 0 { Some(last_write(hive, key)?) } else { None };
                let last_opened = extension_last_opened(hive, key, &target)?;
                Ok(RecentDoc {
                    extension: key_name.clone(),
                    mru,
                    row: row(
                        vec![
                            ("Extension", key_name.as_str().into()),
                            ("ValueName", name.as_str().into()),
                            ("TargetName", target.as_str().into()),
                            ("LnkName", lnk_name.as_str().into()),
                            ("MruPosition", mru.into()),
                            ("OpenedOn", opened_on.into()),
                            ("ExtensionLastOpened", last_opened.into()),
                        ],
                        Some(key_path.clone()),
                        Some(name.clone()),
                        format!("Lnk: {lnk_name} Target: {target}"),
                        Some(format!("Opened on: {} Ext last open: {}", time(opened_on), time(last_opened))),
                        Some(format!("MRU: {mru}")),
                    ),
                })
            };
            match one() {
                Ok(doc) => docs.push(doc),
                Err(e) => out.errors.push(format!("Error processing recent key ({key_path}), value {name}: {e}")),
            }
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing recent key ({key_path}): {e}"));
    }
    for &sub in subkeys(hive, key) {
        docs.extend(recent_key(hive, sub, out));
    }
    docs.sort_by(|a, b| compare_culture(&b.extension, &a.extension).then(a.mru.cmp(&b.mru)));
    docs
}

pub fn recent_docs(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let docs = recent_key(hive, key, out);
    out.rows.extend(docs.into_iter().map(|d| d.row));
    Ok(())
}
