//! Plugins for what a user opened or searched for (NTUSER.DAT): the MRU lists and other per-user keys.

use std::collections::HashMap;
use std::sync::OnceLock;

use ez_common::Timestamp;
use ez_common::net::{self, NetResult};
use fancy_regex::Regex;
use registry_ez::cells::filetime;
use registry_ez::{Hive, KeyId};

use crate::helpers::{NO_MATCH, NULL_REFERENCE, OUT_OF_BOUNDS, byte_at, data, hex_byte, last_write, mru_of_units, offset_text, parse_i32, parse_i32_of, parse_i64, parse_u32, path, row, subkey, subkeys, text, time, try_parse_u32, unicode_at, value, values};
use crate::{Cell, Output, ValuesOut};

const REG_BINARY: u32 = 3;

fn first_part(raw: &[u8]) -> String {
    net::utf16(raw).split('\0').next().unwrap_or_default().to_string()
}

fn sorted(mut list: Vec<(i32, ValuesOut)>, out: &mut Output) {
    list.sort_by_key(|(mru, _)| *mru);
    out.rows.extend(list.into_iter().map(|(_, r)| r));
}

/// MRUListEx read until 0xFFFFFFFF, which must be there, every position only once
fn strict_positions(raw: &[u8]) -> NetResult<HashMap<u32, i32>> {
    let mut positions = HashMap::new();
    let mut index = 0;
    let mut i = 0;
    loop {
        let position = net::u32_at(raw, index)?;
        index += 4;
        if position == 0xFFFF_FFFF {
            return Ok(positions);
        }
        if positions.insert(position, i).is_some() {
            return Err(format!("An item with the same key has already been added. Key: {position}"));
        }
        i += 1;
    }
}

/// `mruPositions[uint.Parse(name)]`
fn strict_position(positions: &HashMap<u32, i32>, name: &str) -> NetResult<i32> {
    let number = parse_u32(name)?;
    positions.get(&number).copied().ok_or_else(|| format!("The given key '{number}' was not present in the dictionary."))
}

/// `Convert.ToChar(Convert.ToUInt32(chunk, 16))` of each pair of characters
fn decode_hex(hex: &str) -> NetResult<String> {
    let units: Vec<u16> = hex.encode_utf16().collect();
    let mut text = Vec::with_capacity(units.len() / 2);
    for pair in units.chunks_exact(2) {
        text.push(u16::from(hex_byte(pair)?));
    }
    Ok(String::from_utf16_lossy(&text))
}

/// A string value, REG_SZ or REG_BINARY ANSI text
fn adobe_text(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<String>> {
    let Some(v) = value(hive, key, name)? else { return Ok(None) };
    if hive.vks[v].data_type.get() == REG_BINARY {
        return Ok(Some(net::cp1252(&hive.value_raw(v)?).trim_matches('\0').to_string()));
    }
    data(hive, v).map(Some)
}

fn digits(text: &str) -> Option<u32> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

/// The zone of `zzz`: a sign, hours, and minutes
fn parse_zone(zone: &str) -> Option<i64> {
    let (sign, rest) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    // one or two digits of hours, a `:` or not, two digits of minutes
    let count = rest.bytes().take(2).take_while(u8::is_ascii_digit).count();
    let (hours, after) = rest.split_at(count);
    let minutes = after.strip_prefix(':').unwrap_or(after);
    if hours.is_empty() || minutes.len() != 2 {
        return None;
    }
    let (hours, minutes) = (i64::from(digits(hours)?), i64::from(digits(minutes)?));
    if minutes > 59 || hours * 60 + minutes > 14 * 60 {
        return None;
    }
    Some(sign * (hours * 60 + minutes))
}

/// sDate, `D:yyyyMMddHHmmss` and a time zone. None when there is none or it can't be read
fn adobe_date(input: Option<&str>) -> Option<Timestamp> {
    let input = input?;
    let units: Vec<u16> = input.encode_utf16().collect();
    if units.len() < 16 {
        return None;
    }
    let part = |a: usize, b: usize| String::from_utf16_lossy(&units[a..b]);
    let mut zone = part(16, units.len()).replace('\'', ":");
    zone.truncate(zone.trim_end_matches(':').len());
    if zone.ends_with('Z') {
        zone = "+0:00".to_string();
    }
    let number = |a: usize, b: usize, least: u32, most: u32| digits(&part(a, b)).filter(|n| (least..=most).contains(n));
    let year = number(2, 6, 1, 9999)?;
    let month = number(6, 8, 1, 12)?;
    let day = number(8, 10, 1, ez_common::time::days_in_month(year as i32, month))?;
    let (hour, minute, second) = (number(10, 12, 0, 23)?, number(12, 14, 0, 59)?, number(14, 16, 0, 59)?);
    let offset = parse_zone(&zone)?;
    let local = Timestamp::from_parts(year as i32, month, day, hour, minute, second, 0)?;
    let ticks = local.0 - offset * 600_000_000;
    (0..=Timestamp::from_parts(9999, 12, 31, 23, 59, 59, 9_999_999)?.0).contains(&ticks).then_some(Timestamp(ticks))
}

pub fn adobe(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &product in subkeys(hive, key) {
        for &version in subkeys(hive, product) {
            let Some(recent) = subkey(hive, version, "AVGeneral").and_then(|k| subkey(hive, k, "cRecentFiles")) else { continue };
            for &item in subkeys(hive, recent) {
                let one = || -> NetResult<ValuesOut> {
                    let number = |name: &str| -> NetResult<i32> {
                        match value(hive, item, name)? {
                            Some(v) => {
                                let raw = hive.value_raw(v)?;
                                if raw.len() >= 4 { net::i32_at(&raw, 0) } else { Ok(0) }
                            }
                            None => Ok(0),
                        }
                    };
                    let full_path = adobe_text(hive, item, "tDIText")?;
                    let last_opened = adobe_text(hive, item, "sDate")?;
                    let file_name = adobe_text(hive, item, "tFileName")?;
                    let file_size = number("uFileSize")?;
                    let file_source = adobe_text(hive, item, "tFileSource")?;
                    let page_count = number("uPageCount")?;
                    let opened = adobe_date(last_opened.as_deref());
                    let product_name = hive.key_name(product);
                    let version_name = hive.key_name(version);
                    Ok(row(
                        vec![
                            ("ProductName", product_name.into()),
                            ("ProductVersion", version_name.into()),
                            ("FullPath", full_path.clone().into()),
                            ("LastOpened", opened.into()),
                            ("FileName", file_name.into()),
                            ("FileSize", file_size.into()),
                            ("FileSource", file_source.into()),
                            ("PageCount", page_count.into()),
                        ],
                        Some(path(hive, recent)),
                        Some(hive.key_name(item).to_string()),
                        format!("Product: {product_name} {version_name}"),
                        Some(format!("FullPath: {}", full_path.as_deref().unwrap_or(""))),
                        Some(format!("LastOpened: {}", time(opened))),
                    ))
                };
                match one() {
                    Ok(r) => out.rows.push(r),
                    Err(e) => out.errors.push(format!("Error processing Adobe product '{}': {e}", path(hive, version))),
                }
            }
        }
    }
    Ok(())
}

const ARES_DEFAULT_AWAY: &str = "5468697320697320616E206175746F6D617469632061776179206D6573736167652067656E65726174656420627920417265732070726F6772616D2C20757365722069736E27742068657265206E6F772E";

pub fn ares(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    fn ares_row(name: String, value_text: String, key_path: String, value_name: String) -> ValuesOut {
        let data1 = format!("Name: {name}");
        let data2 = format!("Value: {value_text}");
        row(vec![("PropertyName", name.into()), ("PropertyValue", value_text.into())], Some(key_path), Some(value_name), data1, Some(data2), None)
    }
    let read = |out: &mut Output| -> NetResult<()> {
        let key_path = path(hive, key);
        let add = |out: &mut Output, name: &str, value_text: String, value_name: &str| out.rows.push(ares_row(name.to_string(), value_text, key_path.clone(), value_name.to_string()));
        if let Some(v) = value(hive, key, "Network.DHTID")? {
            add(out, "Ares Network DHTID", data(hive, v)?.replace('-', ""), "Network.DHTID");
        }
        if let Some(v) = value(hive, key, "Download.Folder")? {
            add(out, "Download folder", decode_hex(&data(hive, v)?)?, "Download.Folder");
        }
        if let Some(v) = value(hive, key, "Personal.CustomMessage")? {
            add(out, "Custom message", data(hive, v)?, "Personal.CustomMessage");
        }
        if let Some(v) = value(hive, key, "Personal.Nickname")? {
            add(out, "User nickname", decode_hex(&data(hive, v)?)?, "Personal.Nickname");
        }
        if let Some(v) = value(hive, key, "PrivateMessage.AwayMessage")? {
            let text = data(hive, v)?;
            if text != ARES_DEFAULT_AWAY {
                add(out, "Away message", decode_hex(&text)?, "PrivateMessage.AwayMessage");
            }
        }
        if let Some(v) = value(hive, key, "Stats.LstConnect")? {
            let seconds = i64::from(parse_i32(&data(hive, v)?)?);
            add(out, "Last connection time", offset_text(Timestamp(621_355_968_000_000_000 + seconds * 10_000_000)), "Stats.LstConnect");
        }
        if let Some(v) = value(hive, key, "Transfer.ServerPort")? {
            let port = parse_i32(&data(hive, v)?)?;
            if port > 0 {
                add(out, "Port number", port.to_string(), "Transfer.ServerPort");
            }
        }
        if let Some(v) = value(hive, key, "Personal.GUID")? {
            add(out, "Personal GUID", data(hive, v)?, "Personal.GUID");
        }
        if let Some(search) = subkey(hive, key, "Search.History") {
            for &sub in subkeys(hive, search) {
                if values(hive, sub).is_empty() {
                    continue;
                }
                let sub_name = hive.key_name(sub);
                let mut terms = Vec::new();
                for &v in values(hive, sub) {
                    let name = hive.vks[v].name()?.to_string();
                    match decode_hex(&name) {
                        Ok(term) => terms.push(term),
                        Err(e) => out.errors.push(format!("Key: {sub_name}, Value name: {name}, message: {e}")),
                    }
                }
                let units: Vec<u16> = sub_name.encode_utf16().collect();
                if units.len() < 4 {
                    return Err(format!("length ('{}') must be a non-negative value. (Parameter 'length')\nActual value was {}.", units.len() as i64 - 4, units.len() as i64 - 4));
                }
                let mut search_type = String::from_utf16_lossy(&units[..units.len() - 4]);
                if search_type == "gen" {
                    search_type = "all".to_string();
                }
                out.rows.push(ares_row(format!("Search history for '{search_type}'"), terms.join(", "), path(hive, sub), "All".to_string()));
            }
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing Ares search history: {e}"));
    }
    Ok(())
}

pub fn cid_size_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list = Vec::new();
    let mut read = || -> NetResult<()> {
        let mut positions: HashMap<u32, i32> = HashMap::new();
        if let Some(v) = value(hive, key, "MRUListEx")? {
            let mut i = 0;
            for bytes in hive.value_raw(v)?.chunks_exact(4) {
                let position = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if position == 0xFFFF_FFFF {
                    break;
                }
                positions.entry(position).or_insert(i);
                i += 1;
            }
        }
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUListEx" {
                continue;
            }
            let Some(number) = try_parse_u32(&name) else { continue };
            let mru = positions.get(&number).copied().unwrap_or(-1);
            let executable = first_part(&hive.value_raw(v)?);
            let opened_on = if mru == 0 { Some(last_write(hive, key)?) } else { None };
            list.push((
                mru,
                row(
                    vec![("Executable", executable.as_str().into()), ("MRUPosition", mru.into()), ("OpenedOn", opened_on.into())],
                    Some(path(hive, key)),
                    Some(name),
                    executable.clone(),
                    Some(format!("Opened: {}", time(opened_on))),
                    Some(format!("Mru: {mru}")),
                ),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing CIDSizeMRU key: {e}"));
    }
    sorted(list, out);
    Ok(())
}

pub fn file_exts(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut current = String::new();
    let mut read = |out: &mut Output| -> NetResult<()> {
        for &sub in subkeys(hive, key) {
            let name = hive.key_name(sub).to_string();
            current.clone_from(&name);
            let mut executables: Vec<String> = Vec::new();
            let mut programs: Vec<String> = Vec::new();
            let mut user_choice = "(UserChoice key not present)".to_string();
            let make = |executables: &[String], programs: &[String], user_choice: &str, batch: bool| {
                let (e, p) = (executables.join(", "), programs.join(", "));
                row(
                    vec![("Extension", name.as_str().into()), ("OpensWithExecutables", e.as_str().into()), ("OpensWithProgramIDs", p.as_str().into()), ("UserChoice", user_choice.into())],
                    batch.then(|| path(hive, key)),
                    batch.then(|| "Multiple".to_string()),
                    format!("Extension: {name}"),
                    Some(format!("Open Exes: {e} Open ProgIds: {p}")),
                    Some(format!("User choice: {user_choice}")),
                )
            };
            if subkeys(hive, sub).is_empty() {
                if let Some(v) = value(hive, sub, "Progid")? {
                    programs.push(data(hive, v)?);
                }
                out.rows.push(make(&executables, &programs, &user_choice, false));
                continue;
            }
            for &detail in subkeys(hive, sub) {
                match hive.key_name(detail) {
                    "OpenWithList" => {
                        if let Some(list) = value(hive, detail, "MRUList")? {
                            for unit in data(hive, list)?.encode_utf16() {
                                let slot = String::from_utf16_lossy(&[unit]);
                                let found = if char::from_u32(u32::from(unit)).is_some() { value(hive, detail, &slot)? } else { None };
                                match found {
                                    Some(v) => executables.push(data(hive, v)?),
                                    None => executables.push(format!("(Executable name for MRU slot '{slot}' not found!)")),
                                }
                            }
                        }
                    }
                    "OpenWithProgids" => {
                        for &v in values(hive, detail) {
                            programs.push(hive.vks[v].name()?.to_string());
                        }
                    }
                    "UserChoice" => {
                        if let Some(v) = value(hive, detail, "ProgId")? {
                            user_choice = data(hive, v)?;
                        }
                    }
                    _ => {}
                }
            }
            out.rows.push(make(&executables, &programs, &user_choice, true));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing FileExts subkey {current}: {e}"));
    }
    Ok(())
}

pub fn first_folder(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list = Vec::new();
    let mut read = || -> NetResult<()> {
        let v = value(hive, key, "MRUListEx")?.ok_or(NO_MATCH)?;
        let positions = strict_positions(&hive.value_raw(v)?)?;
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUListEx" {
                continue;
            }
            let mru = strict_position(&positions, &name)?;
            let text = net::utf16(&hive.value_raw(v)?);
            let mut chunks = text.split('\0');
            let executable = chunks.next().unwrap_or_default();
            let folder = chunks.next().unwrap_or_default();
            let opened_on = if mru == 0 { Some(last_write(hive, key)?) } else { None };
            list.push((
                mru,
                row(
                    vec![("Executable", executable.into()), ("FolderName", folder.into()), ("MRUPosition", mru.into()), ("OpenedOn", opened_on.into())],
                    Some(path(hive, key)),
                    Some(name),
                    format!("Exe: {executable} Folder: {folder}"),
                    Some(format!("Opened: {}", time(opened_on))),
                    Some(format!("Mru: {mru}")),
                ),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing FirstFolder key: {e}"));
    }
    sorted(list, out);
    Ok(())
}

pub fn icon_layouts(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let Some(v) = value(hive, key, "IconLayouts")? else { return Ok(()) };
    let raw = hive.value_raw(v)?;
    let length = raw.len() as i64;
    let read_i16 = |at: i64| -> Option<i16> {
        (at + 2 <= length).then(|| i16::from_le_bytes([raw[at as usize], raw[at as usize + 1]]))
    };
    let Some(count) = read_i16(0x18) else {
        out.errors.push("The IconLayouts value is truncated".to_string());
        return Ok(());
    };
    let mut position = 0x18 + 2 + 6;
    for i in 0..i32::from(count) {
        let Some(size) = read_i16(position) else {
            out.errors.push("The IconLayouts value is truncated".to_string());
            break;
        };
        position += 2 + 6;
        let size = i64::from(size);
        if size < 0 || position + size * 2 > length {
            out.errors.push(format!("Entry {i}: name length {size} is past the end of the value"));
            break;
        }
        let name = net::utf16(&raw[position as usize..(position + size * 2) as usize]);
        position += size * 2;
        out.rows.push(row(vec![("Name", name.as_str().into())], Some(path(hive, key)), Some("Multiple".to_string()), format!("Name: {name}"), Some(String::new()), Some(String::new())));
    }
    Ok(())
}

pub fn last_visited_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list = Vec::new();
    let mut read = || -> NetResult<()> {
        let order: Vec<u16> = match value(hive, key, "MRUList")? {
            Some(v) => data(hive, v)?.encode_utf16().collect(),
            None => vec![],
        };
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUList" {
                continue;
            }
            let text = net::utf16(&hive.value_raw(v)?);
            let mru = mru_of_units(&order, &name);
            let opened_on = if mru == 0 { Some(last_write(hive, key)?) } else { None };
            let mut segments = text.split('\0');
            let executable = segments.next().unwrap_or_default();
            let directory = segments.next().ok_or(OUT_OF_BOUNDS)?;
            list.push((
                mru,
                row(
                    vec![("ValueName", name.as_str().into()), ("MruPosition", mru.into()), ("Executable", executable.into()), ("Directory", directory.into()), ("OpenedOn", opened_on.into())],
                    Some(path(hive, key)),
                    Some(name),
                    format!("Exe: {executable} Folder: {executable} Directory: {directory}"),
                    Some(format!("Opened: {}", time(opened_on))),
                    Some(format!("MRU: {mru}")),
                ),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing LastVisitedMRU subkey {}: {e}", hive.key_name(key)));
    }
    sorted(list, out);
    Ok(())
}

/// long.TryParse(text, NumberStyles.HexNumber)
fn try_parse_hex_i64(text: &str) -> Option<i64> {
    let white = |c: char| matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ');
    let t = text.trim_start_matches(white).trim_end_matches('\0').trim_end_matches(white);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(t, 16).ok().map(|v| v as i64)
}

pub fn office_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let office_row = |name: &str, opened: Option<Timestamp>, closed: Option<Timestamp>, file: &str| {
        row(
            vec![("ValueName", name.into()), ("LastOpened", opened.into()), ("LastClosed", closed.into()), ("FileName", file.into())],
            Some(path(hive, key)),
            Some(name.to_string()),
            format!("File name: {file}"),
            Some(format!("Last opened: {}", time(opened))),
            Some(format!("Last closed: {}", time(closed))),
        )
    };
    let read = |out: &mut Output| -> NetResult<()> {
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            let text = data(hive, v)?;
            if name.starts_with("FOLDER") {
                out.rows.push(office_row(&name, None, None, &text));
                continue;
            }
            if name == "Max Display" || name.starts_with("Item Metadata") {
                continue;
            }
            let segments: Vec<&str> = text.split('*').collect();
            let file = segments[segments.len() - 1];
            let raw_time = segments[0].split('[').find(|t| t.starts_with('T') && t.ends_with(']'));
            let parsed = raw_time.and_then(|t| try_parse_hex_i64(&t[1..t.len() - 1]));
            let (true, Some(file_time)) = (segments.len() >= 2, parsed) else {
                out.errors.push(format!("Value '{name}' is not an MRU entry: {text}"));
                continue;
            };
            let first_open = filetime(file_time)?;
            let parent = |k: Option<KeyId>| k.and_then(|k| hive.keys[k].parent);
            let reading = parent(parent(parent(Some(key)))).and_then(|k| subkey(hive, k, "Reading Locations"));
            let mut last_open = None;
            if let Some(reading) = reading {
                for &sub in subkeys(hive, reading) {
                    if let Some(v) = value(hive, sub, "File Path")? {
                        if data(hive, v)? == file {
                            last_open = Some(last_write(hive, sub)?);
                            break;
                        }
                    }
                }
            }
            out.rows.push(office_row(&name, Some(first_open), last_open, file));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing MRU key: {e}"));
    }
    Ok(())
}

pub fn open_save_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list = Vec::new();
    let mut current = String::new();
    let one_key = |k: KeyId, extension: &str, list: &mut Vec<(i32, ValuesOut)>| -> NetResult<()> {
        let order: Vec<u16> = match value(hive, k, "MRUList")? {
            Some(v) => data(hive, v)?.encode_utf16().collect(),
            None => vec![],
        };
        for &v in values(hive, k) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUList" {
                continue;
            }
            let mru = mru_of_units(&order, &name);
            let opened_on = if mru == 0 { Some(last_write(hive, k)?) } else { None };
            let file = data(hive, v)?;
            list.push((
                mru,
                row(
                    vec![("Extension", extension.into()), ("ValueName", name.as_str().into()), ("MruPosition", mru.into()), ("Filename", file.as_str().into()), ("OpenedOn", opened_on.into())],
                    Some(path(hive, k)),
                    Some(name),
                    format!("File name: {file}"),
                    Some(format!("Opened: {}", time(opened_on))),
                    Some(format!("MRU: {mru}")),
                ),
            ));
        }
        Ok(())
    };
    let mut read = || -> NetResult<()> {
        one_key(key, "OpenSaveMRU", &mut list)?;
        for &sub in subkeys(hive, key) {
            current = hive.key_name(sub).to_string();
            one_key(sub, hive.key_name(sub), &mut list)?;
        }
        Ok(())
    };
    let result = read();
    if let Err(e) = result {
        out.errors.push(format!("Error processing OpenSaveMRU subkey {current}: {e}"));
    }
    sorted(list, out);
    Ok(())
}

pub fn recent_apps(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let read = |out: &mut Output| -> NetResult<()> {
        for &sub in subkeys(hive, key) {
            let app_id = text(hive, sub, "AppId")?;
            let app_path = text(hive, sub, "AppPath")?;
            let access = text(hive, sub, "LastAccessedTime")?;
            let count = text(hive, sub, "LaunchCount")?;
            let accessed = filetime(parse_i64(access.as_deref())?)?;
            let launches = parse_i32_of(count.as_deref())?;
            let mut docs: Vec<String> = Vec::new();
            let mut items: Vec<String> = Vec::new();
            if let Some(recent) = subkey(hive, sub, "RecentItems") {
                for &item in subkeys(hive, recent) {
                    let display = text(hive, item, "DisplayName")?;
                    let access = text(hive, item, "LastAccessedTime")?;
                    let item_path = text(hive, item, "Path")?;
                    let item_time = filetime(parse_i64(access.as_deref())?)?;
                    docs.push(format!("{}/{}: {}", display.as_deref().unwrap_or(""), item_path.as_deref().unwrap_or(""), offset_text(item_time)));
                    // an object in a dictionary: ServiceStack names the type of the list's first item
                    let mut o = ez_common::json::ServiceStackObject::new();
                    if items.is_empty() {
                        o.string("__type", Some("RegistryPlugin.RecentApps.RecentItem, RegistryPlugin.RecentApps"));
                    }
                    o.string("KeyName", Some(hive.key_name(item)));
                    match &display {
                        Some(_) => o.string("DisplayName", display.as_deref()),
                        None => o.raw("DisplayName", "null"),
                    };
                    o.raw("LastAccessed", &format!("\"{}\"", item_time.to_json_string()));
                    match &item_path {
                        Some(_) => o.string("Path", item_path.as_deref()),
                        None => o.raw("Path", "null"),
                    };
                    items.push(o.finish());
                }
            }
            out.rows.push(row(
                vec![
                    ("KeyName", hive.key_name(sub).into()),
                    ("AppId", app_id.clone().into()),
                    ("AppPath", app_path.clone().into()),
                    ("LastAccessed", accessed.into()),
                    ("LaunchCount", launches.into()),
                    ("RecentDocs", docs.join(",").into()),
                    ("RecentItems", Cell::JsonOnly(format!("[{}]", items.join(",")))),
                ],
                Some(path(hive, sub)),
                Some("Multiple".to_string()),
                format!("AppId: {} App path: {}", app_id.as_deref().unwrap_or(""), app_path.as_deref().unwrap_or("")),
                Some(format!("Last Accessed: {}", time(Some(accessed)))),
                Some(format!("Launch count: {launches}")),
            ));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing RecentApps value '': {e}"));
    }
    Ok(())
}

pub fn task_flow(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let task_row = |position: i32, full: Option<&str>, exe: Option<&str>, title: Option<&str>, other: Option<&str>, batch: bool| {
        row(
            vec![
                ("Position", position.into()),
                ("FullPath", full.map(str::to_string).into()),
                ("ExeName", exe.map(str::to_string).into()),
                ("WindowTitle", title.map(str::to_string).into()),
                ("Other", other.map(str::to_string).into()),
            ],
            batch.then(|| path(hive, key)),
            batch.then(|| "Data".to_string()),
            format!("Full path: {} Exe name: {}", full.unwrap_or(""), exe.unwrap_or("")),
            Some(format!("Window title: {} Position: {position}", title.unwrap_or(""))),
            Some(format!("Other: {}", other.unwrap_or(""))),
        )
    };
    let read = |out: &mut Output| -> NetResult<()> {
        let Some(v) = value(hive, key, "Data")? else { return Ok(()) };
        let raw = hive.value_raw(v)?;
        let length = raw.len() as i64;
        let mut index = 4i64;
        let stamp = filetime(net::i64_at(&raw, index)?)?;
        out.rows.push(task_row(0, None, None, None, Some(&format!("Timestamp: {}", stamp.format("yyyy-MM-dd HH:mm:ss"))), false));
        index += 8 + 0xd;
        let mut position = 0;
        while index < length {
            position += 1;
            if index + 1 == length {
                break;
            }
            net::i16_at(&raw, index)?;
            index += 2;
            let mut size = i64::from(byte_at(&raw, index)?);
            index += 1;
            let full = unicode_at(&raw, index, size * 2)?;
            index += size * 2 + 5;
            if byte_at(&raw, index)? != 0xd2 {
                index += 1;
            }
            net::i16_at(&raw, index)?;
            index += 2;
            size = i64::from(byte_at(&raw, index)?);
            index += 1;
            let exe = unicode_at(&raw, index, size * 2)?;
            index += size * 2;
            let kind = net::i16_at(&raw, index)?;
            let mut title = String::new();
            if kind != 0x32c6 {
                index += 2;
                size = i64::from(byte_at(&raw, index)?);
                index += 1;
                if byte_at(&raw, index)? == 0x01 {
                    index += 1;
                }
                title = unicode_at(&raw, index, size * 2)?.trim().to_string();
                index += size * 2 + 0x1a;
            } else {
                index += 0x1a;
            }
            out.rows.push(task_row(position, Some(&full), Some(&exe), Some(&title), None, true));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing Taskflow Shell Activities: {e}"));
    }
    Ok(())
}

pub fn trusted_documents(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let read = |out: &mut Output| -> NetResult<()> {
        for &v in values(hive, key) {
            let text = data(hive, v)?;
            let name = hive.vks[v].name()?.to_string();
            let bin: Vec<u16> = text.replace('-', "").encode_utf16().collect();
            if bin.len() < 16 {
                return Err("Index and length must refer to a location within the string. (Parameter 'length')".to_string());
            }
            let kind = String::from_utf16_lossy(&bin[bin.len() - 8..]);
            let mut bytes = [0u8; 8];
            for (i, pair) in bin[..16].chunks_exact(2).enumerate() {
                bytes[i] = hex_byte(pair)?;
            }
            let file_time = i64::from_le_bytes(bytes);
            let stamp = filetime(file_time)?;
            let event = match kind.as_str() {
                "01000000" => "Enable Editing",
                "FFFFFF7F" => "Enable Content/Macros",
                _ => "Unknown value",
            };
            let mut up = Some(key);
            for _ in 0..6 {
                up = up.and_then(|k| hive.keys[k].parent);
            }
            let top = up.ok_or(NULL_REFERENCE)?;
            let explorer = subkey(hive, top, "Internet Explorer").ok_or(NULL_REFERENCE)?;
            let mut username = String::new();
            for _ in subkeys(hive, explorer) {
                let sites = subkey(hive, explorer, "Suggested Sites").ok_or(NULL_REFERENCE)?;
                for &site in values(hive, sites) {
                    if hive.vks[site].name()? == "LogFileFolder" {
                        let folder = data(hive, site)?;
                        username = folder.split('\\').nth(2).ok_or(OUT_OF_BOUNDS)?.to_string();
                        break;
                    }
                }
            }
            out.rows.push(row(
                vec![("EventType", event.into()), ("Timestamp", stamp.into()), ("FileName", name.as_str().into()), ("Username", username.into())],
                Some(path(hive, key)),
                Some(name.clone()),
                format!("File Name: {name}"),
                Some(format!("File Opened: {}", offset_text(stamp))),
                Some(format!("Event Type: {event}")),
            ));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing Trusted Documents key: {e}"));
    }
    Ok(())
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from(c as u8 + 13),
            'n'..='z' | 'N'..='Z' => char::from(c as u8 - 13),
            _ => c,
        })
        .collect()
}

fn guid_pattern() -> &'static Regex {
    static GUID: OnceLock<Regex> = OnceLock::new();
    GUID.get_or_init(|| Regex::new(r"(?i)\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b").expect("valid"))
}

/// TimeSpan.ToString(@"d'd, 'h'h, 'mm'm, 'ss's'") of milliseconds
fn focus_time(milliseconds: i32) -> String {
    let total = i64::from(milliseconds).abs() / 1000;
    format!("{}d, {}h, {:02}m, {:02}s", total / 86400, total / 3600 % 24, total / 60 % 60, total % 60)
}

/// `{n:N0}`
fn n0_signed(n: i32) -> String {
    let text = ez_common::dotnet::n0(u64::from(n.unsigned_abs()));
    if n < 0 { format!("-{text}") } else { text }
}

fn user_assist_key(hive: &Hive, key: KeyId, out: &mut Output) {
    for &v in values(hive, key) {
        let one = || -> NetResult<ValuesOut> {
            let name = hive.vks[v].name()?.to_string();
            let mut program = rot13(&name);
            if let Ok(Some(found)) = guid_pattern().find(&program) {
                let guid = found.as_str().to_string();
                let folder = shellitems_ez::utils::guid_name(&guid);
                program = program.replace(&guid, &folder);
            }
            let raw = hive.value_raw(v)?;
            let mut run = 0;
            let mut last_run = None;
            let mut focus_count = None;
            let mut focus = 0;
            if raw.len() >= 16 {
                run = net::i32_at(&raw, 4)?;
                last_run = Some(filetime(net::i64_at(&raw, 8)?)?);
                if raw.len() >= 68 {
                    focus_count = Some(net::i32_at(&raw, 8)?);
                    focus = net::i32_at(&raw, 12)?;
                    last_run = Some(filetime(net::i64_at(&raw, 60)?)?);
                }
            }
            let last_run = last_run.filter(|t| t.parts().year >= 1970);
            let mut r = row(
                vec![
                    ("ProgramName", program.as_str().into()),
                    ("RunCounter", run.into()),
                    ("FocusCount", focus_count.into()),
                    ("FocusTime", focus_time(focus).into()),
                    ("LastExecuted", last_run.into()),
                ],
                Some(path(hive, key)),
                Some(name),
                program.clone(),
                Some(format!("Last executed: {}", time(last_run))),
                Some(format!("Run count: {}", n0_signed(run))),
            );
            r.batch_first = true;
            Ok(r)
        };
        match one() {
            Ok(r) => out.rows.push(r),
            Err(e) => out.errors.push(format!("Value name: {}, message: {e}", hive.vks[v].name().unwrap_or(""))),
        }
    }
}

pub fn user_assist(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    if hive.key_name(key) == "UserAssist" {
        for &sub in subkeys(hive, key) {
            for &inner in subkeys(hive, sub) {
                user_assist_key(hive, inner, out);
            }
        }
    } else {
        user_assist_key(hive, key, out);
    }
    Ok(())
}

pub fn word_wheel_query(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut list: Vec<(i32, ValuesOut)> = Vec::new();
    let mut local = |k: KeyId, out: &mut Output| {
        let mut read = || -> NetResult<()> {
            let v = value(hive, k, "MRUListEx")?.ok_or(NO_MATCH)?;
            let positions = strict_positions(&hive.value_raw(v)?)?;
            for &v in values(hive, k) {
                let name = hive.vks[v].name()?.to_string();
                if name == "MRUListEx" {
                    continue;
                }
                let mru = strict_position(&positions, &name)?;
                let term = net::utf16(&hive.value_raw(v)?).trim_matches('\0').to_string();
                let stamp = if mru == 0 { Some(last_write(hive, k)?) } else { None };
                list.push((
                    mru,
                    row(
                        vec![("SearchTerm", term.as_str().into()), ("MruPosition", mru.into()), ("KeyName", hive.key_name(k).into()), ("LastWriteTimestamp", stamp.into())],
                        Some(path(hive, k)),
                        Some(name),
                        format!("Term: {term}"),
                        Some(format!("MRU: {mru}")),
                        Some(String::new()),
                    ),
                ));
            }
            Ok(())
        };
        if let Err(e) = read() {
            out.errors.push(format!("Error processing WordWheelQuery key: {e}"));
        }
    };
    local(key, out);
    for &sub in subkeys(hive, key) {
        local(sub, out);
    }
    sorted(list, out);
    Ok(())
}

