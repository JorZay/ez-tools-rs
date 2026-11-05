//! What the plugins share: the LINQ lookups they use on keys and values, and .NET's parsing and its messages.

use ez_common::Timestamp;
use ez_common::net::NetResult;
use registry_ez::{Hive, KeyId, VkId};

use crate::{Cell, Output, ValuesOut};

pub const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";
pub const NO_MATCH: &str = "Sequence contains no matching element";
pub const OUT_OF_BOUNDS: &str = "Index was outside the bounds of the array.";

/// `{x}` of a string in an interpolated string
pub fn s(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("")
}

/// `{x?.ToUniversalTime():yyyy-MM-dd HH:mm:ss.fffffff}`
pub fn time(v: Option<Timestamp>) -> String {
    v.map(|t| t.format("yyyy-MM-dd HH:mm:ss.fffffff")).unwrap_or_default()
}

pub fn subkeys(hive: &Hive, key: KeyId) -> &[KeyId] {
    &hive.keys[key].subkeys
}

pub fn values(hive: &Hive, key: KeyId) -> &[VkId] {
    &hive.keys[key].values
}

/// SubKeys.FirstOrDefault(t => t.KeyName == name)
pub fn subkey(hive: &Hive, key: KeyId, name: &str) -> Option<KeyId> {
    subkeys(hive, key).iter().copied().find(|&k| hive.key_name(k) == name)
}

/// Values.FirstOrDefault(t => t.ValueName == name)
pub fn value(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<VkId>> {
    for &v in values(hive, key) {
        if hive.vks[v].name()? == name {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// KeyValue.ValueData
pub fn data(hive: &Hive, v: VkId) -> NetResult<String> {
    Ok(hive.value_data(v)?.text())
}

/// Values.FirstOrDefault(t => t.ValueName == name)?.ValueData
pub fn text(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<String>> {
    value(hive, key, name)?.map(|v| data(hive, v)).transpose()
}

pub fn path(hive: &Hive, key: KeyId) -> String {
    hive.keys[key].path.clone()
}

/// RegistryKey.LastWriteTime
pub fn last_write(hive: &Hive, key: KeyId) -> NetResult<Timestamp> {
    hive.nk(key).last_write()
}

/// A ValuesOut, its columns in the order the class declares them
pub fn row(
    columns: Vec<(&'static str, Cell)>,
    key_path: Option<String>,
    value_name: Option<String>,
    data1: String,
    data2: Option<String>,
    data3: Option<String>,
) -> ValuesOut {
    ValuesOut {
        columns,
        batch_key_path: key_path,
        batch_value_name: value_name,
        batch_value_data1: data1,
        batch_value_data2: data2,
        batch_value_data3: data3,
        batch_first: false,
        data1_null: false,
    }
}

/// The usual ProcessKey: a row per subkey of the key, what goes wrong with one is an error with this start and the next
/// is read. No row is wanted when `f` gives None.
pub fn per_subkey(
    hive: &Hive,
    key: KeyId,
    out: &mut Output,
    error: &str,
    mut f: impl FnMut(KeyId) -> NetResult<Option<ValuesOut>>,
) {
    for &sk in subkeys(hive, key) {
        match f(sk) {
            Ok(Some(row)) => out.rows.push(row),
            Ok(None) => {}
            Err(e) => out.errors.push(format!("{error}: {e}")),
        }
    }
}

fn is_white(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ')
}

/// The digits of a number as NumberStyles.Integer reads it (white space around it, a sign, NULs at its end)
fn integer_text(s: &str) -> Option<&str> {
    let t = s.trim_start_matches(is_white).trim_end_matches('\0').trim_end_matches(is_white);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    (!digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit())).then_some(t)
}

fn format_error(s: &str) -> String {
    format!("The input string '{s}' was not in a correct format.")
}

/// int.TryParse
pub fn try_parse_i32(s: &str) -> Option<i32> {
    integer_text(s)?.parse().ok()
}

/// uint.TryParse: `-0` is a number too
pub fn try_parse_u32(s: &str) -> Option<u32> {
    let t = integer_text(s)?;
    match t.strip_prefix('-') {
        Some(digits) => digits.bytes().all(|c| c == b'0').then_some(0),
        None => t.parse().ok(),
    }
}

/// uint.Parse
pub fn parse_u32(s: &str) -> NetResult<u32> {
    try_parse_u32(s).ok_or_else(|| if integer_text(s).is_some() { "Value was either too large or too small for a UInt32.".to_string() } else { format_error(s) })
}

/// long.Parse: null throws
pub fn parse_i64(s: Option<&str>) -> NetResult<i64> {
    let s = s.ok_or("Value cannot be null. (Parameter 's')")?;
    let t = integer_text(s).ok_or_else(|| format_error(s))?;
    t.parse().map_err(|_| "Value was either too large or too small for an Int64.".to_string())
}

/// int.Parse of what can be null
pub fn parse_i32_of(s: Option<&str>) -> NetResult<i32> {
    parse_i32(s.ok_or("Value cannot be null. (Parameter 's')")?)
}

/// Each UTF-16 unit of an MRUList is one entry: the place of a value with this name
pub fn mru_of_units(order: &[u16], name: &str) -> i32 {
    let mut units = name.encode_utf16();
    match (units.next(), units.next()) {
        (Some(u), None) => order.iter().position(|o| *o == u).map_or(-1, |p| p as i32),
        _ => -1,
    }
}

/// `Encoding.Unicode.GetString(raw, index, count)`
pub fn unicode_at(raw: &[u8], index: i64, count: i64) -> NetResult<String> {
    if index < 0 || count < 0 || index > raw.len() as i64 || count > raw.len() as i64 - index {
        return Err("Index and count must refer to a location within the buffer. (Parameter 'bytes')".to_string());
    }
    Ok(ez_common::net::utf16(&raw[index as usize..(index + count) as usize]))
}

/// A byte: `raw[index]`
pub fn byte_at(raw: &[u8], index: i64) -> NetResult<u8> {
    usize::try_from(index).ok().and_then(|i| raw.get(i)).copied().ok_or_else(|| OUT_OF_BOUNDS.to_string())
}

/// DateTimeOffset.ToString() in en-US, of a UTC time
pub fn offset_text(t: Timestamp) -> String {
    let p = t.parts();
    let hour = if p.hour % 12 == 0 { 12 } else { p.hour % 12 };
    format!("{}/{}/{} {hour}:{:02}:{:02}\u{202f}{} +00:00", p.month, p.day, format_args!("{:04}", p.year), p.minute, p.second, if p.hour < 12 { "AM" } else { "PM" })
}

/// `Convert.ToByte(text, 16)` of two characters
pub fn hex_byte(text: &[u16]) -> NetResult<u8> {
    let s = String::from_utf16_lossy(text);
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(&s);
    if digits.is_empty() && !s.is_empty() {
        return Ok(0);
    }
    if digits.is_empty() || !digits.as_bytes()[0].is_ascii_hexdigit() {
        return Err("Could not find any recognizable digits.".to_string());
    }
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Additional non-parsable characters are at the end of the string.".to_string());
    }
    u8::from_str_radix(digits, 16).map_err(|e| e.to_string())
}

/// int.Parse
pub fn parse_i32(s: &str) -> NetResult<i32> {
    let t = integer_text(s).ok_or_else(|| format_error(s))?;
    t.parse().map_err(|_| "Value was either too large or too small for an Int32.".to_string())
}

/// Convert.ToInt64(string): null is 0
pub fn to_int64(s: Option<&str>) -> NetResult<i64> {
    let Some(s) = s else { return Ok(0) };
    let t = integer_text(s).ok_or_else(|| format_error(s))?;
    t.parse().map_err(|_| "Value was either too large or too small for an Int64.".to_string())
}

/// DateTime.FromFileTime(Convert.ToInt64(timestamp)).ToUniversalTime()
pub fn filetime_text(s: Option<&str>) -> NetResult<Timestamp> {
    registry_ez::cells::filetime(to_int64(s)?)
}

/// s.Length in C#
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// s.Substring(0, length) for a length within the string
pub fn utf16_prefix(s: &str, length: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(length).collect();
    String::from_utf16_lossy(&units)
}
