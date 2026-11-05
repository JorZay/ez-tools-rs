//! ApplicationSettingsContainer: the typed values of a packaged application's settings.dat. Each value's data ends with a
//! FILETIME, after what the type says comes first.

use ez_common::net::{self, NetResult};
use registry_ez::cells::{filetime, float_text, timespan};
use registry_ez::{Hive, KeyId, VkId};

use crate::helpers::{path, row, unicode_at, values};
use crate::{Cell, Output};

const COMPOSITE_NOTE: &str = "Composite Value cannot be deciphered at the moment. This is a collection of other RegUwp keys.";
const OFFSET_NOTE: &str = "This Int64 value has been observed to represent Windows FILETIME or DateTime.Ticks.";
const OFFSETS_NOTE: &str = "These Int64 values have been observed to represent Windows FILETIME or DateTime.Ticks.";

pub fn application_settings_container(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &v in values(hive, key) {
        if let Err(e) = read_value(hive, key, v, out) {
            // the catch is around the whole list: the rest of the key isn't read
            out.errors.push(format!("Error processing ApplicationSettingsContainer: {e}"));
            break;
        }
    }
    Ok(())
}

fn single(raw: &[u8], at: i64) -> NetResult<f32> {
    Ok(f32::from_bits(net::u32_at(raw, at)?))
}

fn single_text(v: f32) -> String {
    float_text(f64::from(v), true)
}

fn double_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(float_text(f64::from_bits(net::u64_at(raw, at)?), false))
}

/// A char's ToString(): an unpaired surrogate is written as U+FFFD
fn char_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(net::utf16(&net::u16_at(raw, at)?.to_le_bytes()))
}

fn bool_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(if net::byte_at(raw, at)? != 0 { "True" } else { "False" }.to_string())
}

fn guid_text(raw: &[u8], at: i64) -> NetResult<String> {
    let bytes: [u8; 16] = net::copy(raw, at, 16)?.try_into().map_err(|_| net::TOO_SHORT.to_string())?;
    Ok(net::guid(&bytes))
}

/// `new Point((int)single, (int)single).ToString()`. `as` saturates as .NET's cast does, with NaN as 0
fn point_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(format!("{{X={},Y={}}}", single(raw, at)? as i32, single(raw, at + 4)? as i32))
}

fn size_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(format!("{{Width={}, Height={}}}", single(raw, at)? as i32, single(raw, at + 4)? as i32))
}

fn rect_text(raw: &[u8], at: i64) -> NetResult<String> {
    Ok(format!(
        "{{X={},Y={},Width={},Height={}}}",
        single(raw, at)? as i32,
        single(raw, at + 4)? as i32,
        single(raw, at + 8)? as i32,
        single(raw, at + 12)? as i32
    ))
}

/// `new T[count]` filled from `read(i)`: a negative count throws, and a count past the data stops at its first bad read
fn array(count: i32, read: impl Fn(i64) -> NetResult<String>) -> NetResult<Vec<String>> {
    if count < 0 {
        return Err(net::OVERFLOW.to_string());
    }
    (0..i64::from(count)).map(read).collect()
}

fn bracketed(items: &[String], separator: &str) -> String {
    format!("[{}]", items.join(separator))
}

fn byte_list(raw: &[u8], count: i32) -> NetResult<String> {
    if count < 0 {
        return Err(net::OVERFLOW.to_string());
    }
    let bytes = net::copy(raw, 0, i64::from(count))?;
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    Ok(bracketed(&items, ", "))
}

fn read_value(hive: &Hive, key: KeyId, v: VkId, out: &mut Output) -> NetResult<()> {
    let vk = &hive.vks[v];
    let kind = vk.data_type_raw;
    if !(257..=293).contains(&kind) {
        return Ok(());
    }
    let name = vk.name()?.to_string();
    let raw = hive.value_raw(v)?;
    let raw = raw.as_slice();
    // DataLength, with the resident bit if it has it, as an int after taking the time stamp's 8 bytes off
    let body = vk.data_length.wrapping_sub(8) as i32;
    let list = |size: i32, read: &dyn Fn(i64) -> NetResult<String>| -> NetResult<(String, i64)> {
        let count = body / size;
        let items = array(count, |i| read(i * i64::from(size)))?;
        Ok((bracketed(&items, ","), i64::from(count) * i64::from(size)))
    };

    let (type_name, (value, stamp_at), notes): (&str, (String, i64), &str) = match kind {
        257 => ("RegUwpByte", (format!("0x{:02X}", net::byte_at(raw, 0)?), 1), ""),
        258 => ("RegUwpInt16", (net::i16_at(raw, 0)?.to_string(), 2), ""),
        259 => ("RegUwpUint16", (net::u16_at(raw, 0)?.to_string(), 2), ""),
        260 => ("RegUwpInt32", (net::i32_at(raw, 0)?.to_string(), 4), ""),
        261 => ("RegUwpUint32", (net::u32_at(raw, 0)?.to_string(), 4), ""),
        262 => ("RegUwpInt64", (net::i64_at(raw, 0)?.to_string(), 8), ""),
        263 => ("RegUwpUint64", (net::u64_at(raw, 0)?.to_string(), 8), ""),
        264 => ("RegUwpSingle", (single_text(single(raw, 0)?), 4), ""),
        265 => ("RegUwpDouble", (double_text(raw, 0)?, 8), ""),
        266 => ("RegUwpChar", (char_text(raw, 0)?, 2), ""),
        267 => ("RegUwpBoolean", (bool_text(raw, 0)?, 1), ""),
        268 => {
            let mut end = 0;
            while end + 1 < raw.len() && (raw[end] != 0 || raw[end + 1] != 0) {
                end += 2;
            }
            ("RegUwpString", (net::utf16(&raw[..end]), end as i64 + 2), "")
        }
        269 => ("RegUwpCompositeValue", (byte_list(raw, body)?, i64::from(body)), COMPOSITE_NOTE),
        270 => ("RegUwpDateTimeOffset", (net::i64_at(raw, 0)?.to_string(), 8), OFFSET_NOTE),
        271 => ("RegUwpTimeSpan", (timespan(net::i64_at(raw, 0)?), 8), ""),
        272 => ("RegUwpGuid", (guid_text(raw, 0)?, 16), ""),
        273 => ("RegUwpPoint", (point_text(raw, 0)?, 8), ""),
        274 => ("RegUwpSize", (size_text(raw, 0)?, 8), ""),
        275 => ("RegUwpRect", (rect_text(raw, 0)?, 16), ""),
        276 => ("RegUwpArrayByte", (byte_list(raw, body)?, i64::from(body)), ""),
        277 => ("RegUwpArrayInt16", list(2, &|at| Ok(net::i16_at(raw, at)?.to_string()))?, ""),
        278 => ("RegUwpArrayUint16", list(2, &|at| Ok(net::u16_at(raw, at)?.to_string()))?, ""),
        279 => ("RegUwpArrayInt32", list(4, &|at| Ok(net::i32_at(raw, at)?.to_string()))?, ""),
        280 => ("RegUwpArrayUint32", list(4, &|at| Ok(net::u32_at(raw, at)?.to_string()))?, ""),
        281 => ("RegUwpArrayInt64", list(8, &|at| Ok(net::i64_at(raw, at)?.to_string()))?, ""),
        282 => ("RegUwpArrayUint64", list(8, &|at| Ok(net::u64_at(raw, at)?.to_string()))?, ""),
        283 => ("RegUwpArraySingle", list(4, &|at| Ok(single_text(single(raw, at)?)))?, ""),
        284 => ("RegUwpArrayDouble", list(8, &|at| double_text(raw, at))?, ""),
        285 => ("RegUwpArrayChar", list(2, &|at| char_text(raw, at))?, ""),
        286 => ("RegUwpArrayBoolean", list(1, &|at| bool_text(raw, at))?, ""),
        287 => {
            let mut check = 0i32;
            let mut items = Vec::new();
            while check < body {
                let length = net::i32_at(raw, i64::from(check))?;
                let start = i64::from(check.wrapping_add(4));
                items.push(unicode_at(raw, start, i64::from(length.wrapping_sub(2)))?);
                check = check.wrapping_add(length).wrapping_add(4);
            }
            ("RegUwpArrayString", (bracketed(&items, ","), i64::from(body)), "")
        }
        288 => ("RegUwpArrayDateTimeOffset", list(8, &|at| Ok(net::i64_at(raw, at)?.to_string()))?, OFFSETS_NOTE),
        289 => ("RegUwpArrayTimeSpan", list(8, &|at| Ok(timespan(net::i64_at(raw, at)?)))?, ""),
        290 => ("RegUwpArrayGuid", list(16, &|at| guid_text(raw, at))?, ""),
        291 => ("RegUwpArrayPoint", list(8, &|at| point_text(raw, at))?, ""),
        292 => ("RegUwpArraySize", list(8, &|at| size_text(raw, at))?, ""),
        _ => {
            // RegUwpArrayRect (293): 16 bytes each, but the original steps through them 8 at a time
            let count = body / 16;
            let items = array(count, |i| rect_text(raw, i * 8))?;
            ("RegUwpArrayRect", (bracketed(&items, ","), i64::from(count) * 16), "")
        }
    };

    let stamp = filetime(net::i64_at(raw, stamp_at)?)?;
    out.rows.push(row(
        vec![
            ("ValueName", name.as_str().into()),
            ("ValueType", type_name.into()),
            ("Value", value.as_str().into()),
            ("Notes", notes.into()),
            ("UTCTimestamp", Cell::Time(Some(stamp))),
        ],
        Some(path(hive, key)),
        Some(name),
        value,
        Some(type_name.to_string()),
        // DateTime.ToString() with the en-US culture
        Some(stamp.format("M/d/yyyy h:mm:ss\u{202F}tt")),
    ));
    Ok(())
}
