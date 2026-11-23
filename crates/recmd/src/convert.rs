//! Batch file BinaryConvert (RECmd 2026.11, issue #117; RECmd's ValueConverter): turns a value's data into what it
//! holds. Binary and number values are read from their bytes; string values are read as text, and as a number
//! (decimal or 0x hex) for the conversions that want one. Input may be anything: a conversion that doesn't fit gives
//! None, and the data stays as it is.

use ez_common::net;
use ez_common::time::{MAX_TICKS, Timestamp};

/// Key.BinConvert, by its number in batch files
pub const BIN_CONVERTS: &[(&str, i64)] = &[
    ("None", 0),
    ("Filetime", 1),
    ("Ip", 2),
    ("Epoch", 3),
    ("Sid", 4),
    ("Systemtime", 5),
    ("DateTimeTicks", 6),
    ("OLE", 7),
    ("EpochMilliseconds", 8),
    ("Ascii", 9),
    ("Unicode", 10),
    ("ToBase64", 11),
    ("FromBase64", 12),
    ("Guid", 13),
    ("DosTimeDate", 14),
    ("DosDateTime", 15),
    ("Ipv6", 16),
    ("MacAddress", 17),
    ("Rot13", 18),
    ("WebKit", 19),
    ("MacAbsolute", 20),
    ("BigEndian", 21),
    ("ProductKey", 22),
    ("ProductKeyOld", 23),
];

const TICKS_PER_SECOND: i64 = 10_000_000;
/// 1601-01-01, 1970-01-01 and 2001-01-01 in ticks
const FILETIME_EPOCH: i64 = 504_911_232_000_000_000;
const UNIX_EPOCH: i64 = 621_355_968_000_000_000;
const MAC_EPOCH: i64 = 631_139_040_000_000_000;

type R = Result<String, ()>;

/// TryConvert: `kind` is the batch file's BinaryConvert number, `value_type` the Registry package's type name
/// (RegBinary, RegSz, RegDword...), `raw` the value's data and `text` the data as the Registry package shows it.
pub fn try_convert(kind: i64, value_type: &str, raw: &[u8], text: &str, dt: &str) -> Option<String> {
    convert(kind, value_type, raw, text, dt).ok()
}

fn is_string(value_type: &str) -> bool {
    matches!(value_type, "RegSz" | "RegExpandSz" | "RegMultiSz")
}

/// string.Trim (char.IsWhiteSpace), then TrimEnd('\0')
fn trim(s: &str) -> &str {
    s.trim_matches(char::is_whitespace).trim_end_matches('\0')
}

/// The bytes to read a number from: the value's bytes, or for a string value the number it holds, as 8 little-endian
/// bytes (0x hex as a ulong, else a long, else a double)
fn number_bytes(value_type: &str, raw: &[u8], text: &str) -> Result<Vec<u8>, ()> {
    if !is_string(value_type) {
        return Ok(raw.to_vec());
    }
    let t = trim(text);
    if t.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("0x")) {
        let h = t[2..].trim_matches(char::is_whitespace);
        if h.is_empty() || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(());
        }
        let h = h.trim_start_matches('0');
        if h.len() > 16 {
            return Err(());
        }
        return Ok(u64::from_str_radix(if h.is_empty() { "0" } else { h }, 16).map_err(|_| ())?.to_le_bytes().to_vec());
    }
    if let Some(l) = parse_long(t) {
        return Ok(l.to_le_bytes().to_vec());
    }
    parse_double(t).map(|d| d.to_le_bytes().to_vec()).ok_or(())
}

/// long.TryParse, NumberStyles.Integer, invariant culture (white space was trimmed)
fn parse_long(t: &str) -> Option<i64> {
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// double.Parse with NumberStyles.Float and the invariant culture
fn parse_double(t: &str) -> Option<f64> {
    let t = trim(t);
    let unsigned = t.strip_prefix(['+', '-']).unwrap_or(t);
    let lower = unsigned.to_ascii_lowercase();
    if lower == "infinity" || unsigned == "∞" {
        return Some(if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY });
    }
    if lower == "nan" {
        return Some(f64::NAN);
    }
    // digits, a decimal point and an exponent only (Rust also takes "inf" and others)
    if unsigned.is_empty() || !unsigned.bytes().all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-')) {
        return None;
    }
    t.parse().ok()
}

fn need(b: &[u8], count: usize) -> Result<&[u8], ()> {
    if b.len() < count { Err(()) } else { Ok(b) }
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn i64_at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// A time stamp from .NET ticks, in range
fn ticks(t: i64) -> Result<Timestamp, ()> {
    if (0..=MAX_TICKS).contains(&t) { Ok(Timestamp(t)) } else { Err(()) }
}

/// DateTimeOffset.FromFileTime
fn from_filetime(ft: i64) -> Result<Timestamp, ()> {
    if ft < 0 {
        return Err(());
    }
    ticks(ft.checked_add(FILETIME_EPOCH).ok_or(())?)
}

/// ToString(dt), failing when .NET rejects the format
fn format(t: Timestamp, dt: &str) -> R {
    Timestamp::check_format(dt).map_err(|_| ())?;
    Ok(t.format(dt))
}

/// Encoding.Unicode.GetString of the even part of the bytes
fn utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

fn convert(kind: i64, value_type: &str, raw: &[u8], text: &str, dt: &str) -> R {
    let num = || number_bytes(value_type, raw, text);
    match kind {
        // Filetime
        1 => format(from_filetime(u64::from_le_bytes(need(&num()?, 8)?[..8].try_into().unwrap()) as i64)?, dt),
        // Ip: IPAddress(uint): the first byte first
        2 => {
            let b = num()?;
            let b = need(&b, 4)?;
            Ok(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }
        // Epoch (a uint of seconds)
        3 => {
            let s = u32::from_le_bytes(need(&num()?, 4)?[..4].try_into().unwrap()) as i64;
            format(ticks(UNIX_EPOCH + s * TICKS_PER_SECOND)?, dt)
        }
        4 => sid(need(raw, 8)?),
        5 => systemtime(need(raw, 16)?, dt),
        // DateTimeTicks
        6 => format(ticks(i64_at(need(&num()?, 8)?, 0))?, dt),
        // OLE
        7 => format(from_oa_date(f64::from_le_bytes(need(&num()?, 8)?[..8].try_into().unwrap()))?, dt),
        // EpochMilliseconds
        8 => {
            let ms = i64_at(need(&num()?, 8)?, 0);
            if !(-62_135_596_800_000..=253_402_300_799_999).contains(&ms) {
                return Err(());
            }
            format(ticks(UNIX_EPOCH + ms * 10_000)?, dt)
        }
        // Ascii
        9 => Ok(net::cp1252(raw).trim_end_matches('\0').to_string()),
        // Unicode
        10 => Ok(if is_string(value_type) { text.to_string() } else { utf16(raw).trim_end_matches('\0').to_string() }),
        // ToBase64
        11 => Ok(ez_common::json::base64(raw)),
        // FromBase64
        12 => from_base64(&if is_string(value_type) { text.to_string() } else { utf16(raw) }),
        // Guid, with what it names
        13 => {
            let b: [u8; 16] = need(raw, 16)?[..16].try_into().unwrap();
            let g = net::guid(&b);
            let name = guidmapping_ez::description_or_unmapped(&g);
            Ok(if name.is_empty() || name.to_ascii_lowercase().starts_with("unmapped guid") { g } else { format!("{g} ({name})") })
        }
        // DosTimeDate, DosDateTime
        14 => format(dos(need(raw, 4)?, 2, 0)?, dt),
        15 => format(dos(need(raw, 4)?, 0, 2)?, dt),
        16 => Ok(ipv6(need(raw, 16)?[..16].try_into().unwrap())),
        // MacAddress
        17 => Ok(need(raw, 6)?[..6].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")),
        // Rot13
        18 => Ok(rot13(&if is_string(value_type) { text.to_string() } else { utf16(raw).trim_end_matches('\0').to_string() })),
        // WebKit: microseconds since 1601
        19 => {
            let us = i64_at(need(&num()?, 8)?, 0);
            format(from_filetime(us.checked_mul(10).ok_or(())?)?, dt)
        }
        // MacAbsolute: seconds since 2001, a double
        20 => {
            let seconds = if is_string(value_type) {
                parse_double(text).ok_or(())?
            } else {
                f64::from_le_bytes(need(raw, 8)?[..8].try_into().unwrap())
            };
            if !seconds.is_finite() {
                return Err(());
            }
            format(add_seconds(MAC_EPOCH, seconds)?, dt)
        }
        // BigEndian
        21 => {
            let b = if is_string(value_type) { num()? } else { raw.to_vec() };
            if !matches!(b.len(), 2 | 4 | 8) {
                return Err(());
            }
            Ok(b.iter().fold(0u64, |v, &x| (v << 8) | x as u64).to_string())
        }
        22 => Ok(product_key_win8(need(raw, 67)?)),
        23 => Ok(product_key_old(need(raw, 67)?)),
        _ => Err(()),
    }
}

/// S-R-I-S-S..., as SecurityIdentifier writes it (the authority in hex when it doesn't fit in 32 bits)
fn sid(b: &[u8]) -> R {
    let count = b[1] as usize;
    if b[0] != 1 || count > 15 || b.len() < 8 + count * 4 {
        return Err(());
    }
    let authority = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64);
    let mut s = if authority < 0x1_0000_0000 { format!("S-1-{authority}") } else { format!("S-1-0x{authority:012X}") };
    for i in 0..count {
        let o = 8 + i * 4;
        s.push_str(&format!("-{}", u32::from_le_bytes(b[o..o + 4].try_into().unwrap())));
    }
    Ok(s)
}

/// new DateTime(year, month, day, hour, minute, second, millisecond)
fn date_time(y: i32, mo: i32, d: i32, h: i32, mi: i32, s: i32, ms: i32) -> Result<Timestamp, ()> {
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&s) || !(0..1000).contains(&ms) {
        return Err(());
    }
    if !(1..=9999).contains(&y) || !(1..=12).contains(&mo) || d < 1 {
        return Err(());
    }
    Timestamp::from_parts(y, mo as u32, d as u32, h as u32, mi as u32, s as u32, ms as u32 * 10_000).ok_or(())
}

/// 128 bit SYSTEMTIME: year, month, (day of week), day, hour, minute, second, milliseconds
fn systemtime(b: &[u8], dt: &str) -> R {
    let s = |i: usize| i16::from_le_bytes([b[i], b[i + 1]]) as i32;
    format(date_time(s(0), s(2), s(6), s(8), s(10), s(12), s(14))?, dt)
}

/// An MS-DOS date and time: the date word at `date_at`, the time word at `time_at` (2 second resolution)
fn dos(b: &[u8], date_at: usize, time_at: usize) -> Result<Timestamp, ()> {
    let (date, time) = (u16_at(b, date_at) as i32, u16_at(b, time_at) as i32);
    date_time(((date >> 9) & 0x7F) + 1980, (date >> 5) & 0x0F, date & 0x1F, (time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2, 0)
}

/// DateTime.FromOADate
fn from_oa_date(d: f64) -> Result<Timestamp, ()> {
    if !(d > -657435.0 && d < 2958466.0) {
        return Err(());
    }
    const MS_PER_DAY: i64 = 86_400_000;
    let mut ms = (d * MS_PER_DAY as f64 + if d >= 0.0 { 0.5 } else { -0.5 }) as i64;
    if ms < 0 {
        ms -= (ms % MS_PER_DAY) * 2;
    }
    // 1899-12-30 in milliseconds
    ms += 59_926_435_200_000;
    if !(0..=315_537_897_599_999).contains(&ms) {
        return Err(());
    }
    Ok(Timestamp(ms * 10_000))
}

/// DateTime.AddSeconds (.NET 7 and later: the whole seconds, then the fraction in ticks, truncated)
fn add_seconds(start: i64, value: f64) -> Result<Timestamp, ()> {
    const MAX_SECONDS: f64 = (MAX_TICKS / TICKS_PER_SECOND) as f64;
    if value.abs() > MAX_SECONDS {
        return Err(());
    }
    let integral = value.trunc();
    let fraction = value - integral;
    let t = (integral as i64) * TICKS_PER_SECOND + (fraction * TICKS_PER_SECOND as f64) as i64;
    ticks(start.checked_add(t).ok_or(())?)
}

/// Base64 text decoded: as text when it is UTF-16 or printable Windows-1252, else as hex bytes
fn from_base64(s: &str) -> R {
    let bytes = base64_decode(trim(s))?;
    if bytes.len() >= 2 && bytes.len() % 2 == 0 && bytes.iter().skip(1).step_by(2).all(|&b| b == 0) {
        return Ok(utf16(&bytes).trim_end_matches('\0').to_string());
    }
    let ansi = net::cp1252(&bytes);
    let ansi = ansi.trim_end_matches('\0');
    Ok(if ansi.chars().all(|c| c as u32 >= 0x20 || matches!(c, '\r' | '\n' | '\t')) { ansi.to_string() } else { net::hex(&bytes) })
}

/// Convert.FromBase64String: white space (space, tab, CR, LF) anywhere is skipped; up to two '=' at the end
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let chars: Vec<u8> = s.bytes().filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n')).collect();
    if chars.len() % 4 != 0 || s.chars().any(|c| !c.is_ascii()) {
        return Err(());
    }
    let pad = chars.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return Err(());
    }
    let value = |c: u8| -> Result<u32, ()> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        } as u32)
    };
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for (n, quad) in chars.chunks(4).enumerate() {
        let last = n == chars.len() / 4 - 1;
        let keep = if last { 4 - pad } else { 4 };
        let mut v = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            v = (v << 6) | if i < keep { value(c)? } else { 0 };
        }
        let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
        out.extend_from_slice(&bytes[..keep - 1]);
    }
    Ok(out)
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (b'a' + (c as u8 - b'a' + 13) % 26) as char,
            'A'..='Z' => (b'A' + (c as u8 - b'A' + 13) % 26) as char,
            _ => c,
        })
        .collect()
}

/// IPAddress(byte[16]).ToString(): RFC 5952 (the longest run of zero groups as ::), with an embedded IPv4 address
/// written in dots
fn ipv6(b: [u8; 16]) -> String {
    let n: Vec<u16> = b.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    let ipv4 = (n[0] == 0 && n[1] == 0 && n[2] == 0 && n[3] == 0 && n[6] != 0 && ((n[4] == 0 && (n[5] == 0 || n[5] == 0xFFFF)) || (n[4] == 0xFFFF && n[5] == 0)))
        || (n[4] == 0 && n[5] == 0x5EFE);
    let groups = if ipv4 { 6 } else { 8 };
    // the longest run of zeros (the first of equal ones), when longer than one group
    let (mut start, mut len, mut current) = (usize::MAX, 0, 0);
    for (i, &v) in n.iter().enumerate().take(groups) {
        if v == 0 {
            current += 1;
            if current > len {
                len = current;
                start = i + 1 - current;
            }
        } else {
            current = 0;
        }
    }
    if len < 2 {
        start = usize::MAX;
    }
    let mut s = String::new();
    let mut needs_colon = false;
    let mut i = 0;
    while i < groups {
        if i == start {
            s.push_str("::");
            i += len;
            needs_colon = false;
            continue;
        }
        if needs_colon {
            s.push(':');
        }
        s.push_str(&format!("{:x}", n[i]));
        needs_colon = true;
        i += 1;
    }
    if ipv4 {
        if needs_colon {
            s.push(':');
        }
        s.push_str(&format!("{}.{}.{}.{}", b[12], b[13], b[14], b[15]));
    }
    s
}

const KEY_DIGITS: &[u8; 24] = b"BCDFGHJKMPQRTVWXY2346789";

/// DigitalProductId's product key, Windows 8 and later (as Registry Explorer's data interpreter decodes it)
fn product_key_win8(digital_product_id: &[u8]) -> String {
    let mut id = digital_product_id[..67].to_vec();
    const KEY_OFFSET: usize = 52;
    let is_win8 = (id[66] / 6) & 1;
    id[66] = (id[66] & 0xF7) | ((is_win8 & 2) * 4);
    let mut key: Vec<u8> = Vec::new();
    let mut last = 0usize;
    for _ in 0..25 {
        let mut current = 0usize;
        for j in (0..=14).rev() {
            current = current * 256 + id[j + KEY_OFFSET] as usize;
            id[j + KEY_OFFSET] = (current / 24) as u8;
            current %= 24;
            last = current;
        }
        key.insert(0, KEY_DIGITS[current]);
    }
    let key = String::from_utf8(key).unwrap();
    let mut key = format!("{}N{}", &key[1..1 + last], &key[last + 1..]);
    let mut i = 5;
    while i < key.len() {
        key.insert(i, '-');
        i += 6;
    }
    key
}

/// DigitalProductId's product key, Windows 7 and earlier (as Registry Explorer's data interpreter decodes it)
fn product_key_old(digital_product_id: &[u8]) -> String {
    let mut hex_pid = digital_product_id[52..67].to_vec();
    let mut decoded = [b'\0'; 29];
    for i in (0..29).rev() {
        if (i + 1) % 6 == 0 {
            decoded[i] = b'-';
            continue;
        }
        let mut index = 0usize;
        for j in (0..=14).rev() {
            let v = (index << 8) | hex_pid[j] as usize;
            hex_pid[j] = (v / 24) as u8;
            index = v % 24;
            decoded[i] = KEY_DIGITS[index];
        }
    }
    String::from_utf8(decoded.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_text() {
        let a = |s: [u16; 8]| {
            let mut b = [0u8; 16];
            for (i, v) in s.iter().enumerate() {
                b[i * 2..i * 2 + 2].copy_from_slice(&v.to_be_bytes());
            }
            ipv6(b)
        };
        assert_eq!(a([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]), "2001:db8::1");
        assert_eq!(a([0; 8]), "::");
        assert_eq!(a([0, 0, 0, 0, 0, 0, 0, 1]), "::1");
        assert_eq!(a([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]), "::ffff:1.2.3.4");
        assert_eq!(a([1, 0, 0, 2, 0, 0, 0, 3]), "1:0:0:2::3");
        assert_eq!(a([1, 0, 2, 3, 4, 5, 6, 7]), "1:0:2:3:4:5:6:7");
    }

    #[test]
    fn strings_as_numbers() {
        assert_eq!(try_convert(3, "RegSz", &[], " 0x10 ", "yyyy-MM-dd HH:mm:ss").unwrap(), "1970-01-01 00:00:16");
        assert_eq!(try_convert(21, "RegDword", &[0, 1], "", "").unwrap(), "1");
        assert!(try_convert(21, "RegBinary", &[0, 1, 2], "", "").is_none());
        assert_eq!(try_convert(12, "RegSz", &[], "SGk=", "").unwrap(), "Hi");
        assert_eq!(try_convert(18, "RegSz", &[], "HRZN", "").unwrap(), "UEMA");
        assert_eq!(try_convert(4, "RegBinary", &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], "", "").unwrap(), "S-1-5-18");
    }
}
