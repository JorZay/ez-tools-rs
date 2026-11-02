//! Substitution and inline values as text. The formats are EvtxECmd's (maps and scripts depend on them): times as
//! `yyyy-MM-dd HH:mm:ss.fffffff` UTC, GUIDs without braces, binary as `AA-BB`, booleans as `True`/`False`, hex as
//! `0x1F`.

use std::fmt::Write;

use crate::time::Timestamp;
pub use ez_common::dotnet::{dotnet_f32, dotnet_f64};

/// MS-EVEN6 2.2.12 value types
pub mod types {
    pub const NULL: u8 = 0x00;
    pub const STRING: u8 = 0x01;
    pub const ANSI_STRING: u8 = 0x02;
    pub const INT8: u8 = 0x03;
    pub const UINT8: u8 = 0x04;
    pub const INT16: u8 = 0x05;
    pub const UINT16: u8 = 0x06;
    pub const INT32: u8 = 0x07;
    pub const UINT32: u8 = 0x08;
    pub const INT64: u8 = 0x09;
    pub const UINT64: u8 = 0x0A;
    pub const REAL32: u8 = 0x0B;
    pub const REAL64: u8 = 0x0C;
    pub const BOOL: u8 = 0x0D;
    pub const BINARY: u8 = 0x0E;
    pub const GUID: u8 = 0x0F;
    pub const SIZE_T: u8 = 0x10;
    pub const FILETIME: u8 = 0x11;
    pub const SYSTIME: u8 = 0x12;
    pub const SID: u8 = 0x13;
    pub const HEX_INT32: u8 = 0x14;
    pub const HEX_INT64: u8 = 0x15;
    pub const EVT_HANDLE: u8 = 0x20;
    pub const BINXML: u8 = 0x21;
    pub const EVT_XML: u8 = 0x23;
    /// Arrays are the element type with 0x80 set
    pub const ARRAY_FLAG: u8 = 0x80;
}

use types::*;

/// A substitution value: its type and where its bytes are in the chunk
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Value {
    pub ty: u8,
    pub offset: usize,
    pub size: usize,
}

/// A value as text. Inline (ValueText) strings are kept as they are; substituted strings have NULs trimmed and runs
/// of control characters replaced with ", ".
pub(crate) fn format(b: &[u8], v: Value, inline: bool) -> String {
    let o = v.offset;
    let n = v.size;
    let d = &b[o..o + n];

    match v.ty {
        NULL => String::new(),
        STRING => {
            let s = utf16(&d[..n & !1]);
            if inline { s } else { clean_string(s.trim_matches('\0')) }
        }
        ANSI_STRING => clean_string(ansi(d).trim_matches('\0')),
        INT8 => d.first().map(|&x| (x as i8).to_string()).unwrap_or_default(),
        UINT8 => d.first().map(|&x| x.to_string()).unwrap_or_default(),
        INT16 => fixed::<2>(d).map(|a| i16::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        UINT16 => fixed::<2>(d).map(|a| u16::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        INT32 => fixed::<4>(d).map(|a| i32::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        UINT32 => fixed::<4>(d).map(|a| u32::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        INT64 => fixed::<8>(d).map(|a| i64::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        UINT64 => fixed::<8>(d).map(|a| u64::from_le_bytes(a).to_string()).unwrap_or_else(|| hex(d)),
        REAL32 => fixed::<4>(d).map(|a| dotnet_f32(f32::from_le_bytes(a))).unwrap_or_else(|| hex(d)),
        REAL64 => fixed::<8>(d).map(|a| dotnet_f64(f64::from_le_bytes(a))).unwrap_or_else(|| hex(d)),
        BOOL => d.first().map(|&x| bool_text(x != 0).to_string()).unwrap_or_default(),
        BINARY => hex(d),
        GUID => fixed::<16>(d).map(|a| guid(&a)).unwrap_or_else(|| hex(d)),
        SIZE_T => match n {
            4 => format!("0x{:X}", u32::from_le_bytes(d.try_into().unwrap())),
            8 => format!("0x{:X}", u64::from_le_bytes(d.try_into().unwrap())),
            _ => hex(d),
        },
        FILETIME => fixed::<8>(d).map(|a| filetime(i64::from_le_bytes(a))).unwrap_or_else(|| hex(d)),
        SYSTIME => {
            if n < 16 {
                hex(d)
            } else {
                systemtime(&d[..16])
            }
        }
        SID => sid(d).0,
        HEX_INT32 => fixed::<4>(d).map(|a| format!("0x{:X}", i32::from_le_bytes(a))).unwrap_or_else(|| hex(d)),
        HEX_INT64 => fixed::<8>(d).map(|a| format!("0x{:X}", i64::from_le_bytes(a))).unwrap_or_else(|| hex(d)),
        EVT_XML | EVT_HANDLE => "UNKNOWN: Please submit to saericzimmerman@gmail.com!".to_string(),
        BINXML => "BinaryXML".to_string(),
        t if t & ARRAY_FLAG != 0 => format_array(d, t & 0x7F),
        // an unknown type: the bytes
        _ => hex(d),
    }
}

fn fixed<const N: usize>(d: &[u8]) -> Option<[u8; N]> {
    d.get(..N).map(|s| s.try_into().unwrap())
}

/// Array items, joined as EvtxECmd always has: strings with ", ", everything else with ","
fn format_array(d: &[u8], element: u8) -> String {
    fn each<const N: usize>(d: &[u8], f: impl Fn([u8; N]) -> String) -> Vec<String> {
        d.chunks_exact(N).map(|c| f(c.try_into().unwrap())).collect()
    }

    let items: Vec<String> = match element {
        STRING => {
            let s = utf16(&d[..d.len() & !1]);
            return s.split('\0').filter(|t| !t.is_empty()).collect::<Vec<_>>().join(", ");
        }
        ANSI_STRING => {
            let s = ansi(d);
            return s.split('\0').filter(|t| !t.is_empty()).collect::<Vec<_>>().join(", ");
        }
        INT8 => d.iter().map(|&x| (x as i8).to_string()).collect(),
        UINT8 => d.iter().map(|x| x.to_string()).collect(),
        INT16 => each::<2>(d, |a| i16::from_le_bytes(a).to_string()),
        UINT16 => each::<2>(d, |a| u16::from_le_bytes(a).to_string()),
        INT32 => each::<4>(d, |a| i32::from_le_bytes(a).to_string()),
        UINT32 => each::<4>(d, |a| u32::from_le_bytes(a).to_string()),
        INT64 => each::<8>(d, |a| i64::from_le_bytes(a).to_string()),
        UINT64 => each::<8>(d, |a| u64::from_le_bytes(a).to_string()),
        REAL32 => each::<4>(d, |a| dotnet_f32(f32::from_le_bytes(a))),
        // 8 bytes each (EvtxECmd used to step by 4)
        REAL64 => each::<8>(d, |a| dotnet_f64(f64::from_le_bytes(a))),
        BOOL => each::<4>(d, |a| bool_text(i32::from_le_bytes(a) != 0).to_string()),
        GUID => each::<16>(d, |a| guid(&a)),
        SIZE_T => {
            // the pointer size of the system that logged it: 8 bytes each unless that does not fit
            if d.len() % 8 == 0 {
                each::<8>(d, |a| format!("0x{:X}", u64::from_le_bytes(a)))
            } else {
                each::<4>(d, |a| format!("0x{:X}", u32::from_le_bytes(a)))
            }
        }
        FILETIME => each::<8>(d, |a| filetime(i64::from_le_bytes(a))),
        SYSTIME => d.chunks_exact(16).map(systemtime).collect(),
        SID => {
            let mut items = Vec::new();
            let mut i = 0;
            while i + 8 <= d.len() {
                let (s, used) = sid(&d[i..]);
                items.push(s);
                i += used;
            }
            items
        }
        HEX_INT32 => each::<4>(d, |a| format!("0x{:X}", i32::from_le_bytes(a))),
        HEX_INT64 => each::<8>(d, |a| format!("0x{:X}", i64::from_le_bytes(a))),
        _ => return hex(d),
    };
    items.join(",")
}

pub(crate) fn bool_text(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

/// UTF-16LE as .NET's Encoding.Unicode decodes it: an unpaired surrogate is U+FFFD
pub(crate) fn utf16(d: &[u8]) -> String {
    let units = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect()
}

/// Windows-1252, as .NET's code page 1252 decodes it (the five undefined bytes are the C1 controls)
fn ansi(d: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{02C6}',
        '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}',
        '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}',
        '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    ];
    d.iter()
        .map(|&c| if (0x80..0xA0).contains(&c) { HIGH[(c - 0x80) as usize] } else { c as char })
        .collect()
}

/// A FILETIME as UTC, or its raw value when it is not a valid time
pub(crate) fn filetime(raw: i64) -> String {
    match Timestamp::from_filetime(raw) {
        Some(t) => t.to_string(),
        None => format!("0x{raw:016X}"),
    }
}

fn systemtime(d: &[u8]) -> String {
    systemtime_value(d).map(|t| t.to_string()).unwrap_or_else(|| hex(&d[..16]))
}

/// A SYSTEMTIME (year, month, day of week, day, hours, minutes, seconds, milliseconds), or None when not valid
pub(crate) fn systemtime_value(d: &[u8]) -> Option<Timestamp> {
    let w = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as u32;
    let ms = w(14);
    if ms > 999 {
        return None;
    }
    Timestamp::from_parts(w(0) as i32, w(2), w(6), w(8), w(10), w(12), ms * 10_000)
}

/// A SID (revision, subauthority count, 48 bit big-endian authority, subauthorities), and the bytes it used
fn sid(d: &[u8]) -> (String, usize) {
    let n = d.len();
    if n < 8 {
        return (hex(d), n);
    }
    let mut count = d[1] as usize;
    if 8 + 4 * count > n {
        // fewer subauthorities than the count says: the ones that are there
        count = (n - 8) / 4;
    }
    let authority = d[2..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64);
    let mut s = format!("S-{}-{}", d[0], authority);
    for i in 0..count {
        let o = 8 + i * 4;
        write!(s, "-{}", u32::from_le_bytes(d[o..o + 4].try_into().unwrap())).unwrap();
    }
    (s, 8 + 4 * count)
}

/// A GUID as .NET's Guid.ToString() writes it (lowercase, no braces)
pub(crate) fn guid(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// Bytes as .NET's BitConverter.ToString writes them: `AA-BB-CC`
pub(crate) fn hex(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len() * 3);
    for (i, b) in d.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        write!(s, "{b:02X}").unwrap();
    }
    s
}

/// Runs of control characters (line breaks, tabs, NULs in multi-strings) become ", "
pub(crate) fn clean_string(s: &str) -> String {
    if !s.chars().any(char::is_control) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut in_run = false;
    for c in s.chars() {
        if c.is_control() {
            if !in_run {
                out.push_str(", ");
                in_run = true;
            }
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(ty: u8, bytes: &[u8]) -> String {
        format(bytes, Value { ty, offset: 0, size: bytes.len() }, false)
    }

    #[test]
    fn values() {
        assert_eq!(fmt(BINARY, &[0xAB, 0x01]), "AB-01");
        assert_eq!(fmt(BINARY, &[]), "");
        assert_eq!(fmt(HEX_INT32, &(-1i32).to_le_bytes()), "0xFFFFFFFF");
        assert_eq!(fmt(HEX_INT64, &0x1Fi64.to_le_bytes()), "0x1F");
        assert_eq!(fmt(SIZE_T, &0x10u64.to_le_bytes()), "0x10");
        assert_eq!(fmt(BOOL, &[1, 0, 0, 0]), "True");
        assert_eq!(fmt(FILETIME, &(-1i64).to_le_bytes()), "0xFFFFFFFFFFFFFFFF");
        assert_eq!(
            fmt(GUID, &[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        // S-1-5-21-1-2
        let sid_bytes = [1u8, 3, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(fmt(SID, &sid_bytes), "S-1-5-21-1-2");
        // a count larger than the data
        assert_eq!(fmt(SID, &sid_bytes[..16]), "S-1-5-21-1");
        let s: Vec<u8> = "a\r\nb\0\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(fmt(STRING, &s), "a, b");
        let multi: Vec<u8> = "one\0two\0\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(fmt(STRING | ARRAY_FLAG, &multi), "one, two");
        assert_eq!(fmt(UINT16 | ARRAY_FLAG, &[1, 0, 2, 0]), "1,2");
        assert_eq!(fmt(ANSI_STRING, &[b'a', 0x80, 0]), "a\u{20AC}");
        // SYSTEMTIME 2020-02-29 10:11:12.345
        let st = [0xE4u8, 0x07, 2, 0, 6, 0, 29, 0, 10, 0, 11, 0, 12, 0, 0x59, 0x01];
        assert_eq!(fmt(SYSTIME, &st), "2020-02-29 10:11:12.3450000");
    }
}
