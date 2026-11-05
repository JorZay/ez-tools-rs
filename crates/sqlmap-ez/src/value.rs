//! Values as the original gets them: System.Data.SQLite picks a .NET type from the column's declared type, then CsvHelper
//! and ServiceStack write it. Each rule here was checked against the reference with every declared type and stored kind.

use chrono::{Datelike, Utc};
use ez_common::Timestamp;
use ez_common::dotnet::{dotnet_f32, dotnet_f64};
use ez_common::json::service_stack_string;

use crate::db::NetError;

/// A value of a result row
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Single(f32),
    Double(f64),
    /// System.Decimal's text
    Decimal(String),
    Text(String),
    Blob(Vec<u8>),
    Guid([u8; 16]),
    Date(Timestamp),
}

/// The .NET type a declared type gives
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Not in the table, or no declared type: as stored
    AsStored,
    Text,
    Binary,
    Bool,
    SByte,
    Byte,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Single,
    Double,
    Decimal,
    Date,
    Guid,
}

fn kind_of_name(name: &str) -> Option<Kind> {
    use Kind::*;
    Some(match name.to_ascii_uppercase().as_str() {
        "BIGINT" | "COUNTER" | "IDENTITY" | "INT64" | "INTEGER" | "INTEGER64" | "LONG" => Int64,
        "BIGUINT" | "UINT64" | "ULONG" | "UNSIGNEDINTEGER" | "UNSIGNEDINTEGER64" => UInt64,
        "BINARY" | "BLOB" | "GENERAL" | "IMAGE" | "OLEOBJECT" | "RAW" | "VARBINARY" => Binary,
        "BIT" | "BOOL" | "BOOLEAN" | "LOGICAL" | "YESNO" => Bool,
        "CHAR" | "CLOB" | "LONGCHAR" | "LONGTEXT" | "LONGVARCHAR" | "MEMO" | "NCHAR" | "NOTE" | "NTEXT" | "NVARCHAR" | "STRING" | "TEXT" | "VARCHAR" | "VARCHAR2" => Text,
        "CURRENCY" | "DECIMAL" | "DECIMALTEXT" | "MONEY" | "NUMBER" | "NUMERIC" | "NUMERICTEXT" => Decimal,
        "DATE" | "DATETIME" | "SMALLDATE" | "TIME" | "TIMESTAMP" => Date,
        "DOUBLE" | "FLOAT" | "REAL" => Double,
        "GUID" | "UNIQUEIDENTIFIER" => Guid,
        "INT" | "INT32" | "INTEGER32" | "MEDIUMINT" => Int32,
        "INT8" | "INTEGER8" | "TINYSINT" => SByte,
        "INT16" | "INTEGER16" | "SMALLINT" => Int16,
        "MEDIUMUINT" | "UINT" | "UINT32" | "UNSIGNEDINTEGER32" => UInt32,
        "SINGLE" => Single,
        "SMALLUINT" | "UINT16" | "UNSIGNEDINTEGER16" => UInt16,
        "TINYINT" | "UINT8" | "UNSIGNEDINTEGER8" => Byte,
        _ => return None,
    })
}

/// SQLiteConvert.TypeNameToDbType: the whole name, then the part before a parenthesis
pub(crate) fn kind_of(declared: Option<&str>) -> Kind {
    let Some(name) = declared else { return Kind::AsStored };
    kind_of_name(name).or_else(|| name.find('(').filter(|i| *i > 0).and_then(|i| kind_of_name(name[..i].trim_end()))).unwrap_or(Kind::AsStored)
}

const DATE_FORMATS: &[&str] = &[
    "THHmmssK",
    "THHmmK",
    "HH:mm:ss.FFFFFFFK",
    "HH:mm:ssK",
    "HH:mmK",
    "yyyy-MM-dd HH:mm:ss.FFFFFFFK",
    "yyyy-MM-dd HH:mm:ssK",
    "yyyy-MM-dd HH:mmK",
    "yyyy-MM-ddTHH:mm:ss.FFFFFFFK",
    "yyyy-MM-ddTHH:mmK",
    "yyyy-MM-ddTHH:mm:ssK",
    "yyyyMMddHHmmssK",
    "yyyyMMddHHmmK",
    "yyyyMMddTHHmmssFFFFFFFK",
    "yyyy-MM-dd",
    "yyyyMMdd",
    "yy-MM-dd",
];

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;

struct Parsed {
    year: Option<i32>,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    fraction: u32,
    /// The offset in minutes
    offset: Option<i64>,
}

fn digits(s: &mut &[u8], count: usize) -> Option<u32> {
    if s.len() < count || !s[..count].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = s[..count].iter().fold(0u32, |v, d| v * 10 + u32::from(d - b'0'));
    *s = &s[count..];
    Some(value)
}

/// K: Z, an offset of one or two hour digits and two minute digits with or without a colon, or nothing
fn zone(s: &mut &[u8]) -> Option<Option<i64>> {
    match s.first() {
        Some(b'Z') => {
            *s = &s[1..];
            Some(Some(0))
        }
        Some(sign @ (b'+' | b'-')) => {
            let negative = *sign == b'-';
            *s = &s[1..];
            let hour_length = s.iter().take(2).take_while(|b| b.is_ascii_digit()).count();
            if hour_length == 0 {
                return None;
            }
            let hour = digits(s, hour_length)?;
            if s.first() == Some(&b':') {
                *s = &s[1..];
            }
            let minute = digits(s, 2)?;
            if minute > 59 || hour > 14 || (hour == 14 && minute > 0) {
                return None;
            }
            let total = i64::from(hour) * 60 + i64::from(minute);
            Some(Some(if negative { -total } else { total }))
        }
        _ => Some(None),
    }
}

fn parse_with(format: &str, text: &str) -> Option<Parsed> {
    let mut s = text.as_bytes();
    let mut f = format;
    let mut p = Parsed { year: None, month: 1, day: 1, hour: 0, minute: 0, second: 0, fraction: 0, offset: None };
    while !f.is_empty() {
        if let Some(rest) = f.strip_prefix("yyyy") {
            p.year = Some(digits(&mut s, 4)? as i32);
            f = rest;
        } else if let Some(rest) = f.strip_prefix("yy") {
            let y = digits(&mut s, 2)? as i32;
            p.year = Some(if y <= 49 { 2000 + y } else { 1900 + y });
            f = rest;
        } else if let Some(rest) = f.strip_prefix("MM") {
            p.month = digits(&mut s, 2)?;
            f = rest;
        } else if let Some(rest) = f.strip_prefix("dd") {
            p.day = digits(&mut s, 2)?;
            f = rest;
        } else if let Some(rest) = f.strip_prefix("HH") {
            p.hour = digits(&mut s, 2)?;
            f = rest;
        } else if let Some(rest) = f.strip_prefix("mm") {
            p.minute = digits(&mut s, 2)?;
            f = rest;
        } else if let Some(rest) = f.strip_prefix("ss") {
            p.second = digits(&mut s, 2)?;
            f = rest;
        } else if let Some(rest) = f.strip_prefix(".FFFFFFF") {
            // the point goes when there are no digits
            if s.first() == Some(&b'.') {
                s = &s[1..];
                p.fraction = fraction(&mut s);
            }
            f = rest;
        } else if let Some(rest) = f.strip_prefix("FFFFFFF") {
            p.fraction = fraction(&mut s);
            f = rest;
        } else if let Some(rest) = f.strip_prefix('K') {
            p.offset = zone(&mut s)?;
            f = rest;
        } else {
            let c = f.as_bytes()[0];
            if s.first() != Some(&c) {
                return None;
            }
            s = &s[1..];
            f = &f[1..];
        }
    }
    s.is_empty().then_some(p)
}

fn fraction(s: &mut &[u8]) -> u32 {
    let n = s.iter().take(7).take_while(|b| b.is_ascii_digit()).count();
    let mut value = 0u32;
    for d in &s[..n] {
        value = value * 10 + u32::from(d - b'0');
    }
    *s = &s[n..];
    value * 10u32.pow(7 - n as u32)
}

/// DateTime.ParseExact with the ISO 8601 formats and AdjustToUniversal. A time with no date is today, where the time zone is
fn parse_date(text: &str) -> Option<Timestamp> {
    DATE_FORMATS.iter().find_map(|format| {
        let p = parse_with(format, text)?;
        let (year, month, day) = match p.year {
            Some(y) => (y, p.month, p.day),
            None => {
                let today = match p.offset {
                    Some(minutes) => (Utc::now() + chrono::Duration::minutes(minutes)).date_naive(),
                    None => chrono::Local::now().date_naive(),
                };
                (today.year(), today.month(), today.day())
            }
        };
        let time = Timestamp::from_parts(year, month, day, p.hour, p.minute, p.second, p.fraction)?;
        let Some(offset) = p.offset else { return Some(time) };
        let mut ticks = time.ticks() - offset * 60 * TICKS_PER_SECOND;
        if ticks < 0 {
            ticks += TICKS_PER_DAY;
        }
        (0..=ez_common::time::MAX_TICKS).contains(&ticks).then_some(Timestamp(ticks))
    })
}

pub(crate) fn to_date(text: &str) -> Result<Value, NetError> {
    parse_date(text).map(Value::Date).ok_or_else(|| NetError::format(format!("String '{text}' was not recognized as a valid DateTime.")))
}

/// SQLiteConvert.ToBoolean
pub(crate) fn text_to_bool(text: &str) -> Result<bool, NetError> {
    let prefix_of = |word: &str| word.len() >= text.len() && word[..text.len()].eq_ignore_ascii_case(text);
    if !text.is_ascii() {
        return Err(NetError::argument("source"));
    }
    if prefix_of("True") {
        return Ok(true);
    }
    if prefix_of("False") {
        return Ok(false);
    }
    match text.to_ascii_lowercase().as_str() {
        "y" | "yes" | "on" | "1" => Ok(true),
        "n" | "no" | "off" | "0" => Ok(false),
        _ => Err(NetError::argument("source")),
    }
}

/// Convert.ToDecimal(double): 15 significant digits
pub(crate) fn to_decimal(v: f64) -> Result<Value, NetError> {
    if !v.is_finite() || v.abs() >= 7.922_816_251_426_434e28 {
        return Err(NetError::overflow("Value was either too large or too small for a Decimal."));
    }
    if v == 0.0 || v.abs() < 1e-28 {
        return Ok(Value::Decimal("0".into()));
    }
    let sci = format!("{:.14e}", v.abs());
    let exp: i32 = sci.split_once('e').unwrap().1.parse().unwrap();
    // 15 significant digits, and at most 28 decimals
    let decimals = (14 - exp).clamp(0, 28) as usize;
    let mut out = format!("{:.*}", decimals, v.abs());
    if exp > 14 {
        // digits past the 15th are zeros
        let digits: String = sci.split_once('e').unwrap().0.chars().filter(|c| *c != '.').collect();
        out = format!("{digits}{}", "0".repeat((exp - 14) as usize));
    }
    if out.contains('.') {
        out = out.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    if out == "0" || out.is_empty() {
        return Ok(Value::Decimal("0".into()));
    }
    Ok(Value::Decimal(if v < 0.0 { format!("-{out}") } else { out }))
}

fn hex_value(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn from_hex_parts(parts: &[&str]) -> Option<[u8; 16]> {
    let text: String = parts.concat();
    if text.len() != 32 || !text.is_ascii() {
        return None;
    }
    let b = text.as_bytes();
    let mut raw = [0u8; 16];
    for (i, r) in raw.iter_mut().enumerate() {
        *r = hex_value(b[i * 2])? << 4 | hex_value(b[i * 2 + 1])?;
    }
    Some([raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]])
}

/// new Guid(string): the N, D, B and P forms, with spaces around them
pub(crate) fn to_guid(text: &str) -> Result<Value, NetError> {
    let t = text.trim();
    let dashed = |s: &str| -> Option<[u8; 16]> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 || parts[0].len() != 8 || parts[1].len() != 4 || parts[2].len() != 4 || parts[3].len() != 4 || parts[4].len() != 12 {
            return None;
        }
        from_hex_parts(&parts)
    };
    let guid = if t.len() == 32 {
        from_hex_parts(&[t])
    } else if t.len() == 36 {
        dashed(t)
    } else if t.len() == 38 && ((t.starts_with('{') && t.ends_with('}')) || (t.starts_with('(') && t.ends_with(')'))) {
        dashed(&t[1..37])
    } else {
        None
    };
    guid.map(Value::Guid).ok_or_else(|| NetError::format("Unrecognized Guid format.".to_string()))
}

fn base64(d: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(d.len().div_ceil(3) * 4);
    for chunk in d.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

impl Value {
    /// As CsvHelper writes it with the invariant culture
    pub fn csv_text(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Blob(b) => {
                let mut out = String::with_capacity(2 + b.len() * 2);
                out.push_str("0x");
                for x in b {
                    use std::fmt::Write;
                    write!(out, "{x:02X}").unwrap();
                }
                out
            }
            Value::Date(t) => t.format("MM/dd/yyyy HH:mm:ss"),
            other => other.number_text(),
        }
    }

    fn number_text(&self) -> String {
        match self {
            Value::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
            Value::Int(v) => v.to_string(),
            Value::UInt(v) => v.to_string(),
            Value::Single(v) => dotnet_f32(*v),
            Value::Double(v) => dotnet_f64(*v),
            Value::Decimal(s) | Value::Text(s) => s.clone(),
            Value::Guid(g) => ez_common::net::guid(g),
            _ => String::new(),
        }
    }

    /// As ServiceStack writes it, with SQLECmd's date format
    pub fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Text(s) => service_stack_string(out, s),
            Value::Blob(b) => {
                out.push('"');
                out.push_str(&base64(b));
                out.push('"');
            }
            Value::Guid(g) => {
                out.push('"');
                out.push_str(&ez_common::net::guid(g).replace('-', ""));
                out.push('"');
            }
            Value::Date(t) => {
                out.push('"');
                out.push_str(&t.to_json_string());
                out.push('"');
            }
            // ServiceStack's own text for the largest doubles
            Value::Double(v) if v.abs() == f64::MAX => out.push_str(&dotnet_f64(*v).to_lowercase()),
            Value::Single(v) => out.push_str(&dotnet_f32(*v).to_lowercase().replace("infinity", "Infinity").replace("nan", "NaN")),
            other => out.push_str(&other.number_text()),
        }
    }

    /// object.ToString() in en-US, what a blob's file name is made from
    pub fn display_text(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Blob(_) => "System.Byte[]".to_string(),
            // .NET's en-US pattern, with the narrow space ICU has before AM and PM
            Value::Date(t) => t.format("M/d/yyyy h:mm:ss\u{202f}tt"),
            other => other.number_text(),
        }
    }

    /// Dapper's conversion of a scalar to string: Convert.ChangeType with the invariant culture
    pub(crate) fn scalar_text(&self) -> Result<Option<String>, NetError> {
        match self {
            Value::Null => Ok(None),
            Value::Blob(_) | Value::Guid(_) => Err(NetError::invalid_cast("Object must implement IConvertible.")),
            other => Ok(Some(other.csv_text())),
        }
    }
}
