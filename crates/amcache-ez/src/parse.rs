//! The .NET parsers the original uses on registry values, with the messages of the exceptions they throw.

use ez_common::Timestamp;

/// The characters NumberStyles.Integer allows around a number
fn is_white(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ')
}

/// The sign and digits of a number in NumberStyles.Integer form
fn number(s: &str) -> Option<(bool, &str)> {
    let t = s.trim_start_matches(is_white);
    let t = t.trim_end_matches('\0').trim_end_matches(is_white);
    let (negative, digits) = match t.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some((negative, digits))
}

fn parse(s: &str, min: i128, max: i128, type_name: &str) -> Result<i128, String> {
    let too_big = || format!("Value was either too large or too small for {type_name}.");
    let Some((negative, digits)) = number(s) else {
        return Err(format!("The input string '{s}' was not in a correct format."));
    };
    let digits = digits.trim_start_matches('0');
    if digits.len() > 30 {
        return Err(too_big());
    }
    let value: i128 = if digits.is_empty() { 0 } else { digits.parse().map_err(|_| too_big())? };
    let value = if negative { -value } else { value };
    if value < min || value > max { Err(too_big()) } else { Ok(value) }
}

/// int.Parse
pub fn int(s: &str) -> Result<i32, String> {
    parse(s, i32::MIN as i128, i32::MAX as i128, "an Int32").map(|v| v as i32)
}

/// long.Parse
pub fn long(s: &str) -> Result<i64, String> {
    parse(s, i64::MIN as i128, i64::MAX as i128, "an Int64").map(|v| v as i64)
}

/// uint.Parse
pub fn uint(s: &str) -> Result<u32, String> {
    parse(s, 0, u32::MAX as i128, "a UInt32").map(|v| v as u32)
}

/// ulong.Parse
pub fn ulong(s: &str) -> Result<u64, String> {
    parse(s, 0, u64::MAX as i128, "a UInt64").map(|v| v as u64)
}

/// int.Parse with NumberStyles.HexNumber: the bits of up to 8 digits
pub fn int_hex(s: &str) -> Result<i32, String> {
    let t = s.trim_start_matches(is_white).trim_end_matches('\0').trim_end_matches(is_white);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("The input string '{s}' was not in a correct format."));
    }
    let t = t.trim_start_matches('0');
    if t.len() > 8 {
        return Err("Value was either too large or too small for an Int32.".into());
    }
    Ok(if t.is_empty() { 0 } else { u32::from_str_radix(t, 16).map(|v| v as i32).unwrap_or(0) })
}

/// long.Parse with NumberStyles.HexNumber, None when it throws (the only caller ignores the error)
pub fn long_hex(s: &str) -> Option<i64> {
    let t = s.trim_start_matches(is_white).trim_end_matches('\0').trim_end_matches(is_white);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let t = t.trim_start_matches('0');
    if t.len() > 16 {
        return None;
    }
    Some(if t.is_empty() { 0 } else { u64::from_str_radix(t, 16).ok()? as i64 })
}

/// Convert.ToInt32(s, 16)
pub fn convert_to_int32_hex(s: &str) -> Result<i32, String> {
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.starts_with('-') {
        return Err("String cannot contain a minus sign if the base is not 10.".into());
    }
    let end = digits.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(digits.len());
    if end == 0 {
        return Err("Could not find any recognizable digits.".into());
    }
    if end < digits.len() {
        return Err("Additional non-parsable characters are at the end of the string.".into());
    }
    let t = digits.trim_start_matches('0');
    if t.len() > 8 {
        return Err("Value was either too large or too small for an Int32.".into());
    }
    Ok(if t.is_empty() { 0 } else { u32::from_str_radix(t, 16).map(|v| v as i32).unwrap_or(0) })
}

const WEEKDAYS: [&str; 14] =
    ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

const MONTHS: [&str; 12] =
    ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

fn month_named(word: &str) -> Option<u32> {
    let w = word.to_ascii_lowercase();
    MONTHS.iter().position(|m| *m == w || (w.len() == 3 && m.starts_with(&w))).map(|i| i as u32 + 1)
}

/// A year as DateTime.Parse takes it: two digits are 1950 to 2049 in the invariant culture
fn year(digits: &str) -> Option<i32> {
    let n: i32 = digits.parse().ok()?;
    match digits.len() {
        1 | 2 => Some(if n <= 49 { 2000 + n } else { 1900 + n }),
        3 | 4 => Some(n),
        _ => None,
    }
}

#[derive(Default)]
struct Time {
    hour: u32,
    minute: u32,
    second: u32,
    fraction: u32,
    offset_minutes: Option<i64>,
}

/// h[:mm[:ss[.fffffff]]] with AM/PM, Z, GMT or an offset. A number on its own needs AM or PM to be a time
fn time(s: &str) -> Option<Time> {
    let mut t = Time::default();
    let mut rest = s.trim();
    let upper = rest.to_ascii_uppercase();
    let mut meridiem = None;
    if let Some(r) = upper.strip_suffix("GMT").or_else(|| upper.strip_suffix('Z')) {
        rest = rest[..r.len()].trim_end();
        t.offset_minutes = Some(0);
    } else if let Some(at) = rest.rfind(['+', '-']) {
        let sign = if rest.as_bytes()[at] == b'-' { -1 } else { 1 };
        let (h, m) = match rest[at + 1..].split_once(':') {
            Some((h, m)) => (h, m),
            None => (&rest[at + 1..], "0"),
        };
        let (h, m): (i64, i64) = (h.trim().parse().ok()?, m.trim().parse().ok()?);
        if h > 14 || m > 59 {
            return None;
        }
        t.offset_minutes = Some(sign * (h * 60 + m));
        rest = rest[..at].trim_end();
    }
    let upper = rest.to_ascii_uppercase();
    if let Some(r) = upper.strip_suffix("AM") {
        meridiem = Some(false);
        rest = rest[..r.len()].trim_end();
    } else if let Some(r) = upper.strip_suffix("PM") {
        meridiem = Some(true);
        rest = rest[..r.len()].trim_end();
    }
    let mut parts = rest.split(':');
    let hour = parts.next()?.trim();
    if hour.is_empty() || hour.len() > 2 || !hour.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.hour = hour.parse().ok()?;
    let mut any_colon = false;
    if let Some(m) = parts.next() {
        any_colon = true;
        if m.is_empty() || m.len() > 2 || !m.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        t.minute = m.parse().ok()?;
    }
    if let Some(sec) = parts.next() {
        let (sec, fraction) = match sec.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (sec, None),
        };
        if sec.is_empty() || sec.len() > 2 || !sec.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        t.second = sec.parse().ok()?;
        if let Some(f) = fraction {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            // to the nearest tick, as .NET's parser does
            let v: f64 = format!("0.{f}").parse().ok()?;
            t.fraction = (v * 10_000_000.0).round() as u32;
        }
    }
    if parts.next().is_some() || (!any_colon && meridiem.is_none()) {
        return None;
    }
    // as .NET's AdjustHour: AM takes 0 to 12, PM 0 to 23
    match meridiem {
        Some(false) if t.hour > 12 => return None,
        Some(false) if t.hour == 12 => t.hour = 0,
        Some(true) if t.hour > 23 => return None,
        Some(true) if t.hour < 12 => t.hour += 12,
        _ => {}
    }
    Some(t)
}

/// The date at the start of a value, and what follows it
fn date(s: &str) -> Option<((i32, u32, u32), &str)> {
    let bytes = s.as_bytes();
    let number_end = |from: usize| bytes[from..].iter().position(|b| !b.is_ascii_digit()).map_or(bytes.len(), |p| from + p);

    if bytes.first()?.is_ascii_alphabetic() {
        // May 19, 2025 and May 2025
        let end = bytes.iter().position(|b| !b.is_ascii_alphabetic()).unwrap_or(bytes.len());
        let month = month_named(&s[..end])?;
        let rest = s[end..].trim_start_matches([' ', '.']);
        let n1_end = rest.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(rest.len());
        if n1_end == 0 {
            return None;
        }
        let after = rest[n1_end..].trim_start();
        if n1_end >= 3 {
            return Some(((year(&rest[..n1_end])?, month, 1), after));
        }
        let day: u32 = rest[..n1_end].parse().ok()?;
        let after_comma = after.strip_prefix(',').map(str::trim_start).unwrap_or(after);
        let y_end = after_comma.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(after_comma.len());
        if y_end != 4 {
            return None;
        }
        return Some(((year(&after_comma[..4])?, month, day), after_comma[4..].trim_start()));
    }

    let e1 = number_end(0);
    if e1 == 0 {
        return None;
    }
    let first = &s[..e1];
    let sep = *bytes.get(e1)? as char;
    if sep == ' ' && bytes.get(e1 + 1).is_some_and(u8::is_ascii_digit) {
        // 1 2 2003
        let mut parts = s.splitn(3, ' ');
        let (m, d, rest) = (parts.next()?, parts.next()?, parts.next()?);
        let end = rest.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(rest.len());
        return Some(((year(&rest[..end])?, m.parse().ok()?, d.parse().ok()?), &rest[end..]));
    }
    if sep == ' ' {
        // 19 May 2025
        let rest = s[e1..].trim_start();
        let end = rest.bytes().position(|b| !b.is_ascii_alphabetic()).unwrap_or(rest.len());
        let month = month_named(&rest[..end])?;
        let after = rest[end..].trim_start_matches([' ', ',', '.']);
        let y_end = after.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(after.len());
        if y_end != 4 {
            return None;
        }
        return Some(((year(&after[..4])?, month, first.parse().ok()?), after[4..].trim_start()));
    }
    if !matches!(sep, '/' | '-' | '.') {
        return None;
    }
    let s2 = e1 + 1;
    let e2 = number_end(s2);
    if e2 == s2 {
        return None;
    }
    let second = &s[s2..e2];
    let third = (bytes.get(e2) == Some(&(sep as u8))).then(|| (e2 + 1, number_end(e2 + 1))).filter(|(a, b)| b > a);
    match third {
        Some((s3, e3)) => {
            let third = &s[s3..e3];
            let parts = if first.len() >= 3 {
                (year(first)?, second.parse().ok()?, third.parse().ok()?)
            } else {
                (year(third)?, first.parse().ok()?, second.parse().ok()?)
            };
            Some((parts, &s[e3..]))
        }
        None => {
            let parts = if first.len() >= 3 {
                (year(first)?, second.parse().ok()?, 1)
            } else if second.len() >= 3 {
                (year(second)?, first.parse().ok()?, 1)
            } else {
                (Timestamp::now().parts().year, first.parse().ok()?, second.parse().ok()?)
            };
            Some((parts, &s[e2..]))
        }
    }
}

/// DateTime.Parse(value, InvariantInfo) for the forms found in Amcache data and the usual neighbours: M/d/yyyy and
/// yyyy-M-d with `/`, `-` or `.`, month names, and a time with AM/PM or an offset. The result is UTC; where .NET would
/// use the machine's time zone (an offset in the value) this gives the instant in UTC, which doesn't depend on the
/// machine. Other forms that .NET can read (a time on its own, say) are None, which leaves the date empty.
pub fn date_time(value: &str) -> Option<Timestamp> {
    let s = value.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    // a weekday in front (Tue, 03 Jun 2025) is not checked against the date when it fits, so it is only skipped
    let s = match s.split_once(", ") {
        Some((day, rest)) if WEEKDAYS.iter().any(|w| w.eq_ignore_ascii_case(day)) => rest,
        _ => s,
    };
    let ((y, m, d), rest) = date(s)?;
    let rest = rest.trim_start();
    // T only follows a date that starts with the year
    let year_first = s.bytes().position(|b| !b.is_ascii_digit()).is_some_and(|p| p == 4);
    let rest = if year_first { rest.strip_prefix('T').unwrap_or(rest) } else { rest };
    let t = if rest.trim().is_empty() { Time::default() } else { time(rest)? };
    let stamp = Timestamp::from_parts(y, m, d, t.hour, t.minute, t.second, t.fraction)?;
    let ticks = stamp.ticks() - t.offset_minutes.unwrap_or(0) * 600_000_000;
    (0..=ez_common::time::MAX_TICKS).contains(&ticks).then_some(Timestamp(ticks))
}

/// DateTimeOffset.FromUnixTimeSeconds
pub fn from_unix_seconds(seconds: i64) -> Result<Timestamp, String> {
    if !(-62135596800..=253402300799).contains(&seconds) {
        return Err("Valid values are between -62135596800 and 253402300799, inclusive. (Parameter 'seconds')".into());
    }
    Ok(Timestamp((seconds + 62135596800) * ez_common::time::TICKS_PER_SECOND))
}

/// DateTimeOffset.FromFileTime
pub fn from_file_time(value: i64) -> Result<Timestamp, String> {
    Timestamp::from_filetime(value).ok_or_else(|| "Not a valid Win32 FileTime. (Parameter 'fileTime')".to_string())
}

/// Path.GetExtension as on Windows, where these paths come from: only `\` and `/` end the search
pub fn windows_extension(path: &str) -> &str {
    for (i, c) in path.char_indices().rev() {
        if c == '.' {
            return if i + 1 == path.len() { "" } else { &path[i..] };
        }
        if c == '\\' || c == '/' {
            break;
        }
    }
    ""
}
