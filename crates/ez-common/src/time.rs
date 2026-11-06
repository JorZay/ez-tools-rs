//! Time stamps as .NET ticks (100 ns units since 0001-01-01 00:00:00 UTC): the range and precision EvtxECmd
//! has, and what its output formats are written in.

use std::fmt;

pub const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
/// 1601-01-01, where FILETIMEs start
const FILETIME_EPOCH_TICKS: i64 = 504_911_232_000_000_000;
/// 9999-12-31 23:59:59.9999999 (DateTime.MaxValue)
pub const MAX_TICKS: i64 = 3_155_378_975_999_999_999;
/// The largest FILETIME a DateTime can hold
pub const MAX_FILETIME: i64 = MAX_TICKS - FILETIME_EPOCH_TICKS;
/// Days from 0001-01-01 to 1970-01-01
const UNIX_EPOCH_DAYS: i64 = 719_162;

/// A UTC time stamp in ticks. The default (0) is 0001-01-01 00:00:00, what EvtxECmd shows for a missing time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);

/// A time stamp's calendar fields
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateParts {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 0..9_999_999 ticks within the second
    pub fraction: u32,
    /// 0 = Sunday
    pub weekday: u32,
}

impl Timestamp {
    pub const MIN: Timestamp = Timestamp(0);

    /// A FILETIME, or None when it is outside what a DateTime can hold (EvtxECmd then shows the raw value)
    pub fn from_filetime(raw: i64) -> Option<Timestamp> {
        if !(0..=MAX_FILETIME).contains(&raw) {
            return None;
        }
        Some(Timestamp(raw + FILETIME_EPOCH_TICKS))
    }

    /// The current time
    pub fn now() -> Timestamp {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        Timestamp(UNIX_EPOCH_DAYS * TICKS_PER_DAY + (d.as_nanos() / 100) as i64)
    }

    pub fn ticks(self) -> i64 {
        self.0
    }

    /// From calendar fields (UTC); None when they are not a valid date and time
    pub fn from_parts(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32, fraction: u32) -> Option<Timestamp> {
        if !(1..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || fraction >= TICKS_PER_SECOND as u32
        {
            return None;
        }
        let days = days_from_civil(year, month, day) + UNIX_EPOCH_DAYS;
        let ticks = days * TICKS_PER_DAY
            + (hour as i64 * 3600 + minute as i64 * 60 + second as i64) * TICKS_PER_SECOND
            + fraction as i64;
        Some(Timestamp(ticks))
    }

    pub fn parts(self) -> DateParts {
        let days = self.0.div_euclid(TICKS_PER_DAY);
        let rem = self.0.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days - UNIX_EPOCH_DAYS);
        let secs = rem / TICKS_PER_SECOND;
        DateParts {
            year,
            month,
            day,
            hour: (secs / 3600) as u32,
            minute: (secs / 60 % 60) as u32,
            second: (secs % 60) as u32,
            fraction: (rem % TICKS_PER_SECOND) as u32,
            // 0001-01-01 was a Monday
            weekday: ((days + 1).rem_euclid(7)) as u32,
        }
    }

    /// Formats with a .NET custom date and time format string (as EvtxECmd's --dt), e.g. `yyyy-MM-dd HH:mm:ss.fffffff`.
    /// The time is UTC, so offsets (z, zz, zzz, K) are +00:00.
    pub fn format(self, format: &str) -> String {
        let mut out = String::with_capacity(format.len() + 8);
        format_into(self, format, &mut out);
        out
    }

    /// DateTimeOffset.ToString(format) of this time at offset 0 with the en-US culture, for tools that take the format as
    /// given and fail on a bad one: an empty format and the standard ones as .NET has them on ICU (which puts U+202F before
    /// AM and PM), or .NET's error message
    pub fn format_en_us(self, format: &str) -> Result<String, &'static str> {
        const BAD_FORMAT: &str = "Input string was not in a correct format.";
        const BAD_QUOTE: &str = "Cannot find a matching quote character for the character '''.";
        let chars: Vec<char> = format.chars().collect();
        let custom = match chars.as_slice() {
            [] => "M/d/yyyy h:mm:ss tt zzz",
            [c] => match c {
                'd' => "M/d/yyyy",
                'D' => "dddd, MMMM d, yyyy",
                'f' => "dddd, MMMM d, yyyy h:mm tt",
                'F' => "dddd, MMMM d, yyyy h:mm:ss tt",
                'g' => "M/d/yyyy h:mm tt",
                'G' => "M/d/yyyy h:mm:ss tt",
                'm' | 'M' => "MMMM d",
                'o' | 'O' => "yyyy-MM-ddTHH:mm:ss.fffffffK",
                'r' | 'R' => "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
                's' => "yyyy-MM-ddTHH:mm:ss",
                't' => "h:mm tt",
                'T' => "h:mm:ss tt",
                'u' => "yyyy-MM-dd HH:mm:ssZ",
                'y' | 'Y' => "MMMM yyyy",
                _ => return Err(BAD_FORMAT),
            },
            _ => {
                let mut i = 0;
                while i < chars.len() {
                    match chars[i] {
                        'f' | 'F' => {
                            let run = chars[i..].iter().take_while(|&&c| c == chars[i]).count();
                            if run > 7 {
                                return Err(BAD_FORMAT);
                            }
                            i += run;
                        }
                        quote @ ('\'' | '"') => {
                            i += 1;
                            loop {
                                match chars.get(i) {
                                    None => return Err(BAD_QUOTE),
                                    Some('\\') if i + 1 >= chars.len() => return Err(BAD_FORMAT),
                                    Some('\\') => i += 2,
                                    Some(&c) if c == quote => break,
                                    Some(_) => i += 1,
                                }
                            }
                            i += 1;
                        }
                        '\\' if i + 1 >= chars.len() => return Err(BAD_FORMAT),
                        '\\' => i += 2,
                        '%' if chars.get(i + 1).is_none_or(|&c| c == '%') => return Err(BAD_FORMAT),
                        _ => i += 1,
                    }
                }
                format
            }
        };
        let mut out = String::with_capacity(custom.len() + 8);
        format_custom(self, custom, "AD", &mut out);
        Ok(out)
    }

    /// ISO 8601 with 7 decimals and Z, as EvtxECmd writes time stamps in JSON
    pub fn to_json_string(self) -> String {
        self.format("yyyy-MM-ddTHH:mm:ss.fffffffZ")
    }

    /// Parses a date and time the way people write them on a command line, as DateTimeOffset.TryParse with
    /// AssumeUniversal does for the common forms: `2024-01-31`, `2024-01-31 13:45`, `2024-01-31T13:45:10.1234567Z`,
    /// `2024/01/31 13:45:10 +02:00`. A time without an offset is UTC. The result is converted to UTC.
    pub fn parse(s: &str) -> Option<Timestamp> {
        let mut p = Scanner { b: s.trim().as_bytes(), i: 0 };
        let year = p.number(4, 4)? as i32;
        let sep = p.peek()?;
        if sep != b'-' && sep != b'/' && sep != b'.' {
            return None;
        }
        p.i += 1;
        let month = p.number(1, 2)?;
        if p.peek()? != sep {
            return None;
        }
        p.i += 1;
        let day = p.number(1, 2)?;

        let (mut hour, mut minute, mut second, mut fraction) = (0, 0, 0, 0u32);
        if matches!(p.peek(), Some(b'T') | Some(b't') | Some(b' ')) {
            p.i += 1;
            while p.peek() == Some(b' ') {
                p.i += 1;
            }
            hour = p.number(1, 2)?;
            if p.peek()? != b':' {
                return None;
            }
            p.i += 1;
            minute = p.number(1, 2)?;
            if p.peek() == Some(b':') {
                p.i += 1;
                second = p.number(1, 2)?;
                if p.peek() == Some(b'.') || p.peek() == Some(b',') {
                    p.i += 1;
                    let start = p.i;
                    while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                        p.i += 1;
                    }
                    let digits = &s.trim()[start..p.i];
                    if digits.is_empty() {
                        return None;
                    }
                    // rounded to ticks, as .NET does with more than 7 digits
                    let value: f64 = format!("0.{digits}").parse().ok()?;
                    fraction = (value * TICKS_PER_SECOND as f64).round() as u32;
                }
            }
        }

        while p.peek() == Some(b' ') {
            p.i += 1;
        }
        let mut offset_minutes: i64 = 0;
        match p.peek() {
            None => {}
            Some(b'Z') | Some(b'z') => p.i += 1,
            Some(c @ (b'+' | b'-')) => {
                p.i += 1;
                let h = p.number(1, 2)? as i64;
                let mut m = 0;
                if p.peek() == Some(b':') {
                    p.i += 1;
                    m = p.number(2, 2)? as i64;
                } else if p.peek().is_some_and(|c| c.is_ascii_digit()) {
                    m = p.number(2, 2)? as i64;
                }
                if h > 14 || m > 59 {
                    return None;
                }
                offset_minutes = (h * 60 + m) * if c == b'-' { -1 } else { 1 };
            }
            Some(_) => return None,
        }
        if p.i != p.b.len() {
            return None;
        }

        let mut extra_second = 0;
        if fraction >= TICKS_PER_SECOND as u32 {
            fraction -= TICKS_PER_SECOND as u32;
            extra_second = TICKS_PER_SECOND;
        }
        let local = Timestamp::from_parts(year, month, day, hour, minute, second, fraction)?;
        let utc = local.0 + extra_second - offset_minutes * 60 * TICKS_PER_SECOND;
        if !(0..=MAX_TICKS).contains(&utc) {
            return None;
        }
        Some(Timestamp(utc))
    }
}

impl fmt::Display for Timestamp {
    /// `yyyy-MM-dd HH:mm:ss.fffffff`, EvtxECmd's default
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.parts();
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:07}",
            p.year, p.month, p.day, p.hour, p.minute, p.second, p.fraction
        )
    }
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn number(&mut self, min: usize, max: usize) -> Option<u32> {
        let start = self.i;
        let mut v: u32 = 0;
        while self.i - start < max {
            match self.peek() {
                Some(c) if c.is_ascii_digit() => {
                    v = v * 10 + (c - b'0') as u32;
                    self.i += 1;
                }
                _ => break,
            }
        }
        if self.i - start < min { None } else { Some(v) }
    }
}

pub fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

pub fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm)
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

const DAY_NAMES: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTH_NAMES: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
    "December",
];

/// .NET custom date and time format specifiers (invariant culture)
fn format_into(t: Timestamp, format: &str, out: &mut String) {
    let chars: Vec<char> = format.chars().collect();

    // a format of one character is a standard format in .NET; the common ones
    if chars.len() == 1 {
        let standard = match chars[0] {
            'o' | 'O' => Some("yyyy-MM-ddTHH:mm:ss.fffffffK"),
            's' => Some("yyyy-MM-ddTHH:mm:ss"),
            'u' => Some("yyyy-MM-dd HH:mm:ssZ"),
            'd' => Some("MM/dd/yyyy"),
            'D' => Some("dddd, dd MMMM yyyy"),
            'g' => Some("MM/dd/yyyy HH:mm"),
            'G' => Some("MM/dd/yyyy HH:mm:ss"),
            't' => Some("HH:mm"),
            'T' => Some("HH:mm:ss"),
            _ => None,
        };
        if let Some(s) = standard {
            format_into(t, s, out);
            return;
        }
    }
    format_custom(t, format, "A.D.", out);
}

/// A format of several characters. `era` is what `g` writes, which depends on the culture
fn format_custom(t: Timestamp, format: &str, era: &str, out: &mut String) {
    use std::fmt::Write;
    let p = t.parts();
    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;
    // %x is x alone, whatever follows it
    let mut alone = false;

    while i < chars.len() {
        let c = chars[i];
        let mut run = 1;
        while !alone && i + run < chars.len() && chars[i + run] == c {
            run += 1;
        }
        alone = false;
        match c {
            'y' => {
                let y = p.year;
                match run {
                    1 => write!(out, "{}", y % 100).unwrap(),
                    2 => write!(out, "{:02}", y % 100).unwrap(),
                    n => write!(out, "{:0width$}", y, width = n).unwrap(),
                }
            }
            'M' => match run {
                1 => write!(out, "{}", p.month).unwrap(),
                2 => write!(out, "{:02}", p.month).unwrap(),
                3 => out.push_str(&MONTH_NAMES[p.month as usize - 1][..3]),
                _ => out.push_str(MONTH_NAMES[p.month as usize - 1]),
            },
            'd' => match run {
                1 => write!(out, "{}", p.day).unwrap(),
                2 => write!(out, "{:02}", p.day).unwrap(),
                3 => out.push_str(&DAY_NAMES[p.weekday as usize][..3]),
                _ => out.push_str(DAY_NAMES[p.weekday as usize]),
            },
            'H' => {
                if run == 1 {
                    write!(out, "{}", p.hour).unwrap()
                } else {
                    write!(out, "{:02}", p.hour).unwrap()
                }
            }
            'h' => {
                let h = if p.hour % 12 == 0 { 12 } else { p.hour % 12 };
                if run == 1 { write!(out, "{h}").unwrap() } else { write!(out, "{h:02}").unwrap() }
            }
            'm' => {
                if run == 1 {
                    write!(out, "{}", p.minute).unwrap()
                } else {
                    write!(out, "{:02}", p.minute).unwrap()
                }
            }
            's' => {
                if run == 1 {
                    write!(out, "{}", p.second).unwrap()
                } else {
                    write!(out, "{:02}", p.second).unwrap()
                }
            }
            'f' | 'F' => {
                let digits = format!("{:07}", p.fraction);
                let n = run.min(7);
                let mut s = &digits[..n];
                if c == 'F' {
                    s = s.trim_end_matches('0');
                    if s.is_empty() && out.ends_with('.') {
                        // .NET drops the decimal point when F prints nothing
                        out.pop();
                    }
                }
                out.push_str(s);
            }
            't' => out.push_str(if run == 1 {
                if p.hour < 12 { "A" } else { "P" }
            } else if p.hour < 12 {
                "AM"
            } else {
                "PM"
            }),
            'z' => out.push_str(match run {
                1 => "+0",
                2 => "+00",
                _ => "+00:00",
            }),
            'K' => {
                for _ in 0..run {
                    out.push_str("+00:00");
                }
            }
            'g' => out.push_str(era),
            '\'' | '"' => {
                // a quoted literal
                let mut j = i + 1;
                while j < chars.len() && chars[j] != c {
                    if chars[j] == '\\' && j + 1 < chars.len() {
                        j += 1;
                    }
                    out.push(chars[j]);
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            '\\' => {
                if i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                }
                i += 2;
                continue;
            }
            '%' => {
                i += 1;
                alone = true;
                continue;
            }
            _ => {
                for _ in 0..run {
                    out.push(c);
                }
            }
        }
        i += run;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn en_us_formats() {
        let t = Timestamp::from_parts(2020, 1, 2, 15, 4, 5, 0).unwrap();
        let f = |format: &str| t.format_en_us(format);
        assert_eq!(f("").unwrap(), "1/2/2020 3:04:05\u{202F}PM +00:00");
        assert_eq!(f("G").unwrap(), "1/2/2020 3:04:05\u{202F}PM");
        assert_eq!(f("D").unwrap(), "Thursday, January 2, 2020");
        assert_eq!(f("r").unwrap(), "Thu, 02 Jan 2020 15:04:05 GMT");
        assert_eq!(f("yyyy-MM-dd gg").unwrap(), "2020-01-02 AD");
        assert_eq!(f("%dd").unwrap(), "22");
        assert_eq!(f("FFFFFFF").unwrap(), "");
        for bad in ["x", "U", "%", "%%", "\\", "ffffffff", "yyyy\\", "yyyy%"] {
            assert_eq!(f(bad), Err("Input string was not in a correct format."), "{bad}");
        }
        assert_eq!(f("yyyy'"), Err("Cannot find a matching quote character for the character '''."));
    }

    #[test]
    fn filetime_round_trip() {
        let t = Timestamp::from_parts(2019, 11, 8, 23, 20, 54, 6_705_004).unwrap();
        assert_eq!(Timestamp::from_filetime(t.0 - FILETIME_EPOCH_TICKS), Some(t));
        assert_eq!(t.to_string(), "2019-11-08 23:20:54.6705004");
        assert_eq!(t.to_json_string(), "2019-11-08T23:20:54.6705004Z");
        assert!(Timestamp::from_filetime(-1).is_none());
        assert!(Timestamp::from_filetime(MAX_FILETIME + 1).is_none());
        assert_eq!(Timestamp::from_filetime(0).unwrap().to_string(), "1601-01-01 00:00:00.0000000");
        assert_eq!(Timestamp::MIN.to_string(), "0001-01-01 00:00:00.0000000");
        assert_eq!(Timestamp(MAX_TICKS).to_string(), "9999-12-31 23:59:59.9999999");
    }

    #[test]
    fn custom_formats() {
        let t = Timestamp::parse("2024-02-29T07:05:09.1200000Z").unwrap();
        assert_eq!(t.format("yyyy-MM-dd HH:mm:ss.fff"), "2024-02-29 07:05:09.120");
        assert_eq!(t.format("yyyy-MM-dd HH:mm:ss.FFFFFFF"), "2024-02-29 07:05:09.12");
        assert_eq!(t.format("dd/MM/yy h:mm tt"), "29/02/24 7:05 AM");
        assert_eq!(t.format("ddd MMM d 'at' HH\\h"), "Thu Feb 29 at 07h");
        assert_eq!(t.format("o"), "2024-02-29T07:05:09.1200000+00:00");
        let whole = Timestamp::parse("2024-02-29 07:05:09").unwrap();
        assert_eq!(whole.format("HH:mm:ss.FFF"), "07:05:09");
    }

    #[test]
    fn parsing() {
        assert_eq!(Timestamp::parse("2024-01-31").unwrap().to_string(), "2024-01-31 00:00:00.0000000");
        assert_eq!(Timestamp::parse("2024/01/31 13:45").unwrap().to_string(), "2024-01-31 13:45:00.0000000");
        assert_eq!(
            Timestamp::parse("2024-01-31T13:45:10.5+02:00").unwrap().to_string(),
            "2024-01-31 11:45:10.5000000"
        );
        assert_eq!(Timestamp::parse("2024-01-31 13:45:10 -0130").unwrap().to_string(), "2024-01-31 15:15:10.0000000");
        assert!(Timestamp::parse("2024-02-30").is_none());
        assert!(Timestamp::parse("0x01D5968F3B4E9F6C").is_none());
        assert!(Timestamp::parse("yesterday").is_none());
    }
}
