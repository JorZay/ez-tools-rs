//! .NET's text functions the original uses, where Rust's differ.

use std::cmp::Ordering;
use std::sync::LazyLock;

use icu_properties::CodePointSetDataBorrowed;
use icu_properties::props::GraphemeExtend;

static EXTEND: LazyLock<CodePointSetDataBorrowed<'static>> = LazyLock::new(icu_properties::CodePointSetData::new::<GraphemeExtend>);

/// A character with no collation weight at all (controls, U+00AD, U+200B, U+FEFF...), which a culture comparison skips
fn ignorable(c: char) -> bool {
    let mut buf = [0u8; 4];
    ez_common::dotnet::compare_culture(c.encode_utf8(&mut buf), "") == Ordering::Equal
}

/// string.StartsWith(prefix) with a one-character prefix, which compares in the current culture (ICU): characters without
/// weight before it are skipped, and the character must not be followed by a combining mark, which would make it another
pub fn culture_starts_with(s: &str, prefix: char) -> bool {
    let mut chars = s.chars().skip_while(|&c| ignorable(c));
    if chars.next() != Some(prefix) {
        return false;
    }
    !chars.next().is_some_and(|c| EXTEND.contains(c) && !ignorable(c))
}

/// Convert.FromBase64String: white space (space, tab, CR, LF) anywhere is skipped; the rest must be whole groups of four,
/// with at most two `=` at the end. The bits left over in the last character aren't checked
pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<u8> = s.bytes().filter(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n')).collect();
    if chars.len() % 4 != 0 {
        return None;
    }
    let padding = chars.iter().rev().take_while(|&&c| c == b'=').count();
    if padding > 2 {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    for (n, group) in chars.chunks(4).enumerate() {
        let last = n == chars.len() / 4 - 1;
        let pad = if last { padding } else { 0 };
        let mut bits = 0u32;
        for &c in &group[..4 - pad] {
            bits = bits << 6 | value(c)?;
        }
        bits <<= 6 * pad as u32;
        let bytes = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// WebUtility.UrlDecode: `+` is a space and `%XX` a byte; bytes are read as UTF-8 (U+FFFD for what isn't), along with the
/// ASCII characters between them
pub fn url_decode(s: &str) -> String {
    let hex = |c: Option<&u8>| c.and_then(|c| (*c as char).to_digit(16));
    if !s.contains('%') {
        return s.replace('+', " ");
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut bytes: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'+' {
            bytes.push(b' ');
            i += 1;
            continue;
        }
        if c == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b.get(i + 1)), hex(b.get(i + 2))) {
                bytes.push((h << 4 | l) as u8);
                i += 3;
                continue;
            }
        }
        if c < 0x80 {
            bytes.push(c);
            i += 1;
            continue;
        }
        // a character other than ASCII goes as it is
        out.push_str(&String::from_utf8_lossy(&bytes));
        bytes.clear();
        let ch = s[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out.push_str(&String::from_utf8_lossy(&bytes));
    out
}

/// int.TryParse and long.TryParse with NumberStyles.Integer and the invariant culture: white space around, a sign, ASCII
/// digits, and (as .NET allows) NUL characters at the very end
pub fn parse_integer(s: &str, min: i64, max: i64) -> Option<i64> {
    let white = |c: char| c == ' ' || ('\t'..='\r').contains(&c);
    let s = s.trim_start_matches(white);
    let (negative, s) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = s[digits..].trim_start_matches(white);
    if !rest.chars().all(|c| c == '\0') {
        return None;
    }
    let mut v: i128 = 0;
    for c in s[..digits].bytes() {
        v = v * 10 + (c - b'0') as i128;
        if v > i64::MAX as i128 + 1 {
            return None;
        }
    }
    let v = if negative { -v } else { v };
    if v < min as i128 || v > max as i128 { None } else { Some(v as i64) }
}

/// The user's name from the last `Users` folder in a path, as the original's regular expression
/// `(?:\\|/)Users(?:\\|/)([^\\\/]+)(?!.*(?:\\|/)Users(?:\\|/))` finds it (case ignored): "" when there is none
pub fn user_profile(path: &str) -> String {
    let sep = |c: u8| c == b'\\' || c == b'/';
    let b = path.as_bytes();
    // where "\Users\" starts
    let users_at = users_at_within(b, b.len());
    for i in 0..b.len() {
        if !users_at(i) {
            continue;
        }
        let start = i + 7;
        let end = start + b[start..].iter().take_while(|&&c| !sep(c)).count();
        if end == start {
            continue;
        }
        // no later "\Users\" on the same line (`.` stops at a line feed)
        let line_end = end + b[end..].iter().take_while(|&&c| c != b'\n').count();
        if (end..line_end).any(users_at_within(b, line_end)) {
            continue;
        }
        return path[start..end].to_string();
    }
    String::new()
}

/// Whether "\\Users\\" (either separator, any case) starts at a position and ends by `limit`
fn users_at_within(b: &[u8], limit: usize) -> impl Fn(usize) -> bool + '_ {
    move |i| {
        let sep = |c: u8| c == b'\\' || c == b'/';
        i + 7 <= limit && sep(b[i]) && b[i + 1..i + 6].eq_ignore_ascii_case(b"users") && sep(b[i + 6])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_in_the_culture() {
        assert!(culture_starts_with("{\"a\"", '{'));
        assert!(culture_starts_with("\u{feff}{", '{'));
        assert!(culture_starts_with("\u{ad}\u{200b}\0{", '{'));
        assert!(!culture_starts_with("{\u{301}", '{'));
        assert!(!culture_starts_with(" {", '{'));
        assert!(!culture_starts_with("\u{ff5b}", '{'));
        assert!(!culture_starts_with("", '{'));
    }

    #[test]
    fn base64_as_dotnet() {
        assert_eq!(from_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(from_base64("aGVsbG9=").unwrap(), b"hello");
        assert_eq!(from_base64(" aGVs\r\nbG8=\t").unwrap(), b"hello");
        assert_eq!(from_base64("   ").unwrap(), b"");
        assert_eq!(from_base64("aGVsbA==").unwrap(), b"hell");
        for bad in ["aGVsbG8", "aGVsbG8==", "aG=sbG8=", "aGVsbG8=aGk=", "aGVsbG8-", "YQ", "YQ=", "Y===", "===="] {
            assert!(from_base64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn url_decoding() {
        assert_eq!(url_decode("a+b%2Bc"), "a b+c");
        assert_eq!(url_decode("%"), "%");
        assert_eq!(url_decode("%41%zz"), "A%zz");
        assert_eq!(url_decode("%C3%A9 %E2%82%AC"), "\u{e9} \u{20ac}");
        assert_eq!(url_decode("%C3 bad %FF"), "\u{fffd} bad \u{fffd}");
        assert_eq!(url_decode("\u{e9}%41\u{e9}"), "\u{e9}A\u{e9}");
        assert_eq!(url_decode("x%2"), "x%2");
        assert_eq!(url_decode("%%41"), "%A");
    }

    #[test]
    fn integers_as_dotnet() {
        let int = |s| parse_integer(s, i32::MIN as i64, i32::MAX as i64);
        assert_eq!(int(" +5 "), Some(5));
        assert_eq!(int("16\0"), Some(16));
        assert_eq!(int("1 \0"), Some(1));
        assert_eq!(int("1\0 "), None);
        assert_eq!(int("2147483648"), None);
        assert_eq!(int("-2147483648"), Some(i32::MIN as i64));
        assert_eq!(int("1.5"), None);
        assert_eq!(int(""), None);
        assert_eq!(int("\u{661}"), None);
        assert_eq!(parse_integer("-9223372036854775808", i64::MIN, i64::MAX), Some(i64::MIN));
        assert_eq!(parse_integer("9223372036854775808", i64::MIN, i64::MAX), None);
    }

    #[test]
    fn user_names() {
        assert_eq!(user_profile("C:\\Users\\jane\\AppData\\x.db"), "jane");
        assert_eq!(user_profile("/a/Users/first/x/Users/second/x.db"), "second");
        assert_eq!(user_profile("/a/users/lower/x.db"), "lower");
        assert_eq!(user_profile("/a/U\u{17f}ers/longs/x.db"), "");
        assert_eq!(user_profile("Users/x/y.db"), "");
        assert_eq!(user_profile("/a/Users/x.db"), "x.db");
        assert_eq!(user_profile("/a/Users//b"), "");
    }
}
