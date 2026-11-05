//! Numbers as .NET writes them with the invariant culture.

use icu_collator::options::{CollatorOptions, Strength};
use icu_collator::{Collator, CollatorBorrowed};
use std::sync::LazyLock;
use std::fmt::Write;

/// A double as .NET (Core 3.0 and later) writes it with the invariant culture: the shortest text that reads back
/// as the same value, in scientific notation (`1E+15`) when the exponent is 15 or more or -5 or less
pub fn dotnet_f64(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    shortest(&format!("{v:e}"), 17)
}

/// A float as .NET writes it (scientific notation when the exponent is 9 or more or -5 or less)
pub fn dotnet_f32(v: f32) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    shortest(&format!("{v:e}"), 9)
}

/// Rust's shortest round-trip scientific text (`-1.25e-7`) in .NET's general format
fn shortest(sci: &str, precision: i32) -> String {
    let (mantissa, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if exp >= precision || exp <= -5 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        write!(out, "E{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs()).unwrap();
    } else if exp >= 0 {
        let whole = exp as usize + 1;
        if digits.len() <= whole {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n('0', whole - digits.len()));
        } else {
            out.push_str(&digits[..whole]);
            out.push('.');
            out.push_str(&digits[whole..]);
        }
    } else {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', (-exp - 1) as usize));
        out.push_str(&digits);
    }
    out
}

static COLLATOR: LazyLock<CollatorBorrowed<'static>> =
    LazyLock::new(|| Collator::try_new(Default::default(), CollatorOptions::default()).expect("the root collation is compiled in"));

static COLLATOR_IGNORE_CASE: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    let mut options = CollatorOptions::default();
    options.strength = Some(Strength::Secondary);
    Collator::try_new(Default::default(), options).expect("the root collation is compiled in")
});

/// string.CompareTo in en-US, which is ICU's root collation: by letter first, then by accent, then lowercase before uppercase
pub fn compare_culture(a: &str, b: &str) -> std::cmp::Ordering {
    COLLATOR.compare(a, b)
}

/// StringComparison.InvariantCultureIgnoreCase: the same accents count, however they are written, and case doesn't
pub fn equals_invariant_ignore_case(a: &str, b: &str) -> bool {
    COLLATOR_IGNORE_CASE.compare(a, b) == std::cmp::Ordering::Equal
}

/// A number with thousands separators (.NET's N0)
pub fn n0(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A number in .NET's N format with `decimals` decimals (thousands separators; exact halves rounded to even, as
/// .NET does with the exact value)
pub fn number_n(v: f64, decimals: usize) -> String {
    let text = format!("{:.*}", decimals, v.abs());
    let (int_text, frac) = text.split_once('.').unwrap_or((&text, ""));
    let mut out = String::new();
    if v < 0.0 && text.bytes().any(|c| (b'1'..=b'9').contains(&c)) {
        out.push('-');
    }
    for (i, c) in int_text.chars().enumerate() {
        if i > 0 && (int_text.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if decimals > 0 {
        out.push('.');
        out.push_str(frac);
    }
    out
}

/// char.ToUpperInvariant
pub fn upper_invariant_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_uppercase();
    }
    match c {
        // Rust gives these several characters; .NET its simple mapping
        '\u{1F80}'..='\u{1F87}' | '\u{1F90}'..='\u{1F97}' | '\u{1FA0}'..='\u{1FA7}' => return char::from_u32(c as u32 + 8).unwrap_or(c),
        '\u{1FB3}' | '\u{1FC3}' | '\u{1FF3}' => return char::from_u32(c as u32 + 9).unwrap_or(c),
        // .NET keeps the dotless i
        '\u{131}' => return c,
        _ if newer_than_dotnet(c) => return c,
        _ => {}
    }
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

/// Cased letters of a newer Unicode than .NET 10's, which .NET leaves as they are
fn newer_than_dotnet(c: char) -> bool {
    matches!(c, '\u{A7CE}' | '\u{A7CF}' | '\u{A7D2}'..='\u{A7D5}' | '\u{16EA0}'..='\u{16EB8}' | '\u{16EBB}'..='\u{16ED3}')
}

/// char.ToLowerInvariant
pub fn lower_invariant_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    // .NET keeps the dotted capital I
    if c == '\u{130}' || newer_than_dotnet(c) {
        return c;
    }
    let mut u = c.to_lowercase();
    match (u.next(), u.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}

/// string.ToUpperInvariant
pub fn upper_invariant(s: &str) -> String {
    s.chars().map(upper_invariant_char).collect()
}

/// The form OrdinalIgnoreCase compares strings in: ToUpperInvariant, except that it keeps U+017F (long s)
pub fn ordinal_ignore_case(s: &str) -> String {
    s.chars().map(|c| if c == '\u{17F}' { c } else { upper_invariant_char(c) }).collect()
}

/// string.ToLowerInvariant
pub fn lower_invariant(s: &str) -> String {
    s.chars().map(lower_invariant_char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every code point was compared with .NET 10's ToUpperInvariant and ToLowerInvariant; these are the ones Rust maps differently
    #[test]
    fn ordinal_ignore_case_keeps_long_s() {
        assert_eq!(ordinal_ignore_case("\u{17F}a\u{E9}"), "\u{17F}A\u{C9}");
        assert_eq!(upper_invariant("\u{17F}"), "S");
    }

    #[test]
    fn case_mapping_as_dotnet() {
        assert_eq!(lower_invariant("\u{130}A\u{3A3}"), "\u{130}a\u{3C3}");
        assert_eq!(upper_invariant("\u{131}a\u{DF}"), "\u{131}A\u{DF}");
        assert_eq!(upper_invariant_char('\u{1F80}'), '\u{1F88}');
        assert_eq!(upper_invariant_char('\u{1F97}'), '\u{1F9F}');
        assert_eq!(upper_invariant_char('\u{1FA7}'), '\u{1FAF}');
        assert_eq!(upper_invariant_char('\u{1FB3}'), '\u{1FBC}');
        assert_eq!(upper_invariant_char('\u{1FF3}'), '\u{1FFC}');
        assert_eq!(upper_invariant_char('\u{A7CF}'), '\u{A7CF}');
        assert_eq!(lower_invariant_char('\u{A7CE}'), '\u{A7CE}');
        assert_eq!(lower_invariant_char('\u{16EA0}'), '\u{16EA0}');
        assert_eq!(upper_invariant_char('\u{16EBB}'), '\u{16EBB}');
    }

    #[test]
    fn doubles_as_dotnet() {
        assert_eq!(dotnet_f64(0.0), "0");
        assert_eq!(dotnet_f64(-0.0), "-0");
        assert_eq!(dotnet_f64(1.5), "1.5");
        assert_eq!(dotnet_f64(100.0), "100");
        assert_eq!(dotnet_f64(0.1), "0.1");
        assert_eq!(dotnet_f64(0.0001), "0.0001");
        assert_eq!(dotnet_f64(0.00001), "1E-05");
        assert_eq!(dotnet_f64(1e15), "1000000000000000");
        assert_eq!(dotnet_f64(1e16), "10000000000000000");
        assert_eq!(dotnet_f64(1.2345678901234568e17), "1.2345678901234568E+17");
        assert_eq!(dotnet_f64(123456789012345.0), "123456789012345");
        assert_eq!(dotnet_f64(1.2345678901234568e20), "1.2345678901234568E+20");
        assert_eq!(dotnet_f64(f64::NAN), "NaN");
        assert_eq!(dotnet_f32(1e7), "10000000");
        assert_eq!(dotnet_f32(123456789.0), "123456790");
        assert_eq!(dotnet_f32(1e9), "1E+09");
        assert_eq!(dotnet_f32(3.4028235e38), "3.4028235E+38");
        assert_eq!(dotnet_f32(1234567.0), "1234567");
        assert_eq!(dotnet_f32(0.3), "0.3");
    }

    #[test]
    fn n_format() {
        assert_eq!(number_n(92.1875, 3), "92.188");
        assert_eq!(number_n(1234.5, 3), "1,234.500");
        assert_eq!(number_n(0.0625, 3), "0.062");
        assert_eq!(number_n(82.8125, 3), "82.812");
        assert_eq!(number_n(999.9996, 3), "1,000.000");
        assert_eq!(number_n(1.785, 3), "1.785");
    }

    #[test]
    fn culture_order() {
        use std::cmp::Ordering::Less;
        assert_eq!(compare_culture("a_b", "a-b"), Less);
        assert_eq!(compare_culture("a-b", "a1"), Less);
        assert_eq!(compare_culture("a", "A"), Less);
        assert_eq!(compare_culture("A", "b"), Less);
        assert_eq!(compare_culture("e", "\u{e9}"), Less);
        assert_eq!(compare_culture("\u{e9}", "f"), Less);
        assert_eq!(compare_culture("z", "\u{5b50}"), Less);
        assert_eq!(compare_culture("\u{e1}", "\u{e0}"), Less, "acute before grave");
        assert_eq!(compare_culture("\u{e4}", "\u{e3}"), Less, "diaeresis before tilde");
        assert_eq!(compare_culture("\u{f1}", "o"), Less, "n with tilde among the n's");
        assert_eq!(compare_culture("\u{e9}", "e\u{301}"), std::cmp::Ordering::Equal);
        assert!(equals_invariant_ignore_case("CAF\u{c9}", "cafe\u{301}"));
        assert!(!equals_invariant_ignore_case("cafe", "caf\u{e9}"));
    }

    #[test]
    fn thousands() {
        assert_eq!(n0(0), "0");
        assert_eq!(n0(1234567), "1,234,567");
    }
}
