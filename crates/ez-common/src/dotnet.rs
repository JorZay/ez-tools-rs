//! Numbers as .NET writes them with the invariant culture.

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn thousands() {
        assert_eq!(n0(0), "0");
        assert_eq!(n0(1234567), "1,234,567");
    }
}
