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
    shortest(&format!("{v:e}"), 15)
}

/// A float as .NET writes it (scientific notation when the exponent is 7 or more or -5 or less)
pub fn dotnet_f32(v: f32) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    shortest(&format!("{v:e}"), 7)
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
        assert_eq!(dotnet_f64(1e15), "1E+15");
        assert_eq!(dotnet_f64(123456789012345.0), "123456789012345");
        assert_eq!(dotnet_f64(1.2345678901234568e20), "1.2345678901234568E+20");
        assert_eq!(dotnet_f64(f64::NAN), "NaN");
        assert_eq!(dotnet_f32(1e7), "1E+07");
        assert_eq!(dotnet_f32(1234567.0), "1234567");
        assert_eq!(dotnet_f32(0.3), "0.3");
    }

    #[test]
    fn thousands() {
        assert_eq!(n0(0), "0");
        assert_eq!(n0(1234567), "1,234,567");
    }
}
