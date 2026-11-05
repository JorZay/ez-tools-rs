//! The SQL functions System.Data.SQLite's native library adds to SQLite (extension-functions.c), which a map may use. `trim`
//! and `replace` stay SQLite's own, as in that library's build. On Linux its math functions report errno's text.

use std::collections::BTreeMap;

use rusqlite::functions::{Aggregate, Context, FunctionFlags};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, Error, Result};

use crate::db::NetError;

// As in the C library, where Rust has its own versions that can differ in the last digit
unsafe extern "C" {
    safe fn acosh(x: f64) -> f64;
    safe fn asinh(x: f64) -> f64;
    safe fn atanh(x: f64) -> f64;
}

const EDOM: &str = "Numerical argument out of domain";
const ERANGE: &str = "Numerical result out of range";

fn fail(message: &str) -> Error {
    Error::UserFunctionError(message.to_string().into())
}

/// A number at the start of a text, as SQLite reads one
fn number_prefix(text: &str) -> &str {
    let t = text.trim_start();
    let b = t.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i == start || (i == start + 1 && b[start] == b'.') {
        return "";
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            i = j;
        }
    }
    &t[..i]
}

/// sqlite3_value_double
fn double_of(v: ValueRef<'_>) -> f64 {
    match v {
        ValueRef::Null => 0.0,
        ValueRef::Integer(i) => i as f64,
        ValueRef::Real(r) => r,
        ValueRef::Text(b) | ValueRef::Blob(b) => number_prefix(&String::from_utf8_lossy(b)).parse().unwrap_or(0.0),
    }
}

/// sqlite3_value_int64
fn int_of(v: ValueRef<'_>) -> i64 {
    match v {
        ValueRef::Null => 0,
        ValueRef::Integer(i) => i,
        ValueRef::Real(r) => r as i64,
        ValueRef::Text(b) | ValueRef::Blob(b) => {
            let text = String::from_utf8_lossy(b);
            let t = text.trim_start();
            let digits_end = t.char_indices().skip(1).find(|(_, c)| !c.is_ascii_digit()).map_or(t.len(), |(i, _)| i);
            let head = &t[..digits_end];
            match head.parse::<i128>() {
                Ok(n) => n.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
                Err(_) => 0,
            }
        }
    }
}

/// A real as SQLite writes it with 15 digits
fn real_text(v: f64) -> String {
    if v == 0.0 {
        return "0.0".to_string();
    }
    let sci = format!("{v:.14e}");
    let (mantissa, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if !(-4..15).contains(&exp) {
        let m = mantissa.trim_end_matches('0');
        let m = if m.ends_with('.') { format!("{m}0") } else { m.to_string() };
        return format!("{m}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    }
    let fixed = format!("{v:.*}", (14 - exp) as usize);
    let t = fixed.trim_end_matches('0');
    if t.ends_with('.') { format!("{t}0") } else { t.to_string() }
}

/// sqlite3_value_text as C reads it: up to the first NUL
fn text_of(v: ValueRef<'_>) -> Vec<u8> {
    let mut bytes = match v {
        ValueRef::Null => Vec::new(),
        ValueRef::Integer(i) => i.to_string().into_bytes(),
        ValueRef::Real(r) => real_text(r).into_bytes(),
        ValueRef::Text(b) | ValueRef::Blob(b) => b.to_vec(),
    };
    if let Some(i) = bytes.iter().position(|b| *b == 0) {
        bytes.truncate(i);
    }
    bytes
}

fn text_value(bytes: Vec<u8>) -> SqlValue {
    SqlValue::Text(String::from_utf8_lossy(&bytes).into_owned())
}

/// The characters of a text as slices of its bytes
fn characters(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] & 0xC0 == 0x80 {
            j += 1;
        }
        out.push(&bytes[i..j]);
        i = j;
    }
    out
}

fn is_null(v: ValueRef<'_>) -> bool {
    matches!(v, ValueRef::Null)
}

/// A function of one double, with what sets errno on glibc
fn math1(conn: &Connection, name: &'static str, f: fn(f64) -> f64, error: fn(f64, f64) -> Option<&'static str>) -> Result<()> {
    conn.create_scalar_function(name, 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        let v = ctx.get_raw(0);
        if is_null(v) {
            return Ok(SqlValue::Null);
        }
        let x = double_of(v);
        let y = f(x);
        match error(x, y) {
            Some(message) => Err(fail(message)),
            None => Ok(SqlValue::Real(y)),
        }
    })
}

fn no_error(_: f64, _: f64) -> Option<&'static str> {
    None
}

fn domain_if_infinite(x: f64, _: f64) -> Option<&'static str> {
    x.is_infinite().then_some(EDOM)
}

fn overflow(x: f64, y: f64) -> Option<&'static str> {
    (y.is_infinite() && x.is_finite()).then_some(ERANGE)
}

fn log_error(x: f64, _: f64) -> Option<&'static str> {
    if x < 0.0 {
        Some(EDOM)
    } else if x == 0.0 {
        Some(ERANGE)
    } else {
        None
    }
}

fn exp_error(x: f64, y: f64) -> Option<&'static str> {
    (x.is_finite() && (y.is_infinite() || y == 0.0 || y.is_subnormal())).then_some(ERANGE)
}

fn pow_error(x: f64, y: f64, r: f64) -> Option<&'static str> {
    if x.is_finite() && y.is_finite() {
        if r.is_nan() {
            return Some(EDOM);
        }
        if r.is_infinite() || ((r == 0.0 || r.is_subnormal()) && x != 0.0) {
            return Some(ERANGE);
        }
    }
    None
}

/// (i64)ceil(x) on x86: what doesn't fit is the smallest integer
fn to_i64(v: f64) -> i64 {
    if v >= -9.223_372_036_854_775_8e18 && v < 9.223_372_036_854_775_8e18 { v as i64 } else { i64::MIN }
}

fn round_function(conn: &Connection, name: &'static str, f: fn(f64) -> f64) -> Result<()> {
    conn.create_scalar_function(name, 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(i) => SqlValue::Integer(i),
            other => SqlValue::Integer(to_i64(f(double_of(other)))),
        })
    })
}

fn pad(ctx: &Context<'_>, left: fn(i64, i64) -> i64) -> Result<SqlValue> {
    if is_null(ctx.get_raw(0)) {
        return Ok(SqlValue::Null);
    }
    let text = text_of(ctx.get_raw(0));
    let length = int_of(ctx.get_raw(1));
    if length < 0 {
        return Err(fail("domain error"));
    }
    let chars = characters(&text).len() as i64;
    if chars >= length {
        return Ok(text_value(text));
    }
    let before = left(length, chars) as usize;
    let after = (length - chars) as usize - before;
    let mut out = vec![b' '; before];
    out.extend_from_slice(&text);
    out.extend(std::iter::repeat_n(b' ', after));
    Ok(text_value(out))
}

/// _substr: the 0 based character where needle is, from character `start` on, comparing one byte of each character
fn find_characters(needle: &[u8], text: &[u8], start: usize) -> i64 {
    if needle.is_empty() {
        return -1;
    }
    let needle = characters(needle);
    let text = characters(text);
    let mut at = start.min(text.len());
    while at < text.len() {
        let matched = needle.iter().enumerate().all(|(k, c)| text.get(at + k).is_some_and(|t| t[0] == c[0]));
        if matched {
            return at as i64;
        }
        at += 1;
    }
    -1
}

fn soundex(text: &[u8]) -> [u8; 4] {
    const CODE: [u8; 128] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 0, 0, 2, 2,
        4, 5, 5, 0, 1, 2, 6, 2, 3, 0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 1, 2, 0, 0, 2, 2, 4, 5, 5, 0, 1, 2, 6, 2, 3, 0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0,
    ];
    let Some(mut i) = text.iter().position(u8::is_ascii_alphabetic) else { return *b"?000" };
    let mut out = *b"0000";
    out[0] = text[i].to_ascii_uppercase();
    let mut j = 1;
    while j < 4 && i < text.len() {
        let code = CODE[usize::from(text[i] & 0x7F)];
        if code > 0 {
            out[j] = code + b'0';
            j += 1;
        }
        i += 1;
    }
    out
}

#[derive(Default)]
struct Stdev {
    mean: f64,
    sum: f64,
    count: i64,
}

#[derive(Clone, Copy)]
struct VarianceOf {
    root: bool,
}

impl Aggregate<Stdev, f64> for VarianceOf {
    fn init(&self, _: &mut Context<'_>) -> Result<Stdev> {
        Ok(Stdev::default())
    }

    fn step(&self, ctx: &mut Context<'_>, s: &mut Stdev) -> Result<()> {
        let v = ctx.get_raw(0);
        if !is_null(v) {
            s.count += 1;
            let x = double_of(v);
            let delta = x - s.mean;
            s.mean += delta / s.count as f64;
            s.sum += delta * (x - s.mean);
        }
        Ok(())
    }

    fn finalize(&self, _: &mut Context<'_>, s: Option<Stdev>) -> Result<f64> {
        Ok(match s {
            Some(s) if s.count > 1 => {
                let variance = s.sum / (s.count - 1) as f64;
                if self.root { variance.sqrt() } else { variance }
            }
            _ => 0.0,
        })
    }
}

/// The values seen by mode, median and the quartiles: integers or doubles, as the first one was
#[derive(Default)]
struct Values {
    started: bool,
    is_double: bool,
    integers: BTreeMap<i64, i64>,
    doubles: Vec<(f64, i64)>,
    count: i64,
}

/// sqlite3_value_numeric_type is INTEGER
fn numeric_is_integer(v: ValueRef<'_>) -> bool {
    match v {
        ValueRef::Integer(_) => true,
        ValueRef::Text(b) => {
            let text = String::from_utf8_lossy(b);
            let t = text.trim();
            !t.is_empty() && t.parse::<i64>().is_ok()
        }
        _ => false,
    }
}

impl Values {
    fn add(&mut self, v: ValueRef<'_>) {
        if is_null(v) {
            return;
        }
        if !self.started {
            self.started = true;
            self.is_double = !numeric_is_integer(v);
        }
        self.count += 1;
        if self.is_double {
            let x = double_of(v);
            match self.doubles.binary_search_by(|(d, _)| d.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Less)) {
                Ok(i) => self.doubles[i].1 += 1,
                Err(i) => self.doubles.insert(i, (x, 1)),
            }
        } else {
            *self.integers.entry(int_of(v)).or_insert(0) += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum Statistic {
    Mode,
    /// The share of the values below it
    Percentile(f64),
}

fn mode(values: &Values) -> SqlValue {
    let (mut most, mut ties) = (0i64, 0i64);
    let (mut integer, mut double) = (0i64, 0f64);
    let mut see = |count: i64, set: &mut dyn FnMut()| {
        if most == count {
            ties += 1;
        } else if most < count {
            set();
            most = count;
            ties = 1;
        }
    };
    if values.is_double {
        for (d, count) in &values.doubles {
            see(*count, &mut || double = *d);
        }
    } else {
        // the original reads the integers through an int*
        for (i, count) in &values.integers {
            see(*count, &mut || integer = i64::from(*i as i32));
        }
    }
    if ties != 1 {
        return SqlValue::Null;
    }
    if values.is_double { SqlValue::Real(double) } else { SqlValue::Integer(integer) }
}

fn percentile(values: &Values, share: f64) -> SqlValue {
    let wanted = values.count as f64 * share;
    let (left, right) = (wanted, values.count as f64 - wanted);
    let (mut below, mut hits) = (0i64, 0i64);
    let (mut integer, mut double) = (0i64, 0f64);
    let mut see = |count: i64, add: &mut dyn FnMut()| -> bool {
        let lower = (below + count) as f64;
        let upper = (values.count - below) as f64;
        if lower >= left {
            if upper >= right {
                hits += 1;
                add();
            } else {
                return false;
            }
        }
        below += count;
        true
    };
    if values.is_double {
        for (d, count) in &values.doubles {
            if !see(*count, &mut || double += *d) {
                break;
            }
        }
    } else {
        for (i, count) in &values.integers {
            if !see(*count, &mut || integer += i64::from(*i as i32)) {
                break;
            }
        }
    }
    if values.is_double {
        SqlValue::Real(double / hits as f64)
    } else if hits == 1 {
        SqlValue::Integer(integer)
    } else {
        SqlValue::Real(integer as f64 / hits as f64)
    }
}

impl Aggregate<Values, SqlValue> for Statistic {
    fn init(&self, _: &mut Context<'_>) -> Result<Values> {
        Ok(Values::default())
    }

    fn step(&self, ctx: &mut Context<'_>, values: &mut Values) -> Result<()> {
        values.add(ctx.get_raw(0));
        Ok(())
    }

    fn finalize(&self, _: &mut Context<'_>, values: Option<Values>) -> Result<SqlValue> {
        let Some(values) = values.filter(|v| v.started) else { return Ok(SqlValue::Null) };
        Ok(match self {
            Statistic::Mode => mode(&values),
            Statistic::Percentile(share) => percentile(&values, *share),
        })
    }
}

fn register_all(conn: &Connection) -> Result<()> {
    let utf8 = FunctionFlags::SQLITE_UTF8;
    math1(conn, "sqrt", f64::sqrt, |x, _| (x < 0.0).then_some(EDOM))?;
    math1(conn, "acos", f64::acos, |x, _| (x.abs() > 1.0).then_some(EDOM))?;
    math1(conn, "asin", f64::asin, |x, _| (x.abs() > 1.0).then_some(EDOM))?;
    math1(conn, "atan", f64::atan, no_error)?;
    math1(conn, "acosh", |x| acosh(x), |x, _| (x < 1.0).then_some(EDOM))?;
    math1(conn, "asinh", |x| asinh(x), |_, y| y.is_subnormal().then_some(ERANGE))?;
    math1(conn, "atanh", |x| atanh(x), |x, y| {
        if x.abs() > 1.0 {
            Some(EDOM)
        } else if x.abs() == 1.0 || y.is_subnormal() {
            Some(ERANGE)
        } else {
            None
        }
    })?;
    math1(conn, "sin", f64::sin, domain_if_infinite)?;
    math1(conn, "cos", f64::cos, domain_if_infinite)?;
    math1(conn, "tan", f64::tan, domain_if_infinite)?;
    math1(conn, "cot", |x| 1.0 / x.tan(), domain_if_infinite)?;
    math1(conn, "sinh", f64::sinh, overflow)?;
    math1(conn, "cosh", f64::cosh, overflow)?;
    math1(conn, "tanh", f64::tanh, no_error)?;
    math1(conn, "coth", |x| 1.0 / x.tanh(), no_error)?;
    math1(conn, "log", f64::ln, log_error)?;
    math1(conn, "log10", f64::log10, log_error)?;
    math1(conn, "exp", f64::exp, exp_error)?;
    math1(conn, "degrees", |x| 180.0 * x / std::f64::consts::PI, no_error)?;
    math1(conn, "radians", |x| x * std::f64::consts::PI / 180.0, no_error)?;
    round_function(conn, "ceil", f64::ceil)?;
    round_function(conn, "ceiling", f64::ceil)?;
    round_function(conn, "floor", f64::floor)?;

    conn.create_scalar_function("pi", 0, utf8, |_| Ok(std::f64::consts::PI))?;
    conn.create_scalar_function("last_rows_affected", 0, utf8, |ctx| {
        // only reads the count of the connection the function runs on
        let db = unsafe { ctx.get_connection() }?;
        Ok(db.changes() as i64)
    })?;
    conn.create_scalar_function("square", 1, utf8, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(i) => SqlValue::Integer(i.wrapping_mul(i)),
            other => {
                let x = double_of(other);
                SqlValue::Real(x * x)
            }
        })
    })?;
    conn.create_scalar_function("sign", 1, utf8, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(i) => SqlValue::Integer(i.signum()),
            other => {
                let x = double_of(other);
                SqlValue::Real(if x > 0.0 {
                    1.0
                } else if x < 0.0 {
                    -1.0
                } else {
                    0.0
                })
            }
        })
    })?;
    conn.create_scalar_function("power", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
            return Ok(SqlValue::Null);
        }
        let (x, y) = (double_of(ctx.get_raw(0)), double_of(ctx.get_raw(1)));
        let r = x.powf(y);
        match pow_error(x, y, r) {
            Some(message) => Err(fail(message)),
            None => Ok(SqlValue::Real(r)),
        }
    })?;
    for name in ["atn2", "atan2"] {
        conn.create_scalar_function(name, 2, utf8, |ctx| {
            if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
                return Ok(SqlValue::Null);
            }
            Ok(SqlValue::Real(double_of(ctx.get_raw(0)).atan2(double_of(ctx.get_raw(1)))))
        })?;
    }

    conn.create_scalar_function("replicate", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) {
            return Ok(SqlValue::Null);
        }
        let count = int_of(ctx.get_raw(1));
        if count < 0 {
            return Err(fail("domain error"));
        }
        // with a NUL inside, the copies are written past where C stops reading
        let text = text_of(ctx.get_raw(0));
        let cut = ctx.get_raw(0).as_bytes().is_ok_and(|b| b.contains(&0));
        Ok(text_value(if cut && count > 0 { text } else { text.repeat(count as usize) }))
    })?;
    conn.create_scalar_function("proper", 1, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) {
            return Ok(SqlValue::Null);
        }
        let mut start = true;
        let out = text_of(ctx.get_raw(0))
            .into_iter()
            .map(|b| {
                if b == b' ' || b == b'\t' {
                    start = true;
                    b
                } else {
                    let converted = if start { b.to_ascii_uppercase() } else { b.to_ascii_lowercase() };
                    start = false;
                    converted
                }
            })
            .collect();
        Ok(text_value(out))
    })?;
    conn.create_scalar_function("padl", 2, utf8, |ctx| pad(ctx, |length, chars| length - chars))?;
    conn.create_scalar_function("padr", 2, utf8, |ctx| pad(ctx, |_, _| 0))?;
    conn.create_scalar_function("padc", 2, utf8, |ctx| pad(ctx, |length, chars| (length - chars) / 2))?;
    conn.create_scalar_function("strfilter", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
            return Ok(SqlValue::Null);
        }
        let text = text_of(ctx.get_raw(0));
        let allowed = text_of(ctx.get_raw(1));
        let allowed = characters(&allowed);
        let mut out = Vec::new();
        for c in characters(&text) {
            if allowed.contains(&c) {
                out.extend_from_slice(c);
            }
        }
        Ok(text_value(out))
    })?;
    for args in [2, 3] {
        conn.create_scalar_function("charindex", args, utf8, |ctx| {
            if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
                return Ok(SqlValue::Null);
            }
            let start = if ctx.len() == 3 { (int_of(ctx.get_raw(2)) as i32).wrapping_sub(1).max(0) } else { 0 };
            let found = find_characters(&text_of(ctx.get_raw(0)), &text_of(ctx.get_raw(1)), start as usize);
            Ok(SqlValue::Integer(found + 1))
        })?;
    }
    conn.create_scalar_function("leftstr", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
            return Ok(SqlValue::Null);
        }
        let text = text_of(ctx.get_raw(0));
        let length = (int_of(ctx.get_raw(1)) as i32).max(0) as usize;
        Ok(text_value(characters(&text).into_iter().take(length).flatten().copied().collect()))
    })?;
    conn.create_scalar_function("rightstr", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
            return Ok(SqlValue::Null);
        }
        let text = text_of(ctx.get_raw(0));
        let chars = characters(&text);
        let length = i64::from(int_of(ctx.get_raw(1)) as i32);
        let skip = (chars.len() as i64 - length).max(0) as usize;
        Ok(text_value(chars.into_iter().skip(skip).flatten().copied().collect()))
    })?;
    conn.create_scalar_function("reverse", 1, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) {
            return Ok(SqlValue::Null);
        }
        let text = text_of(ctx.get_raw(0));
        Ok(text_value(characters(&text).into_iter().rev().flatten().copied().collect()))
    })?;
    conn.create_scalar_function("difference", 2, utf8, |ctx| {
        if is_null(ctx.get_raw(0)) || is_null(ctx.get_raw(1)) {
            return Ok(SqlValue::Null);
        }
        let (a, b) = (soundex(&text_of(ctx.get_raw(0))), soundex(&text_of(ctx.get_raw(1))));
        Ok(SqlValue::Integer(a.iter().zip(&b).filter(|(x, y)| x == y).count() as i64))
    })?;

    conn.create_aggregate_function("stdev", 1, utf8, VarianceOf { root: true })?;
    conn.create_aggregate_function("variance", 1, utf8, VarianceOf { root: false })?;
    conn.create_aggregate_function("mode", 1, utf8, Statistic::Mode)?;
    conn.create_aggregate_function("median", 1, utf8, Statistic::Percentile(0.5))?;
    conn.create_aggregate_function("lower_quartile", 1, utf8, Statistic::Percentile(0.25))?;
    conn.create_aggregate_function("upper_quartile", 1, utf8, Statistic::Percentile(0.75))?;
    Ok(())
}

pub(crate) fn register(conn: &Connection) -> std::result::Result<(), NetError> {
    Ok(register_all(conn)?)
}
