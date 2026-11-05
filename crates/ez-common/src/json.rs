//! JSON as ServiceStack.Text writes it (EZ tools' --json output): objects with their properties in order, null
//! ones left out.

/// A JSON string as ServiceStack.Text writes it: the usual short escapes, control characters as \uXXXX (uppercase)
pub fn service_stack_string(out: &mut String, s: &str) {
    use std::fmt::Write;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() => write!(out, "\\u{:04X}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// An object written as ServiceStack.Text serializes one: properties in declaration order, null ones left out
pub struct ServiceStackObject {
    out: String,
    first: bool,
}

impl Default for ServiceStackObject {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceStackObject {
    pub fn new() -> Self {
        ServiceStackObject { out: String::from("{"), first: true }
    }

    fn key(&mut self, name: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        self.out.push('"');
        self.out.push_str(name);
        self.out.push_str("\":");
    }

    pub fn string(&mut self, name: &str, value: Option<&str>) -> &mut Self {
        if let Some(v) = value {
            self.key(name);
            service_stack_string(&mut self.out, v);
        }
        self
    }

    pub fn raw(&mut self, name: &str, value: &str) -> &mut Self {
        self.key(name);
        self.out.push_str(value);
        self
    }

    pub fn number(&mut self, name: &str, value: impl std::fmt::Display) -> &mut Self {
        self.key(name);
        use std::fmt::Write;
        write!(self.out, "{value}").unwrap();
        self
    }

    pub fn bool(&mut self, name: &str, value: bool) -> &mut Self {
        self.raw(name, if value { "true" } else { "false" })
    }

    pub fn finish(&mut self) -> String {
        self.out.push('}');
        std::mem::take(&mut self.out)
    }
}

const JSON_DATE_FORMAT: &str = "yyyy-MM-ddTHH:mm:ss.fffffffZ";

/// Base64, as Convert.ToBase64String
pub fn base64(d: &[u8]) -> String {
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

/// An object graph as ServiceStack.Text sees it, for tools that serialize whole objects: written as JSON (`ToJson()`) or as
/// its laid out JSV (`Dump()`). A null property is left out
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number, as text
    Number(String),
    /// A float: its exponent's case depends on the format
    Float(f32),
    Text(String),
    List(Vec<Value>),
    Object(Vec<(std::borrow::Cow<'static, str>, Value)>),
}

impl Value {
    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    pub fn opt_text(s: Option<&str>) -> Value {
        s.map_or(Value::Null, Value::text)
    }

    pub fn number(n: impl std::fmt::Display) -> Value {
        Value::Number(n.to_string())
    }

    /// A time, as the tools' JsConfig writes every date: UTC with seven decimals and a Z
    pub fn time(t: crate::Timestamp) -> Value {
        Value::Text(t.format(JSON_DATE_FORMAT))
    }

    /// A DateTimeOffset that isn't nullable: ServiceStack leaves out its default, the minimum
    pub fn required_time(t: crate::Timestamp) -> Value {
        if t == crate::Timestamp::MIN { Value::Null } else { Value::time(t) }
    }

    pub fn opt_time(t: Option<crate::Timestamp>) -> Value {
        t.map_or(Value::Null, Value::time)
    }

    /// A byte[]
    pub fn bytes(d: &[u8]) -> Value {
        Value::Text(base64(d))
    }

    /// A Guid, from its usual text: ServiceStack writes it without dashes
    pub fn guid(text: &str) -> Value {
        Value::Text(text.replace('-', ""))
    }

    pub fn strings<'a>(list: impl IntoIterator<Item = &'a String>) -> Value {
        Value::List(list.into_iter().map(|s| Value::text(s.as_str())).collect())
    }

    /// An object from properties in order
    pub fn object(properties: Vec<(&'static str, Value)>) -> Value {
        Value::Object(properties.into_iter().map(|(n, v)| (n.into(), v)).collect())
    }

    /// `ToJson()`
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(n),
            Value::Float(f) => out.push_str(&crate::dotnet::dotnet_f32(*f).replace('E', "e")),
            Value::Text(s) => service_stack_string(out, s),
            Value::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Object(properties) => {
                out.push('{');
                let mut first = true;
                for (name, value) in properties {
                    if *value == Value::Null {
                        continue;
                    }
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    service_stack_string(out, name);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }

    fn write_jsv(&self, out: &mut String) {
        match self {
            Value::Null => {}
            Value::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
            Value::Number(n) => out.push_str(n),
            // the two extremes keep the lower case in JSV as well
            Value::Float(f) if *f == f32::MAX || *f == f32::MIN => out.push_str(&crate::dotnet::dotnet_f32(*f).replace('E', "e")),
            Value::Float(f) => out.push_str(&crate::dotnet::dotnet_f32(*f)),
            Value::Text(s) => out.push_str(&jsv_value(s)),
            Value::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_jsv(out);
                }
                out.push(']');
            }
            Value::Object(properties) => {
                out.push('{');
                let mut first = true;
                for (name, value) in properties {
                    if *value == Value::Null {
                        continue;
                    }
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push_str(&jsv_value(name));
                    out.push(':');
                    value.write_jsv(out);
                }
                out.push('}');
            }
        }
    }

    /// `Dump()`: ServiceStack's JSV format, laid out by its JsvFormatter
    pub fn dump(&self) -> String {
        let mut jsv = String::new();
        self.write_jsv(&mut jsv);
        jsv_format(&jsv)
    }
}

/// How ServiceStack writes a string in JSV: quoted when it has to be, and an empty one as two quotes
pub fn jsv_value(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if value.contains(['"', ':', ',', '{', '}', '[', ']', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// JsvFormatter.Format: braces make new lines even inside quotes; commas don't
pub fn jsv_format(text: &str) -> String {
    fn tab_line(out: &mut String, tabs: i32) {
        out.push('\n');
        for _ in 0..tabs {
            out.push('\t');
        }
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    let (mut tabs, mut first_key, mut in_string) = (0i32, true, false);
    let mut i = 0;
    while i < chars.len() {
        let current = chars[i];
        let previous = if i > 0 { chars[i - 1] } else { '\0' };
        let next = chars.get(i + 1).copied().unwrap_or('\0');
        i += 1;
        if current == '{' || current == '[' {
            if previous == ':' {
                if next == '}' || next == ']' {
                    out.push(current);
                    out.push(next);
                    i += 1;
                    continue;
                }
                tab_line(&mut out, tabs);
            }
            out.push(current);
            tabs += 1;
            tab_line(&mut out, tabs);
            first_key = true;
            continue;
        }
        if current == '}' || current == ']' {
            tabs -= 1;
            tab_line(&mut out, tabs);
            out.push(current);
            first_key = true;
            continue;
        }
        if current == '"' {
            in_string = !in_string;
        }
        if current == ',' && !in_string {
            out.push(current);
            tab_line(&mut out, tabs);
            first_key = true;
            continue;
        }
        out.push(current);
        if current == ':' && first_key {
            out.push(' ');
            first_key = false;
        }
    }
    out
}

#[cfg(test)]
mod value_tests {
    use super::*;

    #[test]
    fn nulls_are_left_out_and_empty_lists_stay_on_their_line() {
        let v = Value::object(vec![("A", Value::Null), ("B", Value::List(Vec::new())), ("C", Value::text("x: y")), ("D", Value::text("")), ("E", Value::Bool(true))]);
        assert_eq!(v.to_json(), r#"{"B":[],"C":"x: y","D":"","E":true}"#);
        assert_eq!(v.dump(), "{\n\tB: [],\n\tC: \"x: y\",\n\tD: \"\",\n\tE: True\n}");
    }

    #[test]
    fn floats_write_their_exponent_as_servicestack_does() {
        let object = |f: f32| Value::object(vec![("R", Value::Float(f))]);
        assert_eq!(object(3e-45).to_json(), r#"{"R":3e-45}"#);
        assert_eq!(object(1e20).to_json(), r#"{"R":1e+20}"#);
        assert_eq!(object(f32::NAN).to_json(), r#"{"R":NaN}"#);
        assert_eq!(object(f32::INFINITY).to_json(), r#"{"R":Infinity}"#);
        assert_eq!(object(3e-45).dump(), "{\n\tR: 3E-45\n}");
        assert_eq!(object(f32::MAX).dump(), "{\n\tR: 3.4028235e+38\n}");
    }

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn the_default_date_is_left_out_only_where_it_is_not_nullable() {
        assert_eq!(Value::required_time(crate::Timestamp::MIN), Value::Null);
        assert_eq!(Value::time(crate::Timestamp::MIN), Value::text("0001-01-01T00:00:00.0000000Z"));
    }
}
