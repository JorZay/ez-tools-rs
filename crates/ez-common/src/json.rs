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
