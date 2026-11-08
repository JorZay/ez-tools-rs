//! JSON as System.Text.Json's JsonDocument reads it with its default options: strict RFC 8259 (no comments, no trailing commas,
//! nothing after the value), at most 64 levels deep. Strings are unescaped only when asked for, as JsonElement.GetString does,
//! which is when an escaped unpaired surrogate is an error.

/// A value, with where its text is in the document
#[derive(Debug)]
pub struct Node {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub enum Kind {
    /// Each property: the span of its name inside the quotes, and its value
    Object(Vec<((usize, usize), Node)>),
    Array(Vec<Node>),
    /// The span inside the quotes, still escaped
    String(usize, usize),
    Number,
    True,
    False,
    Null,
}

const MAX_DEPTH: usize = 64;

/// A parsed document: its text and its root value
pub struct Document<'a> {
    pub text: &'a str,
    pub root: Node,
}

impl<'a> Document<'a> {
    /// JsonDocument.Parse
    pub fn parse(text: &'a str) -> Result<Document<'a>, String> {
        let mut p = Parser { b: text.as_bytes(), i: 0 };
        p.ws();
        let root = p.value(0)?;
        p.ws();
        if p.i < p.b.len() {
            return Err(format!("'{}' is invalid after a single JSON value. Expected end of data. Position {}.", p.shown(), p.i));
        }
        Ok(Document { text, root })
    }

    /// The JSON text of a value (JsonElement.GetRawText)
    pub fn raw(&self, node: &Node) -> &'a str {
        &self.text[node.start..node.end]
    }

    /// A property by name, in any case (StringComparison.OrdinalIgnoreCase): its string, the JSON text of another value, or
    /// None for null or when it isn't there. Names are unescaped in turn until one matches, and that can fail
    pub fn property(&self, object: &Node, name: &str) -> Result<Option<String>, String> {
        let Kind::Object(properties) = &object.kind else { return Ok(None) };
        let wanted = ez_common::dotnet::ordinal_ignore_case(name);
        for ((start, end), value) in properties {
            let key = unescape(&self.text[*start..*end])?;
            if ez_common::dotnet::ordinal_ignore_case(&key) == wanted {
                return match value.kind {
                    Kind::String(s, e) => unescape(&self.text[s..e]).map(Some),
                    Kind::Null => Ok(None),
                    _ => Ok(Some(self.raw(value).to_string())),
                };
            }
        }
        Ok(None)
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn shown(&self) -> String {
        match self.b.get(self.i) {
            Some(c) if c.is_ascii_graphic() => (*c as char).to_string(),
            Some(c) => format!("0x{c:02X}"),
            None => "end of data".to_string(),
        }
    }

    fn error<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("'{}' {what}. Position {}.", self.shown(), self.i))
    }

    fn value(&mut self, depth: usize) -> Result<Node, String> {
        let start = self.i;
        let kind = match self.b.get(self.i) {
            None => return Err("The input does not contain any JSON tokens, or ends before a value.".to_string()),
            Some(b'{') => {
                if depth >= MAX_DEPTH {
                    return Err(format!("The maximum configured depth of {MAX_DEPTH} has been exceeded. Position {}.", self.i));
                }
                self.i += 1;
                let mut properties = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        if self.b.get(self.i) != Some(&b'"') {
                            return self.error("is an invalid start of a property name. Expected a '\"'");
                        }
                        let name = self.string()?;
                        self.ws();
                        if self.b.get(self.i) != Some(&b':') {
                            return self.error("is invalid after a property name. Expected a ':'");
                        }
                        self.i += 1;
                        self.ws();
                        let value = self.value(depth + 1)?;
                        properties.push((name, value));
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => {
                                self.i += 1;
                                self.ws();
                                if self.b.get(self.i) == Some(&b'}') {
                                    return Err(format!("The JSON object contains a trailing comma at the end. Position {}.", self.i));
                                }
                            }
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            None => return Err("There is an open JSON object or array that should be closed.".to_string()),
                            _ => return self.error("is invalid after a value. Expected either ',', '}', or ']'"),
                        }
                    }
                }
                Kind::Object(properties)
            }
            Some(b'[') => {
                if depth >= MAX_DEPTH {
                    return Err(format!("The maximum configured depth of {MAX_DEPTH} has been exceeded. Position {}.", self.i));
                }
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        if self.i >= self.b.len() {
                            return Err("There is an open JSON object or array that should be closed.".to_string());
                        }
                        items.push(self.value(depth + 1)?);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => {
                                self.i += 1;
                                self.ws();
                                if self.b.get(self.i) == Some(&b']') {
                                    return Err(format!("The JSON array contains a trailing comma at the end. Position {}.", self.i));
                                }
                            }
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            None => return Err("There is an open JSON object or array that should be closed.".to_string()),
                            _ => return self.error("is invalid after a value. Expected either ',', '}', or ']'"),
                        }
                    }
                }
                Kind::Array(items)
            }
            Some(b'"') => {
                let (s, e) = self.string()?;
                Kind::String(s, e)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
                Kind::Number
            }
            Some(b't') => {
                self.literal(b"true")?;
                Kind::True
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Kind::False
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Kind::Null
            }
            _ => return self.error("is an invalid start of a value"),
        };
        Ok(Node { kind, start, end: self.i })
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), String> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(())
        } else {
            self.error("is an invalid JSON literal")
        }
    }

    /// A string; the span inside its quotes
    fn string(&mut self) -> Result<(usize, usize), String> {
        self.i += 1;
        let start = self.i;
        loop {
            match self.b.get(self.i) {
                None => return Err("Expected end of string, but instead reached end of data.".to_string()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok((start, self.i - 1));
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.b.get(self.i) {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 1,
                        Some(b'u') => {
                            self.i += 1;
                            for _ in 0..4 {
                                match self.b.get(self.i) {
                                    Some(c) if c.is_ascii_hexdigit() => self.i += 1,
                                    _ => return self.error("is not a hex digit following '\\u' within a JSON string"),
                                }
                            }
                        }
                        _ => return self.error("is an invalid escapable character within a JSON string"),
                    }
                }
                Some(c) if *c < 0x20 => return self.error("is invalid within a JSON string. The string should be correctly escaped"),
                Some(_) => self.i += 1,
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<(), String> {
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => {
                self.i += 1;
                if self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                    return self.error("follows an invalid leading zero");
                }
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return self.error("is invalid within a number, immediately after a sign character"),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return self.error("is invalid within a number, immediately after a decimal point");
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return self.error("is invalid within a number, immediately after an exponent");
            }
        }
        match self.b.get(self.i) {
            None | Some(b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}' | b']') => Ok(()),
            _ => self.error("is an invalid end of a number. Expected a delimiter"),
        }
    }
}

/// The text of a JSON string, as GetString gives it: an unpaired surrogate written as an escape is an error
pub fn unescape(raw: &str) -> Result<String, String> {
    if !raw.contains('\\') {
        return Ok(raw.to_string());
    }
    let b = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    let hex = |at: usize| u32::from_str_radix(&raw[at..at + 4], 16).unwrap_or(0);
    while i < b.len() {
        let rest = &raw[i..];
        let Some(slash) = rest.find('\\') else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..slash]);
        i += slash + 1;
        let c = b[i];
        i += 1;
        match c {
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let unit = hex(i);
                i += 4;
                match unit {
                    0xD800..=0xDBFF => {
                        if b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u') {
                            let low = hex(i + 2);
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(format!("Cannot read invalid UTF-16 JSON text as string. Invalid surrogate value: '0x{low:X}'."));
                            }
                            i += 6;
                            out.push(char::from_u32(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)).unwrap_or('\u{FFFD}'));
                        } else {
                            return Err("Cannot read incomplete UTF-16 JSON text as string with missing low surrogate.".to_string());
                        }
                    }
                    0xDC00..=0xDFFF => return Err(format!("Cannot read invalid UTF-16 JSON text as string. Invalid surrogate value: '0x{unit:X}'.")),
                    _ => out.push(char::from_u32(unit).unwrap_or('\u{FFFD}')),
                }
            }
            other => out.push(other as char),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> bool {
        Document::parse(text).is_ok()
    }

    #[test]
    fn strict_json() {
        for good in ["{}", " [ ] ", "1", "-0.5e+3", "\"\\u00e9\"", "[[1],{\"a\":null}]", "{\"a\":1,\"a\":2}", "\"\u{7f}\""] {
            assert!(ok(good), "{good}");
        }
        for bad in ["", "{", "{\"a\":1,}", "[1,]", "01", "1.", "-", "1e", "NaN", "tru", "'a'", "{a:1}", "\"\u{1}\"", "\"\\x\"", "\"\\u12\"", "1 2", "{}/**/", "\u{feff}{}"] {
            assert!(!ok(bad), "{bad}");
        }
    }

    #[test]
    fn depth_is_at_most_64() {
        assert!(ok(&format!("{}{}", "[".repeat(64), "]".repeat(64))));
        assert!(!ok(&format!("{}{}", "[".repeat(65), "]".repeat(65))));
    }

    #[test]
    fn properties_as_system_text_json_gives_them() {
        let text = r#"{"A":"x\n\u00e9\ud83d\ude00","b":{"c" : [1, 2]},"n":null,"bad\ud800":1,"z":5}"#;
        let doc = Document::parse(text).unwrap();
        assert_eq!(doc.property(&doc.root, "a").unwrap().as_deref(), Some("x\n\u{e9}\u{1F600}"));
        assert_eq!(doc.property(&doc.root, "B").unwrap().as_deref(), Some(r#"{"c" : [1, 2]}"#));
        assert_eq!(doc.property(&doc.root, "n").unwrap(), None);
        // the bad name comes before z
        assert!(doc.property(&doc.root, "z").is_err());
        assert!(unescape("\\udc00").is_err());
        assert!(unescape("\\ud800x").is_err());
    }
}
