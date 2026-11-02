//! The event as XML, as EvtxECmd always wrote it (an XmlDocument saved with 2 space indents and CRLF):
//! whitespace-only text is dropped, line breaks in text are CRLF, white space in attribute values is a space, xmlns
//! attributes are left out, and text in an element stops the indenting inside it.

use std::borrow::Cow;
use std::ops::Range;

use crate::binxml::render::{OutElement, OutNode, is_whitespace};

const NEW_LINE: &str = "\r\n";

/// A child as an XmlDocument loads it: adjacent text merged, whitespace-only text dropped
pub(crate) enum Loaded<'a> {
    Text(Cow<'a, str>),
    Element(&'a OutElement),
    CData(&'a str),
    Pi { target: &'a str, data: &'a str },
}

pub(crate) fn loaded_children(e: &OutElement) -> Vec<Loaded<'_>> {
    let mut result = Vec::with_capacity(e.children.len());
    let mut text: Option<Cow<str>> = None;

    fn flush<'a>(text: &mut Option<Cow<'a, str>>, result: &mut Vec<Loaded<'a>>) {
        if let Some(s) = text.take() {
            if !s.is_empty() && !is_whitespace(&s) {
                result.push(Loaded::Text(s));
            }
        }
    }

    for c in &e.children {
        match c {
            OutNode::Text(s) => match &mut text {
                None => text = Some(Cow::Borrowed(s)),
                Some(t) => t.to_mut().push_str(s),
            },
            OutNode::Element(child) => {
                flush(&mut text, &mut result);
                result.push(Loaded::Element(child));
            }
            OutNode::CData(s) => {
                flush(&mut text, &mut result);
                result.push(Loaded::CData(s));
            }
            OutNode::Pi { target, data } => {
                flush(&mut text, &mut result);
                result.push(Loaded::Pi { target, data });
            }
        }
    }
    flush(&mut text, &mut result);
    result
}

pub(crate) fn is_xmlns(name: &str) -> bool {
    name == "xmlns" || name.starts_with("xmlns:")
}

/// Writes the event; returns the XML and where `target` (when given) is in it
pub(crate) fn write(root: &OutElement, target: Option<&OutElement>) -> (String, Option<Range<usize>>) {
    let mut w = XmlWriter { out: String::with_capacity(1024), level: 0, mixed: false, mixed_stack: Vec::new(), last_was_text: true, target, span: None };
    w.element(root);
    (w.out, w.span)
}

struct XmlWriter<'a> {
    out: String,
    level: usize,
    mixed: bool,
    mixed_stack: Vec<bool>,
    last_was_text: bool,
    target: Option<&'a OutElement>,
    span: Option<Range<usize>>,
}

impl XmlWriter<'_> {
    fn element(&mut self, e: &OutElement) {
        if !self.mixed && !self.last_was_text {
            self.indent();
        }
        self.level += 1;
        self.mixed_stack.push(self.mixed);

        let start = self.out.len();
        self.out.push('<');
        self.out.push_str(&e.name);
        for (k, v) in &e.attributes {
            if is_xmlns(k) {
                continue;
            }
            self.out.push(' ');
            self.out.push_str(k);
            self.out.push_str("=\"");
            append_attribute(&mut self.out, v);
            self.out.push('"');
        }
        self.last_was_text = false;

        let children = loaded_children(e);
        if children.is_empty() {
            if e.empty_tag {
                self.out.push_str(" />");
            } else {
                self.out.push_str("></");
                self.out.push_str(&e.name);
                self.out.push('>');
            }
            self.level -= 1;
            self.mixed = self.mixed_stack.pop().unwrap();
            self.mark(e, start);
            return;
        }

        self.out.push('>');
        // the root element does not inherit mixed content; others do
        self.mixed = self.level != 1 && *self.mixed_stack.last().unwrap();
        let content_start = self.out.len();

        for c in &children {
            match c {
                Loaded::Text(s) => {
                    append_text(&mut self.out, s);
                    self.mixed = true;
                    self.last_was_text = true;
                }
                Loaded::Element(child) => self.element(child),
                Loaded::CData(s) => {
                    self.out.push_str("<![CDATA[");
                    self.out.push_str(&s.replace("]]>", "]]]]><![CDATA[>"));
                    self.out.push_str("]]>");
                    self.mixed = true;
                    self.last_was_text = false;
                }
                Loaded::Pi { target, data } => {
                    if !self.mixed && !self.last_was_text {
                        self.indent();
                    }
                    self.out.push_str("<?");
                    self.out.push_str(target);
                    if !data.is_empty() {
                        self.out.push(' ');
                        self.out.push_str(data);
                    }
                    self.out.push_str("?>");
                    self.last_was_text = false;
                }
            }
        }

        self.level -= 1;
        if !self.mixed && self.out.len() != content_start && !self.last_was_text {
            self.indent();
        }
        self.mixed = self.mixed_stack.pop().unwrap();
        self.out.push_str("</");
        self.out.push_str(&e.name);
        self.out.push('>');
        self.last_was_text = false;
        self.mark(e, start);
    }

    fn mark(&mut self, e: &OutElement, start: usize) {
        if self.target.is_some_and(|t| std::ptr::eq(t, e)) {
            self.span = Some(start..self.out.len());
        }
    }

    fn indent(&mut self) {
        self.out.push_str(NEW_LINE);
        self.out.extend(std::iter::repeat_n(' ', self.level * 2));
    }
}

fn append_text(out: &mut String, s: &str) {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str(NEW_LINE);
            }
            '\n' => out.push_str(NEW_LINE),
            _ => out.push(valid_char(c)),
        }
    }
}

fn append_attribute(out: &mut String, s: &str) {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => {
                // attribute value normalization: a line break (CRLF counts once) or tab is a space
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' | '\t' => out.push(' '),
            _ => out.push(valid_char(c)),
        }
    }
}

/// Characters XML cannot hold (other control characters, U+FFFE/U+FFFF) become U+FFFD. Strings here never hold lone
/// surrogates: they are replaced when UTF-16 is decoded.
fn valid_char(c: char) -> char {
    if (c >= '\u{20}' && c != '\u{FFFE}' && c != '\u{FFFF}') || c == '\t' { c } else { '\u{FFFD}' }
}

fn needs_change(s: &str) -> bool {
    s.chars().any(|c| c < '\u{20}' || c == '\u{FFFE}' || c == '\u{FFFF}')
}

/// Text as an XML parser reads back what is written: line breaks are LF, impossible characters U+FFFD
pub(crate) fn text_value(s: &str) -> Cow<'_, str> {
    line_breaks(s, "\n")
}

/// Text as an XPathDocument of the written XML has it: that reader does not normalize line endings, so line breaks
/// stay CRLF as written; impossible characters U+FFFD
pub(crate) fn xpath_text_value(s: &str) -> Cow<'_, str> {
    line_breaks(s, "\r\n")
}

fn line_breaks<'a>(s: &'a str, nl: &str) -> Cow<'a, str> {
    if !needs_change(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str(nl);
            }
            '\n' => out.push_str(nl),
            _ => out.push(valid_char(c)),
        }
    }
    Cow::Owned(out)
}

/// An attribute value as an XML parser reads back what is written: line breaks and tabs are spaces
pub(crate) fn attribute_value(s: &str) -> Cow<'_, str> {
    if !needs_change(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' | '\t' => out.push(' '),
            _ => out.push(valid_char(c)),
        }
    }
    Cow::Owned(out)
}
