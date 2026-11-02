//! JSON writers.
//!
//! [`element`] writes an element exactly as Json.NET's SerializeXmlNode wrote the XmlDocument EvtxECmd used to load
//! the payload into: attributes as "@Name", text as "#text", children with the same name grouped into an array (at
//! the first one's place), an element with only text as that text, `<x/>` as null and `<x></x>` as "".
//!

use std::collections::HashMap;

use super::xml::{Loaded, attribute_value, is_xmlns, loaded_children, text_value, xpath_text_value};
use crate::binxml::render::OutElement;

/// `{"Name": ...}` for the element. `crlf`: line breaks in text as CRLF (as the whole event's XML had them when it
/// was loaded) rather than LF (as the payload had them, after the XmlReader that extracted it).
pub(crate) fn element(root: &OutElement, crlf: bool) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    json_net_string(&mut out, &root.name);
    out.push(':');
    append_element(&mut out, root, crlf);
    out.push('}');
    out
}

fn append_element(out: &mut String, e: &OutElement, crlf: bool) {
    let children = loaded_children(e);
    let attributes: Vec<_> = e.attributes.iter().filter(|(k, _)| !is_xmlns(k)).collect();

    if attributes.is_empty() && children.len() == 1 {
        if let Loaded::Text(t) = &children[0] {
            json_net_string(out, &text(t, crlf));
            return;
        }
    }
    if attributes.is_empty() && children.is_empty() {
        out.push_str(if e.empty_tag { "null" } else { "\"\"" });
        return;
    }

    out.push('{');
    let mut first = true;
    for (k, v) in attributes {
        comma(out, &mut first);
        out.push_str("\"@");
        json_net_escape(out, k);
        out.push_str("\":");
        json_net_string(out, &attribute_value(v));
    }
    append_grouped(out, &children, &mut first, crlf);
    out.push('}');
}

/// Children grouped by name in the order each name first appears; a name used more than once is an array
fn append_grouped(out: &mut String, children: &[Loaded], first: &mut bool, crlf: bool) {
    if children.len() == 1 {
        comma(out, first);
        append_named(out, &children[0], crlf);
        return;
    }

    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<&Loaded>> = HashMap::new();
    for c in children {
        let name = property_name(c);
        match groups.get_mut(&name) {
            Some(g) => g.push(c),
            None => {
                groups.insert(name.clone(), vec![c]);
                order.push(name);
            }
        }
    }

    for name in &order {
        let group = &groups[name];
        comma(out, first);
        if group.len() == 1 {
            append_named(out, group[0], crlf);
            continue;
        }
        json_net_string(out, name);
        out.push_str(":[");
        for (i, c) in group.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            append_value(out, c, crlf);
        }
        out.push(']');
    }
}

fn append_named(out: &mut String, node: &Loaded, crlf: bool) {
    json_net_string(out, &property_name(node));
    out.push(':');
    append_value(out, node, crlf);
}

fn append_value(out: &mut String, node: &Loaded, crlf: bool) {
    match node {
        Loaded::Element(e) => append_element(out, e, crlf),
        Loaded::Text(s) => json_net_string(out, &text(s, crlf)),
        Loaded::CData(s) => json_net_string(out, s),
        Loaded::Pi { data, .. } => json_net_string(out, data),
    }
}

fn property_name(node: &Loaded) -> String {
    match node {
        Loaded::Element(e) => e.name.to_string(),
        Loaded::CData(_) => "#cdata-section".into(),
        Loaded::Pi { target, .. } => format!("?{target}"),
        Loaded::Text(_) => "#text".into(),
    }
}

fn text(s: &str, crlf: bool) -> std::borrow::Cow<'_, str> {
    if crlf { xpath_text_value(s) } else { text_value(s) }
}

fn comma(out: &mut String, first: &mut bool) {
    if *first {
        *first = false;
    } else {
        out.push(',');
    }
}

/// A JSON string as Json.NET escapes it by default
pub(crate) fn json_net_string(out: &mut String, s: &str) {
    out.push('"');
    json_net_escape(out, s);
    out.push('"');
}

fn json_net_escape(out: &mut String, s: &str) {
    use std::fmt::Write;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{85}' | '\u{2028}' | '\u{2029}' => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
}

pub use ez_common::json::{ServiceStackObject, service_stack_string};
