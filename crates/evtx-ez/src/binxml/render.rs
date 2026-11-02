//! Resolves template instances and substitutions into a tree of [`OutElement`]s: the event as XML would show it.

use super::parser::{Attribute, BinXmlParser, Name, Node};
use super::value::{self, Value, types};
use crate::error::{ParseError, Result};

const MAX_DEPTH: usize = 32;

/// A rendered element: substitutions resolved, ready to write or query
#[derive(Debug, Clone, PartialEq)]
pub struct OutElement {
    pub name: Name,
    pub attributes: Vec<(Name, String)>,
    pub children: Vec<OutNode>,
    /// Closed with CloseEmptyElementToken: `<x />` rather than `<x></x>` (JSON: null rather than "")
    pub empty_tag: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutNode {
    Text(String),
    Element(OutElement),
    CData(String),
    Pi { target: Name, data: String },
}

impl OutElement {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| &**k == name).map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&OutElement> {
        self.elements().find(|e| &*e.name == name)
    }

    pub fn elements(&self) -> impl Iterator<Item = &OutElement> {
        self.children.iter().filter_map(|c| match c {
            OutNode::Element(e) => Some(e),
            _ => None,
        })
    }

    /// The text directly in the element, as the XML parser that used to read it saw it (whitespace-only is empty)
    pub fn text(&self) -> String {
        let mut s = String::new();
        for c in &self.children {
            if let OutNode::Text(t) = c {
                s.push_str(t);
            }
        }
        if is_whitespace(&s) { String::new() } else { s }
    }
}

pub(crate) fn is_whitespace(s: &str) -> bool {
    s.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Renders a record's nodes; the root element is the first element in the output
pub(crate) fn render_record(parser: &mut BinXmlParser, nodes: &[Node]) -> Result<Vec<OutNode>> {
    let mut output = Vec::new();
    render(parser, nodes, None, &mut output, 0)?;
    Ok(output)
}

fn render(parser: &mut BinXmlParser, nodes: &[Node], values: Option<&[Value]>, output: &mut Vec<OutNode>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(ParseError::new("Template instances nested too deeply", -1, "TemplateInstance"));
    }
    for node in nodes {
        match node {
            Node::TemplateInstance { template, values } => {
                let template = template.clone();
                let values = values.clone();
                render(parser, &template.nodes, Some(&values), output, depth + 1)?;
            }
            Node::Element(e) => {
                // MS-EVEN6 2.2.12.1 says an element whose dependency value is NULL is not rendered, but EvtxECmd
                // always rendered them (e.g. an empty <Binary></Binary>), as the Rust evtx parser does
                let mut element =
                    OutElement { name: e.name.clone(), attributes: Vec::new(), children: Vec::new(), empty_tag: e.empty_tag };
                for a in &e.attributes {
                    if let Some(v) = attribute_value(parser.bytes(), a, values) {
                        element.attributes.push((a.name.clone(), v));
                    }
                }
                render(parser, &e.content, values, &mut element.children, depth)?;
                output.push(OutNode::Element(element));
            }
            Node::Text(t) => output.push(OutNode::Text(t.clone())),
            Node::Substitution { index, .. } => render_substitution(parser, *index, values, output, depth)?,
            Node::CharRef(c) => output.push(OutNode::Text(char_ref(*c).to_string())),
            Node::EntityRef(name) => output.push(OutNode::Text(entity(name))),
            Node::CData(t) => output.push(OutNode::CData(t.clone())),
            Node::Pi { target, data } => output.push(OutNode::Pi { target: target.clone(), data: data.clone() }),
        }
    }
    Ok(())
}

fn render_substitution(parser: &mut BinXmlParser, index: u16, values: Option<&[Value]>, output: &mut Vec<OutNode>, depth: usize) -> Result<()> {
    let Some(v) = values.and_then(|vs| vs.get(index as usize)).copied() else {
        return Ok(());
    };
    match v.ty {
        types::NULL => {}
        types::BINXML => {
            // MS-EVEN6 2.2.12.3: a BinXml value is rendered in place (typically a template instance of its own)
            if v.size > 0 {
                let (nested, _) = parser.parse_fragment(v.offset, v.offset + v.size, false, depth + 1)?;
                render(parser, &nested, None, output, depth + 1)?;
            }
        }
        _ => output.push(OutNode::Text(value::format(parser.bytes(), v, false))),
    }
    Ok(())
}

/// None when the attribute is not rendered: its value is only optional substitutions that are NULL
fn attribute_value(b: &[u8], a: &Attribute, values: Option<&[Value]>) -> Option<String> {
    let lookup = |index: u16| values.and_then(|vs| vs.get(index as usize)).filter(|v| v.ty != types::NULL);

    if a.value.len() == 1 {
        match &a.value[0] {
            Node::Text(t) => return Some(t.clone()),
            Node::Substitution { index, optional, .. } => {
                return match lookup(*index) {
                    Some(v) => Some(value::format(b, *v, false)),
                    None if *optional => None,
                    None => Some(String::new()),
                };
            }
            _ => {}
        }
    }

    let mut s = String::new();
    let mut any = false;
    for part in &a.value {
        match part {
            Node::Text(t) => {
                s.push_str(t);
                any = true;
            }
            Node::Substitution { index, optional, .. } => {
                if let Some(v) = lookup(*index) {
                    s.push_str(&value::format(b, *v, false));
                    any = true;
                } else if !optional {
                    any = true;
                }
            }
            Node::CharRef(c) => {
                s.push(char_ref(*c));
                any = true;
            }
            Node::EntityRef(name) => {
                s.push_str(&entity(name));
                any = true;
            }
            _ => {}
        }
    }
    if any || a.value.is_empty() { Some(s) } else { None }
}

/// A character reference; a lone surrogate (which XML cannot hold) is U+FFFD
fn char_ref(c: u16) -> char {
    char::from_u32(c as u32).unwrap_or('\u{FFFD}')
}

fn entity(name: &str) -> String {
    match name {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" => "'".into(),
        _ => format!("&{name};"),
    }
}
