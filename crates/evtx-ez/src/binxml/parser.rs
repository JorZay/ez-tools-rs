//! BinXml (MS-EVEN6 2.2.12) parsed straight from a chunk's bytes. Names and template definitions are stored in the
//! chunk: a name or template definition offset equal to the current position means the data follows inline,
//! otherwise it was defined earlier in the chunk at that offset. Elements in template definitions have a 2 byte
//! dependency id; elements written directly in a record or in a BinXml value do not.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use super::value::{self, Value, types};
use crate::error::{ParseError, Result};

/// Nested BinXml values and templates deeper than this are treated as corrupt
const MAX_DEPTH: usize = 32;

pub(crate) type Name = Arc<str>;

/// A BinXml node as parsed from a record, a template definition or a BinXml value
#[derive(Debug)]
pub(crate) enum Node {
    Element(Element),
    /// ValueText: an inline value (normally a string; other types appear in records without templates)
    Text(String),
    /// The value type is in the substitution too, but the value's own type is what is used
    Substitution { index: u16, optional: bool },
    CharRef(u16),
    EntityRef(Name),
    CData(String),
    Pi { target: Name, data: String },
    /// A template instance: the template definition and the substitution values for it
    TemplateInstance { template: Rc<TemplateDefinition>, values: Rc<[Value]> },
}

#[derive(Debug)]
pub(crate) struct Element {
    pub name: Name,
    pub attributes: Vec<Attribute>,
    pub content: Vec<Node>,
    /// Closed with CloseEmptyElementToken (written as `<Name />`)
    pub empty_tag: bool,
}

#[derive(Debug)]
pub(crate) struct Attribute {
    pub name: Name,
    /// Text, substitutions, character and entity references
    pub value: Vec<Node>,
}

/// A template definition, parsed once per chunk
#[derive(Debug)]
pub(crate) struct TemplateDefinition {
    pub nodes: Vec<Node>,
}

pub(crate) struct BinXmlParser<'a> {
    b: &'a [u8],
    names: HashMap<usize, Name>,
    templates: HashMap<usize, Rc<TemplateDefinition>>,
    templates_in_progress: HashSet<usize>,
}

fn err<T>(message: impl Into<String>, offset: usize, field: &'static str) -> Result<T> {
    Err(ParseError::new(message, offset, field))
}

impl<'a> BinXmlParser<'a> {
    pub fn new(chunk: &'a [u8]) -> Self {
        BinXmlParser { b: chunk, names: HashMap::new(), templates: HashMap::new(), templates_in_progress: HashSet::new() }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.b
    }

    /// The number of template definitions the records used
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Parses a fragment (a record's event data or a BinXml value) from start up to end; also returns where parsing
    /// stopped (after the EOF token, or end)
    pub fn parse_fragment(&mut self, start: usize, end: usize, in_template: bool, depth: usize) -> Result<(Vec<Node>, usize)> {
        if depth > MAX_DEPTH {
            return err("BinXml nested too deeply", start, "BinXml");
        }
        let end = end.min(self.b.len());
        let mut nodes = Vec::new();
        let mut pos = start;

        while pos < end {
            let token = self.b[pos];
            match token & 0xBF {
                0x00 => return Ok((nodes, pos + 1)),
                // FragmentHeader: token, major, minor, flags
                0x0F => pos += 4,
                0x0C => nodes.push(self.parse_template_instance(&mut pos, end, depth)?),
                0x01 => nodes.push(Node::Element(self.parse_element(&mut pos, end, in_template, depth)?)),
                0x0A => nodes.push(self.parse_pi(&mut pos, end)?),
                _ => return err(format!("Unexpected BinXml token 0x{token:02X} at the top of a fragment"), pos, "BinXml"),
            }
        }
        Ok((nodes, pos))
    }

    fn parse_element(&mut self, pos: &mut usize, end: usize, in_template: bool, depth: usize) -> Result<Element> {
        if depth > MAX_DEPTH {
            return err("BinXml elements nested too deeply", *pos, "BinXml");
        }
        let token = self.b[*pos];
        *pos += 1;
        let has_attributes = token & 0x40 != 0;

        if in_template {
            // the dependency id (MS-EVEN6 says an element whose dependency value is NULL is not rendered, but
            // EvtxECmd always rendered them, as the Rust evtx parser does)
            self.u16(*pos, end)?;
            *pos += 2;
        }

        // the data size is bytes after it, including the end token; checked against what is parsed
        let data_size = self.u32(*pos, end)? as usize;
        *pos += 4;
        let element_end = *pos + data_size;
        if element_end > end {
            return err(format!("Element of 0x{data_size:X} bytes runs past the end of its data"), *pos, "OpenStartElement");
        }

        let name = self.read_name(pos, end)?;
        let mut element = Element { name, attributes: Vec::new(), content: Vec::new(), empty_tag: false };

        if has_attributes {
            let list_size = self.u32(*pos, end)? as usize;
            *pos += 4;
            let list_end = *pos + list_size;
            if list_end > element_end {
                return err("Attribute list runs past the end of its element", *pos, "AttributeList");
            }
            while *pos < list_end {
                if self.b[*pos] & 0xBF != 0x06 {
                    return err(format!("Expected an attribute, found token 0x{:02X}", self.b[*pos]), *pos, "Attribute");
                }
                *pos += 1;
                let name = self.read_name(pos, end)?;
                let mut value = Vec::new();
                self.parse_attribute_value(pos, list_end, &mut value)?;
                element.attributes.push(Attribute { name, value });
            }
        }

        let close = self.byte(*pos, end)?;
        *pos += 1;
        match close {
            0x03 => {
                element.empty_tag = true;
                return Ok(element);
            }
            0x02 => {}
            _ => return err(format!("Expected the end of a start tag, found token 0x{close:02X}"), *pos - 1, "CloseStartElement"),
        }

        self.parse_content(pos, element_end, &mut element.content, in_template, depth)?;
        Ok(element)
    }

    fn parse_attribute_value(&mut self, pos: &mut usize, end: usize, value: &mut Vec<Node>) -> Result<()> {
        while *pos < end {
            match self.b[*pos] & 0xBF {
                0x05 => value.push(self.parse_value_text(pos, end)?),
                0x0D | 0x0E => value.push(self.parse_substitution(pos, end)?),
                0x08 => value.push(self.parse_char_ref(pos, end)?),
                0x09 => {
                    *pos += 1;
                    value.push(Node::EntityRef(self.read_name(pos, end)?));
                }
                // the next attribute
                _ => return Ok(()),
            }
        }
        Ok(())
    }

    fn parse_content(&mut self, pos: &mut usize, end: usize, content: &mut Vec<Node>, in_template: bool, depth: usize) -> Result<()> {
        while *pos < end {
            let token = self.b[*pos];
            match token & 0xBF {
                // EndElementToken
                0x04 => {
                    *pos += 1;
                    return Ok(());
                }
                0x01 => content.push(Node::Element(self.parse_element(pos, end, in_template, depth + 1)?)),
                0x05 => content.push(self.parse_value_text(pos, end)?),
                0x0D | 0x0E => content.push(self.parse_substitution(pos, end)?),
                0x07 => {
                    *pos += 1;
                    content.push(Node::CData(self.read_length_prefixed_string(pos, end)?));
                }
                0x08 => content.push(self.parse_char_ref(pos, end)?),
                0x09 => {
                    *pos += 1;
                    content.push(Node::EntityRef(self.read_name(pos, end)?));
                }
                0x0A => content.push(self.parse_pi(pos, end)?),
                0x0C => content.push(self.parse_template_instance(pos, end, depth + 1)?),
                0x0F => *pos += 4,
                _ => return err(format!("Unexpected BinXml token 0x{token:02X} in element content"), *pos, "Content"),
            }
        }
        err("Element has no end", *pos, "EndElement")
    }

    fn parse_char_ref(&mut self, pos: &mut usize, end: usize) -> Result<Node> {
        *pos += 1;
        let value = self.u16(*pos, end)?;
        *pos += 2;
        Ok(Node::CharRef(value))
    }

    fn parse_pi(&mut self, pos: &mut usize, end: usize) -> Result<Node> {
        *pos += 1;
        let target = self.read_name(pos, end)?;
        let mut data = String::new();
        if *pos < end && self.b[*pos] == 0x0B {
            *pos += 1;
            data = self.read_length_prefixed_string(pos, end)?;
        }
        Ok(Node::Pi { target, data })
    }

    fn parse_substitution(&mut self, pos: &mut usize, end: usize) -> Result<Node> {
        let optional = self.b[*pos] & 0xBF == 0x0E;
        *pos += 1;
        let index = self.u16(*pos, end)?;
        *pos += 2;
        self.byte(*pos, end)?;
        *pos += 1;
        Ok(Node::Substitution { index, optional })
    }

    /// ValueText: a type, then the value (strings are length prefixed; other types have their fixed size)
    fn parse_value_text(&mut self, pos: &mut usize, end: usize) -> Result<Node> {
        *pos += 1;
        let ty = self.byte(*pos, end)?;
        *pos += 1;

        if ty == types::STRING {
            return Ok(Node::Text(self.read_length_prefixed_string(pos, end)?));
        }

        use types::*;
        let size = match ty {
            NULL => 0,
            INT8 | UINT8 => 1,
            INT16 | UINT16 => 2,
            INT32 | UINT32 | REAL32 | HEX_INT32 | BOOL => 4,
            INT64 | UINT64 | REAL64 | HEX_INT64 | FILETIME | SIZE_T => 8,
            GUID | SYSTIME => 16,
            SID => 8 + 4 * self.byte(*pos + 1, end)? as usize,
            _ => return err(format!("Inline value of type {} has no size", type_name(ty)), *pos, "ValueText"),
        };

        if *pos + size > end {
            return err(format!("Inline {} value runs past the end of its data", type_name(ty)), *pos, "ValueText");
        }

        let text = value::format(self.b, Value { ty, offset: *pos, size }, true);
        *pos += size;
        Ok(Node::Text(text))
    }

    fn parse_template_instance(&mut self, pos: &mut usize, end: usize, depth: usize) -> Result<Node> {
        // token, an unknown byte, the template id, the definition's offset
        *pos += 2;
        let template_id = self.u32(*pos, end)?;
        *pos += 4;
        let definition_offset = self.u32(*pos, end)? as usize;
        *pos += 4;

        let template = if definition_offset == *pos {
            // defined here: next template offset, GUID, data size, data
            let data_size = self.u32(*pos + 20, end)? as usize;
            let template = self.get_template(definition_offset, depth)?;
            *pos += 24 + data_size;
            template
        } else {
            self.get_template(definition_offset, depth)?
        };

        let count = self.u32(*pos, end)? as usize;
        *pos += 4;
        if count > (end - *pos) / 4 {
            return err(
                format!("Template instance has {count} substitution values, more than fit in its data (template id 0x{template_id:X})"),
                *pos,
                "TemplateInstanceData",
            );
        }

        let mut values = Vec::with_capacity(count);
        let descriptor = *pos;
        *pos += count * 4;
        for i in 0..count {
            let size = self.u16(descriptor + i * 4, end)? as usize;
            let ty = self.b[descriptor + i * 4 + 2];
            if *pos + size > end {
                return err(
                    format!("Substitution value {i} ({}, 0x{size:X} bytes) runs past the end of the record", type_name(ty)),
                    *pos,
                    "Value",
                );
            }
            values.push(Value { ty, offset: *pos, size });
            *pos += size;
        }

        Ok(Node::TemplateInstance { template, values: values.into() })
    }

    /// The template definition at offset in the chunk: next template offset, GUID, data size, data
    fn get_template(&mut self, offset: usize, depth: usize) -> Result<Rc<TemplateDefinition>> {
        if let Some(t) = self.templates.get(&offset) {
            return Ok(t.clone());
        }
        if offset < 0x200 || offset > i32::MAX as usize || offset + 24 > self.b.len() {
            return err(format!("Template definition offset 0x{offset:X} is outside the chunk"), offset, "TemplateDefinition");
        }
        if !self.templates_in_progress.insert(offset) {
            return err(format!("Template definition at 0x{offset:X} refers to itself"), offset, "TemplateDefinition");
        }

        let result = (|| {
            let data_size = self.u32(offset + 20, self.b.len())? as usize;
            let data_start = offset + 24;
            if data_size > i32::MAX as usize || data_start + data_size > self.b.len() {
                return err(
                    format!("Template definition at 0x{offset:X} (0x{data_size:X} bytes) runs past the end of the chunk"),
                    offset,
                    "TemplateDefinition",
                );
            }
            let (nodes, _) = self.parse_fragment(data_start, data_start + data_size, true, depth + 1)?;
            let template = Rc::new(TemplateDefinition { nodes });
            self.templates.insert(offset, template.clone());
            Ok(template)
        })();

        self.templates_in_progress.remove(&offset);
        result
    }

    /// A name: its chunk offset, and when that is the current position, the name itself inline
    fn read_name(&mut self, pos: &mut usize, end: usize) -> Result<Name> {
        let offset = self.u32(*pos, end)? as usize;
        *pos += 4;
        let name = self.get_name(offset)?;
        if offset == *pos {
            // next string offset, hash, character count, characters, NUL
            *pos += 8 + self.u16(*pos + 6, end)? as usize * 2 + 2;
        }
        Ok(name)
    }

    fn get_name(&mut self, offset: usize) -> Result<Name> {
        if let Some(n) = self.names.get(&offset) {
            return Ok(n.clone());
        }
        if offset > i32::MAX as usize || offset + 8 > self.b.len() {
            return err(format!("Name offset 0x{offset:X} is outside the chunk"), offset, "Name");
        }
        let chars = u16::from_le_bytes([self.b[offset + 6], self.b[offset + 7]]) as usize;
        if offset + 8 + chars * 2 > self.b.len() {
            return err(format!("Name at 0x{offset:X} ({chars} characters) runs past the end of the chunk"), offset, "Name");
        }
        let name: Name = value::utf16(&self.b[offset + 8..offset + 8 + chars * 2]).into();
        self.names.insert(offset, name.clone());
        Ok(name)
    }

    fn read_length_prefixed_string(&mut self, pos: &mut usize, end: usize) -> Result<String> {
        let chars = self.u16(*pos, end)? as usize;
        *pos += 2;
        if *pos + chars * 2 > end {
            return err(format!("String of {chars} characters runs past the end of its data"), *pos, "String");
        }
        let s = value::utf16(&self.b[*pos..*pos + chars * 2]);
        *pos += chars * 2;
        Ok(s)
    }

    fn byte(&self, pos: usize, end: usize) -> Result<u8> {
        if pos >= end {
            return err("BinXml ends early", pos, "BinXml");
        }
        Ok(self.b[pos])
    }

    fn u16(&self, pos: usize, end: usize) -> Result<u16> {
        if pos + 2 > end {
            return err("BinXml ends early", pos, "BinXml");
        }
        Ok(u16::from_le_bytes([self.b[pos], self.b[pos + 1]]))
    }

    fn u32(&self, pos: usize, end: usize) -> Result<u32> {
        if pos + 4 > end {
            return err("BinXml ends early", pos, "BinXml");
        }
        Ok(u32::from_le_bytes(self.b[pos..pos + 4].try_into().unwrap()))
    }
}

/// The .NET enum names of value types, as error messages show them
pub(crate) fn type_name(ty: u8) -> String {
    use types::*;
    let name = match ty {
        NULL => "NullType",
        STRING => "StringType",
        ANSI_STRING => "AnsiStringType",
        INT8 => "Int8Type",
        UINT8 => "UInt8Type",
        INT16 => "Int16Type",
        UINT16 => "UInt16Type",
        INT32 => "Int32Type",
        UINT32 => "UInt32Type",
        INT64 => "Int64Type",
        UINT64 => "UInt64Type",
        REAL32 => "Real32Type",
        REAL64 => "Real64Type",
        BOOL => "BoolType",
        BINARY => "BinaryType",
        GUID => "GuidType",
        SIZE_T => "SizeTType",
        FILETIME => "FileTimeType",
        SYSTIME => "SysTimeType",
        SID => "SidType",
        HEX_INT32 => "HexInt32Type",
        HEX_INT64 => "HexInt64Type",
        EVT_HANDLE => "EvtHandle",
        BINXML => "BinXmlType",
        EVT_XML => "EvtXml",
        ARRAY_FLAG => "ArrayFlag",
        _ => return ty.to_string(),
    };
    name.to_string()
}
