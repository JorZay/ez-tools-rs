//! An event record: `**\0\0`, size, record number, FILETIME, BinXml event data, then the size again.

use crate::binxml::parser::BinXmlParser;
use crate::binxml::render::{self, OutElement, OutNode};
use crate::error::{ParseError, Result};
use crate::output::{json, xml};
use crate::time::Timestamp;

pub(crate) const RECORD_HEADER_SIZE: usize = 0x18;
pub(crate) const RECORD_SIGNATURE: u32 = 0x0000_2A2A;

/// An event, rendered, with the fields EvtxECmd shows. The `map_*`-filled fields (`user_name`, `payload_data`...)
/// are set when maps are applied.
#[derive(Debug, Clone)]
pub struct EventRecord {
    /// The number in the record header
    pub record_number: i64,
    /// The time in the record header
    pub timestamp: Timestamp,
    /// Event/System/TimeCreated/@SystemTime (0001-01-01 when missing or not a time)
    pub time_created: Timestamp,
    pub event_record_id: Option<String>,
    pub event_id: i32,
    pub level: Option<String>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub process_id: i32,
    pub thread_id: i32,
    pub computer: Option<String>,
    pub user_id: Option<String>,
    pub keywords: Option<String>,
    /// The RenderingInfo element of forwarded events, as JSON
    pub rendering_info: Option<String>,

    pub map_description: Option<String>,
    pub user_name: Option<String>,
    pub remote_host: Option<String>,
    pub executable_info: Option<String>,
    pub payload_data: [Option<String>; 6],

    /// The chunk's index in the file
    pub chunk_number: u32,
    /// Where the record is in its chunk
    pub record_position: usize,
    pub size: u32,
    /// Where a record signature was found in this record's slack, relative to the record (0 for none)
    pub extra_data_offset: i64,
    /// A record found hidden in another record's slack (e.g. DanderSpritz's eventlogedit)
    pub hidden_record: bool,

    root: OutElement,
    /// Index in root.children of the payload element (EventData, UserData, or the element after System)
    payload: Option<usize>,
}

impl EventRecord {
    pub(crate) fn parse(parser: &mut BinXmlParser, chunk_number: u32, position: usize, size: usize) -> Result<EventRecord> {
        let b = parser.bytes();
        if size < RECORD_HEADER_SIZE + 4 || position + size > b.len() {
            return Err(ParseError::new(format!("Record size 0x{size:X} does not fit in the chunk"), position, "EventRecord"));
        }

        let record_number = i64::from_le_bytes(b[position + 8..position + 16].try_into().unwrap());
        let raw_time = i64::from_le_bytes(b[position + 16..position + 24].try_into().unwrap());
        let timestamp = Timestamp::from_filetime(raw_time)
            .ok_or_else(|| ParseError::new("Record timestamp is not a valid FILETIME", position + 16, "EventRecord"))?;

        let end = position + size - 4;
        let (nodes, stop) = parser.parse_fragment(position + RECORD_HEADER_SIZE, end, false, 0)?;
        let extra_data_offset = find_hidden_record(b, stop, end, position);

        let output = render::render_record(parser, &nodes)?;
        let root = output
            .into_iter()
            .find_map(|n| match n {
                OutNode::Element(e) => Some(e),
                _ => None,
            })
            .ok_or_else(|| ParseError::new("Record does not contain an event", position, "EventRecord"))?;

        let mut record = EventRecord {
            record_number,
            timestamp,
            time_created: Timestamp::MIN,
            event_record_id: None,
            event_id: 0,
            level: None,
            provider: None,
            channel: None,
            process_id: 0,
            thread_id: 0,
            computer: None,
            user_id: None,
            keywords: None,
            rendering_info: None,
            map_description: None,
            user_name: None,
            remote_host: None,
            executable_info: None,
            payload_data: Default::default(),
            chunk_number,
            record_position: position,
            size: size as u32,
            extra_data_offset,
            hidden_record: false,
            root,
            payload: None,
        };
        record.build_properties();
        Ok(record)
    }

    /// A whole record at `extra_data_offset` (signature, size, size copy) that is not this one
    pub(crate) fn has_hidden_record(&self, b: &[u8]) -> bool {
        if self.extra_data_offset <= 0 {
            return false;
        }
        let i = self.record_position + self.extra_data_offset as usize;
        let end = self.record_position + self.size as usize;
        if i + RECORD_HEADER_SIZE + 4 > end || u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) != RECORD_SIGNATURE {
            return false;
        }
        let size = i32::from_le_bytes(b[i + 4..i + 8].try_into().unwrap());
        size >= (RECORD_HEADER_SIZE + 4) as i32
            && i + size as usize <= end
            && i64::from_le_bytes(b[i + 8..i + 16].try_into().unwrap()) != self.record_number
    }

    /// The rendered event
    pub fn root(&self) -> &OutElement {
        &self.root
    }

    /// The EventData or UserData element (or the element after System when there is neither)
    pub fn payload_element(&self) -> Option<&OutElement> {
        self.payload.and_then(|i| match &self.root.children[i] {
            OutNode::Element(e) => Some(e),
            _ => None,
        })
    }

    /// The event as XML (CRLF line breaks, 2 space indents), as EvtxECmd's --xml writes it
    pub fn to_xml(&self) -> String {
        xml::write(&self.root, None).0
    }

    /// The payload element as XML with LF line breaks (empty when there is none)
    pub fn payload_xml(&self) -> String {
        let Some(payload) = self.payload_element() else {
            return String::new();
        };
        let (xml, span) = xml::write(&self.root, Some(payload));
        xml[span.unwrap()].replace("\r\n", "\n")
    }

    /// The payload as JSON (empty when there is none): what EvtxECmd writes in the Payload column
    pub fn payload_json(&self) -> String {
        self.payload_element().map(|p| json::element(p, false)).unwrap_or_default()
    }

    /// The whole event as JSON (EvtxECmd's --fj)
    pub fn event_json(&self) -> String {
        json::element(&self.root, true)
    }

    /// A 128-bit hash of what the event says: the record number, the header time and the whole rendered event.
    /// Where the record is (file, chunk, offset) is left out, so the same event in two copies of a log has the same
    /// hash.
    pub fn content_hash(&self) -> u128 {
        let mut h = xxhash_rust::xxh3::Xxh3::new();
        h.update(&self.record_number.to_le_bytes());
        h.update(&self.timestamp.0.to_le_bytes());
        hash_element(&mut h, &self.root);
        h.digest128()
    }

    fn build_properties(&mut self) {
        let root = &self.root;
        let mut system_index = None;
        if let Some((i, system)) = root.children.iter().enumerate().find_map(|(i, c)| match c {
            OutNode::Element(e) if &*e.name == "System" => Some((i, e)),
            _ => None,
        }) {
            system_index = Some(i);
            for e in system.elements() {
                match &*e.name {
                    "Provider" => self.provider = e.attribute("Name").map(str::to_string),
                    "EventID" => self.event_id = parse_int(e.text().trim()).unwrap_or(0),
                    "Level" => self.level = Some(level_name(e.text().trim())),
                    "Keywords" => self.keywords = Some(keywords_name(&e.text())),
                    "TimeCreated" => {
                        if let Some(t) = e.attribute("SystemTime").and_then(Timestamp::parse) {
                            self.time_created = t;
                        }
                    }
                    "EventRecordID" => self.event_record_id = Some(e.text()),
                    "Execution" => {
                        if let Some(pid) = e.attribute("ProcessID").and_then(parse_int) {
                            self.process_id = pid;
                        }
                        if let Some(tid) = e.attribute("ThreadID").and_then(parse_int) {
                            self.thread_id = tid;
                        }
                    }
                    "Channel" => self.channel = Some(e.text()),
                    "Computer" => self.computer = Some(e.text()),
                    "Security" => self.user_id = e.attribute("UserID").map(str::to_string),
                    _ => {}
                }
            }
        }

        let mut payload = None;
        let mut first_after_system = None;
        let mut after_system = false;
        let mut rendering_info = None;
        for (i, c) in root.children.iter().enumerate() {
            let OutNode::Element(e) = c else { continue };
            match &*e.name {
                "EventData" | "UserData" => payload = Some(i),
                "RenderingInfo" => rendering_info = Some(rendering_info_json(e)),
                _ => {}
            }
            if after_system && first_after_system.is_none() {
                first_after_system = Some(i);
            }
            if Some(i) == system_index {
                after_system = true;
            }
        }
        if rendering_info.is_some() {
            self.rendering_info = rendering_info;
        }
        self.payload = payload.or(first_after_system);
    }
}

fn hash_element(h: &mut xxhash_rust::xxh3::Xxh3, e: &OutElement) {
    // each part is tagged and length-prefixed, so different trees cannot write the same bytes
    fn put(h: &mut xxhash_rust::xxh3::Xxh3, tag: u8, s: &str) {
        h.update(&[tag]);
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }
    put(h, b'<', &e.name);
    for (k, v) in &e.attributes {
        put(h, b'@', k);
        put(h, b'=', v);
    }
    put(h, if e.empty_tag { b'/' } else { b'>' }, "");
    for c in &e.children {
        match c {
            OutNode::Text(t) => put(h, b't', t),
            OutNode::CData(t) => put(h, b'c', t),
            OutNode::Pi { target, data } => {
                put(h, b'?', target);
                put(h, b'd', data);
            }
            OutNode::Element(child) => hash_element(h, child),
        }
    }
    h.update(b")");
}

/// The first "**" within 16 bytes after the event data (data left from another record, or a record hidden there),
/// relative to the record; 0 for none
fn find_hidden_record(b: &[u8], start: usize, end: usize, record_position: usize) -> i64 {
    let last = (start + 16).min(end.saturating_sub(1));
    for i in start..last {
        if b[i] != 0x2A {
            continue;
        }
        if b[i + 1] == 0x2A {
            return (i - record_position) as i64;
        }
        return 0;
    }
    0
}

/// int.TryParse with NumberStyles.Integer: white space around, an optional sign
pub(crate) fn parse_int(s: &str) -> Option<i32> {
    s.trim_matches(|c: char| c == ' ' || ('\t'..='\r').contains(&c)).parse().ok()
}

fn level_name(level: &str) -> String {
    match level {
        "0" => "LogAlways",
        "1" => "Critical",
        "2" => "Error",
        "3" => "Warning",
        "4" => "Info",
        "5" => "Verbose",
        "8" => "Success",
        "16" => "Failure",
        _ => level,
    }
    .to_string()
}

fn keywords_name(kw: &str) -> String {
    match kw {
        "0x8010000000000000" => "Audit failure",
        "0x8020000000000000" => "Audit success",
        "0x8000000000000010" => "Time",
        "0x8000000000000080" => "State",
        "0x8000000000000040" => "Reboot",
        "0x8000000000000018" => "Installation",
        "0x8000000000000014" => "Download",
        "0x8080000000000000" => "Audit success, classic",
        "0x8000000000000000" => "Classic",
        _ => kw,
    }
    .to_string()
}

/// RenderingInfo's names and message (Keywords can be a list of Keyword elements or text), as EvtxECmd serializes
/// them
fn rendering_info_json(e: &OutElement) -> String {
    let mut fields: [Option<String>; 7] = Default::default();
    const NAMES: [&str; 7] = ["Level", "Opcode", "Task", "Channel", "Provider", "Keywords", "Message"];
    for child in e.elements() {
        let i = match &*child.name {
            "Message" => 6,
            "Level" => 0,
            "Task" => 2,
            "Opcode" => 1,
            "Channel" => 3,
            "Provider" => 4,
            "Keywords" => {
                let mut keywords: Vec<String> = child.elements().filter(|k| &*k.name == "Keyword").map(|k| k.text()).collect();
                let text = child.text();
                if keywords.is_empty() && !text.is_empty() {
                    keywords.push(text);
                }
                fields[5] = Some(keywords.join(","));
                continue;
            }
            _ => continue,
        };
        fields[i] = Some(child.text());
    }
    let mut o = json::ServiceStackObject::new();
    for (name, value) in NAMES.iter().zip(&fields) {
        o.string(name, value.as_deref());
    }
    o.finish()
}
