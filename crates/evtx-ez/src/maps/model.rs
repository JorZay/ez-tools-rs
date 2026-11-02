//! The map file format, read as YamlDotNet read it into EvtxECmd's classes: scalars as written (`0x10` stays
//! "0x10"), `~`/`null`/nothing as null, and an unknown property is an error.

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[derive(Debug, Clone, Default)]
pub struct EventLogMap {
    pub author: Option<String>,
    pub description: Option<String>,
    pub event_id: i32,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub maps: Option<Vec<Option<MapEntry>>>,
    pub lookups: Option<Vec<Option<LookupEntry>>>,
}

#[derive(Debug, Clone, Default)]
pub struct MapEntry {
    /// UserName, RemoteHost, ExecutableInfo, PayloadData1-6
    pub property: Option<String>,
    /// The value, with `%name%` for each value entry
    pub property_value: Option<String>,
    pub values: Option<Vec<Option<ValueEntry>>>,
}

#[derive(Debug, Clone, Default)]
pub struct ValueEntry {
    pub name: Option<String>,
    /// An XPath
    pub value: Option<String>,
    /// A regex to run against the value; the matches are joined with " | ". Optional.
    pub refine: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LookupEntry {
    pub name: Option<String>,
    pub default: Option<String>,
    /// In file order; a key used twice keeps its first place and the last value
    pub values: Option<Vec<(String, Option<String>)>>,
}

/// A YAML node, scalars as written
#[derive(Debug)]
enum Node {
    /// The text, and whether it was a plain scalar (only plain scalars can be null)
    Scalar(String, bool, Marker),
    Seq(Vec<Node>, Marker),
    Map(Vec<(Node, Node)>, Marker),
}

impl Node {
    fn mark(&self) -> Marker {
        match self {
            Node::Scalar(_, _, m) | Node::Seq(_, m) | Node::Map(_, m) => *m,
        }
    }

    fn is_null(&self) -> bool {
        matches!(self, Node::Scalar(s, true, _) if matches!(s.as_str(), "" | "~" | "null" | "Null" | "NULL"))
    }
}

#[derive(Default)]
struct Builder {
    stack: Vec<Node>,
    keys: Vec<Option<Node>>,
    root: Option<Node>,
    error: Option<String>,
}

impl Builder {
    fn push(&mut self, node: Node) {
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(node);
                }
            }
            Some(Node::Seq(items, _)) => items.push(node),
            Some(Node::Map(entries, _)) => {
                let key = self.keys.last_mut().unwrap();
                match key.take() {
                    None => *key = Some(node),
                    Some(k) => entries.push((k, node)),
                }
            }
            Some(Node::Scalar(..)) => unreachable!(),
        }
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::Scalar(s, style, _, _) => self.push(Node::Scalar(s, style == TScalarStyle::Plain, mark)),
            Event::SequenceStart(..) => self.stack.push(Node::Seq(Vec::new(), mark)),
            Event::MappingStart(..) => {
                self.stack.push(Node::Map(Vec::new(), mark));
                self.keys.push(None);
            }
            Event::SequenceEnd => {
                let n = self.stack.pop().unwrap();
                self.push(n);
            }
            Event::MappingEnd => {
                self.keys.pop();
                let n = self.stack.pop().unwrap();
                self.push(n);
            }
            Event::Alias(_) => {
                self.error.get_or_insert_with(|| format!("{}: aliases are not supported", position(mark)));
            }
            _ => {}
        }
    }
}

fn position(m: Marker) -> String {
    format!("(Line: {}, Col: {})", m.line(), m.col() + 1)
}

fn not_found(key: &Node, ty: &str) -> String {
    let name = match key {
        Node::Scalar(s, _, _) => s.as_str(),
        _ => "?",
    };
    format!("{}: Property '{name}' not found on type 'evtx.{ty}'.", position(key.mark()))
}

fn string(n: &Node) -> Result<Option<String>, String> {
    if n.is_null() {
        return Ok(None);
    }
    match n {
        Node::Scalar(s, _, _) => Ok(Some(s.clone())),
        _ => Err(format!("{}: Expected a scalar value", position(n.mark()))),
    }
}

fn list<T>(n: &Node, item: impl Fn(&Node) -> Result<T, String>) -> Result<Option<Vec<Option<T>>>, String> {
    if n.is_null() {
        return Ok(None);
    }
    match n {
        Node::Seq(items, _) => {
            items.iter().map(|i| if i.is_null() { Ok(None) } else { item(i).map(Some) }).collect::<Result<_, _>>().map(Some)
        }
        _ => Err(format!("{}: Expected a sequence", position(n.mark()))),
    }
}

fn entries<'a>(n: &'a Node) -> Result<&'a [(Node, Node)], String> {
    match n {
        Node::Map(e, _) => Ok(e),
        _ => Err(format!("{}: Expected a mapping", position(n.mark()))),
    }
}

fn key(n: &Node) -> &str {
    match n {
        Node::Scalar(s, _, _) => s,
        _ => "",
    }
}

/// Reads a map file
pub fn parse(text: &str) -> Result<EventLogMap, String> {
    let mut b = Builder::default();
    let mut parser = Parser::new_from_str(text);
    parser.load(&mut b, false).map_err(|e| e.to_string())?;
    if let Some(e) = b.error {
        return Err(e);
    }
    let Some(root) = b.root else {
        return Ok(EventLogMap::default());
    };
    if root.is_null() {
        return Ok(EventLogMap::default());
    }

    let mut map = EventLogMap::default();
    for (k, v) in entries(&root)? {
        match key(k) {
            "Author" => map.author = string(v)?,
            "Description" => map.description = string(v)?,
            "EventId" => {
                let s = string(v)?.unwrap_or_default();
                map.event_id = s.trim().parse().map_err(|_| {
                    format!("{}: Failed to convert '{s}' to Int32 for property EventId.", position(v.mark()))
                })?;
            }
            "Channel" => map.channel = string(v)?,
            "Provider" => map.provider = string(v)?,
            "Maps" => map.maps = list(v, map_entry)?,
            "Lookups" => map.lookups = list(v, lookup_entry)?,
            _ => return Err(not_found(k, "EventLogMap")),
        }
    }
    Ok(map)
}

fn map_entry(n: &Node) -> Result<MapEntry, String> {
    let mut m = MapEntry::default();
    for (k, v) in entries(n)? {
        match key(k) {
            "Property" => m.property = string(v)?,
            "PropertyValue" => m.property_value = string(v)?,
            "Values" => m.values = list(v, value_entry)?,
            _ => return Err(not_found(k, "MapEntry")),
        }
    }
    Ok(m)
}

fn value_entry(n: &Node) -> Result<ValueEntry, String> {
    let mut m = ValueEntry::default();
    for (k, v) in entries(n)? {
        match key(k) {
            "Name" => m.name = string(v)?,
            "Value" => m.value = string(v)?,
            "Refine" => m.refine = string(v)?,
            _ => return Err(not_found(k, "ValueEntry")),
        }
    }
    Ok(m)
}

fn lookup_entry(n: &Node) -> Result<LookupEntry, String> {
    let mut m = LookupEntry::default();
    for (k, v) in entries(n)? {
        match key(k) {
            "Name" => m.name = string(v)?,
            "Default" => m.default = string(v)?,
            "Values" => {
                if v.is_null() {
                    m.values = None;
                    continue;
                }
                let mut values: Vec<(String, Option<String>)> = Vec::new();
                for (lk, lv) in entries(v)? {
                    let lk = string(lk)?.unwrap_or_default();
                    let lv = string(lv)?;
                    match values.iter_mut().find(|(k, _)| *k == lk) {
                        Some(existing) => existing.1 = lv,
                        None => values.push((lk, lv)),
                    }
                }
                m.values = Some(values);
            }
            _ => return Err(not_found(k, "LookupEntry")),
        }
    }
    Ok(m)
}

fn not_empty(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(|s| !s.trim().is_empty())
}

/// The FluentValidation rules EvtxECmd checks maps with; the messages for the rules that fail
pub fn validate(map: &EventLogMap) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, v) in [
        ("Channel", &map.channel),
        ("Provider", &map.provider),
        ("Author", &map.author),
        ("Description", &map.description),
    ] {
        if !not_empty(v) {
            errors.push(format!("'{name}' must not be empty."));
        }
    }
    if let Some(maps) = &map.maps {
        if maps.is_empty() {
            errors.push("'Maps Count' must be greater than '0'.".into());
        }
        for (i, m) in maps.iter().enumerate() {
            let Some(m) = m else {
                errors.push("Values".into());
                continue;
            };
            match &m.property {
                Some(p) if !p.trim().is_empty() => {
                    const NAMES: [&str; 9] = [
                        "username",
                        "remotehost",
                        "executableinfo",
                        "payloaddata1",
                        "payloaddata2",
                        "payloaddata3",
                        "payloaddata4",
                        "payloaddata5",
                        "payloaddata6",
                    ];
                    if !NAMES.contains(&p.to_lowercase().as_str()) {
                        errors.push(
                            "\r\n'Property' must be one of the following: UserName|RemoteHost|ExecutableInfo|PayloadData1|PayloadData2|PayloadData3|PayloadData4|PayloadData5|PayloadData6"
                                .into(),
                        );
                    }
                }
                _ => errors.push(format!("'Maps[{i}].Property' must not be empty.")),
            }
            if !not_empty(&m.property_value) {
                errors.push(format!("'Maps[{i}].Property Value' must not be empty."));
            }
            if let Some(values) = &m.values {
                if values.is_empty() {
                    errors.push(format!("'Maps[{i}].Values Count' must be greater than '0'."));
                }
                if values.iter().any(Option::is_none) {
                    errors.push("Values".into());
                }
            }
        }
    }
    errors
}
