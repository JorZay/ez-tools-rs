//! Batch mode: the .reb file (YAML), its validation, and the rows (BatchCsvOut) with their CSV and JSON.

use ez_common::cli::log::Logger;
use ez_common::json::ServiceStackObject;
use ez_common::net::{self, NetResult};
use ez_common::{Timestamp, csv};
use registry_ez::hive::{Hive, KeyId, VkId, upper};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Key.HiveType_ (its names differ from the library's HiveTypeEnum in one place: userdiff)
const HIVE_TYPES: &[(&str, i64)] = &[
    ("Other", 0),
    ("NtUser", 1),
    ("Sam", 2),
    ("Security", 3),
    ("Software", 4),
    ("System", 5),
    ("UsrClass", 6),
    ("Components", 7),
    ("Drivers", 8),
    ("Amcache", 9),
    ("Syscache", 10),
    ("Bcd", 11),
    ("BcdTemplate", 12),
    ("Elam", 13),
    ("userdiff", 14),
    ("Bbi", 15),
    ("Vsmidk", 16),
    ("Default", 17),
    ("User", 18),
    ("UserClasses", 19),
    ("settings", 20),
    ("Registry", 21),
];

const BIN_CONVERTS: &[(&str, i64)] = &[
    ("None", 0),
    ("Filetime", 1),
    ("Ip", 2),
    ("Epoch", 3),
    ("Sid", 4),
    ("Systemtime", 5),
    ("DateTimeTicks", 6),
    ("OLE", 7),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinConvert {
    None,
    Filetime,
    Ip,
    Epoch,
    Sid,
    Systemtime,
    DateTimeTicks,
    Ole,
}

/// A Keys entry of a batch file
#[derive(Debug, Default, Clone)]
pub struct BatchKey {
    pub description: Option<String>,
    pub hive_type: i64,
    pub category: Option<String>,
    pub key_path: Option<String>,
    pub value_name: Option<String>,
    pub recursive: bool,
    pub disable_plugin: bool,
    pub include_binary: bool,
    pub binary_convert: i64,
    pub comment: Option<String>,
}

impl BatchKey {
    pub fn hive_type_name(&self) -> String {
        net::enum_name(self.hive_type, HIVE_TYPES)
    }

    fn convert(&self) -> Option<BinConvert> {
        Some(match self.binary_convert {
            0 => BinConvert::None,
            1 => BinConvert::Filetime,
            2 => BinConvert::Ip,
            3 => BinConvert::Epoch,
            4 => BinConvert::Sid,
            5 => BinConvert::Systemtime,
            6 => BinConvert::DateTimeTicks,
            7 => BinConvert::Ole,
            _ => return None,
        })
    }
}

/// ReBatch
#[derive(Debug, Default)]
pub struct Batch {
    pub description: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    pub id: Option<String>,
    pub keys: Option<Vec<BatchKey>>,
}

// ---- YAML ----

#[derive(Debug)]
enum Node {
    Scalar(String, bool, Marker),
    Map(Vec<(String, Node, Marker)>, Marker),
    Seq(Vec<Node>, Marker),
}

impl Node {
    fn mark(&self) -> Marker {
        match self {
            Node::Scalar(_, _, m) | Node::Map(_, m) | Node::Seq(_, m) => *m,
        }
    }
}

#[derive(Default)]
struct Builder {
    stack: Vec<(Node, Option<(String, Marker)>)>,
    done: Option<Node>,
}

impl Builder {
    fn push_value(&mut self, node: Node) {
        match self.stack.last_mut() {
            None => {
                if self.done.is_none() {
                    self.done = Some(node);
                }
            }
            Some((Node::Seq(items, _), _)) => items.push(node),
            Some((Node::Map(entries, _), pending)) => match pending.take() {
                None => {
                    let (key, m) = match node {
                        Node::Scalar(s, _, m) => (s, m),
                        other => (String::new(), other.mark()),
                    };
                    *pending = Some((key, m));
                }
                Some((key, m)) => entries.push((key, node, m)),
            },
            Some((Node::Scalar(..), _)) => {}
        }
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::Scalar(v, style, _, _) => self.push_value(Node::Scalar(v, style == TScalarStyle::Plain, mark)),
            Event::SequenceStart(..) => self.stack.push((Node::Seq(vec![], mark), None)),
            Event::MappingStart(..) => self.stack.push((Node::Map(vec![], mark), None)),
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((node, _)) = self.stack.pop() {
                    self.push_value(node);
                }
            }
            Event::Alias(_) => self.push_value(Node::Scalar(String::new(), true, mark)),
            _ => {}
        }
    }
}

/// Why a batch file could not be read, as ValidateBatchFile reports it
pub enum LoadError {
    /// SyntaxErrorException: the message, line and column (1-based)
    Syntax(String, usize, usize),
    /// YamlException: the message and the inner exception's message
    Yaml(String, Option<String>),
}

fn is_null(v: &str, plain: bool) -> bool {
    plain && matches!(v, "" | "~" | "null" | "Null" | "NULL")
}

fn string_of(node: &Node) -> Result<Option<String>, LoadError> {
    match node {
        Node::Scalar(v, plain, _) => Ok(if is_null(v, *plain) { None } else { Some(v.clone()) }),
        _ => Err(LoadError::Yaml("Exception during deserialization".into(), Some("Expected a scalar value".into()))),
    }
}

fn bool_of(node: &Node) -> Result<bool, LoadError> {
    let Node::Scalar(v, ..) = node else {
        return Err(LoadError::Yaml("Exception during deserialization".into(), Some("Expected a scalar value".into())));
    };
    match v.to_lowercase().as_str() {
        "true" | "y" | "yes" | "on" => Ok(true),
        "false" | "n" | "no" | "off" => Ok(false),
        _ => Err(LoadError::Yaml(
            "Exception during deserialization".into(),
            Some(format!("The value \"{v}\" is not a valid YAML Boolean")),
        )),
    }
}

/// Enum.Parse(type, value, ignoreCase: true): a name, or a number
fn enum_of(node: &Node, names: &[(&str, i64)]) -> Result<i64, LoadError> {
    let Node::Scalar(v, ..) = node else {
        return Err(LoadError::Yaml("Exception during deserialization".into(), Some("Expected a scalar value".into())));
    };
    let t = v.trim();
    if let Ok(n) = t.parse::<i64>() {
        return Ok(n);
    }
    let mut total = 0;
    for part in t.split(',') {
        let p = part.trim().to_lowercase();
        match names.iter().find(|(n, _)| n.to_lowercase() == p) {
            Some((_, n)) => total |= n,
            None => {
                return Err(LoadError::Yaml(
                    "Exception during deserialization".into(),
                    Some(format!("Requested value '{v}' was not found.")),
                ));
            }
        }
    }
    Ok(total)
}

fn not_found(name: &str, on: &str) -> LoadError {
    LoadError::Yaml(format!("Property '{name}' not found on type '{on}'."), None)
}

/// Deserializes a batch file as YamlDotNet does into ReBatch (property names as written, case-sensitive)
pub fn load(text: &str) -> Result<Option<Batch>, LoadError> {
    let mut b = Builder::default();
    let mut parser = Parser::new_from_str(text);
    if let Err(e) = parser.load(&mut b, false) {
        let m = e.marker();
        return Err(LoadError::Syntax(e.info().to_string(), m.line(), m.col() + 1));
    }
    let Some(root) = b.done else { return Ok(None) };
    let Node::Map(entries, _) = root else {
        return Err(LoadError::Yaml("Exception during deserialization".into(), Some("Expected a mapping".into())));
    };
    let mut batch = Batch::default();
    for (name, node, _) in &entries {
        match name.as_str() {
            "Description" => batch.description = string_of(node)?,
            "Author" => batch.author = string_of(node)?,
            "Version" => batch.version = string_of(node)?,
            "Id" => batch.id = string_of(node)?,
            "Keys" => {
                batch.keys = match node {
                    Node::Scalar(v, plain, _) if is_null(v, *plain) => None,
                    Node::Seq(items, _) => {
                        let mut keys = Vec::new();
                        for item in items {
                            keys.push(load_key(item)?);
                        }
                        Some(keys)
                    }
                    _ => {
                        return Err(LoadError::Yaml(
                            "Exception during deserialization".into(),
                            Some("Expected a sequence".into()),
                        ));
                    }
                }
            }
            other => return Err(not_found(other, "RECmd.ReBatch")),
        }
    }
    Ok(Some(batch))
}

fn load_key(node: &Node) -> Result<BatchKey, LoadError> {
    let Node::Map(entries, _) = node else {
        return Err(LoadError::Yaml("Exception during deserialization".into(), Some("Expected a mapping".into())));
    };
    let mut k = BatchKey::default();
    for (name, node, _) in entries {
        match name.as_str() {
            "Description" => k.description = string_of(node)?,
            "HiveType" => k.hive_type = enum_of(node, HIVE_TYPES)?,
            "Category" => k.category = string_of(node)?,
            "KeyPath" => k.key_path = string_of(node)?,
            "ValueName" => k.value_name = string_of(node)?,
            "Recursive" => k.recursive = bool_of(node)?,
            "DisablePlugin" => k.disable_plugin = bool_of(node)?,
            "IncludeBinary" => k.include_binary = bool_of(node)?,
            "BinaryConvert" => k.binary_convert = enum_of(node, BIN_CONVERTS)?,
            "Comment" => k.comment = string_of(node)?,
            other => return Err(not_found(other, "RECmd.Key")),
        }
    }
    Ok(k)
}

/// ReBatchValidator's errors, in its order
pub fn validate(b: &Batch) -> Vec<String> {
    let mut errors = Vec::new();
    let empty = |name: &str| format!("'{name}' must not be empty.");
    for (v, name) in [(&b.description, "Description"), (&b.author, "Author"), (&b.version, "Version"), (&b.id, "Id")] {
        if v.is_none() {
            errors.push(empty(name));
        }
    }
    match &b.keys {
        None => errors.push(empty("Keys")),
        Some(keys) => {
            if keys.is_empty() {
                errors.push("'Keys Count' must be greater than '0'.".into());
            }
            for k in keys {
                for (v, name) in [(&k.description, "Description"), (&k.category, "Category"), (&k.key_path, "Key Path")] {
                    if v.is_none() {
                        errors.push(empty(name));
                    }
                }
            }
        }
    }
    errors
}

/// Shows why the batch file is not usable (the messages of ValidateBatchFile); false when it is not
pub fn read_and_validate(path: &str, log: &mut Logger) -> Option<Batch> {
    let text = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(b.strip_prefix(ez_common::cli::BOM).unwrap_or(&b)).into_owned(),
        Err(e) => {
            log.info("");
            log.warning(&format!("Error when validating {path}"));
            log.error(&e.to_string());
            return failed(log);
        }
    };
    match load(&text) {
        Ok(Some(batch)) => {
            let errors = validate(&batch);
            if errors.is_empty() {
                return Some(batch);
            }
            log.info("");
            log.error(&format!("{path} had validation errors"));
            for e in errors {
                log.info(&e);
            }
            log.info("");
            log.error("Correct the errors and try again. Exiting");
            log.info("");
            None
        }
        Ok(None) => {
            log.info("");
            log.warning(&format!("Error when validating {path}"));
            log.error("Object reference not set to an instance of an object.");
            failed(log)
        }
        Err(LoadError::Syntax(message, line, column)) => {
            log.info("");
            log.warning(&format!("Syntax error in {path}"));
            log.error(&message);
            let lines: Vec<&str> = text.lines().collect();
            let index = line.saturating_sub(1).min(lines.len().saturating_sub(1));
            let bad = lines.get(index).copied().unwrap_or("");
            log.info("");
            log.error(&format!("Bad line (or close to it) {bad} has invalid data at column {column}"));
            if text.contains('\t') {
                log.info("");
                log.error("Bad line contains one or more tab characters. Replace them with spaces");
                log.info("");
                log.info(&text.replace('\t', "<TAB>"));
            }
            failed(log)
        }
        Err(LoadError::Yaml(message, inner)) => {
            log.info("");
            log.warning(&format!("Syntax error in {path}"));
            log.error(&message);
            log.error(inner.as_deref().unwrap_or("null"));
            failed(log)
        }
    }
}

fn failed(log: &mut Logger) -> Option<Batch> {
    log.info("");
    log.info("");
    log.warning("The batch file failed validation. Fix the issues and try again");
    log.info("");
    None
}

// ---- rows ----

/// BatchCsvOut
#[derive(Debug, Clone)]
pub struct Row {
    pub hive_path: String,
    pub hive_type: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub key_path: String,
    pub value_name: String,
    pub value_type: String,
    pub value_data: String,
    pub comment: Option<String>,
    pub recursive: bool,
    pub deleted: bool,
    pub last_write: Timestamp,
}

pub const CSV_HEADER: &str = "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile";

fn bool_text(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

impl Row {
    pub fn csv(&self, out: &mut String, dt: &str) {
        let fields: [&str; 11] = [
            &self.hive_path,
            &self.hive_type,
            self.description.as_deref().unwrap_or(""),
            self.category.as_deref().unwrap_or(""),
            &self.key_path,
            &self.value_name,
            &self.value_type,
            &self.value_data,
            "",
            "",
            self.comment.as_deref().unwrap_or(""),
        ];
        for f in fields {
            csv::field(out, f);
            out.push(',');
        }
        out.push_str(bool_text(self.recursive));
        out.push(',');
        out.push_str(bool_text(self.deleted));
        out.push(',');
        csv::field(out, &self.last_write.format(dt));
        out.push(',');
        out.push_str(csv::NEW_LINE);
    }

    pub fn json(&self) -> String {
        let mut o = ServiceStackObject::new();
        let null = |o: &mut ServiceStackObject, name: &str, v: Option<&str>| {
            match v {
                Some(s) => o.string(name, Some(s)),
                None => o.raw(name, "null"),
            };
        };
        o.string("HivePath", Some(&self.hive_path)).string("HiveType", Some(&self.hive_type));
        null(&mut o, "Description", self.description.as_deref());
        null(&mut o, "Category", self.category.as_deref());
        o.string("KeyPath", Some(&self.key_path))
            .string("ValueName", Some(&self.value_name))
            .string("ValueType", Some(&self.value_type))
            .string("ValueData", Some(&self.value_data))
            .raw("ValueData2", "null")
            .raw("ValueData3", "null");
        null(&mut o, "Comment", self.comment.as_deref());
        o.bool("Recursive", self.recursive).bool("Deleted", self.deleted);
        o.raw("LastWriteTimestamp", &format!("\"{}\"", self.last_write.to_json_string())).raw("PluginDetailFile", "null");
        o.finish()
    }
}

const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";

/// BuildBatchCsvOut. Warnings (conversions that failed) go to `warn`.
pub fn build_row(hive: &Hive, k: KeyId, key: &BatchKey, value: Option<VkId>, dt: &str, warn: &mut Vec<String>) -> NetResult<Row> {
    let nk = hive.nk(k);
    let mut row = Row {
        hive_path: hive.path.clone(),
        hive_type: key.hive_type_name(),
        description: key.description.clone(),
        category: key.category.clone(),
        key_path: hive.keys[k].path.clone(),
        value_name: match value {
            Some(v) => hive.vks[v].name()?.to_string(),
            None => String::new(),
        },
        value_type: value.map(|v| hive.vks[v].type_name()).unwrap_or_default(),
        value_data: String::new(),
        comment: key.comment.clone(),
        recursive: key.recursive,
        deleted: nk.deleted.get(),
        last_write: nk.last_write()?,
    };
    let data = |v: VkId| -> NetResult<String> { Ok(hive.value_data(v)?.text()) };
    if row.value_type == "RegBinary" {
        let v = value.unwrap();
        row.value_data = "(Binary data)".into();
        if key.include_binary {
            let raw = hive.value_raw(v)?;
            row.value_data = match key.convert() {
                Some(BinConvert::Filetime) => convert(filetime(&raw, dt), "Error converting to FILETIME. Using bytes instead!", v, hive, warn)?,
                Some(BinConvert::Ip) => match net::u32_at(&raw, 0) {
                    Ok(_) => format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]),
                    Err(e) => {
                        warn.push(format!("Error converting to IP address. Using bytes instead! Error: {e}"));
                        data(v)?
                    }
                },
                Some(BinConvert::Epoch) => convert(epoch(&raw, dt), "Error converting to Epoch. Using bytes instead!", v, hive, warn)?,
                Some(BinConvert::Sid) => convert(sid(&raw), "Error converting to SID. Using bytes instead!", v, hive, warn)?,
                Some(BinConvert::Systemtime) => {
                    convert(systemtime(&raw, dt), "Error converting to SYSTEMTIME. Using bytes instead!", v, hive, warn)?
                }
                Some(BinConvert::DateTimeTicks) => {
                    convert(ticks(&raw, dt), "Error converting to DateTime.Ticks. Using bytes instead!", v, hive, warn)?
                }
                Some(BinConvert::Ole) => {
                    convert(ole(&raw, dt), "Error converting to OLE Automation Date OLE2.0. Using bytes instead!", v, hive, warn)?
                }
                _ => data(v)?,
            };
        }
        return Ok(row);
    }
    row.value_data = match value {
        Some(v) => data(v)?,
        None => String::new(),
    };
    let message = match key.convert() {
        Some(BinConvert::Epoch) => "Error converting to Epoch. Using bytes instead!",
        Some(BinConvert::Filetime) => "Error converting to FILETIME. Using bytes instead!",
        Some(BinConvert::Systemtime) => "Error converting to SYSTEMTIME. Using bytes instead!",
        Some(BinConvert::DateTimeTicks) => "Error converting to DateTime.Ticks. Using bytes instead!",
        Some(BinConvert::Ole) => "Error converting to OLE Automation Date OLE2.0. Using bytes instead!",
        _ => return Ok(row),
    };
    let Some(v) = value else {
        // the value is null: the conversion throws, and so does the fallback in its catch
        warn.push(message.into());
        return Err(NULL_REFERENCE.into());
    };
    let raw = hive.value_raw(v)?;
    let result = match key.convert() {
        Some(BinConvert::Epoch) => epoch(&raw, dt),
        Some(BinConvert::Filetime) => filetime(&raw, dt),
        Some(BinConvert::Systemtime) => systemtime(&raw, dt),
        Some(BinConvert::DateTimeTicks) => ticks(&raw, dt),
        _ => ole(&raw, dt),
    };
    row.value_data = convert(result, message, v, hive, warn)?;
    Ok(row)
}

fn convert(r: Result<String, String>, message: &str, v: VkId, hive: &Hive, warn: &mut Vec<String>) -> NetResult<String> {
    match r {
        Ok(s) => Ok(s),
        Err(_) => {
            warn.push(message.into());
            Ok(hive.value_data(v)?.text())
        }
    }
}

fn filetime(raw: &[u8], dt: &str) -> Result<String, String> {
    let ft = net::u64_at(raw, 0)? as i64;
    Ok(registry_ez::cells::filetime(ft)?.format(dt))
}

fn epoch(raw: &[u8], dt: &str) -> Result<String, String> {
    let s = net::u32_at(raw, 0)? as i64;
    Ok(Timestamp(621_355_968_000_000_000 + s * 10_000_000).format(dt))
}

fn ticks(raw: &[u8], dt: &str) -> Result<String, String> {
    let t = net::i64_at(raw, 0)?;
    if !(0..=ez_common::time::MAX_TICKS).contains(&t) {
        return Err("Ticks must be between DateTime.MinValue.Ticks and DateTime.MaxValue.Ticks.".into());
    }
    Ok(Timestamp(t).format(dt))
}

fn systemtime(raw: &[u8], dt: &str) -> Result<String, String> {
    let mut f = [0i32; 8];
    for (i, v) in f.iter_mut().enumerate() {
        *v = net::i16_at(raw, i as i64 * 2)? as i32;
    }
    let (y, mo, d, h, mi, s, ms) = (f[0], f[1], f[3], f[4], f[5], f[6], f[7]);
    if !(0..1000).contains(&ms) || !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&s) {
        return Err("invalid".into());
    }
    let t = Timestamp::from_parts(y, mo.max(0) as u32, d.max(0) as u32, h as u32, mi as u32, s as u32, ms as u32 * 10_000)
        .ok_or("invalid")?;
    Ok(t.format(dt))
}

/// DateTime.FromOADate
fn ole(raw: &[u8], dt: &str) -> Result<String, String> {
    let d = f64::from_bits(net::u64_at(raw, 0)?);
    if !(d > -657435.0 && d < 2958466.0) {
        return Err("Not a legal OleAut date.".into());
    }
    const MS_PER_DAY: i64 = 86_400_000;
    let mut ms = (d * MS_PER_DAY as f64 + if d >= 0.0 { 0.5 } else { -0.5 }) as i64;
    if ms < 0 {
        ms -= (ms % MS_PER_DAY) * 2;
    }
    // 1899-12-30 in milliseconds
    ms += 59_926_435_200_000;
    if !(0..=315_537_897_599_999).contains(&ms) {
        return Err("Not a legal OleAut date.".into());
    }
    Ok(Timestamp(ms * 10_000).format(dt))
}

/// SecurityIdentifier(bytes, 0).ToString(), as on Windows
fn sid(raw: &[u8]) -> Result<String, String> {
    if raw.len() < 8 || raw[0] != 1 || raw[1] > 15 || raw.len() < 8 + 4 * raw[1] as usize {
        return Err("invalid SID".into());
    }
    let authority = raw[2..8].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut s = format!("S-1-{authority}");
    for i in 0..raw[1] as usize {
        let o = 8 + 4 * i;
        s.push_str(&format!("-{}", u32::from_le_bytes(raw[o..o + 4].try_into().unwrap())));
    }
    Ok(s)
}

/// The value with this name (FirstOrDefault, case-insensitively)
pub fn find_value(hive: &Hive, k: KeyId, name: &str) -> NetResult<Option<VkId>> {
    let want = upper(name);
    for &v in &hive.keys[k].values {
        if upper(hive.vks[v].name()?) == want {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

