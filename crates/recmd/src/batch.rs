//! Batch mode: the .reb file (YAML), its validation, and the rows (BatchCsvOut) with their CSV and JSON.

use ez_common::cli::log::Logger;
use ez_common::json::ServiceStackObject;
use ez_common::net::{self, NetResult};
use ez_common::{Timestamp, csv};
use registry_ez::hive::{Hive, KeyId, VkId};
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

pub use crate::convert::BIN_CONVERTS;

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
    /// BatchValueName of a plugin's row can be null
    pub value_name: Option<String>,
    pub value_type: String,
    pub value_data: String,
    /// ValueData is null: shown as such in JSON
    pub value_data_null: bool,
    pub value_data2: Option<String>,
    pub value_data3: Option<String>,
    pub comment: Option<String>,
    pub recursive: bool,
    pub deleted: bool,
    pub last_write: Timestamp,
    pub plugin_detail_file: Option<String>,
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
            self.value_name.as_deref().unwrap_or(""),
            &self.value_type,
            &self.value_data,
            self.value_data2.as_deref().unwrap_or(""),
            self.value_data3.as_deref().unwrap_or(""),
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
        csv::field(out, self.plugin_detail_file.as_deref().unwrap_or(""));
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
        o.string("KeyPath", Some(&self.key_path));
        null(&mut o, "ValueName", self.value_name.as_deref());
        o.string("ValueType", Some(&self.value_type));
        null(&mut o, "ValueData", (!self.value_data_null).then_some(self.value_data.as_str()));
        null(&mut o, "ValueData2", self.value_data2.as_deref());
        null(&mut o, "ValueData3", self.value_data3.as_deref());
        null(&mut o, "Comment", self.comment.as_deref());
        o.bool("Recursive", self.recursive).bool("Deleted", self.deleted);
        o.raw("LastWriteTimestamp", &format!("\"{}\"", self.last_write.to_json_string()));
        null(&mut o, "PluginDetailFile", self.plugin_detail_file.as_deref());
        o.finish()
    }
}

/// BuildBatchCsvOut. Warnings (conversions that failed) go to `warn`.
pub fn build_row(hive: &Hive, k: KeyId, key: &BatchKey, value: Option<VkId>, dt: &str, warn: &mut Vec<String>) -> NetResult<Row> {
    let nk = hive.nk(k);
    let mut row = Row {
        hive_path: hive.path.clone(),
        hive_type: key.hive_type_name(),
        description: key.description.clone(),
        category: key.category.clone(),
        key_path: hive.keys[k].path.clone(),
        value_name: Some(match value {
            Some(v) => hive.vks[v].name()?.to_string(),
            None => String::new(),
        }),
        value_type: value.map(|v| hive.vks[v].type_name()).unwrap_or_default(),
        value_data: String::new(),
        value_data_null: false,
        value_data2: None,
        value_data3: None,
        comment: key.comment.clone(),
        recursive: key.recursive,
        deleted: nk.deleted.get(),
        last_write: nk.last_write()?,
        plugin_detail_file: None,
    };
    let data = |v: VkId| -> NetResult<String> { Ok(hive.value_data(v)?.text()) };
    if row.value_type == "RegBinary" {
        let v = value.unwrap();
        row.value_data = "(Binary data)".into();
        if key.include_binary {
            row.value_data = data(v)?;
            convert(hive, v, key, &mut row, dt, warn)?;
        }
        return Ok(row);
    }
    if let Some(v) = value {
        row.value_data = data(v)?;
        convert(hive, v, key, &mut row, dt, warn)?;
    }
    Ok(row)
}

/// BinaryConvert (any value type, RECmd 2026.11): when the conversion doesn't fit, the data stays as it is
fn convert(hive: &Hive, v: VkId, key: &BatchKey, row: &mut Row, dt: &str, warn: &mut Vec<String>) -> NetResult<()> {
    if key.binary_convert == 0 {
        return Ok(());
    }
    let raw = hive.value_raw(v)?;
    match crate::convert::try_convert(key.binary_convert, &row.value_type, &raw, &row.value_data, dt) {
        Some(converted) => row.value_data = converted,
        None => warn.push(format!(
            "Error converting {} ({}) with {}. Using the data as it is!",
            row.value_name.as_deref().unwrap_or(""),
            row.value_type,
            net::enum_name(key.binary_convert, BIN_CONVERTS)
        )),
    }
    Ok(())
}

/// The row of a plugin's output: BatchDumpKey's BatchCsvOut. The key path is the key the batch file reached, not the row's
pub fn plugin_row(hive: &Hive, k: KeyId, key: &BatchKey, row: registry_plugins::ValuesOut, detail: Option<String>) -> NetResult<Row> {
    let nk = hive.nk(k);
    Ok(Row {
        hive_path: hive.path.clone(),
        hive_type: key.hive_type_name(),
        description: key.description.clone(),
        category: key.category.clone(),
        key_path: hive.keys[k].path.clone(),
        value_name: row.batch_value_name,
        value_type: "(plugin)".into(),
        value_data_null: row.data1_null,
        value_data: row.batch_value_data1,
        value_data2: row.batch_value_data2,
        value_data3: row.batch_value_data3,
        comment: key.comment.clone(),
        recursive: key.recursive,
        deleted: nk.deleted.get(),
        last_write: nk.last_write()?,
        plugin_detail_file: detail,
    })
}

/// The value with this name (FirstOrDefault, case-insensitively)
pub fn find_value(hive: &Hive, k: KeyId, name: &str) -> NetResult<Option<VkId>> {
    for &v in &hive.keys[k].values {
        if ez_common::dotnet::equals_invariant_ignore_case(hive.vks[v].name()?, name) {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

