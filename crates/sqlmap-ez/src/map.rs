//! `.smap` files as YamlDotNet and FluentValidation take them in SQLMap: scalars stay text (`IdentifyValue: 05` is "05"),
//! unknown fields are errors, and null, empty and missing values are told apart.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ez_common::Level;
use ez_common::cli::log::Logger;
use ez_common::dotnet::{compare_culture, upper_invariant};
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::TScalarStyle;

/// Where messages go
pub trait Sink {
    fn log(&mut self, level: Level, message: &str);
    /// A message followed by an exception as .NET writes it (a stack trace isn't kept)
    fn exception(&mut self, level: Level, message: &str, exception: &str);
    /// Console.WriteLine
    fn blank(&mut self);
}

impl Sink for Logger {
    fn log(&mut self, level: Level, message: &str) {
        self.block(level, message);
    }

    fn exception(&mut self, level: Level, message: &str, exception: &str) {
        // Serilog reads the exception's text line by line, and a lone \r also ends a line
        self.block(level, &format!("{message}\n{}", exception.replace("\r\n", "\n").replace('\r', "\n")));
    }

    fn blank(&mut self) {
        Logger::blank(self);
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlobColumn {
    pub blob_column: Option<String>,
    pub name_column: Option<String>,
    pub blob_extension: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct QueryInfo {
    pub name: Option<String>,
    pub query: Option<String>,
    pub base_file_name: Option<String>,
    /// null entries are kept for the validator
    pub blob_columns: Option<Vec<Option<BlobColumn>>>,
}

#[derive(Clone, Debug, Default)]
pub struct MapFile {
    pub description: Option<String>,
    pub author: Option<String>,
    pub email: Option<String>,
    pub id: Option<String>,
    pub version: f64,
    pub csv_prefix: Option<String>,
    pub file_name: Option<String>,
    pub identify_query: Option<String>,
    pub identify_value: Option<String>,
    pub queries: Option<Vec<Option<QueryInfo>>>,
}

impl MapFile {
    pub fn id_text(&self) -> &str {
        self.id.as_deref().unwrap_or_default()
    }
    pub fn description_text(&self) -> &str {
        self.description.as_deref().unwrap_or_default()
    }
    pub fn prefix_text(&self) -> &str {
        self.csv_prefix.as_deref().unwrap_or_default()
    }
    pub fn file_name_text(&self) -> &str {
        self.file_name.as_deref().unwrap_or_default()
    }
    pub fn identify_query_text(&self) -> &str {
        self.identify_query.as_deref().unwrap_or_default()
    }
    pub fn identify_value_text(&self) -> &str {
        self.identify_value.as_deref().unwrap_or_default()
    }
    /// After validation there are no null queries
    pub fn query_list(&self) -> impl Iterator<Item = &QueryInfo> {
        self.queries.iter().flatten().flatten()
    }
}

impl QueryInfo {
    pub fn name_text(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }
    pub fn query_text(&self) -> &str {
        self.query.as_deref().unwrap_or_default()
    }
    pub fn base_name_text(&self) -> &str {
        self.base_file_name.as_deref().unwrap_or_default()
    }
    pub fn blob_list(&self) -> impl Iterator<Item = &BlobColumn> {
        self.blob_columns.iter().flatten().flatten()
    }
}

/// How a file failed to load
enum Failure {
    /// SyntaxErrorException
    Syntax(String),
    /// YamlException, with its inner exception's message
    Yaml(Option<String>),
}

#[derive(Clone)]
enum Node {
    Null,
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
}

fn is_null_scalar(text: &str, style: TScalarStyle, tag: &Option<Tag>) -> bool {
    if tag.as_ref().is_some_and(|t| t.suffix == "null") {
        return true;
    }
    style == TScalarStyle::Plain && tag.is_none() && matches!(text, "" | "~" | "null" | "Null" | "NULL")
}

/// A collection being read
enum Frame {
    Seq(Vec<Node>, usize),
    /// The pairs, the key waiting for its value, and the anchor
    Map(Vec<(Node, Node)>, Option<Node>, usize),
}

fn add(stack: &mut [Frame], root: &mut Option<Node>, node: Node) {
    match stack.last_mut() {
        None => *root = Some(node),
        Some(Frame::Seq(items, _)) => items.push(node),
        Some(Frame::Map(pairs, key, _)) => match key.take() {
            Some(k) => pairs.push((k, node)),
            None => *key = Some(node),
        },
    }
}

/// One document, as Deserialize takes it: a second one is an error
fn read_document(text: &str) -> Result<Option<Node>, Failure> {
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<Frame> = Vec::new();
    let mut anchors: HashMap<usize, Node> = HashMap::new();
    let mut root = None;
    let mut documents = 0;

    loop {
        let (event, _) = parser.next_token().map_err(|_| failure_of_scan(text))?;
        match event {
            Event::StreamStart | Event::Nothing | Event::DocumentEnd => {}
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(Failure::Yaml(None));
                }
            }
            Event::Alias(id) => {
                let Some(node) = anchors.get(&id).cloned() else { return Err(Failure::Yaml(None)) };
                add(&mut stack, &mut root, node);
            }
            Event::Scalar(value, style, anchor, tag) => {
                let node = if is_null_scalar(&value, style, &tag) { Node::Null } else { Node::Scalar(value) };
                if anchor > 0 {
                    anchors.insert(anchor, node.clone());
                }
                add(&mut stack, &mut root, node);
            }
            Event::SequenceStart(anchor, _) => stack.push(Frame::Seq(Vec::new(), anchor)),
            Event::MappingStart(anchor, _) => stack.push(Frame::Map(Vec::new(), None, anchor)),
            Event::SequenceEnd | Event::MappingEnd => {
                let (node, anchor) = match stack.pop() {
                    Some(Frame::Seq(items, anchor)) => (Node::Seq(items), anchor),
                    Some(Frame::Map(pairs, _, anchor)) => (Node::Map(pairs), anchor),
                    None => (Node::Null, 0),
                };
                if anchor > 0 {
                    anchors.insert(anchor, node.clone());
                }
                add(&mut stack, &mut root, node);
            }
        }
    }
    Ok(root)
}

/// YamlDotNet's scanner reports a tab where indentation is expected as a syntax error, the others from its parser as
/// plain YAML errors. Its texts are its own
fn failure_of_scan(text: &str) -> Failure {
    if text.contains('\t') {
        Failure::Syntax("While scanning a plain scalar, found a tab character that violate indentation.".to_string())
    } else {
        Failure::Yaml(None)
    }
}

fn string_of(node: &Node) -> Result<Option<String>, Failure> {
    match node {
        Node::Null => Ok(None),
        Node::Scalar(s) => Ok(Some(s.clone())),
        Node::Seq(_) => Err(Failure::Yaml(None)),
        Node::Map(_) => Err(Failure::Yaml(Some("Failed to create an instance of type 'System.String'.".to_string()))),
    }
}

/// double.Parse with the invariant culture
fn double_of(node: &Node) -> Result<f64, Failure> {
    match node {
        Node::Null => Ok(0.0),
        Node::Scalar(s) => match s.trim().parse::<f64>() {
            Ok(v) if !s.trim().is_empty() => Ok(v),
            _ => Err(Failure::Yaml(Some(format!("The input string '{s}' was not in a correct format.")))),
        },
        Node::Seq(_) => Err(Failure::Yaml(None)),
        Node::Map(_) => Err(Failure::Yaml(Some("Failed to create an instance of type 'System.Double'.".to_string()))),
    }
}

fn pairs_of<'a>(node: &'a Node, type_name: &str) -> Result<&'a [(Node, Node)], Failure> {
    match node {
        Node::Map(pairs) => Ok(pairs),
        Node::Scalar(_) => Err(Failure::Yaml(Some(format!("Invalid cast from 'System.String' to '{type_name}'.")))),
        _ => Err(Failure::Yaml(None)),
    }
}

fn key_of(key: &Node) -> Result<&str, Failure> {
    match key {
        Node::Scalar(k) => Ok(k),
        _ => Err(Failure::Yaml(None)),
    }
}

fn blob_of(node: &Node) -> Result<Option<BlobColumn>, Failure> {
    if matches!(node, Node::Null) {
        return Ok(None);
    }
    let mut blob = BlobColumn::default();
    for (key, value) in pairs_of(node, "SQLMaps.BlobColumnConfig")? {
        match key_of(key)? {
            "BlobColumn" => blob.blob_column = string_of(value)?,
            "NameColumn" => blob.name_column = string_of(value)?,
            "BlobExtension" => blob.blob_extension = string_of(value)?,
            _ => return Err(Failure::Yaml(None)),
        }
    }
    Ok(Some(blob))
}

fn list_of<T>(node: &Node, item: impl Fn(&Node) -> Result<Option<T>, Failure>) -> Result<Option<Vec<Option<T>>>, Failure> {
    match node {
        Node::Null => Ok(None),
        Node::Seq(items) => items.iter().map(item).collect::<Result<Vec<_>, _>>().map(Some),
        _ => Err(Failure::Yaml(None)),
    }
}

fn query_of(node: &Node) -> Result<Option<QueryInfo>, Failure> {
    if matches!(node, Node::Null) {
        return Ok(None);
    }
    // the class starts BlobColumns as an empty list
    let mut query = QueryInfo { blob_columns: Some(Vec::new()), ..QueryInfo::default() };
    for (key, value) in pairs_of(node, "SQLMaps.QueryInfo")? {
        match key_of(key)? {
            "Name" => query.name = string_of(value)?,
            "Query" => query.query = string_of(value)?,
            "BaseFileName" => query.base_file_name = string_of(value)?,
            "BlobColumns" => query.blob_columns = list_of(value, blob_of)?,
            _ => return Err(Failure::Yaml(None)),
        }
    }
    Ok(Some(query))
}

fn map_of(node: &Node) -> Result<Option<MapFile>, Failure> {
    if matches!(node, Node::Null) {
        return Ok(None);
    }
    let mut map = MapFile::default();
    for (key, value) in pairs_of(node, "SQLMaps.MapFile")? {
        match key_of(key)? {
            "Description" => map.description = string_of(value)?,
            "Author" => map.author = string_of(value)?,
            "Email" => map.email = string_of(value)?,
            "Id" => map.id = string_of(value)?,
            "Version" => map.version = double_of(value)?,
            "CSVPrefix" => map.csv_prefix = string_of(value)?,
            "FileName" => map.file_name = string_of(value)?,
            "IdentifyQuery" => map.identify_query = string_of(value)?,
            "IdentifyValue" => map.identify_value = string_of(value)?,
            "Queries" => map.queries = list_of(value, query_of)?,
            _ => return Err(Failure::Yaml(None)),
        }
    }
    Ok(Some(map))
}

fn not_empty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|s| !s.chars().all(char::is_whitespace))
}

/// FluentValidation's messages, in the order of the rules
fn validate(map: &MapFile) -> Vec<String> {
    let mut errors = Vec::new();
    let empty = |name: &str| format!("'{name}' must not be empty.");
    if map.description.is_none() {
        errors.push(empty("Description"));
    }
    if map.csv_prefix.is_none() {
        errors.push(empty("CSV Prefix"));
    }
    for (value, name) in [(&map.author, "Author"), (&map.email, "Email"), (&map.id, "Id")] {
        if !not_empty(value) {
            errors.push(empty(name));
        }
    }
    if map.version == 0.0 {
        errors.push(empty("Version"));
    }
    for (value, name) in [(&map.file_name, "File Name"), (&map.identify_query, "Identify Query"), (&map.identify_value, "Identify Value")] {
        if !not_empty(value) {
            errors.push(empty(name));
        }
    }
    let queries = map.queries.as_deref().unwrap_or_default();
    if queries.is_empty() {
        errors.push("Queries must contain at least one query".to_string());
    }
    for query in queries {
        let Some(query) = query else {
            errors.push("Queries".to_string());
            continue;
        };
        for (value, name) in [(&query.name, "Name"), (&query.query, "Query"), (&query.base_file_name, "Base File Name")] {
            if !not_empty(value) {
                errors.push(empty(name));
            }
        }
        for blob in query.blob_columns.as_deref().unwrap_or_default() {
            let Some(blob) = blob else {
                errors.push(empty("Blob Columns"));
                continue;
            };
            if !not_empty(&blob.blob_column) {
                errors.push("BlobColumn in BlobColumnConfig cannot be empty.".to_string());
            }
            if let Some(extension) = blob.blob_extension.as_deref().filter(|e| !e.is_empty()) {
                // ^[a-zA-Z0-9_]+$, where $ also takes a line break at the end
                let body = extension.strip_suffix('\n').unwrap_or(extension);
                if body.is_empty() || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                    errors.push("BlobExtension can only contain alphanumeric characters and underscores.".to_string());
                }
            }
        }
    }
    errors
}

/// File.ReadAllText: the encoding from the byte order mark, UTF-8 otherwise
fn read_all_text(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let utf16 = |rest: &[u8], big: bool| {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| if big { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) }).collect();
        String::from_utf16_lossy(&units)
    };
    Ok(match bytes.as_slice() {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        all => String::from_utf8_lossy(all).into_owned(),
    })
}

/// Every *.smap under the folder, in any case, as EnumerateFileSystemEntries with RecurseSubdirectories finds them
fn find_map_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("smap")) {
            out.push(path.clone());
        }
        if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
            find_map_files(&path, out);
        }
    }
}

pub struct LoadedMaps {
    /// In the order they were loaded, which is the order they are run in
    pub maps: Vec<MapFile>,
    /// Maps with errors, which ends the run
    pub had_errors: bool,
}

fn display_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// SqlMap.LoadMaps
pub fn load_maps(dir: &str, sink: &mut dyn Sink) -> LoadedMaps {
    let mut files = Vec::new();
    find_map_files(Path::new(dir), &mut files);
    let mut names: Vec<(String, PathBuf)> = files.into_iter().map(|p| (p.to_string_lossy().into_owned(), p)).collect();
    names.sort_by(|a, b| compare_culture(&a.0, &b.0));

    let mut maps = Vec::new();
    let mut seen = HashSet::new();
    let mut error_maps = Vec::new();

    for (name, path) in &names {
        let text = match read_all_text(path) {
            Ok(t) => t,
            Err(e) => {
                let message = ez_common::cli::io_message(path, &e);
                sink.exception(Level::Error, &format!("Error loading map file '{name}': {message}"), &format!("{}: {message}", ez_common::cli::io_exception(&e)));
                continue;
            }
        };
        let loaded = read_document(&text).and_then(|d| d.as_ref().map_or(Ok(None), map_of));
        let map = match loaded {
            Ok(Some(map)) => map,
            Ok(None) => {
                let message = "Cannot pass null model to Validate. (Parameter 'instanceToValidate')";
                sink.exception(Level::Error, &format!("Error loading map file '{name}': {message}"), &format!("System.ArgumentNullException: {message}"));
                continue;
            }
            Err(Failure::Syntax(message)) => {
                error_maps.push(display_name(path));
                sink.blank();
                sink.log(Level::Warning, &format!("Syntax error in {name}"));
                sink.log(Level::Fatal, &message);
                sink.blank();
                sink.log(Level::Fatal, "Bad line (or close to it) has invalid data");
                if text.contains('\t') {
                    sink.blank();
                    sink.log(Level::Error, "Bad line contains one or more tab characters. Replace them with spaces");
                    sink.blank();
                    sink.log(Level::Info, &text.replace('\t', "<TAB>"));
                }
                continue;
            }
            Err(Failure::Yaml(inner)) => {
                error_maps.push(display_name(path));
                sink.blank();
                sink.log(Level::Warning, &format!("Syntax error in {name}"));
                sink.log(Level::Info, &text);
                if let Some(inner) = inner {
                    sink.log(Level::Fatal, &inner);
                }
                sink.blank();
                sink.log(Level::Fatal, "Verify all properties against example files or manual and try again");
                continue;
            }
        };

        let errors = validate(&map);
        if !errors.is_empty() {
            sink.blank();
            sink.log(Level::Error, &format!("{name} had validation errors"));
            for e in &errors {
                sink.log(Level::Info, e);
            }
            sink.blank();
            sink.blank();
            sink.log(Level::Error, "Correct the errors and try again. Exiting");
            sink.blank();
            error_maps.push(display_name(path));
            continue;
        }

        if seen.insert(upper_invariant(map.id_text())) {
            sink.log(Level::Debug, &format!("{} is valid. Id: {}. Adding to maps...", display_name(path), map.id_text()));
            maps.push(map);
        } else {
            sink.log(Level::Warning, &format!("A map with Id {} already exists (File name: {}). Map {} will be skipped", map.id_text(), map.file_name_text(), display_name(path)));
        }
    }

    if !error_maps.is_empty() {
        sink.blank();
        sink.log(Level::Error, "The following maps had errors. Scroll up to review errors, correct them, and try again");
        for name in &error_maps {
            sink.log(Level::Info, name);
        }
        sink.blank();
    }

    LoadedMaps { maps, had_errors: !error_maps.is_empty() }
}
