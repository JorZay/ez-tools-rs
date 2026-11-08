//! Reads the Windows 10/11 Timeline database, ActivitiesCache.db, as WxTCmd's ActivitiesCache does: the rows of the Activity,
//! ActivityOperation and Activity_PackageId tables, with the values it takes from them, and what couldn't be read. Input may be
//! damaged or hostile: a damaged table keeps the rows before the damage, a bad value leaves the rest of its row.
//!
//! The database is copied (with its -wal and -journal) to a new folder in a temporary folder, and only the copy is opened, so
//! nothing is written next to the evidence.

pub mod json;
pub mod text;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use ez_common::dotnet::{dotnet_f64, ordinal_ignore_case};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, OpenFlags};

use json::{Document, Kind};

/// The tables, in the order they are read and reported
pub const TABLES: [&str; 3] = ["ActivityOperation", "Activity_PackageId", "Activity"];

const MAX_ERRORS_PER_TABLE: usize = 100;

/// Seconds since 1970 that a DateTimeOffset can hold
pub const MIN_SECONDS: i64 = -62_135_596_800;
pub const MAX_SECONDS: i64 = 253_402_300_799;

/// The names of ActivityTypes
pub const ACTIVITY_TYPES: [(&str, i64); 5] = [("ToastNotification", 2), ("ExecuteOpen", 5), ("InFocus", 6), ("CloudClipboard", 10), ("CopyPaste", 16)];

/// A row of the Activity table. Times are seconds since 1970 (UTC), None for no time
#[derive(Debug, Clone, Default)]
pub struct Activity {
    pub id: String,
    pub executable: String,
    pub display_text: String,
    pub payload: String,
    pub clipboard_payload: String,
    pub content_info: String,
    pub last_modified_time: Option<i64>,
    pub expiration_time: Option<i64>,
    pub created_in_cloud: Option<i64>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub last_modified_on_client: Option<i64>,
    pub original_last_modified_on_client: Option<i64>,
    pub activity_type: i32,
    pub is_local_only: bool,
    pub etag: i32,
    pub package_id_hash: String,
    pub platform_device_id: String,
    pub device_platform: String,
    pub time_zone: String,
    pub app_activity_id: String,
    pub clipboard_text: String,
}

/// A row of the ActivityOperation table (activities waiting to be uploaded)
#[derive(Debug, Clone, Default)]
pub struct Operation {
    pub id: String,
    pub operation_order: i32,
    pub operation_type: i32,
    pub app_id: String,
    pub executable: String,
    pub description: String,
    pub start_time: Option<i64>,
    pub display_text: String,
    pub clipboard_payload: String,
    pub content_info: String,
    pub device_platform: String,
    pub time_zone: String,
    pub activity_type: i32,
    pub last_modified_time: Option<i64>,
    pub expiration_time: Option<i64>,
    pub payload: String,
    pub created_time: Option<i64>,
    pub end_time: Option<i64>,
    pub last_modified_time_on_client: Option<i64>,
    pub operation_expiration_time: Option<i64>,
    pub platform_device_id: String,
    pub app_activity_id: String,
    pub clipboard_text: String,
}

/// A row of the Activity_PackageId table
#[derive(Debug, Clone, Default)]
pub struct PackageId {
    pub id: String,
    pub platform: String,
    pub name: String,
    pub additional_information: String,
    pub expires: Option<i64>,
}

/// EndTime - StartTime in seconds, when there is an end time after 1970 that differs from the start
pub fn duration(start: Option<i64>, end: Option<i64>) -> Option<i64> {
    let (start, end) = (start?, end?);
    // the end's year is 1970 or before up to the end of 1970
    if start == end || end < 31_536_000 {
        return None;
    }
    Some(end - start)
}

/// The name of an activity type, or its number
pub fn activity_type_name(value: i32) -> String {
    ez_common::net::enum_name(value as i64, &ACTIVITY_TYPES)
}

/// What was read
#[derive(Debug, Default)]
pub struct ActivitiesCacheData {
    pub activities: Vec<Activity>,
    pub operations: Vec<Operation>,
    pub package_ids: Vec<PackageId>,
    /// Of the three tables
    pub missing_tables: Vec<&'static str>,
    /// Tables that could not be read to the end; the rows before the problem are kept
    pub table_errors: Vec<String>,
    /// Values that could not be read; the row is kept with what could be read
    pub parse_errors: Vec<String>,
    /// PRAGMA quick_check ("ok" when undamaged)
    pub quick_check: String,
}

impl ActivitiesCacheData {
    pub fn has_timeline_tables(&self) -> bool {
        self.missing_tables.len() < TABLES.len()
    }
}

/// Why a database couldn't be read
#[derive(Debug)]
pub enum ReadError {
    /// Not a SQLite database, or its list of tables can't be read (InvalidDataException in the original)
    InvalidData(String),
    /// SQLite failed otherwise, as on a file it can't open
    Sqlite(String),
    /// The file couldn't be copied
    Io(String),
}

/// SqliteException.Message
fn sqlite_message(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, detail) => {
            let text = detail.clone().unwrap_or_else(|| rusqlite::ffi::code_to_str(f.extended_code).to_string());
            format!("SQLite Error {}: '{text}'.", f.extended_code & 0xFF)
        }
        other => other.to_string(),
    }
}

fn is_not_a_database(e: &rusqlite::Error) -> bool {
    e.sqlite_error_code() == Some(ErrorCode::NotADatabase)
}

/// The copy of a database in its own folder, removed when dropped
struct Copy {
    folder: PathBuf,
    connection: Option<Connection>,
}

impl Drop for Copy {
    fn drop(&mut self) {
        drop(self.connection.take());
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn open_copy(path: &Path, temp_folder: &Path) -> Result<Copy, ReadError> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let folder = temp_folder.join(format!("WxTCmd-{stamp:024x}{:08x}", std::process::id()));
    let io = |p: &Path, e: std::io::Error| ReadError::Io(ez_common::cli::io_message(p, &e));
    std::fs::create_dir_all(&folder).map_err(|e| io(&folder, e))?;
    let mut copy = Copy { folder, connection: None };
    let name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    let target = copy.folder.join(&name);
    for suffix in ["", "-wal", "-journal"] {
        let mut source = path.as_os_str().to_os_string();
        source.push(suffix);
        let source = PathBuf::from(source);
        // File.Exists: a file, not a folder
        if !std::fs::metadata(&source).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let mut destination = target.as_os_str().to_os_string();
        destination.push(suffix);
        let mut input = std::fs::File::open(&source).map_err(|e| io(&source, e))?;
        let mut output = std::fs::File::create_new(&destination).map_err(|e| io(Path::new(&destination), e))?;
        std::io::copy(&mut input, &mut output).map_err(|e| io(&source, e))?;
    }
    let connection = Connection::open_with_flags(&target, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| ReadError::Sqlite(sqlite_message(&e)))?;
    copy.connection = Some(connection);
    Ok(copy)
}

/// Reads the database at `path` from a copy made in a new folder in `temp_folder`
pub fn read(path: &Path, temp_folder: &Path) -> Result<ActivitiesCacheData, ReadError> {
    let copy = open_copy(path, temp_folder)?;
    let db = copy.connection.as_ref().expect("opened");
    let mut data = ActivitiesCacheData::default();

    let check = (|| -> rusqlite::Result<Vec<String>> {
        let mut stmt = db.prepare("PRAGMA quick_check")?;
        let mut rows = stmt.query([])?;
        let mut lines = Vec::new();
        while let Some(row) = rows.next()? {
            lines.push(value_text(row.get_ref(0)?));
        }
        Ok(lines)
    })();
    match check {
        Ok(lines) => data.quick_check = lines.join("\n"),
        Err(e) if is_not_a_database(&e) => return Err(ReadError::InvalidData("not a SQLite database".into())),
        Err(e) => data.quick_check = sqlite_message(&e),
    }

    // a schema that points past the end of a truncated file is otherwise refused as a whole, losing the rows before the damage.
    // Only the copy is opened, and nothing is written to it
    let tables = (|| -> rusqlite::Result<HashSet<String>> {
        db.execute_batch("PRAGMA writable_schema = ON")?;
        let mut stmt = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
        let mut rows = stmt.query([])?;
        let mut names = HashSet::new();
        while let Some(row) = rows.next()? {
            names.insert(ordinal_ignore_case(&value_text(row.get_ref(0)?)));
        }
        Ok(names)
    })()
    .map_err(|e| {
        ReadError::InvalidData(if is_not_a_database(&e) { "not a SQLite database".into() } else { format!("its tables cannot be read: {}", sqlite_message(&e)) })
    })?;

    read_table(db, &tables, "ActivityOperation", &mut data, |row, data| {
        let operation = read_operation(row);
        data.operations.push(operation);
    });
    read_table(db, &tables, "Activity_PackageId", &mut data, |row, data| {
        let package = read_package_id(row);
        data.package_ids.push(package);
    });
    read_table(db, &tables, "Activity", &mut data, |row, data| {
        let activity = read_activity(row);
        data.activities.push(activity);
    });
    Ok(data)
}

/// Convert.ToString of what Microsoft.Data.Sqlite gives for a value
fn value_text(v: ValueRef) -> String {
    match v {
        ValueRef::Null => String::new(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(f) => dotnet_f64(f),
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Blob(_) => "System.Byte[]".to_string(),
    }
}

/// A value as Microsoft.Data.Sqlite's GetValue gives it, by its storage class
#[derive(Debug, Clone)]
enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<ValueRef<'_>> for Value {
    fn from(v: ValueRef) -> Value {
        match v {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(i) => Value::Integer(i),
            ValueRef::Real(f) => Value::Real(f),
            ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Value::Blob(b.to_vec()),
        }
    }
}

/// The names of a query's columns, read as UTF-8 as .NET reads them (a damaged schema can have names that aren't, which
/// rusqlite refuses)
fn column_names(db: &Connection, sql: &str) -> Vec<String> {
    use rusqlite::ffi;
    let Ok(text) = std::ffi::CString::new(sql) else { return Vec::new() };
    let mut names = Vec::new();
    // SAFETY: the statement is prepared on this connection's handle, only read while it lives, and finalized here
    unsafe {
        let mut stmt = std::ptr::null_mut();
        if ffi::sqlite3_prepare_v2(db.handle(), text.as_ptr(), -1, &mut stmt, std::ptr::null_mut()) != ffi::SQLITE_OK || stmt.is_null() {
            ffi::sqlite3_finalize(stmt);
            return names;
        }
        for i in 0..ffi::sqlite3_column_count(stmt) {
            let name = ffi::sqlite3_column_name(stmt, i);
            names.push(if name.is_null() { String::new() } else { String::from_utf8_lossy(std::ffi::CStr::from_ptr(name).to_bytes()).into_owned() });
        }
        ffi::sqlite3_finalize(stmt);
    }
    names
}

fn read_table(db: &Connection, tables: &HashSet<String>, table: &'static str, data: &mut ActivitiesCacheData, mut add: impl FnMut(&mut Row, &mut ActivitiesCacheData)) {
    if !tables.contains(&ordinal_ignore_case(table)) {
        data.missing_tables.push(table);
        return;
    }
    let mut number = 0usize;
    let mut errors = 0usize;
    let result = (|| -> rusqlite::Result<()> {
        let sql = format!("SELECT * FROM [{table}]");
        let mut stmt = db.prepare(&sql)?;
        let mut columns = HashMap::new();
        for (i, name) in column_names(db, &sql).iter().enumerate() {
            columns.insert(ordinal_ignore_case(name), i);
        }
        let count = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            number += 1;
            let mut values = Vec::with_capacity(count);
            for i in 0..count {
                values.push(Value::from(r.get_ref(i)?));
            }
            let mut row = Row { values, columns: &columns, errors: Vec::new() };
            add(&mut row, data);
            for error in row.errors {
                errors += 1;
                if errors <= MAX_ERRORS_PER_TABLE {
                    data.parse_errors.push(format!("{table} row {}: {error}", ez_common::dotnet::n0(number as u64)));
                }
            }
        }
        Ok(())
    })();
    if errors > MAX_ERRORS_PER_TABLE {
        data.parse_errors.push(format!("{table}: {} more errors", ez_common::dotnet::n0((errors - MAX_ERRORS_PER_TABLE) as u64)));
    }
    if let Err(e) = result {
        data.table_errors.push(format!("{table}: error after {} rows: {}", ez_common::dotnet::n0(number as u64), sqlite_message(&e)));
    }
}

/// One row; a missing column reads as null (the schema changed over Windows versions)
struct Row<'a> {
    values: Vec<Value>,
    columns: &'a HashMap<String, usize>,
    errors: Vec<String>,
}

/// How a value is shown in an error: up to 16 bytes of a blob, and at most 40 characters
fn show(v: &Value) -> String {
    let s = match v {
        Value::Blob(b) => ez_common::net::hex(&b[..b.len().min(16)]),
        other => text_of(other).unwrap_or_default(),
    };
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() > 40 { format!("{}...", String::from_utf16_lossy(&units[..40])) } else { s }
}

/// Convert.ToString(value, InvariantCulture), or null for null
fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::Integer(i) => Some(i.to_string()),
        Value::Real(f) => Some(dotnet_f64(*f)),
        Value::Text(t) => Some(t.clone()),
        Value::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
    }
}

impl Row<'_> {
    fn value(&self, column: &str) -> &Value {
        match self.columns.get(&ordinal_ignore_case(column)) {
            Some(&i) => &self.values[i],
            None => &Value::Null,
        }
    }

    /// A string; a blob read as UTF-8
    fn string(&self, column: &str) -> Option<String> {
        text_of(self.value(column))
    }

    fn try_or<T>(&mut self, column: &str, fallback: T, read: impl FnOnce() -> Result<T, String>) -> T {
        match read() {
            Ok(v) => v,
            Err(e) => {
                self.errors.push(format!("{column}: {e}"));
                fallback
            }
        }
    }

    fn int(&mut self, column: &str) -> i32 {
        let v = self.value(column).clone();
        let parsed = match &v {
            Value::Null => return 0,
            Value::Integer(i) => i32::try_from(*i).ok(),
            Value::Text(s) => text::parse_integer(s, i32::MIN as i64, i32::MAX as i64).map(|i| i as i32),
            _ => None,
        };
        parsed.unwrap_or_else(|| {
            self.errors.push(format!("{column}: '{}' is not a number", show(&v)));
            0
        })
    }

    /// Seconds since 1970 (UTC). 0 is no time
    fn time(&mut self, column: &str) -> Option<i64> {
        let v = self.value(column).clone();
        let seconds = match &v {
            Value::Null => return None,
            Value::Integer(i) => Some(*i),
            // (long)d, which saturates; NaN and what is out of range are no number
            Value::Real(d) if *d >= i64::MIN as f64 && *d <= i64::MAX as f64 => Some(*d as i64),
            Value::Text(s) => text::parse_integer(s, i64::MIN, i64::MAX),
            _ => None,
        };
        let Some(seconds) = seconds else {
            self.errors.push(format!("{column}: '{}' is not a time", show(&v)));
            return None;
        };
        if seconds == 0 {
            return None;
        }
        if !(MIN_SECONDS..=MAX_SECONDS).contains(&seconds) {
            self.errors.push(format!("{column}: {seconds} is out of range for a time"));
            return None;
        }
        Some(seconds)
    }

    /// 16 bytes as a .NET Guid; other bytes as hex; anything else as text
    fn guid(&self, column: &str) -> String {
        match self.value(column) {
            Value::Blob(b) if b.len() == 16 => ez_common::net::guid(b[..].try_into().expect("16 bytes")),
            Value::Blob(b) => ez_common::net::hex(b).replace('-', ""),
            other => text_of(other).unwrap_or_default(),
        }
    }
}

/// What a payload gives
#[derive(Default)]
struct PayloadInfo {
    payload: String,
    display_text: Option<String>,
    content_info: Option<String>,
    device_platform: Option<String>,
    time_zone: Option<String>,
}

fn read_payload(row: &mut Row) -> PayloadInfo {
    let mut info = PayloadInfo { payload: String::new(), ..Default::default() };
    let payload = row.string("Payload").unwrap_or_default();
    if !text::culture_starts_with(&payload, '{') {
        info.payload = if payload.is_empty() { String::new() } else { "(Binary data)".to_string() };
        return info;
    }
    info.payload = payload.clone();
    // what is read before a failure stays
    let read = |info: &mut PayloadInfo| -> Result<(), String> {
        let doc = Document::parse(&payload)?;
        if !matches!(doc.root.kind, Kind::Object(_)) {
            return Ok(());
        }
        let json = &doc.root;
        info.time_zone = doc.property(json, "userTimezone")?;
        info.device_platform = doc.property(json, "devicePlatform")?;
        info.display_text = doc.property(json, "displayText")?;
        let description = doc.property(json, "description")?;
        let content_uri = doc.property(json, "contentUri")?;
        if content_uri.is_some() || description.is_some() {
            let app_name = doc.property(json, "appDisplayName")?;
            if let Some(app) = app_name.filter(|a| !a.is_empty()) {
                info.display_text = Some(format!("{} ({app})", info.display_text.as_deref().unwrap_or_default()));
            }
            let uri = content_uri.as_deref().map(content_uri_text);
            info.content_info = match uri.filter(|u| !u.is_empty()) {
                None => description,
                Some(u) => Some(format!("{} ({u})", description.as_deref().unwrap_or_default())),
            };
        }
        Ok(())
    };
    let result = read(&mut info);
    row.try_or("Payload", (), || result);
    info
}

/// The application from the AppId JSON ([{"application":..., "platform":...}, ...]): the Win32 or executable path one, else
/// the UWP one, else the first. A known folder GUID at its start is replaced by the folder's name
pub fn executable(app_id: Option<&str>) -> Result<String, String> {
    let Some(app_id) = app_id.filter(|a| !a.is_empty()) else { return Ok(String::new()) };
    let doc = Document::parse(app_id)?;
    let Kind::Array(items) = &doc.root.kind else { return Ok(String::new()) };
    let mut apps = Vec::new();
    for item in items.iter().filter(|i| matches!(i.kind, Kind::Object(_))) {
        let platform = doc.property(item, "platform")?.unwrap_or_default();
        let application = doc.property(item, "application")?.unwrap_or_default();
        apps.push((ordinal_ignore_case(&platform), application));
    }
    let app = apps
        .iter()
        .find(|(p, _)| p == "WINDOWS_WIN32" || p == "X_EXE_PATH")
        .or_else(|| apps.iter().find(|(p, _)| p == "WINDOWS_UNIVERSAL"))
        .or_else(|| apps.first());
    let Some((_, application)) = app else { return Ok(String::new()) };
    Ok(map_guid_prefix(application).unwrap_or_else(|| application.clone()))
}

/// `{known folder GUID}\rest` with the GUID replaced by the folder's name; None when there is none or it is unknown
pub fn map_guid_prefix(path: &str) -> Option<String> {
    if !path.starts_with('{') {
        return None;
    }
    let (first, rest) = match path.find('\\') {
        Some(i) => (&path[..i], &path[i..]),
        None => (path, ""),
    };
    let name = guidmapping_ez::description(first)?;
    Some(format!("{name}{rest}"))
}

/// A content URI URL decoded; a known folder GUID right after `file:` (or `file:///`) is replaced by the folder's name
pub fn content_uri_text(uri: &str) -> String {
    let decoded = text::url_decode(uri);
    if let Some(rest) = decoded.strip_prefix("file:") {
        let (scheme, rest) = match rest.strip_prefix("///") {
            Some(r) if r.starts_with('{') => ("file:///", r),
            _ => ("file:", rest),
        };
        let guid = rest.strip_prefix('{').and_then(|r| r.get(..37)).filter(|g| g.ends_with('}')).map(|g| &g[..36]);
        if let Some(guid) = guid.filter(|g| g.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')) {
            if let Some(name) = guidmapping_ez::description(guid) {
                return format!("{scheme}{name}{}", &rest[38..]);
            }
        }
    }
    decoded
}

/// ClipboardPayload is a JSON array of {"content": base64, "formatName": ...}: the content of the text formats (or of entries
/// without a format) that is UTF-8 text, joined with " | "
pub fn clipboard_text(payload: &str) -> Result<String, String> {
    let trimmed = payload.trim_start_matches(char::is_whitespace);
    if trimmed.is_empty() || !text::culture_starts_with(trimmed, '[') {
        return Ok(String::new());
    }
    let doc = Document::parse(payload)?;
    let Kind::Array(items) = &doc.root.kind else {
        return Err("The requested operation requires an element of type 'Array', but the target element has type 'Object'.".to_string());
    };
    let mut texts = Vec::new();
    for item in items.iter().filter(|i| matches!(i.kind, Kind::Object(_))) {
        let format = doc.property(item, "formatName")?;
        let content = doc.property(item, "content")?;
        let Some(content) = content.filter(|c| !c.is_empty()) else { continue };
        if format.is_some_and(|f| !ordinal_ignore_case(&f).contains("TEXT")) {
            continue;
        }
        let Some(bytes) = text::from_base64(&content) else { continue };
        if let Ok(text) = String::from_utf8(bytes) {
            texts.push(text.trim_end_matches('\0').to_string());
        }
    }
    Ok(texts.join(" | "))
}

fn read_activity(row: &mut Row) -> Activity {
    let app_id = row.string("AppId");
    let id = row.guid("Id");
    let executable = { let r = executable(app_id.as_deref()); row.try_or("AppId", String::new(), || r) };
    let mut a = Activity {
        id,
        executable,
        activity_type: row.int("ActivityType"),
        last_modified_time: row.time("LastModifiedTime"),
        expiration_time: row.time("ExpirationTime"),
        created_in_cloud: row.time("CreatedInCloud"),
        start_time: row.time("StartTime"),
        end_time: row.time("EndTime"),
        last_modified_on_client: row.time("LastModifiedOnClient"),
        original_last_modified_on_client: row.time("OriginalLastModifiedOnClient"),
        is_local_only: row.int("IsLocalOnly") == 1,
        etag: row.int("ETag"),
        package_id_hash: row.string("PackageIdHash").unwrap_or_default(),
        platform_device_id: row.string("PlatformDeviceId").unwrap_or_default(),
        app_activity_id: row.string("AppActivityId").unwrap_or_default(),
        ..Default::default()
    };
    let p = read_payload(row);
    a.payload = p.payload;
    a.display_text = p.display_text.unwrap_or_default();
    a.content_info = p.content_info.unwrap_or_default();
    a.device_platform = p.device_platform.unwrap_or_default();
    a.time_zone = p.time_zone.unwrap_or_default();
    a.clipboard_payload = row.string("ClipboardPayload").unwrap_or_default();
    let r = clipboard_text(&a.clipboard_payload);
    a.clipboard_text = row.try_or("ClipboardPayload", String::new(), || r);
    a
}

fn read_operation(row: &mut Row) -> Operation {
    let app_id = row.string("AppId");
    let id = row.guid("Id");
    let operation_order = row.int("OperationOrder");
    let operation_type = row.int("OperationType");
    let executable = { let r = executable(app_id.as_deref()); row.try_or("AppId", String::new(), || r) };
    let mut o = Operation {
        id,
        operation_order,
        operation_type,
        app_id: app_id.unwrap_or_default(),
        executable,
        activity_type: row.int("ActivityType"),
        last_modified_time: row.time("LastModifiedTime"),
        expiration_time: row.time("ExpirationTime"),
        created_time: row.time("CreatedTime"),
        start_time: row.time("StartTime"),
        end_time: row.time("EndTime"),
        last_modified_time_on_client: row.time("LastModifiedOnClient"),
        operation_expiration_time: row.time("OperationExpirationTime"),
        platform_device_id: row.string("PlatformDeviceId").unwrap_or_default(),
        app_activity_id: row.string("AppActivityId").unwrap_or_default(),
        ..Default::default()
    };
    let p = read_payload(row);
    o.payload = p.payload;
    o.display_text = p.display_text.unwrap_or_default();
    o.content_info = p.content_info.unwrap_or_default();
    o.device_platform = p.device_platform.unwrap_or_default();
    o.time_zone = p.time_zone.unwrap_or_default();
    o.clipboard_payload = row.string("ClipboardPayload").unwrap_or_default();
    let r = clipboard_text(&o.clipboard_payload);
    o.clipboard_text = row.try_or("ClipboardPayload", String::new(), || r);
    o
}

fn read_package_id(row: &mut Row) -> PackageId {
    let name = row.string("PackageName").unwrap_or_default();
    let additional = if name.contains(".exe") { map_guid_prefix(&name).unwrap_or_default() } else { String::new() };
    let id = row.guid("ActivityId");
    let platform = row.string("Platform");
    let expires = row.time("ExpirationTime");
    let platform = match platform.as_deref() {
        Some("windows_win32") => "Win32".to_string(),
        Some("x_exe_path") => "ExecutablePath".to_string(),
        Some("packageId") => "Package".to_string(),
        other => other.unwrap_or_default().to_string(),
    };
    PackageId { id, platform, name, additional_information: additional, expires }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = r#"[{"application":"{6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe","platform":"windows_win32"},{"application":"","platform":"packageId"}]"#;

    #[test]
    fn executables() {
        assert_eq!(executable(Some(APP_ID)).unwrap(), "ProgramFilesX64\\Notepad++\\notepad++.exe");
        assert_eq!(executable(Some(r#"[{"application":"Microsoft.Windows.Explorer","platform":"windows_universal"},{"application":"x","platform":"host"}]"#)).unwrap(), "Microsoft.Windows.Explorer");
        assert_eq!(executable(Some(r#"[{"application":"a","platform":"host"}]"#)).unwrap(), "a");
        assert_eq!(executable(Some(r#"[{"application":"{00000000-0000-0000-0000-00000000ABCD}\\a.exe","platform":"x_exe_path"}]"#)).unwrap(), "{00000000-0000-0000-0000-00000000ABCD}\\a.exe");
        assert_eq!(executable(Some("[]")).unwrap(), "");
        assert_eq!(executable(Some("{}")).unwrap(), "");
        assert_eq!(executable(None).unwrap(), "");
        assert!(executable(Some("not json")).is_err());
    }

    #[test]
    fn content_uris() {
        assert_eq!(content_uri_text("file:///C:/temp/a%20b.txt?VolumeId={A78E0A99-2928-4625-90CF-E0B88E88439B}"), "file:///C:/temp/a b.txt?VolumeId={A78E0A99-2928-4625-90CF-E0B88E88439B}");
        assert_eq!(content_uri_text("file:{374DE290-123F-4565-9164-39C4925E467B}\\a.zip"), "file:Downloads\\a.zip");
        assert_eq!(content_uri_text("file:///{374DE290-123F-4565-9164-39C4925E467B}\\a.zip"), "file:///Downloads\\a.zip");
        assert_eq!(content_uri_text("file://{374DE290-123F-4565-9164-39C4925E467B}\\a.zip"), "file://{374DE290-123F-4565-9164-39C4925E467B}\\a.zip");
        assert_eq!(content_uri_text("file:{00000000-0000-0000-0000-00000000ABCD}\\a.zip"), "file:{00000000-0000-0000-0000-00000000ABCD}\\a.zip");
        assert_eq!(content_uri_text("{"), "{");
    }

    #[test]
    fn clipboard() {
        let text = |p: &str| clipboard_text(p).unwrap_or_else(|_| "error".into());
        assert_eq!(text(r#"[{"content":"aGVsbG8=","formatName":"Text"}]"#), "hello");
        assert_eq!(text(r#"[{"content":"aGVsbG8="}]"#), "hello");
        assert_eq!(text(r#"[{"content":"aGVsbG8=","formatName":"Text"},{"content":"d29ybGQ=","formatName":"UnicodeText"}]"#), "hello | world");
        assert_eq!(text(r#"[{"content":"/9j/4AAQ","formatName":"Bitmap"}]"#), "");
        assert_eq!(text(r#"[{"content":"/9j/4AAQ","formatName":"Text"}]"#), "");
        assert_eq!(text(r#"[{"content":"not base64!","formatName":"Text"}]"#), "");
        assert_eq!(text(r#"[1, "x", null]"#), "");
        assert_eq!(text(""), "");
        assert_eq!(text("binary"), "");
        assert_eq!(text(r#"[{"content":"aGk=","formatName":"Text"},{"content":" ","formatName":"Text"}]"#), "hi | ");
        assert_eq!(text("[{\"content\": 5"), "error");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(Some(1_646_000_000), Some(1_646_000_065)), Some(65));
        assert_eq!(duration(Some(1_646_000_000), Some(1_646_000_000)), None);
        assert_eq!(duration(Some(1_646_000_000), Some(86_400)), None);
        assert_eq!(duration(Some(1_646_000_000), Some(31_536_000)), Some(31_536_000 - 1_646_000_000));
        assert_eq!(duration(None, Some(5)), None);
    }
}
