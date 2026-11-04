//! AmcacheDatabases: the `Inventory*.db` SQLite databases that replace Amcache.hve's Root keys from Windows 11 26H1 on.
//! Each database is copied, with its -wal and -journal, to a new folder and only the copy is opened, so nothing is
//! written next to the evidence.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ez_common::dotnet::{n0, upper_invariant};
use ez_common::{Level, Timestamp};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use crate::new::{AmcacheNew, InventoryItem, InventoryValue, Reporter, values_text};
use crate::{Error, Observer, Sink};

/// The databases read into the classes; every other one goes to other_tables
const TYPED_DATABASES: [&str; 7] = [
    "InventoryApplication",
    "InventoryApplicationFile",
    "InventoryApplicationShortcut",
    "InventoryDeviceContainer",
    "InventoryDevicePnp",
    "InventoryDriverBinary",
    "InventoryDriverPackage",
];

/// A column's value
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// A database table as it is
#[derive(Debug, Clone)]
pub struct DatabaseTable {
    /// The database's file name (empty for the Metadata table, which has a Database column)
    pub database: String,
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// Rows left out because a newer copy of the same ItemKey was there (damaged databases)
    pub older_copies: usize,
}

fn files_with(directory: &str, matches: impl Fn(&str) -> bool) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(directory) else { return vec![] };
    entries
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| matches(n))
        .collect()
}

/// Whether a folder has the Inventory*.db databases. Names match in any case, as on Windows
pub fn has_databases(directory: &str) -> bool {
    !files_with(directory, |n| {
        let lower = n.to_ascii_lowercase();
        lower.starts_with("inventory") && lower.ends_with(".db")
    })
    .is_empty()
}

/// The *.db files of a folder (names)
pub fn database_files(directory: &str) -> Vec<String> {
    files_with(directory, |n| n.to_ascii_lowercase().ends_with(".db"))
}

/// LastModified (a FILETIME, UTC); 0 or out of range is the minimum
pub fn from_file_time_value(value: i64) -> Timestamp {
    if value > 0 { Timestamp::from_filetime(value).unwrap_or(Timestamp::MIN) } else { Timestamp::MIN }
}

/// What SqliteException says
fn sqlite_message(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, Some(m)) => format!("SQLite Error {}: '{m}'.", f.extended_code & 0xFF),
        rusqlite::Error::SqliteFailure(f, None) => format!("SQLite Error {}: '{f}'.", f.extended_code & 0xFF),
        other => other.to_string(),
    }
}

/// Why a database could not be read, and whether it is an access problem and not a damaged file
struct ReadFailure {
    message: String,
    access: bool,
}

impl From<rusqlite::Error> for ReadFailure {
    fn from(e: rusqlite::Error) -> ReadFailure {
        ReadFailure { message: sqlite_message(&e), access: false }
    }
}

fn io_failure(path: &Path, e: &std::io::Error) -> ReadFailure {
    let message = match e.kind() {
        std::io::ErrorKind::PermissionDenied => format!("Access to the path '{}' is denied.", path.display()),
        std::io::ErrorKind::NotFound => format!("Could not find file '{}'.", path.display()),
        _ => e.to_string(),
    };
    ReadFailure { message, access: true }
}

static NEXT_FOLDER: AtomicU64 = AtomicU64::new(0);

/// A name no other run has, as a GUID gives the original
fn unique_name() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("AmcacheParser-{now:032x}{:08x}{:04x}", std::process::id(), NEXT_FOLDER.fetch_add(1, Ordering::Relaxed))
}

/// A database copied to a new folder, deleted when dropped
struct SqliteCopy<'s, 'a> {
    connection: Option<Connection>,
    folder: PathBuf,
    sink: &'s Sink<'a>,
}

impl Drop for SqliteCopy<'_, '_> {
    fn drop(&mut self) {
        // closed first: SQLite removes a -wal and -journal then
        self.connection.take();
        if let Err(e) = std::fs::remove_dir_all(&self.folder) {
            self.sink.log(Level::Debug, &format!("Could not delete {}: {e}", self.folder.display()));
        }
    }
}

impl<'s, 'a> SqliteCopy<'s, 'a> {
    fn open(path: &Path, temp_directory: Option<&str>, sink: &'s Sink<'a>) -> Result<SqliteCopy<'s, 'a>, ReadFailure> {
        let base = temp_directory.map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let folder = base.join(unique_name());
        std::fs::create_dir(&folder).map_err(|e| io_failure(&folder, &e))?;
        let mut copy = SqliteCopy { connection: None, folder, sink };
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let target = copy.folder.join(&name);
        for suffix in ["", "-wal", "-journal"] {
            let source = PathBuf::from(format!("{}{suffix}", path.display()));
            if source.is_file() {
                let to = PathBuf::from(format!("{}{suffix}", target.display()));
                std::fs::copy(&source, &to).map_err(|e| io_failure(&source, &e))?;
            }
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        copy.connection = Some(Connection::open_with_flags(&target, flags)?);
        Ok(copy)
    }

    fn connection(&self) -> &Connection {
        self.connection.as_ref().expect("the connection is open until the copy is dropped")
    }

    fn quick_check(&self) -> String {
        let run = || -> rusqlite::Result<String> {
            let mut statement = self.connection().prepare("PRAGMA quick_check")?;
            let mut rows = statement.query([])?;
            let mut problems = Vec::new();
            while let Some(row) = rows.next()? {
                problems.push(row.get::<_, String>(0)?);
            }
            Ok(problems.join("\n"))
        };
        run().unwrap_or_else(|e| sqlite_message(&e))
    }

    fn tables(&self) -> rusqlite::Result<Vec<String>> {
        let mut statement =
            self.connection().prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid")?;
        let mut rows = statement.query([])?;
        let mut tables = Vec::new();
        while let Some(row) = rows.next()? {
            tables.push(row.get::<_, String>(0)?);
        }
        Ok(tables)
    }

    /// Every row. An error on the first step is the query failing; a damaged database can also fail part way, and the
    /// rows read until then are kept
    fn read_table(&self, database: &str, name: &str) -> rusqlite::Result<DatabaseTable> {
        let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
        let mut statement = self.connection().prepare(&sql)?;
        let columns: Vec<String> = statement.column_names().iter().map(|s| s.to_string()).collect();
        let count = columns.len();
        let mut table = DatabaseTable { database: database.to_string(), name: name.to_string(), columns, rows: vec![], older_copies: 0 };
        let mut rows = statement.query([])?;
        let mut first = true;
        loop {
            let row = match rows.next() {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(e) if first => return Err(e),
                Err(e) => {
                    self.sink.log(
                        Level::Error,
                        &format!("{database}: reading {name} stopped after {} rows: {}", n0(table.rows.len() as u64), sqlite_message(&e)),
                    );
                    break;
                }
            };
            first = false;
            let mut values = Vec::with_capacity(count);
            for i in 0..count {
                values.push(match row.get_ref(i)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(v) => Value::Integer(v),
                    ValueRef::Real(v) => Value::Real(v),
                    ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => Value::Blob(b.to_vec()),
                });
            }
            table.rows.push(values);
        }
        Ok(table)
    }
}

fn as_long(value: &Value) -> i64 {
    if let Value::Integer(v) = value { *v } else { 0 }
}

/// One row per ItemKey: the one with the latest LastModified (a damaged database can have older copies)
fn newest(table: DatabaseTable, sink: &Sink) -> DatabaseTable {
    let key_index = table.columns.iter().position(|c| c == "ItemKey");
    let time_index = table.columns.iter().position(|c| c == "LastModified");
    let (Some(key_index), Some(time_index)) = (key_index, time_index) else { return table };

    let mut first_seen: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<usize> = Vec::with_capacity(table.rows.len());
    let mut older = 0;
    for (i, row) in table.rows.iter().enumerate() {
        let key = if let Value::Text(k) = &row[key_index] { k.clone() } else { String::new() };
        match first_seen.get(&key) {
            None => {
                first_seen.insert(key, order.len());
                order.push(i);
            }
            Some(&at) => {
                older += 1;
                if as_long(&row[time_index]) > as_long(&table.rows[order[at]][time_index]) {
                    order[at] = i;
                }
            }
        }
    }
    if older == 0 {
        return table;
    }
    sink.log(
        Level::Warning,
        &format!(
            "{}: {} older copies of rows were left out ({} rows, {} ItemKeys)",
            table.database,
            n0(older as u64),
            n0(table.rows.len() as u64),
            n0(order.len() as u64)
        ),
    );
    let rows = order.iter().map(|&i| table.rows[i].clone()).collect();
    DatabaseTable { rows, older_copies: older, ..table }
}

fn add_metadata(other_tables: &mut Vec<DatabaseTable>, read: DatabaseTable) {
    let at = match other_tables.iter().position(|t| t.name == "Metadata") {
        Some(i) => i,
        None => {
            other_tables.push(DatabaseTable {
                database: String::new(),
                name: "Metadata".into(),
                columns: vec!["Database".into(), "Name".into(), "Value".into()],
                rows: vec![],
                older_copies: 0,
            });
            other_tables.len() - 1
        }
    };
    let name_index = read.columns.iter().position(|c| c == "Name");
    let value_index = read.columns.iter().position(|c| c == "Value");
    for row in read.rows {
        let cell = |i: Option<usize>| i.map_or(Value::Null, |i| row[i].clone());
        other_tables[at].rows.push(vec![Value::Text(read.database.clone()), cell(name_index), cell(value_index)]);
    }
}

#[derive(Default)]
struct Counts {
    not_read: i32,
    not_accessed: i32,
}

/// A database's table (the one that isn't Metadata_N), newest row per ItemKey
fn read_database(path: &Path, other_tables: &mut Vec<DatabaseTable>, temp_directory: Option<&str>, counts: &mut Counts, sink: &Sink) -> Result<Option<DatabaseTable>, Error> {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let length = std::fs::metadata(path).map(|m| m.len()).map_err(|e| crate::read_error(&path.to_string_lossy(), &e))?;
    if length == 0 {
        sink.log(Level::Debug, &format!("{file_name} is empty"));
        return Ok(None);
    }

    let mut read = || -> Result<Option<DatabaseTable>, ReadFailure> {
        let db = SqliteCopy::open(path, temp_directory, sink)?;
        let check = db.quick_check();
        if check != "ok" {
            sink.log(
                Level::Warning,
                &format!(
                    "{file_name} is damaged ({}). A row can appear more than once, from older copies of it; the newest is used",
                    check.split('\n').next().unwrap_or("")
                ),
            );
        }
        let mut table = None;
        for name in db.tables()? {
            let read = db.read_table(&file_name, &name)?;
            let lower = name.to_lowercase();
            if lower.starts_with("metadata_") {
                add_metadata(other_tables, read);
                continue;
            }
            if table.is_some() {
                sink.log(Level::Warning, &format!("{file_name} has more than one table; {name} is listed with the other tables"));
                other_tables.push(newest(read, sink));
                continue;
            }
            table = Some(newest(read, sink));
        }
        if table.is_none() {
            sink.log(Level::Warning, &format!("{file_name} has no data table"));
        }
        Ok(table)
    };

    match read() {
        Ok(t) => Ok(t),
        Err(f) => {
            sink.log(Level::Error, &format!("{file_name} could not be read: {}", f.message));
            counts.not_read += 1;
            if f.access {
                counts.not_accessed += 1;
            }
            Ok(None)
        }
    }
}

/// A column's value as the registry value's data was: text as is, numbers in decimal
fn as_registry_data(database: &str, column: &str, value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Text(s) => s.clone(),
        Value::Integer(l) => {
            // a DWORD in the hive (unsigned: Microsoft's reproducible build values are past 2038), signed here
            if *l < 0 && *l >= i32::MIN as i64 && column == "DriverTimeStamp" && database.eq_ignore_ascii_case("InventoryDriverBinary") {
                (*l + 0x1_0000_0000).to_string()
            } else {
                l.to_string()
            }
        }
        Value::Real(d) => ez_common::dotnet::dotnet_f64(*d),
        Value::Blob(b) => b.iter().map(|x| format!("{x:02X}")).collect(),
    }
}

/// The rows as hive keys: ItemKey is the key name, LastModified the last write time, the other columns its values
fn to_items(table: &DatabaseTable, database: &str) -> Vec<InventoryItem> {
    let key_index = table.columns.iter().position(|c| c == "ItemKey");
    let time_index = table.columns.iter().position(|c| c == "LastModified");
    table
        .rows
        .iter()
        .map(|row| {
            let key_name = key_index.map_or(String::new(), |i| as_registry_data("", "", &row[i]));
            let last_write = time_index.map_or(Timestamp::MIN, |i| match &row[i] {
                Value::Integer(v) => from_file_time_value(*v),
                _ => Timestamp::MIN,
            });
            let values = row
                .iter()
                .enumerate()
                .filter(|(i, _)| Some(*i) != key_index && Some(*i) != time_index)
                .map(|(i, v)| InventoryValue { name: table.columns[i].clone(), data: as_registry_data(database, &table.columns[i], v), is_deleted: false })
                .collect();
            InventoryItem { key_path: format!("{}: {key_name}", table.database), key_name, last_write, is_deleted: false, values }
        })
        .collect()
}

const MAX_ERRORS: i32 = 10;

/// Per database table instead of per row: a column the hive logic doesn't use is the same in every row
struct DatabaseReporter<'s, 'a> {
    sink: &'s Sink<'a>,
    errors: i32,
    not_tracked: Vec<(String, BTreeSet<String>)>,
    unknown: Vec<(String, BTreeSet<String>)>,
    per_category: Vec<(String, i32)>,
}

fn add_column(sets: &mut Vec<(String, BTreeSet<String>)>, category: &str, name: &str) {
    if let Some((_, set)) = sets.iter_mut().find(|(c, _)| c == category) {
        set.insert(name.to_string());
    } else {
        sets.push((category.to_string(), BTreeSet::from([name.to_string()])));
    }
}

impl Reporter for DatabaseReporter<'_, '_> {
    fn not_tracked(&mut self, category: &str, _item: &InventoryItem, value: &InventoryValue) {
        add_column(&mut self.not_tracked, category, &value.name);
    }

    fn unknown(&mut self, category: &str, _item: &InventoryItem, value: &InventoryValue, _only_when_not_deleted: bool) {
        add_column(&mut self.unknown, category, &value.name);
    }

    fn error(&mut self, category: &str, item: &InventoryItem, message: &str) {
        let at = match self.per_category.iter().position(|(c, _)| c == category) {
            Some(i) => i,
            None => {
                self.per_category.push((category.to_string(), 0));
                self.per_category.len() - 1
            }
        };
        let count = self.per_category[at].1;
        self.per_category[at].1 = count + 1;
        self.errors += 1;
        if count < MAX_ERRORS {
            self.sink.log(Level::Error, &format!("Error parsing {category} at {}. Error: {message}", item.key_path));
            self.sink.log(Level::Error, &format!("Row data: {}", values_text(item)));
        }
    }

    fn errors(&self) -> i32 {
        self.errors
    }
}

impl DatabaseReporter<'_, '_> {
    fn flush(&self) {
        let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
        for (category, set) in &self.not_tracked {
            self.sink.log(Level::Debug, &format!("Columns not used for {category}: {}", join(set)));
        }
        for (category, set) in &self.unknown {
            self.sink.log(Level::Warning, &format!("Unknown columns for {category}: {}", join(set)));
        }
        for (category, count) in self.per_category.iter().filter(|(_, n)| *n > MAX_ERRORS) {
            self.sink.log(Level::Error, &format!("{} {category} rows could not be parsed ({MAX_ERRORS} shown)", n0(*count as u64)));
        }
    }
}

impl AmcacheNew {
    /// FromDatabases: the copies are made in new folders in `temp_directory` (the system's temporary folder if None)
    pub fn from_databases(directory: &str, temp_directory: Option<&str>, observer: Observer) -> Result<AmcacheNew, Error> {
        let sink = Sink::new(observer);
        let mut am = AmcacheNew::default();
        let mut reporter = DatabaseReporter { sink: &sink, errors: 0, not_tracked: vec![], unknown: vec![], per_category: vec![] };
        let mut counts = Counts::default();

        let items = |am: &mut AmcacheNew, name: &str, counts: &mut Counts| -> Result<Vec<InventoryItem>, Error> {
            let wanted = format!("{name}.db");
            let found = database_files(directory).into_iter().find(|f| f.eq_ignore_ascii_case(&wanted));
            let Some(found) = found else {
                sink.log(Level::Debug, &format!("{} not found", Path::new(directory).join(&wanted).display()));
                return Ok(vec![]);
            };
            let path = Path::new(directory).join(found);
            let table = read_database(&path, &mut am.other_tables, temp_directory, counts, &sink)?;
            Ok(table.map(|t| to_items(&t, name)).unwrap_or_default())
        };
        let ok = |v: Vec<InventoryItem>| v.into_iter().map(Ok::<_, String>);

        // programs first, so files can be associated with them
        let list = items(&mut am, "InventoryApplication", &mut counts)?;
        am.add_programs(&mut ok(list), &mut reporter, &sink)?;
        let list = items(&mut am, "InventoryApplicationFile", &mut counts)?;
        am.add_files(&mut ok(list), &mut reporter, &sink)?;
        let list = items(&mut am, "InventoryApplicationShortcut", &mut counts)?;
        am.add_shortcuts(&mut ok(list), true)?;
        let list = items(&mut am, "InventoryDeviceContainer", &mut counts)?;
        am.add_device_containers(&mut ok(list), &mut reporter)?;
        let list = items(&mut am, "InventoryDevicePnp", &mut counts)?;
        am.add_device_pnps(&mut ok(list), &mut reporter)?;
        let list = items(&mut am, "InventoryDriverBinary", &mut counts)?;
        am.add_driver_binaries(&mut ok(list), &mut reporter, &sink)?;
        let list = items(&mut am, "InventoryDriverPackage", &mut counts)?;
        am.add_driver_packages(&mut ok(list), &mut reporter, &sink)?;

        let mut others = database_files(directory);
        others.sort_by_key(|n| upper_invariant(n));
        for file in others {
            let name = &file[..file.len() - 3];
            if TYPED_DATABASES.iter().any(|t| t.eq_ignore_ascii_case(name)) {
                continue;
            }
            let path = Path::new(directory).join(&file);
            if let Some(table) = read_database(&path, &mut am.other_tables, temp_directory, &mut counts, &sink)? {
                am.other_tables.push(table);
            }
        }

        reporter.flush();
        am.entries_not_parsed = reporter.errors;
        am.databases_not_read = counts.not_read;
        am.databases_not_accessed = counts.not_accessed;
        Ok(am)
    }
}
