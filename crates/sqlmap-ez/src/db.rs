//! A database opened as SQLECmd opens it: statements run as System.Data.SQLite's reader runs them, and failures read as its exceptions.

use std::ffi::CString;
use std::path::Path;
use std::sync::OnceLock;

use ez_common::net::utf8;
use rusqlite::types::{ToSqlOutput, Value as SqlValue, ValueRef};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{Batch, Connection, Error as SqlError, OpenFlags, params};

use crate::value::{Kind, Value, kind_of, text_to_bool, to_date, to_decimal, to_guid};

/// An exception as the original would have it
#[derive(Clone, Debug)]
pub struct NetError {
    /// What the log shows after the message: the exception's ToString(), without its stack trace
    pub exception: String,
    /// Exception.Message
    pub message: String,
    /// IOException or UnauthorizedAccessException, which give exit code 1
    pub access: bool,
}

impl NetError {
    fn plain(type_name: &str, message: impl Into<String>) -> NetError {
        let message = message.into();
        NetError { exception: format!("{type_name}: {message}"), message, access: false }
    }

    pub(crate) fn format(message: String) -> NetError {
        NetError::plain("System.FormatException", message)
    }

    pub(crate) fn argument(message: &str) -> NetError {
        NetError::plain("System.ArgumentException", message)
    }

    pub(crate) fn overflow(message: &str) -> NetError {
        NetError::plain("System.OverflowException", message)
    }

    pub(crate) fn invalid_cast(message: &str) -> NetError {
        NetError::plain("System.InvalidCastException", message)
    }

    fn not_implemented() -> NetError {
        NetError::plain("System.NotImplementedException", "The method or operation is not implemented.")
    }

    fn cannot_convert_to_bool() -> NetError {
        let message = "unknown error\nCannot convert type Object to boolean".to_string();
        NetError { exception: format!("code = 65535 (65535), message = System.Data.SQLite.SQLiteException (0x80004005): {message}"), message, access: false }
    }

    pub fn from_io(path: &Path, e: &std::io::Error) -> NetError {
        let message = ez_common::cli::io_message(path, e);
        NetError { exception: format!("{}: {message}", ez_common::cli::io_exception(e)), message, access: true }
    }

    /// new InvalidDataException("Unable to read database: ...", inner)
    pub fn unable_to_read(inner: &NetError) -> NetError {
        let message = format!("Unable to read database: {}", inner.message);
        NetError { exception: format!("System.IO.InvalidDataException: {message}\n ---> {}\n   --- End of inner exception stack trace ---", inner.exception), message, access: false }
    }

    pub fn duplicate_key(key: &str) -> NetError {
        NetError::plain("System.ArgumentException", format!("An item with the same key has already been added. Key: {key}"))
    }

    fn sqlite(code: i32, detail: &str) -> NetError {
        let (name, text, hresult) = sqlite_code(code & 0xFF);
        let message = format!("{text}\n{detail}").trim().to_string();
        NetError { exception: format!("code = {name} ({}), message = System.Data.SQLite.SQLiteException (0x{hresult:08X}): {message}", code & 0xFF), message, access: false }
    }
}

/// The name of SQLiteErrorCode, sqlite3_errstr, and the HRESULT SQLiteException takes from them
fn sqlite_code(code: i32) -> (&'static str, &'static str, u32) {
    const FACILITY: u32 = 0x87AF_0000;
    match code {
        1 => ("Error", "SQL logic error", FACILITY | 0x001F),
        2 => ("Internal", "internal logic error", 0x8000_FFFF),
        3 => ("Perm", "access permission denied", FACILITY | 0x0005),
        4 => ("Abort", "query aborted", 0x8000_4004),
        5 => ("Busy", "database is locked", FACILITY | 0x00AA),
        6 => ("Locked", "database table is locked", FACILITY | 0x00D4),
        7 => ("NoMem", "out of memory", FACILITY | 0x000E),
        8 => ("ReadOnly", "attempt to write a readonly database", FACILITY | 0x1779),
        9 => ("Interrupt", "interrupted", FACILITY | 0x04C7),
        10 => ("IoErr", "disk I/O error", FACILITY | 0x045D),
        11 => ("Corrupt", "database disk image is malformed", FACILITY | 0x054E),
        12 => ("NotFound", "unknown operation", FACILITY | 0x0032),
        13 => ("Full", "database or disk is full", FACILITY | 0x0070),
        14 => ("CantOpen", "unable to open database file", FACILITY | 0x03F3),
        15 => ("Protocol", "locking protocol", FACILITY | 0x05B4),
        16 => ("Empty", "table contains no data", FACILITY | 0x10D2),
        17 => ("Schema", "database schema has changed", FACILITY | 0x078B),
        18 => ("TooBig", "string or blob too big", 0x8002_88C5),
        19 => ("Constraint", "constraint failed", FACILITY | 0x202F),
        20 => ("Mismatch", "datatype mismatch", FACILITY | 0x065D),
        21 => ("Misuse", "bad parameter or other API misuse", FACILITY | 0x0649),
        22 => ("NoLfs", "large file support is disabled", FACILITY | 0x0646),
        23 => ("Auth", "authorization denied", FACILITY | 0x078F),
        24 => ("Format", "auxiliary database format error", FACILITY | 0x000B),
        25 => ("Range", "column index out of range", 0x8002_8CA1),
        26 => ("NotADb", "file is not a database", FACILITY | 0x0570),
        _ => ("Unknown", "unknown error", 0x8000_4005),
    }
}

impl From<SqlError> for NetError {
    fn from(e: SqlError) -> NetError {
        match e {
            SqlError::SqliteFailure(f, detail) => NetError::sqlite(f.extended_code, detail.as_deref().unwrap_or_default()),
            SqlError::SqlInputError { error, msg, .. } => NetError::sqlite(error.extended_code, &msg),
            other => NetError::sqlite(1, &other.to_string()),
        }
    }
}

/// SqLiteFile.IsSqLiteFile, without the message for what can't be opened
pub fn is_sqlite_file(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut head = [0u8; 8];
    Ok(file.read_exact(&mut head).is_ok() && &head == b"SQLite f")
}

/// The rows of a query, as Dapper's rows behave: they share their column names, and a removed value leaves its column
#[derive(Debug)]
pub struct Table {
    pub names: Vec<String>,
    rows: Vec<Vec<Option<Value>>>,
}

impl Table {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// With duplicate names, the first one
    fn index_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n == name)
    }

    /// row[name]: null for a name that isn't there
    pub fn get(&self, row: usize, name: &str) -> Option<&Value> {
        self.index_of(name).and_then(|i| self.rows[row].get(i)).and_then(Option::as_ref)
    }

    /// The name's column, or a new one
    pub fn set_all(&mut self, name: &str, value: &Value) {
        let index = match self.index_of(name) {
            Some(i) => i,
            None => {
                self.names.push(name.to_string());
                self.names.len() - 1
            }
        };
        for row in &mut self.rows {
            if row.len() <= index {
                row.resize(index + 1, Some(Value::Null));
            }
            row[index] = Some(value.clone());
        }
    }

    /// Removes each column whose name passes, where the first column with that name holds a byte array
    pub fn remove_blobs(&mut self, row: usize, is_blob_column: impl Fn(&str) -> bool) {
        let names: Vec<usize> = self.names.iter().enumerate().filter(|(i, n)| self.rows[row].get(*i).is_some_and(Option::is_some) && is_blob_column(n)).map(|(i, _)| i).collect();
        for i in names {
            let first = self.index_of(&self.names[i].clone()).unwrap_or(i);
            if matches!(self.rows[row].get(first), Some(Some(Value::Blob(_)))) {
                self.rows[row][first] = None;
            }
        }
    }

    /// The names and values the row still has
    pub fn cells(&self, row: usize) -> impl Iterator<Item = (&str, &Value)> {
        self.names.iter().enumerate().filter_map(move |(i, n)| self.rows[row].get(i).and_then(Option::as_ref).map(|v| (n.as_str(), v)))
    }
}

/// The reference's native library has no FTS5, so a query on such a table fails there with "no such module: fts5". This
/// bundled SQLite has it built in: every other module stays. The names come from an empty database, as asking a damaged one
/// would fail here and not at its first query
fn drop_fts5(conn: &Connection) -> Result<(), NetError> {
    static KEEP: OnceLock<Vec<CString>> = OnceLock::new();
    let names = KEEP.get_or_init(|| {
        let list = || -> rusqlite::Result<Vec<String>> {
            let memory = Connection::open_in_memory()?;
            let mut statement = memory.prepare("SELECT name FROM pragma_module_list WHERE name NOT IN ('fts5', 'fts5vocab')")?;
            statement.query_map([], |r| r.get::<_, String>(0))?.collect()
        };
        list().unwrap_or_default().into_iter().filter_map(|n| CString::new(n).ok()).collect()
    });
    let mut pointers: Vec<*const std::ffi::c_char> = names.iter().map(|n| n.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // the list ends with a null, and lives through the call
    unsafe { rusqlite::ffi::sqlite3_drop_modules(conn.handle(), pointers.as_mut_ptr()) };
    Ok(())
}

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Opens the copy of a database
    pub fn open(path: &Path) -> Result<Database, NetError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI)?;
        // the reference's SQLite leaves foreign keys off; this bundled one turns them on
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, false)?;
        // SQLite wrote reals as text with 15 digits until 3.52, as the reference's does; a map may turn one into text
        unsafe { rusqlite::ffi::sqlite3_db_config(conn.handle(), rusqlite::ffi::SQLITE_DBCONFIG_FP_DIGITS, 15i32, std::ptr::null_mut::<i32>()) };
        drop_fts5(&conn)?;
        crate::functions::register(&conn)?;
        Ok(Database { conn })
    }

    fn cast(&self, value: ValueRef<'_>, to: &str) -> Result<SqlValue, NetError> {
        let sql = format!("SELECT CAST(?1 AS {to})");
        let mut statement = self.conn.prepare_cached(&sql)?;
        Ok(statement.query_row(params![ToSqlOutput::Borrowed(value)], |r| r.get::<_, SqlValue>(0))?)
    }

    /// A statement's column names and types. Not through rusqlite, which panics on what isn't UTF-8, as in a damaged schema: the
    /// original reads those as any text, and such a type isn't one it knows
    fn describe(&self, sql: &str) -> Vec<(String, Kind)> {
        use rusqlite::ffi;
        let text = |p: *const std::ffi::c_char| {
            if p.is_null() {
                return None;
            }
            // SQLite's strings end with a NUL and stay valid until the statement is finalized
            Some(String::from_utf8_lossy(unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes()).into_owned())
        };
        let mut columns = Vec::new();
        let Ok(source) = CString::new(sql) else { return columns };
        let mut statement = std::ptr::null_mut();
        // the statement is prepared again only to be read, and finalized here; a failure leaves no columns
        unsafe {
            if ffi::sqlite3_prepare_v2(self.conn.handle(), source.as_ptr(), -1, &mut statement, std::ptr::null_mut()) == ffi::SQLITE_OK {
                for i in 0..ffi::sqlite3_column_count(statement) {
                    let name = text(ffi::sqlite3_column_name(statement, i)).unwrap_or_default();
                    let declared = text(ffi::sqlite3_column_decltype(statement, i));
                    columns.push((name, kind_of(declared.as_deref())));
                }
            }
            ffi::sqlite3_finalize(statement);
        }
        columns
    }

    /// sqlite3_column_int64
    fn as_i64(&self, value: ValueRef<'_>) -> Result<i64, NetError> {
        if let ValueRef::Integer(v) = value {
            return Ok(v);
        }
        match self.cast(value, "INTEGER")? {
            SqlValue::Integer(v) => Ok(v),
            _ => Ok(0),
        }
    }

    /// sqlite3_column_double
    fn as_f64(&self, value: ValueRef<'_>) -> Result<f64, NetError> {
        match value {
            ValueRef::Real(v) => return Ok(v),
            ValueRef::Integer(v) => return Ok(v as f64),
            _ => {}
        }
        match self.cast(value, "REAL")? {
            SqlValue::Real(v) => Ok(v),
            SqlValue::Integer(v) => Ok(v as f64),
            _ => Ok(0.0),
        }
    }

    /// sqlite3_column_text or sqlite3_column_blob's bytes
    fn as_bytes(&self, value: ValueRef<'_>) -> Result<Vec<u8>, NetError> {
        Ok(match value {
            ValueRef::Text(t) | ValueRef::Blob(t) => t.to_vec(),
            ValueRef::Integer(v) => v.to_string().into_bytes(),
            ValueRef::Real(_) => match self.cast(value, "TEXT")? {
                SqlValue::Text(t) => t.into_bytes(),
                _ => Vec::new(),
            },
            ValueRef::Null => Vec::new(),
        })
    }

    fn as_text(&self, value: ValueRef<'_>) -> Result<String, NetError> {
        Ok(utf8(&self.as_bytes(value)?).into_owned())
    }

    /// SQLite3.GetValue
    fn convert(&self, kind: Kind, value: ValueRef<'_>) -> Result<Value, NetError> {
        if matches!(value, ValueRef::Null) {
            return Ok(Value::Null);
        }
        Ok(match kind {
            Kind::AsStored => match value {
                ValueRef::Integer(v) => Value::Int(v),
                ValueRef::Real(v) => Value::Double(v),
                ValueRef::Text(t) => Value::Text(utf8(t).into_owned()),
                ValueRef::Blob(b) => Value::Blob(b.to_vec()),
                ValueRef::Null => Value::Null,
            },
            Kind::Text => Value::Text(self.as_text(value)?),
            Kind::Binary => Value::Blob(self.as_bytes(value)?),
            Kind::Guid => {
                if let ValueRef::Text(t) = value {
                    return to_guid(&utf8(t));
                }
                let bytes = self.as_bytes(value)?;
                match <[u8; 16]>::try_from(bytes.as_slice()) {
                    Ok(g) => Value::Guid(g),
                    Err(_) => Value::Blob(bytes),
                }
            }
            Kind::Date => return to_date(&self.as_text(value)?),
            Kind::Bool => Value::Bool(match value {
                ValueRef::Integer(v) => v != 0,
                ValueRef::Real(v) => v != 0.0,
                ValueRef::Text(t) => text_to_bool(&utf8(t))?,
                ValueRef::Blob([]) => return Err(NetError::not_implemented()),
                _ => return Err(NetError::cannot_convert_to_bool()),
            }),
            Kind::Double => Value::Double(self.as_f64(value)?),
            Kind::Single => Value::Single(self.as_f64(value)? as f32),
            Kind::Decimal => return to_decimal(self.as_f64(value)?),
            Kind::SByte => Value::Int(i64::from(self.as_i64(value)? as i8)),
            Kind::Byte => Value::Int(i64::from(self.as_i64(value)? as u8)),
            Kind::Int16 => Value::Int(i64::from(self.as_i64(value)? as i16)),
            Kind::UInt16 => Value::Int(i64::from(self.as_i64(value)? as u16)),
            Kind::Int32 => Value::Int(i64::from(self.as_i64(value)? as i32)),
            Kind::UInt32 => Value::Int(i64::from(self.as_i64(value)? as u32)),
            Kind::Int64 => Value::Int(self.as_i64(value)?),
            Kind::UInt64 => Value::UInt(self.as_i64(value)? as u64),
        })
    }

    /// db.Query&lt;dynamic&gt;: statements with no columns run first, the first with columns gives the rows, and the rest
    /// still run (and can fail the query)
    pub fn query(&self, sql: &str) -> Result<Table, NetError> {
        let mut table: Option<Table> = None;
        let mut batch = Batch::new(&self.conn, sql);
        while let Some(mut statement) = batch.next()? {
            if table.is_some() || statement.column_count() == 0 {
                statement.raw_query().next()?;
                continue;
            }
            let (names, kinds): (Vec<String>, Vec<Kind>) = self.describe(&statement.expanded_sql().unwrap_or_default()).into_iter().unzip();
            let mut rows = Vec::new();
            let mut cursor = statement.raw_query();
            while let Some(row) = cursor.next()? {
                let mut cells = Vec::with_capacity(names.len() + 1);
                for (i, kind) in kinds.iter().enumerate() {
                    cells.push(Some(self.convert(*kind, row.get_ref(i)?)?));
                }
                rows.push(cells);
            }
            table = Some(Table { names, rows });
        }
        Ok(table.unwrap_or(Table { names: Vec::new(), rows: Vec::new() }))
    }

    /// db.ExecuteScalar&lt;string&gt;: the first column of the first row
    pub fn scalar(&self, sql: &str) -> Result<Option<String>, NetError> {
        let mut batch = Batch::new(&self.conn, sql);
        while let Some(mut statement) = batch.next()? {
            if statement.column_count() == 0 {
                statement.raw_query().next()?;
                continue;
            }
            let kind = self.describe(&statement.expanded_sql().unwrap_or_default()).first().map_or(Kind::AsStored, |c| c.1);
            let mut cursor = statement.raw_query();
            return match cursor.next()? {
                Some(row) => self.convert(kind, row.get_ref(0)?)?.scalar_text(),
                None => Ok(None),
            };
        }
        Ok(None)
    }

    /// The names of the tables, sorted, for a database with no map
    pub fn table_names(&self) -> Result<Vec<String>, NetError> {
        let mut statement = self.conn.prepare("SELECT name FROM sqlite_master WHERE type='table' order by name")?;
        let mut cursor = statement.raw_query();
        let mut names = Vec::new();
        while let Some(row) = cursor.next()? {
            let value = row.get_ref(0)?;
            names.push(self.as_text(value)?);
        }
        Ok(names)
    }
}
