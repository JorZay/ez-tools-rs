//! Maps load as the original takes them, shipped ones are untouched, and values come out as they do from System.Data.SQLite.

use std::path::{Path, PathBuf};

use ez_common::Level;
use sha1::{Digest, Sha1};
use sqlmap_ez::{Database, Sink, Table, load_maps};

#[derive(Default)]
struct Lines(Vec<String>);

impl Sink for Lines {
    fn log(&mut self, _: Level, message: &str) {
        self.0.push(message.to_string());
    }
    fn exception(&mut self, _: Level, message: &str, exception: &str) {
        self.0.push(format!("{message}|{exception}"));
    }
    fn blank(&mut self) {}
}

fn shipped() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../maps-sqlecmd")
}

struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Temp {
        let dir = std::env::temp_dir().join(format!("sqlmap-ez-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Temp(dir)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const VALID: &str = "Description: d\nAuthor: a\nEmail: e\nId: one\nVersion: 1.0\nCSVPrefix: P\nFileName: x.db\nIdentifyQuery: SELECT 1\nIdentifyValue: 1\nQueries:\n    -\n        Name: n\n        Query: SELECT 1 AS a\n        BaseFileName: b\n";

fn load_one(text: &str) -> (sqlmap_ez::LoadedMaps, Vec<String>) {
    let dir = Temp::new(&format!("map{:x}", Sha1::digest(text.as_bytes())[0..4].iter().fold(0u32, |v, b| v << 8 | u32::from(*b))));
    std::fs::write(dir.0.join("m.smap"), text).unwrap();
    let mut lines = Lines::default();
    let loaded = load_maps(dir.0.to_str().unwrap(), &mut lines);
    (loaded, lines.0)
}

#[test]
fn every_shipped_map_loads_unchanged() {
    let mut lines = Lines::default();
    let loaded = load_maps(shipped().to_str().unwrap(), &mut lines);
    assert!(!loaded.had_errors, "{:?}", lines.0);
    assert_eq!(loaded.maps.len(), 93);
    assert_eq!(loaded.maps.iter().map(|m| m.query_list().count()).sum::<usize>(), 138);

    // the maps are used as upstream wrote them: to update them, copy the new ones and this list together
    let list = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/shipped-maps.sha1")).unwrap();
    for line in list.lines() {
        let (expected, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(shipped().join(name)).unwrap();
        let actual: String = Sha1::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual, expected, "{name} was changed");
    }
}

#[test]
fn identify_value_stays_text() {
    for (written, expected) in [("05", "05"), ("0x10", "0x10"), ("1.0", "1.0"), ("true", "true"), ("'null'", "null"), ("\"7\"", "7")] {
        let (loaded, lines) = load_one(&VALID.replace("IdentifyValue: 1", &format!("IdentifyValue: {written}")));
        assert!(!loaded.had_errors, "{lines:?}");
        assert_eq!(loaded.maps[0].identify_value_text(), expected);
    }
}

#[test]
fn what_the_original_refuses_is_refused() {
    for (text, message) in [
        (VALID.replace("Author: a", "Author: ~"), "'Author' must not be empty."),
        (VALID.replace("Author: a", "Author: null"), "'Author' must not be empty."),
        (VALID.replace("CSVPrefix: P\n", ""), "'CSV Prefix' must not be empty."),
        (VALID.replace("FileName: x.db\n", ""), "'File Name' must not be empty."),
        (VALID.replace("Version: 1.0", "Version: 0"), "'Version' must not be empty."),
        (VALID.replace("Version: 1.0", "Version: abc"), "The input string 'abc' was not in a correct format."),
        (format!("{VALID}Extra: 1\n"), "Verify all properties against example files or manual and try again"),
        (VALID.replace("Author:", "author:"), "Verify all properties against example files or manual and try again"),
        (format!("{VALID}---\nAuthor: b\n"), "Verify all properties against example files or manual and try again"),
        (format!("{VALID}        BlobColumns:\n            - BlobColumn: x\n              BlobExtension: a.b\n"), "BlobExtension can only contain alphanumeric characters and underscores."),
    ] {
        let (loaded, lines) = load_one(&text);
        assert!(loaded.had_errors, "{text}");
        assert!(lines.iter().any(|l| l == message), "{message} not in {lines:?}");
    }
}

#[test]
fn what_the_original_takes_is_taken() {
    for text in [
        format!("\u{feff}{VALID}"),
        VALID.replace('\n', "\r\n"),
        VALID.replace("Description: d", "Description: ''"),
        VALID.replace("Version: 1.0", "Version: '1.5'"),
        VALID.replace("Author: a", "Author: &x a").replace("Email: e", "Email: *x"),
        format!("{VALID}Author: other\n"),
        VALID.replace("Author: a", "Author: !!str 5"),
    ] {
        let (loaded, lines) = load_one(&text);
        assert!(!loaded.had_errors, "{text}: {lines:?}");
        assert_eq!(loaded.maps.len(), 1);
    }
    // nothing in the file: an error is logged, but the run goes on
    let (loaded, lines) = load_one("# only a comment\n");
    assert!(!loaded.had_errors);
    assert!(loaded.maps.is_empty());
    assert!(lines[0].contains("Cannot pass null model to Validate."));
}

fn database(name: &str, sql: &str) -> (Temp, Database) {
    let dir = Temp::new(name);
    let db = Database::open(&dir.0.join("t.db")).unwrap();
    db.query(sql).unwrap();
    (dir, db)
}

fn csv(table: &Table, row: usize) -> Vec<String> {
    table.cells(row).map(|(_, v)| v.csv_text()).collect()
}

fn value_of(db: &Database, declared: &str, value: &str) -> Result<String, String> {
    db.query(&format!("DROP TABLE IF EXISTS t; CREATE TABLE t(c {declared}); INSERT INTO t VALUES({value})")).unwrap();
    db.query("SELECT c FROM t").map(|t| csv(&t, 0).remove(0)).map_err(|e| e.message)
}

#[test]
fn values_follow_the_declared_type() {
    let (_dir, db) = database("types", "SELECT 1");
    for (declared, value, expected) in [
        ("INT", "'abc'", "0"),
        ("INTEGER", "1.5", "1"),
        ("INT", "1099511627776", "0"),
        ("INT8", "300", "44"),
        ("TINYINT", "-1", "255"),
        ("SMALLINT", "70000", "4464"),
        ("UINT", "-1", "4294967295"),
        ("UNSIGNEDINTEGER", "-1", "18446744073709551615"),
        ("BOOLEAN", "2", "True"),
        ("BOOLEAN", "0", "False"),
        ("BOOL", "''", "True"),
        ("REAL", "'12'", "12"),
        ("FLOAT", "1e300", "1E+300"),
        ("SINGLE", "1099511627776", "1.0995116E+12"),
        ("NUMERIC", "1.5", "1.5"),
        ("DECIMAL(10,2)", "3.0", "3"),
        ("VARCHAR(20)", "1.5", "1.5"),
        ("TEXT", "x'6869'", "hi"),
        ("BLOB", "x'0102'", "0x0102"),
        ("BLOB", "1", "0x31"),
        ("GUID", "'01020304-0506-0708-090a-0b0c0d0e0f10'", "01020304-0506-0708-090a-0b0c0d0e0f10"),
        ("GUID", "x'000102030405060708090a0b0c0d0e0f'", "03020100-0504-0706-0809-0a0b0c0d0e0f"),
        ("DATETIME", "'2024-01-02 03:04:05.1234567'", "01/02/2024 03:04:05"),
        ("datetime", "'2024-01-02 03:04:05+02:00'", "01/02/2024 01:04:05"),
        ("TIMESTAMP", "'2024-01-02'", "01/02/2024 00:00:00"),
        ("UNKNOWNTYPE", "x'0102'", "0x0102"),
        ("INT UNSIGNED", "1.5", "1.5"),
        ("", "'abc'", "abc"),
    ] {
        assert_eq!(value_of(&db, declared, value), Ok(expected.to_string()), "{declared} {value}");
    }
}

#[test]
fn bad_values_fail_the_query() {
    let (_dir, db) = database("bad", "SELECT 1");
    for (declared, value, message) in [
        ("DATETIME", "5", "String '5' was not recognized as a valid DateTime."),
        ("DATETIME", "'2024-02-30'", "String '2024-02-30' was not recognized as a valid DateTime."),
        ("DATETIME", "'2024-01-02 03:04:05+02'", "String '2024-01-02 03:04:05+02' was not recognized as a valid DateTime."),
        ("BOOLEAN", "'abc'", "source"),
        ("BOOLEAN", "x'6869'", "unknown error\nCannot convert type Object to boolean"),
        ("BOOLEAN", "x''", "The method or operation is not implemented."),
        ("GUID", "'abc'", "Unrecognized Guid format."),
        ("DECIMAL", "1e300", "Value was either too large or too small for a Decimal."),
    ] {
        assert_eq!(value_of(&db, declared, value), Err(message.to_string()), "{declared} {value}");
    }
}

#[test]
fn statements_run_as_the_reader_runs_them() {
    let (_dir, db) = database("statements", "SELECT 1");
    let t = db.query("CREATE TEMP TABLE tt(x); INSERT INTO tt VALUES(7); SELECT x FROM tt").unwrap();
    assert_eq!(csv(&t, 0), ["7"]);
    let t = db.query("SELECT 1 AS one; SELECT 2 AS two").unwrap();
    assert_eq!(t.names, ["one"]);
    assert!(db.query("SELECT 1 AS one WHERE 0; SELECT 2 AS two").unwrap().is_empty());
    assert_eq!(csv(&db.query("SELECT 1 AS one; -- a comment").unwrap(), 0), ["1"]);
    // what comes after the rows still counts
    assert_eq!(db.query("SELECT 1; garbage").unwrap_err().message, "SQL logic error\nnear \"garbage\": syntax error");
    assert_eq!(db.query("SELECT * FROM nosuch").unwrap_err().exception, "code = Error (1), message = System.Data.SQLite.SQLiteException (0x87AF001F): SQL logic error\nno such table: nosuch");
    assert_eq!(db.scalar("SELECT 6; SELECT 7").unwrap().as_deref(), Some("6"));
    assert_eq!(db.scalar("SELECT 5 WHERE 0").unwrap(), None);
    assert_eq!(db.scalar("SELECT x'6869'").unwrap_err().message, "Object must implement IConvertible.");
}

#[test]
fn removed_blobs_shift_later_values() {
    let (_dir, db) = database("blobs", "CREATE TABLE a(id, data BLOB, v); INSERT INTO a VALUES(1, x'01', 'x'), (2, NULL, 'y')");
    let mut t = db.query("SELECT id, data, v FROM a").unwrap();
    for row in 0..t.row_count() {
        t.remove_blobs(row, |name| name.eq_ignore_ascii_case("DATA"));
    }
    assert_eq!(t.cells(0).map(|(n, _)| n).collect::<Vec<_>>(), ["id", "v"]);
    assert_eq!(csv(&t, 0), ["1", "x"]);
    // this row keeps its column, so it has one more field than the header
    assert_eq!(csv(&t, 1), ["2", "", "y"]);

    // with the name twice only the first goes, and SourceFile takes the first of its name
    let mut t = db.query("SELECT x'01' AS data, 2 AS id, x'03' AS data").unwrap();
    t.remove_blobs(0, |name| name == "data");
    assert_eq!(csv(&t, 0), ["2", "0x03"]);
}

#[test]
fn sql_behaves_as_in_the_reference() {
    let (_dir, db) = database("sql", "CREATE VIRTUAL TABLE f4 USING fts4(x); INSERT INTO f4 VALUES('hello')");
    // reals as text have 15 digits, as before SQLite 3.52
    assert_eq!(csv(&db.query("SELECT (0.1+0.2)||'' AS a, CAST(123456789012345678.0 AS TEXT) AS b").unwrap(), 0), ["0.3", "1.23456789012346e+17"]);
    // double-quoted strings, and FTS4 but not FTS5
    assert_eq!(csv(&db.query("SELECT \"text\" AS a").unwrap(), 0), ["text"]);
    assert_eq!(csv(&db.query("SELECT * FROM f4").unwrap(), 0), ["hello"]);
    assert_eq!(db.query("CREATE VIRTUAL TABLE f5 USING fts5(x)").unwrap_err().message, "SQL logic error\nno such module: fts5");
    assert_eq!(csv(&db.query("SELECT key FROM json_each('[5]')").unwrap(), 0), ["0"]);
}

#[test]
fn the_extra_functions_are_there() {
    let (_dir, db) = database("functions", "CREATE TABLE n(v); INSERT INTO n VALUES(1),(2),(2),(5)");
    for (sql, expected) in [
        ("pi()", "3.141592653589793"),
        ("sqrt(4)", "2"),
        ("log(1)", "0"),
        ("log10(100)", "2"),
        ("ceil(1.5)", "2"),
        ("floor(-1.5)", "-2"),
        ("sign(-2.5)", "-1"),
        ("square(3)", "9"),
        ("power(2,10)", "1024"),
        ("reverse('h\u{e9}llo')", "oll\u{e9}h"),
        ("proper('abc dEF')", "Abc Def"),
        ("padl('a',3)", "  a"),
        ("padr('a',3)", "a  "),
        ("padc('a',4)", " a  "),
        ("replicate('ab',2)", "abab"),
        ("charindex('b','abc')", "2"),
        ("charindex('z','abc')", "0"),
        ("leftstr('abc',2)", "ab"),
        ("rightstr('abc',2)", "bc"),
        ("strfilter('abcabc','ac')", "acac"),
        ("difference('Robert','Rupert')", "4"),
    ] {
        assert_eq!(csv(&db.query(&format!("SELECT {sql} AS v")).unwrap(), 0), [expected], "{sql}");
    }
    for (sql, expected) in [("mode(v)", "2"), ("median(v)", "2"), ("lower_quartile(v)", "1.5"), ("upper_quartile(v)", "3.5"), ("variance(v)", "2.9999999999999996")] {
        assert_eq!(csv(&db.query(&format!("SELECT {sql} AS v FROM n")).unwrap(), 0), [expected], "{sql}");
    }
    assert_eq!(db.query("SELECT sqrt(-1)").unwrap_err().message, "SQL logic error\nNumerical argument out of domain");
    assert_eq!(db.query("SELECT log(0)").unwrap_err().message, "SQL logic error\nNumerical result out of range");
}
