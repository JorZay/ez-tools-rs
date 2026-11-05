//! The tool from the outside: output names and contents, exit codes, and evidence left as it was.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sqlmap_ez::Database;

struct Case {
    dir: PathBuf,
}

const MAP: &str = "Description: test map\nAuthor: a\nEmail: e\nId: 11111111-2222-3333-4444-555555555555\nVersion: 1.0\nCSVPrefix: Test\nFileName: test.db\nIdentifyQuery: SELECT count(*) FROM sqlite_master WHERE name='t'\nIdentifyValue: 1\nQueries:\n    -\n        Name: Everything\n        Query: SELECT id, name FROM t\n        BaseFileName: All\n    -\n        Name: Blobs\n        Query: SELECT id, name, data FROM t\n        BaseFileName: Blobs\n        BlobColumns:\n            - BlobColumn: data\n              NameColumn: name\n              BlobExtension: bin\n";

impl Case {
    fn new(name: &str) -> Case {
        let dir = std::env::temp_dir().join(format!("sqlecmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("maps")).unwrap();
        std::fs::create_dir_all(dir.join("ev")).unwrap();
        std::fs::write(dir.join("maps/test.smap"), MAP).unwrap();
        let db = Database::open(&dir.join("ev/test.db")).unwrap();
        db.query("CREATE TABLE t(id INTEGER, name TEXT, data BLOB); INSERT INTO t VALUES(1, 'a/b', x'0102'), (2, 'two', NULL)").unwrap();
        drop(db);
        Case { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sqlecmd"));
        command.args(args).args(["--maps", self.dir.join("maps").to_str().unwrap(), "--temp", self.dir.join("temp").to_str().unwrap(), "--co", "false"]);
        command.output().unwrap()
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn files(&self, folder: &str) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.dir.join(folder)).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_default();
        files.sort();
        files
    }

    fn one_ending(&self, folder: &str, end: &str) -> PathBuf {
        self.files(folder).into_iter().find(|f| f.to_string_lossy().ends_with(end)).unwrap_or_else(|| panic!("no {end}"))
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(p: &Path) -> String {
    String::from_utf8(std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn csv_json_and_blobs() {
    let case = Case::new("all");
    let db = case.path("ev/test.db");
    let out = case.run(&["-f", &db, "--csv", &case.path("c"), "--json", &case.path("j")]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));

    let all = case.one_ending("c", "_Test_All_11111111-2222-3333-4444-555555555555.csv");
    assert_eq!(text(&all), format!("id,name,SourceFile\r\n1,a/b,{db}\r\n2,two,{db}\r\n"));
    // the row with a null blob keeps its column, so its values shift as in the original
    let blobs = case.one_ending("c", "_Test_Blobs_11111111-2222-3333-4444-555555555555.csv");
    assert_eq!(text(&blobs), format!("id,name,SourceFile\r\n1,a/b,{db}\r\n2,two,,{db}\r\n"));
    let blob = case.one_ending("c", "_a_b_data.bin");
    assert_eq!(std::fs::read(blob).unwrap(), [1, 2]);

    let json = case.one_ending("j", "_SQLECmd_Output.json");
    let lines: Vec<String> = text(&json).lines().map(str::to_string).collect();
    assert_eq!(lines[0], format!("{{\"id\":1,\"name\":\"a/b\",\"SourceFile\":\"{db}\",\"MapDescription\":\"test map\"}}"));
    assert_eq!(lines[3], format!("{{\"id\":2,\"name\":\"two\",\"data\":null,\"SourceFile\":\"{db}\",\"MapDescription\":\"test map\"}}"));
}

#[test]
fn noblob_writes_no_blob_files_but_still_removes_the_column() {
    let case = Case::new("noblob");
    let out = case.run(&["-f", &case.path("ev/test.db"), "--csv", &case.path("c"), "--noblob"]);
    assert!(out.status.success());
    assert_eq!(case.files("c").len(), 2);
    assert!(text(&case.one_ending("c", "-555555555555.csv")).starts_with("id,name,"));
}

#[test]
fn exit_codes() {
    let case = Case::new("exit");
    assert_eq!(case.run(&[]).status.code(), Some(1));
    assert_eq!(case.run(&["-f", &case.path("ev/test.db")]).status.code(), Some(1));
    assert_eq!(case.run(&["-f", &case.path("nothing"), "--csv", &case.path("c")]).status.code(), Some(1));
    // not SQLite, or damaged: listed, but not a failure of the tool
    std::fs::write(case.dir.join("ev/not.db"), b"not sqlite").unwrap();
    assert_eq!(case.run(&["-f", &case.path("ev/not.db"), "--csv", &case.path("c")]).status.code(), Some(0));
    std::fs::write(case.dir.join("ev/bad.db"), b"SQLite format 3\0 and then not a database at all, in any way").unwrap();
    let out = case.run(&["-f", &case.path("ev/bad.db"), "--csv", &case.path("c")]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("could not be processed"));
    // a map with an error ends the run
    std::fs::write(case.dir.join("maps/bad.smap"), "Unknown: 1\n").unwrap();
    assert_eq!(case.run(&["-f", &case.path("ev/test.db"), "--csv", &case.path("c")]).status.code(), Some(1));
}

#[test]
fn the_evidence_is_not_changed() {
    let case = Case::new("evidence");
    let db = Database::open(&case.dir.join("ev/wal.db")).unwrap();
    db.query("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(id INTEGER, name TEXT, data BLOB); INSERT INTO t VALUES(7, 'in wal', NULL)").unwrap();
    let (main, wal) = (std::fs::read(case.dir.join("ev/wal.db")).unwrap(), std::fs::read(case.dir.join("ev/wal.db-wal")).unwrap());
    std::fs::copy(case.dir.join("ev/wal.db"), case.dir.join("ev/copy.db")).unwrap();
    std::fs::copy(case.dir.join("ev/wal.db-wal"), case.dir.join("ev/copy.db-wal")).unwrap();
    let out = case.run(&["-f", &case.path("ev/copy.db"), "--csv", &case.path("c")]);
    drop(db);
    assert!(out.status.success());
    assert_eq!(std::fs::read(case.dir.join("ev/copy.db")).unwrap(), main);
    assert_eq!(std::fs::read(case.dir.join("ev/copy.db-wal")).unwrap(), wal);
    // the row only in the -wal was read from the copy
    assert!(text(&case.one_ending("c", "_All_11111111-2222-3333-4444-555555555555.csv")).contains("in wal"));
    // and the temporary folder is gone
    assert!(!case.dir.join("temp").exists());
}

#[test]
fn hunting_finds_renamed_databases() {
    let case = Case::new("hunt");
    std::fs::rename(case.dir.join("ev/test.db"), case.dir.join("ev/renamed.bin")).unwrap();
    let out = case.run(&["-d", &case.path("ev"), "--csv", &case.path("c")]);
    assert!(out.status.success());
    assert_eq!(case.files("c").len(), 3);
    let out = case.run(&["-d", &case.path("ev"), "--csv", &case.path("d"), "--hunt", "false"]);
    assert!(out.status.success());
    assert!(case.files("d").is_empty());
}
