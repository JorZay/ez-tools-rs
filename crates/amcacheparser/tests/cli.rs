//! The program itself: the temporary folder, exit codes, file names and the CSVs' layout.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rusqlite::Connection;

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(name: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("amcacheparser-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Folder(dir)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_amcacheparser")).args(args).output().unwrap()
}

fn databases(dir: &Path) {
    let c = Connection::open(dir.join("InventoryApplicationFile.db")).unwrap();
    c.execute_batch(
        "CREATE TABLE InventoryApplicationFile_0 (ItemKey TEXT, FileId TEXT, LowerCaseLongPath TEXT, LastModified);
         INSERT INTO InventoryApplicationFile_0 VALUES ('a','0000AB','c:\\x\\a.exe',134298448576863666);
         CREATE TABLE Metadata_0 (Name TEXT, Value TEXT);
         INSERT INTO Metadata_0 VALUES ('lastFullSync','134298448576863666');",
    )
    .unwrap();
}

#[test]
fn temp_folder_given_is_created_and_removed() {
    let base = folder("temp");
    let input = base.0.join("in");
    std::fs::create_dir(&input).unwrap();
    databases(&input);
    let (out, temp) = (base.0.join("out"), base.0.join("t"));
    let r = run(&["-f", input.to_str().unwrap(), "--csv", out.to_str().unwrap(), "--csvf", "x.csv", "--temp", temp.to_str().unwrap(), "--co", "false"]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stdout));
    assert!(!temp.exists(), "created for the run, and removed");
    let names = std::fs::read_to_string(out.join("x_Databases_UnassociatedFileEntries.csv")).unwrap();
    assert!(names.contains("c:\\x\\a.exe"));
    let metadata = std::fs::read_to_string(out.join("x_Databases_Metadata.csv")).unwrap();
    assert_eq!(metadata, "Database,Name,Value\r\nInventoryApplicationFile.db,lastFullSync,2026-07-30 00:27:37\r\n");
}

#[test]
fn temp_that_cannot_be_written_stops() {
    let base = folder("temp-file");
    let input = base.0.join("in");
    std::fs::create_dir(&input).unwrap();
    databases(&input);
    let blocked = base.0.join("file");
    std::fs::write(&blocked, "x").unwrap();
    let out = base.0.join("out");
    let r = run(&["-f", input.to_str().unwrap(), "--csv", out.to_str().unwrap(), "--temp", blocked.to_str().unwrap(), "--co", "false"]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stdout).contains("can't be written to"));
}

#[test]
fn exit_codes() {
    let base = folder("exit");
    let out = base.0.join("out");
    let out = out.to_str().unwrap();
    // bad arguments, -f or --csv missing, and -f not there
    assert_eq!(run(&["--nothing"]).status.code(), Some(1));
    assert_eq!(run(&["--csv", out]).status.code(), Some(1));
    assert_eq!(run(&["-f", out]).status.code(), Some(1));
    assert_eq!(run(&["-f", "/no/such/file", "--csv", out]).status.code(), Some(1));
    // a folder with nothing is not a failure
    assert_eq!(run(&["-f", base.0.to_str().unwrap(), "--csv", out, "--co", "false"]).status.code(), Some(0));
    // a file that isn't a hive is a damaged file, not the tool's failure
    let bad = base.0.join("bad.hve");
    std::fs::write(&bad, "not a hive at all").unwrap();
    let r = run(&["-f", bad.to_str().unwrap(), "--csv", out, "--co", "false"]);
    assert_eq!(r.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&r.stdout).contains("is not a Registry hive (bad signature)"));
}

#[test]
fn an_option_given_twice_is_refused() {
    let base = folder("twice");
    let out = base.0.join("out");
    let r = run(&["-f", base.0.to_str().unwrap(), "--csv", out.to_str().unwrap(), "--co", "false", "--co", "false"]);
    assert_eq!(r.status.code(), Some(1));
    assert!(!out.exists());
}

#[test]
fn console_log_is_in_the_csv_folder() {
    let base = folder("log");
    let input = base.0.join("in");
    std::fs::create_dir(&input).unwrap();
    databases(&input);
    let (out, temp) = (base.0.join("out"), base.0.join("t"));
    let r = run(&["-f", input.to_str().unwrap(), "--csv", out.to_str().unwrap(), "--temp", temp.to_str().unwrap()]);
    assert!(r.status.success());
    let log = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with("ConsoleLog.txt")).unwrap();
    let text = std::fs::read_to_string(log).unwrap();
    assert!(text.contains("INF] Total file entries found: 1"), "{text}");
}
