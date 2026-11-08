//! The tool from the outside, on small databases with the Windows 11 schema built here: output files and exit codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCHEMA: &str = "CREATE TABLE [Activity]([Id] GUID PRIMARY KEY NOT NULL, [AppId] TEXT NOT NULL, [PackageIdHash] TEXT, [AppActivityId] TEXT, [ActivityType] INT NOT NULL, [ActivityStatus] INT NOT NULL, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME, [Payload] BLOB, [IsLocalOnly] INT, [PlatformDeviceId] TEXT, [CreatedInCloud] DATETIME, [StartTime] DATETIME, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME, [ClipboardPayload] BLOB, [OriginalLastModifiedOnClient] DATETIME, [ETag] INT NOT NULL);
CREATE TABLE [ActivityOperation]([OperationOrder] INTEGER PRIMARY KEY ASC NOT NULL, [Id] GUID NOT NULL, [OperationType] INT NOT NULL, [AppId] TEXT NOT NULL, [ActivityType] INT NOT NULL, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME, [Payload] BLOB, [CreatedTime] DATETIME, [OperationExpirationTime] DATETIME, [StartTime] DATETIME NOT NULL, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME NOT NULL, [ClipboardPayload] BLOB, [ETag] INT NOT NULL);
CREATE TABLE [Activity_PackageId]([ActivityId] GUID NOT NULL, [Platform] TEXT NOT NULL COLLATE NOCASE, [PackageName] TEXT NOT NULL COLLATE NOCASE, [ExpirationTime] DATETIME NOT NULL);";

const APP_ID: &str = r#"[{"application":"{6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe","platform":"windows_win32"}]"#;
const ID: [u8; 16] = [0x12, 0x95, 0x49, 0x9d, 0x96, 0x83, 0x25, 0x41, 0xf3, 0x91, 0xd0, 0xbb, 0x75, 0xee, 0x3b, 0xe4];

struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str) -> Case {
        let dir = std::env::temp_dir().join(format!("wxtcmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Users/jane/L.jane")).unwrap();
        Case { dir }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("Users/jane/L.jane/ActivitiesCache.db")
    }

    fn make(&self, end_time: i64) -> &Case {
        let db = rusqlite::Connection::open(self.db()).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute(
            "INSERT INTO Activity (Id, AppId, ActivityType, ActivityStatus, LastModifiedTime, StartTime, EndTime, ETag, Payload, ClipboardPayload) VALUES (?, ?, 5, 1, 1646000000, 1646000000, ?, 1, ?, ?)",
            rusqlite::params![&ID[..], APP_ID, end_time, br#"{"displayText":"a.txt","appDisplayName":"Notepad","description":"d","contentUri":"file:///C:/a%20b.txt"}"#.as_slice(), br#"[{"content":"aGVsbG8=","formatName":"Text"}]"#.as_slice()],
        )
        .unwrap();
        db.execute("INSERT INTO Activity_PackageId VALUES (?, 'x_exe_path', '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe', 1648592000)", [&ID[..]]).unwrap();
        db.execute("INSERT INTO ActivityOperation (OperationOrder, Id, OperationType, AppId, ActivityType, LastModifiedTime, StartTime, LastModifiedOnClient, ETag) VALUES (1, ?, 1, ?, 10, 1646000000, 1646000000, 1646000000, 1)", rusqlite::params![&ID[..], APP_ID]).unwrap();
        self
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wxtcmd")).args(args).args(["--temp", &self.path("temp")]).output().unwrap()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn csv(folder: &Path, suffix: &str) -> String {
    let path = std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with(suffix)).unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..3], &[0xef, 0xbb, 0xbf]);
    String::from_utf8(bytes[3..].to_vec()).unwrap()
}

#[test]
fn the_three_tables_to_csv() {
    let case = Case::new("tables");
    case.make(1_646_000_065);
    let out = case.path("out");
    let output = case.run(&["-f", &case.db().to_string_lossy(), "--csv", &out]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let mut names: Vec<String> = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.file_name().to_string_lossy()[14..].to_string()).collect();
    names.sort();
    assert_eq!(names, ["_WxTCmd_0.1.0_ConsoleLog.txt", "_jane_Activity.csv", "_jane_ActivityOperations.csv", "_jane_Activity_PackageIDs.csv"]);
    let activity = csv(Path::new(&out), "_Activity.csv");
    let lines: Vec<&str> = activity.split("\r\n").collect();
    assert!(lines[0].starts_with("Id,ActivityTypeOrg,ActivityType,Executable,DisplayText,ContentInfo,Payload,"));
    assert!(lines[1].starts_with("9d499512-8396-4125-f391-d0bb75ee3be4,5,ExecuteOpen,ProgramFilesX64\\Notepad++\\notepad++.exe,a.txt (Notepad),d (file:///C:/a b.txt),"));
    assert!(lines[1].contains(",2022-02-27 22:13:20,2022-02-27 22:14:25,00:01:05,"));
    assert!(lines[1].ends_with(",hello"));
    assert_eq!(lines.len(), 3);
    let packages = csv(Path::new(&out), "_Activity_PackageIDs.csv");
    assert_eq!(packages, "Id,Platform,Name,AdditionalInformation,Expires\r\n9d499512-8396-4125-f391-d0bb75ee3be4,ExecutablePath,{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe,System\\notepad.exe,2022-03-29 22:13:20\r\n");
    assert!(csv(Path::new(&out), "_ActivityOperations.csv").contains(",10,CloudClipboard,"));
    // the evidence is untouched, and the copy is gone
    assert_eq!(std::fs::read_dir(case.dir.join("Users/jane/L.jane")).unwrap().count(), 1);
    assert!(!Path::new(&case.path("temp")).exists());
}

#[test]
fn a_bad_date_format_stops_at_the_first_time() {
    let case = Case::new("baddt");
    case.make(0);
    let out = case.path("out");
    let output = case.run(&["-f", &case.db().to_string_lossy(), "--csv", &out, "--dt", "x", "--co", "false"]);
    assert_eq!(output.status.code(), Some(1));
    let ops = csv(Path::new(&out), "_ActivityOperations.csv");
    assert!(ops.ends_with("\r\n9d499512-8396-4125-f391-d0bb75ee3be4,10,CloudClipboard,ProgramFilesX64\\Notepad++\\notepad++.exe,,,,"));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
}

#[test]
fn exit_codes() {
    let case = Case::new("exit");
    let out = case.path("out");
    assert_eq!(case.run(&[]).status.code(), Some(1));
    assert_eq!(case.run(&["-f", &case.path("none.db"), "--csv", &out]).status.code(), Some(1));
    assert_eq!(case.run(&["--csv", &out]).status.code(), Some(1));
    // not a database, or not a timeline database: listed, and 0
    std::fs::write(case.path("bad.db"), vec![7u8; 8192]).unwrap();
    let output = case.run(&["-f", &case.path("bad.db"), "--csv", &out, "--co", "false"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("not a SQLite database"));
    rusqlite::Connection::open(case.path("other.db")).unwrap().execute_batch("CREATE TABLE t(a);").unwrap();
    let output = case.run(&["-f", &case.path("other.db"), "--csv", &out, "--co", "false"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Is it an ActivitiesCache.db?"));
}
