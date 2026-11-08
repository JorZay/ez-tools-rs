//! The tool from the outside, on small UAL databases built here: output files and exit codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PAGE: usize = 4096;
const FILE_SERVER: [u8; 16] = [0x6f, 0x22, 0xa9, 0x10, 0xee, 0x50, 0xd8, 0x49, 0xa3, 0x93, 0x9a, 0x50, 0x1d, 0x47, 0xce, 0x04];
/// 2020-03-04 12:00:00 UTC
const FILETIME: i64 = 132_277_968_000_000_000;

/// A leaf page holding these records
fn leaf(records: &[Vec<u8>]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    page[34..36].copy_from_slice(&(records.len() as u16 + 1).to_le_bytes());
    page[36..40].copy_from_slice(&3u32.to_le_bytes()); // a root and a leaf
    let mut at = 0usize;
    for (i, record) in records.iter().enumerate() {
        let mut value = vec![0u8, 0u8]; // no key
        value.extend_from_slice(record);
        page[40 + at..40 + at + value.len()].copy_from_slice(&value);
        let tag = PAGE - 4 * (i + 2);
        page[tag..tag + 2].copy_from_slice(&(value.len() as u16).to_le_bytes());
        page[tag + 2..tag + 4].copy_from_slice(&(at as u16).to_le_bytes());
        at += value.len();
    }
    page
}

/// A catalog record: a table (its root page in `coltyp`) or a column
fn catalog(object: i32, kind: u16, id: i32, coltyp: i32, space: i32, name: &str) -> Vec<u8> {
    let mut r = vec![6u8, 128, 27, 0];
    r.extend_from_slice(&object.to_le_bytes());
    r.extend_from_slice(&kind.to_le_bytes());
    r.extend_from_slice(&id.to_le_bytes());
    r.extend_from_slice(&coltyp.to_le_bytes());
    r.extend_from_slice(&space.to_le_bytes());
    r.extend_from_slice(&0i32.to_le_bytes());
    r.push(0xc0); // the null bitmap
    r.extend_from_slice(&(name.len() as u16).to_le_bytes());
    r.extend_from_slice(name.as_bytes());
    r
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A record of fixed columns (none null), then tagged ones from 256 on
fn record(fixed: &[&[u8]], tagged: &[&[u8]]) -> Vec<u8> {
    let size: usize = fixed.iter().map(|f| f.len()).sum();
    let mut r = vec![fixed.len() as u8, 127, (4 + size + 1) as u8, 0];
    for f in fixed {
        r.extend_from_slice(f);
    }
    r.push(0);
    let mut offset = tagged.len() * 4;
    for (i, t) in tagged.iter().enumerate() {
        r.extend_from_slice(&(256 + i as u16).to_le_bytes());
        r.extend_from_slice(&(offset as u16).to_le_bytes());
        offset += t.len();
    }
    for t in tagged {
        r.extend_from_slice(t);
    }
    r
}

fn database(state: u32, catalog_records: Vec<Vec<u8>>, rows: Vec<Vec<u8>>) -> Vec<u8> {
    let mut file = vec![0u8; PAGE * 7];
    file[4..8].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
    file[8..12].copy_from_slice(&0x620u32.to_le_bytes());
    file[52..56].copy_from_slice(&state.to_le_bytes());
    file[232..236].copy_from_slice(&0xb4u32.to_le_bytes());
    file[236..240].copy_from_slice(&(PAGE as u32).to_le_bytes());
    file[5 * PAGE..6 * PAGE].copy_from_slice(&leaf(&catalog_records));
    file[6 * PAGE..7 * PAGE].copy_from_slice(&leaf(&rows));
    file
}

fn system_identity() -> Vec<u8> {
    database(
        3,
        vec![catalog(8, 1, 8, 5, 0, "ROLE_IDS"), catalog(8, 2, 1, 16, 16, "RoleGuid"), catalog(8, 2, 256, 12, 0, "RoleName")],
        vec![record(&[&FILE_SERVER], &[&utf16("File Server\0")])],
    )
}

fn current(state: u32) -> Vec<u8> {
    database(
        state,
        vec![
            catalog(8, 1, 8, 5, 0, "CLIENTS"),
            catalog(8, 2, 1, 16, 16, "RoleGuid"),
            catalog(8, 2, 2, 14, 4, "TotalAccesses"),
            catalog(8, 2, 3, 8, 8, "LastAccess"),
            catalog(8, 2, 256, 12, 0, "AuthenticatedUserName"),
            catalog(8, 2, 257, 17, 2, "Day64"),
        ],
        vec![
            record(&[&FILE_SERVER, &40_000u32.to_le_bytes(), &FILETIME.to_le_bytes()], &[&utf16("CORP\\alice\0\0"), &40_000u16.to_le_bytes()]),
            record(&[&[1; 16], &5u32.to_le_bytes(), &(-5i64).to_le_bytes()], &[&utf16("bob, \"jr\"")]),
        ],
    )
}

struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str, files: &[(&str, Vec<u8>)]) -> Case {
        let dir = std::env::temp_dir().join(format!("sumecmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sum")).unwrap();
        for (file, data) in files {
            std::fs::write(dir.join("sum").join(file), data).unwrap();
        }
        Case { dir }
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sumecmd")).args(args).args(["--co", "false"]).output().unwrap()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn csv(folder: &Path, name: &str) -> String {
    let path = std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with(&format!("_SumECmd_{name}_Output.csv"))).unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..3], &[0xef, 0xbb, 0xbf]);
    String::from_utf8(bytes[3..].to_vec()).unwrap()
}

#[test]
fn clients_and_their_days() {
    let case = Case::new("rows", &[("SystemIdentity.mdb", system_identity()), ("Current.mdb", current(3))]);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out]);
    assert!(output.status.success());
    let clients = csv(Path::new(&out), "DETAIL_Clients");
    assert_eq!(
        clients,
        "RoleGuid,RoleDescription,AuthenticatedUserName,TotalAccesses,InsertDate,LastAccess,IpAddress,ClientName,TenantId,SourceFile\r\n\
         10a9226f-50ee-49d8-a393-9a501d47ce04,File Server,CORP\\alice,40000,0001-01-01 00:00:00,2020-03-04 12:00:00,,,00000000-0000-0000-0000-000000000000,Current.mdb\r\n\
         01010101-0101-0101-0101-010101010101,(Unknown Role Guid),\"bob, \"\"jr\"\"\",5,0001-01-01 00:00:00,0001-01-01 00:00:00,,,00000000-0000-0000-0000-000000000000,Current.mdb\r\n"
    );
    // day 64 of the year of the latest access, 2020 (a leap year)
    let days = csv(Path::new(&out), "DETAIL_ClientsDetailed");
    assert_eq!(days.lines().nth(1).unwrap(), "2020-03-04,40000,64,10a9226f-50ee-49d8-a393-9a501d47ce04,File Server,CORP\\alice,40000,0001-01-01 00:00:00,2020-03-04 12:00:00,,,00000000-0000-0000-0000-000000000000,Current.mdb");
    assert_eq!(csv(Path::new(&out), "SUMMARY_RoleInfos"), "RoleGuid,RoleName,ProductName\r\n10a9226f-50ee-49d8-a393-9a501d47ce04,File Server,\r\n");
    assert_eq!(csv(Path::new(&out), "SUMMARY_ChainedDbInfo"), "Year,FileName\r\n");
    assert_eq!(csv(Path::new(&out), "SUMMARY_SystemIdentInfo").lines().count(), 1);
    // the bad time is told about, and the rest kept
    let console = String::from_utf8_lossy(&output.stdout);
    assert!(console.contains("Current.mdb CLIENTS: LastAccess 0xFFFFFFFFFFFFFFFB is not a valid time"));
    assert!(console.contains("Found 2 Client entries"));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 5);
}

#[test]
fn without_day_details() {
    let case = Case::new("wd", &[("Current.mdb", current(3))]);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out, "--wd", "false"]);
    assert!(output.status.success());
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 4);
    assert!(String::from_utf8_lossy(&output.stdout).contains("'SystemIdentity.mdb' not found"));
}

#[test]
fn a_dirty_database_is_read_with_a_warning_and_left_as_it_is() {
    let case = Case::new("dirty", &[("Current.mdb", current(2)), ("Svc.log", vec![1, 2, 3])]);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out, "--temp", &case.path("nothing")]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("'Current.mdb' was not shut down cleanly (Dirty Shutdown) and transaction logs are next to it"));
    assert_eq!(csv(Path::new(&out), "DETAIL_Clients").lines().count(), 3);
    assert_eq!(std::fs::read_dir(case.path("sum")).unwrap().count(), 2);
    assert_eq!(std::fs::read(case.path("sum/Current.mdb")).unwrap(), current(2));
    assert!(!Path::new(&case.path("nothing")).exists());
}

#[test]
fn a_database_that_cant_be_opened_does_not_lose_the_others() {
    let mut other_page_size = current(3);
    other_page_size[236..240].copy_from_slice(&8192u32.to_le_bytes());
    let case = Case::new("bad", &[("SystemIdentity.mdb", system_identity()), ("Current.mdb", vec![0x41; 65536]), ("{1}.mdb", other_page_size)]);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out]);
    assert!(output.status.success());
    let console = String::from_utf8_lossy(&output.stdout);
    assert!(console.contains("Current.mdb' could not be opened"));
    assert!(console.contains("{1}.mdb' could not be opened: The database page size does not match the engine"));
    assert_eq!(csv(Path::new(&out), "SUMMARY_RoleInfos").lines().count(), 2);
}

#[test]
fn a_bad_date_format_stops_the_export() {
    let case = Case::new("dt", &[("Current.mdb", current(3))]);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out, "--dt", "U"]);
    assert_eq!(output.status.code(), Some(1));
    // the first row is cut before its first time, as CsvHelper leaves it
    assert!(csv(Path::new(&out), "DETAIL_ClientsDetailed").ends_with("\r\n2020-03-04,40000,64,10a9226f-50ee-49d8-a393-9a501d47ce04,(Unknown Role Guid),CORP\\alice,40000"));
}

#[test]
fn exit_codes() {
    let case = Case::new("codes", &[("notes.txt", vec![1])]);
    let out = case.path("out");
    // neither database: told, and not a failure
    let output = case.run(&["-d", &case.path("sum"), "--csv", &out]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Neither 'SystemIdentity.mdb' nor 'Current.mdb' was found"));
    assert_eq!(case.run(&["--csv", &out]).status.code(), Some(1));
    assert_eq!(case.run(&["-d", &case.path("missing"), "--csv", &out]).status.code(), Some(1));
    assert_eq!(case.run(&["-d", &case.path("sum")]).status.code(), Some(1));
    assert_eq!(case.run(&["-d", &case.path("sum"), "-d", &case.path("sum"), "--csv", &out]).status.code(), Some(1));
}
