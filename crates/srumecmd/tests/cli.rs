//! The tool from the outside, on a small ESE database built here: output files and exit codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PAGE: usize = 4096;
const SID: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";

/// A leaf page holding these records
fn leaf(records: &[Vec<u8>]) -> Vec<u8> {
    let mut page = vec![0u8; PAGE];
    page[34..36].copy_from_slice(&(records.len() as u16 + 1).to_le_bytes());
    page[36..40].copy_from_slice(&2u32.to_le_bytes());
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

/// A record of the id map: type, index and a tagged blob with its flags byte
fn id_map(kind: u8, index: i32, blob: &[u8]) -> Vec<u8> {
    let mut r = vec![2u8, 0x7f, 10, 0, kind];
    r.extend_from_slice(&index.to_le_bytes());
    r.push(0xfc);
    r.extend_from_slice(&[0, 1, 4, 0x40, 1]);
    r.extend_from_slice(blob);
    r
}

/// A record of the network usage table
fn usage(id: i32, app: i32, user: i32) -> Vec<u8> {
    let mut r = vec![6u8, 0x7f, 37, 0];
    r.extend_from_slice(&id.to_le_bytes());
    r.extend_from_slice(&45_000.5f64.to_le_bytes());
    r.extend_from_slice(&app.to_le_bytes());
    r.extend_from_slice(&user.to_le_bytes());
    r.extend_from_slice(&1000i64.to_le_bytes());
    r.extend_from_slice(&0x0006_0000_0000_0000i64.to_le_bytes());
    r.push(0xc0);
    r
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn database(state: u32) -> Vec<u8> {
    let mut header = vec![0u8; PAGE * 5];
    header[4..8].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
    header[8..12].copy_from_slice(&0x620u32.to_le_bytes());
    header[52..56].copy_from_slice(&state.to_le_bytes());
    header[232..236].copy_from_slice(&0x6eu32.to_le_bytes());
    header[236..240].copy_from_slice(&(PAGE as u32).to_le_bytes());
    let pages = [
        (4, leaf(&[
            catalog(8, 1, 8, 5, 0, "SruDbIdMapTable"),
            catalog(8, 2, 1, 2, 1, "IdType"),
            catalog(8, 2, 2, 4, 4, "IdIndex"),
            catalog(8, 2, 256, 11, 0, "IdBlob"),
            catalog(9, 1, 9, 6, 0, SID),
            catalog(9, 2, 1, 4, 4, "AutoIncId"),
            catalog(9, 2, 2, 8, 8, "TimeStamp"),
            catalog(9, 2, 3, 4, 4, "AppId"),
            catalog(9, 2, 4, 4, 4, "UserId"),
            catalog(9, 2, 5, 15, 8, "BytesRecvd"),
            catalog(9, 2, 6, 15, 8, "InterfaceLuid"),
        ])),
        (5, leaf(&[
            id_map(0, 1, &utf16("!!calc,exe!2020/01/02:03:04:05!x!Calculator")),
            id_map(3, 2, &[1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0]),
        ])),
        (6, leaf(&[usage(7, 1, 2), usage(8, 99, 2)])),
    ];
    let mut file = header;
    file.resize(PAGE * 8, 0);
    for (number, page) in pages {
        file[(number + 1) * PAGE..(number + 2) * PAGE].copy_from_slice(&page);
    }
    file
}

struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str, state: u32) -> Case {
        let dir = std::env::temp_dir().join(format!("srumecmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ev/a")).unwrap();
        std::fs::write(dir.join("ev/a/SRUDB.dat"), database(state)).unwrap();
        Case { dir }
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_srumecmd")).args(args).args(["--co", "false"]).output().unwrap()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn csv(folder: &Path, name: &str) -> String {
    let path = std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with(&format!("_SrumECmd_{name}_Output.csv"))).unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..3], &[0xef, 0xbb, 0xbf]);
    String::from_utf8(bytes[3..].to_vec()).unwrap()
}

#[test]
fn rows_get_the_id_maps_names() {
    let case = Case::new("rows", 3);
    let out = case.path("out");
    let output = case.run(&["-f", &case.path("ev/a/SRUDB.dat"), "--csv", &out]);
    assert!(output.status.success());
    let text = csv(Path::new(&out), "NetworkUsages");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "Id,Timestamp,ExeInfo,ExeInfoDescription,ExeTimestamp,SidType,Sid,UserName,UserId,AppId,BytesReceived,BytesSent,InterfaceLuid,InterfaceType,L2ProfileFlags,L2ProfileId,ProfileName");
    assert_eq!(lines[1], "7,2023-03-15 12:00:00,\"calc,exe\",Calculator,01/02/2020 03:04:05 +00:00,LocalSystem,S-1-5-18,,2,1,1000,0,1688849860263936,IF_TYPE_ETHERNET_CSMACD,0,0,");
    // an id that isn't in the map leaves its columns empty, and is told about
    assert!(lines[2].starts_with("8,2023-03-15 12:00:00,,,,LocalSystem,S-1-5-18,,2,99,"));
    let console = String::from_utf8_lossy(&output.stdout);
    assert!(console.contains("1 app or user id(s) are not in SruDbIdMapTable"));
    assert!(console.contains("Network Usage count:"));
}

#[test]
fn the_seven_usual_files_are_always_written_and_the_others_only_with_rows() {
    let case = Case::new("files", 3);
    let out = case.path("out");
    assert!(case.run(&["-f", &case.path("ev/a/SRUDB.dat"), "--csv", &out]).status.success());
    for name in ["EnergyUsage", "AppTimelineProvider", "vfuprov", "AppResourceUseInfo", "NetworkConnections", "NetworkUsages", "PushNotifications"] {
        assert!(csv(Path::new(&out), name).lines().count() >= 1, "{name}");
    }
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 7);
}

#[test]
fn a_dirty_database_is_read_with_a_warning() {
    let case = Case::new("dirty", 2);
    let out = case.path("out");
    let output = case.run(&["-f", &case.path("ev/a/SRUDB.dat"), "--csv", &out]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("'Dirty Shutdown'"));
    assert_eq!(csv(Path::new(&out), "NetworkUsages").lines().count(), 3);
}

#[test]
fn a_folder_is_searched_for_the_database() {
    let case = Case::new("search", 3);
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("ev"), "--csv", &out]);
    assert!(output.status.success());
    let console = String::from_utf8_lossy(&output.stdout);
    assert!(console.contains("(State: Clean Shutdown, Format Version: 0x620,110)"));
    assert!(console.contains("Did not locate any files named 'SOFTWARE'"));
}

#[test]
fn nothing_is_written_next_to_the_database() {
    let case = Case::new("untouched", 3);
    let out = case.path("out");
    let before = std::fs::read(case.path("ev/a/SRUDB.dat")).unwrap();
    assert!(case.run(&["-f", &case.path("ev/a/SRUDB.dat"), "--csv", &out, "--temp", &case.path("nothing")]).status.success());
    assert_eq!(std::fs::read_dir(case.path("ev/a")).unwrap().count(), 1);
    assert_eq!(std::fs::read(case.path("ev/a/SRUDB.dat")).unwrap(), before);
    assert!(!Path::new(&case.path("nothing")).exists());
}

#[test]
fn exit_codes() {
    let case = Case::new("exit", 3);
    let out = case.path("out");
    assert!(!case.run(&[]).status.success());
    assert!(!case.run(&["-f", &case.path("none"), "--csv", &out]).status.success());
    assert!(!case.run(&["-d", &case.path("none"), "--csv", &out]).status.success());
    assert!(!case.run(&["-f", &case.path("ev/a/SRUDB.dat")]).status.success());
    assert!(!case.run(&["-f", &case.path("ev/a/SRUDB.dat"), "-r", &case.path("none"), "--csv", &out]).status.success());
    // no database under a folder isn't a failure, nor is a damaged one
    std::fs::create_dir_all(case.path("empty")).unwrap();
    assert!(case.run(&["-d", &case.path("empty"), "--csv", &out]).status.success());
    std::fs::write(case.path("bad.dat"), vec![1u8; 9000]).unwrap();
    let output = case.run(&["-f", &case.path("bad.dat"), "--csv", &out]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("not an ESE database"));
}
