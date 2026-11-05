//! The tool from the outside: output files and exit codes, on jump lists built here.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FOOTER: [u8; 4] = [0xab, 0xfb, 0xbf, 0xba];
const CLASS_ID: [u8; 16] = [0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];

fn link() -> Vec<u8> {
    let mut b = vec![0u8; 76];
    b[0] = 0x4c;
    b[4..20].copy_from_slice(&CLASS_ID);
    b[20..24].copy_from_slice(&0x84i32.to_le_bytes());
    b[24..28].copy_from_slice(&0x20i32.to_le_bytes());
    b[28..36].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    b[60..64].copy_from_slice(&1i32.to_le_bytes());
    b.extend_from_slice(&[2, 0, b'h', 0, b'i', 0]);
    b.extend_from_slice(&[0, 0, 0, 0]);
    b
}

/// A custom destinations file with a named category of two links
fn custom() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&2i32.to_le_bytes());
    b.extend_from_slice(&1i32.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&5i16.to_le_bytes());
    for u in "Tasks".encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b.extend_from_slice(&2i32.to_le_bytes());
    for _ in 0..2 {
        b.extend_from_slice(&CLASS_ID);
        b.extend_from_slice(&link());
    }
    b.extend_from_slice(&FOOTER);
    b
}

/// A version 1 DestList with an entry numbered 1
fn dest_list() -> Vec<u8> {
    let mut b = Vec::new();
    for v in [1i32, 1, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&1.0f32.to_le_bytes());
    for v in [1i32, 0, 1, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    let mut entry = vec![0u8; 112];
    entry[72..76].copy_from_slice(b"host");
    entry[88..92].copy_from_slice(&1i32.to_le_bytes());
    entry[100..108].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    entry[108..112].copy_from_slice(&(-1i32).to_le_bytes());
    let path: Vec<u16> = "C:\\a.txt".encode_utf16().collect();
    entry.extend_from_slice(&(path.len() as i16).to_le_bytes());
    for u in path {
        entry.extend_from_slice(&u.to_le_bytes());
    }
    b.extend(entry);
    b
}

/// A compound file holding its streams in whole sectors, none in the mini stream
fn automatic() -> Vec<u8> {
    const SECTOR: usize = 512;
    let streams: Vec<(&str, Vec<u8>)> = vec![("DestList", dest_list()), ("1", link()), ("ff", link())];
    let mut sectors: Vec<u8> = Vec::new();
    let mut table: Vec<i32> = Vec::new();
    let add = |data: &[u8], sectors: &mut Vec<u8>, table: &mut Vec<i32>| -> i32 {
        let first = table.len() as i32;
        let count = data.len().div_ceil(SECTOR);
        for i in 0..count {
            table.push(if i + 1 < count { table.len() as i32 + 1 } else { -2 });
        }
        sectors.extend_from_slice(data);
        sectors.resize(table.len() * SECTOR, 0);
        first
    };
    let entry = |name: &str, kind: u8, first: i32, size: i32, next: i32, child: i32| -> Vec<u8> {
        let mut e = vec![0u8; 128];
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        e[..units.len()].copy_from_slice(&units);
        e[64..66].copy_from_slice(&((units.len() + 2) as i16).to_le_bytes());
        e[66] = kind;
        e[68..72].copy_from_slice(&(-1i32).to_le_bytes());
        e[72..76].copy_from_slice(&next.to_le_bytes());
        e[76..80].copy_from_slice(&child.to_le_bytes());
        e[116..120].copy_from_slice(&first.to_le_bytes());
        e[120..124].copy_from_slice(&size.to_le_bytes());
        e
    };
    let mut directory = entry("Root Entry", 5, -2, 0, -1, 1);
    for (i, (name, data)) in streams.iter().enumerate() {
        let first = add(data, &mut sectors, &mut table);
        directory.extend(entry(name, 2, first, data.len() as i32, if i + 1 < streams.len() { i as i32 + 2 } else { -1 }, -1));
    }
    directory.resize(directory.len().div_ceil(SECTOR) * SECTOR, 0);
    let directory_first = add(&directory, &mut sectors, &mut table);
    let fat_sector = table.len() as i32;
    table.push(-3);
    table.resize(SECTOR / 4, -1);
    let mut header = vec![0u8; 512];
    header[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    header[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    header[30..32].copy_from_slice(&9i16.to_le_bytes());
    header[32..34].copy_from_slice(&6i16.to_le_bytes());
    header[44..48].copy_from_slice(&1i32.to_le_bytes());
    header[48..52].copy_from_slice(&directory_first.to_le_bytes());
    header[60..64].copy_from_slice(&(-2i32).to_le_bytes());
    header[68..72].copy_from_slice(&(-2i32).to_le_bytes());
    for i in 0..109 {
        header[76 + i * 4..80 + i * 4].copy_from_slice(&(if i == 0 { fat_sector } else { -1 }).to_le_bytes());
    }
    header.extend(sectors);
    header.extend(table.iter().flat_map(|v| v.to_le_bytes()));
    header
}

struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str) -> Case {
        let dir = std::env::temp_dir().join(format!("jlecmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ev/sub")).unwrap();
        std::fs::write(dir.join("ev/1b4dd67f29cb1962.automaticDestinations-ms"), automatic()).unwrap();
        std::fs::write(dir.join("ev/sub/abc.customDestinations-ms"), custom()).unwrap();
        std::fs::write(dir.join("ev/other.txt"), b"not one").unwrap();
        Case { dir }
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_jlecmd")).args(args).args(["--co", "false"]).output().unwrap()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn file_ending(folder: &Path, ending: &str) -> PathBuf {
    std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with(ending)).unwrap_or_else(|| panic!("no {ending} in {}", folder.display()))
}

#[test]
fn both_kinds_go_to_their_csv_files() {
    let case = Case::new("csv");
    let out = case.path("out");
    let output = case.run(&["-d", &case.path("ev"), "--csv", &out, "-q"]);
    assert!(output.status.success());
    let auto = std::fs::read_to_string(file_ending(Path::new(&out), "_AutomaticDestinations.csv")).unwrap();
    let mut lines = auto.lines();
    assert!(lines.next().unwrap().starts_with("SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,AppIdDescription,HasSps,"));
    let row = lines.next().unwrap();
    assert!(row.contains("Windows Explorer Pinned and Recent."));
    assert!(row.contains(",host,,C:\\a.txt,"));
    let custom = std::fs::read_to_string(file_ending(Path::new(&out), "_CustomDestinations.csv")).unwrap();
    assert_eq!(custom.lines().count(), 3);
    assert!(custom.contains(",Tasks,"));
}

#[test]
fn the_user_column_comes_first_only_when_given() {
    let case = Case::new("user");
    let out = case.path("out");
    assert!(case.run(&["-d", &case.path("ev"), "--csv", &out, "--csvf", "x.csv", "--user", "bob", "-q"]).status.success());
    let text = std::fs::read_to_string(Path::new(&out).join("x_CustomDestinations.csv")).unwrap();
    assert!(text.starts_with("User,SourceFile,"));
    assert!(text.lines().nth(1).unwrap().starts_with("bob,"));
}

#[test]
fn json_has_the_whole_object() {
    let case = Case::new("json");
    let out = case.path("out");
    assert!(case.run(&["-d", &case.path("ev"), "--json", &out, "-q"]).status.success());
    let text = std::fs::read_to_string(file_ending(Path::new(&out), "1b4dd67f29cb1962.automaticDestinations-ms.json")).unwrap();
    assert!(text.starts_with("{\"ParseErrors\":[],\"Directory\":[{\"Id\":0,"));
    assert!(text.contains("\"DestListVersion\":1"));
    assert!(text.contains("\"Path\":\"C:\\\\a.txt\""));
    assert!(text.contains("\"Signature\":\"0002140100000000c000000000000046\""));
}

#[test]
fn dump_to_writes_the_links_out() {
    let case = Case::new("dump");
    let out = case.path("out");
    assert!(case.run(&["-d", &case.path("ev"), "--dumpTo", &out, "-q"]).status.success());
    let auto = Path::new(&out).join("1b4dd67f29cb1962.automaticDestinations-ms");
    assert_eq!(std::fs::read(auto.join("AppId_1b4dd67f29cb1962_DirName_1.lnk")).unwrap(), link());
    assert!(auto.join("AppId_1b4dd67f29cb1962_DirName_ff.lnk").exists());
    let custom = Path::new(&out).join("abc.customDestinations-ms");
    assert_eq!(std::fs::read_dir(custom).unwrap().count(), 2);
}

#[test]
fn with_dir_adds_what_the_dest_list_leaves_out() {
    let case = Case::new("withdir");
    let out = case.path("out");
    assert!(case.run(&["-d", &case.path("ev"), "--csv", &out, "--withDir", "-q"]).status.success());
    let auto = std::fs::read_to_string(file_ending(Path::new(&out), "_AutomaticDestinations.csv")).unwrap();
    assert!(auto.contains("Found in Directory, not DestList"));
    assert!(auto.lines().count() == 3);
}

#[test]
fn a_missing_input_is_a_failure_and_a_damaged_list_is_not() {
    let case = Case::new("exit");
    assert!(!case.run(&["-f", &case.path("nothing")]).status.success());
    assert!(!case.run(&["-d", &case.path("nothing")]).status.success());
    assert!(!case.run(&[]).status.success());
    std::fs::write(case.dir.join("ev/bad.customDestinations-ms"), vec![1u8; 100]).unwrap();
    let output = case.run(&["-d", &case.path("ev"), "-q"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Invalid signature (footer missing)"));
    assert!(text.contains("Processed 2 out of 3 files"));
}

#[test]
fn the_report_has_its_style_sheets() {
    let case = Case::new("html");
    let out = case.path("out");
    assert!(case.run(&["-d", &case.path("ev"), "--html", &out, "-q"]).status.success());
    let folder = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().contains("_JLECmd_Automatic_Output_for_")).unwrap();
    assert!(folder.join("styles/style.css").exists());
    let bytes = std::fs::read(folder.join("index.xhtml")).unwrap();
    assert_eq!(&bytes[..3], &[0xef, 0xbb, 0xbf]);
    assert!(String::from_utf8_lossy(&bytes).ends_with("\n</document>"));
}
