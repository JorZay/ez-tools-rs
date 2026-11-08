//! The tool from the outside: CSV, JSON and exit codes, on files built here.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The CRC-32 of the file without the 4 bytes at 0x10
fn crc(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for (i, &b) in data.iter().enumerate() {
        if (0x10..0x14).contains(&i) {
            continue;
        }
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { 0xEDB8_8320 ^ (crc >> 1) } else { crc >> 1 };
        }
    }
    !crc
}

fn bcf(names: &[&str]) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [0xFFEE_FFFEu32, 0x2211, 3, 1, 0] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    for name in names {
        let units: Vec<u16> = name.encode_utf16().collect();
        d.extend_from_slice(&(units.len() as i32).to_le_bytes());
        d.extend(units.iter().flat_map(|u| u.to_le_bytes()));
        d.extend_from_slice(&[0, 0]);
    }
    let c = crc(&d);
    d[0x10..0x14].copy_from_slice(&c.to_le_bytes());
    d
}

struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("recentfilecacheparser-test-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn write(&self, name: &str, data: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, data).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_recentfilecacheparser")).args(args).output().unwrap()
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The only file in a folder whose name ends so
fn only(folder: &str, suffix: &str) -> String {
    let found: Vec<PathBuf> = std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(suffix)).collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found[0].to_string_lossy().into_owned()
}

#[test]
fn csv_and_json() {
    let dir = Dir::new("csv");
    let f = dir.write("RecentFileCache.bcf", &bcf(&["c:\\a.exe", "c:\\x,y \"z\".exe", "line\nbreak"]));
    let (c, j) = (dir.path("c"), dir.path("j"));
    let out = run(&["-f", &f, "--csv", &c, "--json", &j]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Checksum: 0x"), "{}", text(&out));

    let csv = std::fs::read_to_string(only(&c, "_RecentFileCacheParser_Output.csv")).unwrap();
    assert!(!csv.starts_with('\u{feff}'));
    let lines: Vec<&str> = csv.split("\r\n").collect();
    assert_eq!(lines[0], "SourceFile,SourceCreated,SourceModified,SourceAccessed,Filename");
    assert!(lines[1].starts_with(&format!("{f},")) && lines[1].ends_with(",c:\\a.exe"), "{}", lines[1]);
    assert!(lines[2].ends_with(",\"c:\\x,y \"\"z\"\".exe\""), "{}", lines[2]);
    assert!(lines[3].ends_with(",\"line\nbreak\""), "{}", lines[3]);
    assert_eq!(lines.len(), 5);
    assert!(Path::new(&only(&c, "_ConsoleLog.txt")).exists(), "the log goes to the first output folder");

    let json = std::fs::read_to_string(only(&j, "_RecentFileCache.bcf.json")).unwrap();
    assert!(json.starts_with(&format!("{{\"SourceFile\":\"{f}\",\"SourceCreated\":\"")), "{json}");
    assert!(json.ends_with("\"ParseErrors\":[],\"ParsingError\":false}"), "{json}");
}

#[test]
fn pretty_csvf_and_no_log() {
    let dir = Dir::new("pretty");
    let f = dir.write("r.bcf", &bcf(&["c:\\a.exe"]));
    let (c, j) = (dir.path("c"), dir.path("j"));
    let out = run(&["-f", &f, "--csv", &c, "--csvf", "/elsewhere/mine.csv", "--json", &j, "--pretty", "-q", "--co", "false"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("File names"), "-q");
    assert!(Path::new(&c).join("mine.csv").exists());
    let dump = std::fs::read_to_string(only(&j, "_r.bcf.json")).unwrap();
    assert!(dump.starts_with("{\r\n\tSourceFile: "), "{dump}");
    assert!(dump.contains("\r\n\t\t\"c: \\a.exe\"\r\n"), "{dump}");
    assert!(dump.ends_with("\r\n\tParsingError: False\r\n}"), "{dump}");
    assert_eq!(std::fs::read_dir(&c).unwrap().count(), 1, "--co false: no log");
}

#[test]
fn damaged_file_is_exported_with_its_problems() {
    let dir = Dir::new("damaged");
    let mut d = bcf(&["c:\\a.exe"]);
    d[0x10] ^= 1;
    d.extend_from_slice(&[7, 0]);
    let f = dir.write("d.bcf", &d);
    let c = dir.path("c");
    let out = run(&["-f", &f, "--csv", &c]);
    assert!(out.status.success());
    let console = text(&out);
    assert!(console.contains("(INVALID)") && console.contains("Problems found while parsing:"), "{console}");
    assert!(console.contains("  2 trailing byte(s) at 0x2A are too short for an entry"), "{console}");
    let csv = std::fs::read_to_string(only(&c, "_Output.csv")).unwrap();
    assert_eq!(csv.matches("\r\n").count(), 2);
}

#[test]
fn not_a_recentfilecache_exports_nothing() {
    let dir = Dir::new("bad");
    let f = dir.write("lnk.bcf", &[0x4C, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let c = dir.path("c");
    let out = run(&["-f", &f, "--csv", &c, "--co", "false"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out).contains("Invalid signature 0x0000004C! Should be 0xFFEEFFFE (offset 0x0, field Signature)"), "{}", text(&out));
    assert!(!Path::new(&c).exists());
    let small = dir.write("small.bcf", &[0xFE, 0xFF]);
    let out = run(&["-f", &small]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out).contains("File is 2 bytes, smaller than the 20 byte header (offset 0x0, field Header)"));
}

#[test]
fn failures_exit_with_1() {
    let dir = Dir::new("fail");
    assert_eq!(run(&[]).status.code(), Some(1));
    assert!(text(&run(&[])).contains("-f is required. Exiting"));
    let out = run(&["-f", &dir.path("nope.bcf")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("not found. Exiting"));
    assert_eq!(run(&["-f", &dir.path("")]).status.code(), Some(1), "a folder isn't a file");
    let f = dir.write("r.bcf", &bcf(&["a"]));
    let blocker = dir.write("file", b"x");
    let out = run(&["-f", &f, "--csv", &blocker, "--json", &dir.path("j")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(Path::new(&dir.path("j")).is_dir(), "the JSON is still written");
    assert_eq!(run(&["-f", &f, "-f", &f]).status.code(), Some(1));
    assert_eq!(run(&["-f", &f, "--bogus"]).status.code(), Some(1));
}
