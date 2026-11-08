//! The tool from the outside: output files and exit codes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Case {
    dir: PathBuf,
}

fn link() -> Vec<u8> {
    let mut b = vec![0u8; 76];
    b[0] = 0x4c;
    b[4..20].copy_from_slice(&[0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
    b[20..24].copy_from_slice(&0x84i32.to_le_bytes());
    b[24..28].copy_from_slice(&0x20i32.to_le_bytes());
    b[28..36].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    b[60..64].copy_from_slice(&1i32.to_le_bytes());
    b.extend_from_slice(&[2, 0, b'h', 0, b'i', 0]);
    b.extend_from_slice(&[0, 0, 0, 0]);
    b
}

impl Case {
    fn new(name: &str) -> Case {
        let dir = std::env::temp_dir().join(format!("lecmd-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ev/sub")).unwrap();
        std::fs::write(dir.join("ev/a.lnk"), link()).unwrap();
        std::fs::write(dir.join("ev/sub/B.LNK"), link()).unwrap();
        std::fs::write(dir.join("ev/other.txt"), link()).unwrap();
        std::fs::write(dir.join("ev/empty.lnk"), b"").unwrap();
        Case { dir }
    }

    fn path(&self, p: &str) -> String {
        self.dir.join(p).to_string_lossy().into_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lecmd")).args(args).args(["--co", "false"]).output().unwrap()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn only_file(folder: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(folder).unwrap().flatten().map(|e| e.path()).collect();
    files.sort();
    assert_eq!(files.len(), 1, "{files:?}");
    files.remove(0)
}

#[test]
fn every_output() {
    let case = Case::new("all");
    let out = case.run(&["-d", &case.path("ev"), "-q", "--csv", &case.path("c"), "--json", &case.path("j"), "--xml", &case.path("x"), "--html", &case.path("h")]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));

    let csv = std::fs::read_to_string(only_file(&case.dir.join("c"))).unwrap();
    let mut lines = csv.split("\r\n");
    assert!(lines.next().unwrap().starts_with("SourceFile,SourceCreated,SourceModified,SourceAccessed,TargetCreated,"));
    assert_eq!(csv.split("\r\n").count(), 4, "header, two links and the end");
    assert!(csv.contains(",hi,,SwNormal,"), "{csv}");

    let json = std::fs::read_to_string(only_file(&case.dir.join("j"))).unwrap();
    assert_eq!(json.lines().count(), 2);
    assert!(json.contains("\"TargetCreated\":\"2016-02-15T"), "{json}");
    assert!(json.contains("\"FileSize\":0,"));
    assert!(!json.contains("\"Arguments\""));

    assert_eq!(std::fs::read_dir(case.dir.join("x")).unwrap().count(), 2);
    let html = only_file(&case.dir.join("h"));
    assert!(html.to_string_lossy().contains("_LECmd_Output_for_"));
    assert!(std::fs::read_to_string(html.join("index.xhtml")).unwrap().starts_with("\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<?xml-stylesheet href=\"normalize.css\"?>"));
    // the styles have no byte order mark
    assert_eq!(std::fs::read(html.join("style.css")).unwrap()[0], b'/');
}

#[test]
fn the_console_shows_a_link() {
    let case = Case::new("console");
    let out = case.run(&["-f", &case.path("ev/a.lnk")]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("  Flags: HasName, IsUnicode\n"), "{text}");
    assert!(text.contains("Name: hi\n"));
    assert!(text.contains("  Show window: SwNormal (Activates and displays the window."));
    assert!(text.contains("---------- Processed "));
}

#[test]
fn exit_codes() {
    let case = Case::new("exit");
    assert_eq!(case.run(&[]).status.code(), Some(1));
    assert_eq!(case.run(&["-f", &case.path("nothing.lnk")]).status.code(), Some(1));
    assert_eq!(case.run(&["-d", &case.path("nothing")]).status.code(), Some(1));
    // a damaged link is listed, but isn't the tool's failure
    std::fs::write(case.dir.join("ev/bad.lnk"), b"not a link at all").unwrap();
    let out = case.run(&["-d", &case.path("ev"), "-q"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Failed files"));
    // a broken link is a file that can't be read
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("nowhere", case.dir.join("ev/gone.lnk")).unwrap();
        assert_eq!(case.run(&["-d", &case.path("ev"), "-q"]).status.code(), Some(1));
    }
}
