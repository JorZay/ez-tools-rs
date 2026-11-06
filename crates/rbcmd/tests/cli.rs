//! The tool from the outside: the CSV and exit codes, on files built here.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TIME: i64 = 132_224_078_450_000_000; // 2020-01-02 03:04:05

fn dollar_i2(name: &str) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [2, 1234, TIME] {
        d.extend_from_slice(&i64::to_le_bytes(v));
    }
    let text: Vec<u16> = name.encode_utf16().chain([0]).collect();
    d.extend_from_slice(&(text.len() as i32).to_le_bytes());
    d.extend(text.iter().flat_map(|u| u.to_le_bytes()));
    d
}

fn info2(records: &[(&str, bool)]) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [5, 0, 0, 800, 0] {
        d.extend_from_slice(&i32::to_le_bytes(v));
    }
    for (name, removed) in records {
        let mut r = vec![0u8; 800];
        r[..name.len()].copy_from_slice(name.as_bytes());
        if *removed {
            r[0] = 0;
        }
        r[268..276].copy_from_slice(&TIME.to_le_bytes());
        r[276..280].copy_from_slice(&4096i32.to_le_bytes());
        let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        r[280..280 + text.len()].copy_from_slice(&text);
        d.extend_from_slice(&r);
    }
    d
}

struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("rbcmd-test-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn write(&self, name: &str, data: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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

fn rbcmd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rbcmd")).args(args).output().unwrap()
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn csv_lines(path: &str) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.ends_with("\r\n"), "CsvHelper's line ending");
    text.split("\r\n").filter(|l| !l.is_empty()).map(str::to_string).collect()
}

#[test]
fn finds_files_and_exports_them_dollar_i_first() {
    let dir = Dir::new("finds");
    dir.write("in/a/INFO2", &info2(&[("C:\\kept.txt", false), ("C:\\gone.txt", true)]));
    dir.write("in/b/$IABC", &dollar_i2("C:\\Users\\me\\a,b.txt"));
    dir.write("in/b/$iLOWER", &dollar_i2("C:\\lower.txt"));
    dir.write("in/b/other.txt", b"no");
    let csv = dir.path("csv");
    let out = rbcmd(&["-d", &dir.path("in"), "--csv", &csv, "--csvf", "out.csv", "-q"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("Found 2 files. Processing..."));
    let lines = csv_lines(&format!("{csv}/out.csv"));
    assert_eq!(lines[0], "SourceName,FileType,FileName,FileSize,DeletedOn,Removed");
    assert!(lines[1].ends_with(",$I,\"C:\\Users\\me\\a,b.txt\",1234,2020-01-02 03:04:05,False"), "{}", lines[1]);
    assert!(lines[2].ends_with(",INFO2,C:\\kept.txt,4096,2020-01-02 03:04:05,False"), "{}", lines[2]);
    assert!(lines[3].ends_with(",INFO2,C:\\gone.txt,4096,2020-01-02 03:04:05,True"), "{}", lines[3]);
    assert_eq!(lines.len(), 4);
}

#[test]
fn deleted_folder_contents_are_exported() {
    let dir = Dir::new("folder");
    dir.write("bin/$IDIR", &dollar_i2("C:\\temp"));
    dir.write("bin/$RDIR/a.txt", &[0; 10]);
    let csv = dir.path("csv");
    let out = rbcmd(&["-d", &dir.path("bin"), "--csv", &csv, "--csvf", "o.csv", "-q"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(csv_lines(&format!("{csv}/o.csv"))[2].contains(",$I,C:\\temp\\a.txt,10,"));
}

#[test]
fn console_log_is_on_by_default_beside_the_csv() {
    let dir = Dir::new("colog");
    let file = dir.write("$IABC", &dollar_i2("C:\\a.txt"));
    let csv = dir.path("csv");
    let out = rbcmd(&["-f", &file, "--csv", &csv]);
    assert!(text(&out).contains("Console log: "));
    assert!(!text(&out).contains("does not exist"), "the log file made the folder");
    let names: Vec<String> = std::fs::read_dir(&csv).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    let log = names.iter().find(|n| n.ends_with("_ConsoleLog.txt")).unwrap();
    let output = names.iter().find(|n| n.ends_with("_RBCmd_Output.csv")).unwrap();
    assert_eq!(log[..14], output[..14], "the same time stamp");
    let content = std::fs::read_to_string(Path::new(&csv).join(log)).unwrap();
    assert!(content.contains(" INF] File name: C:\\a.txt"), "{content}");
    assert!(content.contains(" WRN] CSV output will be saved to "), "{content}");
}

#[test]
fn no_console_log_with_co_false() {
    let dir = Dir::new("nolog");
    let file = dir.write("$IABC", &dollar_i2("C:\\a.txt"));
    let csv = dir.path("csv");
    let out = rbcmd(&["-f", &file, "--csv", &csv, "--co", "false"]);
    assert!(text(&out).contains("does not exist. Creating..."));
    assert!(!text(&out).contains("Console log:"));
    assert_eq!(std::fs::read_dir(&csv).unwrap().count(), 1);
}

#[test]
fn exit_codes() {
    let dir = Dir::new("exit");
    assert_eq!(rbcmd(&[]).status.code(), Some(1));
    assert_eq!(rbcmd(&["-f", &dir.path("nope")]).status.code(), Some(1));
    assert_eq!(rbcmd(&["-d", &dir.path("nope")]).status.code(), Some(1));
    // damaged files aren't a failure of the tool
    let damaged = dir.write("$IBROKEN", &[0x99; 10]);
    let out = rbcmd(&["-f", &damaged]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out).contains("Unknown header 0x99!"));
    assert!(text(&out).contains("Failed files"));
    // a failed export is
    let good = dir.write("$IGOOD", &dollar_i2("C:\\a.txt"));
    let blocker = dir.write("blocker", b"");
    assert_eq!(rbcmd(&["-f", &good, "--csv", &blocker, "-q"]).status.code(), Some(1));
}

#[test]
fn bad_date_format_fails_every_file_but_not_the_tool() {
    let dir = Dir::new("baddt");
    let file = dir.write("$IABC", &dollar_i2("C:\\a.txt"));
    let csv = dir.path("csv");
    let out = rbcmd(&["-f", &file, "--dt", "x", "--csv", &csv, "--csvf", "o.csv", "--co", "false"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out).contains("Error: Input string was not in a correct format."));
    assert_eq!(csv_lines(&format!("{csv}/o.csv")).len(), 1);
}

#[test]
fn an_option_with_a_value_can_only_be_given_once_and_a_flag_can_be_repeated() {
    let dir = Dir::new("repeat");
    let file = dir.write("$IABC", &dollar_i2("C:\\a.txt"));
    assert_eq!(rbcmd(&["-f", &file, "-f", &file]).status.code(), Some(1));
    assert_eq!(rbcmd(&["-f", &file, "--dt", "yyyy", "--dt", "MM"]).status.code(), Some(1));
    assert_eq!(rbcmd(&["-f", &file, "-q", "-q", "--debug", "--debug"]).status.code(), Some(0));
}
