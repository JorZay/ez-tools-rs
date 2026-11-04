//! The program itself: exit codes, and what it does with something that isn't a hive.

use std::path::PathBuf;
use std::process::{Command, Output};

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(name: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("appcompatcacheparser-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Folder(dir)
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_appcompatcacheparser")).args(args).output().unwrap()
}

#[test]
fn exit_codes() {
    let base = folder("exit");
    let out = base.0.join("out");
    let out = out.to_str().unwrap();
    assert_eq!(run(&["--nothing"]).status.code(), Some(1), "bad arguments");
    assert_eq!(run(&["-f", "/no/such/SYSTEM"]).status.code(), Some(1), "--csv is required");
    assert_eq!(run(&["-f", "/no/such/SYSTEM", "--csv", out]).status.code(), Some(1));
    let live = run(&["--csv", out, "--co", "false"]);
    assert_eq!(live.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&live.stdout).contains("Live Registry support is not available"));

    // something that isn't a hive is a damaged file, not the tool's failure, and no CSV is written
    let junk = base.0.join("junk");
    std::fs::write(&junk, vec![0u8; 4096]).unwrap();
    let outdir = base.0.join("junkout");
    let r = run(&["-f", junk.to_str().unwrap(), "--csv", outdir.to_str().unwrap(), "--co", "false"]);
    assert_eq!(r.status.code(), Some(0));
    assert!(!outdir.exists());
}

#[test]
fn console_log_is_in_the_csv_folder() {
    let base = folder("log");
    let junk = base.0.join("junk");
    std::fs::write(&junk, vec![0u8; 4096]).unwrap();
    let out = base.0.join("out");
    let r = run(&["-f", junk.to_str().unwrap(), "--csv", out.to_str().unwrap()]);
    assert_eq!(r.status.code(), Some(0));
    let log = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().ends_with("ConsoleLog.txt")).unwrap();
    assert!(std::fs::read_to_string(log).unwrap().contains("is not a Registry hive"));
}
