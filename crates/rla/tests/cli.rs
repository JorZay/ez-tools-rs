//! rla as a program, on small hives made here (RlaTests, and how -d finds hives). The replay itself is compared with the
//! original by tools/parity-rla.sh.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Folder(PathBuf);

impl Folder {
    fn new(name: &str) -> Folder {
        let path = std::env::temp_dir().join(format!("rla-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Folder(path)
    }

    fn put(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn sub(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn checksum(b: &[u8]) -> u32 {
    b[..508].chunks_exact(4).fold(0, |x, c| x ^ u32::from_le_bytes(c.try_into().unwrap()))
}

/// A base block and one empty page of hive bins, with these sequence numbers
fn hive(primary: u32, secondary: u32) -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    b[..4].copy_from_slice(b"regf");
    b[4..8].copy_from_slice(&primary.to_le_bytes());
    b[8..12].copy_from_slice(&secondary.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..28].copy_from_slice(&5u32.to_le_bytes());
    b[40..44].copy_from_slice(&4096u32.to_le_bytes());
    let c = checksum(&b);
    b[508..512].copy_from_slice(&c.to_le_bytes());
    b
}

/// An old format log (DIRT) that changes the first 512 bytes of the hive bins to `fill`
fn old_log(sequence: u32, fill: u8) -> Vec<u8> {
    let mut base = hive(sequence, sequence)[..512].to_vec();
    base[28..32].copy_from_slice(&1u32.to_le_bytes());
    let c = checksum(&base);
    base[508..512].copy_from_slice(&c.to_le_bytes());
    base.extend_from_slice(b"DIRT\x01");
    base.resize(1024, 0);
    base.resize(1536, fill);
    base
}

fn rla(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rla")).args(args).output().unwrap();
    (output.status.code().unwrap(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
}

/// The names of the files in a folder, sorted
fn names(folder: &str) -> Vec<String> {
    let mut list: Vec<String> = fs::read_dir(folder).map_or(vec![], |d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect());
    list.sort();
    list
}

/// Files under a folder, at any depth
fn files_under(folder: &Path) -> Vec<PathBuf> {
    let mut list = Vec::new();
    for entry in fs::read_dir(folder).unwrap().flatten() {
        if entry.path().is_dir() {
            list.extend(files_under(&entry.path()));
        } else {
            list.push(entry.path());
        }
    }
    list
}

#[test]
fn dirty_hive_is_replayed_under_its_path() {
    let dir = Folder::new("replay");
    let hive_path = dir.put("hives/SYSTEM", &hive(9, 8));
    dir.put("hives/SYSTEM.LOG1", &old_log(8, 0x41));
    let out = dir.sub("out");
    let (code, output) = rla(&["-f", &hive_path, "--out", &out, "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Transaction logs applied: SYSTEM.LOG1"), "{output}");
    let saved = files_under(Path::new(&out));
    assert_eq!(saved.len(), 1);
    assert!(saved[0].ends_with("hives/SYSTEM"), "{saved:?}");
    let bytes = fs::read(&saved[0]).unwrap();
    assert_eq!(bytes[4..8], bytes[8..12], "the sequence numbers match");
    assert_eq!(u32::from_le_bytes(bytes[508..512].try_into().unwrap()), checksum(&bytes));
    assert!(bytes[4096..4608].iter().all(|b| *b == 0x41));
    assert!(bytes[4608..].iter().all(|b| *b == 0));
}

#[test]
fn nop_does_not_overwrite() {
    let dir = Folder::new("nop");
    dir.put("in/a/SYSTEM", &hive(1, 1));
    dir.put("in/b/SYSTEM", &hive(1, 1));
    let out = dir.sub("out");
    let (code, output) = rla(&["-d", &dir.sub("in"), "--out", &out, "--nop", "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(names(&out), ["SYSTEM", "SYSTEM_2"]);
}

#[test]
fn profile_hives_get_drive_and_profile() {
    let dir = Folder::new("profile");
    dir.put("in/C/Users/eric/NTUSER.DAT", &hive(1, 1));
    dir.put("in/C/Users/bob/NTUSER.DAT", &hive(1, 1));
    let out = dir.sub("out");
    assert_eq!(rla(&["-d", &dir.sub("in"), "--out", &out, "--nop", "--co", "false"]).0, 0);
    assert_eq!(names(&out), ["C_bob_NTUSER.DAT", "C_eric_NTUSER.DAT"]);
}

#[test]
fn dirty_hive_without_logs() {
    let dir = Folder::new("nologs");
    let hive_path = dir.put("SYSTEM", &hive(2, 1));
    let out = dir.sub("out");
    assert_eq!(rla(&["-f", &hive_path, "--out", &out, "--co", "false"]).0, 0);
    let saved = files_under(Path::new(&out));
    assert_eq!(saved.len(), 1);
    assert_eq!(fs::read(&saved[0]).unwrap(), hive(2, 1), "copied as it is");

    let out2 = dir.sub("out2");
    let (code, output) = rla(&["-f", &hive_path, "--out", &out2, "--ca", "false", "--co", "false"]);
    assert_eq!(code, 1, "{output}");
    assert!(output.contains("could not be processed"), "{output}");
    assert!(!Path::new(&out2).exists());
}

#[test]
fn clean_hive_with_ca_false_is_skipped() {
    let dir = Folder::new("clean");
    let hive_path = dir.put("SYSTEM", &hive(1, 1));
    let out = dir.sub("out");
    let (code, output) = rla(&["-f", &hive_path, "--out", &out, "--ca", "false", "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains("could not be processed"), "{output}");
    assert!(!Path::new(&out).exists());
}

#[test]
fn exit_codes() {
    let dir = Folder::new("codes");
    let good = dir.put("SYSTEM", &hive(1, 1));
    assert_eq!(rla(&["-f", &dir.sub("missing"), "--out", &dir.sub("o1"), "--co", "false"]).0, 1);
    assert_eq!(rla(&["-d", &dir.sub("missing"), "--out", &dir.sub("o1"), "--co", "false"]).0, 1);
    assert_eq!(rla(&["-f", &good]).0, 1, "--out is required");
    assert_eq!(rla(&[]).0, 1);

    // a damaged hive is reported and exits 0
    let not_a_hive = dir.put("notahive", b"not a hive at all");
    let (code, output) = rla(&["-f", &not_a_hive, "--out", &dir.sub("o2")]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("could not be processed"), "{output}");

    // output that can't be written: --out is a file
    let out_file = dir.put("afile", b"");
    assert_eq!(rla(&["-f", &good, "--out", &out_file]).0, 1);
    assert_eq!(rla(&["-d", &dir.sub("nohives"), "--out", &out_file]).0, 1);
}

#[test]
fn console_log() {
    let dir = Folder::new("log");
    let hive_path = dir.put("SYSTEM", &hive(1, 1));
    let out = dir.sub("out");
    let (code, output) = rla(&["-f", &hive_path, "--out", &out]);
    assert_eq!(code, 0, "{output}");
    let logs: Vec<String> = names(&out).into_iter().filter(|n| n.ends_with("_ConsoleLog.txt")).collect();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].find("_rla_"), Some(14), "{}", logs[0]);
    assert!(output.contains(&format!("Console log: {out}/{}", logs[0])), "{output}");
    let text = fs::read_to_string(Path::new(&out).join(&logs[0])).unwrap();
    assert!(text.contains(" INF] Command line: -f "), "{text}");

    let other = dir.sub("other");
    let (code, output) = rla(&["-f", &hive_path, "--out", &other, "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains("Console log:"), "{output}");
    assert!(files_under(Path::new(&other)).iter().all(|p| !p.to_string_lossy().ends_with("_ConsoleLog.txt")));
}

// The original's Windows build, which finds more than its Linux one: any name holding a hive's name, if it is a hive
#[test]
fn d_finds_hives_as_the_windows_build() {
    let dir = Folder::new("find");
    let regf = hive(1, 1);
    for name in ["NTUSER.DAT", "NTUSER1.DAT", "my_usrclass_copy.dat", "SYSTEM.old", "system", "Amcache.hve.tmp", "sub/deeper/SOFTWARE"] {
        dir.put(&format!("in/{name}"), &regf);
    }
    // the same contents with another name, or an extension that is never a hive
    for name in ["unrelated.dat", "SYSTEM.LOG1", "SAM.log", "SECURITY.txt", "DEFAULT.csv"] {
        dir.put(&format!("in/{name}"), &regf);
    }
    // a hive's name without a hive's signature, or too short to have one
    dir.put("in/DEFAULT", b"#!/bin/sh\necho a script\n");
    dir.put("in/COMPONENTS", b"reg");
    let out = dir.sub("out");
    let (code, output) = rla(&["-d", &dir.sub("in"), "--out", &out, "--nop", "--cn", "false", "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Hives found: 7"), "{output}");
    assert!(!output.contains("could not be processed"), "{output}");
    assert_eq!(names(&out), ["Amcache.hve.tmp", "NTUSER.DAT", "NTUSER1.DAT", "SOFTWARE", "SYSTEM.old", "my_usrclass_copy.dat", "system"]);
}

#[test]
fn d_does_not_follow_links_to_folders() {
    let dir = Folder::new("links");
    let target = dir.put("elsewhere/SAM", &hive(1, 1));
    dir.put("in/SYSTEM", &hive(1, 1));
    std::os::unix::fs::symlink(dir.sub("elsewhere"), dir.0.join("in/linked")).unwrap();
    // a link to a hive is a hive, as in the original's Linux build
    std::os::unix::fs::symlink(target, dir.0.join("in/SECURITY")).unwrap();
    let out = dir.sub("out");
    let (code, output) = rla(&["-d", &dir.sub("in"), "--out", &out, "--nop", "--co", "false"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(names(&out), ["SECURITY", "SYSTEM"]);
}

#[test]
fn unreadable_folder_is_reported_and_the_run_goes_on() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Folder::new("locked");
    dir.put("in/SYSTEM", &hive(1, 1));
    let locked = dir.sub("in/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0)).unwrap();
    if fs::read_dir(&locked).is_ok() {
        // root reads everything
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let out = dir.sub("out");
    let (code, output) = rla(&["-d", &dir.sub("in"), "--out", &out, "--nop", "--co", "false"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code, 1, "{output}");
    assert!(output.contains(&format!("Unable to read folder {locked}")), "{output}");
    assert_eq!(names(&out), ["SYSTEM"]);
}
