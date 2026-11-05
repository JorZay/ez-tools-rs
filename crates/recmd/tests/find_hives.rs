//! How -d finds hives: as the original's Windows build, which finds more than its Linux one.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct Folder(PathBuf);

impl Folder {
    fn new(name: &str) -> Folder {
        let path = std::env::temp_dir().join(format!("recmd-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Folder(path)
    }

    fn put(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The names of the hives a run on this folder processes, sorted
fn processed(dir: &Folder) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_recmd")).arg("-d").arg(&dir.0).args(["--sk", "nothing", "--co", "false"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let mut names: Vec<String> =
        text.lines().filter_map(|l| l.strip_prefix("Processing hive ")).map(|p| p.rsplit('/').next().unwrap().to_string()).collect();
    names.sort();
    names
}

#[test]
fn any_name_holding_a_hives_name_if_it_is_a_hive() {
    let dir = Folder::new("names");
    let regf = b"regf\0\0\0\0";
    for name in ["NTUSER.DAT", "NTUSER1.DAT", "my_usrclass_copy.dat", "SYSTEM.old", "system", "settings.dat", "Registry.dat.bak", "sub/deeper/SOFTWARE", "user"] {
        dir.put(name, regf);
    }
    for name in ["unrelated.dat", "SYSTEM.LOG1", "SAM.log", "SECURITY.txt", "DEFAULT.csv"] {
        dir.put(name, regf);
    }
    dir.put("DEFAULT", b"#!/bin/sh\necho a script\n");
    dir.put("COMPONENTS", b"reg");
    assert_eq!(processed(&dir), ["NTUSER.DAT", "NTUSER1.DAT", "Registry.dat.bak", "SOFTWARE", "SYSTEM.old", "my_usrclass_copy.dat", "settings.dat", "system", "user"]);
}

#[test]
fn links_to_folders_are_not_followed() {
    let dir = Folder::new("links");
    dir.put("elsewhere/SAM", b"regf\0\0\0\0");
    dir.put("in/SYSTEM", b"regf\0\0\0\0");
    std::os::unix::fs::symlink(dir.0.join("elsewhere"), dir.0.join("in/linked")).unwrap();
    std::os::unix::fs::symlink(dir.0.join("elsewhere"), dir.0.join("in/SECURITY")).unwrap();
    std::os::unix::fs::symlink(dir.0.join("elsewhere/SAM"), dir.0.join("in/DRIVERS")).unwrap();
    let inner = Folder(dir.0.join("in"));
    assert_eq!(processed(&inner), ["DRIVERS", "SYSTEM"]);
}
