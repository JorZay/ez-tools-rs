//! -q and a file too short to hold its header

use std::path::PathBuf;
use std::process::Command;

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pecmd-quiet-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn short_file_with_quiet_is_skipped_and_the_export_still_runs() {
    let dir = folder("short");
    let mut short = vec![0x11, 0, 0, 0];
    short.extend_from_slice(b"SCCA");
    short.resize(40, 0);
    let input = dir.join("SHORT-00000000.pf");
    std::fs::write(&input, short).unwrap();
    let out = dir.join("out");

    let run = Command::new(env!("CARGO_BIN_EXE_pecmd"))
        .args(["-q", "--csvf", "a.csv", "-d"])
        .arg(&dir)
        .arg("--csv")
        .arg(&out)
        .output()
        .unwrap();
    let console = String::from_utf8_lossy(&run.stdout);

    assert!(run.status.success(), "{console}");
    assert!(console.contains("Error opening") && console.contains("Failed files"), "{console}");
    // nothing was processed, so nothing is exported, and no export error is reported
    assert!(!out.join("a.csv").exists());
    assert!(!console.contains("Error exporting"), "{console}");
    std::fs::remove_dir_all(&dir).unwrap();
}
