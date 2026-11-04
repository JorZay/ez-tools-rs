//! Checks over every sample of the Prefetch library (its RobustnessTests and PrefetchHashTests), and malformed files
//! built in memory. The samples need PREFETCH_TEST_FILES (see upstream.rs); without it those tests do nothing.

use std::path::{Path, PathBuf};

use prefetch_ez::{Error, Prefetch, SourceTimes, Version, executable_path, hash, parse};

fn samples() -> Vec<PathBuf> {
    let Some(root) = std::env::var_os("PREFETCH_TEST_FILES") else { return vec![] };
    let mut files = vec![];
    for dir in std::fs::read_dir(root).unwrap().flatten() {
        if dir.file_name() == "Bad" || !dir.path().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(dir.path()).unwrap().flatten() {
            if f.path().extension().is_some_and(|e| e.eq_ignore_ascii_case("pf")) {
                files.push(f.path());
            }
        }
    }
    files
}

fn open(path: &Path) -> Prefetch {
    prefetch_ez::open(path, &mut |_, _| {}).unwrap()
}

#[test]
fn every_sample_parses_without_errors() {
    for file in samples() {
        let pf = open(&file);
        assert_eq!(pf.parse_errors, Vec::<String>::new(), "{file:?}");
        let h = pf.header.as_ref().unwrap();
        assert_eq!(h.signature, "SCCA");
        assert_eq!(h.file_size as usize, pf.raw_bytes.len(), "{file:?}");
        assert_eq!(pf.file_metrics.len() as i32, pf.file_metrics_count, "{file:?}");
        assert_eq!(pf.trace_chains.len() as i32, pf.trace_chains_count, "{file:?}");
        assert_eq!(pf.volume_information.len() as i32, pf.volume_count, "{file:?}");
        assert_eq!(pf.filenames.len() as i32, pf.file_metrics_count, "{file:?}");
        for (m, name) in pf.file_metrics.iter().zip(&pf.filenames) {
            assert_eq!(m.filename_string_size as usize, name.encode_utf16().count(), "{file:?}");
        }
    }
}

/// Hosting processes and packaged apps hash part of their command line, so no path gives their hash
#[test]
fn hash_of_the_path_matches_the_header_in_every_sample() {
    const HOSTING: &[&str] = &["DLLHOST.EXE", "MMC.EXE", "TASKHOST.EXE", "WWAHOST.EXE", "LIVECOMM.EXE", "CALCULATOR.EXE"];
    let mut checked = 0;
    for file in samples() {
        let pf = open(&file);
        let h = pf.header.as_ref().unwrap();
        let path = executable_path(&pf);
        if HOSTING.contains(&h.executable_filename.as_str()) {
            continue;
        }
        assert!(path.path_validated, "{file:?}: {path:?}");
        checked += 1;
    }
    assert!(samples().is_empty() || checked > 40, "{checked}");
}

#[test]
fn header_hash_value_matches_the_hash_text() {
    assert_eq!(format!("{:X}", 0x087B4001u32), "87B4001");
    assert_eq!(hash::calculate_xp(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE"), 0x087B4001);
}

const FILE_INFO: usize = 84;

fn int(b: &mut [u8], o: usize, v: i32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A minimal version 17 or 23 prefetch file with one of everything (RobustnessTests.Build)
fn build(version: i32) -> Vec<u8> {
    let v17 = version == 17;
    let metrics = FILE_INFO + if v17 { 68 } else { 156 };
    let trace = metrics + if v17 { 20 } else { 32 };
    let strings_at = trace + 12;
    let strings = wide("\\VOLUME\\TEST.EXE\0");
    let volumes = strings_at + strings.len();
    let device = wide("\\VOLUME");
    let device_at = if v17 { 40 } else { 104 };
    let refs_at = device_at + device.len() + 2;
    let refs_header = if v17 { 8 } else { 16 };
    let refs_size = refs_header + 8;
    let dirs_at = refs_at + refs_size;
    let dir = wide("\\VOLUME\\DIR\0");
    let volumes_size = dirs_at + 2 + dir.len();
    let mut b = vec![0u8; volumes + volumes_size];
    let total = b.len() as i32;

    int(&mut b, 0, version);
    b[4..8].copy_from_slice(b"SCCA");
    int(&mut b, 12, total);
    let name = wide("TEST.EXE");
    b[16..16 + name.len()].copy_from_slice(&name);
    int(&mut b, 76, 0x12345678);

    int(&mut b, FILE_INFO, metrics as i32);
    int(&mut b, FILE_INFO + 4, 1);
    int(&mut b, FILE_INFO + 8, trace as i32);
    int(&mut b, FILE_INFO + 12, 1);
    int(&mut b, FILE_INFO + 16, strings_at as i32);
    int(&mut b, FILE_INFO + 20, strings.len() as i32);
    int(&mut b, FILE_INFO + 24, volumes as i32);
    int(&mut b, FILE_INFO + 28, 1);
    int(&mut b, FILE_INFO + 32, volumes_size as i32);

    // 2020-01-02 03:04:05
    let run_time = 132_224_078_450_000_000i64.to_le_bytes();
    let at = FILE_INFO + if v17 { 36 } else { 44 };
    b[at..at + 8].copy_from_slice(&run_time);
    int(&mut b, FILE_INFO + if v17 { 60 } else { 68 }, 7);
    int(&mut b, metrics + if v17 { 12 } else { 16 }, 16);
    b[strings_at..strings_at + strings.len()].copy_from_slice(&strings);

    int(&mut b, volumes, device_at as i32);
    int(&mut b, volumes + 4, (device.len() / 2) as i32);
    b[volumes + 8..volumes + 16].copy_from_slice(&run_time);
    int(&mut b, volumes + 16, 0x1234ABCD);
    int(&mut b, volumes + 20, refs_at as i32);
    int(&mut b, volumes + 24, refs_size as i32);
    int(&mut b, volumes + 28, dirs_at as i32);
    int(&mut b, volumes + 32, 1);
    b[volumes + device_at..volumes + device_at + device.len()].copy_from_slice(&device);

    int(&mut b, volumes + refs_at, if v17 { 1 } else { 3 });
    int(&mut b, volumes + refs_at + 4, 1);
    if !v17 {
        // Unknown header bytes that used to be read as the first reference
        int(&mut b, volumes + refs_at + 8, 0xDEADBEEFu32 as i32);
    }
    int(&mut b, volumes + refs_at + refs_header, 1234);
    b[volumes + refs_at + refs_header + 6] = 2;
    b[volumes + dirs_at..volumes + dirs_at + 2].copy_from_slice(&((dir.len() / 2 - 1) as u16).to_le_bytes());
    b[volumes + dirs_at + 2..volumes + dirs_at + 2 + dir.len()].copy_from_slice(&dir);
    b
}

fn read(b: Vec<u8>) -> Result<Prefetch, Error> {
    parse(b, "test", SourceTimes::default(), &mut |_, _| {})
}

fn message(b: Vec<u8>) -> String {
    read(b).unwrap_err().to_string()
}

#[test]
fn built_file_parses() {
    for version in [17, 23] {
        let pf = read(build(version)).unwrap();
        assert_eq!(pf.parse_errors, Vec::<String>::new());
        let h = pf.header.as_ref().unwrap();
        assert_eq!(h.executable_filename, "TEST.EXE");
        assert_eq!(h.version, if version == 17 { Version::WinXpOrWin2K3 } else { Version::VistaOrWin7 });
        assert_eq!(pf.run_count, 7);
        assert_eq!(pf.last_run_times.len(), 1);
        assert_eq!(pf.last_run_times[0].format("yyyy-MM-dd HH:mm:ss"), "2020-01-02 03:04:05");
        assert_eq!(pf.filenames, [r"\VOLUME\TEST.EXE"]);
        assert_eq!(pf.file_metrics.len(), 1);
        assert_eq!(pf.trace_chains.len(), 1);
        let v = &pf.volume_information[0];
        assert_eq!(v.device_name, r"\VOLUME");
        assert_eq!(v.serial_number, "1234ABCD");
        assert_eq!(v.directory_names, [r"\VOLUME\DIR"]);
        assert_eq!(v.file_references.len(), 1);
        assert_eq!(v.file_references[0].entry_number, 1234);
        assert_eq!(v.file_references[0].sequence_number, Some(2));
    }
}

#[test]
fn name_filling_the_whole_field_is_read() {
    let mut b = build(17);
    let name = "X".repeat(30);
    b[16..76].copy_from_slice(&wide(&name));
    let pf = read(b).unwrap();
    assert_eq!(pf.header.unwrap().executable_filename, name);
    assert!(pf.parse_errors.is_empty());
}

#[test]
fn truncated_file_reports_an_error() {
    let mut b = build(23);
    b.truncate(FILE_INFO + 20);
    let pf = read(b).unwrap();
    assert_eq!(pf.parse_errors.len(), 1);
    assert!(pf.parse_errors[0].starts_with("File information:"), "{:?}", pf.parse_errors);
    assert_eq!(pf.header.unwrap().executable_filename, "TEST.EXE");
    assert!(pf.filenames.is_empty() && pf.file_metrics.is_empty() && pf.volume_information.is_empty());
}

#[test]
fn file_shorter_than_the_header_has_no_header() {
    let mut b = build(17);
    b.truncate(40);
    let pf = read(b).unwrap();
    assert!(pf.header.is_none());
    assert!(pf.parse_errors[0].starts_with("Header: Invalid Header data (offset 0, length 84, available 40)"));
}

#[test]
fn bad_section_only_loses_that_section() {
    let mut b = build(23);
    int(&mut b, FILE_INFO + 8, i32::MAX);
    let pf = read(b).unwrap();
    assert_eq!(pf.parse_errors.len(), 1);
    assert!(pf.parse_errors[0].starts_with("Trace chains:"));
    assert!(pf.trace_chains.is_empty());
    assert_eq!((pf.file_metrics.len(), pf.filenames.len(), pf.volume_information.len()), (1, 1, 1));
}

#[test]
fn huge_or_negative_counts_are_reported() {
    for count in [i32::MAX, -1] {
        let mut b = build(17);
        int(&mut b, FILE_INFO + 4, count);
        let pf = read(b).unwrap();
        assert_eq!(pf.parse_errors.len(), 1);
        assert!(pf.parse_errors[0].starts_with("File metrics:"));
        assert!(pf.file_metrics.is_empty());
    }
}

#[test]
fn out_of_range_run_time_is_reported_and_skipped() {
    let mut b = build(17);
    b[FILE_INFO + 36..FILE_INFO + 44].copy_from_slice(&i64::MAX.to_le_bytes());
    let pf = read(b).unwrap();
    assert_eq!(pf.parse_errors, ["Last run time 0 is out of range (0x7FFFFFFFFFFFFFFF)"]);
    assert!(pf.last_run_times.is_empty());
    assert_eq!(pf.run_count, 7);
}

#[test]
fn bad_directory_string_keeps_the_volume_and_references() {
    let mut b = build(23);
    let volumes = i32::from_le_bytes(b[FILE_INFO + 24..FILE_INFO + 28].try_into().unwrap()) as usize;
    int(&mut b, volumes + 32, 5000);
    let pf = read(b).unwrap();
    assert_eq!(pf.parse_errors.len(), 1);
    assert!(pf.parse_errors[0].starts_with("Volume 0 directory strings:"));
    assert_eq!(pf.volume_information[0].file_references.len(), 1);
}

#[test]
fn unusable_files_are_errors() {
    assert_eq!(message(vec![]), "File is too small to be a prefetch file (0 bytes)");
    assert_eq!(message(vec![0x11, 0, 0]), "File is too small to be a prefetch file (3 bytes)");
    assert_eq!(message(vec![0; 1024]), "Invalid signature! Should be 'SCCA'");
    let mut b = build(17);
    b[0] = 99;
    assert_eq!(message(b), "Unknown version '00000063'");
    assert_eq!(message(vec![b'M', b'A', b'M', 2, 0x10, 0, 0, 0, 0, 0]), "Unsupported MAM compression format 2");
    assert!(message(vec![b'M', b'A', b'M', 4, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0]).starts_with("Decompressed size 2147483647 is larger than"));
    assert_eq!(message(vec![b'M', b'A', b'M', 0x84, 0, 0, 0, 0, 0]), "Compressed file is truncated");
}

#[test]
fn truncated_compressed_sample_is_an_error() {
    let Some(root) = std::env::var_os("PREFETCH_TEST_FILES") else { return };
    let mut b = std::fs::read(Path::new(&root).join("Win10/CMD.EXE-D269B812.pf")).unwrap();
    b.truncate(b.len() / 2);
    assert!(message(b).starts_with("Decompression failed: "));
}

/// Every byte of a real file changed, and every length: reported or parsed, never a crash
#[test]
fn damaged_files_never_panic() {
    let base = build(23);
    for i in 0..base.len() {
        for value in [0x00, 0xFF, 0x7F, 0x80] {
            let mut b = base.clone();
            b[i] = value;
            let _ = read(b);
        }
        let _ = read(base[..i].to_vec());
    }
    let Some(root) = std::env::var_os("PREFETCH_TEST_FILES") else { return };
    let compressed = std::fs::read(Path::new(&root).join("Win10/CMD.EXE-D269B812.pf")).unwrap();
    for i in (0..compressed.len()).step_by(37) {
        let mut b = compressed.clone();
        b[i] ^= 0xA5;
        let _ = read(b);
        let _ = read(compressed[..i].to_vec());
    }
}
