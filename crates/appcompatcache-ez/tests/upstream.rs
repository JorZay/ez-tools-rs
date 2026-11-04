//! The checks of AppCompatCacheParserTest: SampleTests and HiveTests over upstream's samples (needs ACC_TEST_FILES, the
//! upstream AppCompatCacheParserTest/TestFiles folder), and FormatTests over values built here.

use std::io::Read;
use std::path::{Path, PathBuf};

use appcompatcache_ez::{AppCompatCache, CacheEntry, ErrorKind, Execute, OperatingSystemVersion as Os, find_logs};

fn quiet(_: ez_common::Level, _: &str) {}

fn read(raw: &[u8], is32: bool) -> AppCompatCache {
    AppCompatCache::from_bytes(raw, 1, is32, &mut quiet).unwrap()
}

fn sample(name: &str) -> Option<Vec<u8>> {
    Some(std::fs::read(PathBuf::from(std::env::var_os("ACC_TEST_FILES")?).join(name)).unwrap())
}

fn check(e: &CacheEntry, path_size: i32, executed: Execute, path: &str) {
    assert_eq!(e.path_size, path_size, "{}", e.path);
    assert_eq!(e.executed, executed, "{}", e.path);
    assert!(e.path.contains(path), "{}", e.path);
}

#[test]
fn counts() {
    for (name, is32, os, count) in [
        ("WinXPx86.bin", true, Os::WindowsXP, 17),
        ("Win2k8Standard.bin", false, Os::WindowsVistaWin2k3Win2k8, 873),
        ("win7x86.bin", true, Os::Windows7x86, 91),
        ("win7x64.bin", false, Os::Windows7x64_Windows2008R2, 304),
        ("Win80.bin", false, Os::Windows80_Windows2012, 104),
        ("Win81.bin", false, Os::Windows81_Windows2012R2, 1024),
        ("Win10.bin", false, Os::Windows10, 350),
        ("Win10Creators.bin", false, Os::Windows10C_11, 506),
    ] {
        let Some(raw) = sample(name) else { return };
        let acc = read(&raw, is32);
        assert_eq!(acc.operating_system, os, "{name}");
        let cache = &acc.caches[0];
        assert_eq!(cache.entries.len(), count, "{name}");
        assert!(cache.parse_errors.is_empty(), "{name}");
        assert!(cache.entries.iter().enumerate().all(|(i, e)| e.cache_entry_position == i as i32));
        assert!(cache.entries.iter().all(|e| e.control_set == 1 && !e.path.starts_with("\\??\\")));
    }
}

#[test]
fn samples_by_format() {
    let Some(raw) = sample("Win2k8Standard.bin") else { return };
    let acc = read(&raw, false);
    let e = &acc.caches[0].entries;
    assert_eq!(acc.caches[0].entry_count, 873);
    check(&e[0], 164, Execute::Yes, "raw_agent_svc.exe");
    check(&e[5], 62, Execute::No, "SCW.exe");
    check(&e[349], 136, Execute::Yes, "MSExchangeFDS.exe");

    let x64 = read(&sample("win7x64.bin").unwrap(), false);
    check(&x64.caches[0].entries[7], 126, Execute::No, "chrome.exe");
    let x86 = read(&sample("win7x86.bin").unwrap(), true);
    check(&x86.caches[0].entries[8], 108, Execute::No, "wmplayer.exe");

    let w80 = read(&sample("Win80.bin").unwrap(), false);
    assert_eq!(w80.caches[0].entry_count, -1);
    check(&w80.caches[0].entries[2], 144, Execute::Yes, "EditPadLite7.exe");
    let w81 = read(&sample("Win81.bin").unwrap(), false);
    check(&w81.caches[0].entries[1011], 98, Execute::Yes, "osTriage2.exe");

    let w10 = read(&sample("Win10.bin").unwrap(), false);
    assert_eq!(w10.caches[0].entries[0].path_size, 54);
    assert!(w10.caches[0].entries[0].path.contains("vds.exe"));
    let creators = read(&sample("Win10Creators.bin").unwrap(), false);
    assert!(creators.caches[0].entries[349].path.contains("SLUI.exe"));

    let xp = read(&sample("WinXPx86.bin").unwrap(), true);
    let entries = &xp.caches[0].entries;
    assert!(entries.iter().all(|e| e.executed == Execute::NA && !e.path.is_empty()));
    assert!(entries.windows(2).all(|w| w[0].last_update_time_utc >= w[1].last_update_time_utc), "LRU order: most recently updated first");
}

fn museum(logs: bool, target: &Path) -> Option<String> {
    let source = PathBuf::from(std::env::var_os("ACC_TEST_FILES")?).join("DFIRArtifactMuseum/Win11/RathbunVM");
    let files: &[&str] = if logs { &["SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2"] } else { &["SYSTEM"] };
    for file in files {
        let gz = std::fs::read(source.join(format!("{file}.gz"))).unwrap();
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(gz.as_slice()).read_to_end(&mut bytes).unwrap();
        std::fs::write(target.join(file), bytes).unwrap();
    }
    Some(target.join("SYSTEM").to_string_lossy().into_owned())
}

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(name: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("appcompatcache-ez-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Folder(dir)
}

#[test]
fn dirty_hive_with_logs() {
    let dir = folder("logs");
    let Some(hive) = museum(true, &dir.0) else { return };
    let acc = AppCompatCache::open(&hive, -1, false, &mut quiet).unwrap();
    assert_eq!(acc.operating_system, Os::Windows10C_11);
    assert_eq!(acc.caches.len(), 1);
    let cache = &acc.caches[0];
    assert_eq!(cache.control_set, 1);
    assert_eq!(cache.entries.len(), 359);
    assert_eq!(cache.entries.iter().filter(|e| e.executed == Execute::Yes).count(), 30);
    // packaged apps: a tab separated "path" and no time
    assert_eq!(cache.entries.iter().filter(|e| e.path.contains('\t')).count(), 151);
    assert!(cache.entries.iter().filter(|e| e.path.contains('\t')).all(|e| e.last_modified_time_utc.is_none()));
    assert_eq!(cache.entries[0].path, r"C:\Windows\SoftwareDistribution\Download\Install\AM_Delta_Patch_1.357.209.0.exe");
    assert_eq!(cache.entries[0].last_modified_time_utc.unwrap().format("yyyy-MM-dd HH:mm:ss.fffffff"), "2022-02-07 07:37:13.4341508");
    assert_eq!(cache.entries[1].path, r"C:\Windows\System32\PickerHost.exe");
    assert!(cache.slack_entries.is_empty(), "older copies of entries still in the cache");
}

#[test]
fn dirty_hive_without_logs() {
    let dir = folder("nologs");
    let Some(hive) = museum(false, &dir.0) else { return };
    let error = AppCompatCache::open(&hive, -1, false, &mut quiet).err().unwrap();
    assert!(error.message.starts_with("Sequence numbers do not match"));
    assert_eq!(error.kind, ErrorKind::CouldNotProcess);
    assert_eq!(AppCompatCache::open(&hive, -1, true, &mut quiet).unwrap().caches[0].entries.len(), 359);
}

#[test]
fn control_set_that_is_not_there() {
    let dir = folder("set");
    let Some(hive) = museum(true, &dir.0) else { return };
    let error = AppCompatCache::open(&hive, 5, false, &mut quiet).err().unwrap();
    assert_eq!(error.message, "Could not find ControlSet005");
    assert_eq!(error.kind, ErrorKind::CouldNotProcess);
}

#[test]
fn log_files_in_any_case_and_not_empty() {
    let dir = folder("names");
    for (name, text) in [("SYSTEM.LOG1", "x"), ("system.log2", "x"), ("SYSTEM.LOG", ""), ("SYSTEM.LOG3", "x")] {
        std::fs::write(dir.0.join(name), text).unwrap();
    }
    let logs: Vec<String> = find_logs(&dir.0.to_string_lossy(), "SYSTEM").iter().map(|p| p.rsplit('/').next().unwrap().to_string()).collect();
    assert_eq!(logs, ["SYSTEM.LOG1", "system.log2"]);
}

// Values built here, as CacheBuilder does

const TIME: i64 = 133594565890000000;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn tags(list: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in list {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

fn win10_entry(path: &str, data: &[u8]) -> Vec<u8> {
    let p = utf16(path);
    let mut body = Vec::new();
    body.extend_from_slice(&(p.len() as u16).to_le_bytes());
    body.extend_from_slice(&p);
    body.extend_from_slice(&TIME.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(data);
    let mut e = b"10ts\0\0\0\0".to_vec();
    e.extend_from_slice(&(body.len() as u32).to_le_bytes());
    e.extend_from_slice(&body);
    e
}

fn win10(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0u8; 0x34];
    v[0] = 0x34;
    v[0x28] = entries.len() as u8;
    for e in entries {
        v.extend_from_slice(e);
    }
    v
}

#[test]
fn windows_10_executed_is_tag_0x100() {
    let raw = win10(&[
        win10_entry(r"C:\a.exe", &tags(&[(0x100, &[1, 0, 0, 0])])),
        win10_entry(r"C:\b.exe", &tags(&[(0x100, &[1, 0, 0, 0]), (0x800, &[0x64, 0x86, 0, 0])])),
        win10_entry(r"C:\c.exe", &tags(&[(0x800, &[0x64, 0x86, 0, 0])])),
        // the old rule: the last 4 bytes are 1
        win10_entry(r"C:\d.exe", &tags(&[(0x800, &[1, 0, 0, 0])])),
        win10_entry(r"\??\C:\e.exe", &[]),
    ]);
    let acc = read(&raw, false);
    let e = &acc.caches[0].entries;
    assert_eq!(e.iter().map(|x| x.executed).collect::<Vec<_>>(), [Execute::Yes, Execute::Yes, Execute::No, Execute::No, Execute::No]);
    assert_eq!(e[4].path, r"C:\e.exe");
    assert_eq!(e[0].last_modified_time_utc.unwrap().format("yyyy-MM-dd HH:mm:ss"), "2024-05-06 08:09:49");
}

#[test]
fn truncated_windows_10_value_keeps_the_entries_before() {
    let mut raw = win10(&[win10_entry(r"C:\a.exe", &[]), win10_entry(r"C:\b.exe", &[])]);
    raw.truncate(raw.len() - 3);
    let acc = read(&raw, false);
    let cache = &acc.caches[0];
    assert_eq!(cache.entries.len(), 1);
    assert_eq!(cache.parse_errors.len(), 1);
    assert!(cache.parse_errors[0].starts_with("Entry 1 at offset 0x"), "{}", cache.parse_errors[0]);
    assert!(cache.parse_errors[0].contains("is past the end of the data"), "{}", cache.parse_errors[0]);
}

#[test]
fn windows_xp_entries_are_the_lru_array_in_order() {
    let mut raw = vec![0u8; 400 + 552 * 4];
    raw[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    raw[4] = 96;
    raw[8] = 3;
    for (i, slot) in [2u32, 0, 2].iter().enumerate() {
        raw[16 + i * 4..20 + i * 4].copy_from_slice(&slot.to_le_bytes());
    }
    for (slot, name) in [(0, r"C:\zero.exe"), (2, r"\??\C:\two.exe")] {
        let at = 400 + slot * 552;
        let p = utf16(name);
        raw[at..at + p.len()].copy_from_slice(&p);
    }
    let acc = read(&raw, true);
    let cache = &acc.caches[0];
    assert_eq!(cache.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), [r"C:\two.exe", r"C:\zero.exe"]);
    assert_eq!(cache.parse_errors, ["Entry 2 (slot 2): Slot 2 is in the LRU array more than once"]);
}

#[test]
fn too_small_and_unknown_values_are_errors() {
    for raw in [vec![], vec![1, 2, 3, 4], vec![1, 2, 3, 4, 5, 6, 7]] {
        let error = AppCompatCache::from_bytes(&raw, 1, false, &mut quiet).err().unwrap();
        assert_eq!(error.message, format!("The AppCompatCache value is too small ({} bytes)", raw.len()));
        assert_eq!(error.kind, ErrorKind::Parse);
    }
    let error = AppCompatCache::from_bytes(&[0u8; 200], 1, false, &mut quiet).err().unwrap();
    assert!(error.message.starts_with("Unable to determine operating system! The AppCompatCache value (200 bytes) starts with 00-00-"), "{}", error.message);
}

#[test]
fn damage_never_panics() {
    // a simple generator is enough: every format's header, then bytes changed at fixed steps
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut values = vec![win10(&[win10_entry(r"C:\a.exe", &tags(&[(0x100, &[1, 0, 0, 0])])), win10_entry(r"C:\b.exe", &[])])];
    for signature in [0xDEADBEEFu32, 0xBADC0FFE, 0xBADC0FEE] {
        let mut v = vec![0u8; 3000];
        v[0..4].copy_from_slice(&signature.to_le_bytes());
        v[4] = 5;
        v[8] = 5;
        values.push(v);
    }
    let mut w8 = vec![0u8; 128];
    w8.extend_from_slice(&win10_entry(r"C:\a.exe", &[]));
    w8[128..132].copy_from_slice(b"00ts");
    values.push(w8);
    for value in values {
        for _ in 0..3000 {
            let mut b = value.clone();
            for _ in 0..(next() % 12 + 1) {
                let at = (next() % b.len() as u64) as usize;
                b[at] = next() as u8;
            }
            b.truncate((next() % b.len() as u64) as usize + 1);
            let _ = AppCompatCache::from_bytes(&b, 1, next() % 2 == 0, &mut quiet);
        }
    }
}
