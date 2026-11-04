//! The checks of AmcacheParser.Test: HiveTests over the DFIR Artifact Museum samples (needs AMCACHE_TEST_FILES, the
//! upstream AmcacheParser.Test/TestFiles/DFIRArtifactMuseum folder), and DatabaseTests over databases made here.

use std::io::Read;
use std::path::{Path, PathBuf};

use amcache_ez::{AmcacheNew, AmcacheOld, Value, has_databases, is_new_format, log_files};
use ez_common::Timestamp;
use rusqlite::Connection;

const FILE_TIME: i64 = 134298448576863666;

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(name: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("amcache-ez-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Folder(dir)
}

/// A museum hive, decompressed, or None without the samples
fn museum(name: &str, logs: bool, target: &Path) -> Option<String> {
    let source = PathBuf::from(std::env::var_os("AMCACHE_TEST_FILES")?).join(name);
    let files: &[&str] = if logs { &["Amcache.hve", "Amcache.hve.LOG1", "Amcache.hve.LOG2"] } else { &["Amcache.hve"] };
    for file in files {
        let gz = std::fs::read(source.join(format!("{file}.gz"))).unwrap();
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(gz.as_slice()).read_to_end(&mut bytes).unwrap();
        std::fs::write(target.join(file), bytes).unwrap();
    }
    Some(target.join("Amcache.hve").to_string_lossy().into_owned())
}

fn quiet(_: ez_common::Level, _: &str) {}

#[test]
fn new_format_with_logs() {
    let dir = folder("new");
    let Some(hive) = museum("Win10/APTSimulatorVM", true, &dir.0) else { return };
    assert!(is_new_format(&hive, false, &mut quiet));
    let am = AmcacheNew::open(&hive, false, &mut quiet).unwrap();
    assert_eq!(am.programs_entries.len(), 90);
    assert_eq!(am.total_file_entries, 124);
    assert_eq!(am.unassociated_file_entries.len(), 20);
    assert_eq!(am.programs_entries.iter().map(|p| p.file_entries.len()).sum::<usize>(), 104);
    assert_eq!(am.device_containers.len(), 12);
    assert_eq!(am.device_pnps.len(), 189);
    assert!(!am.has_old_format_entries);
    assert!(am.other_tables.is_empty());

    // added by the logs
    let file = am.unassociated_file_entries.iter().find(|f| f.full_path.ends_with("onedrivestandaloneupdater.exe")).unwrap();
    assert_eq!(file.sha1, "57b7fc9bf59cf09a9c19ad0ce0a159746554d682");
    assert_eq!(file.size, 3060072);
    assert_eq!(file.key_name, "onedrivestandalo|70daea7f83b4ffcb");
    assert_eq!(file.file_key_last_write.format("yyyy-MM-dd HH:mm:ss.fffffff"), "2022-03-10 19:46:36.2565599");

    let program = am.programs_entries.iter().find(|p| p.program_id == "0000041ce3ebb98d8d6fe2ef3dfc806b03f300000904").unwrap();
    assert_eq!(program.name, "Microsoft.WindowsCamera");
    assert_eq!(program.key_name, program.program_id);
}

#[test]
fn dirty_without_logs() {
    let dir = folder("dirty");
    let Some(hive) = museum("Win10/APTSimulatorVM", false, &dir.0) else { return };
    let error = AmcacheNew::open(&hive, false, &mut quiet).err().unwrap();
    assert!(error.message.starts_with("Sequence numbers do not match"));
    assert!(error.could_not_process);
    assert!(!AmcacheNew::open(&hive, true, &mut quiet).unwrap().programs_entries.is_empty());
}

#[test]
fn old_format() {
    let dir = folder("old");
    let Some(hive) = museum("Win2012R2/StolenSzechuan", true, &dir.0) else { return };
    assert!(!is_new_format(&hive, false, &mut quiet));
    let am = AmcacheOld::open(&hive, false, &mut quiet).unwrap();
    assert_eq!(am.total_file_entries, 136);
    assert_eq!(am.programs_entries.len(), 3);
    assert_eq!(am.unassociated_file_entries.len(), 2);
    assert!(am.unassociated_file_entries.iter().any(|f| f.full_path == r"C:\Program Files\Common Files\VMware\Drivers\vss\comreg.exe"));
}

#[test]
fn log_files_any_case_and_not_empty() {
    let dir = folder("logs");
    for (name, text) in [("Amcache.hve.LOG1", "x"), ("amcache.hve.log2", "x"), ("Amcache.hve.LOG", ""), ("Amcache.hve.LOG3", "x")] {
        std::fs::write(dir.0.join(name), text).unwrap();
    }
    let logs: Vec<String> = log_files(&dir.0.to_string_lossy(), "Amcache.hve").iter().map(|p| p.rsplit('/').next().unwrap().to_string()).collect();
    assert_eq!(logs, ["Amcache.hve.LOG1", "amcache.hve.log2"]);
}

fn database(dir: &Path, name: &str, sql: &[&str]) {
    let c = Connection::open(dir.join(format!("{name}.db"))).unwrap();
    for s in sql {
        c.execute_batch(s).unwrap();
    }
}

fn read(dir: &Path) -> AmcacheNew {
    let temp = dir.join("temp");
    std::fs::create_dir_all(&temp).unwrap();
    AmcacheNew::from_databases(&dir.to_string_lossy(), Some(&temp.to_string_lossy()), &mut quiet).unwrap()
}

#[test]
fn rows_are_read_as_keys_and_files_find_their_program() {
    let dir = folder("rows");
    database(
        &dir.0,
        "InventoryApplication",
        &[
            "CREATE TABLE InventoryApplication_0 (ItemKey TEXT, ProgramId TEXT, Name TEXT, Language, InstallDate TEXT, HiddenArp, LastModified)",
            &format!("INSERT INTO InventoryApplication_0 VALUES ('p1','p1','App',1033,'05/19/2025 00:00:00',1,{FILE_TIME})"),
            "CREATE TABLE Metadata_0 (Name TEXT, Value TEXT)",
            "INSERT INTO Metadata_0 VALUES ('lastFullSync','134298448576863666')",
        ],
    );
    database(
        &dir.0,
        "InventoryApplicationFile",
        &[
            "CREATE TABLE InventoryApplicationFile_0 (ItemKey TEXT, ProgramId TEXT, FileId TEXT, LowerCaseLongPath TEXT, Size, LinkDate TEXT, LastModified)",
            &format!("INSERT INTO InventoryApplicationFile_0 VALUES ('a','p1','0000ABCD1234','c:\\x.d\\a.exe',10,'53/16/2024',{FILE_TIME})"),
            &format!("INSERT INTO InventoryApplicationFile_0 VALUES ('b','','0000EF','c:\\x.d\\noext',20,'',{FILE_TIME})"),
        ],
    );
    assert!(has_databases(&dir.0.to_string_lossy()));
    let am = read(&dir.0);
    let p = &am.programs_entries[0];
    assert_eq!(p.name, "App");
    assert_eq!(p.language, 1033);
    assert!(p.hidden_arp);
    assert_eq!(p.install_date.unwrap().format("yyyy-MM-dd"), "2025-05-19");
    assert_eq!(p.key_last_write.format("yyyy-MM-dd HH:mm:ss.fffffff"), "2026-07-30 00:27:37.6863666");
    assert_eq!(am.total_file_entries, 2);

    let linked = &p.file_entries[0];
    assert_eq!(linked.application_name, "App");
    assert_eq!(linked.sha1, "abcd1234");
    assert_eq!(linked.file_extension, ".exe");
    // a date LinkDate can't read is the minimum, unlike every other date
    assert_eq!(linked.link_date, Some(Timestamp::MIN));

    let alone = &am.unassociated_file_entries[0];
    assert_eq!(alone.application_name, "Unassociated");
    // only `\` and `/` end the search for the extension, as on Windows
    assert_eq!(alone.file_extension, "");

    let metadata = am.other_tables.iter().find(|t| t.name == "Metadata").unwrap();
    assert_eq!(metadata.rows[0][0], Value::Text("InventoryApplication.db".into()));
}

#[test]
fn signed_driver_time_stamp_is_the_unsigned_dword() {
    let dir = folder("driver");
    database(
        &dir.0,
        "InventoryDriverBinary",
        &["CREATE TABLE InventoryDriverBinary_2 (ItemKey TEXT, DriverId TEXT, DriverTimeStamp, LastModified)", "INSERT INTO InventoryDriverBinary_2 VALUES ('k','0000abcd',-5,0)"],
    );
    let am = read(&dir.0);
    let d = &am.drive_binaries[0];
    assert_eq!(d.driver_id, "abcd");
    assert_eq!(d.driver_time_stamp.unwrap().format("yyyy-MM-dd HH:mm:ss"), "2106-02-07 06:28:11");
}

#[test]
fn newest_copy_of_a_row_is_used() {
    let dir = folder("newest");
    database(
        &dir.0,
        "Other",
        &["CREATE TABLE Other (ItemKey TEXT, X, LastModified)", "INSERT INTO Other VALUES ('o',1,10),('o',2,30),('o',3,20)"],
    );
    let am = read(&dir.0);
    let t = &am.other_tables[0];
    assert_eq!(t.older_copies, 2);
    assert_eq!(t.rows.len(), 1);
    assert_eq!(t.rows[0][1], Value::Integer(2));
}

#[test]
fn bad_date_is_empty_and_counted() {
    let dir = folder("dates");
    database(
        &dir.0,
        "InventoryApplication",
        &[
            "CREATE TABLE InventoryApplication_0 (ItemKey TEXT, ProgramId TEXT, InstallDate TEXT, LastModified)",
            "INSERT INTO InventoryApplication_0 VALUES ('p','p','53/16/2024',0)",
        ],
    );
    let am = read(&dir.0);
    assert_eq!(am.invalid_dates, 1);
    assert_eq!(am.programs_entries[0].install_date, None);
}

#[test]
fn database_names_match_in_any_case() {
    let dir = folder("case");
    database(&dir.0, "INVENTORYAPPLICATION", &["CREATE TABLE InventoryApplication_0 (ItemKey TEXT, ProgramId TEXT, LastModified)", "INSERT INTO InventoryApplication_0 VALUES ('p','p',0)"]);
    assert!(has_databases(&dir.0.to_string_lossy()));
    let am = read(&dir.0);
    assert_eq!(am.programs_entries.len(), 1);
    assert!(am.other_tables.is_empty());
}

#[test]
fn not_a_database_is_listed_and_the_rest_read() {
    let dir = folder("garbage");
    std::fs::write(dir.0.join("Garbage.db"), b"this is not a database, not at all, really".repeat(50)).unwrap();
    std::fs::write(dir.0.join("Empty.db"), b"").unwrap();
    database(&dir.0, "InventoryApplication", &["CREATE TABLE InventoryApplication_0 (ItemKey TEXT, ProgramId TEXT, LastModified)", "INSERT INTO InventoryApplication_0 VALUES ('p','p',0)"]);
    let am = read(&dir.0);
    assert_eq!(am.databases_not_read, 1);
    assert_eq!(am.databases_not_accessed, 0);
    assert_eq!(am.programs_entries.len(), 1);
}

#[test]
fn nothing_is_written_next_to_the_evidence() {
    let dir = folder("evidence");
    let c = Connection::open(dir.0.join("InventoryApplication.db")).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE InventoryApplication_0 (ItemKey TEXT, ProgramId TEXT, LastModified); INSERT INTO InventoryApplication_0 VALUES ('p','p',0);").unwrap();
    // left open: the rows are only in the -wal
    let names = |d: &Path| {
        let mut v: Vec<_> = std::fs::read_dir(d).unwrap().flatten().map(|e| e.file_name()).collect();
        v.sort();
        v
    };
    let db = std::fs::read(dir.0.join("InventoryApplication.db")).unwrap();
    let wal = std::fs::read(dir.0.join("InventoryApplication.db-wal")).unwrap();

    let source = folder("evidence-copy");
    std::fs::write(source.0.join("InventoryApplication.db"), &db).unwrap();
    std::fs::write(source.0.join("InventoryApplication.db-wal"), &wal).unwrap();
    let before = names(&source.0);
    let temp = folder("evidence-temp");
    let am = AmcacheNew::from_databases(&source.0.to_string_lossy(), Some(&temp.0.to_string_lossy()), &mut quiet).unwrap();
    drop(c);

    assert_eq!(am.programs_entries.len(), 1);
    assert_eq!(names(&source.0), before);
    assert_eq!(std::fs::read(source.0.join("InventoryApplication.db")).unwrap(), db);
    assert_eq!(std::fs::read(source.0.join("InventoryApplication.db-wal")).unwrap(), wal);
    assert!(names(&temp.0).is_empty(), "the copies are deleted");
}

#[test]
fn dates_as_dotnet_parses_them() {
    use amcache_ez::parse::date_time;
    let shown = |s: &str| date_time(s).map(|t| t.format("yyyy-MM-dd HH:mm:ss.fffffff"));
    for (value, expected) in [
        ("05/19/2025 00:00:00", Some("2025-05-19 00:00:00.0000000")),
        ("1/2/2003", Some("2003-01-02 00:00:00.0000000")),
        ("2003-01-02", Some("2003-01-02 00:00:00.0000000")),
        ("1.2.2003", Some("2003-01-02 00:00:00.0000000")),
        ("1 2 2003", Some("2003-01-02 00:00:00.0000000")),
        ("02/01/49", Some("2049-02-01 00:00:00.0000000")),
        ("02/01/50", Some("1950-02-01 00:00:00.0000000")),
        ("01/02/2003 1:02:03 PM", Some("2003-01-02 13:02:03.0000000")),
        ("01/02/2003 12:00:00 AM", Some("2003-01-02 00:00:00.0000000")),
        ("1/2/2003 13:00 PM", Some("2003-01-02 13:00:00.0000000")),
        ("1/2/2003 0:00 AM", Some("2003-01-02 00:00:00.0000000")),
        ("January 2, 2003", Some("2003-01-02 00:00:00.0000000")),
        ("2 January 2003", Some("2003-01-02 00:00:00.0000000")),
        ("2003-01-02 03:04:05.1234567", Some("2003-01-02 03:04:05.1234567")),
        ("2003-01-02T03:04:05+02:00", Some("2003-01-02 01:04:05.0000000")),
        ("Tue, 03 Jun 2025 10:00:00 GMT", Some("2025-06-03 10:00:00.0000000")),
        ("53/16/2024", None),
        ("2/30/2020", None),
        ("1/2/2003 24:00", None),
        ("1/2/2003 1:02 a", None),
        ("1/2/2003T1:02", None),
        ("05/19/2025 00:00:00 05/20/2025 00:00:00", None),
        ("20030102", None),
    ] {
        assert_eq!(shown(value).as_deref(), expected, "{value}");
    }
}

#[test]
fn numbers_as_dotnet_parses_them() {
    use amcache_ez::parse::{convert_to_int32_hex, int, int_hex, ulong};
    assert_eq!(int(" +12 "), Ok(12));
    assert_eq!(int("-1"), Ok(-1));
    assert_eq!(int("x").unwrap_err(), "The input string 'x' was not in a correct format.");
    assert_eq!(int("").unwrap_err(), "The input string '' was not in a correct format.");
    assert_eq!(int("9999999999").unwrap_err(), "Value was either too large or too small for an Int32.");
    assert_eq!(ulong("-1").unwrap_err(), "Value was either too large or too small for a UInt64.");
    assert_eq!(int_hex("ffffffff"), Ok(-1));
    assert_eq!(int_hex("100"), Ok(256));
    assert_eq!(int_hex("(default)").unwrap_err(), "The input string '(default)' was not in a correct format.");
    assert_eq!(convert_to_int32_hex("1f"), Ok(31));
    assert_eq!(convert_to_int32_hex("zz").unwrap_err(), "Could not find any recognizable digits.");
}
