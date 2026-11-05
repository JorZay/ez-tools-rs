//! Plugins over small hives built here. What they check was first seen in the original's output.

use registry_ez::{Hive, KeyId};
use registry_plugins::{Cell, Output, PLUGINS};

enum Data {
    Text(&'static str),
    Dword(u32),
    Binary(Vec<u8>),
}

struct Node {
    name: &'static str,
    values: Vec<(&'static str, Data)>,
    subkeys: Vec<Node>,
}

fn node(name: &'static str, values: Vec<(&'static str, Data)>, subkeys: Vec<Node>) -> Node {
    Node { name, values, subkeys }
}

/// A minimal regf hive
struct Builder {
    cells: Vec<u8>,
}

impl Builder {
    const HBIN_HEADER: usize = 32;

    fn cell(&mut self, data: &[u8]) -> u32 {
        let size = (4 + data.len()).next_multiple_of(8);
        let at = self.cells.len() + Self::HBIN_HEADER;
        self.cells.extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.cells.extend_from_slice(data);
        self.cells.resize(at - Self::HBIN_HEADER + size, 0);
        at as u32
    }

    fn value(&mut self, name: &str, data: &Data) -> u32 {
        let (kind, bytes): (u32, Vec<u8>) = match data {
            Data::Text(t) => (1, t.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()),
            Data::Dword(d) => (4, d.to_le_bytes().to_vec()),
            Data::Binary(b) => (3, b.clone()),
        };
        let (length, offset) = if bytes.len() <= 4 && !bytes.is_empty() {
            let mut inline = [0u8; 4];
            inline[..bytes.len()].copy_from_slice(&bytes);
            (bytes.len() as u32 | 0x8000_0000, u32::from_le_bytes(inline))
        } else if bytes.is_empty() {
            (0, u32::MAX)
        } else {
            (bytes.len() as u32, self.cell(&bytes))
        };
        let mut vk = b"vk".to_vec();
        vk.extend_from_slice(&(name.len() as u16).to_le_bytes());
        vk.extend_from_slice(&length.to_le_bytes());
        vk.extend_from_slice(&offset.to_le_bytes());
        vk.extend_from_slice(&kind.to_le_bytes());
        vk.extend_from_slice(&1u16.to_le_bytes());
        vk.extend_from_slice(&0u16.to_le_bytes());
        vk.extend_from_slice(name.as_bytes());
        self.cell(&vk)
    }

    fn key(&mut self, n: &Node, root: bool) -> u32 {
        let subs: Vec<u32> = n.subkeys.iter().map(|s| self.key(s, false)).collect();
        let values: Vec<u32> = n.values.iter().map(|(name, data)| self.value(name, data)).collect();
        let mut list_offset = u32::MAX;
        if !subs.is_empty() {
            let mut lf = b"lf".to_vec();
            lf.extend_from_slice(&(subs.len() as u16).to_le_bytes());
            for s in &subs {
                lf.extend_from_slice(&s.to_le_bytes());
                lf.extend_from_slice(&[0; 4]);
            }
            list_offset = self.cell(&lf);
        }
        let mut values_offset = u32::MAX;
        if !values.is_empty() {
            let list: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
            values_offset = self.cell(&list);
        }
        let mut nk = b"nk".to_vec();
        nk.extend_from_slice(&(0x20u16 | if root { 0x0C } else { 0 }).to_le_bytes());
        nk.extend_from_slice(&132_900_000_000_000_000u64.to_le_bytes());
        nk.extend_from_slice(&[0; 4]);
        for field in [0, subs.len() as u32, 0, list_offset, u32::MAX, values.len() as u32, values_offset, u32::MAX, u32::MAX, 0, 0, 0, 0, 0] {
            nk.extend_from_slice(&field.to_le_bytes());
        }
        nk.extend_from_slice(&(n.name.len() as u16).to_le_bytes());
        nk.extend_from_slice(&0u16.to_le_bytes());
        nk.extend_from_slice(n.name.as_bytes());
        let at = self.cell(&nk);
        for s in subs {
            let parent = s as usize - Self::HBIN_HEADER + 4 + 16;
            self.cells[parent..parent + 4].copy_from_slice(&at.to_le_bytes());
        }
        at
    }
}

fn hive(file_name: &str, tree: Node) -> Hive {
    let mut b = Builder { cells: vec![] };
    let root = b.key(&tree, true);
    let end = b.cells.len() + Builder::HBIN_HEADER;
    let mut size = end.next_multiple_of(4096);
    if size - end < 8 && size != end {
        size += 4096;
    }
    let mut body = b"hbin".to_vec();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(size as u32).to_le_bytes());
    body.resize(Builder::HBIN_HEADER, 0);
    body.extend_from_slice(&b.cells);
    if size != end {
        body.extend_from_slice(&((size - end) as i32).to_le_bytes());
        body.resize(size, 0);
    }
    let mut header = vec![0u8; 4096];
    header[..4].copy_from_slice(b"regf");
    for (at, v) in [(4, 1u32), (8, 1), (20, 1), (24, 3), (28, 0), (32, 1), (36, root), (40, size as u32), (44, 1)] {
        header[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    let name: Vec<u8> = file_name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    header[48..48 + name.len()].copy_from_slice(&name);
    let checksum = header[..508].chunks_exact(4).fold(0u32, |c, w| c ^ u32::from_le_bytes(w.try_into().unwrap()));
    header[508..512].copy_from_slice(&checksum.to_le_bytes());
    header.extend_from_slice(&body);
    let mut hive = Hive::new(header, file_name).unwrap();
    hive.parse().unwrap();
    hive
}

fn run(type_name: &str, hive: &Hive, key: KeyId) -> (Result<(), String>, Output) {
    let plugin = PLUGINS.iter().find(|p| p.type_name == type_name).unwrap();
    let mut out = Output::default();
    let result = (plugin.process)(hive, key, &mut out);
    (result, out)
}

fn text(out: &Output, row: usize, column: &str) -> Option<String> {
    match out.rows[row].columns.iter().find(|(name, _)| *name == column) {
        Some((_, Cell::Text(v))) => v.clone(),
        other => panic!("{column}: {other:?}"),
    }
}

const FILETIME: u64 = 132_900_000_000_000_000;

#[test]
fn table_has_the_40_plugins_once_each() {
    let mut names: Vec<_> = PLUGINS.iter().map(|p| p.type_name).collect();
    assert_eq!(names.len(), 40);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 40);
}

#[test]
fn bam_skips_its_counters_and_reports_a_short_value() {
    let tree = node(
        "ROOT",
        vec![
            (r"\Device\a.exe", Data::Binary(FILETIME.to_le_bytes().to_vec())),
            ("Version", Data::Dword(1)),
            ("SequenceNumber", Data::Dword(1)),
            ("short", Data::Binary(vec![1, 2])),
        ],
        vec![],
    );
    let h = hive("SYSTEM", tree);
    let (result, out) = run("BamDam", &h, h.root.unwrap());
    assert!(result.is_ok());
    assert_eq!(out.rows.len(), 1);
    assert_eq!(out.rows[0].batch_value_data1, r"Program: \Device\a.exe");
    assert_eq!(out.rows[0].batch_value_data2.as_deref(), Some("Execution time: 2022-02-22 10:40:00.0000000"));
    assert_eq!(out.rows[0].batch_value_data3, None);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].starts_with("Value name: short, message: "));
}

#[test]
fn csv_has_the_first_column_before_the_key_path() {
    let tree = node("ROOT", vec![(r"\Device\a.exe", Data::Binary(FILETIME.to_le_bytes().to_vec()))], vec![]);
    let h = hive("SYSTEM", tree);
    let (_, out) = run("BamDam", &h, h.root.unwrap());
    assert_eq!(out.rows[0].csv_header(), "Program,BatchKeyPath,ExecutionTime,BatchValueName");
    let mut line = String::new();
    out.rows[0].csv_line(&mut line);
    assert_eq!(line, r"\Device\a.exe,ROOT,2022-02-22 10:40:00.0000000,\Device\a.exe");
    assert_eq!(
        out.rows[0].json_line(),
        r#"{"Program":"\\Device\\a.exe","ExecutionTime":"2022-02-22T10:40:00.0000000Z","BatchKeyPath":"ROOT","BatchValueName":"\\Device\\a.exe"}"#
    );
}

#[test]
fn run_mru_sorts_by_position_and_drops_the_marker() {
    let tree = node(
        "ROOT",
        vec![
            ("MRUList", Data::Text("ba")),
            ("a", Data::Text("cmd\\1")),
            ("b", Data::Text("calc\\1\\1")),
            ("z", Data::Text("not listed")),
        ],
        vec![],
    );
    let h = hive("NTUSER.DAT", tree);
    let (_, out) = run("RunMRU", &h, h.root.unwrap());
    let executables: Vec<_> = (0..3).map(|i| text(&out, i, "Executable").unwrap()).collect();
    assert_eq!(executables, ["not listed", "calc\\1", "cmd"]);
    assert_eq!(out.rows[1].batch_value_data3.as_deref(), Some("MRU: 0"));
    assert_eq!(out.rows[0].batch_value_data3.as_deref(), Some("MRU: -1"));
}

#[test]
fn radar_without_its_subkeys_fails_like_the_original_and_keeps_no_rows() {
    let diagnosed = node("DiagnosedApplications", vec![], vec![node("a.exe", vec![], vec![])]);
    let h = hive("SOFTWARE", node("ROOT", vec![], vec![diagnosed]));
    let (result, out) = run("RADAR", &h, h.root.unwrap());
    assert_eq!(result.unwrap_err(), "Object reference not set to an instance of an object.");
    assert!(out.rows.is_empty());
}

#[test]
fn radar_has_1601_for_a_missing_time() {
    let diagnosed = node("DiagnosedApplications", vec![], vec![node("a.exe", vec![], vec![])]);
    let reflection = node("ReflectionApplications", vec![], vec![node("b.exe", vec![], vec![])]);
    let h = hive("SOFTWARE", node("ROOT", vec![], vec![diagnosed, reflection]));
    let (result, out) = run("RADAR", &h, h.root.unwrap());
    assert!(result.is_ok());
    assert_eq!(out.rows[0].batch_value_data2.as_deref(), Some("LastDetectionTime: 1601-01-01 00:00:00.0000000"));
    assert_eq!(out.rows[1].batch_value_data2.as_deref(), Some("LastDetectionTime: "));
}

#[test]
fn terminal_server_client_messages_are_dotnets() {
    let default = node("Default", vec![("AB", Data::Text("host"))], vec![]);
    let servers = node("Servers", vec![], vec![node("host", vec![], vec![])]);
    let h = hive("NTUSER.DAT", node("ROOT", vec![], vec![default, servers]));
    let (_, out) = run("TerminalServerClient", &h, h.root.unwrap());
    assert!(out.rows.is_empty());
    assert_eq!(
        out.errors,
        ["Error processing Terminal Server Client key: count ('3') must be less than or equal to '2'. (Parameter 'count')\nActual value was 3."]
    );
}

#[test]
fn profile_list_joins_the_halves_without_padding() {
    // 0x1C8 and 0x1 are 0x1C81 as the original joins them, not 0x1C800000001
    let profile = node(
        "S-1-5-18",
        vec![("LocalProfileLoadTimeHigh", Data::Dword(0x1C8)), ("LocalProfileLoadTimeLow", Data::Dword(1))],
        vec![],
    );
    let bad = node("Bad", vec![("LocalProfileLoadTimeHigh", Data::Text("abc")), ("LocalProfileLoadTimeLow", Data::Dword(1))], vec![]);
    let h = hive("SOFTWARE", node("ROOT", vec![], vec![profile, bad]));
    let (_, out) = run("ProfileList", &h, h.root.unwrap());
    assert_eq!(out.rows.len(), 1);
    let logon = out.rows[0].columns.iter().find(|(n, _)| *n == "LastLogonTime").map(|(_, c)| c.clone());
    assert_eq!(logon, Some(Cell::Time(ez_common::Timestamp::from_filetime(0x1C81))));
    assert_eq!(out.errors, ["Error processing ProfileList key: The input string 'abc' was not in a correct format."]);
}

#[test]
fn etw_names_the_provider_by_its_guid() {
    let provider = node("{CAFEEFAC-0015-0000-0007-ABCDEFFEDCBC}", vec![("ENABLED", Data::Dword(1))], vec![]);
    let unknown = node("not a guid", vec![], vec![]);
    let h = hive("SYSTEM", node("ROOT", vec![], vec![provider, unknown]));
    let (_, out) = run("ETW", &h, h.root.unwrap());
    assert_eq!(text(&out, 0, "Provider").as_deref(), Some("Java Plug-in 1.5.0_07"));
    assert_eq!(text(&out, 0, "Enabled").as_deref(), Some("1"));
    assert_eq!(text(&out, 1, "Provider").as_deref(), Some("Unmapped GUID: not a guid"));
    assert_eq!(text(&out, 1, "Enabled").as_deref(), Some(""));
}

// The shell item plugins

fn u(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn sized(body: &[u8]) -> Vec<u8> {
    let mut b = ((body.len() + 2) as u16).to_le_bytes().to_vec();
    b.extend_from_slice(body);
    b
}

/// My Computer
fn root_item() -> Vec<u8> {
    let mut b = vec![0x1f, 0x50];
    b.extend_from_slice(&[0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00, 0x2b, 0x30, 0x30, 0x9d]);
    sized(&b)
}

fn drive_item() -> Vec<u8> {
    let mut b = vec![0x2f];
    b.extend_from_slice(b"C:\\");
    b.resize(23, 0);
    sized(&b)
}

fn mru(list: &[i32]) -> Vec<u8> {
    list.iter().chain(&[-1]).flat_map(|n| n.to_le_bytes()).collect()
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn text_of<'a>(row: &'a registry_plugins::ValuesOut, name: &str) -> &'a str {
    match &row.columns.iter().find(|(n, _)| *n == name).unwrap().1 {
        Cell::Text(Some(t)) => t,
        other => panic!("{name} is {other:?}"),
    }
}

fn int_of(row: &registry_plugins::ValuesOut, name: &str) -> i32 {
    match row.columns.iter().find(|(n, _)| *n == name).unwrap().1 {
        Cell::Int(v) => v,
        ref other => panic!("{name} is {other:?}"),
    }
}

#[test]
fn last_visited_lists_items_in_mru_order_and_keeps_going_after_a_bad_one() {
    let tree = node(
        "LastVisitedPidlMRU",
        vec![
            ("MRUListEx", Data::Binary(mru(&[1, 0]))),
            ("0", Data::Binary(concat(&[&u("second.exe"), &root_item(), &drive_item(), &[0, 0]]))),
            ("1", Data::Binary(concat(&[&u("first.exe"), &root_item()]))),
            ("2", Data::Binary(concat(&[&u("past.exe"), &root_item(), &[0xff, 0xff, 0, 0]]))),
        ],
        vec![],
    );
    let h = hive("NTUSER.DAT", tree);
    let (_, out) = run("LastVisitedPidlMRU", &h, h.root.unwrap());
    let names: Vec<_> = out.rows.iter().map(|r| text_of(r, "Executable")).collect();
    assert_eq!(names, ["past.exe", "first.exe", "second.exe"]);
    assert_eq!(text_of(&out.rows[2], "AbsolutePath"), "This PC\\C:");
    assert_eq!(int_of(&out.rows[1], "MruPosition"), 0);
    assert!(matches!(out.rows[1].columns.iter().find(|(n, _)| *n == "OpenedOn").unwrap().1, Cell::Time(Some(_))));
    assert_eq!(text_of(&out.rows[0], "AbsolutePath"), "This PC");
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].contains("has size 65535, past the end of the value"), "{:?}", out.errors);
    assert!(text_of(&out.rows[0], "Details").contains("has size 65535"));
}

#[test]
fn open_save_has_a_row_per_value_of_each_subkey() {
    let tree = node(
        "OpenSavePidlMRU",
        vec![],
        vec![
            node("*", vec![("MRUListEx", Data::Binary(mru(&[0]))), ("0", Data::Binary(concat(&[&root_item(), &[0, 0]])))], vec![]),
            node("pdf", vec![("0", Data::Binary(concat(&[&sized(&[0xfe, 1, 2]), &root_item()])))], vec![]),
        ],
    );
    let h = hive("NTUSER.DAT", tree);
    let (_, out) = run("OpenSavePidlMRU", &h, h.root.unwrap());
    assert_eq!(out.rows.len(), 2);
    // no MRUListEx: -1, so it comes first
    assert_eq!(text_of(&out.rows[0], "Extension"), "pdf");
    assert_eq!(int_of(&out.rows[0], "MruPosition"), -1);
    assert_eq!(text_of(&out.rows[1], "Extension"), "*");
    assert!(out.errors[0].contains("Unsupported ShellID: 0xfe"), "{:?}", out.errors);
}

#[test]
fn taskband_reads_chunks_and_a_damaged_value_gives_no_rows() {
    let mut favorites = vec![0u8];
    let chunk = concat(&[&root_item(), &[0, 0]]);
    favorites.extend_from_slice(&((chunk.len() + 4) as i32).to_le_bytes());
    favorites.extend_from_slice(&chunk);
    favorites.extend_from_slice(&[0, 0, 0, 0, 0xff]);
    let h = hive("NTUSER.DAT", node("Taskband", vec![("Favorites", Data::Binary(favorites))], vec![]));
    let (_, out) = run("Taskband", &h, h.root.unwrap());
    assert_eq!(out.rows.len(), 1);
    assert_eq!(text_of(&out.rows[0], "LnkName"), "This PC");
    assert_eq!(text_of(&out.rows[0], "Executable"), "(unknown)");

    let h = hive("NTUSER.DAT", node("Taskband", vec![("Favorites", Data::Binary(vec![0, 1]))], vec![]));
    let (_, out) = run("Taskband", &h, h.root.unwrap());
    assert!(out.rows.is_empty());
    assert_eq!(out.errors, ["Error processing Favorites value '': Unable to read beyond the end of the stream."]);
}

#[test]
fn recent_docs_sorts_by_extension_key_and_finds_when_it_was_last_opened() {
    let item = |name: &str| {
        let mut b = vec![36u8];
        b.extend_from_slice(&[0; 11]);
        b.extend_from_slice(&u(name));
        sized(&b)
    };
    let doc = |target: &str, name: &str| Data::Binary(concat(&[&u(target), &item(name), &[0, 0]]));
    let tree = node(
        "RecentDocs",
        vec![("MRUListEx", Data::Binary(mru(&[1, 0]))), ("0", doc("b.pdf", "b.lnk")), ("1", doc("a.txt", "a.lnk")), ("CachePrefix", Data::Text("x")), ("2", Data::Binary(u("noitem.txt")))],
        vec![node(".pdf", vec![("MRUListEx", Data::Binary(mru(&[0]))), ("0", doc("b.pdf", "b.lnk"))], vec![])],
    );
    let h = hive("NTUSER.DAT", tree);
    let (_, out) = run("RecentDocs", &h, h.root.unwrap());
    let rows: Vec<_> = out.rows.iter().map(|r| (text_of(r, "Extension"), text_of(r, "TargetName"), int_of(r, "MruPosition"))).collect();
    assert_eq!(rows, [("RecentDocs", "a.txt", 0), ("RecentDocs", "b.pdf", 1), (".pdf", "b.pdf", 0)]);
    assert_eq!(text_of(&out.rows[1], "LnkName"), "b.lnk");
    assert!(matches!(out.rows[1].columns.iter().find(|(n, _)| *n == "ExtensionLastOpened").unwrap().1, Cell::Time(Some(_))));
    assert!(matches!(out.rows[0].columns.iter().find(|(n, _)| *n == "ExtensionLastOpened").unwrap().1, Cell::Time(None)));
    assert_eq!(out.errors.len(), 1, "the value without an item");
}
