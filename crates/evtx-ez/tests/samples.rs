//! The omerbenamram/evtx samples: record counts as that parser (and EvtxECmd) finds them, and values.

use std::io::Read;
use std::path::PathBuf;

use evtx_ez::{EventRecord, EvtxFile, ParseOptions};

pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rust-evtx").join(format!("{name}.gz"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap()).read_to_end(&mut out).unwrap();
    out
}

fn records(name: &str) -> (Vec<EventRecord>, Vec<(i64, String)>) {
    let file = EvtxFile::from_bytes(fixture(name)).unwrap();
    let mut records = Vec::new();
    let mut errors = Vec::new();
    for chunk in file.par_chunks(ParseOptions::default()) {
        let chunk = chunk.unwrap();
        records.extend(chunk.records);
        errors.extend(chunk.errors);
    }
    (records, errors)
}

#[test]
fn record_counts() {
    let cases = [
        ("security.evtx", 2261),
        ("system.evtx", 1881),
        ("sysmon.evtx", 358),
        ("new-user-security.evtx", 4),
        ("issue_201.evtx", 1),
        ("Archive-ForwardedEvents-test.evtx", 653),
        ("MSExchange_Management_wec.evtx", 1),
        ("sample_with_a_bad_chunk_magic.evtx", 270),
        ("security_bad_string_cache.evtx", 2261),
        ("sample-with-zero-data-size-event.evtx", 335),
        ("sample-with-irregular-bool-values.evtx", 3028),
        ("Security_with_size_t.evtx", 636),
        ("Application_no_crc32.evtx", 17),
        ("2-system-Security-dirty.evtx", 14621),
    ];
    for (name, expected) in cases {
        let (records, _) = records(name);
        assert_eq!(records.len(), expected, "{name}");
        for r in &records {
            assert!(r.event_id >= 0, "{name}");
            assert!(r.to_xml().starts_with("<Event>"), "{name} record {}", r.record_number);
        }
    }
}

#[test]
fn forwarded_events() {
    // EvtxECmd issue #15: none of these records could be read (they have no templates and typed inline values)
    let (records, errors) = records("Archive-ForwardedEvents-test.evtx");
    assert!(errors.is_empty(), "{errors:?}");
    let first = &records[0];
    assert_eq!(first.record_number, 127638931);
    assert_eq!(first.event_record_id.as_deref(), Some("1447406953"));
    assert_eq!(first.event_id, 4625);
    assert_eq!(first.provider.as_deref(), Some("Microsoft-Windows-Security-Auditing"));
    assert_eq!(first.channel.as_deref(), Some("Security"));
    assert_eq!(first.computer.as_deref(), Some("slad1.saclink.csus.edu"));
    assert_eq!(first.level.as_deref(), Some("LogAlways"));
    assert_eq!(first.keywords.as_deref(), Some("Audit failure"));
    assert_eq!(first.process_id, 512);
    assert_eq!(first.thread_id, 12960);
    assert_eq!(first.time_created.to_string(), "2019-11-08 23:20:54.6705004");
    assert!(first.rendering_info.as_deref().unwrap().starts_with(
        "{\"Level\":\"Information\",\"Opcode\":\"Info\",\"Task\":\"Logon\",\"Channel\":\"Security\",\"Provider\":\"Microsoft Windows security auditing.\",\"Keywords\":\"Audit Failure\",\"Message\":\"An account failed to log on."
    ));
    assert!(first.payload_json().starts_with("{\"EventData\":{\"Data\":[{\"@Name\":\"SubjectUserSid\",\"#text\":\"S-1-0-0\"}"));
    assert!(records.iter().all(|r| r.rendering_info.is_some()));
}

#[test]
fn size_t_values_are_hex() {
    let (records, _) = records("Security_with_size_t.evtx");
    let xml: String = records.iter().map(|r| r.to_xml()).collect();
    // size_t used to be the raw bytes (00-10-00-...)
    assert!(xml.contains(">0x"));
    let raw = xml.split('>').any(|s| {
        let s = s.split('<').next().unwrap();
        s.len() == 23 && s.split('-').count() == 8 && s.split('-').all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    });
    assert!(!raw);
}

#[test]
fn checksums() {
    let bytes = fixture("security.evtx");
    let file = EvtxFile::from_bytes(bytes).unwrap();
    assert_eq!(file.header().crc, file.header().calculated_crc);
    let chunk = file.chunk_data().next().unwrap().parse(ParseOptions::default()).unwrap();
    assert_eq!(chunk.crc, chunk.calculated_crc);
    assert_eq!(chunk.data_crc, chunk.calculated_data_crc);
}

#[test]
fn not_an_event_log() {
    let err = EvtxFile::from_bytes(b"not an event log at all".to_vec()).err().unwrap();
    assert_eq!(err.to_string(), "Invalid signature! Expected 'ElfFile'");
}
