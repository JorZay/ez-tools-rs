//! Links built in memory: what is read, and damage kept while the rest of the file is read.

use lnk_ez::{ExtraBlock, HAS_ARGUMENTS, HAS_NAME, IS_UNICODE, from_bytes};

fn header(flags: i32) -> Vec<u8> {
    let mut b = vec![0u8; 76];
    b[0] = 0x4c;
    b[4..20].copy_from_slice(&[0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
    b[20..24].copy_from_slice(&flags.to_le_bytes());
    b[24..28].copy_from_slice(&0x20i32.to_le_bytes());
    b[28..36].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    b[36..44].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    b[44..52].copy_from_slice(&131_000_000_000_000_000i64.to_le_bytes());
    b[52..56].copy_from_slice(&1234u32.to_le_bytes());
    b[60..64].copy_from_slice(&1i32.to_le_bytes());
    b
}

fn string(text: &str) -> Vec<u8> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let mut b = (units.len() as u16).to_le_bytes().to_vec();
    b.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    b
}

#[test]
fn strings_and_the_terminal_block() {
    let mut raw = header(HAS_NAME | HAS_ARGUMENTS | IS_UNICODE);
    raw.extend(string("my link"));
    raw.extend(string("-a é"));
    raw.extend_from_slice(&[0, 0, 0, 0]);
    let file = from_bytes(&raw, None, 1252).unwrap();
    assert_eq!(file.name.as_deref(), Some("my link"));
    assert_eq!(file.arguments.as_deref(), Some("-a é"));
    assert_eq!(file.header.data_flags_text(), "HasName, HasArguments, IsUnicode");
    assert_eq!(file.header.file_attributes_text(), "FileAttributeArchive");
    assert_eq!(file.header.show_window_text(), "SwNormal");
    assert!(file.parse_errors.is_empty(), "{:?}", file.parse_errors);
}

#[test]
fn damage_is_kept_with_the_rest() {
    // no terminal block
    let file = from_bytes(&header(0), None, 1252).unwrap();
    assert_eq!(file.parse_errors, ["ExtraData has no terminal block"]);
    // data after it
    let mut raw = header(0);
    raw.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3]);
    let file = from_bytes(&raw, None, 1252).unwrap();
    assert_eq!(file.parse_errors, ["3 bytes of data follow the ExtraData terminal block (offset 80)"]);
    // a show command that isn't defined
    let mut raw = header(0);
    raw[60] = 0x0d;
    raw.extend_from_slice(&[0, 0, 0, 0]);
    let file = from_bytes(&raw, None, 1252).unwrap();
    assert_eq!(file.parse_errors, ["ShowCommand 0xD is not a defined SW_* value (treated as SW_SHOWNORMAL)"]);
    // an unknown extra block is damaged, and read as such
    let mut raw = header(0);
    raw.extend_from_slice(&12u32.to_le_bytes());
    raw.extend_from_slice(&0xa0000099u32.to_le_bytes());
    raw.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let file = from_bytes(&raw, None, 1252).unwrap();
    assert!(matches!(file.extra_blocks[0], ExtraBlock::Damaged(_)));
    assert!(file.parse_errors[0].starts_with("Extra data block 2684354713: Unknown extra data block signature: 0xA0000099"), "{:?}", file.parse_errors);
}

#[test]
fn what_stops_a_file() {
    let e = from_bytes(&[0; 10], None, 1252).unwrap_err();
    assert_eq!(e.message, "Error processing file ((raw data)) - the error was (Header is smaller than 76 bytes - is this file corrupt?)");
    let mut raw = header(HAS_NAME);
    raw.extend_from_slice(&[0xff, 0xff]);
    let e = from_bytes(&raw, Some("x.lnk"), 1252).unwrap_err();
    assert!(e.message.contains("Invalid NAME_STRING data (offset 78, length 65535, available 78)"), "{}", e.message);
    assert_eq!((e.offset, e.field.as_deref()), (78, Some("NAME_STRING")));
}

#[test]
fn text_mode_damage_is_recognized() {
    let mut raw = header(HAS_NAME);
    raw.extend_from_slice(&[1, 0, b'\n', 0, 0, 0, 0]);
    let damaged: Vec<u8> = raw.iter().flat_map(|b| if *b == b'\n' { vec![b'\r', b'\n'] } else { vec![*b] }).collect();
    let mut with_error = damaged.clone();
    with_error.push(1);
    let _ = from_bytes(&with_error, None, 1252);
    // nothing panics on any truncation of a link
    for end in 0..raw.len() {
        let _ = from_bytes(&raw[..end], None, 1252);
    }
}
