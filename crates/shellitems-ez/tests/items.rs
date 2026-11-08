//! Shell items and blocks built in memory, with the text the original gives for each.

use shellitems_ez::{BlockKind, create_item};

/// A 0xbeef0004 block, version 9, with a long name
fn beef0004(name: &str) -> Vec<u8> {
    let mut b = vec![0u8; 2];
    b.extend_from_slice(&9u16.to_le_bytes());
    b.extend_from_slice(&0xbeef0004u32.to_le_bytes());
    b.extend_from_slice(&0x4821u16.to_le_bytes()); // created: 2016-01-01
    b.extend_from_slice(&0x0000u16.to_le_bytes());
    b.extend_from_slice(&0x4821u16.to_le_bytes()); // accessed
    b.extend_from_slice(&0x0000u16.to_le_bytes());
    b.extend_from_slice(&0x2eu16.to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&5u32.to_le_bytes()); // entry
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&3u16.to_le_bytes()); // sequence
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&[0; 2]);
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&[0; 4]);
    for u in name.encode_utf16() {
        b.extend_from_slice(&u.to_le_bytes());
    }
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&[0x14, 0]);
    let size = b.len() as u16;
    b[..2].copy_from_slice(&size.to_le_bytes());
    b
}

fn file_item(kind: u8, short: &str, long: &str) -> Vec<u8> {
    let mut b = vec![0u8, 0, kind, 0];
    b.extend_from_slice(&1234u32.to_le_bytes());
    b.extend_from_slice(&0x4821u16.to_le_bytes());
    b.extend_from_slice(&0x6000u16.to_le_bytes());
    b.extend_from_slice(&[0x20, 0]);
    b.extend_from_slice(short.as_bytes());
    b.push(0);
    if b.len() % 2 == 1 {
        b.push(0);
    }
    b.extend_from_slice(&beef0004(long));
    b.extend_from_slice(&[0, 0]);
    let size = b.len() as u16;
    b[..2].copy_from_slice(&size.to_le_bytes());
    b
}

#[test]
fn files_and_folders() {
    let item = create_item(&file_item(0x32, "LONGFI~1.TXT", "long file.txt")).unwrap();
    assert_eq!(item.class, "ShellBag0X32");
    assert_eq!(item.friendly_name, "File");
    assert_eq!(item.value, "long file.txt");
    assert_eq!(item.short_name.as_deref(), Some("LONGFI~1.TXT"));
    let text = item.to_text();
    assert!(text.starts_with("Short name: LONGFI~1.TXT\r\n\r\nFile size: 1,234\r\nModified On: 1/1/2016 12:00:00.000 PM  +00:00\r\n\r\nValue: long file.txt\r\nShell Type: File\r\n\r\n"), "{text}");
    assert!(text.contains("Extension blocks found: 1\r\n---------------------- Block 0 ----------------------\r\nSignature: 0xbeef0004\r\n"), "{text}");
    let BlockKind::Beef0004 { mft, long_name, .. } = &item.extension_blocks[0].kind else { panic!("not a Beef0004") };
    assert_eq!(long_name, "long file.txt");
    assert_eq!(mft.entry_number, Some(5));
    assert_eq!(mft.sequence_number, Some(3));

    let folder = create_item(&file_item(0x31, "FOLDER", "folder name")).unwrap();
    assert_eq!((folder.class, folder.friendly_name.as_str(), folder.value.as_str()), ("ShellBag0X31", "Directory", "folder name"));
    // these read as 0x31, with their own class
    assert_eq!(create_item(&file_item(0xb1, "F", "named")).unwrap().class, "ShellBag0XB1");
    assert_eq!(create_item(&file_item(0x36, "F", "named")).unwrap().friendly_name, "File");
    assert_eq!(create_item(&file_item(0x3a, "F", "named")).unwrap().class, "ShellBag0X3A");
}

#[test]
fn other_kinds() {
    // a GUID root item
    let mut guid = vec![0x14, 0, 0x1f, 0x50];
    guid.extend_from_slice(&[0xe0, 0x4f, 0xd0, 0x20, 0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00, 0x2b, 0x30, 0x30, 0x9d]);
    let item = create_item(&guid).unwrap();
    assert_eq!((item.class, item.friendly_name.as_str(), item.value.as_str()), ("ShellBag0X1F", "Root folder: GUID", "This PC"));
    // a drive letter
    let mut drive = vec![0x19, 0, 0x2f];
    drive.extend_from_slice(b"C:\\");
    drive.resize(0x19, 0);
    let item = create_item(&drive).unwrap();
    assert_eq!((item.friendly_name.as_str(), item.value.as_str()), ("Drive letter", "C:"));
    // no class for this type
    let unknown = create_item(&[5, 0, 0xfe, 1, 2]).unwrap();
    assert_eq!(unknown.class, "ShellBagUnknown");
    assert!(unknown.value.starts_with("**** Unknown type! ShellBag ID: fe, Hex: 05-00-FE-01-02"));
}

#[test]
fn damaged_items_fail_or_are_kept() {
    assert_eq!(create_item(&[1, 0]).unwrap_err(), "A shell item has at least 3 bytes, not 2");
    // a block that can't be read is kept as an error, with the item
    let mut item = file_item(0x32, "A", "b");
    let at = item.windows(4).position(|w| w == [4, 0, 0xef, 0xbe]).unwrap();
    item.truncate(at + 12);
    let size = item.len() as u16;
    item[..2].copy_from_slice(&size.to_le_bytes());
    let read = create_item(&item).unwrap();
    assert_eq!(read.extension_blocks[0].class, "BeefParseError");
    // nothing panics on any truncation
    let whole = file_item(0x31, "SHORT", "a long name");
    for end in 0..whole.len() {
        let _ = create_item(&whole[..end]).map(|i| i.to_text());
    }
}

#[test]
fn an_mtp_folder_cut_short_fails_where_the_original_does() {
    let mut raw = vec![0u8; 60];
    raw[0] = 60;
    raw[6..10].copy_from_slice(&0x07192006u32.to_le_bytes());
    // the size at 0x3a is read, though nothing uses it: it doesn't fit in the 2 bytes left
    assert_eq!(create_item(&raw).unwrap_err(), "The array starting from the specified index is not long enough to read a value of the specified type. (Parameter 'value')");
}

#[test]
fn property_names_are_there() {
    assert_eq!(shellitems_ez::utils::description_from_guid_and_key("46588AE2-4CBC-4338-BBFC-139326986DCE", 4), "SID");
    assert_eq!(shellitems_ez::utils::description_from_guid_and_key("46588ae2-4cbc-4338-bbfc-139326986dce", 99), "(Description not available)");
}

#[test]
fn multistrings_move_on_as_the_original_does() {
    let raw: Vec<u8> = "ab".encode_utf16().flat_map(u16::to_le_bytes).chain([0, 0, b'c', 0, 0, 0, 9, 9]).collect();
    assert_eq!(shellitems_ez::utils::strings_from_multistring(&raw).unwrap()[0], "ab");
    assert_eq!(shellitems_ez::utils::strings_from_multistring(&[0, 0, 0, 0, 0, 0]).unwrap(), [""]);
}

#[test]
fn code_pages_read_as_in_dotnet() {
    use shellitems_ez::utils::{decode_with, provider_decode};
    // one byte per character, which encoding_rs doesn't have
    assert_eq!(provider_decode(37, &[0xc1, 0xc2]).unwrap(), "AB");
    assert_eq!(provider_decode(437, &[0x82]).unwrap(), "é");
    // two: a valid pair, a lead byte alone at the end, and a character where encoding_rs has another
    assert_eq!(provider_decode(932, &[0x82, 0xa0]).unwrap(), "あ");
    assert_eq!(provider_decode(932, &[0x81]).unwrap(), "・");
    assert_eq!(provider_decode(950, &[0x87, 0x40]).unwrap(), "\u{f266}");
    // what the shell items have no encoding for, and Lnk reads: itself, or as 1252
    assert_eq!(provider_decode(65001, b"a"), None);
    assert_eq!(decode_with(65001, "é".as_bytes()), "é");
    assert_eq!(decode_with(99999, &[0xe9]), "é");
    let mut drive = vec![0x19, 0, 0x2f];
    drive.extend_from_slice(b"C:\\");
    drive.resize(0x19, 0);
    assert_eq!(shellitems_ez::create_with_code_page(&drive, 99999).unwrap_err(), "Object reference not set to an instance of an object.");
}
