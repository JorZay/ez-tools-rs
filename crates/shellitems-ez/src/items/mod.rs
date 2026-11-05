//! Shell items: `ShellBag`, `ShellItemFactory` and one constructor per class. A shell item is one struct: what classes share,
//! the few fields LECmd and the others read, and the lines each class's ToString() puts around the shared text.

mod complex;
mod simple;
mod special;

use ez_common::Timestamp;
use ez_common::net::{NetResult, byte_at, hex, i32_at, u32_at};

use crate::blocks::Block;
use crate::sheet::PropertyStore;
use crate::utils::{n0, time_text};

pub use complex::*;
pub use simple::*;
pub use special::*;

/// Utils.Beef0004Signature
pub(crate) const BEEF0004_SIGNATURE: [u8; 4] = [0x04, 0x00, 0xef, 0xbe];

/// Part of the text before what classes share
#[derive(Clone, Debug)]
pub(crate) enum Part {
    Text(String),
    /// A heading line and the store's text, made when the text is asked for
    Store(String, PropertyStore),
}

#[derive(Clone, Debug)]
pub struct ShellItem {
    /// Its class's name, as the original's
    pub class: &'static str,
    pub friendly_name: String,
    pub value: String,
    pub raw: Vec<u8>,
    pub extension_blocks: Vec<Block>,
    pub short_name: Option<String>,
    pub last_modification: Option<Timestamp>,
    pub last_access: Option<Timestamp>,
    pub drive_letter: Option<String>,
    /// PropertyStore: of 0x1F, 0x79, 0x71 and the like
    pub property_store: Option<PropertyStore>,
    /// PropertyStores of 0x00
    pub property_stores: Vec<PropertyStore>,
    /// Of 0x00: the blocks of the items in its Delegate ID List
    pub delegate_extension_blocks: Vec<Block>,
    /// ShellBagDamaged's message
    pub error_message: Option<String>,
    /// Value was left null, which tells some readers it wasn't this class after all
    pub value_is_null: bool,
    pub(crate) parts: Vec<Part>,
    pub(crate) after: String,
    /// ToString() with no shared text (ShellBagUnknown and ShellBagParseError)
    pub(crate) own_text: bool,
    /// ToString() is the shared text alone, with nothing after it (ShellBagDamaged has no ToString of its own)
    pub(crate) base_only: bool,
}

impl ShellItem {
    pub(crate) fn new(class: &'static str, friendly_name: &str, raw: &[u8]) -> ShellItem {
        ShellItem {
            class,
            friendly_name: friendly_name.to_string(),
            value: String::new(),
            raw: raw.to_vec(),
            extension_blocks: Vec::new(),
            short_name: None,
            last_modification: None,
            last_access: None,
            drive_letter: None,
            property_store: None,
            property_stores: Vec::new(),
            delegate_extension_blocks: Vec::new(),
            error_message: None,
            value_is_null: false,
            parts: Vec::new(),
            after: String::new(),
            own_text: false,
            base_only: false,
        }
    }

    pub(crate) fn set_before_line(&mut self, line: Option<String>) {
        self.parts = line.into_iter().map(Part::Text).collect();
    }

    /// base.ToString()
    fn base_text(&self) -> String {
        let mut s = format!("Value: {}\nShell Type: {}\n\n", self.value, self.friendly_name);
        if !self.extension_blocks.is_empty() {
            s.push_str(&format!("\nExtension blocks found: {}\n", self.extension_blocks.len()));
            let mut number = 0i64;
            for block in &self.extension_blocks {
                if block.is_place_holder() {
                    continue;
                }
                s.push_str(&format!("---------------------- Block {} ----------------------\n{}\n", n0(number), block.to_text()));
                number += 1;
            }
            s.push_str("--------------------------------------------------\n");
        }
        s
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        if self.own_text {
            return format!(
                "Value: {}\nShell Type: {}\n\nAbsolute path: \nBagPath: \nSlot #: -1\nNode Slot: 0\nMRU Position: -1\n\n# ChildBags: 0\n\nHex Value: {}\n",
                self.value,
                self.friendly_name,
                hex(&self.raw)
            );
        }
        if self.base_only {
            return self.base_text();
        }
        let mut s = String::new();
        for part in &self.parts {
            match part {
                Part::Text(t) => s.push_str(t),
                Part::Store(heading, store) => {
                    s.push_str(heading);
                    s.push_str(&store.to_text());
                    s.push('\n');
                }
            }
        }
        s.push_str(&self.base_text());
        s.push('\n');
        s.push_str(&self.after);
        s
    }
}

/// new ShellBagUnknown
pub fn new_unknown(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagUnknown", "**** Unknown", raw);
    item.value = format!("**** Unknown type! ShellBag ID: {:x}, Hex: {}", byte_at(raw, 2)?, hex(raw));
    item.own_text = true;
    Ok(item)
}

/// new ShellBagParseError
pub fn new_parse_error(raw: &[u8]) -> NetResult<ShellItem> {
    let mut item = ShellItem::new("ShellBagParseError", &format!("Type ID: 0x{:02X}", byte_at(raw, 2)?), raw);
    item.value = "!!! Parse error placeholder !!!".to_string();
    item.own_text = true;
    Ok(item)
}

/// Lnk's ShellBagDamaged
pub fn new_damaged(raw: &[u8], error: &str) -> ShellItem {
    let kind = raw.get(2).copied().filter(|_| raw.len() > 2).unwrap_or(0);
    let mut item = ShellItem::new("ShellBagDamaged", "Damaged or unsupported shell item", raw);
    item.value = format!("Type 0x{kind:02X}, {} bytes: {error}", raw.len());
    item.error_message = Some(error.to_string());
    item.base_only = true;
    item
}

/// The class named ShellBag0X{id}, if there is one
pub(crate) fn by_type(id: u8) -> Option<fn(&[u8]) -> NetResult<ShellItem>> {
    Some(match id {
        0x00 => new_0x00,
        0x01 => new_0x01,
        0x02 => new_0x02,
        0x03 => new_0x03,
        0x04 => new_0x04,
        0x09 => new_0x09,
        0x0a => new_0x0a,
        0x0f => new_0x0f,
        0x10 => new_0x10,
        0x11 => new_0x11,
        0x16 => new_0x16,
        0x18 => new_0x18,
        0x1a => new_0x1a,
        0x1d => new_0x1d,
        0x1e => new_0x1e,
        0x1f => new_0x1f,
        0x21 => new_0x21,
        0x23 => new_0x23,
        0x25 => new_0x25,
        0x2a => new_0x2a,
        0x2b => new_0x2b,
        0x2c => new_0x2c,
        0x2e => new_0x2e,
        0x2f => new_0x2f,
        0x31 => new_0x31,
        0x32 => new_0x32,
        0x35 => new_0x35,
        0x36 => new_0x36,
        0x39 => new_0x39,
        0x3a => new_0x3a,
        0x3d => new_0x3d,
        0x41 => new_0x41,
        0x42 => new_0x42,
        0x43 => new_0x43,
        0x45 => new_0x45,
        0x46 => new_0x46,
        0x47 => new_0x47,
        0x4c => new_0x4c,
        0x4d => new_0x4d,
        0x4e => new_0x4e,
        0x50 => new_0x50,
        0x52 => new_0x52,
        0x53 => new_0x53,
        0x54 => new_0x54,
        0x5c => new_0x5c,
        0x61 => new_0x61,
        0x63 => new_0x63,
        0x64 => new_0x64,
        0x65 => new_0x65,
        0x67 => new_0x67,
        0x69 => new_0x69,
        0x70 => new_0x70,
        0x71 => new_0x71,
        0x74 => new_0x74,
        0x78 => new_0x78,
        0x79 => new_0x79,
        0x80 => new_0x80,
        0x87 => new_0x87,
        0x94 => new_0x94,
        0xb1 => new_0xb1,
        0xb2 => new_0xb2,
        0xb5 => new_0xb5,
        0xb6 => new_0xb6,
        0xb8 => new_0xb8,
        0xbd => new_0xbd,
        0xc0 => new_0xc0,
        0xc3 => new_0xc3,
        0xc6 => new_0xc6,
        0xca => new_0xca,
        0xe1 => new_0xe1,
        0xe8 => new_0xe8,
        0xf3 => new_0xf3,
        0xf4 => new_0xf4,
        _ => return None,
    })
}

/// Beef000e's choice: the class for the type byte, or unknown
pub(crate) fn by_type_or_unknown(id: u8, raw: &[u8]) -> NetResult<ShellItem> {
    match by_type(id) {
        // Beef000e makes them through Activator.CreateInstance, which wraps what they throw
        Some(make) => make(raw).map_err(|_| "Exception has been thrown by the target of an invocation.".to_string()),
        None => new_unknown(raw),
    }
}

/// HasZipDate: a Unicode MM/dd/yyyy  HH:mm:ss at the offset
fn has_zip_date(raw: &[u8], offset: usize) -> bool {
    const PATTERN: &[u8] = b"00/00/0000  00:00:00";
    if raw.len() < offset + PATTERN.len() * 2 {
        return false;
    }
    PATTERN.iter().enumerate().all(|(i, p)| {
        let c = u16::from_le_bytes([raw[offset + i * 2], raw[offset + i * 2 + 1]]);
        if *p == b'0' { (0x30..=0x39).contains(&c) } else { c == u16::from(*p) }
    })
}

const AUGM_SIGNATURE: i32 = 0x4d677541;
const GFSI_SIGNATURE: i32 = 0x49534647;
const CONTROL_PANEL_CPL_SIGNATURE: u32 = 0xffffff38;
const MTP_DEVICE_SIGNATURE: u32 = 0x08312006;
const MTP_STORAGE_SIGNATURE: u32 = 0x10312005;
const MTP_FOLDER_SIGNATURE: u32 = 0x07192006;
pub(crate) const CFSF_SIGNATURE: u32 = 0x46534643;

/// ShellItemFactory.Create
pub fn create(raw: &[u8]) -> NetResult<ShellItem> {
    if raw.len() < 3 {
        return Err(format!("A shell item has at least 3 bytes, not {}", raw.len()));
    }
    if raw.len() >= 8 {
        let signature = i32_at(raw, 4)?;
        if u32_at(raw, 4)? == CONTROL_PANEL_CPL_SIGNATURE || (signature == GFSI_SIGNATURE && raw[2] != 0) {
            return Err("Unsupported shell item. Send it to saericzimmerman@gmail.com so support can be added!".to_string());
        }
        if signature == AUGM_SIGNATURE {
            return new_cd_burn(raw);
        }
    }
    if raw.len() >= 10 {
        match u32_at(raw, 6)? {
            MTP_DEVICE_SIGNATURE => return new_mtp_device(raw),
            MTP_STORAGE_SIGNATURE => return new_mtp_storage(raw),
            MTP_FOLDER_SIGNATURE => return new_mtp_folder(raw),
            CFSF_SIGNATURE => return new_cfsf(raw),
            _ => {}
        }
    }
    if is_find_data(raw)? {
        return new_find_data(raw);
    }
    if is_ftp_item(raw)? {
        return new_0x00(raw);
    }
    if is_document_drive(raw)? {
        return new_document_drive(raw);
    }
    if is_archive_contents(raw)? {
        return new_archive_contents(raw);
    }
    if raw.len() > 0x28 && (raw[0x8] == 0 || has_zip_date(raw, 0x24)) && (raw[0x28] == 0x2f || raw[0x26] == 0x2f || raw[0x1a] == 0x2f || raw[0x1c] == 0x2f) {
        if let Ok(item) = new_zip_contents(raw) {
            return Ok(item);
        }
    }
    let id = raw[2];
    match by_type(id) {
        Some(make) => make(raw),
        None => {
            match id {
                0x22 if raw.len() > 4 && char::from(raw[3]).is_alphabetic() && raw[4] == b':' => return new_0x23(raw),
                0x77 => return new_0x74(raw),
                0xaa | 0xae => {
                    if let Ok(zip) = new_zip_contents(raw) {
                        if !zip.value_is_null && !zip.value.contains("Unable to determine value") {
                            return Ok(zip);
                        }
                    }
                }
                _ => {}
            }
            new_unknown(raw)
        }
    }
}

/// ShellItemFactory.Create with a code page for the item's ANSI strings
pub fn create_with_code_page(raw: &[u8], code_page: i32) -> NetResult<ShellItem> {
    let previous = crate::utils::code_page();
    crate::utils::set_code_page(code_page);
    let result = create(raw);
    crate::utils::set_code_page(previous);
    result
}

/// The time text most classes use, to keep them short
pub(crate) fn time_line(label: &str, time: Option<Timestamp>) -> String {
    time.map(|t| format!("{label}: {}\n", time_text(t))).unwrap_or_default()
}

