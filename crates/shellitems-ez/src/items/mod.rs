//! Shell items: `ShellBag`, `ShellItemFactory` and one constructor per class. A shell item is one struct: what classes share,
//! the few fields LECmd and the others read, and the lines each class's ToString() puts around the shared text.

mod complex;
mod simple;
mod special;

use ez_common::Timestamp;
use ez_common::json::Value;
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
    /// ShellBagType
    pub bag_type: &'static str,
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
    /// The class's other properties that are serialized, in any order: `own_properties` has the order
    pub(crate) props: Vec<(&'static str, Value)>,
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
            bag_type: default_bag_type(class),
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
            props: Vec::new(),
            parts: Vec::new(),
            after: String::new(),
            own_text: false,
            base_only: false,
        }
    }

    /// Keeps a property for serializing
    pub(crate) fn set(&mut self, name: &'static str, value: Value) {
        self.props.retain(|(n, _)| *n != name);
        self.props.push((name, value));
    }

    /// A property of `own_properties`
    fn property(&self, name: &str) -> Value {
        if let Some((_, value)) = self.props.iter().find(|(n, _)| *n == name) {
            return value.clone();
        }
        let store = |s: &Option<PropertyStore>| s.as_ref().map_or(Value::Null, PropertyStore::to_value);
        match name {
            "ShortName" => Value::opt_text(self.short_name.as_deref()),
            "LastModificationTime" => Value::opt_time(self.last_modification),
            "LastAccessTime" => Value::opt_time(self.last_access),
            "DriveLetter" => Value::opt_text(self.drive_letter.as_deref()),
            // these two classes start with an empty store
            "PropertyStore" if self.property_store.is_none() && matches!(self.class, "ShellBag0X78" | "ShellBagCDBurn") => PropertyStore::default().to_value(),
            // the first of its stores, or a new one
            "PropertyStore" if self.class == "ShellBag0X00" => self.property_stores.first().cloned().unwrap_or_default().to_value(),
            "PropertyStore" => store(&self.property_store),
            "PropertyStores" => Value::List(self.property_stores.iter().map(PropertyStore::to_value).collect()),
            "DelegateExtensionBlocks" => Value::List(self.delegate_extension_blocks.iter().map(Block::to_value).collect()),
            "FileSize" => Value::number(0),
            "IsFtpFile" => Value::Bool(false),
            _ => Value::Null,
        }
    }

    /// The properties ServiceStack serializes, with the type name it adds for an IShellBag. The class's own come first
    pub fn to_value(&self) -> Value {
        let assembly = if self.class == "ShellBagDamaged" { "Lnk.ShellItems.ShellBagDamaged, Lnk".to_string() } else { format!("ExtensionBlocks.{}, ExtensionBlocks", self.class) };
        let mut list = vec![("__type", Value::Text(assembly))];
        let blocks = Value::List(self.extension_blocks.iter().map(Block::to_value).collect());
        let value = if self.value_is_null { Value::Null } else { Value::text(self.value.as_str()) };
        let name = Value::text(self.friendly_name.as_str());
        let id = Value::Text(internal_id());
        let hex_value = Value::bytes(&self.raw);
        let empty = || Value::text("");
        let minus_one = || Value::number(-1);
        let no_bags = || Value::List(Vec::new());
        let bag_type = Value::text(self.bag_type);
        if self.own_text {
            // ShellBagUnknown and ShellBagParseError aren't ShellBags: they declare it all themselves, in their own orders
            list.push(("ExtensionBlocks", blocks));
            list.push(("InternalId", id));
            list.push(("FriendlyName", name));
            if self.class == "ShellBagParseError" {
                list.push(("IsDeleted", Value::Bool(false)));
                list.push(("HexValue", hex_value));
                list.push(("BagPath", empty()));
                list.push(("AbsolutePath", empty()));
                list.push(("ShellBagType", bag_type));
                list.push(("Slot", minus_one()));
            } else {
                list.push(("HexValue", hex_value));
                list.push(("BagPath", empty()));
                list.push(("AbsolutePath", empty()));
                list.push(("ShellBagType", bag_type));
                list.push(("Slot", minus_one()));
                list.push(("IsDeleted", Value::Bool(false)));
            }
            list.push(("MruPosition", minus_one()));
            list.push(("NodeSlot", Value::number(0)));
            list.push(("ChildShellBags", no_bags()));
            list.push(("Value", value));
            list.push(("HasExplored", Value::Bool(false)));
            list.push(("NodeId", Value::number(0)));
            return Value::object(list);
        }
        if self.class == "ShellBagDamaged" {
            list.push(("ItemType", Value::number(self.raw.get(2).copied().filter(|_| self.raw.len() > 2).unwrap_or(0))));
            list.push(("RawBytes", Value::bytes(&self.raw)));
            list.push(("ErrorMessage", Value::opt_text(self.error_message.as_deref())));
        }
        for own in own_properties(self.class) {
            list.push((own, self.property(own)));
        }
        list.extend([
            ("InternalId", id),
            ("FriendlyName", name),
            ("HexValue", hex_value),
            ("BagPath", empty()),
            ("Slot", minus_one()),
            ("IsDeleted", Value::Bool(false)),
            ("MruPosition", minus_one()),
            ("NodeSlot", Value::number(0)),
            ("ChildShellBags", no_bags()),
            ("Value", value),
            ("HasExplored", Value::Bool(false)),
            ("ShellBagType", bag_type),
            ("ExtensionBlocks", blocks),
            ("NodeId", Value::number(0)),
        ]);
        Value::object(list)
    }

    pub(crate) fn set_before_line(&mut self, line: Option<String>) {
        self.parts = line.into_iter().map(Part::Text).collect();
    }

    /// base.ToString()
    fn base_text(&self) -> String {
        let mut s = format!("Value: {}\r\nShell Type: {}\r\n\r\n", self.value, self.friendly_name);
        if !self.extension_blocks.is_empty() {
            s.push_str(&format!("\r\nExtension blocks found: {}\r\n", self.extension_blocks.len()));
            let mut number = 0i64;
            for block in &self.extension_blocks {
                if block.is_place_holder() {
                    continue;
                }
                s.push_str(&format!("---------------------- Block {} ----------------------\r\n{}\r\n", n0(number), block.to_text()));
                number += 1;
            }
            s.push_str("--------------------------------------------------\r\n");
        }
        s
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        if self.own_text {
            return format!(
                "Value: {}\r\nShell Type: {}\r\n\r\nAbsolute path: \r\nBagPath: \r\nSlot #: -1\r\nNode Slot: 0\r\nMRU Position: -1\r\n\r\n# ChildBags: 0\r\n\r\nHex Value: {}\r\n",
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
                    s.push_str("\r\n");
                }
            }
        }
        s.push_str(&self.base_text());
        s.push_str("\r\n");
        s.push_str(&self.after);
        s
    }
}

/// InternalId: a new GUID for each item, as Guid.NewGuid() makes
fn internal_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let random = |salt: u64| {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(salt);
        h.finish()
    };
    let (a, b) = (random(1), random(2));
    let c = (b & 0x3fff_ffff_ffff_ffff) | 0x8000_0000_0000_0000;
    format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}", a >> 32, (a >> 16) & 0xffff, a & 0xfff, c >> 48, c & 0xffff_ffff_ffff)
}

/// What the constructors set first. Those that read more change it
fn default_bag_type(class: &str) -> &'static str {
    match class {
        "ShellBag0X00" => "Variable",
        "ShellBag0X01" | "ShellBag0X2E" => "ControlPanelCategory",
        "ShellBag0X02" => "HyperVResource",
        "ShellBag0X03" | "ShellBagUnknown" => "Unknown",
        "ShellBag0X1D" => "NotAssigned",
        "ShellBag0X21" | "ShellBag0X4D" | "ShellBag0X4E" | "ShellBag0X53" | "ShellBag0X70" | "ShellBag0X71" | "ShellBag0X74" => "Guid",
        "ShellBag0X23" | "ShellBag0X25" | "ShellBag0X2A" | "ShellBag0X2F" => "DriveLetter",
        "ShellBag0X2C" | "ShellBag0X78" | "ShellBagCFSF" => "User",
        "ShellBag0X32" => "File",
        "ShellBag0X41" | "ShellBag0X42" | "ShellBag0X43" | "ShellBag0X46" | "ShellBag0X47" | "ShellBag0XC3" => "Network",
        "ShellBag0X52" => "Backup",
        "ShellBag0X61" => "FtpUri",
        "ShellBag0X64" | "ShellBag0X67" | "ShellBag0X69" => "History",
        "ShellBagArchiveContents" | "ShellBagZipContents" => "ZipFileContents",
        "ShellBagCDBurn" => "OpticalMedia",
        "ShellBagMTPDevice" => "MtpDevice",
        "ShellBagMTPFolder" => "MtpFolder",
        "ShellBagMTPStorage" => "MtpStorage",
        "ShellBagParseError" | "ShellBagDamaged" => "ParseError",
        // the enum's first value, which is also what a class that sets nothing has
        _ => "Directory",
    }
}

/// Each class's own properties, in the order .NET's reflection gives them
fn own_properties(class: &str) -> &'static [&'static str] {
    const FILE_ENTRY: &[&str] = &["ShortName", "LastModificationTime", "LastAccessTime"];
    const TIME: &[&str] = &["Timestamp"];
    const TWO_TIMES: &[&str] = &["Timestamp", "Timestamp2"];
    const DESCRIPTION: &[&str] = &["Description"];
    const STORE: &[&str] = &["PropertyStore"];
    const MODIFIED: &[&str] = &["ModifiedOn"];
    const BACKUP: &[&str] = &["PropertyStore", "ModifiedDateFromBackup", "CreatedDateFromBackup", "BackupDateTime", "BackupUnknownDateTime", "LastAccessTime"];
    match class {
        "ShellBag0X00" => &["PropertyStore", "PropertyStores", "DelegateExtensionBlocks", "LastModificationTime", "CreatedOnTime", "LastAccessTime", "FTPFolderTime", "IsFtpFile", "FileSize", "Miscellaneous", "FullUrl", "ShortName"],
        "ShellBag0X01" => &["DriveLetter"],
        "ShellBag0X02" => &["LastModificationTime", "CreatedOnTime", "LastAccessTime", "ShortName"],
        "ShellBag0X04" => &["ExtraData"],
        "ShellBag0X09" | "ShellBag0X0F" | "ShellBag0X10" | "ShellBag0X18" | "ShellBag0X1A" | "ShellBag0X2B" | "ShellBag0X87" | "ShellBag0X94" | "ShellBag0XB2" | "ShellBag0XB6" | "ShellBag0XB8" | "ShellBag0XBD" | "ShellBag0XC0"
        | "ShellBag0XC6" | "ShellBag0XCA" | "ShellBag0XF3" | "ShellBag0XF4" => TIME,
        "ShellBag0X0A" | "ShellBag0X11" | "ShellBag0X16" => TWO_TIMES,
        "ShellBag0X1D" => &["FileTime1", "URI"],
        "ShellBag0X1F" | "ShellBag0X79" => BACKUP,
        "ShellBag0X2E" => &["LastAccessTime", "PropertyStore", "Category", "DevicePath"],
        "ShellBag0X31" => &["LastModificationTime", "LastAccessTime", "ShortName"],
        "ShellBag0X32" => &["FileSize", "LastModificationTime", "LastAccessTime", "ShortName"],
        "ShellBag0X35" | "ShellBag0X36" | "ShellBag0X39" | "ShellBag0X3A" | "ShellBag0X3D" | "ShellBag0XB1" | "ShellBag0XB5" => FILE_ENTRY,
        "ShellBag0X41" | "ShellBag0X42" | "ShellBag0X43" | "ShellBag0X46" | "ShellBag0X47" | "ShellBag0X5C" | "ShellBag0X63" => DESCRIPTION,
        "ShellBag0X4D" | "ShellBag0X71" | "ShellBag0X74" | "ShellBag0X78" => STORE,
        "ShellBag0X4E" => &["LastAccessTime", "PropertyStore"],
        "ShellBag0X50" => &["FileTime1"],
        "ShellBag0X52" => &["LastAccessTime"],
        "ShellBag0X54" | "ShellBag0X65" | "ShellBag0X69" | "ShellBag0X80" => MODIFIED,
        "ShellBag0X61" => &["FileTime1", "ModifiedOn", "URI", "UserName"],
        "ShellBag0XC3" => &["LocationDescription"],
        "ShellBagArchiveContents" => &["FileAttributes", "FileSize", "ModifiedOn", "ArchivePath"],
        "ShellBagCDBurn" => &["PropertyStore", "LastModificationTime", "CreatedOnTime", "LastAccessTime", "FileSize", "Miscellaneous", "ShortName"],
        "ShellBagCFSF" => &["FileSize", "LastModificationTime", "LastAccessTime"],
        "ShellBagDocumentDrive" => &["ItemId", "ParentId", "CreatedOn", "ModifiedOn", "AccessedOn"],
        "ShellBagFindData" => &["FileAttributes", "FileSize", "CreatedOn", "AccessedOn", "ModifiedOn", "SecondName"],
        "ShellBagMTPDevice" => &["ClassId", "DeviceName", "DevicePath", "DevicePropsGuid", "FunctionalObjectGuid", "FunctionalCategoryGuid", "DelegateFolderGuid", "PortableDeviceId"],
        "ShellBagMTPFolder" => &["FolderName", "FolderName2", "PropertyArrays"],
        "ShellBagMTPStorage" => &["PropertyArrays", "FileSystemName2", "StorageName", "PersistentUniqueId", "FileSystemName", "WpdEventHandlers", "StorageSerialNumber"],
        "ShellBagZipContents" => &["LastAccessTime", "LastAccessTimeString", "ParentFolder"],
        _ => &[],
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
    time.map(|t| format!("{label}: {}\r\n", time_text(t))).unwrap_or_default()
}

