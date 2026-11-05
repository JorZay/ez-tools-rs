//! Windows shortcut (.lnk) files, as Eric Zimmerman's Lnk reads them: damage is kept in `parse_errors` while the rest of the file
//! is still read, and only what stops it altogether is an error. Nothing here prints or exits.

mod extra;

use std::path::Path;

use ez_common::Timestamp;
use ez_common::net::{enum_name, flags_name, unicode_string};
use shellitems_ez::ShellItem;
use shellitems_ez::items::{create_with_code_page, new_damaged};
use shellitems_ez::utils::{decode_with, is_argument_or_index_error};

pub use extra::{DamagedData, ExtraBlock};

/// LnkParseException, or what else stopped the file being read
#[derive(Clone, Debug)]
pub struct LnkError {
    pub message: String,
    /// Where, when the original knows: -1 otherwise
    pub offset: i32,
    pub field: Option<String>,
    /// An exception that means the file couldn't be read, as opposed to a damaged one
    pub read_error: bool,
    /// The exception as the log shows it, without its stack trace
    pub exception: String,
}

impl LnkError {
    pub(crate) fn parse(message: String, offset: i32, field: &str) -> LnkError {
        LnkError { exception: format!("Lnk.LnkParseException: {message}"), message, offset, field: Some(field.to_string()), read_error: false }
    }
}

pub(crate) type LnkResult<T> = Result<T, LnkError>;

pub const HEADER_SIZE: usize = 0x4c;
const GOOD_SIGNATURE: &str = "00021401-0000-0000-c000-000000000046";

const DATA_FLAGS: &[(&str, i64)] = &[
    ("HasTargetIdList", 0x1),
    ("HasLinkInfo", 0x2),
    ("HasName", 0x4),
    ("HasRelativePath", 0x8),
    ("HasWorkingDir", 0x10),
    ("HasArguments", 0x20),
    ("HasIconLocation", 0x40),
    ("IsUnicode", 0x80),
    ("ForceNoLinkInfo", 0x100),
    ("HasExpString", 0x200),
    ("RunInSeparateProcess", 0x400),
    ("Reserved0", 0x800),
    ("HasDarwinId", 0x1000),
    ("RunAsUser", 0x2000),
    ("HasExpIcon", 0x4000),
    ("NoPidlAlias", 0x8000),
    ("Reserved1", 0x10000),
    ("RunWithShimLayer", 0x20000),
    ("ForceNoLinkTrack", 0x40000),
    ("EnableTargetMetadata", 0x80000),
    ("DisableLinkPathTracking", 0x100000),
    ("DisableKnownFolderTracking", 0x200000),
    ("DisableKnownFolderAlias", 0x400000),
    ("AllowLinkToLink", 0x800000),
    ("UnaliasOnSave", 0x1000000),
    ("PreferEnvironmentPath", 0x2000000),
    ("KeepLocalIdListForUncTarget", 0x4000000),
];
const FILE_ATTRIBUTES: &[(&str, i64)] = &[
    ("FileAttributeReadonly", 0x1),
    ("FileAttributeHidden", 0x2),
    ("FileAttributeSystem", 0x4),
    ("ResVolumeLabel", 0x8),
    ("FileAttributeDirectory", 0x10),
    ("FileAttributeArchive", 0x20),
    ("FileAttributeDevice", 0x40),
    ("FileAttributeNormal", 0x80),
    ("FileAttributeTemporary", 0x100),
    ("FileAttributeSparseFile", 0x200),
    ("FileAttributeReparsePoint", 0x400),
    ("FileAttributeCompressed", 0x800),
    ("FileAttributeOffline", 0x1000),
    ("FileAttributeNotContentIndexed", 0x2000),
    ("FileAttributeEncrypted", 0x4000),
    ("UnkWin95Fat", 0x8000),
    ("FileAttributeVirtual", 0x10000),
];
const SHOW_WINDOW: &[(&str, i64, &str)] = &[
    ("SwHide", 0, "Hides the window and activates another window."),
    ("SwNormal", 1, "Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized."),
    ("SwShowminimized", 2, "Activates and minimizes the window."),
    ("SwMaximize", 3, "Activates and maximizes the window."),
    ("SwShownoactivate", 4, "Display the window in its most recent position and size without activating it."),
    ("SwShow", 5, "Activates the window and displays it in its current size and position."),
    ("SwMinimize", 6, "Minimizes the window and activates the next top-level windows (in order of depth (Z order))"),
    ("SwShowminnoactive", 7, "Display the window as minimized without activating it."),
    ("SwShowna", 8, "Display the window in its current size and position without activating it."),
    ("SwRestore", 9, "Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized."),
    ("SwShowdefault", 10, "Set the show state based on the ShowWindow values specified during the creation of the process."),
    ("SwForceminimize", 11, "Minimizes a window, even if the thread that owns the window is not responding."),
    ("SwNormalna", 0xcc, "Undocumented according to wine project."),
];
const DRIVE_TYPES: &[(&str, i64, &str)] = &[
    ("DriveUnknown", 0, "Unknown"),
    ("DriveNoRootDir", 1, "No root directory"),
    ("DriveRemovable", 2, "Removable storage media (Floppy, USB)"),
    ("DriveFixed", 3, "Fixed storage media (Hard drive)"),
    ("DriveRemote", 4, "Remote storage"),
    ("DriveCdrom", 5, "Optical disc (CD-ROM, DVD, BD)"),
    ("DriveRamdisk", 6, "RAM drive"),
];
const LOCATION_FLAGS: &[(&str, i64)] = &[("VolumeIdAndLocalBasePath", 1), ("CommonNetworkRelativeLinkAndPathSuffix", 2)];
const SHARE_FLAGS: &[(&str, i64)] = &[("ValidDevice", 1), ("ValidNetType", 2)];
const PROVIDER_TYPES: &[(&str, i64)] = &[
    ("WnncNet10Net", 0x50000), ("WnncNet_3In1", 0x270000), ("WnncNet_9Tiles", 0x90000), ("WnncNetAppletalk", 0x130000), ("WnncNetAs400", 0xB0000), ("WnncNetAvid", 0x1A0000),
    ("WnncNetAvid1", 0x3A0000), ("WnncNetBmc", 0x180000), ("WnncNetBwnfs", 0x100000), ("WnncNetClearcase", 0x160000), ("WnncNetCogent", 0x110000), ("WnncNetCsc", 0x260000),
    ("WnncNetDav", 0x2E0000), ("WnncNetDce", 0x190000), ("WnncNetDecorb", 0x200000), ("WnncNetDfs", 0x3B0000), ("WnncNetDistinct", 0x230000), ("WnncNetDocuspace", 0x1B0000),
    ("WnncNetDriveonweb", 0x3E0000), ("WnncNetExifs", 0x2D0000), ("WnncNetExtendnet", 0x290000), ("WnncNetFarallon", 0x120000), ("WnncNetFjRedir", 0x220000), ("WnncNetFoxbat", 0x2B0000),
    ("WnncNetFrontier", 0x170000), ("WnncNetFtpNfs", 0xC0000), ("WnncNetGoogle", 0x430000), ("WnncNetHobNfs", 0x320000), ("WnncNetIbmal", 0x340000), ("WnncNetIntergraph", 0x140000),
    ("WnncNetKnoware", 0x2F0000), ("WnncNetKwnp", 0x3C0000), ("WnncNetLanman", 0x20000), ("WnncNetLanstep", 0x80000), ("WnncNetLantastic", 0xA0000), ("WnncNetLifenet", 0xE0000),
    ("WnncNetLock", 0x350000), ("WnncNetLocus", 0x60000), ("WnncNetMangosoft", 0x1C0000), ("WnncNetMasfax", 0x310000), ("WnncNetMfiles", 0x410000), ("WnncNetMsNfs", 0x420000),
    ("WnncNetNetware", 0x30000), ("WnncNetObjectDire", 0x300000), ("WnncNetOpenafs", 0x390000), ("WnncNetPathworks", 0xD0000), ("WnncNetPowerlan", 0xF0000), ("WnncNetProtstor", 0x210000),
    ("WnncNetQuincy", 0x380000), ("WnncNetRdr2Sample", 0x250000), ("WnncNetRiverfront1", 0x1E0000), ("WnncNetRiverfront2", 0x1F0000), ("WnncNetRsfx", 0x400000), ("WnncNetSernet", 0x1D0000),
    ("WnncNetShiva", 0x330000), ("WnncNetSrt", 0x370000), ("WnncNetStac", 0x2A0000), ("WnncNetSunPcNfs", 0x70000), ("WnncNetSymfonet", 0x150000), ("WnncNetTermsrv", 0x360000),
    ("WnncNetTwins", 0x240000), ("WnncNetVines", 0x40000), ("WnncNetVmware", 0x3F0000), ("WnncNetYahoo", 0x2C0000), ("WnncNetZenworks", 0x3D0000),
];

fn pick(table: &[(&'static str, i64, &'static str)], value: i64, description: bool) -> String {
    match table.iter().find(|(_, v, _)| *v == value) {
        Some((name, _, text)) => (if description { *text } else { *name }).to_string(),
        None => value.to_string(),
    }
}

// Helpers: reads with their own error messages

pub(crate) fn ensure_range(buffer: &[u8], offset: i64, count: i64, field: &str, limit: i64) -> LnkResult<()> {
    let end = if limit < 0 { buffer.len() as i64 } else { limit.min(buffer.len() as i64) };
    if offset < 0 || count < 0 || offset + count > end {
        return Err(LnkError::parse(format!("Invalid {field} data (offset {offset}, length {count}, available {end}) - is this file corrupt?"), offset.max(-1).min(i64::from(i32::MAX)) as i32, field));
    }
    Ok(())
}

fn read_u16(buffer: &[u8], offset: i64, field: &str) -> LnkResult<u16> {
    ensure_range(buffer, offset, 2, field, -1)?;
    Ok(u16::from_le_bytes(buffer[offset as usize..offset as usize + 2].try_into().unwrap()))
}

pub(crate) fn read_u32(buffer: &[u8], offset: i64, field: &str, limit: i64) -> LnkResult<u32> {
    ensure_range(buffer, offset, 4, field, limit)?;
    Ok(u32::from_le_bytes(buffer[offset as usize..offset as usize + 4].try_into().unwrap()))
}

pub(crate) fn read_i32(buffer: &[u8], offset: i64, field: &str) -> LnkResult<i32> {
    read_u32(buffer, offset, field, -1).map(|v| v as i32)
}

pub(crate) fn slice<'a>(buffer: &'a [u8], offset: i64, count: i64, field: &str, limit: i64) -> LnkResult<&'a [u8]> {
    ensure_range(buffer, offset, count, field, limit)?;
    Ok(&buffer[offset as usize..(offset + count) as usize])
}

pub(crate) fn read_ansi_z(buffer: &[u8], offset: i64, code_page: i32, field: &str, limit: i64) -> LnkResult<String> {
    let end = if limit < 0 { buffer.len() as i64 } else { limit.min(buffer.len() as i64) };
    ensure_range(buffer, offset, 0, field, end)?;
    let bytes = &buffer[offset as usize..end as usize];
    let length = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(decode_with(code_page, &bytes[..length]))
}

pub(crate) fn read_unicode_z(buffer: &[u8], offset: i64, field: &str, limit: i64) -> LnkResult<String> {
    let end = if limit < 0 { buffer.len() as i64 } else { limit.min(buffer.len() as i64) };
    ensure_range(buffer, offset, 0, field, end)?;
    let mut i = offset;
    while i + 1 < end && (buffer[i as usize] != 0 || buffer[i as usize + 1] != 0) {
        i += 2;
    }
    let mut length = i.min(end) - offset;
    length -= length % 2;
    Ok(if length <= 0 { String::new() } else { shellitems_ez::utils::unicode(&buffer[offset as usize..(offset + length) as usize]) })
}

/// Hot key text
fn hot_key(low: u8, high: u8) -> String {
    if low == 0 && high == 0 {
        return String::new();
    }
    let mut key = String::new();
    if high & 1 != 0 {
        key.push_str("SHIFT+");
    }
    if high & 2 != 0 {
        key.push_str("CONTROL+");
    }
    if high & 4 != 0 {
        key.push_str("ALT+");
    }
    match low {
        0x30..=0x39 | 0x41..=0x5a => format!("{key}{}", low as char),
        0x70..=0x87 => format!("{key}F{}", low - 0x6f),
        0x90 => format!("{key}NUMLOCK"),
        0x91 => format!("{key}SCROLLLOCK"),
        0 => key.trim_end_matches('+').to_string(),
        _ => format!("{key}0x{low:02X}"),
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub data_flags: i32,
    pub file_attributes: i32,
    /// The minimum for a value out of range
    pub target_created: Timestamp,
    pub target_modified: Timestamp,
    pub target_accessed: Timestamp,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_window: i32,
    pub hot_key: String,
}

impl Header {
    fn read(raw: &[u8]) -> LnkResult<(Header, [i64; 3])> {
        let u32_at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let i64_at = |at: usize| i64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        if raw.len() < HEADER_SIZE {
            return Err(LnkError::parse(format!("Header is smaller than {HEADER_SIZE} bytes - is this file corrupt?"), 0, "ShellLinkHeader"));
        }
        let guid = ez_common::net::guid(raw[4..20].try_into().unwrap());
        if u32_at(0) as usize != HEADER_SIZE || guid != GOOD_SIGNATURE {
            return Err(LnkError::parse("Invalid Signature!".to_string(), 0, "HeaderSize/LinkCLSID"));
        }
        let raws = [i64_at(28), i64_at(36), i64_at(44)];
        let time = |raw: i64| Timestamp::from_filetime(raw).unwrap_or(Timestamp::MIN);
        Ok((
            Header {
                data_flags: u32_at(20) as i32,
                file_attributes: u32_at(24) as i32,
                target_created: time(raws[0]),
                target_accessed: time(raws[1]),
                target_modified: time(raws[2]),
                file_size: u32_at(52),
                icon_index: u32_at(56) as i32,
                show_window: u32_at(60) as i32,
                hot_key: hot_key(raw[64], raw[65]),
            },
            raws,
        ))
    }

    pub fn has_flag(&self, flag: i32) -> bool {
        self.data_flags & flag == flag
    }

    /// DataFlags.ToString()
    pub fn data_flags_text(&self) -> String {
        flags_name(i64::from(self.data_flags), DATA_FLAGS)
    }

    /// FileAttributes.ToString()
    pub fn file_attributes_text(&self) -> String {
        flags_name(i64::from(self.file_attributes), FILE_ATTRIBUTES)
    }

    /// ShowWindow.ToString()
    pub fn show_window_text(&self) -> String {
        pick(SHOW_WINDOW, i64::from(self.show_window), false)
    }

    /// The show window value's description, or its name
    pub fn show_window_description(&self) -> String {
        pick(SHOW_WINDOW, i64::from(self.show_window), true)
    }
}

pub const HAS_TARGET_ID_LIST: i32 = 0x1;
pub const HAS_LINK_INFO: i32 = 0x2;
pub const HAS_NAME: i32 = 0x4;
pub const HAS_RELATIVE_PATH: i32 = 0x8;
pub const HAS_WORKING_DIR: i32 = 0x10;
pub const HAS_ARGUMENTS: i32 = 0x20;
pub const HAS_ICON_LOCATION: i32 = 0x40;
pub const IS_UNICODE: i32 = 0x80;

#[derive(Clone, Debug)]
pub struct VolumeInfo {
    pub drive_type: i32,
    pub serial_number: String,
    pub label: String,
}

impl VolumeInfo {
    fn read(raw: &[u8], code_page: i32) -> LnkResult<VolumeInfo> {
        const FIELD: &str = "VolumeID";
        ensure_range(raw, 0, 0x10, FIELD, -1)?;
        let u32_at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let label_offset = u32_at(12) as i32;
        let label = if label_offset == 0x14 {
            let unicode_offset = read_i32(raw, 0x10, FIELD)?;
            read_unicode_z(raw, i64::from(unicode_offset), FIELD, -1)?
        } else {
            read_ansi_z(raw, i64::from(label_offset), code_page, FIELD, -1)?
        };
        Ok(VolumeInfo { drive_type: u32_at(4) as i32, serial_number: format!("{:08X}", u32_at(8)), label })
    }

    /// The drive type's description, or its number
    pub fn drive_type_description(&self) -> String {
        pick(DRIVE_TYPES, i64::from(self.drive_type), true)
    }
}

pub const DRIVE_REMOVABLE: i32 = 2;

#[derive(Clone, Debug)]
pub struct NetworkShareInfo {
    pub share_flags: i32,
    pub provider_type: i32,
    pub share_name: String,
    pub device_name: String,
}

impl NetworkShareInfo {
    fn read(raw: &[u8], code_page: i32) -> LnkResult<NetworkShareInfo> {
        const FIELD: &str = "CommonNetworkRelativeLink";
        ensure_range(raw, 0, 0x14, FIELD, -1)?;
        let i32_at = |at: usize| i32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let share_flags = i32_at(4);
        let name_offset = i32_at(8);
        let device_offset = i32_at(12);
        let provider_type = i32_at(16);
        let mut share_name = read_ansi_z(raw, i64::from(name_offset), code_page, FIELD, -1)?;
        let valid_device = share_flags & 1 == 1;
        let mut device_name = String::new();
        if valid_device && device_offset > 0 {
            device_name = read_ansi_z(raw, i64::from(device_offset), code_page, FIELD, -1)?;
        }
        if name_offset > 0x14 {
            let unicode_name = read_i32(raw, 0x14, FIELD)?;
            let unicode_device = read_i32(raw, 0x18, FIELD)?;
            if unicode_name > 0 {
                share_name = read_unicode_z(raw, i64::from(unicode_name), FIELD, -1)?;
            }
            if valid_device && unicode_device > 0 {
                device_name = read_unicode_z(raw, i64::from(unicode_device), FIELD, -1)?;
            }
        }
        Ok(NetworkShareInfo { share_flags, provider_type, share_name, device_name })
    }

    pub fn has_valid_provider_type(&self) -> bool {
        self.share_flags & 2 == 2
    }

    pub fn provider_type_text(&self) -> String {
        enum_name(i64::from(self.provider_type), PROVIDER_TYPES)
    }

    pub fn share_flags_text(&self) -> String {
        flags_name(i64::from(self.share_flags), SHARE_FLAGS)
    }
}

/// IdList.Parse: the shell items of an ID list; an item that can't be read becomes a damaged one
pub(crate) fn parse_id_list(buffer: &[u8], offset: i64, end: i64, code_page: i32, errors: &mut Vec<String>) -> Vec<ShellItem> {
    let mut items = Vec::new();
    let mut pos = offset;
    while pos + 2 <= end {
        let size = i64::from(u16::from_le_bytes([buffer[pos as usize], buffer[pos as usize + 1]]));
        if size == 0 {
            return items;
        }
        if size < 3 || pos + size > end {
            let message = format!("Invalid ItemID size {size} at offset {pos} (IDList ends at {end})");
            items.push(new_damaged(&buffer[pos as usize..end as usize], &message));
            errors.push(message);
            return items;
        }
        let bytes = &buffer[pos as usize..(pos + size) as usize];
        let made = create_with_code_page(bytes, code_page).and_then(|item| {
            if item.class == "ShellBagUnknown" {
                Err(format!("Unknown shell item ID: 0x{:X}. Please send to saericzimmerman@gmail.com so support can be added.", bytes[2]))
            } else {
                Ok(item)
            }
        });
        match made {
            Ok(item) => items.push(item),
            Err(e) => {
                let reason = if is_argument_or_index_error(&e) { "item data ends before the parser expected (truncated or corrupt item)".to_string() } else { e };
                errors.push(format!("Shell item at offset {pos} (type 0x{:02X}): {reason}", bytes[2]));
                items.push(new_damaged(bytes, &reason));
            }
        }
        pos += size;
    }
    if pos < end {
        errors.push(format!("IDList at offset {offset} is missing its TerminalID"));
    }
    items
}

#[derive(Clone, Debug, Default)]
pub struct SourceTimes {
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct LnkFile {
    pub source_file: Option<String>,
    pub source: SourceTimes,
    pub header: Header,
    pub target_ids: Vec<ShellItem>,
    pub extra_blocks: Vec<ExtraBlock>,
    pub location_flags: i32,
    pub volume_info: Option<VolumeInfo>,
    pub network_share_info: Option<NetworkShareInfo>,
    pub local_path: Option<String>,
    pub common_path: Option<String>,
    pub name: Option<String>,
    pub relative_path: Option<String>,
    pub working_directory: Option<String>,
    pub arguments: Option<String>,
    pub icon_location: Option<String>,
    pub parse_errors: Vec<String>,
}

impl LnkFile {
    /// LocationFlags.ToString()
    pub fn location_flags_text(&self) -> String {
        flags_name(i64::from(self.location_flags), LOCATION_FLAGS)
    }
}

fn io_error(e: &std::io::Error, path: &str) -> LnkError {
    let full = std::path::absolute(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string());
    let mut detail = String::new();
    let (exception, message) = match e.kind() {
        std::io::ErrorKind::NotFound => {
            detail = format!("\nFile name: '{full}'");
            ("System.IO.FileNotFoundException", format!("Could not find file '{full}'."))
        }
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => ("System.UnauthorizedAccessException", format!("Access to the path '{full}' is denied.")),
        _ => ("System.IO.IOException", e.to_string()),
    };
    LnkError { exception: format!("{exception}: {message}{detail}"), message, offset: -1, field: None, read_error: true }
}

/// Lnk.LoadFile
pub fn load_file(path: &str, code_page: i32) -> LnkResult<LnkFile> {
    let raw = std::fs::read(path).map_err(|e| io_error(&e, path))?;
    if raw.len() < HEADER_SIZE {
        return Err(LnkError::parse(format!("File ({path}) is less than 76 bytes which is too small to be a valid LNK file!"), 0, "ShellLinkHeader"));
    }
    if u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize != HEADER_SIZE {
        return Err(LnkError::parse(format!("File ({path}) has an invalid signature! Is it a valid LNK file?"), 0, "HeaderSize"));
    }
    read(&raw, Some(path), code_page, true)
}

/// new LnkFile(rawBytes, sourceFile, codepage)
pub fn from_bytes(raw: &[u8], source_file: Option<&str>, code_page: i32) -> LnkResult<LnkFile> {
    read(raw, source_file, code_page, true)
}

fn read(raw: &[u8], source_file: Option<&str>, code_page: i32, check_text_mode: bool) -> LnkResult<LnkFile> {
    match parse(raw, source_file, code_page, check_text_mode) {
        Ok(file) => Ok(file),
        Err(e) => {
            let text_mode = if check_text_mode { describe_text_mode_damage(raw, code_page) } else { None };
            let suffix = text_mode.map(|t| format!(". {t}")).unwrap_or_default();
            let message = format!("Error processing file ({}) - the error was ({}){suffix}", source_file.unwrap_or("(raw data)"), e.message);
            Err(LnkError { exception: format!("Lnk.LnkParseException: {message}"), message, offset: e.offset, field: e.field, read_error: false })
        }
    }
}

fn describe_text_mode_damage(raw: &[u8], code_page: i32) -> Option<String> {
    let mut pairs = 0u64;
    for i in 0..raw.len() {
        if raw[i] != 0x0a {
            continue;
        }
        if i == 0 || raw[i - 1] != 0x0d {
            return None;
        }
        pairs += 1;
    }
    if pairs == 0 {
        return None;
    }
    let mut repaired = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        if raw[i] == 0x0d && raw.get(i + 1) == Some(&0x0a) {
            continue;
        }
        repaired.push(raw[i]);
    }
    match read(&repaired, None, code_page, false) {
        Ok(file) if file.parse_errors.is_empty() => {}
        _ => return None,
    }
    let lf = if pairs == 1 {
        "its LF (0x0A) byte has a CR (0x0D) before it, and with that CR byte".to_string()
    } else {
        format!("each of its {} LF (0x0A) bytes has a CR (0x0D) before it, and with those CR bytes", ez_common::dotnet::n0(pairs))
    };
    Some(format!("The file appears to have been converted to text mode (for example by an ASCII mode FTP transfer): {lf} removed it parses without errors. The file was damaged before it was parsed"))
}

fn read_string_data(raw: &[u8], index: &mut i64, unicode: bool, code_page: i32, field: &str) -> LnkResult<String> {
    let count = i64::from(read_u16(raw, *index, &format!("{field} size"))?);
    *index += 2;
    let bytes = if unicode { count * 2 } else { count };
    ensure_range(raw, *index, bytes, field, -1)?;
    let at = *index as usize;
    let value = if unicode { unicode_string(raw, *index, bytes).unwrap_or_default() } else { decode_with(code_page, &raw[at..at + bytes as usize]) };
    *index += bytes;
    Ok(value)
}

struct LinkInfo {
    flags: i32,
    volume: Option<VolumeInfo>,
    local_path: Option<String>,
    network: Option<NetworkShareInfo>,
    common_path: String,
}

fn parse_link_info(raw: &[u8], start: i64, size: i64, code_page: i32, errors: &mut Vec<String>) -> LnkResult<LinkInfo> {
    let end = start + size;
    let header_size = read_u32(raw, start + 4, "LinkInfoHeaderSize", end)?;
    let flags = read_u32(raw, start + 8, "LinkInfoFlags", end)? as i32;
    let volume_offset = i64::from(read_u32(raw, start + 12, "VolumeIDOffset", end)?);
    let local_offset = i64::from(read_u32(raw, start + 16, "LocalBasePathOffset", end)?);
    let network_offset = i64::from(read_u32(raw, start + 20, "CommonNetworkRelativeLinkOffset", end)?);
    let suffix_offset = i64::from(read_u32(raw, start + 24, "CommonPathSuffixOffset", end)?);
    let (mut local_unicode, mut suffix_unicode) = (0i64, 0i64);
    if header_size >= 0x24 {
        local_unicode = i64::from(read_u32(raw, start + 28, "LocalBasePathOffsetUnicode", end)?);
        suffix_unicode = i64::from(read_u32(raw, start + 32, "CommonPathSuffixOffsetUnicode", end)?);
    }
    let mut info = LinkInfo { flags, volume: None, local_path: None, network: None, common_path: String::new() };
    if flags & 1 == 1 {
        if volume_offset > 0 {
            let attempt = (|| -> LnkResult<VolumeInfo> {
                let at = start + volume_offset;
                let volume_size = read_u32(raw, at, "VolumeIDSize", end)?;
                if volume_size <= 0x10 {
                    return Err(LnkError::parse(format!("Invalid volume data size ({volume_size}) - is this file corrupt?"), at as i32, "VolumeIDSize"));
                }
                VolumeInfo::read(slice(raw, at, i64::from(volume_size), "VolumeID", end)?, code_page)
            })();
            match attempt {
                Ok(v) => info.volume = Some(v),
                Err(e) => errors.push(format!("VolumeID: {}", e.message)),
            }
        }
        let attempt = (|| -> LnkResult<()> {
            if local_offset > 0 {
                info.local_path = Some(read_ansi_z(raw, start + local_offset, code_page, "LocalBasePath", end)?);
            }
            if local_unicode > 0 {
                info.local_path = Some(read_unicode_z(raw, start + local_unicode, "LocalBasePathUnicode", end)?);
            }
            Ok(())
        })();
        if let Err(e) = attempt {
            errors.push(format!("LocalBasePath: {}", e.message));
        }
    }
    if flags & 2 == 2 {
        let attempt = (|| -> LnkResult<NetworkShareInfo> {
            let at = start + network_offset;
            let network_size = read_u32(raw, at, "CommonNetworkRelativeLinkSize", end)?;
            if network_offset == 0 || network_size < 0x14 {
                return Err(LnkError::parse(format!("Invalid network share data size ({network_size}) - is this file corrupt?"), at as i32, "CommonNetworkRelativeLinkSize"));
            }
            NetworkShareInfo::read(slice(raw, at, i64::from(network_size), "CommonNetworkRelativeLink", end)?, code_page)
        })();
        match attempt {
            Ok(n) => info.network = Some(n),
            Err(e) => errors.push(format!("CommonNetworkRelativeLink: {}", e.message)),
        }
    }
    let attempt = (|| -> LnkResult<()> {
        if suffix_offset > 0 {
            info.common_path = read_ansi_z(raw, start + suffix_offset, code_page, "CommonPathSuffix", end)?;
        }
        if suffix_unicode > 0 {
            info.common_path = read_unicode_z(raw, start + suffix_unicode, "CommonPathSuffixUnicode", end)?;
        }
        Ok(())
    })();
    if let Err(e) = attempt {
        errors.push(format!("CommonPathSuffix: {}", e.message));
    }
    Ok(info)
}

/// The file's times as .NET gives them: on Unix, where it doesn't read the birth time, the creation time is the older of the
/// last write and last change times. A time in 1601 means none
fn file_times(path: &str) -> SourceTimes {
    let Ok(metadata) = std::fs::symlink_metadata(path) else { return SourceTimes::default() };
    let from_unix = |seconds: i64, nanos: i64| -> Option<Timestamp> {
        let stamp = Timestamp(621_355_968_000_000_000 + seconds * 10_000_000 + nanos / 100);
        (stamp.parts().year != 1601).then_some(stamp)
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let modified = (metadata.mtime(), metadata.mtime_nsec());
        let changed = (metadata.ctime(), metadata.ctime_nsec());
        let created = modified.min(changed);
        SourceTimes { created: from_unix(created.0, created.1), modified: from_unix(modified.0, modified.1), accessed: from_unix(metadata.atime(), metadata.atime_nsec()) }
    }
    #[cfg(not(unix))]
    {
        let time = |t: std::io::Result<std::time::SystemTime>| t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).and_then(|d| from_unix(d.as_secs() as i64, i64::from(d.subsec_nanos())));
        SourceTimes { created: time(metadata.created()), modified: time(metadata.modified()), accessed: time(metadata.accessed()) }
    }
}

fn parse(raw: &[u8], source_file: Option<&str>, code_page: i32, check_text_mode: bool) -> LnkResult<LnkFile> {
    let mut errors = Vec::new();
    let (header, raws) = Header::read(raw)?;
    let mut file = LnkFile {
        source_file: None,
        source: SourceTimes::default(),
        header: header.clone(),
        target_ids: Vec::new(),
        extra_blocks: Vec::new(),
        location_flags: 0,
        volume_info: None,
        network_share_info: None,
        local_path: None,
        common_path: None,
        name: None,
        relative_path: None,
        working_directory: None,
        arguments: None,
        icon_location: None,
        parse_errors: Vec::new(),
    };
    if let Some(path) = source_file.filter(|p| !p.is_empty()) {
        file.source_file = Some(ez_common::cli::full_path(path));
        // FileInfo: of the link itself, for a link
        if !Path::new(path).is_dir() || std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink()) {
            file.source = file_times(path);
        }
    }
    let out_of_range = |t: Timestamp, name: &str, raw_value: i64, errors: &mut Vec<String>| {
        if t == Timestamp::MIN {
            errors.push(format!("Target {name} time is out of range (raw 0x{raw_value:016X})"));
        }
    };
    out_of_range(header.target_created, "creation", raws[0], &mut errors);
    out_of_range(header.target_modified, "modification", raws[2], &mut errors);
    out_of_range(header.target_accessed, "last access", raws[1], &mut errors);
    if !SHOW_WINDOW.iter().any(|(_, v, _)| *v == i64::from(header.show_window)) {
        errors.push(format!("ShowCommand 0x{:X} is not a defined SW_* value (treated as SW_SHOWNORMAL)", header.show_window));
    }
    let mut index = HEADER_SIZE as i64;
    let unicode = header.has_flag(IS_UNICODE);
    if header.has_flag(HAS_TARGET_ID_LIST) {
        let size = i64::from(read_u16(raw, index, "LinkTargetIDList size")?);
        index += 2;
        ensure_range(raw, index, size, "LinkTargetIDList", -1)?;
        file.target_ids = parse_id_list(raw, index, index + size, code_page, &mut errors);
        index += size;
    }
    if header.has_flag(HAS_LINK_INFO) {
        let size = read_u32(raw, index, "LinkInfo size", -1)?;
        if size < 0x1c {
            return Err(LnkError::parse(format!("Invalid location item data size ({size}) - is this file corrupt?"), index as i32, "LinkInfoSize"));
        }
        ensure_range(raw, index, i64::from(size), "LinkInfo", -1)?;
        let info = parse_link_info(raw, index, i64::from(size), code_page, &mut errors)?;
        file.location_flags = info.flags;
        file.volume_info = info.volume;
        file.local_path = info.local_path;
        file.network_share_info = info.network;
        file.common_path = Some(info.common_path);
        index += i64::from(size);
    }
    if header.has_flag(HAS_NAME) {
        file.name = Some(read_string_data(raw, &mut index, unicode, code_page, "NAME_STRING")?);
    }
    if header.has_flag(HAS_RELATIVE_PATH) {
        file.relative_path = Some(read_string_data(raw, &mut index, unicode, code_page, "RELATIVE_PATH")?);
    }
    if header.has_flag(HAS_WORKING_DIR) {
        file.working_directory = Some(read_string_data(raw, &mut index, unicode, code_page, "WORKING_DIR")?);
    }
    if header.has_flag(HAS_ARGUMENTS) {
        file.arguments = Some(read_string_data(raw, &mut index, unicode, code_page, "COMMAND_LINE_ARGUMENTS")?);
    }
    if header.has_flag(HAS_ICON_LOCATION) {
        file.icon_location = Some(read_string_data(raw, &mut index, unicode, code_page, "ICON_LOCATION")?);
    }
    let mut terminated = false;
    while index + 4 <= raw.len() as i64 {
        let block_size = i64::from(u32::from_le_bytes(raw[index as usize..index as usize + 4].try_into().unwrap()));
        if block_size < 4 {
            terminated = true;
            index += 4;
            break;
        }
        let available = raw.len() as i64 - index;
        if block_size < 8 || block_size > available {
            let bytes = slice(raw, index, available, "ExtraData block", -1)?;
            errors.push(format!("Extra data block at offset {index} declares {block_size} bytes but {available} remain"));
            file.extra_blocks.push(ExtraBlock::read(bytes, code_page));
            index = raw.len() as i64;
            break;
        }
        file.extra_blocks.push(ExtraBlock::read(slice(raw, index, block_size, "ExtraData block", -1)?, code_page));
        index += block_size;
    }
    let trailing = raw.len() as i64 - index;
    if !terminated && trailing == 0 {
        errors.push("ExtraData has no terminal block".to_string());
    } else if trailing > 0 {
        let count = ez_common::dotnet::n0(trailing as u64);
        errors.push(if terminated { format!("{count} bytes of data follow the ExtraData terminal block (offset {index})") } else { format!("ExtraData has no terminal block; {count} unparsed bytes at offset {index}") });
    }
    for block in &file.extra_blocks {
        if let ExtraBlock::Damaged(damaged) = block {
            errors.push(format!("Extra data block {}: {}", damaged.original_signature_text(), damaged.error_message));
        }
    }
    for block in &file.extra_blocks {
        if let ExtraBlock::VistaAndAboveIdList { parse_errors, .. } = block {
            errors.extend(parse_errors.iter().map(|e| format!("VistaAndAboveIDListDataBlock: {e}")));
        }
    }
    if !errors.is_empty() && check_text_mode {
        if let Some(text) = describe_text_mode_damage(raw, code_page) {
            errors.push(text);
        }
    }
    file.parse_errors = errors;
    Ok(file)
}
