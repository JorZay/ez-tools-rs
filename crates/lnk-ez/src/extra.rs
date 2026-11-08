//! The extra data blocks of a link.

use ez_common::Timestamp;
use ez_common::json::Value;
use ez_common::net::flags_name;
use shellitems_ez::ShellItem;
use shellitems_ez::sheet::PropertyStore;
use shellitems_ez::utils::{description_from_guid_and_key, guid_name, guid_text};

use crate::{LnkError, LnkResult, parse_id_list, read_ansi_z, read_unicode_z};

const FILL_ATTRIBUTES: &[(&str, i64)] = &[
    ("ForegroundBlue", 1),
    ("ForegroundGreen", 2),
    ("ForegroundRed", 4),
    ("ForegroundIntensity", 8),
    ("BackgroundBlue", 0x10),
    ("BackgroundGreen", 0x20),
    ("BackgroundRed", 0x40),
    ("BackgroundIntensity", 0x80),
];

/// ConsoleDataBlock
#[derive(Clone, Debug)]
pub struct ConsoleData {
    pub fill_attributes: String,
    pub popup_fill_attributes: String,
    pub screen_width_buffer_size: i16,
    pub screen_height_buffer_size: i16,
    pub window_width: i16,
    pub window_height: i16,
    pub window_origin_x: i16,
    pub window_origin_y: i16,
    pub font_size: u32,
    pub is_bold: bool,
    pub face_name: String,
    pub cursor_size: &'static str,
    pub is_full_screen: bool,
    pub is_quick_edit: bool,
    pub is_insert_mode: bool,
    pub is_auto_positioned: bool,
    pub history_buffer_size: u32,
    pub history_buffer_count: u32,
    pub history_duplicates_allowed: bool,
    pub fill_attributes_raw: u16,
    pub popup_fill_attributes_raw: u16,
    pub reserved0: i32,
    pub reserved1: i32,
    pub font_width: u32,
    pub font_family: u32,
    pub font_pitch: u32,
    pub font_weight: u32,
    pub cursor_size_raw: u32,
    pub color_table: Vec<u32>,
}

/// DamagedDataBlock
#[derive(Clone, Debug)]
pub struct DamagedData {
    pub original_signature: u32,
    pub original_data: Vec<u8>,
    pub error_message: String,
}

impl DamagedData {
    /// OriginalSignature.ToString()
    pub fn original_signature_text(&self) -> String {
        match self.original_signature {
            0 => "DamagedDataBlock",
            0xa0000002 => "ConsoleDataBlock",
            0xa0000004 => "ConsoleFeDataBlock",
            0xa0000006 => "DarwinDataBlock",
            0xa0000001 => "EnvironmentVariableDataBlock",
            0xa0000007 => "IconEnvironmentDataBlock",
            0xa000000b => "KnownFolderDataBlock",
            0xa0000009 => "PropertyStoreDataBlock",
            0xa0000008 => "ShimDataBlock",
            0xa0000005 => "SpecialFolderDataBlock",
            0xa0000003 => "TrackerDataBlock",
            0xa000000c => "VistaAndAboveIdListDataBlock",
            other => return other.to_string(),
        }
        .to_string()
    }
}

/// TrackerDataBaseBlock
#[derive(Clone, Debug)]
pub struct TrackerData {
    pub machine_id: String,
    pub volume_droid: String,
    pub file_droid: String,
    pub volume_droid_birth: String,
    pub file_droid_birth: String,
    /// The file droid's byte 7 shows a version 1 UUID, the only kind with a time and a MAC address
    pub is_time_based: bool,
    pub mac_address: String,
    pub creation_time: Timestamp,
    pub length: u32,
    pub version: i32,
}

#[derive(Clone, Debug)]
pub enum ExtraBlock {
    Console(ConsoleData),
    ConsoleFe { code_page: u32 },
    Darwin { application_identifier_ascii: String, application_identifier_unicode: String, product_code: String, feature_name: String, component_id: String },
    EnvironmentVariable { ascii: String, unicode: String },
    IconEnvironment { ascii: String, unicode: String },
    KnownFolder { id: String, name: String, offset: u32 },
    PropertyStore(PropertyStore),
    Shim { layer_name: String },
    SpecialFolder { id: u32, offset: u32 },
    Tracker(TrackerData),
    VistaAndAboveIdList { target_ids: Vec<ShellItem>, parse_errors: Vec<String> },
    Damaged(DamagedData),
}

fn require_size(raw: &[u8], minimum: usize, name: &str) -> LnkResult<()> {
    if raw.len() < minimum {
        return Err(LnkError::parse(format!("{name} must be at least 0x{minimum:X} bytes but is 0x{:X} - is this file corrupt?", raw.len()), 0, name));
    }
    Ok(())
}

const BASE85: &str = "!$%&'()*+,-.0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~";

fn quad_to_hex(quad: &[u16]) -> LnkResult<i32> {
    let mut value = 0i32;
    for i in (0..5).rev() {
        let found = char::from_u32(u32::from(quad[i])).and_then(|c| BASE85.find(c));
        let Some(found) = found else {
            let text = String::from_utf16_lossy(&quad[i..=i]);
            return Err(LnkError::parse(format!("Invalid character '{text}' in Darwin descriptor"), -1, "DarwinData"));
        };
        value = value.wrapping_add(found as i32);
        if i > 0 {
            value = value.wrapping_mul(85);
        }
    }
    Ok(value)
}

fn flip(text: &str) -> String {
    (0..4).rev().map(|i| &text[i * 2..i * 2 + 2]).collect()
}

fn darwin_to_guid(raw: &[u16]) -> LnkResult<String> {
    let chunks = [quad_to_hex(&raw[0..5])?, quad_to_hex(&raw[5..10])?, quad_to_hex(&raw[10..15])?, quad_to_hex(&raw[15..20])?];
    let block2 = format!("{:08X}", chunks[1]);
    let b3 = flip(&format!("{:08X}", chunks[2]));
    let b4 = flip(&format!("{:08X}", chunks[3]));
    Ok(format!("{{{:08X}-{}-{}-{}-{}{b4}}}", chunks[0], &block2[4..], &block2[..4], &b3[..4], &b3[4..]))
}

fn darwin(raw: &[u8], code_page: i32) -> LnkResult<ExtraBlock> {
    require_size(raw, 0x314, "DarwinDataBlock")?;
    let ascii = read_ansi_z(raw, 8, code_page, "DarwinDataAnsi", 8 + 260)?;
    let unicode = read_unicode_z(raw, 268, "DarwinDataUnicode", 268 + 520)?;
    let (mut product, mut feature, mut component) = ("(None)".to_string(), "(None)".to_string(), "(None)".to_string());
    let descriptor = if ascii.is_empty() { &unicode } else { &ascii };
    let separator = if descriptor.contains('<') { '<' } else { '>' };
    let mut parts = descriptor.split(separator);
    let left: Vec<u16> = parts.next().unwrap_or_default().encode_utf16().collect();
    if left.len() >= 20 {
        product = darwin_to_guid(&left[..20])?;
        if left.len() > 20 {
            feature = String::from_utf16_lossy(&left[20..]);
        }
    }
    if let Some(right) = parts.next() {
        let right: Vec<u16> = right.encode_utf16().collect();
        if right.len() >= 20 {
            component = darwin_to_guid(&right[..20])?;
        }
    }
    Ok(ExtraBlock::Darwin { application_identifier_ascii: ascii, application_identifier_unicode: unicode, product_code: product, feature_name: feature, component_id: component })
}

fn tracker(raw: &[u8], code_page: i32) -> LnkResult<ExtraBlock> {
    require_size(raw, 0x60, "TrackerDataBlock")?;
    let machine_id = read_ansi_z(raw, 16, code_page, "MachineID", 16 + 16)?;
    let guid = |at: usize| ez_common::net::guid(raw[at..at + 16].try_into().unwrap());
    let file = &raw[0x30..0x40];
    let mac_address = file[10..].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&file[..8]);
    let is_time_based = bytes[7] >> 4 == 1;
    bytes[7] &= 0x0f;
    let gregorian = Timestamp::from_parts(1582, 10, 15, 0, 0, 0, 0).expect("a valid date").ticks();
    let ticks = i64::from_le_bytes(bytes).wrapping_add(gregorian);
    if !(0..=ez_common::time::MAX_TICKS).contains(&ticks) {
        return Err(plain_error("Ticks must be between DateTime.MinValue.Ticks and DateTime.MaxValue.Ticks. (Parameter 'ticks')".to_string()));
    }
    Ok(ExtraBlock::Tracker(TrackerData {
        machine_id,
        volume_droid: guid(0x20),
        file_droid: guid(0x30),
        volume_droid_birth: guid(0x40),
        file_droid_birth: guid(0x50),
        is_time_based,
        mac_address,
        creation_time: Timestamp(ticks),
        length: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
        version: i32::from_le_bytes(raw[12..16].try_into().unwrap()),
    }))
}

fn console(raw: &[u8]) -> LnkResult<ExtraBlock> {
    require_size(raw, 0xcc, "ConsoleDataBlock")?;
    let u16_at = |at: usize| u16::from_le_bytes(raw[at..at + 2].try_into().unwrap());
    let i16_at = |at: usize| u16_at(at) as i16;
    let u32_at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
    let cursor = u32_at(108);
    Ok(ExtraBlock::Console(ConsoleData {
        fill_attributes: flags_name(i64::from(u16_at(8)), FILL_ATTRIBUTES),
        popup_fill_attributes: flags_name(i64::from(u16_at(10)), FILL_ATTRIBUTES),
        screen_width_buffer_size: i16_at(12),
        screen_height_buffer_size: i16_at(14),
        window_width: i16_at(16),
        window_height: i16_at(18),
        window_origin_x: i16_at(20),
        window_origin_y: i16_at(22),
        font_size: u32::from(u16_at(34)),
        is_bold: u32_at(40) >= 700,
        face_name: read_unicode_z(raw, 44, "FaceName", 44 + 64)?,
        cursor_size: if cursor <= 25 { "Small" } else if cursor <= 50 { "Normal" } else { "Large" },
        is_full_screen: u32_at(112) > 0,
        is_quick_edit: u32_at(116) > 0,
        is_insert_mode: u32_at(120) > 0,
        is_auto_positioned: u32_at(124) > 0,
        history_buffer_size: u32_at(128),
        history_buffer_count: u32_at(132),
        history_duplicates_allowed: u32_at(136) == 0,
        fill_attributes_raw: u16_at(8),
        popup_fill_attributes_raw: u16_at(10),
        reserved0: u32_at(24) as i32,
        reserved1: u32_at(28) as i32,
        font_width: u32::from(u16_at(32)),
        font_family: u32_at(36) & 0xf0,
        font_pitch: u32_at(36) & 0x0f,
        font_weight: u32_at(40),
        cursor_size_raw: cursor,
        color_table: (0..16).map(|i| u32_at(140 + i * 4)).collect(),
    }))
}

fn plain_error(message: String) -> LnkError {
    LnkError { exception: format!("System.Exception: {message}"), message, offset: -1, field: None, read_error: false }
}

impl ExtraBlock {
    /// ParseExtraBlock: what can't be read is a damaged block
    pub(crate) fn read(block: &[u8], code_page: i32) -> ExtraBlock {
        let parsed = (|| -> LnkResult<ExtraBlock> {
            if block.len() < 8 {
                return Err(LnkError::parse(format!("Extra data block is only {} bytes", block.len()), 0, "ExtraData block"));
            }
            let signature = u32::from_le_bytes(block[4..8].try_into().unwrap());
            let u32_at = |at: usize| u32::from_le_bytes(block[at..at + 4].try_into().unwrap());
            Ok(match signature {
                0xa0000003 => tracker(block, code_page)?,
                0xa0000002 => console(block)?,
                0xa0000004 => {
                    require_size(block, 0x0c, "ConsoleFEDataBlock")?;
                    ExtraBlock::ConsoleFe { code_page: u32_at(8) }
                }
                0xa0000006 => darwin(block, code_page)?,
                0xa0000001 => {
                    require_size(block, 0x314, "EnvironmentVariableDataBlock")?;
                    ExtraBlock::EnvironmentVariable { ascii: read_ansi_z(block, 8, code_page, "TargetAnsi", 8 + 260)?, unicode: read_unicode_z(block, 268, "TargetUnicode", 268 + 520)? }
                }
                0xa0000007 => {
                    require_size(block, 0x314, "IconEnvironmentDataBlock")?;
                    ExtraBlock::IconEnvironment { ascii: read_ansi_z(block, 8, code_page, "TargetAnsi", 8 + 260)?, unicode: read_unicode_z(block, 268, "TargetUnicode", 268 + 520)? }
                }
                0xa000000b => {
                    require_size(block, 0x1c, "KnownFolderDataBlock")?;
                    let id = guid_text(&block[8..24]).map_err(plain_error)?;
                    ExtraBlock::KnownFolder { name: guid_name(&id), id, offset: u32_at(24) }
                }
                0xa0000009 => {
                    require_size(block, 0x0c, "PropertyStoreDataBlock")?;
                    ExtraBlock::PropertyStore(PropertyStore::read(&block[8..]).map_err(plain_error)?)
                }
                0xa0000008 => {
                    require_size(block, 0x88, "ShimDataBlock")?;
                    ExtraBlock::Shim { layer_name: read_unicode_z(block, 8, "LayerName", -1)? }
                }
                0xa0000005 => {
                    require_size(block, 0x10, "SpecialFolderDataBlock")?;
                    ExtraBlock::SpecialFolder { id: u32_at(8), offset: u32_at(12) }
                }
                0xa000000c => {
                    require_size(block, 0x0a, "VistaAndAboveIDListDataBlock")?;
                    let mut parse_errors = Vec::new();
                    let target_ids = parse_id_list(block, 8, block.len() as i64, code_page, &mut parse_errors);
                    ExtraBlock::VistaAndAboveIdList { target_ids, parse_errors }
                }
                other => return Err(LnkError::parse(format!("Unknown extra data block signature: 0x{other:X}. Please send lnk file to saericzimmerman@gmail.com so support can be added"), 4, "BlockSignature")),
            })
        })();
        match parsed {
            Ok(b) => b,
            Err(e) => {
                let original_signature = if block.len() >= 8 { u32::from_le_bytes(block[4..8].try_into().unwrap()) } else { 0 };
                ExtraBlock::Damaged(DamagedData { original_signature, original_data: block.to_vec(), error_message: e.message })
            }
        }
    }

    /// GetType().Name
    pub fn class_name(&self) -> &'static str {
        match self {
            ExtraBlock::Console(_) => "ConsoleDataBlock",
            ExtraBlock::ConsoleFe { .. } => "ConsoleFeDataBlock",
            ExtraBlock::Darwin { .. } => "DarwinDataBlock",
            ExtraBlock::EnvironmentVariable { .. } => "EnvironmentVariableDataBlock",
            ExtraBlock::IconEnvironment { .. } => "IconEnvironmentDataBlock",
            ExtraBlock::KnownFolder { .. } => "KnownFolderDataBlock",
            ExtraBlock::PropertyStore(_) => "PropertyStoreDataBlock",
            ExtraBlock::Shim { .. } => "ShimDataBlock",
            ExtraBlock::SpecialFolder { .. } => "SpecialFolderDataBlock",
            ExtraBlock::Tracker(_) => "TrackerDataBaseBlock",
            ExtraBlock::VistaAndAboveIdList { .. } => "VistaAndAboveIdListDataBlock",
            ExtraBlock::Damaged(_) => "DamagedDataBlock",
        }
    }

    /// The properties ServiceStack serializes, with the type name it adds for an ExtraDataBase
    pub fn to_value(&self) -> Value {
        let text = |s: &String| Value::text(s.as_str());
        let mut list = vec![("__type", Value::text(format!("Lnk.ExtraData.{}, Lnk", self.class_name())))];
        list.extend::<Vec<(&'static str, Value)>>(match self {
            ExtraBlock::Console(c) => {
                let family = match c.font_family {
                    0x00 => "Dontcare".to_string(),
                    0x10 => "Roman".to_string(),
                    0x20 => "Swiss".to_string(),
                    0x30 => "Modern".to_string(),
                    0x40 => "Script".to_string(),
                    0x50 => "Decorative".to_string(),
                    other => other.to_string(),
                };
                vec![
                    ("FillAttributes", Value::number(c.fill_attributes_raw)),
                    ("PopupFillAttributes", Value::number(c.popup_fill_attributes_raw)),
                    ("ScreenWidthBufferSize", Value::number(c.screen_width_buffer_size)),
                    ("ScreenHeightBufferSize", Value::number(c.screen_height_buffer_size)),
                    ("WindowWidth", Value::number(c.window_width)),
                    ("WindowHeight", Value::number(c.window_height)),
                    ("WindowOriginX", Value::number(c.window_origin_x)),
                    ("WindowOriginY", Value::number(c.window_origin_y)),
                    ("Reserved0", Value::number(c.reserved0)),
                    ("Reserved1", Value::number(c.reserved1)),
                    ("FontSize", Value::number(c.font_size)),
                    ("FontWidth", Value::number(c.font_width)),
                    ("FontFamily", Value::Text(family)),
                    ("FontPitch", Value::number(c.font_pitch)),
                    ("FontWeight", Value::number(c.font_weight)),
                    ("IsBold", Value::Bool(c.is_bold)),
                    ("FaceName", text(&c.face_name)),
                    ("CursorSize", Value::text(c.cursor_size)),
                    ("CursorSizeRaw", Value::number(c.cursor_size_raw)),
                    ("IsFullScreen", Value::Bool(c.is_full_screen)),
                    ("IsQuickEdit", Value::Bool(c.is_quick_edit)),
                    ("IsInsertMode", Value::Bool(c.is_insert_mode)),
                    ("IsAutoPositioned", Value::Bool(c.is_auto_positioned)),
                    ("HistoryBufferSize", Value::number(c.history_buffer_size)),
                    ("HistoryBufferCount", Value::number(c.history_buffer_count)),
                    ("HistoryDuplicatesAllowed", Value::Bool(c.history_duplicates_allowed)),
                    ("ColorTable", Value::List(c.color_table.iter().map(Value::number).collect())),
                ]
            }
            ExtraBlock::ConsoleFe { code_page } => vec![("CodePage", Value::number(code_page))],
            ExtraBlock::Darwin { application_identifier_ascii, application_identifier_unicode, product_code, feature_name, component_id } => vec![
                ("FeatureName", text(feature_name)),
                ("ComponentId", text(component_id)),
                ("ProductCode", text(product_code)),
                ("ApplicationIdentifierAscii", text(application_identifier_ascii)),
                ("ApplicationIdentifierUnicode", text(application_identifier_unicode)),
            ],
            ExtraBlock::EnvironmentVariable { ascii, unicode } => vec![("EnvironmentVariablesAscii", text(ascii)), ("EnvironmentVariablesUnicode", text(unicode))],
            ExtraBlock::IconEnvironment { ascii, unicode } => vec![("IconPathAscii", text(ascii)), ("IconPathUni", text(unicode))],
            ExtraBlock::KnownFolder { id, name, offset } => vec![("Offset", Value::number(offset)), ("KnownFolderId", Value::guid(id)), ("KnownFolderName", text(name))],
            ExtraBlock::PropertyStore(store) => vec![("PropertyStore", store.to_value())],
            ExtraBlock::Shim { layer_name } => vec![("LayerName", text(layer_name))],
            ExtraBlock::SpecialFolder { id, offset } => vec![("SpecialFolderId", Value::number(id)), ("Offset", Value::number(offset))],
            ExtraBlock::Tracker(t) => vec![
                ("CreationTime", Value::time(t.creation_time)),
                ("Length", Value::number(t.length)),
                ("Version", Value::number(t.version)),
                ("MachineId", text(&t.machine_id)),
                ("VolumeDroid", Value::guid(&t.volume_droid)),
                ("FileDroid", Value::guid(&t.file_droid)),
                ("VolumeDroidBirth", Value::guid(&t.volume_droid_birth)),
                ("FileDroidBirth", Value::guid(&t.file_droid_birth)),
                ("MacAddress", text(&t.mac_address)),
            ],
            ExtraBlock::VistaAndAboveIdList { target_ids, parse_errors } => vec![("ParseErrors", Value::strings(parse_errors)), ("TargetIDs", Value::List(target_ids.iter().map(ShellItem::to_value).collect()))],
            ExtraBlock::Damaged(d) => vec![("OriginalSignature", Value::text(d.original_signature_text())), ("OriginalData", Value::bytes(&d.original_data)), ("ErrorMessage", text(&d.error_message))],
        });
        Value::object(list)
    }

    /// ToString()
    pub fn to_text(&self) -> String {
        let yes = |b: bool| if b { "True" } else { "False" };
        match self {
            ExtraBlock::Console(c) => format!(
                "Console data block\r\nFill Attributes: {}\r\nPopup Attributes: {}\r\nBuffer Size (Width x Height): {} x {}\r\nWindow Size (Width x Height): {} x {}\r\nOrigin (X/Y): {}/{}\r\nFont Size: {}\r\nIs Bold: {}\r\nFace Name: {}\r\nCursor Size: {}\r\nIs Full Screen: {}\r\nIs Quick Edit: {}\r\nIs Insert Mode: {}\r\nIs Auto Positioned: {}\r\nHistory Buffer Size: {}\r\nHistory Buffer Count: {}\r\nHistory Duplicates Allowed: {}",
                c.fill_attributes, c.popup_fill_attributes, c.screen_width_buffer_size, c.screen_height_buffer_size, c.window_width, c.window_height, c.window_origin_x, c.window_origin_y, c.font_size,
                yes(c.is_bold), c.face_name, c.cursor_size, yes(c.is_full_screen), yes(c.is_quick_edit), yes(c.is_insert_mode), yes(c.is_auto_positioned), c.history_buffer_size, c.history_buffer_count, yes(c.history_duplicates_allowed)
            ),
            ExtraBlock::ConsoleFe { code_page } => format!("Console FE data block\r\nCodePage: {code_page}"),
            ExtraBlock::Darwin { application_identifier_ascii, product_code, feature_name, component_id, .. } => {
                format!("Darwin data block\r\nRaw data: {application_identifier_ascii}, Product code: {product_code}, Feature name: {feature_name}, ComponentId: {component_id}")
            }
            ExtraBlock::EnvironmentVariable { ascii, unicode } => format!("Environment variable data block\r\nEnvironment variables Ascii: {ascii}\r\nEnvironment variables unicode: {unicode}"),
            ExtraBlock::IconEnvironment { ascii, unicode } => format!("Icon environment data block\r\nIcon path: {ascii}\r\nIcon path (Unicode): {unicode}"),
            ExtraBlock::KnownFolder { id, name, .. } => format!("Known folder data block\r\nKnown folder GUID: {id} ({name})"),
            ExtraBlock::PropertyStore(store) => {
                let mut s = String::new();
                if !store.sheets.is_empty() {
                    s.push_str("Property store data block (Format: GUID\\ID Description ==> Value)\r\n");
                    let mut count = 0;
                    for sheet in &store.sheets {
                        for (key, value) in &sheet.property_names {
                            count += 1;
                            let prefix = pad_right(&format!("{}\\{key}", sheet.guid), 43);
                            let name = match key.parse::<i32>() {
                                Ok(k) => description_from_guid_and_key(&sheet.guid, k),
                                Err(_) => key.clone(),
                            };
                            s.push_str(&format!("{prefix} {} ==> {value}\r\n", pad_right(&name, 35)));
                        }
                    }
                    if count == 0 {
                        s.push_str("(Property store is empty)\r\n");
                    }
                }
                s
            }
            ExtraBlock::Shim { layer_name } => format!("Shimcache data block\r\nLayerName: {layer_name}"),
            ExtraBlock::SpecialFolder { id, .. } => format!("Special folder data block\r\nSpecialFolderID: {id}"),
            ExtraBlock::Tracker(t) => format!(
                "Tracker database block\r\nMachine ID: {}\r\nMac Address: {}\r\nCreation: {}\r\nVolume Droid: {}\r\nVolume Droid Birth: {}\r\nFile Droid: {}\r\nFile Droid birth: {}",
                t.machine_id, t.mac_address, t.creation_time.format("M/d/yyyy h:mm:ss tt K"), t.volume_droid, t.volume_droid_birth, t.file_droid, t.file_droid_birth
            ),
            ExtraBlock::VistaAndAboveIdList { target_ids, .. } => {
                let mut s = "Vista and above ID List data block\r\n".to_string();
                for item in target_ids {
                    s.push_str(&item.to_text());
                    s.push_str("\r\n");
                }
                s
            }
            ExtraBlock::Damaged(d) => format!("Damaged data block\r\nOriginal Signature: {}\r\nErrorMessage: {}", d.original_signature_text(), d.error_message),
        }
    }
}

/// string.PadRight
pub fn pad_right(text: &str, width: usize) -> String {
    let length = text.encode_utf16().count();
    if length >= width { text.to_string() } else { format!("{text}{}", " ".repeat(width - length)) }
}

