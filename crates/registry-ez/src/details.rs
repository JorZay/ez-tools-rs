//! RegistryKey.ToString(), with the en-US culture: what RECmd's --details shows, and what AmcacheParser logs for a key it could not parse.

use ez_common::dotnet::n0;
use ez_common::net;

use crate::cells::en_us_date;
use crate::hive::{Hive, KeyId, ValueObj, VkId};

const NK_FLAGS: &[(&str, i64)] = &[
    ("CompressedName", 0x0020),
    ("HiveEntryRootKey", 0x0004),
    ("HiveExit", 0x0002),
    ("NoDelete", 0x0008),
    ("PredefinedHandle", 0x0040),
    ("SymbolicLink", 0x0010),
    ("Unused0400", 0x0400),
    ("Unused0800", 0x0800),
    ("Unused1000", 0x1000),
    ("Unused2000", 0x2000),
    ("Unused4000", 0x4000),
    ("Unused8000", 0x8000),
    ("UnusedVolatileKey", 0x0001),
    ("VirtMirrored", 0x0080),
    ("VirtTarget", 0x0100),
    ("VirtualStore", 0x0200),
];
const KEY_FLAGS: &[(&str, i64)] = &[("Deleted", 1), ("HasActiveParent", 2)];

/// --details: RegistryKey.ToString()
pub fn key_text(hive: &Hive, k: KeyId) -> Result<String, String> {
    let mut sb = String::new();
    key_into(hive, k, &mut sb)?;
    Ok(sb)
}

fn key_into(hive: &Hive, k: KeyId, sb: &mut String) -> Result<(), String> {
    use std::fmt::Write;
    let key = &hive.keys[k];
    let nk = hive.nk(k);
    let date = en_us_date(nk.last_write()?);
    write!(sb, "Key Name: {}\r\n", hive.key_name(k)).unwrap();
    write!(sb, "Key Path: {}\r\n\r\n", key.path).unwrap();
    write!(sb, "Last Write Time: {date}\r\n\r\n").unwrap();
    write!(sb, "Key flags: {}\r\n\r\n", net::flags_name(key.flags as i64, KEY_FLAGS)).unwrap();
    // NkCellRecord.ToString()
    write!(sb, "NK Record: Size: 0x{:X}\r\n", nk.size()).unwrap();
    write!(sb, "Relative Offset: 0x{:X}\r\n", nk.relative_offset).unwrap();
    write!(sb, "Absolute Offset: 0x{:X}\r\n", nk.absolute_offset()).unwrap();
    write!(sb, "Signature: nk\r\n").unwrap();
    write!(sb, "Flags: {}\r\n\r\n", net::flags_name(nk.flags as i64, NK_FLAGS)).unwrap();
    write!(sb, "Name: {}\r\n\r\n", hive.key_name(k)).unwrap();
    write!(sb, "Last Write Timestamp: {date}\r\n\r\n").unwrap();
    write!(sb, "Is Free: {}\r\n\r\n", if nk.is_free() { "True" } else { "False" }).unwrap();
    write!(sb, "Debug: 0x{:X}\r\n\r\n", nk.debug).unwrap();
    write!(sb, "Maximum Class Length: 0x{:X}\r\n", nk.max_class_length).unwrap();
    write!(sb, "Class Cell Index: 0x{:X}\r\n", nk.class_cell).unwrap();
    write!(sb, "Class Length: 0x{:X}\r\n\r\n", nk.class_length).unwrap();
    write!(sb, "Maximum Value Data Length: 0x{:X}\r\n", nk.max_value_data_length).unwrap();
    write!(sb, "Maximum Value Name Length: 0x{:X}\r\n\r\n", nk.max_value_name_length).unwrap();
    write!(sb, "Name Length: 0x{:X}\r\n", nk.name_length).unwrap();
    write!(sb, "Maximum Name Length: 0x{:X}\r\n\r\n", nk.max_name_length).unwrap();
    write!(sb, "Parent Cell Index: 0x{:X}\r\n", nk.parent).unwrap();
    write!(sb, "Security Cell Index: 0x{:X}\r\n\r\n", nk.security).unwrap();
    write!(sb, "Subkey Counts Stable: 0x{:X}\r\n", nk.subkey_count_stable).unwrap();
    write!(sb, "Subkey Lists Stable Cell Index: 0x{:X}\r\n\r\n", nk.subkey_list).unwrap();
    write!(sb, "Subkey Counts Volatile: 0x{:X}\r\n\r\n", nk.subkey_count_volatile).unwrap();
    // the flags are the byte's binary digits read as a decimal number
    let bits = format!("{:08b}", nk.user_byte);
    let user: i64 = bits[..4].parse().unwrap();
    let virt: i64 = bits[4..].parse().unwrap();
    write!(sb, "User Flags: 0x{user:08X}\r\n").unwrap();
    write!(sb, "Virtual Control Flags: 0x{virt:08X}\r\n").unwrap();
    write!(sb, "Work Var: 0x{:X}\r\n\r\n", nk.work_var).unwrap();
    write!(sb, "Value Count: 0x{:X}\r\n", nk.value_count).unwrap();
    write!(sb, "Value List Cell Index: 0x{:X}\r\n", nk.value_list).unwrap();
    if !nk.padding.is_empty() {
        write!(sb, "\r\nPadding: {}\r\n", net::hex(&nk.padding)).unwrap();
    }
    write!(sb, "\r\n\r\n").unwrap();
    write!(sb, "SubKey count: {}\r\n", n0(key.subkeys.len() as u64)).unwrap();
    for (i, &sk) in key.subkeys.iter().enumerate() {
        write!(sb, "------------ SubKey #{i} ------------\r\n").unwrap();
        key_into(hive, sk, sb)?;
        sb.push_str("\r\n");
    }
    write!(sb, "\r\nValue count: {}\r\n", n0(key.values.len() as u64)).unwrap();
    for (i, &v) in key.values.iter().enumerate() {
        write!(sb, "------------ Value #{i} ------------\r\n").unwrap();
        write!(sb, "VK Record: {}\r\n", value_text(hive, v)?).unwrap();
        sb.push_str("\r\n");
    }
    Ok(())
}

/// The .NET type of ValueData's object for a type whose data is not bytes (for the cast's exception)
fn object_type(t: u32) -> &'static str {
    match t {
        258 => "System.Int16",
        259 => "System.UInt16",
        260 | 1 => "System.Int32",
        261 => "System.UInt32",
        262 | 270 => "System.Int64",
        263 => "System.UInt64",
        264 => "System.Single",
        265 => "System.Double",
        266 => "System.Char",
        267 => "System.Boolean",
        271 => "System.TimeSpan",
        272 => "System.Guid",
        _ => "System.String",
    }
}

/// VkCellRecord.ToString()
fn value_text(hive: &Hive, v: VkId) -> Result<String, String> {
    use std::fmt::Write;
    let vk = &hive.vks[v];
    let mut sb = String::new();
    write!(sb, "Size: 0x{:X}\r\n", vk.size_raw.unsigned_abs()).unwrap();
    write!(sb, "Relative Offset: 0x{:X}\r\n", vk.relative_offset).unwrap();
    write!(sb, "Absolute Offset: 0x{:X}\r\n", vk.absolute_offset()).unwrap();
    write!(sb, "Signature: vk\r\n").unwrap();
    write!(sb, "Data Type raw: 0x{:X}\r\n\r\n", vk.data_type_raw).unwrap();
    write!(sb, "Is Free: {}\r\n\r\n", if vk.is_free() { "True" } else { "False" }).unwrap();
    write!(sb, "Data Length: 0x{:X}\r\n", vk.data_length).unwrap();
    write!(sb, "Offset To Data: 0x{:X}\r\n\r\n", vk.offset_to_data).unwrap();
    write!(sb, "Name Length: 0x{:X}\r\n", vk.name_length).unwrap();
    write!(sb, "Name Present Flag: 0x{:X}\r\n\r\n", vk.name_flag).unwrap();
    if !vk.padding.is_empty() {
        write!(sb, "Padding: {}\r\n", net::hex(&vk.padding)).unwrap();
    }
    write!(sb, "\r\nValue Name: {}\r\n", vk.name()?).unwrap();
    let t = vk.data_type.get();
    write!(sb, "Value Type: {}\r\n", vk.type_name()).unwrap();
    let data = hive.value_data(v)?;
    let cast = |to: &str| match &data {
        ValueObj::Bytes(_) => format!("Unable to cast object of type 'System.Byte[]' to type '{to}'."),
        ValueObj::FileTime(_) => format!("Unable to cast object of type 'System.DateTimeOffset' to type '{to}'."),
        ValueObj::UInt(_) => format!("Unable to cast object of type 'System.UInt32' to type '{to}'."),
        ValueObj::Text(_) => format!("Unable to cast object of type '{}' to type '{to}'.", object_type(t)),
    };
    let shown = match t {
        1 | 2 | 7 | 6 => match &data {
            ValueObj::Bytes(_) => "System.Byte[]".to_string(),
            other => other.text(),
        },
        0 | 3 | 8 | 0xA | 9 => match &data {
            ValueObj::Bytes(b) => net::hex(b),
            _ => return Err(cast("System.Byte[]")),
        },
        0x10 => match &data {
            ValueObj::FileTime(d) => en_us_date(*d),
            _ => return Err(cast("System.DateTimeOffset")),
        },
        4 | 5 | 0xB => match &data {
            ValueObj::UInt(n) => format!("{}.000", n0(*n)),
            _ => "System.Byte[]".to_string(),
        },
        _ => match &data {
            ValueObj::Bytes(b) => net::hex(b),
            _ => return Err(cast("System.Byte[]")),
        },
    };
    write!(sb, "Value Data: {shown}\r\n").unwrap();
    write!(sb, "Value Data Slack: {}\r\n", net::hex(&hive.value_slack(v)?)).unwrap();
    Ok(sb)
}
