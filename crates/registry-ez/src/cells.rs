//! Key (nk), value (vk) and subkey list records. Like the Registry library, nk and vk fields are read from the
//! hive bytes where the record is; past the end of the record (or of the file) they are 0.

use std::cell::{Cell, OnceCell};

use ez_common::net::{self, NetResult};

pub const NK: i16 = 0x6b6e;
pub const VK: i16 = 0x6b76;
pub const SK: i16 = 0x6b73;
pub const LK: i16 = 0x6b6c;
pub const LF: i16 = 0x666c;
pub const LH: i16 = 0x686c;
pub const LI: i16 = 0x696c;
pub const RI: i16 = 0x6972;
pub const DB: i16 = 0x6264;
pub const HBIN: i32 = 0x6E696268;

/// nk flag HiveEntryRootKey
pub const KEY_HIVE_ENTRY_ROOT: u16 = 0x0004;
/// nk flag CompressedName
const KEY_COMPRESSED_NAME: u16 = 0x0020;

/// Helpers.AbsSize: the size of a cell (negative when allocated)
pub fn abs_size(v: i32) -> i32 {
    if v == i32::MIN { i32::MAX } else { v.abs() }
}

/// ReadBytesFromHive: up to `length` bytes at `offset` (fewer at the end of the file)
pub fn read_bytes(file: &[u8], offset: i64, length: i32) -> &[u8] {
    let len = abs_size(length) as i64;
    let remaining = file.len() as i64 - offset;
    if remaining <= 0 || offset < 0 {
        return &[];
    }
    let n = len.min(remaining) as usize;
    &file[offset as usize..offset as usize + n]
}

/// Helpers.Slice, with its exception
pub fn slice(b: &[u8], offset: i64, length: i64) -> NetResult<&[u8]> {
    if offset < 0 || length < 0 || offset + length > b.len() as i64 {
        return Err(format!(
            "0x{:X} bytes at 0x{:X} is outside the 0x{:X} bytes available (Parameter 'length')",
            length as i32, offset as i32, b.len()
        ));
    }
    Ok(&b[offset as usize..(offset + length) as usize])
}

/// Helpers.Latin1: "" when there is nothing at offset, the length clamped to the bytes there
pub fn latin1(b: &[u8], offset: i64, length: i64) -> String {
    if offset < 0 || length <= 0 || offset >= b.len() as i64 {
        return String::new();
    }
    let end = (offset + length).min(b.len() as i64) as usize;
    b[offset as usize..end].iter().map(|&c| c as char).collect()
}

/// A field of a record read in place: little-endian, 0 past the record or the file
fn field(rec: &[u8], offset: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in (0..n).rev() {
        v = (v << 8) | rec.get(offset + i).copied().unwrap_or(0) as u64;
    }
    v
}

/// NkCellRecord
#[derive(Debug)]
pub struct Nk {
    pub relative_offset: i64,
    pub raw_len: usize,
    pub size_raw: i32,
    pub flags: u16,
    pub last_write_raw: i64,
    pub access: i32,
    pub parent: u32,
    pub subkey_count_stable: u32,
    pub subkey_count_volatile: u32,
    pub subkey_list: u32,
    pub value_count: u32,
    pub value_list: u32,
    pub security: u32,
    pub class_cell: u32,
    pub max_name_length: u16,
    pub user_byte: u8,
    pub debug: u8,
    pub max_class_length: u32,
    pub max_value_name_length: u32,
    pub max_value_data_length: u32,
    pub work_var: u32,
    pub name_length: u16,
    pub class_length: u16,
    pub name: NetResult<String>,
    pub padding: Vec<u8>,
    pub referenced: Cell<bool>,
    pub deleted: Cell<bool>,
}

impl Nk {
    pub fn new(file: &[u8], record_size: usize, relative_offset: i64) -> Nk {
        let abs = relative_offset + 4096;
        let rec = read_bytes(file, abs, record_size as i32);
        let f = |o, n| field(rec, o, n);
        let size_raw = f(0, 4) as i32;
        let flags = f(6, 2) as u16;
        let name_length = f(0x4c, 2) as u16;
        let is_free = size_raw > 0;
        let nl = name_length as i64;
        let name = if flags & KEY_COMPRESSED_NAME != 0 {
            if is_free && (rec.len() as i64) < 0x50 + nl {
                Ok("(Unable to determine name)".into())
            } else {
                Ok(latin1(rec, 0x50, nl))
            }
        } else if is_free {
            if rec.len() as i64 >= 0x50 + nl {
                net::unicode_string(rec, 0x50, nl)
            } else {
                Ok("(Unable to determine name)".into())
            }
        } else {
            let count = (nl.min(rec.len() as i64 - 0x50)).max(0) / 2 * 2;
            net::unicode_string(rec, 0x50, count)
        };
        let padding = if is_free {
            vec![]
        } else {
            let po = 0x50 + nl as usize;
            let pl = po.div_ceil(8) * 8 - po;
            if pl > 0 && po + pl <= rec.len() { rec[po..po + pl].to_vec() } else { vec![] }
        };
        let none_if_ff = |v: u64| if v == 0xFFFFFFFF { 0 } else { v as u32 };
        Nk {
            relative_offset,
            raw_len: record_size,
            size_raw,
            flags,
            last_write_raw: f(8, 8) as i64,
            access: f(0x10, 4) as i32,
            parent: f(0x14, 4) as u32,
            subkey_count_stable: f(0x18, 4) as u32,
            subkey_count_volatile: f(0x1c, 4) as u32,
            subkey_list: none_if_ff(f(0x20, 4)),
            value_count: f(0x28, 4) as u32,
            value_list: none_if_ff(f(0x2c, 4)),
            security: f(0x30, 4) as u32,
            class_cell: none_if_ff(f(0x34, 4)),
            max_name_length: f(0x38, 2) as u16,
            user_byte: f(0x3a, 1) as u8,
            debug: f(0x3b, 1) as u8,
            max_class_length: f(0x3c, 4) as u32,
            max_value_name_length: f(0x40, 4) as u32,
            max_value_data_length: f(0x44, 4) as u32,
            work_var: f(0x48, 4) as u32,
            name_length,
            class_length: f(0x4e, 2) as u16,
            name,
            padding,
            referenced: Cell::new(false),
            deleted: Cell::new(false),
        }
    }

    pub fn is_free(&self) -> bool {
        self.size_raw > 0
    }

    pub fn size(&self) -> i32 {
        abs_size(self.size_raw)
    }

    pub fn absolute_offset(&self) -> i64 {
        self.relative_offset + 4096
    }

    /// LastWriteTimestamp: DateTimeOffset.FromFileTime, which throws for a value that is not a FILETIME
    pub fn last_write(&self) -> NetResult<ez_common::Timestamp> {
        filetime(self.last_write_raw)
    }

    /// The SubkeyListsVolatileCellIndex (0 for 0xFFFFFFFF)
    pub fn volatile_list(&self, file: &[u8]) -> u32 {
        let rec = read_bytes(file, self.absolute_offset(), self.raw_len as i32);
        let v = field(rec, 0x24, 4);
        if v == 0xFFFFFFFF { 0 } else { v as u32 }
    }
}

/// DateTimeOffset.FromFileTime(ts).ToUniversalTime()
pub fn filetime(ts: i64) -> NetResult<ez_common::Timestamp> {
    ez_common::Timestamp::from_filetime(ts).ok_or_else(|| "Not a valid Win32 FileTime. (Parameter 'fileTime')".to_string())
}

/// VkCellRecord.DataTypeEnum
pub const TYPE_NAMES: &[(&str, i64)] = &[
    ("RegBinary", 3),
    ("RegDword", 4),
    ("RegDwordBigEndian", 5),
    ("RegExpandSz", 2),
    ("RegFileTime", 0x10),
    ("RegFullResourceDescription", 9),
    ("RegLink", 6),
    ("RegMultiSz", 7),
    ("RegNone", 0),
    ("RegQword", 0xB),
    ("RegResourceList", 8),
    ("RegResourceRequirementsList", 0xA),
    ("RegSz", 1),
    ("RegUnknown", 999),
    ("RegUwpByte", 257),
    ("RegUwpInt16", 258),
    ("RegUwpUint16", 259),
    ("RegUwpInt32", 260),
    ("RegUwpUint32", 261),
    ("RegUwpInt64", 262),
    ("RegUwpUint64", 263),
    ("RegUwpSingle", 264),
    ("RegUwpDouble", 265),
    ("RegUwpChar", 266),
    ("RegUwpBoolean", 267),
    ("RegUwpString", 268),
    ("RegUwpCompositeValue", 269),
    ("RegUwpDateTimeOffset", 270),
    ("RegUwpTimeSpan", 271),
    ("RegUwpGuid", 272),
    ("RegUwpPoint", 273),
    ("RegUwpSize", 274),
    ("RegUwpRect", 275),
    ("RegUwpArrayByte", 276),
    ("RegUwpArrayInt16", 277),
    ("RegUwpArrayUint16", 278),
    ("RegUwpArrayInt32", 279),
    ("RegUwpArrayUint32", 280),
    ("RegUwpArrayInt64", 281),
    ("RegUwpArrayUint64", 282),
    ("RegUwpArraySingle", 283),
    ("RegUwpArrayDouble", 284),
    ("RegUwpArrayChar", 285),
    ("RegUwpArrayBoolean", 286),
    ("RegUwpArrayString", 287),
    ("RegUwpArrayDateTimeOffset", 288),
    ("RegUwpArrayTimeSpan", 289),
    ("RegUwpArrayGuid", 290),
    ("RegUwpArrayPoint", 291),
    ("RegUwpArraySize", 292),
    ("RegUwpArrayRect", 293),
];

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BE: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 0xB;
pub const REG_FILETIME: u32 = 0x10;
pub const REG_UNKNOWN: u32 = 999;

/// VkCellRecord
#[derive(Debug)]
pub struct Vk {
    pub relative_offset: i64,
    pub raw_len: usize,
    pub size_raw: i32,
    pub name_length: u16,
    pub data_length: u32,
    pub offset_to_data: u32,
    pub data_type_raw: u32,
    pub name_flag: u16,
    pub resident: bool,
    /// The data length without the resident bit
    pub length_internal: u32,
    /// DataType; ValueData changes a type that has no name to RegUnknown
    pub data_type: Cell<u32>,
    pub name: NetResult<String>,
    pub padding: Vec<u8>,
    pub referenced: Cell<bool>,
    /// The data block and where the data starts in it (0 for resident and big data, else 4)
    pub(crate) block: OnceCell<(Vec<u8>, u32)>,
}

impl Vk {
    pub fn new(file: &[u8], record_size: usize, relative_offset: i64) -> Vk {
        let abs = relative_offset + 4096;
        let rec = read_bytes(file, abs, record_size as i32);
        let f = |o, n| field(rec, o, n);
        let size_raw = f(0, 4) as i32;
        let name_length = f(6, 2) as u16;
        let data_length = f(8, 4) as u32;
        let data_type_raw = f(0x10, 4) as u32 & 0xFFF;
        let name_flag = f(0x14, 2) as u16;
        let resident = data_length & 0x80000000 != 0;
        let is_free = size_raw > 0;
        let nl = name_length as i64;
        let name = if name_length == 0 {
            Ok("(default)".to_string())
        } else if name_flag > 0 {
            if is_free && (rec.len() as i64) < nl + 0x18 {
                Ok("(Unable to determine name)".into())
            } else {
                Ok(latin1(rec, 0x18, nl))
            }
        } else if !is_free {
            let count = (nl.min(rec.len() as i64 - 0x18)).max(0) / 2 * 2;
            net::unicode_string(rec, 0x18, count)
        } else if rec.len() as i64 >= 0x18 + nl {
            // BitConverter.ToString then a regex for a byte followed by 00
            let b = &rec[0x18..0x18 + nl as usize];
            if b.windows(2).any(|w| w[1] == 0) { Ok(net::utf16(b)) } else { Ok("(Unable to determine name)".into()) }
        } else {
            Err("Destination array is not long enough to copy all the items in the collection. Check array index and length.".into())
        };
        let po = 0x18 + nl as usize;
        let pl = po.div_ceil(8) * 8 - po;
        let padding = if pl > 0 && po + pl <= rec.len() { rec[po..po + pl].to_vec() } else { vec![] };
        let data_type = if data_type_raw > 293 { REG_UNKNOWN } else { data_type_raw };
        Vk {
            relative_offset,
            raw_len: record_size,
            size_raw,
            name_length,
            data_length,
            offset_to_data: f(0xc, 4) as u32,
            data_type_raw,
            name_flag,
            resident,
            length_internal: if resident { data_length.wrapping_sub(0x80000000) } else { data_length },
            data_type: Cell::new(data_type),
            name,
            padding,
            referenced: Cell::new(false),
            block: OnceCell::new(),
        }
    }

    pub fn is_free(&self) -> bool {
        self.size_raw > 0
    }

    pub fn absolute_offset(&self) -> i64 {
        self.relative_offset + 4096
    }

    /// ValueType: the type's name, or its number when it has none
    pub fn type_name(&self) -> String {
        net::enum_name(self.data_type.get() as i64, TYPE_NAMES)
    }

    pub fn name(&self) -> NetResult<&str> {
        self.name.as_deref().map_err(|e| e.clone())
    }
}

/// The subkey lists (and db records, which are big data lists)
#[derive(Debug)]
pub enum List {
    /// lf and lh: the offsets (without duplicates)
    Lx(Vec<u32>, &'static str),
    Li(Vec<u32>),
    Ri(Vec<u32>),
    Db,
}

impl List {
    pub fn signature(&self) -> &'static str {
        match self {
            List::Lx(_, s) => s,
            List::Li(_) => "li",
            List::Ri(_) => "ri",
            List::Db => "db",
        }
    }

    pub fn new(sig: i16, raw: &[u8]) -> List {
        let count = u16::from_le_bytes([raw[6], raw[7]]) as usize;
        let u32_at = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap());
        match sig {
            LF | LH => {
                let mut offsets = Vec::new();
                let mut seen = std::collections::HashSet::new();
                let mut index = 8;
                for _ in 0..count {
                    if index + 8 > raw.len() {
                        break;
                    }
                    let os = u32_at(index);
                    index += 8;
                    if seen.insert(os) {
                        offsets.push(os);
                    }
                }
                List::Lx(offsets, if sig == LF { "lf" } else { "lh" })
            }
            LI => {
                let mut offsets = Vec::new();
                let mut index = 8;
                while offsets.len() < count && index + 4 <= raw.len() {
                    let os = u32_at(index);
                    index += 4;
                    if os == 0 {
                        break;
                    }
                    offsets.push(os);
                }
                List::Li(offsets)
            }
            RI => {
                let mut offsets = Vec::new();
                let mut index = 8;
                while offsets.len() < count && index + 4 <= raw.len() {
                    offsets.push(u32_at(index));
                    index += 4;
                }
                List::Ri(offsets)
            }
            _ => List::Db,
        }
    }
}

/// .NET's TimeSpan.ToString() ("c"): [-][d.]hh:mm:ss[.fffffff]
pub fn timespan(ticks: i64) -> String {
    let neg = ticks < 0;
    let t = (ticks as i128).abs();
    let days = t / 864_000_000_000;
    let rem = t % 864_000_000_000;
    let h = rem / 36_000_000_000;
    let m = rem / 600_000_000 % 60;
    let s = rem / 10_000_000 % 60;
    let f = rem % 10_000_000;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if days > 0 {
        out.push_str(&format!("{days}."));
    }
    out.push_str(&format!("{h:02}:{m:02}:{s:02}"));
    if f > 0 {
        out.push_str(&format!(".{f:07}"));
    }
    out
}

/// A float's ToString() with the en-US culture (ICU): infinities are ∞
pub fn float_text(v: f64, single: bool) -> String {
    if v.is_infinite() {
        return if v > 0.0 { "∞".into() } else { "-∞".into() };
    }
    if single { ez_common::dotnet::dotnet_f32(v as f32) } else { ez_common::dotnet::dotnet_f64(v) }
}

/// DateTimeOffset.ToString() with the en-US culture (ICU, which puts a narrow no-break space before AM/PM)
pub fn en_us_date(t: ez_common::Timestamp) -> String {
    t.format("M/d/yyyy h:mm:ss\u{202F}tt zzz")
}
