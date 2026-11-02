//! FILE record attributes, parsed as the MFT library parses them. A parser that fails returns the message of the
//! exception the original throws; the record keeps the attributes that parsed and lists the message in ParseErrors.

use ez_common::net::{
    self, NetResult, ascii_string, byte_at, copy, i16_at, i32_at, i64_at, u16_at, u32_at, u64_at, unicode_string,
};

use super::{MftEntryInfo, TimestampSource};
use crate::time::MAX_FILETIME;

pub mod types {
    pub const END_OF_ATTRIBUTES: i32 = -1;
    pub const STANDARD_INFORMATION: i32 = 0x10;
    pub const ATTRIBUTE_LIST: i32 = 0x20;
    pub const FILE_NAME: i32 = 0x30;
    pub const VOLUME_VERSION_OBJECT_ID: i32 = 0x40;
    pub const SECURITY_DESCRIPTOR: i32 = 0x50;
    pub const VOLUME_NAME: i32 = 0x60;
    pub const VOLUME_INFORMATION: i32 = 0x70;
    pub const DATA: i32 = 0x80;
    pub const INDEX_ROOT: i32 = 0x90;
    pub const INDEX_ALLOCATION: i32 = 0xA0;
    pub const BITMAP: i32 = 0xB0;
    pub const REPARSE_POINT: i32 = 0xC0;
    pub const EA_INFORMATION: i32 = 0xD0;
    pub const EA: i32 = 0xE0;
    pub const PROPERTY_SET: i32 = 0xF0;
    pub const LOGGED_UTILITY_STREAM: i32 = 0x100;
    pub const USER_DEFINED_ATTRIBUTE: i32 = 0x1000;
}

/// AttributeType's names, as .NET writes them
pub const ATTRIBUTE_TYPE_NAMES: &[(&str, i64)] = &[
    ("EndOfAttributes", -1),
    ("Unused", 0),
    ("StandardInformation", 0x10),
    ("AttributeList", 0x20),
    ("FileName", 0x30),
    ("VolumeVersionObjectId", 0x40),
    ("SecurityDescriptor", 0x50),
    ("VolumeName", 0x60),
    ("VolumeInformation", 0x70),
    ("Data", 0x80),
    ("IndexRoot", 0x90),
    ("IndexAllocation", 0xA0),
    ("Bitmap", 0xB0),
    ("ReparsePoint", 0xC0),
    ("EaInformation", 0xD0),
    ("Ea", 0xE0),
    ("PropertySet", 0xF0),
    ("LoggedUtilityStream", 0x100),
    ("UserDefinedAttribute", 0x1000),
];

pub fn attribute_type_name(t: i32) -> String {
    net::enum_name(t as i64, ATTRIBUTE_TYPE_NAMES)
}

/// $STANDARD_INFORMATION and $FILE_NAME flags (StandardInfo.Flag)
pub const SI_FLAG_NAMES: &[(&str, i64)] = &[
    ("None", 0x00),
    ("ReadOnly", 0x01),
    ("Hidden", 0x02),
    ("System", 0x04),
    ("VolumeLabel", 0x08),
    ("Directory", 0x010),
    ("Archive", 0x020),
    ("Device", 0x040),
    ("Normal", 0x080),
    ("Temporary", 0x0100),
    ("SparseFile", 0x0200),
    ("ReparsePoint", 0x0400),
    ("Compressed", 0x0800),
    ("Offline", 0x01000),
    ("NotContentIndexed", 0x02000),
    ("Encrypted", 0x04000),
    ("IntegrityStream", 0x08000),
    ("Virtual", 0x010000),
    ("NoScrubData", 0x020000),
    ("RecallOnOpen", 0x040000),
    ("RecallOnDataAccess", 0x400000),
    ("Pinned", 0x80000),
    ("UnPinned", 0x100000),
    ("IsDirectory", 0x10000000),
    ("IsIndexView", 0x20000000),
];

pub const NAME_TYPE_NAMES: &[(&str, i64)] = &[("Posix", 0), ("Windows", 1), ("Dos", 2), ("DosWindows", 3)];
pub const NAME_TYPE_DOS: u8 = 2;

/// FileTimes.Check: a FILETIME, or 0 (none) when it is not positive or past DateTime's range (with a warning)
fn check_time(raw: i64, field: &str, source: &TimestampSource, warnings: &mut Vec<String>) -> i64 {
    if raw <= 0 {
        return 0;
    }
    if raw > MAX_FILETIME {
        warnings.push(format!("Invalid {field} timestamp 0x{raw:016X} in {source}"));
        return 0;
    }
    raw
}

/// The attribute header (Attribute's constructor)
#[derive(Debug, Clone)]
pub struct AttributeHeader {
    pub attribute_type: i32,
    pub size: i32,
    pub content_length: i32,
    pub name_size: i32,
    pub name_offset: i16,
    pub data_flags: i16,
    pub name: String,
    pub number: i32,
    pub resident: bool,
    pub content_offset: i16,
}

impl AttributeHeader {
    fn parse(raw: &[u8]) -> NetResult<AttributeHeader> {
        let mut h = AttributeHeader {
            number: i16_at(raw, 0xE)? as i32,
            attribute_type: i32_at(raw, 0)?,
            size: i32_at(raw, 4)?,
            resident: byte_at(raw, 8)? == 0,
            name_size: byte_at(raw, 9)? as i32,
            name_offset: i16_at(raw, 0xA)?,
            data_flags: i16_at(raw, 0xC)?,
            content_length: i32_at(raw, 0x10)?,
            content_offset: i16_at(raw, 0x14)?,
            name: String::new(),
        };
        if h.name_size > 0 {
            h.name = unicode_string(raw, h.name_offset as i64, h.name_size as i64 * 2)?;
        }
        Ok(h)
    }

    fn content<'a>(&self, raw: &'a [u8]) -> NetResult<&'a [u8]> {
        copy(raw, self.content_offset as i64, self.content_length as i64)
    }
}

#[derive(Debug, Clone)]
pub struct DataRun {
    pub clusters_in_run: u64,
    pub cluster_offset: i64,
}

#[derive(Debug, Clone)]
pub struct NonResidentData {
    pub starting_vcn: u64,
    pub ending_vcn: u64,
    pub allocated_size: u64,
    pub actual_size: u64,
    pub initialized_size: u64,
    pub data_runs: Vec<DataRun>,
}

impl NonResidentData {
    pub(crate) fn parse(raw: &[u8]) -> NetResult<NonResidentData> {
        let mut n = NonResidentData {
            starting_vcn: u64_at(raw, 0x10)?,
            ending_vcn: u64_at(raw, 0x18)?,
            allocated_size: 0,
            actual_size: 0,
            initialized_size: 0,
            data_runs: Vec::new(),
        };
        let offset_to_runs = u16_at(raw, 0x20)?;
        n.allocated_size = u64_at(raw, 0x28)?;
        n.actual_size = u64_at(raw, 0x30)?;
        n.initialized_size = u64_at(raw, 0x38)?;
        let mut index = offset_to_runs as usize;
        let mut start = raw.get(index).copied().unwrap_or(0);
        while start != 0 {
            let offset_length = (start >> 4) as usize;
            let length_bytes = (start & 0x0F) as usize;
            index += 1;
            if length_bytes > 8 || offset_length > 8 || index + length_bytes + offset_length > raw.len() {
                break;
            }
            let mut len = [0u8; 8];
            len[..length_bytes].copy_from_slice(&raw[index..index + length_bytes]);
            index += length_bytes;
            let mut off = [0u8; 8];
            off[..offset_length].copy_from_slice(&raw[index..index + offset_length]);
            if offset_length > 0 && off[offset_length - 1] >= 0x80 {
                off[offset_length..].fill(0xFF);
            }
            index += offset_length;
            n.data_runs.push(DataRun { clusters_in_run: u64::from_le_bytes(len), cluster_offset: i64::from_le_bytes(off) });
            start = raw.get(index).copied().unwrap_or(0);
        }
        Ok(n)
    }
}

#[derive(Debug, Clone)]
pub struct StandardInfo {
    pub created: i64,
    pub content_modified: i64,
    pub record_modified: i64,
    pub last_accessed: i64,
    pub flags: i32,
    pub max_version: i32,
    pub flags2: i32,
    pub class_id: i32,
    pub owner_id: i32,
    pub security_id: i32,
    pub quota_charged: i32,
    pub update_sequence_number: i64,
}

impl StandardInfo {
    fn parse(raw: &[u8], source: &TimestampSource, w: &mut Vec<String>) -> NetResult<StandardInfo> {
        let s = source.with_attribute("$STANDARD_INFORMATION");
        let mut si = StandardInfo {
            created: check_time(i64_at(raw, 0x18)?, "CreatedOn", &s, w),
            content_modified: check_time(i64_at(raw, 0x20)?, "ContentModifiedOn", &s, w),
            record_modified: check_time(i64_at(raw, 0x28)?, "RecordModifiedOn", &s, w),
            last_accessed: check_time(i64_at(raw, 0x30)?, "LastAccessedOn", &s, w),
            flags: i32_at(raw, 0x38)?,
            max_version: i32_at(raw, 0x3C)?,
            flags2: i32_at(raw, 0x40)?,
            class_id: i32_at(raw, 0x44)?,
            owner_id: 0,
            security_id: 0,
            quota_charged: 0,
            update_sequence_number: 0,
        };
        if raw.len() <= 0x48 {
            return Ok(si);
        }
        si.owner_id = i32_at(raw, 0x48)?;
        si.security_id = i32_at(raw, 0x4C)?;
        si.quota_charged = i32_at(raw, 0x50)?;
        si.update_sequence_number = i64_at(raw, 0x58)?;
        Ok(si)
    }
}

/// $FILE_NAME's content (FileInfo)
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub parent: MftEntryInfo,
    pub created: i64,
    pub content_modified: i64,
    pub record_modified: i64,
    pub last_accessed: i64,
    pub physical_size: u64,
    pub logical_size: u64,
    pub flags: i32,
    pub reparse_value: i32,
    pub name_length: u8,
    pub name_type: u8,
    pub file_name: String,
}

impl FileInfo {
    pub(crate) fn parse(raw: &[u8], source: &TimestampSource, w: &mut Vec<String>) -> NetResult<FileInfo> {
        let parent = MftEntryInfo::parse(copy(raw, 0, 8).map_err(|_| block_copy_error(raw.len(), 0, 8))?);
        let created = check_time(i64_at(raw, 0x8)?, "CreatedOn", source, w);
        let content_modified = check_time(i64_at(raw, 0x10)?, "ContentModifiedOn", source, w);
        let record_modified = check_time(i64_at(raw, 0x18)?, "RecordModifiedOn", source, w);
        let last_accessed = check_time(i64_at(raw, 0x20)?, "LastAccessedOn", source, w);
        let physical_size = u64_at(raw, 0x28)?;
        let logical_size = u64_at(raw, 0x30)?;
        let flags = i32_at(raw, 0x38)?;
        let reparse_value = i32_at(raw, 0x3c)?;
        let name_length = byte_at(raw, 0x40)?;
        let name_type = byte_at(raw, 0x41)?;
        let file_name = unicode_string(raw, 0x42, name_length as i64 * 2)?;
        Ok(FileInfo {
            parent,
            created,
            content_modified,
            record_modified,
            last_accessed,
            physical_size,
            logical_size,
            flags,
            reparse_value,
            name_length,
            name_type,
            file_name,
        })
    }
}

/// Buffer.BlockCopy(src, offset, new byte[n], 0, n) into a fixed array: the error message
fn block_copy_error(src_len: usize, offset: i64, n: i64) -> String {
    net::block_copy_check(src_len, offset, n as usize, 0, n).err().unwrap_or_default()
}

/// Data, Bitmap, LoggedUtilityStream: resident bytes or non-resident runs
#[derive(Debug, Clone)]
pub struct DataContent {
    pub resident: Option<Vec<u8>>,
    pub non_resident: Option<NonResidentData>,
}

#[derive(Debug, Clone)]
pub struct ObjectId {
    pub object_id: [u8; 16],
    pub birth_volume_id: [u8; 16],
    pub birth_object_id: [u8; 16],
    pub domain_id: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct ReparsePoint {
    pub tag: Option<&'static str>,
    pub substitute_name: String,
    pub print_name: String,
    pub symlink_flag_relative: bool,
}

const REPARSE_TAGS: &[(u32, &str)] = &[
    (0x00000000, "ReservedZero"),
    (0x00000001, "ReservedOne"),
    (0x00000002, "ReservedTwo"),
    (0x80000005, "DriverExtender"),
    (0x80000006, "HierarchicalStorageManager2"),
    (0x80000007, "SisFilterDriver"),
    (0x80000008, "Wim"),
    (0x80000009, "Csv"),
    (0x8000000a, "DistributedFileSystem"),
    (0x8000000b, "FilterManagerTestHarness"),
    (0x80000012, "DistributedFileSystemR"),
    (0xa0000003, "MountPoint"),
    (0xa000000c, "SymbolicLink"),
    (0xc0000004, "HierarchicalStorageManager"),
    (0x80000013, "DeDupe"),
    (0x80000014, "Nfs"),
    (0x80000015, "FilePlaceHolder"),
    (0x80000017, "Wof"),
    (0x80000018, "Wci"),
    (0x80000019, "GlobalReparse"),
    (0x8000001B, "AppExeCLink"),
    (0x8000001E, "Hfs"),
    (0x80000020, "Unhandled"),
    (0x80000021, "OneDrive"),
    (0x9000001A, "Cloud"),
    (0x9000101A, "CloudRoot"),
    (0x9000201A, "CloudOnDemand"),
    (0x9000301A, "CloudRootOnDemand"),
    (0x9000001C, "Gvfs"),
    (0xA0000010, "IisCache"),
    (0xA0000019, "GlobalReparse"),
    (0xA000001D, "LxSymLink"),
    (0xA000001F, "WciTombstone"),
    (0xA0000022, "GvfsTombstone"),
    (0xC0000014, "AppXStrim"),
];

impl ReparsePoint {
    /// The tag's name; an unknown tag is ReservedZero (the enum's default)
    pub fn tag_name(&self) -> &'static str {
        self.tag.unwrap_or("ReservedZero")
    }

    fn parse(h: &AttributeHeader, raw: &[u8]) -> NetResult<ReparsePoint> {
        let mut r = ReparsePoint { tag: None, substitute_name: String::new(), print_name: String::new(), symlink_flag_relative: false };
        if h.content_length == 0 || h.content_length == 8 {
            return Ok(r);
        }
        let content = h.content(raw)?;
        let tag = u32_at(content, 0)?;
        r.tag = REPARSE_TAGS.iter().find(|(t, _)| *t == tag).map(|(_, n)| *n);
        let mut sub_offset = i16_at(content, 8)?;
        let sub_size = i16_at(content, 10)?;
        if sub_size == 0 {
            r.print_name = ascii_string(content, 0xc, content.len() as i64 - 0xc)?.trim_matches('\0').to_string();
            return Ok(r);
        }
        let mut print_offset = i16_at(content, 12)?;
        let print_size = i16_at(content, 14)?;
        let name = r.tag_name();
        if name != "SymbolicLink" && name != "MountPoint" {
            return Ok(r);
        }
        if name == "SymbolicLink" {
            if i32_at(content, 16)? == 1 {
                r.symlink_flag_relative = true;
            }
            sub_offset = sub_offset.wrapping_add(4);
        }
        if sub_size > 0 {
            sub_offset = if sub_offset == 0 { 0x10 } else { 0x14 };
            r.substitute_name = unicode_string(content, sub_offset as i64, sub_size as i64)?;
        }
        if print_size > 0 {
            print_offset = if print_offset == 0 {
                sub_offset.wrapping_add(sub_size)
            } else {
                sub_offset.wrapping_add(print_offset)
            };
            r.print_name = unicode_string(content, print_offset as i64, print_size as i64)?;
        }
        Ok(r)
    }
}

#[derive(Debug, Clone)]
pub struct AttributeInfo {
    pub first_vcn: u64,
    pub entry: MftEntryInfo,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttributeList {
    pub offset_to_data_run: u16,
    pub starting_vcn: u64,
    pub ending_vcn: u64,
    pub allocated_size: u64,
    pub actual_size: u64,
    pub initialized_size: u64,
    pub data_runs: Vec<DataRun>,
    pub infos: Vec<AttributeInfo>,
}

impl AttributeList {
    fn parse(h: &AttributeHeader, raw: &[u8]) -> NetResult<AttributeList> {
        let mut a = AttributeList {
            offset_to_data_run: 0,
            starting_vcn: 0,
            ending_vcn: 0,
            allocated_size: 0,
            actual_size: 0,
            initialized_size: 0,
            data_runs: Vec::new(),
            infos: Vec::new(),
        };
        if h.resident {
            let mut index = h.content_offset as i64;
            let end = (raw.len() as i64).min(h.content_offset as i64 + (h.content_length as i64).max(0));
            while end - index >= 0x1A {
                let size = u16_at(raw, index + 4)? as i64;
                if size < 0x1A || size > end - index {
                    break;
                }
                let buf = copy(raw, index, size)?;
                let mut entry = [0u8; 8];
                entry.copy_from_slice(&buf[0x10..0x18]);
                let name_size = buf[6] as i64;
                let name_offset = buf[7] as i64;
                let name = if name_size > 0 { Some(unicode_string(buf, name_offset, name_size * 2)?) } else { None };
                a.infos.push(AttributeInfo { first_vcn: u64_at(buf, 8)?, entry: MftEntryInfo::parse(&entry), name });
                index += size;
            }
        } else {
            a.starting_vcn = u64_at(raw, 0x10)?;
            a.ending_vcn = u64_at(raw, 0x18)?;
            a.offset_to_data_run = u16_at(raw, 0x20)?;
            a.allocated_size = u64_at(raw, 0x28)?;
            a.actual_size = u64_at(raw, 0x30)?;
            a.initialized_size = u64_at(raw, 0x38)?;
            let mut index = a.offset_to_data_run as usize;
            let mut another = raw.get(index).is_some_and(|&b| b > 0);
            while another {
                let start = raw[index];
                index += 1;
                let count_bytes = (start & 0x0F) as usize;
                let offset_bytes = (start >> 4) as usize;
                if count_bytes > 8 || offset_bytes > 8 || index + count_bytes + offset_bytes > raw.len() {
                    break;
                }
                let mut count = [0u8; 8];
                count[..count_bytes].copy_from_slice(&raw[index..index + count_bytes]);
                index += count_bytes;
                let mut off = [0u8; 8];
                off[..offset_bytes].copy_from_slice(&raw[index..index + offset_bytes]);
                index += offset_bytes;
                if offset_bytes > 0 && off[offset_bytes - 1] >= 0x80 {
                    off[offset_bytes..].fill(0xFF);
                }
                a.data_runs.push(DataRun { clusters_in_run: u64::from_le_bytes(count), cluster_offset: i64::from_le_bytes(off) });
                another = raw.get(index).is_some_and(|&b| b > 0);
            }
        }
        Ok(a)
    }
}

/// An index entry in $INDEX_ROOT (MFT.Other.IndexEntry)
#[derive(Debug, Clone, Default)]
pub struct IndexEntry {
    pub mft_reference: Option<MftEntryInfo>,
    pub parent: Option<MftEntryInfo>,
    pub created: i64,
    pub content_modified: i64,
    pub record_modified: i64,
    pub last_accessed: i64,
    pub physical_size: u64,
    pub logical_size: u64,
    pub flags: i32,
    pub reparse_value: i32,
    pub name_length: u8,
    pub name_type: u8,
    pub file_name: Option<String>,
}

impl IndexEntry {
    /// IndexEntry.FromEntry: a whole entry (the file reference, then the rest)
    fn from_entry(entry: &[u8], source: &TimestampSource, w: &mut Vec<String>) -> NetResult<IndexEntry> {
        let reference = MftEntryInfo::parse(copy(entry, 0, 8)?);
        let rest = copy(entry, 8, entry.len() as i64 - 8)?;
        let mut e = IndexEntry { mft_reference: Some(reference), ..Default::default() };
        let key_size = i16_at(rest, 2)?;
        let flags = i32_at(rest, 4)?;
        if flags & 2 == 2 || key_size == 0x10 || key_size <= 0x40 {
            return Ok(e);
        }
        let mut info = [0u8; 8];
        net::block_copy_check(rest.len(), 8, 8, 0, 8)?;
        info.copy_from_slice(&rest[8..16]);
        e.parent = Some(MftEntryInfo::parse(&info));
        e.created = check_time(i64_at(rest, 16)?, "CreatedOn", source, w);
        e.content_modified = check_time(i64_at(rest, 24)?, "ContentModifiedOn", source, w);
        e.record_modified = check_time(i64_at(rest, 32)?, "RecordModifiedOn", source, w);
        e.last_accessed = check_time(i64_at(rest, 40)?, "LastAccessedOn", source, w);
        e.physical_size = u64_at(rest, 48)?;
        e.logical_size = u64_at(rest, 56)?;
        e.flags = i32_at(rest, 64)?;
        e.reparse_value = i32_at(rest, 68)?;
        e.name_length = byte_at(rest, 72)?;
        e.name_type = byte_at(rest, 73)?;
        e.file_name = Some(unicode_string(rest, 74, e.name_length as i64 * 2)?);
        Ok(e)
    }
}

#[derive(Debug, Clone)]
pub struct IndexRoot {
    pub indexed_attribute_type: i32,
    pub collation_type: i32,
    pub entry_size: i32,
    pub number_cluster_blocks: i32,
    pub offset_to_first_index_entry: i32,
    pub total_size_of_index_entries: i32,
    pub allocated_size_of_entries: i32,
    pub flags: u8,
    pub entries: Vec<IndexEntry>,
    pub mft_record: Option<MftEntryInfo>,
}

impl IndexRoot {
    fn parse(h: &AttributeHeader, raw: &[u8], source: &TimestampSource, w: &mut Vec<String>) -> NetResult<IndexRoot> {
        let s = source.with_attribute("$INDEX_ROOT entry");
        let mut index = h.content_offset as i64;
        let mut r = IndexRoot {
            indexed_attribute_type: i32_at(raw, index)?,
            collation_type: i32_at(raw, index + 4)?,
            entry_size: i32_at(raw, index + 8)?,
            number_cluster_blocks: i32_at(raw, index + 12)?,
            offset_to_first_index_entry: i32_at(raw, index + 16)?,
            total_size_of_index_entries: i32_at(raw, index + 20)?,
            allocated_size_of_entries: i32_at(raw, index + 24)?,
            flags: byte_at(raw, index + 28)?,
            entries: Vec::new(),
            mft_record: None,
        };
        index += 32;
        while raw.len() as i64 - index >= 10 {
            let mut size = i16_at(raw, index + 8)? as i64;
            if size <= 0x10 {
                break;
            }
            if size > raw.len() as i64 - index {
                size = (raw.len() as i64 - index) as i16 as i64;
            }
            let buf = copy(raw, index, size)?;
            let e = IndexEntry::from_entry(buf, &s, w)?;
            if r.mft_record.is_none() {
                r.mft_record = e.mft_reference;
            }
            r.entries.push(e);
            index += size;
        }
        if r.mft_record.is_none() && raw.len() as i64 - index >= 8 {
            r.mft_record = Some(MftEntryInfo::parse(copy(raw, index, 8)?));
        }
        Ok(r)
    }
}

#[derive(Debug, Clone)]
pub struct SecurityDescriptorAttr {
    pub resident: Option<Vec<u8>>,
    pub non_resident: Option<NonResidentData>,
}

#[derive(Debug, Clone)]
pub struct VolumeInformation {
    pub unknown: [u8; 8],
    pub major_version: u8,
    pub minor_version: u8,
    pub flags: i16,
}

#[derive(Debug, Clone)]
pub struct EaInformation {
    pub ea_size: i16,
    pub need_ea_count: i16,
    pub ea_data_size: i32,
}

/// An extended attribute entry the library decodes
#[derive(Debug, Clone)]
pub enum EaItem {
    Lx { name: String },
    LongName { name: String },
    Lxattrb { values: [i32; 7], format: i16, version: i16, times: [i64; 3] },
    Lxattrr { format: i16, version: i16, key_values: Vec<(String, String)> },
    PurgeEsbCache { timestamp: i64, timestamp2: i64 },
    CatHint { format: i16, hint: String },
    AppFixCache { timestamp: i64, remaining: Vec<u8> },
    ClassInfo,
}

const INVALID_FILETIME: &str = "Not a valid Win32 FileTime. (Parameter 'fileTime')";
const INVALID_UNIX_SECONDS: &str = "Valid values are between -62135596800 and 253402300799, inclusive. (Parameter 'seconds')";

/// DateTimeOffset.FromFileTime's check
fn from_file_time(raw: i64) -> NetResult<i64> {
    if !(0..=MAX_FILETIME).contains(&raw) { Err(INVALID_FILETIME.into()) } else { Ok(raw) }
}

fn from_unix_seconds(s: i64) -> NetResult<i64> {
    if !(-62_135_596_800..=253_402_300_799).contains(&s) { Err(INVALID_UNIX_SECONDS.into()) } else { Ok(s) }
}

#[derive(Debug, Clone)]
pub struct ExtendedAttribute {
    pub content: Vec<u8>,
    pub items: Vec<EaItem>,
}

impl ExtendedAttribute {
    fn parse(h: &AttributeHeader, raw: &[u8]) -> NetResult<ExtendedAttribute> {
        let content = h.content(raw)?.to_vec();
        let mut items = Vec::new();
        let mut chunks: Vec<&[u8]> = Vec::new();
        let mut index = 0i64;
        while content.len() as i64 - index >= 8 {
            let size = i32_at(&content, index)? as i64;
            if size < 8 || size > content.len() as i64 - index {
                break;
            }
            chunks.push(&content[index as usize..(index + size) as usize]);
            index += size;
        }
        for b in chunks {
            if u32_at(b, 0)? == 0 {
                break;
            }
            let name_len = byte_at(b, 5)? as i64;
            u16_at(b, 6)?;
            let mut idx = 8i64;
            let mut name = unicode_string(b, idx, name_len)?;
            if byte_at(b, idx + 1)? != 0 {
                name = ascii_string(b, idx, name_len)?;
            }
            idx += name_len + 1;
            let rest_len = b.len() as i64 - idx;
            let rest = || copy(b, idx, rest_len);
            let item = match name.as_str() {
                "$LXUID" | "$LXGID" | "$LXMOD" => EaItem::Lx { name: format!("{name}: {}", net::hex(rest()?)) },
                ".LONGNAME" => {
                    let r = rest()?;
                    let size = i16_at(r, 2)? as i64;
                    EaItem::LongName { name: unicode_string(r, 4, size)? }
                }
                "LXATTRB" => {
                    let r = rest()?;
                    let mut values = [0i32; 7];
                    let format = i16_at(r, 0)?;
                    let version = i16_at(r, 2)?;
                    for (k, v) in values.iter_mut().enumerate() {
                        *v = i32_at(r, 4 + k as i64 * 4)?;
                    }
                    let mut times = [0i64; 3];
                    for (k, t) in times.iter_mut().enumerate() {
                        *t = from_unix_seconds(i64_at(r, 32 + k as i64 * 8)?)?;
                    }
                    EaItem::Lxattrb { values, format, version, times }
                }
                "LXXATTR" => {
                    let r = rest()?;
                    let format = i16_at(r, 0)?;
                    let version = i16_at(r, 2)?;
                    let mut i = 4i64;
                    let mut kv: Vec<(String, String)> = Vec::new();
                    while i < r.len() as i64 {
                        let next = i32_at(r, i)?;
                        i += 4;
                        let value_size = i16_at(r, i)? as i64;
                        i += 2;
                        let key_size = byte_at(r, i)? as i64;
                        i += 1;
                        let key = unicode_string(r, i, key_size)?;
                        i += key_size;
                        let value = unicode_string(r, i, value_size)?;
                        i += value_size + 1;
                        if kv.iter().any(|(k, _)| *k == key) {
                            return Err(format!("An item with the same key has already been added. Key: {key}"));
                        }
                        kv.push((key, value));
                        if next == 0 {
                            break;
                        }
                    }
                    EaItem::Lxattrr { format, version, key_values: kv }
                }
                "$KERNEL.PURGE.ESBCACHE" => {
                    let r = rest()?;
                    let timestamp = from_file_time(i64_at(r, 8)?)?;
                    let timestamp2 = from_file_time(i64_at(r, 16)?)?;
                    EaItem::PurgeEsbCache { timestamp, timestamp2 }
                }
                "$CI.CATALOGHINT" => {
                    let r = rest()?;
                    let format = i16_at(r, 0)?;
                    let size = i16_at(r, 2)? as i64;
                    EaItem::CatHint { format, hint: unicode_string(r, 4, size)? }
                }
                "$KERNEL.PURGE.APPFIXCACHE" | "$KERNEL.PURGE.APPXFICACHE" => {
                    let r = rest()?;
                    let raw_ts = i64_at(r, 0)?.max(0);
                    let timestamp = from_file_time(raw_ts)?;
                    EaItem::AppFixCache { timestamp, remaining: copy(r, 8, r.len() as i64 - 8)?.to_vec() }
                }
                ".CLASSINFO" => {
                    rest()?;
                    EaItem::ClassInfo
                }
                _ => continue,
            };
            items.push(item);
        }
        Ok(ExtendedAttribute { content, items })
    }
}

#[derive(Debug, Clone)]
pub enum AttributeBody {
    StandardInfo(StandardInfo),
    FileName(FileInfo),
    Data(DataContent),
    IndexAllocation(NonResidentData),
    IndexRoot(IndexRoot),
    Bitmap(DataContent),
    ObjectId(ObjectId),
    SecurityDescriptor(SecurityDescriptorAttr),
    VolumeName(String),
    VolumeInformation(VolumeInformation),
    LoggedUtilityStream(Vec<u8>),
    ReparsePoint(ReparsePoint),
    AttributeList(AttributeList),
    Ea(ExtendedAttribute),
    EaInformation(EaInformation),
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub header: AttributeHeader,
    pub body: AttributeBody,
}

impl Attribute {
    pub fn file_name(&self) -> Option<&FileInfo> {
        match &self.body {
            AttributeBody::FileName(f) => Some(f),
            _ => None,
        }
    }

    /// FileRecord.ParseAttribute: None for a type the library does not parse
    pub(crate) fn parse(ty: i32, raw: &[u8], source: &TimestampSource, w: &mut Vec<String>) -> NetResult<Option<Attribute>> {
        use types::*;
        if !matches!(
            ty,
            STANDARD_INFORMATION
                | FILE_NAME
                | DATA
                | INDEX_ALLOCATION
                | INDEX_ROOT
                | BITMAP
                | VOLUME_VERSION_OBJECT_ID
                | SECURITY_DESCRIPTOR
                | VOLUME_NAME
                | VOLUME_INFORMATION
                | LOGGED_UTILITY_STREAM
                | REPARSE_POINT
                | ATTRIBUTE_LIST
                | EA
                | EA_INFORMATION
        ) {
            return Ok(None);
        }
        let h = AttributeHeader::parse(raw)?;
        let body = match ty {
            STANDARD_INFORMATION => AttributeBody::StandardInfo(StandardInfo::parse(raw, source, w)?),
            FILE_NAME => {
                let content = copy(raw, h.content_offset as i64, raw.len() as i64 - h.content_offset as i64)?;
                AttributeBody::FileName(FileInfo::parse(content, &source.with_attribute("$FILE_NAME"), w)?)
            }
            DATA => AttributeBody::Data(data_content(&h, raw)?),
            BITMAP => AttributeBody::Bitmap(data_content(&h, raw)?),
            INDEX_ALLOCATION => AttributeBody::IndexAllocation(NonResidentData::parse(raw)?),
            INDEX_ROOT => AttributeBody::IndexRoot(IndexRoot::parse(&h, raw, source, w)?),
            VOLUME_VERSION_OBJECT_ID => {
                let d = h.content(raw)?;
                let mut o = ObjectId { object_id: [0; 16], birth_volume_id: [0; 16], birth_object_id: [0; 16], domain_id: [0; 16] };
                let g = |off: i64| -> NetResult<[u8; 16]> {
                    net::block_copy_check(d.len(), off, 16, 0, 16)?;
                    Ok(d[off as usize..off as usize + 16].try_into().unwrap())
                };
                o.object_id = g(0)?;
                if d.len() != 16 {
                    o.birth_volume_id = g(0x0A)?;
                    o.birth_object_id = g(0x20)?;
                    o.domain_id = g(0x30)?;
                }
                AttributeBody::ObjectId(o)
            }
            SECURITY_DESCRIPTOR => {
                let attr = if h.resident {
                    let d = h.content(raw)?.to_vec();
                    super::security::SkSecurityDescriptor::check(&d)?;
                    SecurityDescriptorAttr { resident: Some(d), non_resident: None }
                } else {
                    SecurityDescriptorAttr { resident: None, non_resident: Some(NonResidentData::parse(raw)?) }
                };
                AttributeBody::SecurityDescriptor(attr)
            }
            VOLUME_NAME => {
                let name = if raw.is_empty() {
                    String::new()
                } else {
                    unicode_string(raw, h.content_offset as i64, raw.len() as i64 - h.content_offset as i64)?
                        .trim_end_matches('\0')
                        .to_string()
                };
                AttributeBody::VolumeName(name)
            }
            VOLUME_INFORMATION => {
                let o = h.content_offset as i64;
                net::block_copy_check(raw.len(), o, 8, 0, 8)?;
                let mut unknown = [0u8; 8];
                unknown.copy_from_slice(&raw[o as usize..o as usize + 8]);
                AttributeBody::VolumeInformation(VolumeInformation {
                    unknown,
                    major_version: byte_at(raw, o + 8)?,
                    minor_version: byte_at(raw, o + 9)?,
                    flags: i16_at(raw, o + 0xA)?,
                })
            }
            LOGGED_UTILITY_STREAM => AttributeBody::LoggedUtilityStream(h.content(raw)?.to_vec()),
            REPARSE_POINT => AttributeBody::ReparsePoint(ReparsePoint::parse(&h, raw)?),
            ATTRIBUTE_LIST => AttributeBody::AttributeList(AttributeList::parse(&h, raw)?),
            EA => AttributeBody::Ea(ExtendedAttribute::parse(&h, raw)?),
            EA_INFORMATION => {
                let c = h.content(raw)?;
                AttributeBody::EaInformation(EaInformation {
                    ea_size: i16_at(c, 0)?,
                    need_ea_count: i16_at(c, 2)?,
                    ea_data_size: i32_at(c, 4)?,
                })
            }
            _ => unreachable!(),
        };
        Ok(Some(Attribute { header: h, body }))
    }
}

fn data_content(h: &AttributeHeader, raw: &[u8]) -> NetResult<DataContent> {
    if h.resident {
        Ok(DataContent { resident: Some(h.content(raw)?.to_vec()), non_resident: None })
    } else {
        Ok(DataContent { resident: None, non_resident: Some(NonResidentData::parse(raw)?) })
    }
}
