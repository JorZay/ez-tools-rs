//! Windows Recycle Bin files, as Eric Zimmerman's RecycleBin library reads them: `$I` files (`$Recycle.Bin`, Vista and
//! later) and `INFO2` files (`RECYCLER`, Windows 95 to XP/2003). Damaged data is parsed as far as it goes: only data too
//! small or of another format is an error, and other problems are listed in `parse_errors`.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use ez_common::Timestamp;
use ez_common::cli::{full_path, io_message};
use ez_common::net::{ascii, utf16};

const DOLLAR_I_HEADER: usize = 24;
const FORMAT1_NAME_SIZE: usize = 520;
const INFO2_HEADER: usize = 20;

/// Size of an INFO2 record without the UTF-16 path (Windows 95/98/ME)
pub const ANSI_RECORD_SIZE: i32 = 280;
/// Size of an INFO2 record with the UTF-16 path (Windows NT 4 to XP/2003)
pub const UNICODE_RECORD_SIZE: i32 = 800;

/// The data can't be used: it's too small or not of a known format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub offset: usize,
    pub field: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

fn i32_at(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i64_at(b: &[u8], at: usize) -> i64 {
    i64::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3], b[at + 4], b[at + 5], b[at + 6], b[at + 7]])
}

/// Text up to the first NUL
fn until_nul(mut text: String) -> String {
    if let Some(end) = text.find('\0') {
        text.truncate(end);
    }
    text
}

/// A FILETIME. One out of range goes to `errors` and becomes the earliest time
fn from_file_time(raw: i64, offset: usize, field: &str, errors: &mut Vec<String>) -> Timestamp {
    Timestamp::from_filetime(raw).unwrap_or_else(|| {
        errors.push(format!("{field} at 0x{offset:X} is out of range (0x{raw:016X})"));
        Timestamp::MIN
    })
}

/// A file in the `$R` folder of a deleted folder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirFileInfo {
    /// Its path under the deleted folder's, with Windows' separator
    pub file_name: String,
    pub file_size: i64,
}

/// A `$I` file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DollarI {
    /// 1 (Vista to 8.1) or 2 (Windows 10/11)
    pub format: i64,
    /// Size of the deleted file or folder
    pub file_size: i64,
    /// Original path of the deleted file or folder
    pub filename: String,
    pub source_name: String,
    /// When the deleted item is a folder, the files in its `$R` folder
    pub directory_files: Vec<DirFileInfo>,
    /// The earliest time when the stored value is out of range
    pub deleted_on: Timestamp,
    pub parse_errors: Vec<String>,
}

impl DollarI {
    /// Parses a `$I` file. When `$RXXXXXX` next to `source_name` (`$IXXXXXX`) is a folder, its files are listed, the only
    /// use of the file system here
    pub fn parse(raw: &[u8], source_name: &str) -> Result<DollarI, ParseError> {
        if raw.len() < DOLLAR_I_HEADER {
            return Err(ParseError {
                message: format!("File is {} bytes, smaller than the {DOLLAR_I_HEADER} byte $I header", raw.len()),
                offset: 0,
                field: "Header",
            });
        }
        let format = i64_at(raw, 0);
        if format != 1 && format != 2 {
            return Err(ParseError { message: format!("Unsupported $I format {format}. Expected 1 or 2"), offset: 0, field: "Format" });
        }
        let mut parse_errors = Vec::new();
        let deleted_on = from_file_time(i64_at(raw, 16), 16, "Deletion time", &mut parse_errors);
        let filename = if format == 1 { format1_name(raw, &mut parse_errors) } else { format2_name(raw, &mut parse_errors) };
        let directory_files = directory_files(source_name, &filename, &mut parse_errors);
        Ok(DollarI { format, file_size: i64_at(raw, 8), filename, source_name: source_name.to_string(), directory_files, deleted_on, parse_errors })
    }
}

fn format1_name(raw: &[u8], errors: &mut Vec<String>) -> String {
    let available = raw.len() - DOLLAR_I_HEADER;
    if available < FORMAT1_NAME_SIZE {
        errors.push(format!("File name at 0x{DOLLAR_I_HEADER:X} is {available} bytes, shorter than the {FORMAT1_NAME_SIZE} bytes of format 1"));
    }
    let length = available.min(FORMAT1_NAME_SIZE) & !1;
    until_nul(utf16(&raw[DOLLAR_I_HEADER..DOLLAR_I_HEADER + length]))
}

fn format2_name(raw: &[u8], errors: &mut Vec<String>) -> String {
    let name_offset = DOLLAR_I_HEADER + 4;
    if raw.len() < name_offset {
        errors.push(format!("File is too short for the file name length at 0x{DOLLAR_I_HEADER:X}"));
        return String::new();
    }
    let stored = i32_at(raw, DOLLAR_I_HEADER);
    let available = (raw.len() - name_offset) / 2;
    let length = match usize::try_from(stored) {
        Ok(length) if length <= available => length,
        _ => {
            errors.push(format!("File name length at 0x{DOLLAR_I_HEADER:X} is {stored} characters, but only {available} remain"));
            available
        }
    };
    until_nul(utf16(&raw[name_offset..name_offset + length * 2]))
}

fn directory_files(source_name: &str, filename: &str, errors: &mut Vec<String>) -> Vec<DirFileInfo> {
    // .NET resolves `..` before it looks, so a folder before it needn't exist
    let full = full_path(source_name);
    let source = Path::new(&full);
    let Some(name) = source.file_name().map(|n| n.to_string_lossy()) else {
        return Vec::new();
    };
    let is_dollar_i = name.get(..2).is_some_and(|start| start.eq_ignore_ascii_case("$I"));
    if !is_dollar_i {
        return Vec::new();
    }
    let dir_name = source.parent().unwrap_or(Path::new("")).join(format!("$R{}", &name[2..]));
    if !dir_name.is_dir() {
        return Vec::new();
    }
    match list_files(&dir_name) {
        Ok(files) => files.into_iter().map(|(relative, file_size)| DirFileInfo { file_name: format!("{filename}{relative}"), file_size }).collect(),
        Err((path, e)) => {
            errors.push(format!("Unable to list the files in '{}': {}", dir_name.display(), error_text(&path, &e)));
            Vec::new()
        }
    }
}

fn error_text(path: &Path, e: &io::Error) -> String {
    let text = io_message(path, e);
    text.rfind(" (os error").map_or_else(|| text.clone(), |end| text[..end].to_string())
}

/// Directory.GetFiles(folder, "*", AllDirectories): each folder's files in NTFS order, as on Windows, then the
/// folders found, in turn. Links to folders are followed, and a link's size is its own. All or nothing, as a failure there
/// is an exception. Paths are relative, with `\`
fn list_files(root: &Path) -> Result<Vec<(String, i64)>, (PathBuf, io::Error)> {
    let mut queue = VecDeque::from([(root.to_path_buf(), String::new())]);
    let mut files = Vec::new();
    while let Some((folder, relative)) = queue.pop_front() {
        let entries = ez_common::cli::read_dir_ntfs_order(&folder).map_err(|e| (folder.clone(), e))?;
        for entry in entries {
            let path = entry.path();
            let child = format!("{relative}\\{}", entry.file_name().to_string_lossy());
            if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                queue.push_back((path, child));
            } else {
                let size = std::fs::symlink_metadata(&path).map_err(|e| (path.clone(), e))?.len();
                files.push((child, size as i64));
            }
        }
    }
    Ok(files)
}

/// A record of an INFO2 file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub file_name_unicode: String,
    /// Empty when `removed`, as the first byte has been cleared
    pub file_name_ascii: String,
    pub index: i32,
    /// The drive the file was deleted from: 0 is A:, 2 is C:
    pub drive_number: i32,
    /// The earliest time when the stored value is out of range
    pub deleted_on: Timestamp,
    pub file_size: i32,
    /// The file is no longer in the Recycle Bin (restored, or the bin was emptied): Windows clears the first byte of the
    /// ANSI path and leaves the rest of the record
    pub removed: bool,
}

/// An INFO2 file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info2 {
    pub version: i32,
    pub unknown1: i32,
    pub unknown2: i32,
    pub file_entry_size: i32,
    pub unknown3: i32,
    pub source_name: String,
    pub file_records: Vec<FileRecord>,
    pub parse_errors: Vec<String>,
}

impl Info2 {
    pub fn parse(raw: &[u8], source_name: &str) -> Result<Info2, ParseError> {
        if raw.len() < INFO2_HEADER {
            return Err(ParseError {
                message: format!("File is {} bytes, smaller than the {INFO2_HEADER} byte INFO2 header", raw.len()),
                offset: 0,
                field: "Header",
            });
        }
        let file_entry_size = i32_at(raw, 12);
        if file_entry_size < ANSI_RECORD_SIZE {
            return Err(ParseError {
                message: format!("Record size {file_entry_size} is smaller than the {ANSI_RECORD_SIZE} byte minimum"),
                offset: 12,
                field: "FileEntrySize",
            });
        }
        let mut parse_errors = Vec::new();
        if file_entry_size != ANSI_RECORD_SIZE && file_entry_size != UNICODE_RECORD_SIZE {
            parse_errors.push(format!("Unexpected record size {file_entry_size} (expected {ANSI_RECORD_SIZE} or {UNICODE_RECORD_SIZE})"));
        }
        let size = file_entry_size as usize;
        let mut file_records = Vec::new();
        let mut index = INFO2_HEADER;
        while raw.len() - index >= size {
            file_records.push(read_record(raw, index, size, &mut parse_errors));
            index += size;
        }
        if index < raw.len() {
            parse_errors.push(format!("{} trailing byte(s) at 0x{index:X} are too short for a {file_entry_size} byte record", raw.len() - index));
        }
        Ok(Info2 {
            version: i32_at(raw, 0),
            unknown1: i32_at(raw, 4),
            unknown2: i32_at(raw, 8),
            file_entry_size,
            unknown3: i32_at(raw, 16),
            source_name: source_name.to_string(),
            file_records,
            parse_errors,
        })
    }
}

fn read_record(raw: &[u8], at: usize, size: usize, errors: &mut Vec<String>) -> FileRecord {
    let file_name_unicode = if size >= UNICODE_RECORD_SIZE as usize { until_nul(utf16(&raw[at + 280..at + 800])) } else { String::new() };
    FileRecord {
        file_name_unicode,
        file_name_ascii: until_nul(ascii(&raw[at..at + 260])),
        index: i32_at(raw, at + 260),
        drive_number: i32_at(raw, at + 264),
        deleted_on: from_file_time(i64_at(raw, at + 268), at + 268, "Deletion time", errors),
        file_size: i32_at(raw, at + 276),
        removed: raw[at] == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Not a real path, so no $R folder is looked at
    const NAME: &str = "memory";
    const TIME: i64 = 132_224_078_450_000_000;

    fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn dollar_i1(name: &str, time: i64, name_bytes: usize) -> Vec<u8> {
        let mut d = Vec::new();
        for v in [1, 1234, time] {
            d.extend_from_slice(&i64::to_le_bytes(v));
        }
        let mut text = wide(name);
        text.resize(520, 0);
        d.extend_from_slice(&text[..name_bytes]);
        d
    }

    fn dollar_i2(name: &str, length: Option<i32>) -> Vec<u8> {
        let mut d = Vec::new();
        for v in [2, 1234, TIME] {
            d.extend_from_slice(&i64::to_le_bytes(v));
        }
        let text = wide(&format!("{name}\0"));
        d.extend_from_slice(&length.unwrap_or((text.len() / 2) as i32).to_le_bytes());
        d.extend_from_slice(&text);
        d
    }

    fn info2(size: i32, records: &[(&str, bool)]) -> Vec<u8> {
        let mut d = Vec::new();
        for v in [if size == 280 { 4 } else { 5 }, 0, 0, size, 0] {
            d.extend_from_slice(&i32::to_le_bytes(v));
        }
        for (n, (name, removed)) in records.iter().enumerate() {
            let mut r = vec![0u8; size as usize];
            r[..name.len()].copy_from_slice(name.as_bytes());
            if *removed {
                r[0] = 0;
            }
            r[260..264].copy_from_slice(&(n as i32 + 1).to_le_bytes());
            r[264..268].copy_from_slice(&2i32.to_le_bytes());
            r[268..276].copy_from_slice(&TIME.to_le_bytes());
            r[276..280].copy_from_slice(&4096i32.to_le_bytes());
            if size >= 800 {
                let text = wide(name);
                r[280..280 + text.len()].copy_from_slice(&text);
            }
            d.extend_from_slice(&r);
        }
        d
    }

    #[test]
    fn dollar_i_too_small_or_of_another_format() {
        for size in [0, 8, 23] {
            assert_eq!(DollarI::parse(&vec![0; size], NAME).unwrap_err().field, "Header");
        }
        for format in [0i64, 3, -1] {
            let mut d = dollar_i2("C:\\a.txt", None);
            d[..8].copy_from_slice(&format.to_le_bytes());
            assert_eq!(DollarI::parse(&d, NAME).unwrap_err().field, "Format");
        }
    }

    #[test]
    fn format1_truncated_name_keeps_what_is_there() {
        let di = DollarI::parse(&dollar_i1("C:\\short.txt", TIME, 41), NAME).unwrap();
        assert_eq!(di.filename, "C:\\short.txt");
        assert_eq!(di.parse_errors, ["File name at 0x18 is 41 bytes, shorter than the 520 bytes of format 1"]);
    }

    #[test]
    fn format2_bad_name_length_is_reported_and_clamped() {
        for length in [-1, i32::MIN, i32::MAX, 500] {
            let di = DollarI::parse(&dollar_i2("C:\\file.txt", Some(length)), NAME).unwrap();
            assert_eq!(di.filename, "C:\\file.txt");
            assert_eq!(di.parse_errors, [format!("File name length at 0x18 is {length} characters, but only 12 remain")]);
        }
    }

    #[test]
    fn format2_without_name_length_is_reported() {
        let di = DollarI::parse(&dollar_i2("x", None)[..26], NAME).unwrap();
        assert_eq!(di.filename, "");
        assert_eq!(di.parse_errors.len(), 1);
    }

    #[test]
    fn out_of_range_time_is_reported() {
        for time in [-1, i64::MAX] {
            let di = DollarI::parse(&dollar_i1("C:\\a.txt", time, 520), NAME).unwrap();
            assert_eq!(di.deleted_on, Timestamp::MIN);
            assert_eq!(di.filename, "C:\\a.txt");
            assert_eq!(di.parse_errors.len(), 1);
            assert!(di.parse_errors[0].contains("Deletion time at 0x10"));
        }
    }

    #[test]
    fn deletion_time() {
        let di = DollarI::parse(&dollar_i1("C:\\a.txt", TIME, 520), NAME).unwrap();
        assert_eq!(di.deleted_on, Timestamp::from_parts(2020, 1, 2, 3, 4, 5, 0).unwrap());
    }

    #[test]
    fn info2_too_small_or_bad_record_size() {
        for size in [0, 19] {
            assert_eq!(Info2::parse(&vec![0; size], NAME).unwrap_err().field, "Header");
        }
        for size in [0, -800, 279] {
            let mut d = info2(800, &[]);
            d[12..16].copy_from_slice(&i32::to_le_bytes(size));
            assert_eq!(Info2::parse(&d, NAME).unwrap_err().field, "FileEntrySize");
        }
    }

    #[test]
    fn info2_ansi_records() {
        let i = Info2::parse(&info2(280, &[("C:\\WINDOWS\\a.txt", false), ("C:\\WINDOWS\\b.txt", true)]), NAME).unwrap();
        assert!(i.parse_errors.is_empty());
        let ascii: Vec<_> = i.file_records.iter().map(|r| r.file_name_ascii.as_str()).collect();
        assert_eq!(ascii, ["C:\\WINDOWS\\a.txt", ""]);
        assert!(i.file_records.iter().all(|r| r.file_name_unicode.is_empty()));
        assert_eq!(i.file_records.iter().map(|r| r.removed).collect::<Vec<_>>(), [false, true]);
    }

    #[test]
    fn info2_high_bytes_are_question_marks() {
        let mut d = info2(280, &[("C:\\caf_", false)]);
        d[INFO2_HEADER + 6] = 0xe9;
        assert_eq!(Info2::parse(&d, NAME).unwrap().file_records[0].file_name_ascii, "C:\\caf?");
    }

    #[test]
    fn info2_trailing_bytes_are_reported() {
        for extra in [1, 799] {
            let mut d = info2(800, &[("C:\\a.txt", false)]);
            d.extend(vec![0; extra]);
            let i = Info2::parse(&d, NAME).unwrap();
            assert_eq!(i.file_records.len(), 1);
            assert!(i.parse_errors[0].starts_with(&format!("{extra} trailing byte(s) at 0x334")), "{:?}", i.parse_errors);
        }
    }

    #[test]
    fn info2_unexpected_record_size_is_reported_and_used() {
        let i = Info2::parse(&info2(900, &[("C:\\a.txt", false), ("C:\\b.txt", false)]), NAME).unwrap();
        let names: Vec<_> = i.file_records.iter().map(|r| r.file_name_unicode.as_str()).collect();
        assert_eq!(names, ["C:\\a.txt", "C:\\b.txt"]);
        assert_eq!(i.parse_errors, ["Unexpected record size 900 (expected 280 or 800)"]);
    }

    #[test]
    fn info2_out_of_range_time_is_reported() {
        let mut d = info2(800, &[("C:\\a.txt", false)]);
        d[INFO2_HEADER + 268..INFO2_HEADER + 276].copy_from_slice(&(-5i64).to_le_bytes());
        let i = Info2::parse(&d, NAME).unwrap();
        assert_eq!(i.file_records[0].deleted_on, Timestamp::MIN);
        assert_eq!(i.parse_errors, ["Deletion time at 0x120 is out of range (0xFFFFFFFFFFFFFFFB)"]);
    }

    #[test]
    fn deleted_folder_files_come_from_the_r_folder() {
        let dir = std::env::temp_dir().join(format!("recyclebin-ez-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("$RABC.zip/sub")).unwrap();
        std::fs::write(dir.join("$RABC.zip/a.txt"), [0; 10]).unwrap();
        std::fs::write(dir.join("$RABC.zip/sub/b.txt"), [0; 3]).unwrap();
        let source = dir.join("$IABC.zip");
        let di = DollarI::parse(&dollar_i2("C:\\temp", None), source.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            di.directory_files,
            [DirFileInfo { file_name: "C:\\temp\\a.txt".into(), file_size: 10 }, DirFileInfo { file_name: "C:\\temp\\sub\\b.txt".into(), file_size: 3 }]
        );
    }

    #[test]
    fn corruption_never_panics() {
        // a small generator, so the test needs nothing else
        let mut seed = 7u64;
        let mut next = move |limit: usize| {
            seed = seed.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(1);
            ((seed >> 33) as usize) % limit.max(1)
        };
        let goods = [
            dollar_i1("C:\\Users\\test\\file.txt", TIME, 520),
            dollar_i2("C:\\Users\\test\\file.txt", None),
            info2(800, &[("C:\\a.txt", false), ("C:\\b.txt", true)]),
            info2(280, &[("C:\\a.txt", false)]),
        ];
        for good in &goods {
            for _ in 0..2000 {
                let mut data = good[..next(good.len() + 1)].to_vec();
                for _ in 0..next(6) {
                    if !data.is_empty() {
                        let at = next(data.len());
                        data[at] = next(256) as u8;
                    }
                }
                let _ = DollarI::parse(&data, NAME);
                let _ = Info2::parse(&data, NAME);
            }
        }
    }
}
