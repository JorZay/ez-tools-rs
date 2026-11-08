//! RecentFileCache.bcf, as RecentFileCacheParser's RecentFileCache library reads it: a 20 byte header (signature
//! 0xFFEEFFFE at 0x00, a CRC-32 at 0x10), then entries to the end of the file, each a 32-bit character count, that
//! many UTF-16LE characters and a NUL character.

use ez_common::Timestamp;
use ez_common::json::Value;

pub const SIGNATURE: u32 = 0xFFEE_FFFE;
/// The header's size, which is also where the first entry starts
pub const HEADER_SIZE: usize = 0x14;
const CHECKSUM_OFFSET: usize = 0x10;

/// What RecentFileCacheParseException holds: the data is too small or has a bad signature
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub offset: i32,
    pub field: &'static str,
}

/// The source file's times, as FileInfo gives them
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SourceTimes {
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecentFileCacheFile {
    /// Path.GetFullPath of the source
    pub source_file: String,
    pub source: SourceTimes,
    /// The CRC-32 in the header
    pub checksum: u32,
    /// The CRC-32 of the file without the 4 checksum bytes
    pub calculated_checksum: u32,
    /// In the order they are stored. An entry whose length runs past the end of the file is left out
    pub file_names: Vec<String>,
    /// A checksum mismatch, a damaged entry or unexpected data; parsing goes on where it can
    pub parse_errors: Vec<String>,
}

impl RecentFileCacheFile {
    /// RecentFileCache.LoadFile: the file read, with its times. Err(Ok) is a file that can't be read, Err(Err) one that
    /// isn't usable
    pub fn load(path: &str) -> Result<RecentFileCacheFile, Result<std::io::Error, ParseError>> {
        let raw = std::fs::read(ez_common::cli::full_path(path)).map_err(Ok)?;
        RecentFileCacheFile::parse(&raw, path, source_times(path)).map_err(Err)
    }

    /// The file's contents, from `source_file` (made a full path, as Path.GetFullPath) with its times (the default ones
    /// when it doesn't exist)
    pub fn parse(raw: &[u8], source_file: &str, source: SourceTimes) -> Result<RecentFileCacheFile, ParseError> {
        if raw.len() < HEADER_SIZE {
            return Err(ParseError { message: format!("File is {} bytes, smaller than the {HEADER_SIZE} byte header", raw.len()), offset: 0, field: "Header" });
        }
        let signature = u32_at(raw, 0);
        if signature != SIGNATURE {
            return Err(ParseError { message: format!("Invalid signature 0x{signature:08X}! Should be 0x{SIGNATURE:08X}"), offset: 0, field: "Signature" });
        }
        let checksum = u32_at(raw, CHECKSUM_OFFSET);
        let calculated_checksum = crc32_skipping(raw, CHECKSUM_OFFSET);
        let mut file = RecentFileCacheFile {
            source_file: ez_common::cli::full_path(source_file),
            source,
            checksum,
            calculated_checksum,
            file_names: Vec::new(),
            parse_errors: Vec::new(),
        };
        if !file.checksum_valid() {
            file.parse_errors.push(format!(
                "Checksum mismatch: header has 0x{checksum:08X}, contents give 0x{calculated_checksum:08X}. The file may have been modified or damaged"
            ));
        }
        file.parse_entries(raw);
        Ok(file)
    }

    pub fn checksum_valid(&self) -> bool {
        self.checksum == self.calculated_checksum
    }

    pub fn parsing_error(&self) -> bool {
        !self.parse_errors.is_empty()
    }

    fn parse_entries(&mut self, raw: &[u8]) {
        let mut index = HEADER_SIZE;
        while index < raw.len() {
            let remaining = raw.len() - index;
            if remaining < 4 {
                self.parse_errors.push(format!("{remaining} trailing byte(s) at 0x{index:X} are too short for an entry"));
                return;
            }
            let length = u32_at(raw, index) as i32;
            // a bad length means the rest can't be found, as entries have no other marker
            if length < 0 || i64::from(length) * 2 > remaining as i64 - 4 {
                self.parse_errors.push(format!(
                    "Entry at 0x{index:X} has a length of {length} characters, but only {} bytes remain. Stopping",
                    remaining - 4
                ));
                return;
            }
            let start = index + 4;
            let terminator = start + length as usize * 2;
            let name = ez_common::net::utf16(&raw[start..terminator]);
            if terminator + 2 > raw.len() {
                self.parse_errors.push(format!("Entry at 0x{index:X} ('{name}') is missing its NUL terminator"));
                self.file_names.push(name);
                return;
            }
            if raw[terminator] != 0 || raw[terminator + 1] != 0 {
                let found = u16::from_le_bytes([raw[terminator], raw[terminator + 1]]);
                self.parse_errors.push(format!("Entry at 0x{index:X} ('{name}') has 0x{found:04X} instead of a NUL terminator"));
            }
            self.file_names.push(name);
            index = terminator + 2;
        }
    }

    /// The object as ServiceStack serializes it, its properties in declaration order
    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("SourceFile", Value::text(self.source_file.as_str())),
            ("SourceCreated", Value::time(self.source.created)),
            ("SourceModified", Value::time(self.source.modified)),
            ("SourceAccessed", Value::time(self.source.accessed)),
            ("Checksum", Value::number(self.checksum)),
            ("CalculatedChecksum", Value::number(self.calculated_checksum)),
            ("ChecksumValid", Value::Bool(self.checksum_valid())),
            ("FileNames", Value::strings(&self.file_names)),
            ("ParseErrors", Value::strings(&self.parse_errors)),
            ("ParsingError", Value::Bool(self.parsing_error())),
        ])
    }
}

/// FileInfo's times, when File.Exists (not a folder), of the link itself for a link: on Unix, where .NET doesn't read the
/// birth time, the creation time is the older of the last write and last change times
pub fn source_times(path: &str) -> SourceTimes {
    if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        return SourceTimes::default();
    }
    let Ok(m) = std::fs::symlink_metadata(path) else { return SourceTimes::default() };
    let from_unix = |seconds: i64, nanos: i64| Timestamp(621_355_968_000_000_000 + seconds * 10_000_000 + nanos / 100);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let modified = (m.mtime(), m.mtime_nsec());
        let created = modified.min((m.ctime(), m.ctime_nsec()));
        SourceTimes { created: from_unix(created.0, created.1), modified: from_unix(modified.0, modified.1), accessed: from_unix(m.atime(), m.atime_nsec()) }
    }
    #[cfg(not(unix))]
    {
        let time = |t: std::io::Result<std::time::SystemTime>| {
            t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or_else(Timestamp::default, |d| from_unix(d.as_secs() as i64, i64::from(d.subsec_nanos())))
        };
        SourceTimes { created: time(m.created()), modified: time(m.modified()), accessed: time(m.accessed()) }
    }
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// CRC-32 (IEEE 802.3, as zlib's) of `data` without the 4 bytes at `skip`
pub fn crc32_skipping(data: &[u8], skip: usize) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for (i, &b) in data.iter().enumerate() {
        if (skip..skip + 4).contains(&i) {
            continue;
        }
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { 0xEDB8_8320 ^ (crc >> 1) } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header as in the samples (0x2211, 3, 1) with a correct checksum unless one is given, then entries
    fn build(entries: &[Vec<u8>], checksum: Option<u32>) -> Vec<u8> {
        let mut raw = Vec::new();
        for v in [SIGNATURE, 0x2211, 3, 1, 0] {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        entries.iter().for_each(|e| raw.extend_from_slice(e));
        let crc = checksum.unwrap_or_else(|| crc32_skipping(&raw, CHECKSUM_OFFSET));
        raw[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    fn entry_with(name: &str, length: Option<i32>, terminator: u16) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut e = length.unwrap_or(units.len() as i32).to_le_bytes().to_vec();
        units.iter().for_each(|u| e.extend_from_slice(&u.to_le_bytes()));
        e.extend_from_slice(&terminator.to_le_bytes());
        e
    }

    fn entry(name: &str) -> Vec<u8> {
        entry_with(name, None, 0)
    }

    fn parse(raw: &[u8]) -> RecentFileCacheFile {
        RecentFileCacheFile::parse(raw, "/x/memory.bcf", SourceTimes::default()).unwrap()
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32_skipping(b"1234\0\0\0\056789", 4), 0xCBF4_3926);
    }

    #[test]
    fn the_second_sample() {
        // upstream's RecentFileCache 2.bcf, which its tests build the same way
        let f = parse(&build(&[entry("c:\\windows\\psexesvc.exe"), entry("c:\\windows\\system32\\tasklist.exe")], None));
        assert_eq!(f.checksum, 0xE591_8E10);
        assert_eq!(f.file_names, ["c:\\windows\\psexesvc.exe", "c:\\windows\\system32\\tasklist.exe"]);
        assert!(f.checksum_valid() && !f.parsing_error());
        assert_eq!(f.source_file, "/x/memory.bcf");
    }

    #[test]
    fn header_only_and_empty_names() {
        let f = parse(&build(&[], None));
        assert!(f.file_names.is_empty() && !f.parsing_error());
        assert_eq!(f.source, SourceTimes::default());
        assert_eq!(parse(&build(&[entry(""), entry("b.exe")], None)).file_names, ["", "b.exe"]);
    }

    #[test]
    fn checksum_mismatch_still_parses() {
        let f = parse(&build(&[entry("a.exe")], Some(0x1234_5678)));
        assert_eq!(f.file_names, ["a.exe"]);
        assert_eq!(f.parse_errors.len(), 1);
        assert!(f.parse_errors[0].starts_with("Checksum mismatch: header has 0x12345678, contents give 0x"), "{}", f.parse_errors[0]);
    }

    #[test]
    fn bad_length_stops() {
        for length in [-1, i32::MIN, i32::MAX, 1000] {
            let f = parse(&build(&[entry("good.exe"), entry_with("bad.exe", Some(length), 0), entry("never.exe")], None));
            assert_eq!(f.file_names, ["good.exe"]);
            // header 0x14, then good.exe: 4 + 16 + 2 bytes
            assert_eq!(f.parse_errors, [format!("Entry at 0x2A has a length of {length} characters, but only 40 bytes remain. Stopping")]);
        }
    }

    #[test]
    fn cut_terminator_keeps_the_name() {
        let raw = build(&[entry("good.exe"), entry("cut.exe")], None);
        let f = parse(&raw[..raw.len() - 2]);
        assert_eq!(f.file_names, ["good.exe", "cut.exe"]);
        assert_eq!(f.parse_errors[1], "Entry at 0x2A ('cut.exe') is missing its NUL terminator");
    }

    #[test]
    fn non_nul_terminator_goes_on() {
        let f = parse(&build(&[entry_with("odd.exe", None, 0x4141), entry("next.exe")], None));
        assert_eq!(f.file_names, ["odd.exe", "next.exe"]);
        assert_eq!(f.parse_errors, ["Entry at 0x14 ('odd.exe') has 0x4141 instead of a NUL terminator"]);
    }

    #[test]
    fn trailing_bytes() {
        for extra in [1usize, 3] {
            let f = parse(&build(&[entry("a.exe"), vec![0; extra]], None));
            assert_eq!(f.file_names, ["a.exe"]);
            // 0x14 + 4 + 10 + 2
            assert_eq!(f.parse_errors, [format!("{extra} trailing byte(s) at 0x24 are too short for an entry")]);
        }
    }

    #[test]
    fn invalid_utf16_is_replaced() {
        let mut e = 2i32.to_le_bytes().to_vec();
        e.extend_from_slice(&[0x00, 0xD8, 0x41, 0x00, 0, 0]);
        assert_eq!(parse(&build(&[e], None)).file_names, ["\u{FFFD}A"]);
    }

    #[test]
    fn bad_headers() {
        for size in [0, 1, 19] {
            let e = RecentFileCacheFile::parse(&vec![0; size], "/x", SourceTimes::default()).unwrap_err();
            assert_eq!((e.field, e.offset), ("Header", 0));
            assert_eq!(e.message, format!("File is {size} bytes, smaller than the 20 byte header"));
        }
        let e = RecentFileCacheFile::parse(&[1; 20], "/x", SourceTimes::default()).unwrap_err();
        assert_eq!((e.field, e.message.as_str()), ("Signature", "Invalid signature 0x01010101! Should be 0xFFEEFFFE"));
    }

    #[test]
    fn random_damage_never_panics() {
        let good = build(&(0..20).map(|i| entry(&format!("c:\\windows\\file{i}.exe"))).collect::<Vec<_>>(), None);
        let mut seed = 42u64;
        let mut next = |n: usize| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize % n
        };
        for _ in 0..2000 {
            let mut d = good[..HEADER_SIZE + next(good.len() - HEADER_SIZE + 1)].to_vec();
            for _ in 0..1 + next(7) {
                if d.len() > HEADER_SIZE {
                    let at = HEADER_SIZE + next(d.len() - HEADER_SIZE);
                    d[at] = next(256) as u8;
                }
            }
            parse(&d);
        }
    }

    #[test]
    fn json_and_dump() {
        let times = SourceTimes { created: Timestamp(637_134_336_001_234_567), ..SourceTimes::default() };
        let f = RecentFileCacheFile::parse(&build(&[entry("c:\\a.exe")], None), "/x/r.bcf", times).unwrap();
        let json = f.to_value().to_json();
        assert!(json.starts_with(r#"{"SourceFile":"/x/r.bcf","SourceCreated":"2020-01-01T00:00:00.1234567Z","SourceModified":"0001-01-01T00:00:00.0000000Z","#), "{json}");
        assert!(json.ends_with(r#""ChecksumValid":true,"FileNames":["c:\\a.exe"],"ParseErrors":[],"ParsingError":false}"#), "{json}");
        let dump = f.to_value().dump();
        assert!(dump.starts_with("{\r\n\tSourceFile: /x/r.bcf,\r\n"), "{dump}");
        assert!(dump.ends_with("\tParseErrors: [],\r\n\tParsingError: False\r\n}"), "{dump}");
    }
}
