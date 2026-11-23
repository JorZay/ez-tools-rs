//! Resident $DATA decoded for the $MFT output's ResidentDataDecoded column (MFTECmd's ResidentDecoder): Recycle Bin
//! $I files (always: an emptied Recycle Bin can leave them in free FILE records, Issues #260) and, with --ir, UTF-16
//! text. Input may be damaged or hostile: anything that doesn't fit gives None.

use crate::time::Timestamp;

/// Version 1 (Vista to 8.1): header + 260 UTF-16 characters
const I1_SIZE: usize = 0x220;
/// Version 2 (Windows 10+): header + a character count + the name
const I2_HEADER_SIZE: usize = 0x1C;
const MAX_PATH_CHARS: i32 = 0x8000;
/// DateTime.MaxValue.ToFileTimeUtc()
const MAX_FILETIME: i64 = 2_650_467_743_999_999_999;

/// A Recycle Bin $I file's name: $I + 6 characters, plus any extension
pub fn is_recycle_bin_info_name(file_name: &str) -> bool {
    file_name.encode_utf16().count() >= 8
        && file_name.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("$I"))
}

fn i64_at(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

/// "Version: 2 | Path: C:\x\y.txt | Size: 1234 | Deleted: (deletion time in `date_format`)", or None when `data` is
/// not a $I file
pub fn decode_recycle_bin_info(data: &[u8], date_format: &str) -> Option<String> {
    if data.len() < 0x18 {
        return None;
    }
    let version = i64_at(data, 0);
    let size = i64_at(data, 8);
    let file_time = i64_at(data, 0x10);
    let path = match version {
        1 => {
            if data.len() < I1_SIZE {
                return None;
            }
            utf16_until_nul(data, 0x18, 260)
        }
        2 => {
            if data.len() < I2_HEADER_SIZE {
                return None;
            }
            let chars = i32::from_le_bytes(data[0x18..0x1C].try_into().unwrap());
            if chars <= 0 || chars > MAX_PATH_CHARS || I2_HEADER_SIZE + chars as usize * 2 > data.len() {
                return None;
            }
            utf16_until_nul(data, I2_HEADER_SIZE, chars as usize)
        }
        _ => return None,
    };
    if size < 0 || path.is_empty() {
        return None;
    }
    let deleted = match Timestamp::from_filetime(file_time).filter(|_| file_time > 0 && file_time <= MAX_FILETIME) {
        Some(t) => t.format(date_format),
        None => format!("0x{file_time:X}"),
    };
    Some(format!("Version: {version} | Path: {path} | Size: {size} | Deleted: {deleted}"))
}

/// UTF-16LE text (with or without a byte order mark), or None when `data` doesn't look like it: an odd length, or
/// characters that aren't printable text
pub fn decode_utf16_text(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data.len() % 2 != 0 {
        return None;
    }
    let start = if data[0] == 0xFF && data[1] == 0xFE { 2 } else { 0 };
    let units: Vec<u16> = data[start..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_end_matches('\0');
    if text.is_empty() {
        return None;
    }
    let mut len = 0;
    let mut latin = 0;
    for c in text.chars() {
        let u = c as u32;
        len += 1;
        if u < 0x250 {
            latin += 1;
        }
        if c == '\r' || c == '\n' || c == '\t' {
            continue;
        }
        // char.IsControl, a surrogate (any character past U+FFFF is a pair of them in .NET), U+FFFD, U+FFFF
        if c.is_control() || u > 0xFFFF || u == 0xFFFD || u == 0xFFFF {
            return None;
        }
    }
    // plain ASCII read as UTF-16 gives CJK characters: want mostly Latin-1 or a byte order mark
    if start == 0 && latin * 2 < len {
        return None;
    }
    Some(text.to_string())
}

/// Characters from `offset` up to a NUL, at most `max_chars` (lone surrogates become U+FFFD when written)
fn utf16_until_nul(data: &[u8], offset: usize, max_chars: usize) -> String {
    let mut units = Vec::new();
    let mut i = 0;
    while i < max_chars && offset + i * 2 + 1 < data.len() {
        let c = u16::from_le_bytes([data[offset + i * 2], data[offset + i * 2 + 1]]);
        if c == 0 {
            break;
        }
        units.push(c);
        i += 1;
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i2(path: &str, size: i64, time: i64) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&2i64.to_le_bytes());
        d.extend_from_slice(&size.to_le_bytes());
        d.extend_from_slice(&time.to_le_bytes());
        let units: Vec<u16> = path.encode_utf16().chain([0]).collect();
        d.extend_from_slice(&(units.len() as i32).to_le_bytes());
        for u in units {
            d.extend_from_slice(&u.to_le_bytes());
        }
        d
    }

    #[test]
    fn recycle_bin_v2() {
        let d = i2("C:\\x\\y.txt", 1234, 133_000_000_000_000_000);
        assert_eq!(
            decode_recycle_bin_info(&d, "yyyy-MM-dd HH:mm:ss").unwrap(),
            "Version: 2 | Path: C:\\x\\y.txt | Size: 1234 | Deleted: 2022-06-18 04:26:40"
        );
        assert_eq!(decode_recycle_bin_info(&i2("C:\\a", 1, -5), "yyyy").unwrap(), "Version: 2 | Path: C:\\a | Size: 1 | Deleted: 0xFFFFFFFFFFFFFFFB");
        assert!(decode_recycle_bin_info(&i2("C:\\a", -1, 0), "yyyy").is_none());
        assert!(is_recycle_bin_info_name("$IABC123.txt") && !is_recycle_bin_info_name("$IABC12") && is_recycle_bin_info_name("$iabc123"));
    }

    #[test]
    fn utf16_text() {
        let enc = |s: &str| s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
        assert_eq!(decode_utf16_text(&enc("héllo\r\n")).as_deref(), Some("héllo\r\n"));
        assert!(decode_utf16_text(b"abcd").is_none());
        assert!(decode_utf16_text(&enc("a\u{1}bc")).is_none());
        let mut bom = vec![0xFF, 0xFE];
        bom.extend(enc("日本語"));
        assert_eq!(decode_utf16_text(&bom).as_deref(), Some("日本語"));
        assert!(decode_utf16_text(&enc("日本語")).is_none());
    }
}
