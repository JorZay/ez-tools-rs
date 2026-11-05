//! .NET behavior the parsers reproduce: reading bytes as BitConverter, Buffer.BlockCopy and Encoding do (with the
//! messages of the exceptions they throw, which the EZ tools put in their output), decoding text as .NET does, and
//! formatting enums.
//!
//! The messages are .NET 9's.

use std::borrow::Cow;

/// An exception's message
pub type NetResult<T> = Result<T, String>;

pub const INDEX_OUT_OF_RANGE: &str =
    "Index was out of range. Must be non-negative and less than the size of the collection. (Parameter 'startIndex')";
pub const TOO_SHORT: &str =
    "The array starting from the specified index is not long enough to read a value of the specified type. (Parameter 'value')";
pub const OUT_OF_BOUNDS: &str = "Offset and length were out of bounds for the array or count is greater than the number of elements from index to the end of the source collection.";
pub const ARRAY_INDEX: &str = "Index was outside the bounds of the array.";
pub const OVERFLOW: &str = "Arithmetic operation resulted in an overflow.";
pub const BUFFER_RANGE: &str = "Index and count must refer to a location within the buffer. (Parameter 'bytes')";
pub const MORE_THAN_ONE: &str = "Sequence contains more than one matching element";

fn non_negative(name: &str, value: i64) -> String {
    format!("{name} ('{value}') must be a non-negative value. (Parameter '{name}')\nActual value was {value}.")
}

/// BitConverter.ToXxx(b, index): N bytes at index
pub fn bytes_at<const N: usize>(b: &[u8], index: i64) -> NetResult<[u8; N]> {
    if index < 0 || index >= b.len() as i64 {
        return Err(INDEX_OUT_OF_RANGE.into());
    }
    let i = index as usize;
    if i + N > b.len() {
        return Err(TOO_SHORT.into());
    }
    Ok(b[i..i + N].try_into().unwrap())
}

pub fn i16_at(b: &[u8], i: i64) -> NetResult<i16> {
    bytes_at::<2>(b, i).map(i16::from_le_bytes)
}
pub fn u16_at(b: &[u8], i: i64) -> NetResult<u16> {
    bytes_at::<2>(b, i).map(u16::from_le_bytes)
}
pub fn i32_at(b: &[u8], i: i64) -> NetResult<i32> {
    bytes_at::<4>(b, i).map(i32::from_le_bytes)
}
pub fn u32_at(b: &[u8], i: i64) -> NetResult<u32> {
    bytes_at::<4>(b, i).map(u32::from_le_bytes)
}
pub fn i64_at(b: &[u8], i: i64) -> NetResult<i64> {
    bytes_at::<8>(b, i).map(i64::from_le_bytes)
}
pub fn u64_at(b: &[u8], i: i64) -> NetResult<u64> {
    bytes_at::<8>(b, i).map(u64::from_le_bytes)
}

/// b[index]
pub fn byte_at(b: &[u8], index: i64) -> NetResult<u8> {
    if index < 0 || index >= b.len() as i64 {
        return Err(ARRAY_INDEX.into());
    }
    Ok(b[index as usize])
}

/// `new byte[count]`, then Buffer.BlockCopy(src, offset, it, 0, count): the bytes, or the exception
pub fn copy(src: &[u8], offset: i64, count: i64) -> NetResult<&[u8]> {
    if count < 0 {
        // the array is made first
        return Err(OVERFLOW.into());
    }
    block_copy_check(src.len(), offset, count as usize, 0, count)?;
    Ok(&src[offset as usize..offset as usize + count as usize])
}

/// Buffer.BlockCopy's checks: (source length, srcOffset, destination length, dstOffset, count)
pub fn block_copy_check(src_len: usize, src_offset: i64, dst_len: usize, dst_offset: i64, count: i64) -> NetResult<()> {
    if src_offset < 0 {
        return Err(non_negative("srcOffset", src_offset));
    }
    if dst_offset < 0 {
        return Err(non_negative("dstOffset", dst_offset));
    }
    if count < 0 {
        return Err(non_negative("count", count));
    }
    if src_len as i64 - src_offset < count || dst_len as i64 - dst_offset < count {
        return Err(OUT_OF_BOUNDS.into());
    }
    Ok(())
}

/// The range Encoding.GetString(b, index, count) reads
fn get_string_range(b: &[u8], index: i64, count: i64) -> NetResult<&[u8]> {
    if index < 0 {
        return Err(non_negative("index", index));
    }
    if count < 0 {
        return Err(non_negative("count", count));
    }
    if b.len() as i64 - index < count {
        return Err(BUFFER_RANGE.into());
    }
    Ok(&b[index as usize..(index + count) as usize])
}

/// Encoding.Unicode.GetString(b, index, count)
pub fn unicode_string(b: &[u8], index: i64, count: i64) -> NetResult<String> {
    get_string_range(b, index, count).map(utf16)
}

/// Encoding.ASCII.GetString(b, index, count)
pub fn ascii_string(b: &[u8], index: i64, count: i64) -> NetResult<String> {
    get_string_range(b, index, count).map(ascii)
}

/// UTF-16LE as Encoding.Unicode decodes it: an unpaired surrogate, and an odd last byte, are U+FFFD
pub fn utf16(d: &[u8]) -> String {
    let units = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    let mut s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect();
    if d.len() % 2 == 1 {
        s.push('\u{FFFD}');
    }
    s
}

/// Encoding.ASCII: bytes over 0x7F are '?'
pub fn ascii(d: &[u8]) -> String {
    d.iter().map(|&c| if c < 0x80 { c as char } else { '?' }).collect()
}

/// Encoding.UTF8.GetString: invalid sequences are U+FFFD (one per maximal invalid subsequence, as .NET does)
pub fn utf8(d: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(d)
}

/// Windows-1252, as .NET's code page 1252 decodes it (the five undefined bytes are the C1 controls)
pub fn cp1252(d: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{02C6}',
        '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}',
        '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}',
        '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    ];
    d.iter().map(|&c| if (0x80..0xA0).contains(&c) { HIGH[(c - 0x80) as usize] } else { c as char }).collect()
}

/// A GUID as .NET's Guid.ToString() writes it (lowercase, no braces)
pub fn guid(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// Bytes as BitConverter.ToString writes them: `AA-BB-CC`
pub fn hex(d: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(d.len() * 3);
    for (i, b) in d.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        write!(s, "{b:02X}").unwrap();
    }
    s
}

/// An enum value's ToString(): its name, or the number when it has none
pub fn enum_name(value: i64, names: &[(&str, i64)]) -> String {
    names.iter().find(|(_, v)| *v == value).map(|(n, _)| n.to_string()).unwrap_or_else(|| value.to_string())
}

/// A [Flags] enum value's ToString(): the names of its flags in ascending order, joined with ", ", the largest
/// fitting values taken first; the number when some bits have no name; the name of 0 (or "0") for 0
pub fn flags_name(value: i64, names: &[(&str, i64)]) -> String {
    let mut sorted: Vec<(&str, i64)> = names.to_vec();
    // stable: of names with the same value, the first declared
    sorted.sort_by_key(|(_, v)| *v as u64);
    if value == 0 {
        return sorted.iter().find(|(_, v)| *v == 0).map(|(n, _)| n.to_string()).unwrap_or_else(|| "0".into());
    }
    let mut rest = value;
    let mut found = Vec::new();
    let mut i = sorted.len();
    while i > 0 {
        i -= 1;
        let v = sorted[i].1;
        if v == 0 {
            break;
        }
        // of equal values, .NET keeps the first; skip a later duplicate
        if i > 0 && sorted[i - 1].1 == v {
            continue;
        }
        if rest & v == v {
            rest -= v;
            found.push(sorted[i].0);
        }
    }
    if rest != 0 {
        return value.to_string();
    }
    found.reverse();
    found.join(", ")
}

/// Path.GetExtension on Linux (where only '/' separates directories): from the last '.', or empty
pub fn path_extension(path: &str) -> &str {
    for (i, c) in path.char_indices().rev() {
        if c == '.' {
            return if i + 1 == path.len() { "" } else { &path[i..] };
        }
        if c == '/' {
            break;
        }
    }
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitconverter_messages() {
        let b = [0u8; 4];
        assert!(i32_at(&b, 4).unwrap_err().starts_with("Index was out of range"));
        assert!(i32_at(&b, 2).unwrap_err().starts_with("The array starting"));
        assert!(i32_at(&b, -1).unwrap_err().starts_with("Index was out of range"));
        assert_eq!(copy(&b, 2, 4).unwrap_err(), OUT_OF_BOUNDS);
        assert_eq!(copy(&b, -1, 1).unwrap_err(), "srcOffset ('-1') must be a non-negative value. (Parameter 'srcOffset')\nActual value was -1.");
        assert_eq!(copy(&b, 0, -1).unwrap_err(), OVERFLOW);
        assert_eq!(unicode_string(&b, 2, 4).unwrap_err(), BUFFER_RANGE);
    }

    #[test]
    fn enums() {
        let n = [("Posix", 0), ("Windows", 1), ("Dos", 2), ("DosWindows", 3)];
        assert_eq!(flags_name(3, &n), "DosWindows");
        assert_eq!(flags_name(0, &n), "Posix");
        assert_eq!(flags_name(5, &n), "5");
        let f = [("None", 0), ("ReadOnly", 1), ("Hidden", 2), ("System", 4), ("Archive", 0x20)];
        assert_eq!(flags_name(0x26, &f), "Hidden, System, Archive");
        assert_eq!(flags_name(0, &f), "None");
    }

    #[test]
    fn text() {
        assert_eq!(utf16(&[0x41, 0, 0x42]), "A\u{FFFD}");
        assert_eq!(ascii(&[0x41, 0xC3]), "A?");
        assert_eq!(path_extension("a.txt"), ".txt");
        assert_eq!(path_extension("a."), "");
        assert_eq!(path_extension(".bashrc"), ".bashrc");
        assert_eq!(path_extension("dir.d/file"), "");
        assert_eq!(path_extension("noext"), "");
    }
}
