//! Reads that check the bounds first: the value can be truncated or not what it claims to be.

use ez_common::Timestamp;

use crate::{ParseError, Result};

pub(crate) fn fits(b: &[u8], offset: i64, length: i64) -> bool {
    offset >= 0 && length >= 0 && offset.checked_add(length).is_some_and(|end| end <= b.len() as i64)
}

pub(crate) fn need(b: &[u8], offset: i64, length: i64, field: &str) -> Result<()> {
    if fits(b, offset, length) {
        return Ok(());
    }
    Err(ParseError(format!("{field} (0x{length:X} bytes at 0x{offset:X}) is past the end of the data (0x{:X} bytes)", b.len())))
}

pub(crate) fn u16_at(b: &[u8], offset: i64, field: &str) -> Result<u16> {
    need(b, offset, 2, field)?;
    Ok(u16::from_le_bytes(b[offset as usize..offset as usize + 2].try_into().unwrap()))
}

pub(crate) fn u32_at(b: &[u8], offset: i64, field: &str) -> Result<u32> {
    need(b, offset, 4, field)?;
    Ok(u32::from_le_bytes(b[offset as usize..offset as usize + 4].try_into().unwrap()))
}

pub(crate) fn i64_at(b: &[u8], offset: i64, field: &str) -> Result<i64> {
    need(b, offset, 8, field)?;
    Ok(i64::from_le_bytes(b[offset as usize..offset as usize + 8].try_into().unwrap()))
}

pub(crate) fn utf16(b: &[u8], offset: i64, length: i64, field: &str) -> Result<String> {
    need(b, offset, length, field)?;
    Ok(ez_common::net::utf16(&b[offset as usize..(offset + length) as usize]))
}

/// Empty when it doesn't fit
pub(crate) fn ascii(b: &[u8], offset: i64, length: i64) -> String {
    if fits(b, offset, length) { ez_common::net::ascii(&b[offset as usize..(offset + length) as usize]) } else { String::new() }
}

pub(crate) fn slice(b: &[u8], offset: i64, length: i64, field: &str) -> Result<Vec<u8>> {
    need(b, offset, length, field)?;
    Ok(b[offset as usize..(offset + length) as usize].to_vec())
}

/// A FILETIME, or None for 0, 1601 (as the parsers always showed them) and values that are not valid times
pub(crate) fn file_time(value: i64) -> Option<Timestamp> {
    if value <= 0 {
        return None;
    }
    Timestamp::from_filetime(value).filter(|t| t.parts().year != 1601)
}

/// A path as the cache stores it, without the \??\ prefix
pub(crate) fn clean_path(path: &str) -> String {
    path.replace("\\??\\", "")
}
