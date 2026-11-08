//! ExtensionBlocks' `Utils`.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::OnceLock;

use encoding_rs::{GB18030, ISO_2022_JP, UTF_8, UTF_16BE, UTF_16LE};
use ez_common::Timestamp;
use ez_common::net::{NetResult, cp1252, u16_at, utf16};

/// .NET's error for an index that isn't in a List
pub const LIST_INDEX: &str = "Index was out of range. Must be non-negative and less than the size of the collection. (Parameter 'index')";

thread_local! {
    static CODE_PAGE: Cell<i32> = const { Cell::new(1252) };
}

/// Utils.CodePage: of the ANSI strings in the shell items being read on this thread
pub fn code_page() -> i32 {
    CODE_PAGE.with(Cell::get)
}

pub fn set_code_page(code_page: i32) {
    CODE_PAGE.with(|c| c.set(code_page));
}

/// The code pages of one byte per character, taken from .NET: the number, then 256 characters as 4 hex digits each
static SINGLE_BYTE_PAGES: &str = include_str!("../data/codepages.txt");

fn single_byte_page(code_page: i32) -> Option<&'static [char; 256]> {
    static PAGES: OnceLock<HashMap<i32, [char; 256]>> = OnceLock::new();
    PAGES
        .get_or_init(|| {
            SINGLE_BYTE_PAGES
                .lines()
                .filter_map(|line| {
                    let (number, hex) = line.split_once('\t')?;
                    let mut table = ['\0'; 256];
                    for (i, slot) in table.iter_mut().enumerate() {
                        *slot = char::from_u32(u32::from_str_radix(hex.get(i * 4..i * 4 + 4)?, 16).ok()?)?;
                    }
                    Some((number.parse().ok()?, table))
                })
                .collect()
        })
        .get(&code_page)
}

/// The pages of one or two bytes per character, taken from .NET as encoding_rs reads some of these differently. For a page: `P`, its
/// number and each byte's text. Then for each lead byte: `L`, the byte, the text of most pairs and runs of the others (`trail:text`
/// of a character each, or `trail:=text` for one pair).
static DOUBLE_BYTE_PAGES: &str = include_str!("../data/dbcs.txt");

struct DoubleBytePage {
    single: Vec<String>,
    /// 256 pairs per lead byte
    pairs: HashMap<u8, Vec<String>>,
}

fn hex_text(hex: &str) -> String {
    let units: Vec<u16> = (0..hex.len() / 4).filter_map(|i| u16::from_str_radix(hex.get(i * 4..i * 4 + 4)?, 16).ok()).collect();
    String::from_utf16_lossy(&units)
}

fn read_double_byte_page(code_page: i32) -> Option<DoubleBytePage> {
    let wanted = format!("P\t{code_page}\t");
    let mut lines = DOUBLE_BYTE_PAGES.lines().skip_while(|line| !line.starts_with(&wanted));
    let single = lines.next()?.strip_prefix(&wanted)?.split(' ').map(hex_text).collect();
    let mut pairs = HashMap::new();
    for line in lines.take_while(|line| line.starts_with('L')) {
        let mut fields = line.split('\t').skip(1);
        let lead = u8::from_str_radix(fields.next()?, 16).ok()?;
        let mut row = vec![hex_text(fields.next()?); 256];
        for run in fields.next()?.split(' ').filter(|run| !run.is_empty()) {
            let (trail, text) = run.split_once(':')?;
            let trail = usize::from_str_radix(trail, 16).ok()?;
            match text.strip_prefix('=') {
                Some(whole) => row[trail] = hex_text(whole),
                None => {
                    for i in 0..text.len() / 4 {
                        row[trail + i] = hex_text(text.get(i * 4..i * 4 + 4)?);
                    }
                }
            }
        }
        pairs.insert(lead, row);
    }
    Some(DoubleBytePage { single, pairs })
}

fn double_byte_decode(code_page: i32, bytes: &[u8]) -> Option<String> {
    static PAGE: OnceLock<std::sync::Mutex<HashMap<i32, Option<&'static DoubleBytePage>>>> = OnceLock::new();
    let mut pages = PAGE.get_or_init(Default::default).lock().ok()?;
    let page: &DoubleBytePage = (*pages.entry(code_page).or_insert_with(|| read_double_byte_page(code_page).map(|p| &*Box::leak(Box::new(p)))))?;
    drop(pages);
    let mut text = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (page.pairs.get(&bytes[i]), bytes.get(i + 1)) {
            (Some(row), Some(trail)) => {
                text.push_str(&row[usize::from(*trail)]);
                i += 2;
            }
            _ => {
                text.push_str(&page.single[usize::from(bytes[i])]);
                i += 1;
            }
        }
    }
    Some(text)
}

/// `CodePagesEncodingProvider.Instance.GetEncoding(codePage)?.GetString(bytes)`
pub fn provider_decode(code_page: i32, bytes: &[u8]) -> Option<String> {
    if code_page == 1252 {
        return Some(cp1252(bytes));
    }
    if let Some(table) = single_byte_page(code_page) {
        return Some(bytes.iter().map(|b| table[usize::from(*b)]).collect());
    }
    if let Some(text) = double_byte_decode(code_page, bytes) {
        return Some(text);
    }
    match code_page {
        54936 => Some(GB18030.decode_without_bom_handling(bytes).0.into_owned()),
        50220..=50222 => Some(ISO_2022_JP.decode_without_bom_handling(bytes).0.into_owned()),
        // The rest of what .NET has, none of them a Windows ANSI page, isn't ported: read as 1252 (see the plan)
        50225 | 52936 | 57002..=57011 => Some(cp1252(bytes)),
        _ => None,
    }
}

/// Lnk's `Helpers.GetEncoding(codePage).GetString(bytes)`: the provider, what .NET itself has, and then 1252
pub fn decode_with(code_page: i32, bytes: &[u8]) -> String {
    if let Some(text) = provider_decode(code_page, bytes) {
        return text;
    }
    match code_page {
        20127 => bytes.iter().map(|b| if *b < 0x80 { char::from(*b) } else { '\u{fffd}' }).collect(),
        28591 => bytes.iter().map(|b| char::from(*b)).collect(),
        1200 => UTF_16LE.decode_without_bom_handling(bytes).0.into_owned(),
        1201 => UTF_16BE.decode_without_bom_handling(bytes).0.into_owned(),
        65001 => UTF_8.decode_without_bom_handling(bytes).0.into_owned(),
        12000 | 12001 => bytes
            .chunks(4)
            .map(|c| match <[u8; 4]>::try_from(c) {
                Ok(b) => char::from_u32(if code_page == 12000 { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }).unwrap_or('\u{fffd}'),
                Err(_) => '\u{fffd}',
            })
            .collect(),
        _ => cp1252(bytes),
    }
}

const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";

/// The shell items' `CodePagesEncodingProvider.Instance.GetEncoding(CodePage).GetString(bytes)`: null, for a page it doesn't have
pub fn ansi(bytes: &[u8]) -> NetResult<String> {
    provider_decode(code_page(), bytes).ok_or_else(|| NULL_REFERENCE.to_string())
}

/// The same, `GetString(bytes, index, count)`
pub fn ansi_at(bytes: &[u8], index: i64, count: i64) -> NetResult<String> {
    if provider_decode(code_page(), &[]).is_none() {
        return Err(NULL_REFERENCE.to_string());
    }
    if index < 0 {
        return Err(format!("Non-negative number required. (Parameter 'index')"));
    }
    if count < 0 {
        return Err(format!("Non-negative number required. (Parameter 'count')"));
    }
    if bytes.len() as i64 - index < count {
        return Err("Index and count must refer to a location within the buffer. (Parameter 'bytes')".to_string());
    }
    ansi(&bytes[index as usize..(index + count) as usize])
}

/// `Array.Copy(bytes, index, new byte[count], 0, count)`
pub fn array_copy(bytes: &[u8], index: i64, count: i64) -> NetResult<&[u8]> {
    if count < 0 {
        return Err(ez_common::net::OVERFLOW.to_string());
    }
    if index < 0 {
        return Err("Non-negative number required. (Parameter 'sourceIndex')".to_string());
    }
    if index + count > bytes.len() as i64 {
        return Err("Source array was not long enough. Check the source index, length, and the array's lower bounds. (Parameter 'sourceArray')".to_string());
    }
    Ok(&bytes[index as usize..(index + count) as usize])
}

/// `bytes.Skip(index).Take(count)`
pub fn skip_take(bytes: &[u8], index: usize, count: usize) -> &[u8] {
    let start = index.min(bytes.len());
    &bytes[start..start.saturating_add(count).min(bytes.len())]
}

/// `bytes.Skip(index)`
pub fn skip(bytes: &[u8], index: usize) -> &[u8] {
    &bytes[index.min(bytes.len())..]
}

/// `new string` split on NUL, leaving out empty ones
pub fn split_nul_no_empty(text: &str) -> Vec<&str> {
    text.split('\0').filter(|s| !s.is_empty()).collect()
}

/// The format of times in the text of blocks and items: en-US's patterns with milliseconds and the offset, as DateTimeFormat
/// left unset gives there (LECmd doesn't set it)
pub fn time_text(t: Timestamp) -> String {
    t.format("M/d/yyyy h:mm:ss.fff tt  K")
}

/// Utils.FromFileTime: the minimum for what isn't a valid FILETIME. Times are UTC here: the original keeps the local offset for
/// the few blocks that don't convert it
pub fn from_file_time(file_time: i64) -> Timestamp {
    Timestamp::from_filetime(file_time).unwrap_or(Timestamp::MIN)
}

/// new DateTime(ticks) from DateTime.FromFileTimeUtc, written with the invariant culture
pub fn file_time_invariant(file_time: i64) -> NetResult<String> {
    match Timestamp::from_filetime(file_time) {
        Some(t) => Ok(t.format("MM/dd/yyyy HH:mm:ss")),
        None => Err("Not a valid Win32 FileTime. (Parameter 'fileTime')".to_string()),
    }
}

/// Utils.ExtractDateTimeOffsetFromBytes: an MS-DOS date and time; None when unset or invalid
pub fn dos_time(raw: &[u8]) -> NetResult<Option<Timestamp>> {
    let date = u32::from(u16_at(raw, 0)?);
    let time = u32::from(u16_at(raw, 2)?);
    let day = date & 0x1f;
    let month = (date & 0x1e0) >> 5;
    let year = ((date & 0xfe00) >> 9) as i32 + 1980;
    let hour = (time & 0xf800) >> 11;
    let minute = (time & 0x7e0) >> 5;
    let seconds = (time & 0x1f) * 2;
    Ok(Timestamp::from_parts(year, month, day, hour, minute, seconds, 0))
}

/// Utils.ExtractGuidFromShellItem, and new Guid(byte[])
pub fn guid_text(raw: &[u8]) -> NetResult<String> {
    let raw = &raw[..raw.len().min(16)];
    match <&[u8; 16]>::try_from(raw) {
        Ok(g) => Ok(ez_common::net::guid(g)),
        Err(_) => Err("Byte array for Guid must be exactly 16 bytes long. (Parameter 'b')".to_string()),
    }
}

/// GuidMapping.GetDescriptionFromGuid
pub fn guid_name(guid: &str) -> String {
    guidmapping_ez::description_or_unmapped(guid)
}

fn property_names() -> &'static HashMap<(&'static str, i32), &'static str> {
    static NAMES: OnceLock<HashMap<(&'static str, i32), &'static str>> = OnceLock::new();
    NAMES.get_or_init(|| {
        include_str!("../data/property_names.txt")
            .lines()
            .filter_map(|l| {
                let mut parts = l.splitn(3, '\t');
                Some(((parts.next()?, parts.next()?.parse().ok()?), parts.next()?))
            })
            .collect()
    })
}

/// Utils.GetDescriptionFromGuidAndKey
pub fn description_from_guid_and_key(guid: &str, key: i32) -> String {
    let guid = guid.to_lowercase();
    property_names().get(&(guid.as_str(), key)).map_or("(Description not available)", |n| n).to_string()
}

/// Utils.GetStringsFromMultistring, with its way of moving on after each string
pub fn strings_from_multistring(raw: &[u8]) -> NetResult<Vec<String>> {
    let raw = &raw[..raw.len().saturating_sub(2)];
    let mut hex = String::with_capacity(raw.len() * 3 + 3);
    for (i, b) in raw.iter().enumerate() {
        use std::fmt::Write;
        if i > 0 {
            hex.push('-');
        }
        write!(hex, "{b:02X}").unwrap();
    }
    let mut out = Vec::new();
    if hex.starts_with("00-00-00-") {
        out.push(String::new());
        return Ok(out);
    }
    if !hex.ends_with("-00-00-00") {
        hex.push_str("-00");
    }
    let mut index = 0i64;
    let mut from = 0;
    while let Some(found) = hex[from..].find("00-00-") {
        let at = from + found;
        let position = ((at + 3) / 3) as i64;
        if position + 2 < raw.len() as i64 {
            out.push(ez_common::net::unicode_string(raw, index, position - index)?.replace('\0', ""));
            index += position + 2;
        }
        from = at + 6;
    }
    if index + 4 <= raw.len() as i64 {
        out.push(ez_common::net::unicode_string(raw, index, raw.len() as i64 - index)?.replace('\0', ""));
    }
    Ok(out)
}

/// Utils.IndexOf
pub fn index_of(data: &[u8], pattern: &[u8], start: i64) -> i64 {
    let start = start.max(0) as usize;
    if start > data.len() {
        return -1;
    }
    data[start..].windows(pattern.len()).position(|w| w == pattern).map_or(-1, |i| (i + start) as i64)
}

/// Utils.FindExtensionBlockSignatures
pub fn find_extension_block_signatures(buffer: &[u8]) -> Vec<i64> {
    let mut result = Vec::new();
    let mut i = 0usize;
    while i + 3 < buffer.len() {
        let Some(e) = buffer[(i + 2).min(buffer.len())..].iter().position(|b| *b == 0xef).map(|p| p + i + 2) else { break };
        if e + 1 >= buffer.len() {
            break;
        }
        let p = e - 2;
        if buffer[e + 1] == 0xbe && buffer[e - 1] == 0x00 {
            result.push(p as i64);
            i = p + 4;
        } else {
            i = p + 1;
        }
    }
    result
}

/// Utils.GetNetworkLocation: the location and, when the flags have it, the description
pub fn network_location(raw: &[u8]) -> NetResult<(String, Option<String>)> {
    if raw.len() <= 5 {
        return Ok(("(None)".to_string(), None));
    }
    let text = ansi(&raw[5..])?;
    let parts: Vec<&str> = text.split('\0').collect();
    let description = (raw[4] & 0x80 != 0 && parts.len() > 1 && !parts[1].is_empty()).then(|| parts[1].to_string());
    Ok((parts[0].to_string(), description))
}

/// Encoding.Unicode.GetString over the whole slice
pub fn unicode(bytes: &[u8]) -> String {
    utf16(bytes)
}

/// A number with thousands separators, for any integer
pub fn n0(v: i64) -> String {
    if v < 0 { format!("-{}", ez_common::dotnet::n0(v.unsigned_abs())) } else { ez_common::dotnet::n0(v as u64) }
}

/// The offset of an error's kind: whether Lnk reads it as "item data ends before the parser expected": ArgumentException and
/// IndexOutOfRangeException, and the exceptions that derive from them
pub fn is_argument_or_index_error(message: &str) -> bool {
    use ez_common::net::{ARRAY_INDEX, BUFFER_RANGE, INDEX_OUT_OF_RANGE, OUT_OF_BOUNDS, TOO_SHORT};
    message == ARRAY_INDEX || message == INDEX_OUT_OF_RANGE || message == TOO_SHORT || message == OUT_OF_BOUNDS || message == BUFFER_RANGE || message.contains("(Parameter '")
}
