//! $I30 directory index allocations: 4096 byte INDX pages of index entries ($FILE_NAME keys), and entries left in
//! the slack after the active ones.

use ez_common::net::{self, NetResult};

use crate::mft::attributes::FileInfo;
use crate::mft::{MftEntryInfo, TimestampSource};

const PAGE_SIZE: usize = 0x1000;
const NODE_HEADER_OFFSET: usize = 0x18;
const INDX_SIG: i32 = 0x58444E49;

/// An index entry (IndexEntryI30): active, or found in slack (no file reference of its own)
#[derive(Debug, Clone)]
pub struct IndexEntryI30 {
    pub flag: i32,
    pub page_number: i32,
    pub from_slack: bool,
    pub absolute_offset: i64,
    pub mft_reference_self: Option<MftEntryInfo>,
    pub file_info: Option<FileInfo>,
    /// MD5 of a slack entry's bytes
    pub md5: Option<String>,
}

pub const ENTRY_FLAG_NAMES: &[(&str, i64)] = &[("HasSubNodes", 1), ("LastEntry", 2)];

impl IndexEntryI30 {
    /// Parses an entry; invalid timestamp warnings go to `warnings` (also when the entry then fails)
    pub fn parse(
        raw: &[u8],
        absolute_offset: i64,
        page_number: i32,
        from_slack: bool,
        source: &TimestampSource,
        warnings: &mut Vec<String>,
    ) -> NetResult<IndexEntryI30> {
        let mut e = IndexEntryI30 {
            flag: 0,
            page_number,
            from_slack,
            absolute_offset,
            mft_reference_self: None,
            file_info: None,
            md5: None,
        };
        let mut skip = 0;
        if !from_slack {
            let r = MftEntryInfo::parse(&raw[0..8]);
            e.mft_reference_self = Some(r);
            if r.entry == 0 {
                return Ok(e);
            }
            e.flag = i32::from_le_bytes(raw[12..16].try_into().unwrap());
            skip = 16;
        }
        e.file_info = Some(FileInfo::parse(&raw[skip..], source, warnings)?);
        Ok(e)
    }
}

/// FileRecord.GetSlackFileEntries: index entries found in slack, from runs of printable UTF-16 (the names)
pub fn slack_entries(slack: &[u8], page_number: i32, start_offset: i32, entry_number: u32, warnings: &mut Vec<String>) -> Vec<IndexEntryI30> {
    let mut entries = Vec::new();
    let units: Vec<u16> = slack.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut i = 0;
    while i < units.len() {
        if !(0x20..=0x7E).contains(&units[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < units.len() && (0x20..=0x7E).contains(&units[i]) {
            i += 1;
        }
        if i - start < 3 {
            continue;
        }
        let text: String = units[start..i].iter().map(|&u| u as u8 as char).collect();
        let hit = text.trim();
        if hit.is_empty() {
            continue;
        }
        let offset = start * 2;
        let abs = start_offset as i64 + offset as i64;
        if offset == 0 {
            warnings.push(format!("Found possible slack index entry for {hit} at 0x{abs:X}, but not enough data to interpret. Skipping..."));
            continue;
        }
        let name_size = slack[offset - 2] as i64;
        let begin = offset as i64 - 0x42;
        let end = offset as i64 + name_size * 2;
        if begin < 0 {
            warnings.push(format!("Found possible slack index entry for {hit} at 0x{abs:X}, but not enough data to interpret. Skipping..."));
            continue;
        }
        let result = (|| -> NetResult<Option<IndexEntryI30>> {
            let buff = net::copy(slack, begin, end - begin)?;
            let md5 = md5_hex(buff);
            let slack_offset = start_offset as i64 + begin - 0x10;
            let source = TimestampSource::index_entry(slack_offset, entry_number, true);
            let mut e = IndexEntryI30::parse(buff, slack_offset, page_number, true, &source, warnings)?;
            e.md5 = Some(md5);
            let fi = e.file_info.as_ref().unwrap();
            if fi.name_length == 0 || fi.flags < 0 {
                return Ok(None);
            }
            Ok(Some(e))
        })();
        match result {
            Ok(Some(e)) => entries.push(e),
            Ok(None) => {}
            Err(m) => {
                if entry_number > 0 {
                    warnings.push(format!(
                        "Error processing slack index entry in FILE Entry ox{entry_number:X}! You may want to review this manually. Offset 0x{abs:X}. Name: {hit}. Error: {m}"
                    ));
                } else {
                    warnings.push(format!(
                        "Error processing slack index entry! You may want to review this manually. Offset 0x{abs:X}. Name: {hit}. Error: {m}"
                    ));
                }
            }
        }
    }
    entries
}

fn md5_hex(d: &[u8]) -> String {
    use md5::{Digest, Md5};
    use std::fmt::Write;
    let mut s = String::with_capacity(32);
    for b in Md5::digest(d) {
        write!(s, "{b:02X}").unwrap();
    }
    s
}

/// A parsed $I30
pub struct I30 {
    pub entries: Vec<IndexEntryI30>,
    pub parse_errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl I30 {
    pub fn parse(bytes: &[u8]) -> Result<I30, String> {
        let mut r = I30 { entries: Vec::new(), parse_errors: Vec::new(), warnings: Vec::new() };
        let mut unique_md5s: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (page_number, chunk) in bytes.chunks(PAGE_SIZE).enumerate() {
            let page_offset = page_number as i64 * PAGE_SIZE as i64;
            if chunk.len() < 0x28 {
                r.parse_errors.push(format!("Page at 0x{page_offset:X} is only 0x{:X} bytes", chunk.len()));
                break;
            }
            let sig = i32::from_le_bytes(chunk[0..4].try_into().unwrap());
            if sig == 0 {
                r.warnings.push(format!("Empty page found at offset 0x{page_offset:X}. Skipping"));
                continue;
            }
            if sig != INDX_SIG {
                if page_number == 0 {
                    return Err("Invalid header! Expected 'INDX' Signature".into());
                }
                r.warnings.push(format!("Page at offset 0x{page_offset:X} has no 'INDX' signature. Skipping"));
                r.parse_errors.push(format!("Page at 0x{page_offset:X} has no 'INDX' signature; skipped"));
                continue;
            }
            let mut page = chunk.to_vec();
            r.page(&mut page, page_number as i32, &mut unique_md5s);
        }
        Ok(r)
    }

    fn page(&mut self, page: &mut [u8], page_number: i32, unique: &mut std::collections::HashSet<String>) {
        let page_offset = page_number as i64 * PAGE_SIZE as i64;
        let i16_at = |p: &[u8], o: usize| i16::from_le_bytes([p[o], p[o + 1]]);
        let i32_at = |p: &[u8], o: usize| i32::from_le_bytes(p[o..o + 4].try_into().unwrap());
        let fixup_offset = i16_at(page, 4) as i64;
        let pairs = i16_at(page, 6) as i64;
        let data_start = i32_at(page, NODE_HEADER_OFFSET) as i64;
        let data_size = i32_at(page, NODE_HEADER_OFFSET + 4) as i64;
        let len = page.len() as i64;
        if fixup_offset > 0 && pairs > 0 && fixup_offset + pairs * 2 <= len {
            let fixups = page[fixup_offset as usize..(fixup_offset + pairs * 2) as usize].to_vec();
            let expected = i16::from_le_bytes([fixups[0], fixups[1]]);
            let mut sector_end = 510usize;
            for pair in fixups[2..].chunks_exact(2) {
                if sector_end + 2 > page.len() {
                    break;
                }
                let found = i16_at(page, sector_end);
                if found != expected {
                    self.warnings.push(format!(
                        "Fixup values do not match at 0x{sector_end:X}. Expected: 0x{expected:02X}, actual: 0x{found:02X}"
                    ));
                }
                page[sector_end..sector_end + 2].copy_from_slice(pair);
                sector_end += 512;
            }
        } else {
            self.parse_errors.push(format!(
                "Page at 0x{page_offset:X}: fixup array at 0x{fixup_offset:X} with 0x{pairs:X} entries does not fit; fixups not applied"
            ));
        }

        let active_start = NODE_HEADER_OFFSET as i64 + data_start;
        let active_end = NODE_HEADER_OFFSET as i64 + data_size;
        if data_start < 0x10 || active_start > len || active_end < active_start || active_end > len {
            self.parse_errors.push(format!(
                "Page at 0x{page_offset:X}: entries from 0x{:X} to 0x{:X} do not fit in the page",
                data_start as i32, data_size as i32
            ));
            return;
        }
        let mut index = active_start;
        while active_end - index >= 0x10 {
            let absolute = page_offset + index;
            let size = i16_at(page, index as usize + 8) as i64;
            if size < 0x10 || size > active_end - index {
                self.parse_errors.push(format!(
                    "Page at 0x{page_offset:X}: index entry at 0x{absolute:X} has size 0x{:X}; rest of the page skipped",
                    size as i16
                ));
                break;
            }
            let buf = &page[index as usize..(index + size) as usize];
            index += size;
            let source = TimestampSource::index_entry(absolute, 0, false);
            match IndexEntryI30::parse(buf, absolute, page_number, false, &source, &mut self.warnings) {
                Ok(ie) => {
                    if ie.mft_reference_self.is_some_and(|r| r.entry == 0) {
                        continue;
                    }
                    self.entries.push(ie);
                }
                Err(e) => self.parse_errors.push(format!(
                    "Page at 0x{page_offset:X}: index entry at 0x{absolute:X} could not be parsed: {e}"
                )),
            }
        }
        let slack = &page[active_end as usize..];
        let slack_abs = page_offset + active_end;
        let found = slack_entries(slack, page_number, slack_abs as i32, 0, &mut self.warnings);
        for e in found {
            let md5 = e.md5.clone().unwrap_or_default();
            if unique.contains(&md5) {
                continue;
            }
            unique.insert(md5);
            self.entries.push(e);
        }
    }
}
