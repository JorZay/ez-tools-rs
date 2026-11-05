//! OLE compound files ([MS-CFB]), such as jump lists, as Eric Zimmerman's OleCf reads them: what can't be read at all is an
//! error, and other damage is kept in `parse_errors`. Nothing here prints or exits.

use std::collections::HashSet;

use ez_common::Timestamp;
use ez_common::json::Value;
use ez_common::net::guid;

/// OleCfParseException's message
pub type OleResult<T> = Result<T, String>;

const SIGNATURE: u64 = 0xe11a_b1a1_e011_cfd0;
const HEADER_MSAT_ENTRIES: usize = 109;
const DIRECTORY_ENTRY_SIZE: usize = 128;

fn i16_at(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn i32_at(b: &[u8], at: usize) -> i32 {
    u32_at(b, at) as i32
}

#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    pub id: i32,
    pub class_id: String,
    pub user_flags: u32,
    pub creation_time: Option<Timestamp>,
    pub modified_time: Option<Timestamp>,
    pub first_sector: u32,
    pub size: i32,
    pub previous_id: i32,
    pub next_id: i32,
    pub sub_id: i32,
    pub name: String,
    pub entry_type: u8,
    pub color: u8,
    pub parse_errors: Vec<String>,
}

pub const TYPE_STREAM: u8 = 2;
pub const TYPE_ROOT_STORAGE: u8 = 5;

impl DirectoryEntry {
    fn read(raw: &[u8], id: i32) -> DirectoryEntry {
        let mut errors = Vec::new();
        let mut length = i32::from(i16_at(raw, 64));
        if !(2..=64).contains(&length) || length % 2 != 0 {
            errors.push(format!("Invalid name length {length}"));
            length = (length & !1).clamp(2, 64);
        }
        let mut time = |at: usize, field: &str| -> Option<Timestamp> {
            let value = i64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
            if value == 0 {
                return None;
            }
            match Timestamp::from_filetime(value) {
                Some(t) => (t.parts().year != 1601).then_some(t),
                None => {
                    errors.push(format!("{field} is out of range (0x{value:016X})"));
                    None
                }
            }
        };
        let creation_time = time(100, "Creation time");
        let modified_time = time(108, "Modified time");
        DirectoryEntry {
            id,
            class_id: guid(raw[80..96].try_into().unwrap()),
            user_flags: u32_at(raw, 96),
            creation_time,
            modified_time,
            first_sector: u32_at(raw, 116),
            size: i32_at(raw, 120),
            previous_id: i32_at(raw, 68),
            next_id: i32_at(raw, 72),
            sub_id: i32_at(raw, 76),
            name: ez_common::net::unicode_string(raw, 0, i64::from(length - 2)).unwrap_or_default(),
            entry_type: raw[66],
            color: raw[67],
            parse_errors: errors,
        }
    }

    /// DirectoryType.ToString()
    pub fn type_text(&self) -> String {
        match self.entry_type {
            0 => "Empty".to_string(),
            1 => "Storage".to_string(),
            2 => "Stream".to_string(),
            3 => "LockBytes".to_string(),
            4 => "Property".to_string(),
            5 => "RootStorage".to_string(),
            other => other.to_string(),
        }
    }

    /// The properties ServiceStack serializes
    pub fn to_value(&self) -> Value {
        let color = match self.color {
            0 => "Red".to_string(),
            1 => "Black".to_string(),
            other => other.to_string(),
        };
        Value::object(vec![
            ("Id", Value::number(self.id)),
            ("ClassId", Value::guid(&self.class_id)),
            ("UserFlags", Value::number(self.user_flags)),
            ("CreationTime", Value::opt_time(self.creation_time)),
            ("ModifiedTime", Value::opt_time(self.modified_time)),
            ("FirstDirectorySectorId", Value::number(self.first_sector)),
            ("DirectorySize", Value::number(self.size)),
            ("PreviousDirectoryId", Value::number(self.previous_id)),
            ("NextDirectoryId", Value::number(self.next_id)),
            ("SubDirectoryId", Value::number(self.sub_id)),
            ("DirectoryName", Value::text(self.name.as_str())),
            ("DirectoryType", Value::Text(self.type_text())),
            ("NodeColor", Value::Text(color)),
            ("ParseErrors", Value::strings(&self.parse_errors)),
        ])
    }
}

struct Header {
    sector_shift: i16,
    short_shift: i16,
    total_sat: i32,
    directory_first: i32,
    minimum_stream: u32,
    ssat_first: i32,
    msat_first: i32,
    sat_sectors: Vec<i32>,
}

impl Header {
    fn sector_bytes(&self) -> i32 {
        1 << self.sector_shift
    }

    fn sector_offset(&self, id: i32) -> i32 {
        ((i64::from(id) + 1) * i64::from(self.sector_bytes())).min(i64::from(i32::MAX)) as i32
    }

    fn read(raw: &[u8], file_length: i64) -> OleResult<Header> {
        if u64::from_le_bytes(raw[0..8].try_into().unwrap()) != SIGNATURE {
            return Err("Invalid signature!".to_string());
        }
        if u16::from_le_bytes([raw[28], raw[29]]) != 0xfffe {
            return Err("Big endian compound files are not supported".to_string());
        }
        let sector_shift = i16_at(raw, 30);
        let short_shift = i16_at(raw, 32);
        if !(7..=16).contains(&sector_shift) {
            return Err(format!("Invalid sector size shift {sector_shift}"));
        }
        if short_shift < 1 || short_shift >= sector_shift {
            return Err(format!("Invalid short sector size shift {short_shift}"));
        }
        let total_sat = i32_at(raw, 44);
        let mut header = Header {
            sector_shift,
            short_shift,
            total_sat,
            directory_first: i32_at(raw, 48),
            minimum_stream: u32_at(raw, 56),
            ssat_first: i32_at(raw, 60),
            msat_first: i32_at(raw, 68),
            sat_sectors: Vec::new(),
        };
        let maximum = file_length / i64::from(header.sector_bytes()) + 1;
        if total_sat < 0 || i64::from(total_sat) > maximum {
            return Err(format!("Invalid number of SAT sectors ({total_sat}) - is this file corrupt?"));
        }
        header.sat_sectors = vec![0; total_sat as usize];
        for i in 0..HEADER_MSAT_ENTRIES {
            let address = i32_at(raw, 76 + i * 4);
            if address >= 0 {
                if i >= header.sat_sectors.len() {
                    return Err(format!("The current sector ({i}) was larger than the total number of sectors expected from the header data ({total_sat}) - is this file corrupt?"));
                }
                header.sat_sectors[i] = header.sector_offset(address);
            }
        }
        Ok(header)
    }
}

pub struct OleCfFile<'a> {
    raw: &'a [u8],
    header: Header,
    sat: Vec<i32>,
    ssat: Option<Vec<i32>>,
    mini_stream: Vec<u8>,
    pub directory: Vec<DirectoryEntry>,
    pub parse_errors: Vec<String>,
}

fn follow_chain(table: &[i32], first: i32, name: &str, table_name: &str) -> OleResult<Vec<i32>> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut sector = first;
    while sector >= 0 {
        if sector as usize >= table.len() {
            return Err(format!("Sector {sector} of '{name}' is outside the {table_name} ({} entries) - is this file corrupt?", table.len()));
        }
        if !visited.insert(sector) {
            return Err(format!("The {table_name} chain of '{name}' loops back to sector {sector} - is this file corrupt?"));
        }
        chain.push(sector);
        sector = table[sector as usize];
    }
    if chain.is_empty() {
        return Err(format!("'{name}' starts at invalid sector {first}"));
    }
    Ok(chain)
}

impl<'a> OleCfFile<'a> {
    /// new OleCfFile
    pub fn new(raw: &'a [u8], source_file: &str) -> OleResult<OleCfFile<'a>> {
        if raw.len() < 512 {
            return Err(format!("The file length ({}) is less than the length of an OLESS header (512 bytes) - this file ({source_file}) is either not an OLE structured storage document or is corrupt.", raw.len()));
        }
        let header = Header::read(&raw[..512], raw.len() as i64)?;
        let mut file = OleCfFile { raw, header, sat: Vec::new(), ssat: None, mini_stream: Vec::new(), directory: Vec::new(), parse_errors: Vec::new() };
        if file.header.total_sat as usize > HEADER_MSAT_ENTRIES {
            file.read_msat_sectors()?;
        }
        file.read_sat();
        if file.header.ssat_first >= 0 {
            let (bytes, truncated) = file.data_from_sat(file.header.ssat_first, "SSAT")?;
            if truncated {
                file.parse_errors.push("The SSAT is truncated (the file ends before its last sector)".to_string());
            }
            file.ssat = Some(bytes.chunks_exact(4).map(|c| i32::from_le_bytes(c.try_into().unwrap())).collect());
        }
        file.read_directory()?;
        let root = file.directory.iter().find(|d| d.entry_type == TYPE_ROOT_STORAGE).or_else(|| file.directory.iter().find(|d| ez_common::dotnet::lower_invariant(&d.name) == "root entry"));
        if let Some((first, size)) = root.filter(|d| d.size > 0).map(|d| (d.first_sector, d.size)) {
            let (mini, truncated) = file.data_from_sat(first as i32, "Mini stream")?;
            if truncated && (mini.len() as i64) < i64::from(size) {
                file.parse_errors.push(format!("The mini stream is truncated: {} of {size} bytes are in the file", mini.len()));
            }
            file.mini_stream = mini;
        }
        Ok(file)
    }

    fn read_msat_sectors(&mut self) -> OleResult<()> {
        let sector_size = self.header.sector_bytes() as usize;
        let ids_per_sector = sector_size / 4 - 1;
        let mut remaining = self.header.total_sat as usize - HEADER_MSAT_ENTRIES;
        let mut sat_index = HEADER_MSAT_ENTRIES;
        let mut msat = self.header.msat_first;
        let mut visited = HashSet::new();
        while remaining > 0 {
            let offset = self.header.sector_offset(msat);
            if msat < 0 || !visited.insert(msat) || i64::from(offset) + sector_size as i64 > self.raw.len() as i64 {
                return Err(format!("MSAT sector {msat} is invalid, repeated or past the end of the file, with {remaining} SAT sector ids still to read - is this file corrupt?"));
            }
            let offset = offset as usize;
            let count = remaining.min(ids_per_sector);
            for i in 0..count {
                let address = i32_at(self.raw, offset + i * 4);
                if address >= 0 {
                    self.header.sat_sectors[sat_index] = self.header.sector_offset(address);
                }
                sat_index += 1;
            }
            remaining -= count;
            msat = i32_at(self.raw, offset + ids_per_sector * 4);
        }
        Ok(())
    }

    fn read_sat(&mut self) {
        let sector_size = self.header.sector_bytes() as usize;
        let per_sector = sector_size / 4;
        let mut sat = vec![0i32; self.header.total_sat as usize * per_sector];
        for (i, &offset) in self.header.sat_sectors.iter().enumerate() {
            if offset == 0 || i64::from(offset) + sector_size as i64 > self.raw.len() as i64 {
                self.parse_errors.push(if offset == 0 { format!("SAT sector {i} is missing") } else { format!("SAT sector {i} at 0x{offset:X} is past the end of the file") });
                sat[i * per_sector..(i + 1) * per_sector].fill(-1);
                continue;
            }
            for j in 0..per_sector {
                sat[i * per_sector + j] = i32_at(self.raw, offset as usize + j * 4);
            }
        }
        self.sat = sat;
    }

    fn read_directory(&mut self) -> OleResult<()> {
        let (bytes, truncated) = self.data_from_sat(self.header.directory_first, "Directory")?;
        if truncated {
            self.parse_errors.push("The directory is truncated (the file ends before its last sector)".to_string());
        }
        for (i, raw) in bytes.chunks_exact(DIRECTORY_ENTRY_SIZE).enumerate() {
            if raw[66] != 0 && i16_at(raw, 64) > 0 {
                let entry = DirectoryEntry::read(raw, i as i32);
                for e in &entry.parse_errors {
                    self.parse_errors.push(format!("Directory entry {} ({}): {e}", entry.id, entry.name));
                }
                self.directory.push(entry);
            }
        }
        Ok(())
    }

    /// GetDataFromSat: the contents of a chain's sectors that are in the file, and whether some aren't
    fn data_from_sat(&self, first: i32, name: &str) -> OleResult<(Vec<u8>, bool)> {
        let sector_size = i64::from(self.header.sector_bytes());
        let chain = follow_chain(&self.sat, first, name, "SAT")?;
        let length = self.raw.len() as i64;
        let mut present = 0;
        while present < chain.len() && (i64::from(chain[present]) + 1) * sector_size < length {
            present += 1;
        }
        let mut out = Vec::with_capacity(present * sector_size as usize);
        let mut truncated = present < chain.len();
        for (i, &sector) in chain[..present].iter().enumerate() {
            let index = i64::from(self.header.sector_offset(sector));
            let size = sector_size.min(length - index);
            out.extend_from_slice(&self.raw[index as usize..(index + size) as usize]);
            if size < sector_size {
                truncated = i < chain.len() - 1 || truncated;
                break;
            }
        }
        Ok((out, truncated))
    }

    fn data_from_ssat(&self, ssat: &[i32], first: i32, name: &str) -> OleResult<Vec<u8>> {
        let sector_size = 1i64 << self.header.short_shift;
        let chain = follow_chain(ssat, first, name, "SSAT")?;
        let mut out = Vec::with_capacity(chain.len() * sector_size as usize);
        let length = self.mini_stream.len() as i64;
        for &sector in &chain {
            let start = i64::from(sector) * sector_size;
            if start >= length {
                break;
            }
            let size = sector_size.min(length - start);
            out.extend_from_slice(&self.mini_stream[start as usize..(start + size) as usize]);
            if size < sector_size {
                break;
            }
        }
        Ok(out)
    }

    /// GetPayloadForDirectory. None when the stream is in the mini stream and the file has no SSAT
    pub fn payload(&mut self, index: usize) -> OleResult<Option<Vec<u8>>> {
        let (size, first, name) = {
            let d = &self.directory[index];
            (d.size, d.first_sector as i32, d.name.clone())
        };
        if size < 0 {
            return Err(format!("Invalid size ({size}) for directory ({name})"));
        }
        let mut bytes = if i64::from(size) >= i64::from(self.header.minimum_stream) {
            self.data_from_sat(first, &name)?.0
        } else if let Some(ssat) = &self.ssat {
            if size == 0 {
                return Ok(Some(Vec::new()));
            }
            self.data_from_ssat(ssat, first, &name)?
        } else {
            return Ok(None);
        };
        let size = size as usize;
        if size > bytes.len() {
            let message = format!("Stream '{name}' is truncated: {} of {size} bytes are in the file", bytes.len());
            if !self.parse_errors.contains(&message) {
                self.parse_errors.push(message);
            }
        } else {
            bytes.truncate(size);
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_or_foreign_file_is_an_error() {
        assert!(OleCfFile::new(&[0; 10], "x").err().unwrap().contains("less than the length of an OLESS header"));
        assert_eq!(OleCfFile::new(&[0; 512], "x").err().unwrap(), "Invalid signature!");
    }

    #[test]
    fn chains_that_loop_or_leave_the_table_are_errors() {
        assert!(follow_chain(&[1, 0], 0, "a", "SAT").unwrap_err().contains("loops back to sector 0"));
        assert!(follow_chain(&[5], 0, "a", "SAT").unwrap_err().contains("outside the SAT"));
        assert!(follow_chain(&[-2], -1, "a", "SAT").unwrap_err().contains("starts at invalid sector -1"));
        assert_eq!(follow_chain(&[1, -2], 0, "a", "SAT").unwrap(), vec![0, 1]);
    }
}
