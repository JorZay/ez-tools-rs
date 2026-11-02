//! $Secure:$SDS: security descriptors in 256 KB data blocks, each followed by a 256 KB mirror. Each security id is
//! returned once from the data blocks; a mirror copy that differs is added, marked as from the mirror.

use crate::mft::security::SkSecurityDescriptor;

const BLOCK_SIZE: usize = 0x40000;
const HEADER_SIZE: u32 = 0x14;

#[derive(Debug, Clone)]
pub struct SdsEntry {
    hash: u32,
    pub id: u32,
    pub offset: u64,
    pub size: u32,
    pub file_offset: u64,
    pub security_descriptor: SkSecurityDescriptor,
    pub from_mirror: bool,
}

impl SdsEntry {
    /// The hash's bytes as hex, in file order
    pub fn hash(&self) -> String {
        let b = self.hash.to_le_bytes();
        format!("{:02X}{:02X}{:02X}{:02X}", b[0], b[1], b[2], b[3])
    }
}

pub struct Sds {
    pub entries: Vec<SdsEntry>,
    pub parse_errors: Vec<String>,
}

impl Sds {
    pub fn parse(raw: &[u8]) -> Sds {
        let mut s = Sds { entries: Vec::new(), parse_errors: Vec::new() };
        let read = raw.len();
        let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        let mut block = 0usize;
        while block < read {
            let end = (block + BLOCK_SIZE).min(read) as i64;
            let mut index = block as i64;
            while end - index >= HEADER_SIZE as i64 {
                let i = index as usize;
                let (hash, id, offset, size) = (u32_at(i), u32_at(i + 4), u64_at(i + 8), u32_at(i + 16));
                if hash == 0 && id == 0 && offset == 0 && size == 0 {
                    break;
                }
                if size < HEADER_SIZE || size as i64 > end - index || (id > 0 && offset != index as u64) {
                    s.parse_errors.push(format!(
                        "Bad entry at 0x{index:X} (id 0x{id:X}, offset 0x{offset:X}, size 0x{size:X}); looking for the next entry"
                    ));
                    index = resync(raw, index + 16, end);
                    continue;
                }
                if id > 0 {
                    s.add(raw, i, hash, id, offset, size, false);
                    let mirror = i + BLOCK_SIZE;
                    if mirror + size as usize <= read && raw[i..i + size as usize] != raw[mirror..mirror + size as usize] {
                        let mirror_size = u32_at(mirror + 16);
                        if mirror_size >= HEADER_SIZE && mirror + mirror_size as usize <= read {
                            s.add(raw, mirror, u32_at(mirror), u32_at(mirror + 4), u64_at(mirror + 8), mirror_size, true);
                        }
                    }
                }
                index += ((size + 15) & !15) as i64;
            }
            block += 2 * BLOCK_SIZE;
        }
        s
    }

    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, raw: &[u8], index: usize, hash: u32, id: u32, offset: u64, size: u32, from_mirror: bool) {
        let d = raw[index + HEADER_SIZE as usize..index + size as usize].to_vec();
        match SkSecurityDescriptor::new(d) {
            Ok(sk) => self.entries.push(SdsEntry {
                hash,
                id,
                offset,
                size,
                file_offset: index as u64,
                security_descriptor: sk,
                from_mirror,
            }),
            Err(e) => self.parse_errors.push(format!(
                "Security descriptor of entry 0x{id:X} at 0x{index:X} could not be parsed: {e}"
            )),
        }
    }
}

fn resync(raw: &[u8], mut index: i64, end: i64) -> i64 {
    let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
    while end - index >= HEADER_SIZE as i64 {
        let i = index as usize;
        let id = u32_at(i + 4);
        let offset = u64::from_le_bytes(raw[i + 8..i + 16].try_into().unwrap());
        let size = u32_at(i + 16);
        if id > 0 && offset == index as u64 && size >= HEADER_SIZE && size as i64 <= end - index {
            return index;
        }
        index += 16;
    }
    end
}
