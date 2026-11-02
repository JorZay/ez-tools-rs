//! A 64 KB chunk: a 512 byte header (with a 64 entry string table and a 32 entry template table, which are only hash
//! tables of what the records define), then event records up to the free space offset.

use crate::binxml::parser::BinXmlParser;
use crate::error::{ParseError, Result};
use crate::maps::MapSet;
use crate::record::{EventRecord, RECORD_HEADER_SIZE, RECORD_SIGNATURE};
use crate::{Diagnostic, Level};

pub const CHUNK_SIZE: usize = 0x10000;
pub const CHUNK_HEADER_SIZE: usize = 0x200;
pub(crate) const CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";

/// How records are parsed
#[derive(Clone, Copy, Default)]
pub struct ParseOptions<'a> {
    /// Maps to fill the mapped fields with
    pub maps: Option<&'a MapSet>,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub absolute_offset: u64,
    pub chunk_number: u32,
    pub first_event_record_number: i64,
    pub last_event_record_number: i64,
    pub first_event_record_identifier: i64,
    pub last_event_record_identifier: i64,
    pub last_record_offset: u32,
    pub free_space_offset: u32,
    /// 0x1: dirty, 0x4: no CRC32 (the header and data CRCs are not kept up to date)
    pub flags: u32,
    /// CRC32 of the header (0x00-0x77 and 0x80-0x1FF), as stored and as calculated. Only reported, never enforced.
    pub crc: u32,
    pub calculated_crc: u32,
    /// CRC32 of the records, as stored and as calculated
    pub data_crc: u32,
    pub calculated_data_crc: u32,
    /// The number of template definitions the records used
    pub template_count: usize,
    /// Records in chunk order; a hidden record follows the record it was found in
    pub records: Vec<EventRecord>,
    /// Records that could not be read: record number and message (the first one for a number)
    pub errors: Vec<(i64, String)>,
    /// Messages EvtxECmd logs while parsing (hidden records, map values not found...)
    pub diagnostics: Vec<Diagnostic>,
}

fn i64_at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// True when the bytes start with the chunk signature
pub fn has_chunk_signature(b: &[u8]) -> bool {
    b.len() >= 8 && &b[..8] == CHUNK_SIGNATURE
}

impl Chunk {
    /// Parses a chunk. Records that cannot be read are listed in `errors`, and parsing goes on with the next one; the
    /// error is for a chunk without the chunk signature.
    pub fn parse(bytes: &[u8], absolute_offset: u64, chunk_number: u32, options: ParseOptions) -> Result<Chunk> {
        if bytes.len() < CHUNK_HEADER_SIZE || !has_chunk_signature(bytes) {
            return Err(ParseError::new("Invalid chunk signature! Expected 'ElfChnk'", absolute_offset as i64, "ChunkHeader"));
        }
        let b = bytes;

        let mut crc = crc32fast::Hasher::new();
        crc.update(&b[..0x78]);
        crc.update(&b[0x80..CHUNK_HEADER_SIZE]);

        let free_space_offset = u32_at(b, 0x30);
        // records end at the free space offset; a bad value (dirty or damaged chunk) means the end of the chunk
        let end = if (CHUNK_HEADER_SIZE as u32..=b.len() as u32).contains(&free_space_offset) {
            free_space_offset as usize
        } else {
            b.len()
        };

        let mut chunk = Chunk {
            absolute_offset,
            chunk_number,
            first_event_record_number: i64_at(b, 0x8),
            last_event_record_number: i64_at(b, 0x10),
            first_event_record_identifier: i64_at(b, 0x18),
            last_event_record_identifier: i64_at(b, 0x20),
            last_record_offset: u32_at(b, 0x2C),
            free_space_offset,
            flags: u32_at(b, 0x78),
            crc: u32_at(b, 0x7C),
            calculated_crc: crc.finalize(),
            data_crc: u32_at(b, 0x34),
            calculated_data_crc: crc32fast::hash(&b[CHUNK_HEADER_SIZE..end]),
            template_count: 0,
            records: Vec::new(),
            errors: Vec::new(),
            diagnostics: Vec::new(),
        };

        if chunk.first_event_record_identifier == -1 {
            // an empty chunk
            return Ok(chunk);
        }

        let mut parser = BinXmlParser::new(b);
        let mut position = CHUNK_HEADER_SIZE;
        while position + RECORD_HEADER_SIZE + 4 <= end {
            if u32_at(b, position) != RECORD_SIGNATURE {
                chunk.diag(Level::Trace, format!("No record signature at 0x{:X}. Stopping", absolute_offset + position as u64));
                break;
            }
            let size = u32_at(b, position + 4) as usize;
            let record_number = i64_at(b, position + 8);

            if size < RECORD_HEADER_SIZE + 4 || position + size > b.len() {
                chunk.diag(
                    Level::Trace,
                    format!("Record at 0x{:X} has an invalid size 0x{size:X}. Stopping", absolute_offset + position as u64),
                );
                chunk.add_error(
                    record_number,
                    format!("Record at offset 0x{:X} has an invalid size (0x{size:X})", absolute_offset + position as u64),
                );
                break;
            }

            let parsed = EventRecord::parse(&mut parser, chunk_number, position, size).and_then(|mut record| {
                if let Some(maps) = options.maps {
                    maps.apply(&mut record, &mut chunk.diagnostics).map_err(|m| ParseError::new(m, position, "Map"))?;
                }
                Ok(record)
            });
            match parsed {
                Ok(record) => {
                    let hidden = record.has_hidden_record(b);
                    let host_position = record.record_position + record.extra_data_offset as usize;
                    chunk.records.push(record);
                    if hidden {
                        chunk.add_hidden_record(&mut parser, host_position, options);
                    }
                }
                Err(e) => {
                    chunk.diag(
                        Level::Error,
                        format!(
                            "Record error at offset 0x{:X}, record #: {record_number} error: {}",
                            absolute_offset + position as u64,
                            e.message
                        ),
                    );
                    chunk.add_error(record_number, e.message);
                }
            }

            position += size;
            if record_number == chunk.last_event_record_identifier {
                // what follows is slack (as the chunk header says, and the reference parsers agree)
                break;
            }
        }

        chunk.template_count = parser.template_count();
        Ok(chunk)
    }

    fn diag(&mut self, level: Level, message: String) {
        self.diagnostics.push(Diagnostic { level, message });
    }

    fn add_error(&mut self, record_number: i64, message: String) {
        if !self.errors.iter().any(|(n, _)| *n == record_number) {
            self.errors.push((record_number, message));
        }
    }

    /// A record hidden in the slack of another (e.g. DanderSpritz's eventlogedit)
    fn add_hidden_record(&mut self, parser: &mut BinXmlParser, position: usize, options: ParseOptions) {
        let b = parser.bytes();
        let size = i32::from_le_bytes(b[position + 4..position + 8].try_into().unwrap());
        let parsed = if size < 0 {
            Err(ParseError::new(format!("Record size 0x{size:X} does not fit in the chunk"), position, "EventRecord"))
        } else {
            EventRecord::parse(parser, self.chunk_number, position, size as usize)
        };
        let parsed = parsed.and_then(|mut record| {
            if let Some(maps) = options.maps {
                maps.apply(&mut record, &mut self.diagnostics).map_err(|m| ParseError::new(m, position, "Map"))?;
            }
            Ok(record)
        });
        match parsed {
            Ok(mut hidden) => {
                hidden.hidden_record = true;
                self.diag(
                    Level::Warning,
                    format!(
                        "Record #: {} (timestamp: {}): Warning! A hidden record was found! Possible DanderSpritz use detected!",
                        hidden.record_number, hidden.time_created
                    ),
                );
                self.records.push(hidden);
            }
            Err(e) => self.diag(
                Level::Debug,
                format!("Possible hidden record at 0x{:X} could not be read: {}", self.absolute_offset + position as u64, e.message),
            ),
        }
    }
}
