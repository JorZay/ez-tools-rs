//! An event log file: a 4 KB header block (`ElfFile`, chunk count, flags, CRC of 0x00-0x77), then 64 KB chunks.

use std::borrow::Cow;
use std::fs::File;
use std::path::Path;

use crate::chunk::{CHUNK_SIZE, Chunk, ParseOptions};
use crate::error::{Error, INVALID_FILE_SIGNATURE, ParseError};

pub const HEADER_BLOCK_SIZE: usize = 0x1000;
const FILE_SIGNATURE: &[u8; 8] = b"ElfFile\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub first_chunk_number: i64,
    pub last_chunk_number: i64,
    pub next_record_id: i64,
    /// 0x80
    pub header_size: i32,
    pub minor_version: i16,
    pub major_version: i16,
    /// 0x1000: the header block chunks start after
    pub header_block_length: u16,
    pub chunk_count: u16,
    /// 0x1: dirty, 0x2: full
    pub flags: u32,
    /// CRC32 of the first 0x78 bytes, as stored and as calculated
    pub crc: u32,
    pub calculated_crc: u32,
}

impl FileHeader {
    pub const FLAG_DIRTY: u32 = 0x1;
    pub const FLAG_FULL: u32 = 0x2;

    pub fn parse(b: &[u8]) -> Result<FileHeader, ParseError> {
        if b.len() < 0x80 || &b[..8] != FILE_SIGNATURE {
            return Err(ParseError::new(INVALID_FILE_SIGNATURE, 0, "FileHeader"));
        }
        let i64_at = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Ok(FileHeader {
            first_chunk_number: i64_at(0x8),
            last_chunk_number: i64_at(0x10),
            next_record_id: i64_at(0x18),
            header_size: u32_at(0x20) as i32,
            minor_version: u16_at(0x24) as i16,
            major_version: u16_at(0x26) as i16,
            header_block_length: u16_at(0x28),
            chunk_count: u16_at(0x2A),
            flags: u32_at(0x78),
            crc: u32_at(0x7C),
            calculated_crc: crc32fast::hash(&b[..0x78]),
        })
    }

    pub fn flags_text(&self) -> String {
        let mut names = Vec::new();
        if self.flags & Self::FLAG_DIRTY != 0 {
            names.push("IsDirty");
        }
        if self.flags & Self::FLAG_FULL != 0 {
            names.push("IsFull");
        }
        if names.is_empty() { "None".into() } else { names.join(", ") }
    }
}

/// A 64 KB block of the file, where a chunk should be
pub struct ChunkData<'a> {
    pub offset: u64,
    /// The block's index in the file (blocks without a chunk signature are counted too)
    pub number: u32,
    /// The bytes; a short last block (a truncated file) is padded with zeros
    pub bytes: Cow<'a, [u8]>,
}

impl ChunkData<'_> {
    pub fn has_signature(&self) -> bool {
        crate::chunk::has_chunk_signature(&self.bytes)
    }

    pub fn parse(&self, options: ParseOptions) -> Result<Chunk, ParseError> {
        Chunk::parse(&self.bytes, self.offset, self.number, options)
    }
}

enum Data {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

/// An event log file, memory mapped or in memory
pub struct EvtxFile {
    data: Data,
    header: FileHeader,
}

impl EvtxFile {
    /// Opens and memory maps a file. Its header must be an event log's.
    ///
    /// The file must not change while it is open (evidence files are read-only copies).
    pub fn open(path: impl AsRef<Path>) -> Result<EvtxFile, Error> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let data = if len == 0 {
            Data::Owned(Vec::new())
        } else {
            // SAFETY: the file is only read, and evidence files are not changed while they are parsed
            Data::Mapped(unsafe { memmap2::Mmap::map(&file)? })
        };
        Self::from_data(data)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<EvtxFile, Error> {
        Self::from_data(Data::Owned(bytes))
    }

    fn from_data(data: Data) -> Result<EvtxFile, Error> {
        let b: &[u8] = match &data {
            Data::Mapped(m) => m,
            Data::Owned(v) => v,
        };
        let header = FileHeader::parse(&b[..b.len().min(HEADER_BLOCK_SIZE)])?;
        Ok(EvtxFile { data, header })
    }

    pub fn bytes(&self) -> &[u8] {
        match &self.data {
            Data::Mapped(m) => m,
            Data::Owned(v) => v,
        }
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// The number of 64 KB blocks after the header block
    pub fn block_count(&self) -> usize {
        self.bytes().len().saturating_sub(HEADER_BLOCK_SIZE).div_ceil(CHUNK_SIZE)
    }

    /// The 64 KB blocks after the header block, in file order
    pub fn chunk_data(&self) -> impl Iterator<Item = ChunkData<'_>> + '_ {
        (0..self.block_count()).map(move |i| self.block(i))
    }

    pub fn block(&self, i: usize) -> ChunkData<'_> {
        let b = self.bytes();
        let start = HEADER_BLOCK_SIZE + i * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(b.len());
        let bytes = if end - start == CHUNK_SIZE {
            Cow::Borrowed(&b[start..end])
        } else {
            let mut padded = b[start..end].to_vec();
            padded.resize(CHUNK_SIZE, 0);
            Cow::Owned(padded)
        };
        ChunkData { offset: start as u64, number: i as u32, bytes }
    }

    /// Every chunk, parsed in file order. Blocks without a chunk signature are left out.
    pub fn chunks<'a>(&'a self, options: ParseOptions<'a>) -> impl Iterator<Item = Result<Chunk, ParseError>> + 'a {
        self.chunk_data().filter(|c| c.has_signature()).map(move |c| c.parse(options))
    }

    /// Every chunk, parsed in parallel, in file order. Blocks without a chunk signature are left out.
    pub fn par_chunks(&self, options: ParseOptions) -> Vec<Result<Chunk, ParseError>> {
        use rayon::prelude::*;
        (0..self.block_count())
            .into_par_iter()
            .filter_map(|i| {
                let c = self.block(i);
                c.has_signature().then(|| c.parse(options))
            })
            .collect()
    }
}
