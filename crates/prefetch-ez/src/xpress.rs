//! LZ77+Huffman (XPRESS Huffman) decompression, as used by Windows 10/11 compressed prefetch files: the plain
//! algorithm of [MS-XCA] 2.2.4, as Xpress2 implements it.

const TABLE_BYTES: usize = 256;
const SYMBOL_COUNT: usize = 512;
const MAX_CODE_LENGTH: usize = 15;
const BLOCK_SIZE: usize = 65536;

fn read_u16(b: &[u8], pos: usize) -> u32 {
    b[pos] as u32 | (b[pos + 1] as u32) << 8
}

struct Bits<'a> {
    buffer: &'a [u8],
    pos: usize,
    next: u32,
    extra: i32,
}

impl Bits<'_> {
    fn consume(&mut self, count: u32) -> Result<(), String> {
        if count == 0 {
            return Ok(());
        }
        self.next <<= count;
        self.extra -= count as i32;
        if self.extra < 0 {
            if self.pos + 2 > self.buffer.len() {
                return Err(format!("Bit stream runs past the end of the data at offset {}", self.pos));
            }
            self.next |= read_u16(self.buffer, self.pos) << -self.extra;
            self.extra += 16;
            self.pos += 2;
        }
        Ok(())
    }
}

/// Decompresses `buffer` into exactly `size` bytes; Err with the reason when the data is corrupt or truncated
pub fn decompress(buffer: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let mut output = vec![0u8; size];
    let mut out_pos = 0;
    let mut in_pos = 0;
    let mut lengths = [0u8; SYMBOL_COUNT];
    let mut table = vec![0u16; 1 << MAX_CODE_LENGTH];

    while out_pos < output.len() {
        if in_pos + TABLE_BYTES + 4 > buffer.len() {
            return Err(format!(
                "Compressed data ends at offset {} before {} bytes were produced (got {out_pos})",
                buffer.len(),
                output.len()
            ));
        }
        // 256 bytes hold 512 4-bit code lengths; the low nibble is the even symbol
        for i in 0..TABLE_BYTES {
            lengths[i * 2] = buffer[in_pos + i] & 0x0F;
            lengths[i * 2 + 1] = buffer[in_pos + i] >> 4;
        }
        build_decoding_table(&lengths, &mut table)?;

        let start = in_pos + TABLE_BYTES;
        let mut bits =
            Bits { buffer, pos: start + 4, next: read_u16(buffer, start) << 16 | read_u16(buffer, start + 2), extra: 16 };
        let block_end = (out_pos + BLOCK_SIZE).min(output.len());

        while out_pos < block_end {
            let symbol = table[(bits.next >> (32 - MAX_CODE_LENGTH)) as usize] as usize;
            bits.consume(lengths[symbol] as u32)?;
            if symbol < 256 {
                output[out_pos] = symbol as u8;
                out_pos += 1;
                continue;
            }
            let symbol = symbol - 256;
            let mut match_length = symbol & 0x0F;
            let offset_bits = (symbol >> 4) as u32;
            if match_length == 15 {
                if bits.pos >= buffer.len() {
                    return Err(format!("Match length byte past end of data at offset {}", bits.pos));
                }
                match_length = buffer[bits.pos] as usize;
                bits.pos += 1;
                if match_length == 255 {
                    if bits.pos + 2 > buffer.len() {
                        return Err(format!("Match length word past end of data at offset {}", bits.pos));
                    }
                    match_length = read_u16(buffer, bits.pos) as usize;
                    bits.pos += 2;
                    if match_length < 15 {
                        return Err(format!("Invalid extended match length {match_length} at offset {}", bits.pos - 2));
                    }
                    match_length -= 15;
                }
                match_length += 15;
            }
            match_length += 3;

            let match_offset =
                if offset_bits == 0 { 1 } else { (bits.next >> (32 - offset_bits)) as usize + (1 << offset_bits) };
            bits.consume(offset_bits)?;
            if match_offset > out_pos {
                return Err(format!(
                    "Match offset {match_offset} points before the start of the output (position {out_pos})"
                ));
            }
            // Matches may overlap their own output and may run past the block end; stop at the declared size
            let copy_end = (out_pos + match_length).min(output.len());
            while out_pos < copy_end {
                output[out_pos] = output[out_pos - match_offset];
                out_pos += 1;
            }
        }
        // Any bits still buffered are discarded; the next block's table starts at the next unread byte
        in_pos = bits.pos;
    }
    Ok(output)
}

/// A canonical Huffman lookup table indexed by the next 15 bits of input
fn build_decoding_table(lengths: &[u8; SYMBOL_COUNT], table: &mut [u16]) -> Result<(), String> {
    let mut next = 0;
    for length in 1..=MAX_CODE_LENGTH {
        let span = 1 << (MAX_CODE_LENGTH - length);
        for (symbol, l) in lengths.iter().enumerate() {
            if *l as usize != length {
                continue;
            }
            if next + span > table.len() {
                return Err("Huffman code lengths are over-subscribed".into());
            }
            table[next..next + span].fill(symbol as u16);
            next += span;
        }
    }
    if next == 0 {
        return Err("Huffman table has no symbols".into());
    }
    // An incomplete code leaves unreachable entries; point them at a symbol with a nonzero length so a corrupt
    // stream can't make the decoder stop consuming input
    let last = table[next - 1];
    table[next..].fill(last);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_then_zero_bit_offset_match() {
        // 'A' (code 0) then symbol 258 (code 1): match length 2 + 3, offset bits 0 => offset 1
        let mut data = [0u8; 260];
        data[32] = 0x10;
        data[129] = 0x01;
        data[257] = 0x40;
        assert_eq!(decompress(&data, 6).unwrap(), b"AAAAAA");
    }

    #[test]
    fn match_with_offset_bits() {
        // 'A' = 0, 'B' = 10, symbol 273 = 11 (length 1 + 3, 1 offset bit), offset bit 0 => offset 2
        let mut data = [0u8; 260];
        data[32] = 0x10;
        data[33] = 0x02;
        data[136] = 0x20;
        data[257] = 0x58;
        assert_eq!(decompress(&data, 6).unwrap(), b"ABABAB");
    }

    #[test]
    fn corrupt_data_is_an_error() {
        assert!(decompress(&[0u8; 10], 6).unwrap_err().starts_with("Compressed data ends"));
        assert_eq!(decompress(&[0u8; 260], 6).unwrap_err(), "Huffman table has no symbols");
    }
}
