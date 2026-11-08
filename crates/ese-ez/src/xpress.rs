//! ESE's Xpress decoder (`_xpress/xdecode.i`, CODING_DIRECT2): LZ77 with 32-bit flag words read high bit first (0 a literal byte,
//! 1 a match), a match being a 16-bit word of the offset less 1 (13 bits) and the length less 3 (3 bits), longer lengths in a
//! shared nibble, a byte and a word.

/// The `size` bytes encoded in `src`
pub fn decode(src: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let short = || "An Xpress compressed value ends early".to_string();
    let mut out = Vec::with_capacity(size);
    let (mut at, mut flags, mut flag_bits) = (0usize, 0u32, 0u32);
    // the byte whose high nibble the next long length takes
    let mut nibble: Option<usize> = None;
    let byte = |at: &mut usize| -> Result<usize, String> {
        let b = *src.get(*at).ok_or_else(short)?;
        *at += 1;
        Ok(usize::from(b))
    };
    let word = |at: &mut usize| -> Result<usize, String> {
        let w = src.get(*at..*at + 2).ok_or_else(short)?;
        *at += 2;
        Ok(usize::from(u16::from_le_bytes([w[0], w[1]])))
    };
    while out.len() < size {
        if flag_bits == 0 {
            let f = src.get(at..at + 4).ok_or_else(short)?;
            flags = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
            at += 4;
            flag_bits = 32;
        }
        flag_bits -= 1;
        if flags & (1 << flag_bits) == 0 {
            out.push(*src.get(at).ok_or_else(short)?);
            at += 1;
            continue;
        }
        let token = word(&mut at)?;
        let offset = (token >> 3) + 1;
        let mut length = token & 7;
        if length == 7 {
            length = match nibble.take() {
                None => {
                    nibble = Some(at);
                    byte(&mut at)? & 15
                }
                Some(n) => usize::from(src[n] >> 4),
            };
            if length == 15 {
                length = byte(&mut at)?;
                if length == 255 {
                    length = word(&mut at)?;
                    if length < 255 + 15 + 7 {
                        return Err("An Xpress compressed value is damaged".to_string());
                    }
                    length -= 15 + 7;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        let from = out.len().checked_sub(offset).ok_or("An Xpress compressed value refers to bytes before its start")?;
        for i in 0..length.min(size - out.len()) {
            out.push(out[from + i]);
        }
    }
    Ok(out)
}

/// An LZ4 block (LZ4_decompress_safe_partial, as ESE calls it) of a value of `size` bytes: tokens of a literal length (high nibble)
/// and a match length less 4 (low nibble), 15 continued by bytes; the literals; a 16-bit offset; the last sequence has no match
pub fn lz4(src: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let short = || "An LZ4 compressed value ends early".to_string();
    let mut out = Vec::with_capacity(size);
    let mut at = 0usize;
    let length = |at: &mut usize, mut n: usize| -> Result<usize, String> {
        if n == 15 {
            loop {
                let b = *src.get(*at).ok_or_else(short)?;
                *at += 1;
                n += usize::from(b);
                if b != 255 {
                    break;
                }
            }
        }
        Ok(n)
    };
    while out.len() < size {
        let token = *src.get(at).ok_or_else(short)?;
        at += 1;
        let literals = length(&mut at, usize::from(token >> 4))?;
        let bytes = src.get(at..at + literals).ok_or_else(short)?;
        at += literals;
        out.extend_from_slice(&bytes[..literals.min(size - out.len())]);
        if out.len() >= size || at >= src.len() {
            break;
        }
        let o = src.get(at..at + 2).ok_or_else(short)?;
        let offset = usize::from(u16::from_le_bytes([o[0], o[1]]));
        at += 2;
        let matched = length(&mut at, usize::from(token & 15))? + 4;
        if offset == 0 || offset > out.len() {
            return Err("An LZ4 compressed value refers to bytes before its start".to_string());
        }
        let from = out.len() - offset;
        for i in 0..matched.min(size - out.len()) {
            out.push(out[from + i]);
        }
    }
    if out.len() != size {
        return Err(format!("An LZ4 compressed value gives {} of its {size} bytes", out.len()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, lz4};

    #[test]
    fn lz4_blocks() {
        // "abc", then 7 bytes from 3 back, then the literal "z"
        let src = [0x33, b'a', b'b', b'c', 3, 0, 0x10, b'z'];
        assert_eq!(lz4(&src, 11).unwrap(), b"abcabcabcaz");
        assert!(lz4(&src[..4], 11).is_err());
        assert!(lz4(&[0x10, b'a', 9, 0], 9).is_err());
    }

    #[test]
    fn literals_and_matches() {
        // "abcabcabca": three literals, then a match of 7 at offset 3 (word: offset-1 = 2 << 3 | 7-3 = 4)
        let flags: u32 = 1 << 28;
        let mut src = flags.to_le_bytes().to_vec();
        src.extend_from_slice(b"abc");
        src.extend_from_slice(&((2u16 << 3) | 4).to_le_bytes());
        assert_eq!(decode(&src, 10).unwrap(), b"abcabcabca");
        assert!(decode(&src[..5], 10).is_err());
    }

    #[test]
    fn long_lengths() {
        // "a", then a match of 3 + 7 + 5 = 15 bytes at offset 1: length 7 in the word, 5 in the nibble
        let flags: u32 = 1 << 30;
        let mut src = flags.to_le_bytes().to_vec();
        src.push(b'a');
        src.extend_from_slice(&7u16.to_le_bytes());
        src.push(5);
        assert_eq!(decode(&src, 16).unwrap(), vec![b'a'; 16]);
    }
}
