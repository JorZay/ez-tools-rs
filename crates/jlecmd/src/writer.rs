//! A file written as a .NET StreamWriter over a FileStream writes it: what the two buffers hold is lost unless the file is
//! closed, which the original doesn't do for the exports it gives up on. So what reaches the disk here is what reaches it there.

use std::fs::File;
use std::io::{self, Write};

const CHAR_BUFFER: usize = 1024;
const FILE_BUFFER: usize = 4096;

pub struct NetWriter {
    file: File,
    chars: Vec<u16>,
    bytes: Vec<u8>,
    preamble: &'static [u8],
    wrote_preamble: bool,
    /// A high surrogate at the end of a block, which the encoder keeps for the next one
    held: Option<u16>,
}

impl NetWriter {
    /// With what the encoding writes first, if anything
    pub fn create(path: &str, preamble: &'static [u8]) -> io::Result<NetWriter> {
        Ok(NetWriter { file: File::create(path)?, chars: Vec::with_capacity(CHAR_BUFFER), bytes: Vec::with_capacity(FILE_BUFFER), preamble, wrote_preamble: false, held: None })
    }

    pub fn write_text(&mut self, text: &str) -> io::Result<()> {
        for unit in text.encode_utf16() {
            self.chars.push(unit);
            if self.chars.len() == CHAR_BUFFER {
                self.flush_chars()?;
            }
        }
        Ok(())
    }

    fn flush_chars(&mut self) -> io::Result<()> {
        if !self.wrote_preamble {
            self.wrote_preamble = true;
            let preamble = self.preamble;
            self.stream_write(preamble)?;
        }
        let mut units = Vec::with_capacity(self.chars.len() + 1);
        units.extend(self.held.take());
        units.append(&mut self.chars);
        if units.last().is_some_and(|u| (0xd800..0xdc00).contains(u)) {
            self.held = units.pop();
        }
        if units.is_empty() {
            return Ok(());
        }
        let text = String::from_utf16_lossy(&units);
        self.stream_write(text.as_bytes())
    }

    /// BufferedFileStreamStrategy.Write
    fn stream_write(&mut self, source: &[u8]) -> io::Result<()> {
        let total = self.bytes.len() + source.len();
        if total + source.len() < FILE_BUFFER * 2 {
            let room = FILE_BUFFER - self.bytes.len();
            let first = room.min(source.len());
            self.bytes.extend_from_slice(&source[..first]);
            if self.bytes.len() < FILE_BUFFER {
                return Ok(());
            }
            self.file.write_all(&self.bytes)?;
            self.bytes.clear();
            self.bytes.extend_from_slice(&source[first..]);
            return Ok(());
        }
        if !self.bytes.is_empty() {
            if total <= FILE_BUFFER * 2 {
                self.bytes.extend_from_slice(source);
                self.file.write_all(&self.bytes)?;
                self.bytes.clear();
                return Ok(());
            }
            self.file.write_all(&self.bytes)?;
            self.bytes.clear();
        }
        self.file.write_all(source)
    }

    /// Flush(), and with it all that was written is in the file
    pub fn flush(&mut self) -> io::Result<()> {
        self.flush_chars()?;
        if !self.bytes.is_empty() {
            self.file.write_all(&self.bytes)?;
            self.bytes.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> String {
        std::env::temp_dir().join(format!("jlecmd-writer-{}-{name}", std::process::id())).to_string_lossy().into_owned()
    }

    #[test]
    fn what_is_not_flushed_is_lost() {
        let path = temp("lost");
        let mut w = NetWriter::create(&path, &[]).unwrap();
        w.write_text(&"a".repeat(1000)).unwrap();
        drop(w);
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_flush_writes_everything_with_the_preamble() {
        let path = temp("flush");
        let mut w = NetWriter::create(&path, &[0xef, 0xbb, 0xbf]).unwrap();
        w.write_text(&"é".repeat(3000)).unwrap();
        w.flush().unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), 3 + 6000);
        std::fs::remove_file(&path).unwrap();
    }
}
