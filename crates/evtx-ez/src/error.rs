use std::fmt;

/// Data that cannot be used: a bad file header, a chunk or record that cannot be read, or BinXml that cannot be
/// parsed. Parsing a file reports these and goes on; only a bad file header stops it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    /// Byte offset of the problem (in the chunk for BinXml and records, in the file for the header), or -1
    pub offset: i64,
    /// The structure being read
    pub field: &'static str,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>, offset: impl TryInto<i64>, field: &'static str) -> ParseError {
        ParseError { message: message.into(), offset: offset.try_into().unwrap_or(-1), field }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

pub type Result<T> = std::result::Result<T, ParseError>;

/// The message for a file that is not an event log
pub const INVALID_FILE_SIGNATURE: &str = "Invalid signature! Expected 'ElfFile'";

/// Opening a file: it could not be read, or it is not an event log
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Parse(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}
