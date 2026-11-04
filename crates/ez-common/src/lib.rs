//! Code the EZ tool ports share: time stamps and .NET's date and number formats, CSV and JSON as the original tools
//! write them, and (for the command line tools) the console log and output files.

pub mod cli;
pub mod csv;
pub mod dotnet;
pub mod json;
pub mod net;
pub mod time;

pub use time::Timestamp;

/// How important a [`Diagnostic`] is (the EZ tools' log levels)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

/// A message about something found while parsing, as the original tool logs it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: Level,
    pub message: String,
}
