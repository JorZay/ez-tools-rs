//! Windows event log (EVTX) parsing with the output EvtxECmd produces.
//!
//! A port of Eric Zimmerman's evtx library and EvtxECmd (<https://github.com/EricZimmerman/evtx>, MIT). Values,
//! XML, JSON and CSV are written as EvtxECmd writes them, so its output and this one can be compared.
//!
//! ```no_run
//! use evtx_ez::{EvtxFile, ParseOptions};
//!
//! let file = EvtxFile::open("Security.evtx")?;
//! for chunk in file.chunks(ParseOptions::default()) {
//!     for record in chunk?.records {
//!         println!("{} {} {}", record.time_created, record.event_id, record.payload_json());
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod binxml;
pub mod chunk;
pub mod error;
pub mod file;
pub mod maps;
pub mod output;
pub mod record;
pub use ez_common::time;
pub mod timeline;

pub use chunk::{Chunk, ParseOptions};
pub use error::{Error, ParseError};
pub use file::{EvtxFile, FileHeader};
pub use maps::MapSet;
pub use record::EventRecord;
pub use time::Timestamp;

pub use ez_common::{Diagnostic, Level};
