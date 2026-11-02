//! NTFS metadata files, parsed as Eric Zimmerman's MFT libraries parse them (https://github.com/EricZimmerman/MFT,
//! MIT), with the output MFTECmd writes.
//!
//! ```no_run
//! use ntfs_ez::mft::{Mft, export};
//!
//! let mft = Mft::open("$MFT")?;
//! let options = export::ExportOptions { source_file: "$MFT".into(), ..Default::default() };
//! for &block in mft.in_use.iter().chain(&mft.free) {
//!     let record = mft.full_record(block);
//!     for row in export::record_rows(&mft, &record, &options)?.rows {
//!         println!("{}\\{}", row.parent_path, row.file_name);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod boot;
pub mod i30;
pub mod mft;
pub mod sds;
pub mod usn;

pub use ez_common::time;
pub use ez_common::{Diagnostic, Level};
