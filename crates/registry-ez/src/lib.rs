//! Windows registry hives as the Registry library (Eric Zimmerman's, used by RECmd) reads them: keys and values,
//! deleted keys and values recovered from free cells and slack, and transaction logs (.LOG1/.LOG2, and the old
//! .LOG format) applied to dirty hives.

pub mod cells;
pub mod header;
pub mod hive;
pub mod replay;

pub use header::{Header, HiveType};
pub use hive::{Hive, KeyId, SearchHit, ValueObj, VkId};
