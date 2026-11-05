//! SQLECmd's maps: loading `.smap` files exactly as the original accepts them, and running them on SQLite databases with
//! the values System.Data.SQLite, Dapper and CsvHelper give. Nothing here prints or exits.

mod db;
mod functions;
mod map;
mod value;

pub use db::{Database, NetError, Table, is_sqlite_file};
pub use map::{BlobColumn, LoadedMaps, MapFile, QueryInfo, Sink, load_maps};
pub use value::Value;
