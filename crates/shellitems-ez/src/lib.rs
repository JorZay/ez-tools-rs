//! Windows shell items, their 0xbeef extension blocks and property stores, as Eric Zimmerman's ExtensionBlocks reads them:
//! the same fields and the same text, for LECmd and the tools that read the same structures. Nothing here prints or exits.

pub mod blocks;
pub mod items;
pub mod sheet;
pub mod utils;

pub use blocks::{Block, BlockKind};
pub use items::{ShellItem, create as create_item, create_with_code_page};
pub use sheet::{PropertySheet, PropertyStore};
