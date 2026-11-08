//! ESE (Extensible Storage Engine, "JET Blue") databases, read directly from the file: the header, the catalog and the rows of
//! each table in key order, with their fixed, variable and tagged columns. It never writes.
//!
//! The file is taken as it is: transaction logs aren't replayed, so a database that wasn't shut down cleanly (see
//! [`Database::state`]) shows what had reached it. Long values and compressed values are reported as errors for the
//! column asked for, not read: SRUM databases have neither. Page checksums aren't checked; every offset is, so damage
//! gives an error and not a panic. Nothing here prints or exits.

use std::collections::{HashMap, HashSet};

const SIGNATURE: u32 = 0x89ab_cdef;
const CATALOG_ROOT: u32 = 4;
const MAX_DEPTH: u32 = 64;

const PAGE_LEAF: u32 = 0x2;
const TAG_DELETED: u16 = 0x2;
const TAG_COMPRESSED_KEY: u16 = 0x4;

const TYPE_TABLE: u16 = 1;
const TYPE_COLUMN: u16 = 2;

const VALUE_COMPRESSED: u8 = 0x2;
const VALUE_LONG: u8 = 0x4;
const VALUE_MULTI: u8 = 0x8;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A column of a table, from the catalog
#[derive(Clone, Debug)]
pub struct Column {
    pub id: u32,
    pub name: String,
    /// JET_coltyp
    pub coltyp: u32,
    pub space: u32,
    /// Where a fixed column is in a record
    offset: usize,
}

/// A table, from the catalog
#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub object_id: i32,
    pub root_page: u32,
    pub columns: Vec<Column>,
    by_name: HashMap<String, usize>,
}

/// The size a fixed column takes. Text and binary ones say so in the catalog
fn fixed_size(coltyp: u32, space: u32) -> usize {
    match coltyp {
        1 | 2 => 1,
        3 | 17 => 2,
        4 | 6 | 14 => 4,
        5 | 7 | 8 | 15 => 8,
        16 => 16,
        _ => space as usize,
    }
}

impl Table {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.by_name.get(name).map(|&i| &self.columns[i])
    }

    fn finish(&mut self) {
        self.columns.sort_by_key(|c| c.id);
        let mut offset = 4;
        for c in &mut self.columns {
            if c.id <= 127 {
                c.offset = offset;
                offset += fixed_size(c.coltyp, c.space);
            }
        }
        self.by_name = self.columns.iter().enumerate().map(|(i, c)| (c.name.clone(), i)).collect();
    }
}

/// A row of a table
#[derive(Clone, Copy)]
pub struct Row<'a> {
    data: &'a [u8],
    masks: Masks,
}

#[derive(Clone, Copy)]
struct Masks {
    value: u16,
    extended: u16,
}

impl<'a> Row<'a> {
    /// A column's bytes; None when it's null or the record ends before it. An error says what couldn't be read
    pub fn value(&self, column: &Column) -> Result<Option<&'a [u8]>, String> {
        let d = self.data;
        if d.len() < 4 {
            return Err(format!("A record of {} bytes is too short", d.len()));
        }
        let (last_fixed, last_variable) = (u32::from(d[0]), u32::from(d[1]));
        let variable_at = usize::from(u16_at(d, 2).unwrap_or(0));
        if column.id <= 127 {
            if column.id > last_fixed {
                return Ok(None);
            }
            let bitmap = variable_at.checked_sub((last_fixed as usize).div_ceil(8)).ok_or("A record's fixed columns are damaged")?;
            let bit = column.id as usize - 1;
            let byte = *d.get(bitmap + bit / 8).ok_or("A record's null bitmap is outside it")?;
            if byte & (1 << (bit % 8)) != 0 {
                return Ok(None);
            }
            let size = fixed_size(column.coltyp, column.space);
            return d.get(column.offset..column.offset + size).map(Some).ok_or_else(|| format!("Column {} is outside its record", column.name));
        }
        let variables = last_variable.saturating_sub(127) as usize;
        let data_at = variable_at + variables * 2;
        let end_of = |index: usize| -> Result<usize, String> {
            let raw = u16_at(d, variable_at + index * 2).ok_or("A record's variable column offsets are outside it")?;
            Ok(usize::from(raw & 0x7fff))
        };
        if column.id <= 255 {
            let index = column.id as usize - 128;
            if index >= variables {
                return Ok(None);
            }
            let raw = u16_at(d, variable_at + index * 2).ok_or("A record's variable column offsets are outside it")?;
            if raw & 0x8000 != 0 {
                return Ok(None);
            }
            let start = if index == 0 { 0 } else { end_of(index - 1)? };
            let end = usize::from(raw & 0x7fff);
            if start > end {
                return Err(format!("Column {} has offsets in the wrong order", column.name));
            }
            return d.get(data_at + start..data_at + end).map(Some).ok_or_else(|| format!("Column {} is outside its record", column.name));
        }
        let tagged_at = data_at + if variables > 0 { end_of(variables - 1)? } else { 0 };
        if tagged_at >= d.len() {
            return Ok(None);
        }
        let area = &d[tagged_at..];
        let first = usize::from(u16_at(area, 2).ok_or("A record's tagged columns are outside it")? & self.masks.value);
        let count = first / 4;
        for i in 0..count {
            let id = u32::from(u16_at(area, i * 4).ok_or("A record's tagged columns are outside it")?);
            if id < column.id {
                continue;
            }
            if id > column.id {
                return Ok(None);
            }
            let raw = u16_at(area, i * 4 + 2).ok_or("A record's tagged columns are outside it")?;
            let start = usize::from(raw & self.masks.value);
            let end = if i + 1 < count { usize::from(u16_at(area, (i + 1) * 4 + 2).ok_or("A record's tagged columns are outside it")? & self.masks.value) } else { area.len() };
            let mut value = area.get(start..end).ok_or_else(|| format!("Column {} is outside its record", column.name))?;
            if raw & self.masks.extended != 0 {
                let Some((&flags, rest)) = value.split_first() else { return Ok(None) };
                if flags & VALUE_LONG != 0 {
                    return Err(format!("Column {} is a long value, which isn't read", column.name));
                }
                if flags & VALUE_COMPRESSED != 0 {
                    return Err(format!("Column {} is compressed, which isn't read", column.name));
                }
                if flags & VALUE_MULTI != 0 {
                    return Err(format!("Column {} has several values, which isn't read", column.name));
                }
                value = rest;
            }
            return Ok(Some(value));
        }
        Ok(None)
    }
}

/// What the header says, without reading the rest of the file
pub struct HeaderInfo {
    pub state: String,
    pub format_version: u32,
    pub format_revision: u32,
}

fn state_text(state: u32) -> String {
    match state {
        1 => "Just Created".to_string(),
        2 => "Dirty Shutdown".to_string(),
        3 => "Clean Shutdown".to_string(),
        4 => "Being Converted".to_string(),
        5 => "Force Detach".to_string(),
        other => other.to_string(),
    }
}

/// The header of the database at a path
pub fn read_header(path: &str) -> std::io::Result<HeaderInfo> {
    use std::io::Read;
    let mut header = [0u8; 240];
    std::fs::File::open(path)?.read_exact(&mut header)?;
    Ok(HeaderInfo { state: state_text(u32_at(&header, 52).unwrap_or(0)), format_version: u32_at(&header, 8).unwrap_or(0), format_revision: u32_at(&header, 232).unwrap_or(0) })
}

/// An ESE database, its bytes in memory
pub struct Database {
    data: Vec<u8>,
    page_size: usize,
    header_size: usize,
    masks: Masks,
    large: bool,
    pub format_version: u32,
    pub format_revision: u32,
    state: u32,
    tables: Vec<Table>,
}

impl Database {
    /// Reads the header and the catalog. An error: it isn't an ESE database, or its catalog can't be read
    pub fn new(data: Vec<u8>) -> Result<Database, String> {
        let signature = u32_at(&data, 4).ok_or("The file is too short to be an ESE database")?;
        if signature != SIGNATURE {
            return Err(format!("The file is not an ESE database (signature 0x{signature:08X})"));
        }
        let (format_version, state, format_revision, page_size) = (u32_at(&data, 8).unwrap_or(0), u32_at(&data, 52).unwrap_or(0), u32_at(&data, 232).unwrap_or(0), u32_at(&data, 236).unwrap_or(0) as usize);
        if ![2048, 4096, 8192, 16384, 32768].contains(&page_size) {
            return Err(format!("The header has an invalid page size ({page_size})"));
        }
        // pages of 16 KB and more have a longer header and longer offsets in their tags
        let large = page_size >= 16384 && format_revision >= 0x11;
        let masks = if large { Masks { value: 0x7fff, extended: 0x8000 } } else { Masks { value: 0x1fff, extended: 0x4000 } };
        let mut db = Database { data, page_size, header_size: if large { 80 } else { 40 }, masks, large, format_version, format_revision, state, tables: Vec::new() };
        db.read_catalog()?;
        Ok(db)
    }

    /// The database's state in its header, in esentutl's words
    pub fn state(&self) -> String {
        state_text(self.state)
    }

    pub fn is_clean(&self) -> bool {
        self.state == 3
    }

    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }

    fn read_catalog(&mut self) -> Result<(), String> {
        let mut tables: Vec<Table> = Vec::new();
        let mut index: HashMap<i32, usize> = HashMap::new();
        let mut columns: Vec<(i32, Column)> = Vec::new();
        self.walk(CATALOG_ROOT, &mut |row| {
            let d = row.data;
            let (Some(object_id), Some(kind), Some(id), Some(coltyp_or_page), Some(space)) = (u32_at(d, 4), u16_at(d, 8), u32_at(d, 10), u32_at(d, 14), u32_at(d, 18)) else {
                return Err("A catalog record is too short".to_string());
            };
            if kind != TYPE_TABLE && kind != TYPE_COLUMN {
                return Ok(());
            }
            let name = catalog_name(d)?;
            if kind == TYPE_TABLE {
                index.insert(object_id as i32, tables.len());
                tables.push(Table { name, object_id: object_id as i32, root_page: coltyp_or_page, columns: Vec::new(), by_name: HashMap::new() });
            } else {
                columns.push((object_id as i32, Column { id, name, coltyp: coltyp_or_page, space, offset: 0 }));
            }
            Ok(())
        })?;
        for (object_id, column) in columns {
            if let Some(&i) = index.get(&object_id) {
                tables[i].columns.push(column);
            }
        }
        for t in &mut tables {
            t.finish();
        }
        if tables.is_empty() {
            return Err("The catalog has no tables".to_string());
        }
        self.tables = tables;
        Ok(())
    }

    /// Each row of a table in key order. Rows given before an error stand
    pub fn for_each_row<'a>(&'a self, table: &Table, f: &mut dyn FnMut(Row<'a>) -> Result<(), String>) -> Result<(), String> {
        self.walk(table.root_page, f)
    }

    fn walk<'a>(&'a self, root: u32, f: &mut dyn FnMut(Row<'a>) -> Result<(), String>) -> Result<(), String> {
        let mut seen = HashSet::new();
        self.walk_page(root, 0, &mut seen, f)
    }

    fn page(&self, number: u32) -> Result<&[u8], String> {
        let start = (number as usize + 1).checked_mul(self.page_size).ok_or("A page number is too large")?;
        self.data.get(start..start + self.page_size).ok_or_else(|| format!("Page {number} is past the end of the file"))
    }

    /// A page's value by its tag: its bytes and flags
    fn tag<'a>(&self, page: &'a [u8], index: usize) -> Result<(&'a [u8], u16), String> {
        let at = self.page_size - 4 * (index + 1);
        let bad = || format!("Tag {index} is outside its page");
        let (size, offset) = (u16_at(page, at).ok_or_else(bad)?, u16_at(page, at + 2).ok_or_else(bad)?);
        let (mask, shift_flags) = (self.masks.value, offset >> 13);
        let start = self.header_size + usize::from(offset & mask);
        let value = page.get(start..start + usize::from(size & mask)).ok_or_else(bad)?;
        let flags = if self.large { u16_at(value, 0).unwrap_or(0) >> 13 } else { shift_flags };
        Ok((value, flags))
    }

    fn walk_page<'a>(&'a self, number: u32, depth: u32, seen: &mut HashSet<u32>, f: &mut dyn FnMut(Row<'a>) -> Result<(), String>) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!("Page {number} is too deep in its tree"));
        }
        if !seen.insert(number) {
            return Err(format!("Page {number} is linked twice"));
        }
        let page = self.page(number)?;
        // itagState: the low 12 bits are the number of tags; newer ESE versions keep the number of reserved tags at the start of the
        // array (the first being the page's external header) in bits 12 to 14. Older pages leave those bits 0 and have 1 reserved tag
        let state = u16_at(page, 34).ok_or("A page header is too short")?;
        let (count, reserved) = (usize::from(state & 0x0fff), usize::from((state >> 12) & 0x7).max(1));
        let flags = u32_at(page, 36).ok_or("A page header is too short")?;
        if count * 4 > self.page_size.saturating_sub(self.header_size) {
            return Err(format!("Page {number} says it has {count} tags"));
        }
        for i in reserved..count {
            let (value, tag_flags) = self.tag(page, i)?;
            if tag_flags & TAG_DELETED != 0 {
                continue;
            }
            let mut at = 0;
            if tag_flags & TAG_COMPRESSED_KEY != 0 {
                at += 2;
            }
            let key = usize::from(u16_at(value, at).ok_or_else(|| format!("Page {number}: tag {i} is too short"))? & 0x1fff);
            at += 2 + key;
            let rest = value.get(at..).ok_or_else(|| format!("Page {number}: the key of tag {i} is outside it"))?;
            if flags & PAGE_LEAF != 0 {
                f(Row { data: rest, masks: self.masks })?;
            } else {
                let child = u32_at(rest, 0).ok_or_else(|| format!("Page {number}: tag {i} has no child page"))?;
                self.walk_page(child, depth + 1, seen, f)?;
            }
        }
        Ok(())
    }
}

/// A catalog record's name: its first variable column
fn catalog_name(d: &[u8]) -> Result<String, String> {
    let at = usize::from(u16_at(d, 2).ok_or("A catalog record is too short")?);
    let variables = usize::from(d[1]).saturating_sub(127);
    if variables == 0 {
        return Err("A catalog record has no name".to_string());
    }
    let end = usize::from(u16_at(d, at).ok_or("A catalog record's name is outside it")? & 0x7fff);
    let start = at + variables * 2;
    let bytes = d.get(start..start + end).ok_or("A catalog record's name is outside it")?;
    Ok(bytes.iter().map(|&b| b as char).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(id: u32, coltyp: u32, offset: usize) -> Column {
        Column { id, name: format!("c{id}"), coltyp, space: 0, offset }
    }

    fn row(data: &[u8]) -> Row<'_> {
        Row { data, masks: Masks { value: 0x1fff, extended: 0x4000 } }
    }

    /// Two fixed columns (a byte and a long, the first null when asked) and a tagged one, as IdMap's records have
    fn record(null_first: bool) -> Vec<u8> {
        let mut r = vec![2, 0x7f, 10, 0, 7, 9, 0, 0, 0, if null_first { 0xfd } else { 0xfc }];
        r.extend_from_slice(&[0, 1, 4, 0x40, 1, b'h', b'i']);
        r
    }

    #[test]
    fn fixed_and_tagged_columns() {
        let r = record(false);
        assert_eq!(row(&r).value(&column(1, 2, 4)).unwrap(), Some(&[7u8][..]));
        assert_eq!(row(&r).value(&column(2, 4, 5)).unwrap(), Some(&[9u8, 0, 0, 0][..]));
        assert_eq!(row(&r).value(&column(256, 11, 0)).unwrap(), Some(&b"hi"[..]));
        assert_eq!(row(&r).value(&column(257, 11, 0)).unwrap(), None);
        assert_eq!(row(&r).value(&column(3, 4, 9)).unwrap(), None);
        assert_eq!(row(&record(true)).value(&column(1, 2, 4)).unwrap(), None);
    }

    #[test]
    fn long_and_compressed_values_are_reported() {
        for (flag, word) in [(VALUE_LONG, "long"), (VALUE_COMPRESSED, "compressed")] {
            let mut r = record(false);
            r[14] = flag;
            assert!(row(&r).value(&column(256, 11, 0)).unwrap_err().contains(word));
        }
    }

    #[test]
    fn variable_columns_and_their_nulls() {
        // no fixed columns; two variable ones, the second null
        let r = [0, 129, 4, 0, 2, 0, 0x02, 0x80, b'a', b'b'];
        assert_eq!(row(&r).value(&column(128, 10, 0)).unwrap(), Some(&b"ab"[..]));
        assert_eq!(row(&r).value(&column(129, 10, 0)).unwrap(), None);
    }

    #[test]
    fn damage_is_an_error_and_not_a_panic() {
        assert!(Database::new(vec![]).is_err());
        assert!(Database::new(vec![0; 700]).err().unwrap().contains("not an ESE database"));
        let mut header = vec![0u8; 8192];
        header[4..8].copy_from_slice(&SIGNATURE.to_le_bytes());
        header[236..240].copy_from_slice(&1234u32.to_le_bytes());
        assert!(Database::new(header.clone()).err().unwrap().contains("page size"));
        header[236..240].copy_from_slice(&4096u32.to_le_bytes());
        assert!(Database::new(header).err().unwrap().contains("past the end"));
        assert!(row(&[1, 2]).value(&column(1, 2, 4)).is_err());
        let truncated = [2u8, 0x7f, 200, 0];
        assert!(row(&truncated).value(&column(1, 2, 4)).is_err());
    }

    /// The rows of a leaf page whose header has `item_state`, its tags 1 to 4 each a record of one byte (its tag number)
    fn leaf_rows(item_state: u16) -> Vec<u8> {
        let page_size = 4096;
        let mut data = vec![0u8; page_size * 2];
        let page = &mut data[page_size..];
        page[34..36].copy_from_slice(&item_state.to_le_bytes());
        page[36..40].copy_from_slice(&PAGE_LEAF.to_le_bytes());
        for i in 1..5u16 {
            // each value: a key of 0 bytes, then the record
            let offset = 3 * i;
            page[40 + usize::from(offset)..][..3].copy_from_slice(&[0, 0, i as u8]);
            let at = page_size - 4 * (usize::from(i) + 1);
            page[at..at + 2].copy_from_slice(&3u16.to_le_bytes());
            page[at + 2..at + 4].copy_from_slice(&offset.to_le_bytes());
        }
        let masks = Masks { value: 0x1fff, extended: 0x4000 };
        let db = Database { data, page_size, header_size: 40, masks, large: false, format_version: 0x620, format_revision: 0x12c, state: 3, tables: Vec::new() };
        let mut rows = Vec::new();
        db.walk(0, &mut |r| {
            rows.push(r.data[0]);
            Ok(())
        })
        .unwrap();
        rows
    }

    #[test]
    fn reserved_tags_in_the_page_header() {
        // before: the number of tags only, and one reserved tag
        assert_eq!(leaf_rows(5), [1, 2, 3, 4]);
        // Windows 11 25H2's SRUDB.dat: the number of reserved tags in bits 12 to 14 of the same field
        assert_eq!(leaf_rows(0x1005), [1, 2, 3, 4]);
        assert_eq!(leaf_rows(0x2005), [2, 3, 4]);
    }
}
