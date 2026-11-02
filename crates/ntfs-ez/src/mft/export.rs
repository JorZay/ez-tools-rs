//! $MFT rows as MFTECmd writes them: one per $FILE_NAME (DOS names only with `include_short`), then one per
//! alternate data stream; CSV, JSON lines, bodyfile and the condensed file listing.

use ez_common::csv::{NEW_LINE, field, field_with};
use ez_common::json::ServiceStackObject;
use ez_common::net::{self, MORE_THAN_ONE};

use super::Mft;
use super::attributes::{AttributeBody, FileInfo, NAME_TYPE_DOS, NAME_TYPE_NAMES, SI_FLAG_NAMES, StandardInfo};
use super::record::FileRecord;
use crate::time::Timestamp;

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// --sn: include DOS names
    pub include_short: bool,
    /// --at: all $FILE_NAME timestamps, not only those that differ from $STANDARD_INFORMATION's
    pub all_timestamps: bool,
    /// --ir: resident data columns
    pub include_resident: bool,
    /// --re: extensions (".txt,.ps1") resident data is included for (all when None)
    pub resident_extensions: Option<String>,
    /// --rm: largest file resident data is included for
    pub resident_max_size: i32,
    /// --cutoff: only records created or modified on or after this
    pub cutoff: Option<Timestamp>,
    /// --dr: return resident $DATA to save
    pub dump_resident: bool,
    /// The SourceFile column
    pub source_file: String,
}

/// A row (MFTRecordOut)
#[derive(Debug, Clone, Default)]
pub struct MftRow {
    pub entry_number: u32,
    pub sequence_number: u16,
    pub parent_entry_number: u64,
    pub parent_sequence_number: u16,
    pub in_use: bool,
    pub parent_path: String,
    pub file_name: String,
    pub extension: Option<String>,
    pub is_directory: bool,
    pub has_ads: bool,
    pub is_ads: bool,
    pub file_size: u64,
    pub created_0x10: Option<Timestamp>,
    pub created_0x30: Option<Timestamp>,
    pub last_modified_0x10: Option<Timestamp>,
    pub last_modified_0x30: Option<Timestamp>,
    pub last_record_change_0x10: Option<Timestamp>,
    pub last_record_change_0x30: Option<Timestamp>,
    pub last_access_0x10: Option<Timestamp>,
    pub last_access_0x30: Option<Timestamp>,
    pub update_sequence_number: i64,
    pub logfile_sequence_number: i64,
    pub security_id: i32,
    pub zone_id_contents: Option<String>,
    pub si_flags: i32,
    pub object_id_file_droid: Option<String>,
    pub reparse_target: Option<String>,
    pub reference_count: i32,
    pub name_type: u8,
    pub logged_util_stream: Option<String>,
    pub timestomped: bool,
    pub usec_zeros: bool,
    pub copied: bool,
    pub fn_attribute_id: i32,
    pub other_attribute_id: i32,
    pub source_file: String,
    pub resident_data_base64: Option<String>,
    pub resident_data_hex: Option<String>,
    pub resident_data_ascii: Option<String>,
    pub parse_errors: Option<String>,
}

/// What a record gives: its rows, and resident data to save (--dr: file name, bytes)
#[derive(Debug, Default)]
pub struct RecordOutput {
    pub rows: Vec<MftRow>,
    pub resident_files: Vec<(String, Vec<u8>)>,
}

fn time(raw: i64) -> Option<Timestamp> {
    Timestamp::from_filetime(raw).filter(|_| raw > 0)
}

struct Ads<'a> {
    name: &'a str,
    size: u64,
    resident: Option<&'a [u8]>,
    attribute_id: i32,
}

/// GetAlternateDataStreams: named $DATA attributes (non-resident ones only from their first run)
fn alternate_data_streams(fr: &FileRecord) -> Vec<Ads<'_>> {
    let mut l = Vec::new();
    for a in &fr.attributes {
        let AttributeBody::Data(d) = &a.body else { continue };
        if a.header.name_size <= 0 {
            continue;
        }
        let size = match (&d.resident, &d.non_resident) {
            (Some(_), _) => a.header.content_length as i64 as u64,
            (None, Some(n)) => {
                if n.starting_vcn > 0 {
                    continue;
                }
                n.actual_size
            }
            _ => continue,
        };
        l.push(Ads { name: &a.header.name, size, resident: d.resident.as_deref(), attribute_id: a.header.number });
    }
    l
}

/// The rows for a record (with its extension records' attributes). An error is the exception the original throws
/// (a record with two $STANDARD_INFORMATION or $OBJECT_ID attributes), which ends its export.
pub fn record_rows(mft: &Mft, fr: &FileRecord, o: &ExportOptions) -> Result<RecordOutput, String> {
    let mut out = RecordOutput::default();
    if fr.is_extension() {
        return Ok(out);
    }
    let mut names: Vec<(&super::attributes::Attribute, &FileInfo)> = fr.file_names().collect();
    // OrderBy NameType (stable)
    names.sort_by_key(|(_, f)| f.name_type);
    for (attr, fi) in names {
        if !o.include_short && fi.name_type == NAME_TYPE_DOS {
            continue;
        }
        let mut row = csv_data(mft, fr, attr.header.number, fi, None, o)?;
        if let Some(cutoff) = o.cutoff {
            if !(row.created_0x10.is_some_and(|t| t >= cutoff) || row.last_modified_0x10.is_some_and(|t| t >= cutoff)) {
                continue;
            }
        }
        let ads = alternate_data_streams(fr);
        if o.dump_resident {
            for a in &fr.attributes {
                if let AttributeBody::Data(d) = &a.body {
                    if let Some(data) = &d.resident {
                        out.resident_files.push((
                            format!("{}-{}-{}_{}.bin", fr.entry_number, fr.sequence_number, a.header.number, fi.file_name),
                            data.clone(),
                        ));
                    }
                }
            }
        }
        row.has_ads = !ads.is_empty();
        out.rows.push(row);
        for a in &ads {
            let mut r = csv_data(mft, fr, attr.header.number, fi, Some(a), o)?;
            r.is_ads = true;
            r.other_attribute_id = a.attribute_id;
            out.rows.push(r);
        }
    }
    Ok(out)
}

/// SingleOrDefault for an attribute type
fn single<'a, T>(fr: &'a FileRecord, pick: impl Fn(&'a AttributeBody) -> Option<&'a T>) -> Result<Option<&'a T>, String> {
    let mut found = None;
    for a in &fr.attributes {
        if let Some(v) = pick(&a.body) {
            if found.is_some() {
                return Err(MORE_THAN_ONE.into());
            }
            found = Some(v);
        }
    }
    Ok(found)
}

fn csv_data(mft: &Mft, fr: &FileRecord, fn_attribute_id: i32, fi: &FileInfo, ads: Option<&Ads>, o: &ExportOptions) -> Result<MftRow, String> {
    let mut r = MftRow {
        entry_number: fr.entry_number,
        file_name: fi.file_name.clone(),
        in_use: !fr.is_deleted(),
        parent_path: mft.full_path(fi.parent.key()).into_owned(),
        sequence_number: fr.sequence_number,
        is_directory: fr.is_directory(),
        parent_entry_number: fi.parent.entry,
        parent_sequence_number: fi.parent.sequence,
        name_type: fi.name_type,
        fn_attribute_id,
        source_file: o.source_file.clone(),
        parse_errors: (!fr.parse_errors.is_empty()).then(|| fr.parse_errors.join("; ")),
        ..Default::default()
    };
    if !r.is_directory {
        r.extension = Some(net::path_extension(&r.file_name).to_string());
        if let Some(d) = fr.attributes.iter().find(|a| matches!(a.body, AttributeBody::Data(_))) {
            r.other_attribute_id = d.header.number;
        }
    }
    r.file_size = fr.file_size();
    if let Some(a) = ads {
        r.file_name = format!("{}:{}", r.file_name, a.name);
        r.file_size = a.size;
        r.extension = Some(net::path_extension(a.name).to_string());
        if a.name == "Zone.Identifier" {
            r.zone_id_contents = Some(match a.resident {
                Some(d) => net::cp1252(d),
                None => "(Zone.Identifier data is non-resident)".into(),
            });
        }
    }
    r.reference_count = fr.name_count();
    r.logfile_sequence_number = fr.log_sequence_number;

    if let Some(oid) = single(fr, |b| match b {
        AttributeBody::ObjectId(x) => Some(x),
        _ => None,
    })? {
        r.object_id_file_droid = Some(net::guid(&oid.object_id));
    }
    if let Some(a) = fr.attributes.iter().find(|a| matches!(a.body, AttributeBody::LoggedUtilityStream(_))) {
        r.logged_util_stream = Some(a.header.name.clone());
    }
    if let Some(rp) = fr.attributes.iter().find_map(|a| match &a.body {
        AttributeBody::ReparsePoint(r) => Some(r),
        _ => None,
    }) {
        r.reparse_target = Some(rp.substitute_name.replace("\\??\\", ""));
    }

    let si: Option<&StandardInfo> = single(fr, |b| match b {
        AttributeBody::StandardInfo(x) => Some(x),
        _ => None,
    })?;
    match si {
        Some(si) => {
            r.update_sequence_number = si.update_sequence_number;
            r.created_0x10 = time(si.created);
            r.last_modified_0x10 = time(si.content_modified);
            r.last_record_change_0x10 = time(si.record_modified);
            r.last_access_0x10 = time(si.last_accessed);
            r.copied = matches!((r.last_modified_0x10, r.created_0x10), (Some(m), Some(c)) if m < c);
            if o.all_timestamps || fi.created != si.created {
                r.created_0x30 = time(fi.created);
            }
            if o.all_timestamps || fi.content_modified != si.content_modified {
                r.last_modified_0x30 = time(fi.content_modified);
            }
            if o.all_timestamps || fi.record_modified != si.record_modified {
                r.last_record_change_0x30 = time(fi.record_modified);
            }
            if o.all_timestamps || fi.last_accessed != si.last_accessed {
                r.last_access_0x30 = time(fi.last_accessed);
            }
            r.security_id = si.security_id;
            r.si_flags = si.flags;
            if let (Some(c30), Some(c10)) = (r.created_0x30, r.created_0x10) {
                r.timestomped = c10 < c30;
            }
            let ms_zero = |t: Option<Timestamp>| t.is_some_and(|t| t.0 / 10_000 % 1000 == 0);
            r.usec_zeros = ms_zero(r.created_0x10) || ms_zero(r.last_modified_0x10);
        }
        None => {
            // no $STANDARD_INFORMATION: the $FILE_NAME times (the original puts Created in 0x30, the rest in 0x10)
            r.created_0x30 = time(fi.created);
            r.last_modified_0x10 = time(fi.content_modified);
            r.last_record_change_0x10 = time(fi.record_modified);
            r.last_access_0x10 = time(fi.last_accessed);
        }
    }
    if o.include_resident && ads.is_none() {
        resident_data(&mut r, fr, o);
    }
    Ok(r)
}

/// PopulateResidentData: the first resident $DATA as base64, hex and (when it is all text) ASCII
fn resident_data(r: &mut MftRow, fr: &FileRecord, o: &ExportOptions) {
    if r.file_size > o.resident_max_size as i64 as u64 {
        return;
    }
    if let Some(exts) = o.resident_extensions.as_deref().filter(|e| !e.is_empty()) {
        let allowed: Vec<String> = exts.split(',').map(|e| e.trim().to_lowercase()).collect();
        if let Some(ext) = r.extension.as_deref().filter(|e| !e.is_empty()) {
            if !allowed.contains(&ext.to_lowercase()) {
                return;
            }
        }
    }
    let Some(data) = fr.attributes.iter().find_map(|a| match &a.body {
        AttributeBody::Data(d) if a.header.resident => d.resident.as_ref(),
        _ => None,
    }) else {
        return;
    };
    r.resident_data_base64 = Some(base64(data));
    r.resident_data_hex = Some(net::hex(data));
    let text = net::utf8(data);
    if text.chars().all(|c| c.is_control() || c.is_whitespace() || (' '..='~').contains(&c)) {
        r.resident_data_ascii = Some(text.into_owned());
    }
}

fn base64(d: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(d.len().div_ceil(3) * 4);
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

pub fn csv_header(include_resident: bool) -> String {
    let mut h = String::from("EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,");
    if include_resident {
        h.push_str("ResidentDataBase64,ResidentDataHex,ResidentDataASCII,");
    }
    h.push_str("ParseErrors");
    h.push_str(NEW_LINE);
    h
}

fn b(v: bool) -> &'static str {
    if v { "True" } else { "False" }
}

fn t(out: &mut String, v: Option<Timestamp>, dt: &str) {
    if let Some(v) = v {
        field(out, &v.format(dt));
    }
}

fn o(out: &mut String, v: &Option<String>) {
    if let Some(v) = v {
        field(out, v);
    }
}

/// Appends a CSV line
pub fn write_csv(out: &mut String, r: &MftRow, dt: &str, include_resident: bool) {
    use std::fmt::Write;
    write!(
        out,
        "{},{},{},{},{},",
        r.entry_number,
        r.sequence_number,
        b(r.in_use),
        r.parent_entry_number,
        r.parent_sequence_number
    )
    .unwrap();
    field(out, &r.parent_path);
    out.push(',');
    field(out, &r.file_name);
    out.push(',');
    o(out, &r.extension);
    write!(out, ",{},{},", r.file_size, r.reference_count).unwrap();
    o(out, &r.reparse_target);
    write!(
        out,
        ",{},{},{},{},{},{},",
        b(r.is_directory),
        b(r.has_ads),
        b(r.is_ads),
        b(r.timestomped),
        b(r.usec_zeros),
        b(r.copied)
    )
    .unwrap();
    field(out, &net::flags_name(r.si_flags as i64, SI_FLAG_NAMES).replace(", ", "|"));
    out.push(',');
    field(out, &net::flags_name(r.name_type as i64, NAME_TYPE_NAMES));
    for v in [
        r.created_0x10,
        r.created_0x30,
        r.last_modified_0x10,
        r.last_modified_0x30,
        r.last_record_change_0x10,
        r.last_record_change_0x30,
        r.last_access_0x10,
        r.last_access_0x30,
    ] {
        out.push(',');
        t(out, v, dt);
    }
    write!(out, ",{},{},{},", r.update_sequence_number, r.logfile_sequence_number, r.security_id).unwrap();
    o(out, &r.object_id_file_droid);
    out.push(',');
    o(out, &r.logged_util_stream);
    out.push(',');
    o(out, &r.zone_id_contents);
    out.push(',');
    field(out, &r.source_file);
    out.push(',');
    if include_resident {
        o(out, &r.resident_data_base64);
        out.push(',');
        o(out, &r.resident_data_hex);
        out.push(',');
        o(out, &r.resident_data_ascii);
        out.push(',');
    }
    o(out, &r.parse_errors);
    out.push_str(NEW_LINE);
}

/// Appends a JSON line (ServiceStack: properties in order, nulls left out, enums as numbers)
pub fn write_json(out: &mut String, r: &MftRow) {
    let ts = |v: Option<Timestamp>| v.map(|t| format!("\"{}\"", t.to_json_string()));
    let mut j = ServiceStackObject::new();
    j.number("EntryNumber", r.entry_number)
        .number("SequenceNumber", r.sequence_number)
        .number("ParentEntryNumber", r.parent_entry_number)
        .number("ParentSequenceNumber", r.parent_sequence_number)
        .bool("InUse", r.in_use)
        .string("ParentPath", Some(&r.parent_path))
        .string("FileName", Some(&r.file_name))
        .string("Extension", r.extension.as_deref())
        .bool("IsDirectory", r.is_directory)
        .bool("HasAds", r.has_ads)
        .bool("IsAds", r.is_ads)
        .number("FileSize", r.file_size);
    for (name, v) in [
        ("Created0x10", r.created_0x10),
        ("Created0x30", r.created_0x30),
        ("LastModified0x10", r.last_modified_0x10),
        ("LastModified0x30", r.last_modified_0x30),
        ("LastRecordChange0x10", r.last_record_change_0x10),
        ("LastRecordChange0x30", r.last_record_change_0x30),
        ("LastAccess0x10", r.last_access_0x10),
        ("LastAccess0x30", r.last_access_0x30),
    ] {
        if let Some(s) = ts(v) {
            j.raw(name, &s);
        }
    }
    j.number("UpdateSequenceNumber", r.update_sequence_number)
        .number("LogfileSequenceNumber", r.logfile_sequence_number)
        .number("SecurityId", r.security_id)
        .string("ZoneIdContents", r.zone_id_contents.as_deref())
        .number("SiFlags", r.si_flags)
        .string("ObjectIdFileDroid", r.object_id_file_droid.as_deref())
        .string("ReparseTarget", r.reparse_target.as_deref())
        .number("ReferenceCount", r.reference_count)
        .number("NameType", r.name_type)
        .string("LoggedUtilStream", r.logged_util_stream.as_deref())
        .bool("Timestomped", r.timestomped)
        .bool("uSecZeros", r.usec_zeros)
        .bool("Copied", r.copied)
        .number("FnAttributeId", r.fn_attribute_id)
        .number("OtherAttributeId", r.other_attribute_id)
        .string("SourceFile", Some(&r.source_file))
        .string("ResidentDataBase64", r.resident_data_base64.as_deref())
        .string("ResidentDataHex", r.resident_data_hex.as_deref())
        .string("ResidentDataASCII", r.resident_data_ascii.as_deref())
        .string("ParseErrors", r.parse_errors.as_deref());
    out.push_str(&j.finish());
    out.push('\n');
}

pub const FILE_LISTING_HEADER: &str = "FullPath,Extension,IsDirectory,FileSize,Created0x10,LastModified0x10\r\n";

/// Appends a file listing line (--fl)
pub fn write_file_listing(out: &mut String, r: &MftRow, dt: &str) {
    use std::fmt::Write;
    field(out, &format!("{}\\{}", r.parent_path, r.file_name));
    out.push(',');
    o(out, &r.extension);
    write!(out, ",{},{},", b(r.is_directory), r.file_size).unwrap();
    t(out, r.created_0x10, dt);
    out.push(',');
    t(out, r.last_modified_0x10, dt);
    out.push_str(NEW_LINE);
}

fn unix(t: Option<Timestamp>) -> Option<i64> {
    t.map(|t| t.0 / 10_000_000 - 62_135_596_800)
}

/// Appends a row's bodyfile lines: from $STANDARD_INFORMATION, and (not for an ADS) from $FILE_NAME
pub fn write_body(out: &mut String, r: &MftRow, drive_letter: &str, new_line: &str) {
    let name = format!(
        "{}:{}\\{}",
        drive_letter.to_lowercase(),
        r.parent_path.get(1..).unwrap_or(""),
        r.file_name
    )
    .replace('\\', "/");
    let deleted = if r.in_use { "" } else { " (deleted)" };
    let line = |out: &mut String, name: &str, inode: String, times: [Option<i64>; 4]| {
        use std::fmt::Write;
        out.push_str("0|");
        field_with(out, &format!("{name}{deleted}"), '|');
        out.push('|');
        field_with(out, &inode, '|');
        write!(out, "|r/rrwxrwxrwx|0|0|{}", r.file_size).unwrap();
        for v in times {
            write!(out, "|{}", v.unwrap_or(0)).unwrap();
        }
        out.push_str(new_line);
    };
    let kind = if r.is_directory { 144 } else { 128 };
    line(
        out,
        &name,
        format!("{}-{kind}-{}", r.entry_number, r.other_attribute_id),
        [unix(r.last_access_0x10), unix(r.last_modified_0x10), unix(r.last_record_change_0x10), unix(r.created_0x10)],
    );
    if r.is_ads {
        return;
    }
    let or = |a: Option<Timestamp>, b: Option<Timestamp>| unix(a.or(b));
    line(
        out,
        &format!("{name} ($FILE_NAME)"),
        format!("{}-48-{}", r.entry_number, r.fn_attribute_id),
        [
            or(r.last_access_0x30, r.last_access_0x10),
            or(r.last_modified_0x30, r.last_modified_0x10),
            or(r.last_record_change_0x30, r.last_record_change_0x10),
            or(r.created_0x30, r.created_0x10),
        ],
    );
}
