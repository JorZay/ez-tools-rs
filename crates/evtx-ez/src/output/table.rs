//! Rows as EvtxECmd writes them: CSV as CsvHelper wrote its records, JSON lines as ServiceStack.Text serialized
//! them.

use crate::output::json::ServiceStackObject;
use crate::time::Timestamp;
use crate::timeline::Row;

/// EvtxECmd's CSV columns, in order
pub const CSV_HEADER: &str = "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload,RenderingInfo";

/// CsvHelper's line ending
pub const CSV_NEW_LINE: &str = "\r\n";

/// EvtxECmd's default time format (--dt)
pub const DEFAULT_DATE_FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";

/// A field as CsvHelper writes it: quoted when it has a quote, a comma or a line break, or starts or ends with a
/// space; quotes doubled
fn field(out: &mut String, s: &str) {
    let quote = s.contains(['"', ',', '\r', '\n']) || s.starts_with(' ') || s.ends_with(' ');
    if !quote {
        out.push_str(s);
        return;
    }
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

/// Appends a CSV line (with its line ending). `source` is the SourceFile column; `date_format` is .NET's format for
/// TimeCreated.
pub fn write_csv_row(out: &mut String, row: &Row, source: &str, date_format: &str) {
    use std::fmt::Write;
    let o = |out: &mut String, v: &Option<String>| field(out, v.as_deref().unwrap_or(""));
    write!(out, "{},", row.record_number).unwrap();
    o(out, &row.event_record_id);
    out.push(',');
    field(out, &row.time_created.format(date_format));
    write!(out, ",{},", row.event_id).unwrap();
    o(out, &row.level);
    out.push(',');
    o(out, &row.provider);
    out.push(',');
    o(out, &row.channel);
    write!(out, ",{},{},", row.process_id, row.thread_id).unwrap();
    o(out, &row.computer);
    write!(out, ",{},", row.chunk_number).unwrap();
    o(out, &row.user_id);
    out.push(',');
    o(out, &row.map_description);
    out.push(',');
    o(out, &row.user_name);
    out.push(',');
    o(out, &row.remote_host);
    for p in &row.payload_data {
        out.push(',');
        o(out, p);
    }
    out.push(',');
    o(out, &row.executable_info);
    out.push_str(if row.hidden_record { ",True," } else { ",False," });
    field(out, source);
    out.push(',');
    o(out, &row.keywords);
    write!(out, ",{},", row.extra_data_offset).unwrap();
    field(out, &row.payload);
    out.push(',');
    o(out, &row.rendering_info);
    out.push_str(CSV_NEW_LINE);
}

/// Appends a JSON line (with "\n"): the record as EvtxECmd's --json writes it, or with `full_json` the whole event
/// (--fj)
pub fn write_json_row(out: &mut String, row: &Row, source: &str, full_json: bool) {
    if full_json {
        if let Some(e) = &row.event_json {
            out.push_str(e);
            out.push('\n');
            return;
        }
    }
    let mut o = ServiceStackObject::new();
    for (i, p) in row.payload_data.iter().enumerate() {
        o.string(["PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6"][i], p.as_deref());
    }
    o.string("UserName", row.user_name.as_deref())
        .string("RemoteHost", row.remote_host.as_deref())
        .string("ExecutableInfo", row.executable_info.as_deref())
        .string("MapDescription", row.map_description.as_deref())
        .number("ChunkNumber", row.chunk_number)
        .string("Computer", row.computer.as_deref())
        .string("Payload", Some(&row.payload))
        .string("UserId", row.user_id.as_deref())
        .string("Channel", row.channel.as_deref())
        .string("Provider", row.provider.as_deref())
        .number("EventId", row.event_id)
        .string("EventRecordId", row.event_record_id.as_deref())
        .number("ProcessId", row.process_id)
        .number("ThreadId", row.thread_id)
        .string("Level", row.level.as_deref())
        .string("Keywords", row.keywords.as_deref())
        .string("SourceFile", Some(source))
        .number("ExtraDataOffset", row.extra_data_offset)
        .bool("HiddenRecord", row.hidden_record);
    // ServiceStack leaves out a TimeCreated that is DateTimeOffset's default (a record without one)
    if row.time_created != Timestamp::MIN {
        o.raw("TimeCreated", &format!("\"{}\"", row.time_created.to_json_string()));
    }
    o.number("RecordNumber", row.record_number)
        .string("RenderingInfo", row.rendering_info.as_deref());
    out.push_str(&o.finish());
    out.push('\n');
}
