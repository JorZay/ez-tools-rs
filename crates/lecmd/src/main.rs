//! LECmd: Windows shortcut (.lnk) files to the console, CSV, JSON, XML and XHTML, with the original's options and output.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_exception, io_message, utc_now};
use ez_common::dotnet::{n0, number_n, upper_invariant};
use ez_common::json::{jsv_format, jsv_value, service_stack_string};
use ez_common::{Level, Timestamp};
use lnk_ez::{ExtraBlock, HAS_ARGUMENTS, HAS_ICON_LOCATION, HAS_LINK_INFO, HAS_NAME, HAS_RELATIVE_PATH, HAS_WORKING_DIR, LnkFile};
use sha1::{Digest, Sha1};
use shellitems_ez::blocks::{Block, BlockKind};
use shellitems_ez::sheet::PropertyStore;
use shellitems_ez::utils::description_from_guid_and_key;
use shellitems_ez::ShellItem;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PRECISE_TIME_FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";
const JSON_DATE_FORMAT: &str = "yyyy-MM-ddTHH:mm:ss.fffffffZ";

/// Reads Windows shortcut (.lnk) files, with LECmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  lecmd -f /tmp/foobar.lnk\n  lecmd -f /tmp/somelink.lnk --json /tmp/jsonOutput --pretty\n  lecmd -d /tmp --csv /tmp/out --html /tmp/out --xml /tmp/xml -q\n  lecmd -f \"/tmp/some other link.lnk\" --nid --neb\n  lecmd -d /tmp --all"
)]
struct Args {
    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// Only process lnk files pointing to removable drives
    #[arg(short = 'r', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    removable: bool,

    /// Process all files in directory vs. only files matching *.lnk
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    all: bool,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// Directory to save JSON formatted results to. Use --pretty for a more human readable layout
    #[arg(long, value_name = "DIR")]
    json: Option<String>,

    /// Directory to save XML formatted results to
    #[arg(long, value_name = "DIR")]
    xml: Option<String>,

    /// Directory to save xhtml formatted results to
    #[arg(long, value_name = "DIR")]
    html: Option<String>,

    /// When exporting to json, use a more human readable layout
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    pretty: bool,

    /// Do not dump full details about each file processed. Speeds up processing when using --json or --csv
    #[arg(short = 'q', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    quiet: bool,

    /// Suppress Target ID list details from being displayed
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nid: bool,

    /// Suppress Extra blocks information from being displayed
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    neb: bool,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// When true, display higher precision for timestamps
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    mp: bool,

    /// Code page to parse strings
    #[arg(long, default_value_t = 1252, value_name = "NUMBER", allow_negative_numbers = true)]
    cp: i32,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_LECmd_<version>_ConsoleLog.txt in the output directory (the first of
    /// --csv, --json, --xml, --html given). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Path.Combine
fn combine(folder: &str, name: &str) -> String {
    Path::new(folder).join(name).to_string_lossy().into_owned()
}

/// The vendors for the first three bytes of MAC addresses
fn load_macs() -> HashMap<String, String> {
    let mut macs = HashMap::new();
    for line in include_str!("../data/MACs.txt").split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let upper = upper_invariant(line);
        let mut parts = upper.split('\t');
        let key = parts.next().unwrap_or_default().trim().to_string();
        let value = parts.next().unwrap_or_default().trim().to_string();
        macs.entry(key).or_insert(value);
    }
    macs
}

fn vendor_from_mac(macs: &HashMap<String, String>, mac: &str) -> String {
    let key: String = mac.split(':').take(3).collect::<String>().to_uppercase();
    macs.get(&key).cloned().unwrap_or_else(|| "(Unknown vendor)".to_string())
}

/// Serilog's text for a nullable time
fn date_or_null(t: Option<Timestamp>, format: &str) -> String {
    t.map_or_else(|| "null".to_string(), |t| t.format(format))
}

/// 1601-01-01 means not set, as does the minimum, which is what's kept for a FILETIME out of range
fn is_unset(t: Timestamp) -> bool {
    t.parts().year <= 1601
}

fn format_timestamp(t: Timestamp, format: &str) -> String {
    if is_unset(t) { String::new() } else { t.format(format) }
}

fn absolute_path(ids: &[ShellItem]) -> String {
    let mut path = String::new();
    for item in ids {
        if item.class == "ShellBagDamaged" {
            path.push_str("(damaged item)\\");
            continue;
        }
        path.push_str(item.value.trim_matches('\\'));
        path.push('\\');
    }
    path.pop();
    path
}

fn anomalies(lnk: &LnkFile) -> Vec<String> {
    let mut out = lnk.parse_errors.clone();
    let Some(args) = lnk.arguments.as_deref().filter(|a| !a.is_empty()) else { return out };
    let length = args.encode_utf16().count();
    if length > 260 {
        out.push(format!("Arguments are {} characters long (the shortcut properties dialog shows 260)", n0(length as u64)));
    }
    let (mut longest, mut run) = (0u64, 0u64);
    for c in args.chars() {
        run = if c.is_whitespace() { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    if longest >= 32 {
        out.push(format!("Arguments contain {} consecutive whitespace characters", n0(longest)));
    }
    out
}

/// The output columns, as CsvOut declares them. None is null
#[derive(Default)]
struct CsvOut {
    source_file: String,
    source_created: String,
    source_modified: String,
    source_accessed: String,
    target_created: String,
    target_modified: String,
    target_accessed: String,
    file_size: u32,
    relative_path: Option<String>,
    working_directory: Option<String>,
    file_attributes: String,
    header_flags: String,
    drive_type: String,
    volume_serial_number: Option<String>,
    volume_label: Option<String>,
    local_path: Option<String>,
    network_path: Option<String>,
    common_path: Option<String>,
    arguments: Option<String>,
    target_id_absolute_path: Option<String>,
    target_mft_entry_number: Option<String>,
    target_mft_sequence_number: Option<String>,
    machine_id: Option<String>,
    machine_mac_address: Option<String>,
    mac_vendor: Option<String>,
    tracker_created_on: Option<String>,
    extra_blocks_present: String,
    name: Option<String>,
    icon_location: Option<String>,
    show_window: String,
    environment_variables: Option<String>,
    volume_droid: Option<String>,
    file_droid: Option<String>,
    volume_droid_birth: Option<String>,
    file_droid_birth: Option<String>,
    anomalies: String,
}

const CSV_COLUMNS: &[&str] = &[
    "SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags",
    "DriveType", "VolumeSerialNumber", "VolumeLabel", "LocalPath", "NetworkPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "MachineID",
    "MachineMACAddress", "MACVendor", "TrackerCreatedOn", "ExtraBlocksPresent", "Name", "IconLocation", "ShowWindow", "EnvironmentVariables", "VolumeDroid", "FileDroid", "VolumeDroidBirth", "FileDroidBirth", "Anomalies",
];

impl CsvOut {
    /// The string columns in the order they're declared, with the file size separate
    fn strings(&self) -> Vec<(&'static str, Option<&str>)> {
        vec![
            ("SourceFile", Some(self.source_file.as_str())),
            ("SourceCreated", Some(self.source_created.as_str())),
            ("SourceModified", Some(self.source_modified.as_str())),
            ("SourceAccessed", Some(self.source_accessed.as_str())),
            ("TargetCreated", Some(self.target_created.as_str())),
            ("TargetModified", Some(self.target_modified.as_str())),
            ("TargetAccessed", Some(self.target_accessed.as_str())),
            ("RelativePath", self.relative_path.as_deref()),
            ("WorkingDirectory", self.working_directory.as_deref()),
            ("FileAttributes", Some(self.file_attributes.as_str())),
            ("HeaderFlags", Some(self.header_flags.as_str())),
            ("DriveType", Some(self.drive_type.as_str())),
            ("VolumeSerialNumber", self.volume_serial_number.as_deref()),
            ("VolumeLabel", self.volume_label.as_deref()),
            ("LocalPath", self.local_path.as_deref()),
            ("NetworkPath", self.network_path.as_deref()),
            ("CommonPath", self.common_path.as_deref()),
            ("Arguments", self.arguments.as_deref()),
            ("TargetIDAbsolutePath", self.target_id_absolute_path.as_deref()),
            ("TargetMFTEntryNumber", self.target_mft_entry_number.as_deref()),
            ("TargetMFTSequenceNumber", self.target_mft_sequence_number.as_deref()),
            ("MachineID", self.machine_id.as_deref()),
            ("MachineMACAddress", self.machine_mac_address.as_deref()),
            ("MACVendor", self.mac_vendor.as_deref()),
            ("TrackerCreatedOn", self.tracker_created_on.as_deref()),
            ("ExtraBlocksPresent", Some(self.extra_blocks_present.as_str())),
            ("Name", self.name.as_deref()),
            ("IconLocation", self.icon_location.as_deref()),
            ("ShowWindow", Some(self.show_window.as_str())),
            ("EnvironmentVariables", self.environment_variables.as_deref()),
            ("VolumeDroid", self.volume_droid.as_deref()),
            ("FileDroid", self.file_droid.as_deref()),
            ("VolumeDroidBirth", self.volume_droid_birth.as_deref()),
            ("FileDroidBirth", self.file_droid_birth.as_deref()),
            ("Anomalies", Some(self.anomalies.as_str())),
        ]
    }

    /// The value of a column in text; None for null
    fn get(&self, column: &str) -> Option<String> {
        if column == "FileSize" {
            return Some(self.file_size.to_string());
        }
        self.strings().into_iter().find(|(n, _)| *n == column).and_then(|(_, v)| v.map(str::to_string))
    }

    fn csv_line(&self) -> String {
        let mut line = String::new();
        for (i, column) in CSV_COLUMNS.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            ez_common::csv::field(&mut line, self.get(column).as_deref().unwrap_or_default());
        }
        line.push_str(ez_common::csv::NEW_LINE);
        line
    }

    /// Non-empty columns in order, as the JSON has them
    fn json_pairs(&self) -> Vec<(&'static str, Option<String>)> {
        CSV_COLUMNS.iter().map(|c| (*c, self.get(c).filter(|v| !v.is_empty()))).collect()
    }

    /// cs.ToJson()
    fn to_json(&self) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (name, value) in self.json_pairs() {
            let Some(value) = value else { continue };
            if !first {
                out.push(',');
            }
            first = false;
            out.push('"');
            out.push_str(name);
            out.push_str("\":");
            if name == "FileSize" {
                out.push_str(&value);
            } else {
                service_stack_string(&mut out, &value);
            }
        }
        out.push('}');
        out
    }

    /// cs.Dump(): ServiceStack's JSV format, laid out by its JsvFormatter
    fn dump(&self) -> String {
        let mut jsv = String::from("{");
        let mut first = true;
        for (name, value) in self.json_pairs() {
            let Some(value) = value else { continue };
            if !first {
                jsv.push(',');
            }
            first = false;
            jsv.push_str(name);
            jsv.push(':');
            jsv.push_str(&jsv_value(&value));
        }
        jsv.push('}');
        jsv_format(&jsv)
    }

    /// csout.ToXml(): DataContractSerializer's element order and nulls
    fn to_xml(&self) -> Result<String, String> {
        const ORDER: &[&str] = &[
            "Anomalies", "Arguments", "CommonPath", "DriveType", "EnvironmentVariables", "ExtraBlocksPresent", "FileAttributes", "FileDroid", "FileDroidBirth", "FileSize", "HeaderFlags", "IconLocation", "LocalPath",
            "MACVendor", "MachineID", "MachineMACAddress", "Name", "NetworkPath", "RelativePath", "ShowWindow", "SourceAccessed", "SourceCreated", "SourceFile", "SourceModified", "TargetAccessed", "TargetCreated", "TargetIDAbsolutePath",
            "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "TargetModified", "TrackerCreatedOn", "VolumeDroid", "VolumeDroidBirth", "VolumeLabel", "VolumeSerialNumber", "WorkingDirectory",
        ];
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><CsvOut xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"http://schemas.datacontract.org/2004/07/LECmd\">");
        for column in ORDER {
            match self.get(column) {
                Some(value) => {
                    out.push('<');
                    out.push_str(column);
                    out.push('>');
                    out.push_str(&xml_writer_text(&value)?);
                    out.push_str("</");
                    out.push_str(column);
                    out.push('>');
                }
                None => {
                    out.push('<');
                    out.push_str(column);
                    out.push_str(" i:nil=\"true\" />");
                }
            }
        }
        out.push_str("</CsvOut>");
        Ok(out)
    }
}

/// Text through XmlWriter's checks: a character XML doesn't allow is an error
fn xml_writer_text(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // NewLineHandling.Replace: each line break is NewLineChars, which is Environment.NewLine
            '\r' => {
                out.push_str(ez_common::dotnet::NEW_LINE);
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            '\n' => out.push_str(ez_common::dotnet::NEW_LINE),
            '\t' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => {
                return Err(format!("'{}', hexadecimal value 0x{:02X}, is an invalid character.", c, c as u32));
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Text through XmlTextWriter: control characters become references
fn xml_text_writer_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{fffe}' || c == '\u{ffff}' => out.push_str(&format!("&#x{:X};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The target's blocks: a property view's are those of the items in its Delegate ID List and then its own
fn target_blocks(item: &ShellItem) -> Vec<&Block> {
    if item.class == "ShellBag0X00" { item.delegate_extension_blocks.iter().chain(item.extension_blocks.iter()).collect() } else { item.extension_blocks.iter().collect() }
}

fn csv_format(lnk: &LnkFile, format: &str, macs: &HashMap<String, String>, log: &mut Logger) -> CsvOut {
    let source_file = lnk.source_file.clone().unwrap_or_default();
    log.debug(&format!("Processing {source_file}"));
    let mut out = CsvOut {
        source_file: source_file.replace("\\\\?\\", ""),
        source_created: lnk.source.created.map(|t| t.format(format)).unwrap_or_default(),
        source_modified: lnk.source.modified.map(|t| t.format(format)).unwrap_or_default(),
        source_accessed: lnk.source.accessed.map(|t| t.format(format)).unwrap_or_default(),
        target_created: format_timestamp(lnk.header.target_created, format),
        target_modified: format_timestamp(lnk.header.target_modified, format),
        target_accessed: format_timestamp(lnk.header.target_accessed, format),
        common_path: lnk.common_path.clone(),
        volume_label: lnk.volume_info.as_ref().map(|v| v.label.clone()),
        volume_serial_number: lnk.volume_info.as_ref().map(|v| v.serial_number.clone()),
        drive_type: lnk.volume_info.as_ref().map_or_else(|| "(None)".to_string(), |v| v.drive_type_description()),
        file_attributes: lnk.header.file_attributes_text(),
        file_size: lnk.header.file_size,
        header_flags: lnk.header.data_flags_text(),
        local_path: lnk.local_path.clone(),
        network_path: Some(lnk.network_share_info.as_ref().map_or_else(String::new, |n| n.share_name.clone())),
        relative_path: lnk.relative_path.clone(),
        arguments: lnk.arguments.clone(),
        name: lnk.name.clone(),
        icon_location: lnk.icon_location.clone(),
        show_window: lnk.header.show_window_text(),
        anomalies: anomalies(lnk).join(" | "),
        working_directory: lnk.working_directory.clone(),
        ..CsvOut::default()
    };
    out.environment_variables = lnk.extra_blocks.iter().find_map(|b| match b {
        ExtraBlock::EnvironmentVariable { ascii, unicode } => Some(if unicode.is_empty() { ascii.clone() } else { unicode.clone() }),
        _ => None,
    });
    if !lnk.target_ids.is_empty() {
        out.target_id_absolute_path = Some(absolute_path(&lnk.target_ids));
    }
    out.extra_blocks_present = lnk.extra_blocks.iter().map(ExtraBlock::class_name).collect::<Vec<_>>().join(", ");
    if let Some(tracker) = lnk.extra_blocks.iter().find_map(|b| if let ExtraBlock::Tracker(t) = b { Some(t) } else { None }) {
        out.machine_id = Some(tracker.machine_id.clone());
        out.volume_droid = Some(tracker.volume_droid.clone());
        out.file_droid = Some(tracker.file_droid.clone());
        out.volume_droid_birth = Some(tracker.volume_droid_birth.clone());
        out.file_droid_birth = Some(tracker.file_droid_birth.clone());
        if tracker.is_time_based {
            out.tracker_created_on = Some(tracker.creation_time.format(format));
            out.machine_mac_address = Some(tracker.mac_address.clone());
            out.mac_vendor = Some(vendor_from_mac(macs, &tracker.mac_address));
        }
    }
    if let Some(last) = lnk.target_ids.last() {
        let blocks = target_blocks(last);
        if let Some(BlockKind::Beef0004 { mft, .. }) = blocks.iter().rev().map(|b| &b.kind).find(|k| matches!(k, BlockKind::Beef0004 { .. })) {
            if let Some(e) = mft.entry_number {
                out.target_mft_entry_number = Some(format!("0x{e:X}"));
            }
            if let Some(s) = mft.sequence_number {
                out.target_mft_sequence_number = Some(format!("0x{s:X}"));
            }
        }
    }
    out
}

fn pad_right(text: &str, width: usize) -> String {
    let length = text.encode_utf16().count();
    if length >= width { text.to_string() } else { format!("{text}{}", " ".repeat(width - length)) }
}

/// int.TryParse
fn parse_int(text: &str) -> Option<i32> {
    text.trim().parse().ok()
}

struct Display<'a> {
    log: &'a mut Logger,
    format: String,
    macs: &'a HashMap<String, String>,
}

impl Display<'_> {
    fn info(&mut self, text: &str) {
        self.log.block(Level::Info, text);
    }

    fn warn(&mut self, text: &str) {
        self.log.block(Level::Warning, text);
    }

    fn time(&self, t: Timestamp) -> String {
        t.format(&self.format)
    }

    fn file_entry(&mut self, item: &ShellItem) {
        self.info(&format!("    Short name: {}", item.short_name.as_deref().unwrap_or_default()));
        match item.last_modification {
            Some(t) => {
                let text = self.time(t);
                self.info(&format!("    Modified:    {text}"));
            }
            None => self.info("    Modified:"),
        }
        self.extension_blocks(&item.extension_blocks);
    }

    fn property_store(&mut self, store: &PropertyStore) {
        if store.sheets.is_empty() {
            return;
        }
        self.info("  >> Property store (Format: GUID\\ID Description ==> Value)");
        let mut count = 0;
        for sheet in &store.sheets {
            for (key, value) in &sheet.property_names {
                count += 1;
                let prefix = pad_right(&format!("{}\\{key}", sheet.guid), 43);
                let suffix = parse_int(key).map_or_else(String::new, |k| pad_right(&description_from_guid_and_key(&sheet.guid, k), 35));
                self.info(&format!("     {prefix} {suffix} ==> {value}"));
            }
        }
        if count == 0 {
            self.warn("     (Property store is empty)");
        }
    }

    fn extension_blocks(&mut self, blocks: &[Block]) {
        if blocks.is_empty() {
            return;
        }
        self.info(&format!("    Extension block count: {}", n0(blocks.len() as u64)));
        self.log.blank();
        for (number, block) in blocks.iter().enumerate() {
            self.info(&format!("    --------- Block {} ({}) ---------", n0(number as u64), block.class));
            match &block.kind {
                BlockKind::Beef0004 { created, last_access, mft, long_name, localised_name, .. } => {
                    self.info(&format!("    Long name: {long_name}"));
                    if !localised_name.is_empty() {
                        self.info(&format!("    Localized name: {localised_name}"));
                    }
                    match created {
                        Some(t) => {
                            let text = self.time(*t);
                            self.info(&format!("    Created:     {text}"));
                        }
                        None => self.info("    Created:"),
                    }
                    match last_access {
                        Some(t) => {
                            let text = self.time(*t);
                            self.info(&format!("    Last access: {text}"));
                        }
                        None => self.info("    Last access: "),
                    }
                    if mft.entry_number.is_some_and(|e| e > 0) {
                        let entry = mft.entry_number.unwrap_or(0);
                        let (seq, seq_hex) = mft.sequence_number.map_or(("null".to_string(), "null".to_string()), |s| (s.to_string(), format!("{s:X}")));
                        self.info(&format!("    MFT entry/sequence #: {entry}/{seq} (0x{entry:X}/0x{seq_hex})"));
                    }
                }
                BlockKind::Beef0025 { file_time1, file_time2 } => {
                    let (a, b) = (self.time(*file_time1), self.time(*file_time2));
                    self.info(&format!("    Filetime 1: {a}, Filetime 2: {b}"));
                }
                BlockKind::Guid1 { guid, folder } if block.class == "Beef0003" => {
                    self.info(&format!("    GUID: {} ({})", guid.as_deref().unwrap_or_default(), folder.as_deref().unwrap_or_default()));
                }
                BlockKind::FileDocumentType(text) if block.class == "Beef001a" => self.info(&format!("    File document type: {text}")),
                _ => {
                    let text = block.to_text();
                    self.info(&format!("    {text}"));
                }
            }
        }
    }

    fn shell_item(&mut self, item: &ShellItem) {
        let value = if item.value.is_empty() { "(None)" } else { item.value.as_str() };
        self.info(&format!("  -{} ==> {value}", item.friendly_name));
        match item.class {
            "ShellBagDamaged" => {
                let message = format!("    This shell item could not be parsed: {}", item.error_message.as_deref().unwrap_or_default());
                self.warn(&message);
            }
            "ShellBag0X31" | "ShellBag0X32" | "ShellBag0X35" | "ShellBag0X36" | "ShellBag0X39" | "ShellBag0XB1" => self.file_entry(item),
            "ShellBag0X3A" if item.short_name.is_some() => self.file_entry(item),
            "ShellBagCFSF" => {
                match item.last_modification {
                    Some(t) => {
                        let text = self.time(t);
                        self.info(&format!("    Modified:    {text}"));
                    }
                    None => self.info("    Modified:"),
                }
                self.extension_blocks(&item.extension_blocks);
            }
            "ShellBag0X00" => {
                for store in &item.property_stores {
                    self.property_store(store);
                }
            }
            "ShellBag0X1F" => {
                if let Some(store) = &item.property_store {
                    self.property_store(store);
                }
            }
            "ShellBag0X01" => {
                if let Some(letter) = item.drive_letter.as_deref().filter(|l| !l.is_empty()) {
                    self.info(&format!("  Drive letter: {letter}"));
                }
            }
            "ShellBag0X71" => {
                if item.property_store.as_ref().is_some_and(|s| !s.sheets.is_empty()) {
                    self.log.block(Level::Fatal, "Property stores found! Please email lnk file to saericzimmerman@gmail.com so support can be added!!");
                }
            }
            "ShellBag0X2E" | "ShellBag0X2F" | "ShellBag0X2A" | "ShellBag0X3A" | "ShellBag0X41" | "ShellBag0X42" | "ShellBag0X43" | "ShellBag0X46" | "ShellBag0X47" | "ShellBag0X61" | "ShellBag0X23" | "ShellBag0XC3" | "ShellBag0X74"
            | "ShellBag0X79" | "ShellBagZipContents" | "ShellBag0X4C" => {}
            _ => {
                self.warn(">> UNMAPPED Type! Please email lnk file to saericzimmerman@gmail.com so support can be added!");
                let text = item.to_text();
                self.warn(&format!(">> {text}"));
            }
        }
        self.log.blank();
    }

    fn extra_block(&mut self, block: &ExtraBlock) {
        let yes = |b: bool| if b { "True" } else { "False" };
        match block {
            ExtraBlock::Console(c) => {
                self.info(">> Console data block");
                self.info(&format!("   Fill Attributes: {}", c.fill_attributes));
                self.info(&format!("   Popup Attributes: {}", c.popup_fill_attributes));
                self.info(&format!("   Buffer Size (Width x Height): {} x {}", c.screen_width_buffer_size, c.screen_height_buffer_size));
                self.info(&format!("   Window Size (Width x Height): {} x {}", c.window_width, c.window_height));
                self.info(&format!("   Origin (X/Y): {}/{}", c.window_origin_x, c.window_origin_y));
                self.info(&format!("   Font Size: {}", c.font_size));
                self.info(&format!("   Is Bold: {}", yes(c.is_bold)));
                self.info(&format!("   Face Name: {}", c.face_name));
                self.info(&format!("   Cursor Size: {}", c.cursor_size));
                self.info(&format!("   Is Full Screen: {}", yes(c.is_full_screen)));
                self.info(&format!("   Is Quick Edit: {}", yes(c.is_quick_edit)));
                self.info(&format!("   Is Insert Mode: {}", yes(c.is_insert_mode)));
                self.info(&format!("   Is Auto Positioned: {}", yes(c.is_auto_positioned)));
                self.info(&format!("   History Buffer Size: {}", c.history_buffer_size));
                self.info(&format!("   History Buffer Count: {}", c.history_buffer_count));
                self.info(&format!("   History Duplicates Allowed: {}", yes(c.history_duplicates_allowed)));
                self.log.blank();
            }
            // the original looks for "ConsoleFEDataBlock", which is not the class's name, so this block shows nothing
            ExtraBlock::ConsoleFe { .. } => {}
            ExtraBlock::Darwin { application_identifier_unicode, product_code, feature_name, component_id, .. } => {
                self.info(">> Darwin data block");
                self.info(&format!("   Application ID: {application_identifier_unicode}"));
                self.info(&format!("   Product code: {product_code}"));
                self.info(&format!("   Feature name: {feature_name}"));
                self.info(&format!("   Component ID: {component_id}"));
                self.log.blank();
            }
            ExtraBlock::EnvironmentVariable { unicode, .. } => {
                self.info(">> Environment variable data block");
                self.info(&format!("   Environment variables: {unicode}"));
                self.log.blank();
            }
            ExtraBlock::IconEnvironment { unicode, .. } => {
                self.info(">> Icon environment data block");
                self.info(&format!("   Icon path: {unicode}"));
                self.log.blank();
            }
            ExtraBlock::KnownFolder { id, name, .. } => {
                self.info(">> Known folder data block");
                self.info(&format!("   Known folder GUID: {id} ==> {name}"));
                self.log.blank();
            }
            ExtraBlock::PropertyStore(store) => {
                if !store.sheets.is_empty() {
                    self.info(">> Property store data block (Format: GUID\\ID Description ==> Value)");
                    let mut count = 0;
                    for sheet in &store.sheets {
                        for (key, value) in &sheet.property_names {
                            count += 1;
                            let prefix = pad_right(&format!("{}\\{key}", sheet.guid), 43);
                            let suffix = parse_int(key).map_or_else(String::new, |k| pad_right(&description_from_guid_and_key(&sheet.guid, k), 35));
                            self.info(&format!("   {prefix} {suffix} ==> {value}"));
                        }
                    }
                    if count == 0 {
                        self.warn("   (Property store is empty)");
                    }
                }
                self.log.blank();
            }
            ExtraBlock::Shim { layer_name } => {
                self.info(">> Shimcache data block");
                self.info(&format!("   Layer name: {layer_name}"));
                self.log.blank();
            }
            ExtraBlock::SpecialFolder { id, .. } => {
                self.info(">> Special folder data block");
                self.info(&format!("   Special Folder ID: {id}"));
                self.log.blank();
            }
            ExtraBlock::Tracker(t) => {
                self.info(">> Tracker database block");
                self.info(&format!("   Machine ID:  {}", t.machine_id));
                if t.is_time_based {
                    self.info(&format!("   MAC Address: {}", t.mac_address));
                    let vendor = vendor_from_mac(self.macs, &t.mac_address);
                    self.info(&format!("   MAC Vendor:  {vendor}"));
                    let text = self.time(t.creation_time);
                    self.info(&format!("   Creation:    {text}"));
                } else {
                    self.info("   MAC Address / Creation: (File Droid is not a time-based UUID)");
                }
                self.log.blank();
                self.info(&format!("   Volume Droid:       {}", t.volume_droid));
                self.info(&format!("   Volume Droid Birth: {}", t.volume_droid_birth));
                self.info(&format!("   File Droid:         {}", t.file_droid));
                self.info(&format!("   File Droid birth:   {}", t.file_droid_birth));
                self.log.blank();
            }
            ExtraBlock::VistaAndAboveIdList { target_ids, .. } => {
                self.info(">> Vista and above ID List data block");
                for item in target_ids {
                    let value = if item.value.is_empty() { "(None)" } else { item.value.as_str() };
                    self.info(&format!("   {} ==> {value}", item.friendly_name));
                }
                self.log.blank();
            }
            ExtraBlock::Damaged(d) => {
                self.info("Damaged data block");
                self.info(&format!("   Original Signature: {}", d.original_signature_text()));
                self.info(&format!("   Error Message: {}", d.error_message));
            }
        }
    }

    /// DisplayLnk
    fn lnk(&mut self, lnk: &LnkFile, nid: bool, neb: bool) {
        let format = self.format.clone();
        self.info(&format!("Source file: {}", lnk.source_file.as_deref().unwrap_or_default().replace("\\\\?\\", "")));
        self.info(&format!("  Source created:  {}", date_or_null(lnk.source.created, &format)));
        self.info(&format!("  Source modified: {}", date_or_null(lnk.source.modified, &format)));
        self.info(&format!("  Source accessed: {}", date_or_null(lnk.source.accessed, &format)));
        self.log.blank();
        self.info("--- Header ---");
        let shown = |t: Timestamp| date_or_null((!is_unset(t)).then_some(t), &format);
        self.info(&format!("  Target created:  {}", shown(lnk.header.target_created)));
        self.info(&format!("  Target modified: {}", shown(lnk.header.target_modified)));
        self.info(&format!("  Target accessed: {}", shown(lnk.header.target_accessed)));
        self.log.blank();
        self.info(&format!("  File size (bytes): {}", n0(u64::from(lnk.header.file_size))));
        self.info(&format!("  Flags: {}", lnk.header.data_flags_text()));
        self.info(&format!("  File attributes: {}", lnk.header.file_attributes_text()));
        if !lnk.header.hot_key.is_empty() {
            self.info(&format!("  Hot key: {}", lnk.header.hot_key));
        }
        self.info(&format!("  Icon index: {}", lnk.header.icon_index));
        self.info(&format!("  Show window: {} ({})", lnk.header.show_window_text(), lnk.header.show_window_description()));
        self.log.blank();
        let text = |o: &Option<String>| o.clone().unwrap_or_default();
        if lnk.header.has_flag(HAS_NAME) {
            self.info(&format!("Name: {}", text(&lnk.name)));
        }
        if lnk.header.has_flag(HAS_RELATIVE_PATH) {
            self.info(&format!("Relative Path: {}", text(&lnk.relative_path)));
        }
        if lnk.header.has_flag(HAS_WORKING_DIR) {
            self.info(&format!("Working Directory: {}", text(&lnk.working_directory)));
        }
        if lnk.header.has_flag(HAS_ARGUMENTS) {
            self.info(&format!("Arguments: {}", text(&lnk.arguments)));
        }
        if lnk.header.has_flag(HAS_ICON_LOCATION) {
            self.info(&format!("Icon Location: {}", text(&lnk.icon_location)));
        }
        if lnk.header.has_flag(HAS_LINK_INFO) {
            self.log.blank();
            self.info("--- Link information ---");
            self.info(&format!("Flags: {}", lnk.location_flags_text()));
            if let Some(volume) = &lnk.volume_info {
                self.log.blank();
                self.info(">> Volume information");
                self.info(&format!("  Drive type: {}", volume.drive_type_description()));
                self.info(&format!("  Serial number: {}", volume.serial_number));
                let label = if volume.label.is_empty() { "(No label)" } else { volume.label.as_str() };
                self.info(&format!("  Label: {label}"));
            }
            if let Some(share) = &lnk.network_share_info {
                self.log.blank();
                self.info("  Network share information");
                if !share.device_name.is_empty() {
                    self.info(&format!("    Device name: {}", share.device_name));
                }
                self.info(&format!("    Share name: {}", share.share_name));
                let provider = if share.has_valid_provider_type() { share.provider_type_text() } else { "(not set)".to_string() };
                self.info(&format!("    Provider type: {provider}"));
                self.info(&format!("    Share flags: {}", share.share_flags_text()));
                self.log.blank();
            }
            if let Some(path) = lnk.local_path.as_deref().filter(|p| !p.is_empty()) {
                self.info(&format!("  Local path: {path}"));
            }
            if let Some(path) = lnk.common_path.as_deref().filter(|p| !p.is_empty()) {
                self.info(&format!("  Common path: {path}"));
            }
        }
        if nid {
            self.log.blank();
            self.info(&format!("(Target ID information suppressed. Lnk TargetID count: {})", n0(lnk.target_ids.len() as u64)));
        }
        if !lnk.target_ids.is_empty() && !nid {
            self.log.blank();
            self.info("--- Target ID information (Format: Type ==> Value) ---");
            self.log.blank();
            self.info(&format!("  Absolute path: {}", absolute_path(&lnk.target_ids)));
            self.log.blank();
            for item in &lnk.target_ids {
                self.shell_item(item);
            }
            self.info("--- End Target ID information ---");
        }
        if neb {
            self.log.blank();
            self.info(&format!("(Extra blocks information suppressed. Lnk Extra block count: {})", n0(lnk.extra_blocks.len() as u64)));
        }
        if !lnk.extra_blocks.is_empty() && !neb {
            self.log.blank();
            self.info("--- Extra blocks information ---");
            self.log.blank();
            for block in &lnk.extra_blocks {
                self.extra_block(block);
            }
        }
        let list = anomalies(lnk);
        if !list.is_empty() {
            self.log.blank();
            self.warn("--- Parse problems and anomalies ---");
            for anomaly in list {
                self.warn(&format!("  {anomaly}"));
            }
        }
    }
}

/// FileSystemName.MatchesSimpleExpression, ignoring case: the masks here are `*.lnk` and `*`
fn matches_mask(mask: &str, name: &str) -> bool {
    mask == "*" || upper_invariant(name).ends_with(".LNK")
}

/// LnkFinder: non-empty files under a folder in .NET's order, without going into links to folders, and what couldn't be read
fn find_lnk_files(directory: &str, mask: &str) -> (Vec<String>, Vec<(String, String)>) {
    let root = if directory.len() > 1 { directory.trim_end_matches('/').to_string() } else { directory.to_string() };
    let mut queue = VecDeque::from([root]);
    let (mut files, mut unreadable) = (Vec::new(), Vec::new());
    while let Some(folder) = queue.pop_front() {
        let entries = match ez_common::cli::read_dir_ntfs_order(std::path::Path::new(&folder)) {
            Ok(e) => e,
            Err(e) => {
                let text = e.to_string();
                let reason = text.rfind(" (os error").map_or(text.clone(), |i| text[..i].to_string());
                unreadable.push((folder, reason));
                continue;
            }
        };
        for entry in entries {
            let path = entry.path();
            let text = path.to_string_lossy().into_owned();
            let is_link = entry.file_type().is_ok_and(|t| t.is_symlink());
            let is_folder = std::fs::metadata(&path).is_ok_and(|m| m.is_dir());
            if is_folder {
                if !is_link {
                    queue.push_back(text);
                }
            } else if std::fs::symlink_metadata(&path).is_ok_and(|m| m.len() > 0) && matches_mask(mask, &entry.file_name().to_string_lossy()) {
                files.push(text);
            }
        }
    }
    (files, unreadable)
}

struct Export {
    csv: Option<BufWriter<File>>,
    json: Option<BufWriter<File>>,
    xhtml: Option<BufWriter<File>>,
}

fn xhtml_element(out: &mut String, name: &str, value: Option<&str>) {
    match value.filter(|v| !v.is_empty()) {
        Some(v) => out.push_str(&format!("\r\n        <{name}>{}</{name}>", xml_text_writer_text(v))),
        None => out.push_str(&format!("\r\n        <{name} />")),
    }
}

fn xhtml_container(o: &CsvOut) -> String {
    let mut s = String::from("\r\n    <Container>");
    for name in [
        "SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags", "DriveType",
        "VolumeSerialNumber", "VolumeLabel", "LocalPath", "NetworkPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "MachineID", "MachineMACAddress", "MACVendor",
        "TrackerCreatedOn", "ExtraBlocksPresent", "Name", "IconLocation", "ShowWindow", "EnvironmentVariables", "VolumeDroid", "FileDroid", "VolumeDroidBirth", "FileDroidBirth", "Anomalies",
    ] {
        xhtml_element(&mut s, name, o.get(name).as_deref());
    }
    s.push_str("\r\n    </Container>");
    s
}

fn save_xml(o: &CsvOut, folder: &str, stamp: &str, log: &mut Logger) -> bool {
    let attempt = || -> Result<(), (String, String)> {
        let fail = |e: std::io::Error, path: &Path| (io_message(path, &e), io_exception(&e).to_string());
        std::fs::create_dir_all(folder).map_err(|e| fail(e, Path::new(folder)))?;
        let hash: String = Sha1::digest(o.source_file.as_bytes())[..4].iter().map(|b| format!("{b:02X}")).collect();
        let path = combine(folder, &format!("{stamp}_{}_{hash}.xml", base_name(&o.source_file)));
        // what ServiceStack says for anything DataContractSerializer can't write
        let xml = o.to_xml().map_err(|_| ("Error serializing object of type LECmd.CsvOut".to_string(), "System.Runtime.Serialization.SerializationException".to_string()))?;
        std::fs::write(&path, xml).map_err(|e| fail(e, Path::new(&path)))
    };
    match attempt() {
        Ok(()) => true,
        Err((message, exception)) => {
            log.block(Level::Error, &format!("Error exporting XML for {}. Error: {message}\n{exception}: {message}", o.source_file));
            false
        }
    }
}

/// The export of every processed file. Exceptions out of the folders and files stop it
fn export(files: &[LnkFile], args: &Args, stamp: &str, macs: &HashMap<String, String>, log: &mut Logger, export_errors: &mut u32) -> Result<(), (String, String)> {
    let fail = |e: std::io::Error, path: &str| (io_message(Path::new(path), &e), io_exception(&e).to_string());
    let mut out = Export { csv: None, json: None, xhtml: None };
    let mut csv_path = String::new();
    if let Some(csv) = given(&args.csv) {
        if !Path::new(csv).is_dir() {
            log.info(&format!("{csv} does not exist. Creating..."));
            std::fs::create_dir_all(csv).map_err(|e| fail(e, csv))?;
        }
        let name = given(&args.csvf).map_or_else(|| format!("{stamp}_LECmd_Output.csv"), |f| base_name(f).to_string());
        let path = combine(csv, &name);
        csv_path = full_path(&path);
        log.info(&format!("CSV output will be saved to {csv_path}"));
        let opened = File::create(&path).and_then(|f| {
            let mut w = BufWriter::new(f);
            let mut line = String::new();
            for (i, c) in CSV_COLUMNS.iter().enumerate() {
                if i > 0 {
                    line.push(',');
                }
                ez_common::csv::field(&mut line, c);
            }
            line.push_str(ez_common::csv::NEW_LINE);
            w.write_all(line.as_bytes())?;
            Ok(w)
        });
        match opened {
            Ok(w) => out.csv = Some(w),
            Err(e) => {
                *export_errors += 1;
                let (message, exception) = fail(e, &path);
                log.block(Level::Error, &format!("Unable to open {path} for writing. CSV export canceled. Error: {message}\n{exception}: {message}"));
            }
        }
    }
    if let Some(json) = given(&args.json) {
        if !Path::new(json).is_dir() {
            log.info(&format!("{json} does not exist. Creating..."));
            std::fs::create_dir_all(json).map_err(|e| fail(e, json))?;
        }
        log.info(&format!("Saving json output to {json}"));
    }
    if let Some(xml) = given(&args.xml) {
        if !Path::new(xml).is_dir() {
            log.info(&format!("{xml} does not exist. Creating..."));
            std::fs::create_dir_all(xml).map_err(|e| fail(e, xml))?;
        }
        log.info(&format!("Saving XML output to {xml}"));
    }
    if let Some(json) = given(&args.json) {
        let path = combine(json, &format!("{stamp}_LECmd_Output.json"));
        out.json = Some(BufWriter::new(File::create(&path).map_err(|e| fail(e, &path))?));
    }
    if let Some(html) = given(&args.html) {
        // on Windows a path's separators become underscores here; so do they on this system
        let folder = combine(html, &format!("{stamp}_LECmd_Output_for_{}", html.replace(":\\", "_").replace(['\\', '/'], "_")));
        std::fs::create_dir_all(&folder).map_err(|e| fail(e, &folder))?;
        let normalize = combine(&folder, "normalize.css");
        std::fs::write(&normalize, ez_common::dotnet::crlf_lines(include_str!("../data/normalize.css").trim_start_matches('\u{feff}'))).map_err(|e| fail(e, &normalize))?;
        let style = combine(&folder, "style.css");
        std::fs::write(&style, ez_common::dotnet::crlf_lines(include_str!("../data/style.css").trim_start_matches('\u{feff}'))).map_err(|e| fail(e, &style))?;
        let path = combine(&folder, "index.xhtml");
        log.info(&format!("Saving HTML output to {path}"));
        let mut w = BufWriter::new(File::create(&path).map_err(|e| fail(e, &path))?);
        w.write_all("\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<?xml-stylesheet href=\"normalize.css\"?>\r\n<?xml-stylesheet href=\"style.css\"?>\r\n".as_bytes()).map_err(|e| fail(e, &path))?;
        out.xhtml = Some(w);
    }
    let mut in_document = false;
    for file in files {
        // a --dt that .NET rejects fails each record, and nothing of it is written
        if let Err(message) = ez_common::Timestamp::check_format(&args.dt) {
            *export_errors += 1;
            let source = file.source_file.as_deref().unwrap_or_default();
            log.block(Level::Error, &format!("Error building output record for {source}. It is missing from the exported files. Error: {message}\nSystem.FormatException: {message}"));
            continue;
        }
        let o = csv_format(file, &args.dt, macs, log);
        if let Some(w) = &mut out.csv {
            if let Err(e) = w.write_all(o.csv_line().as_bytes()) {
                *export_errors += 1;
                let (message, exception) = fail(e, &csv_path);
                log.block(Level::Error, &format!("Error writing record for {} to {csv_path}. Error: {message}\n{exception}: {message}", o.source_file));
            }
        }
        if out.json.is_some() {
            let cs = csv_format(file, JSON_DATE_FORMAT, macs, log);
            let line = if args.pretty { cs.dump() } else { cs.to_json() };
            if let Some(w) = &mut out.json {
                if let Err(e) = write!(w, "{line}{}", ez_common::dotnet::NEW_LINE) {
                    *export_errors += 1;
                    let (message, exception) = (e.to_string(), io_exception(&e).to_string());
                    log.block(Level::Error, &format!("Error writing JSON for {}. Error: {message}\n{exception}: {message}", o.source_file));
                }
            }
        }
        if let Some(w) = &mut out.xhtml {
            if !in_document {
                in_document = true;
                w.write_all(b"<document>").map_err(|e| (e.to_string(), io_exception(&e).to_string()))?;
            }
            w.write_all(xhtml_container(&o).as_bytes()).map_err(|e| (e.to_string(), io_exception(&e).to_string()))?;
        }
        if let Some(xml) = given(&args.xml) {
            if !save_xml(&o, xml, stamp, log) {
                *export_errors += 1;
            }
        }
    }
    if let Some(mut w) = out.csv {
        w.flush().map_err(|e| (e.to_string(), io_exception(&e).to_string()))?;
    }
    if let Some(mut w) = out.json {
        w.flush().map_err(|e| (e.to_string(), io_exception(&e).to_string()))?;
    }
    if let Some(mut w) = out.xhtml {
        let end: &[u8] = if in_document { b"\r\n</document>" } else { b"<document />" };
        w.write_all(end).and_then(|()| w.flush()).map_err(|e| (e.to_string(), io_exception(&e).to_string()))?;
    }
    Ok(())
}

struct Work {
    failed: Vec<String>,
    read_errors: u32,
    processed: Vec<LnkFile>,
}

/// ProcessFile
fn process_file(path: &str, args: &Args, active_format: &str, macs: &HashMap<String, String>, log: &mut Logger, work: &mut Work) {
    let start = Instant::now();
    if !args.quiet {
        log.block(Level::Info, &format!("Processing {}", path.replace("\\\\?\\", "")));
        log.blank();
    }
    let lnk = match lnk_ez::load_file(path, args.cp) {
        Ok(l) => l,
        Err(e) => {
            let place = match (&e.field, e.offset) {
                (field, offset) if offset >= 0 => format!(" [{} at offset {offset}]", field.as_deref().unwrap_or_default()),
                _ => String::new(),
            };
            work.failed.push(format!("{} ==> ({}){place}", path.replace("\\\\?\\", ""), e.message));
            log.block(Level::Error, &format!("Error opening {path}. Message: {}{place}\n{}", e.message, e.exception));
            log.blank();
            if e.read_error {
                work.read_errors += 1;
            }
            return;
        }
    };
    if args.removable && lnk.volume_info.as_ref().map(|v| v.drive_type) != Some(lnk_ez::DRIVE_REMOVABLE) {
        return;
    }
    let source = lnk.source_file.as_deref().unwrap_or_default().replace("\\\\?\\", "");
    if !args.quiet {
        Display { log, format: active_format.to_string(), macs }.lnk(&lnk, args.nid, args.neb);
    } else if !lnk.parse_errors.is_empty() {
        log.block(Level::Warning, &format!("{source} was parsed with {} problem(s): {}", n0(lnk.parse_errors.len() as u64), lnk.parse_errors.join(" | ")));
    }
    if !args.quiet {
        log.blank();
    }
    log.block(Level::Info, &format!("---------- Processed {source} in {} seconds ----------", number_n(start.elapsed().as_secs_f64(), 8)));
    if !args.quiet {
        log.block(Level::Info, "\r\n");
    }
    work.processed.push(lnk);
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    log.blank();
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args = match ez_common::cli::parse_args::<Args>() {
        Ok(a) => a,
        Err(code) => return code,
    };
    let macs = load_macs();
    let active_format = if args.mp { PRECISE_TIME_FORMAT.to_string() } else { args.dt.clone() };
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &active_format).to_stdout();
    let now = utc_now();
    let stamp = now.format("yyyyMMddHHmmss");
    let console_log: Option<PathBuf> = [args.csv.as_deref(), args.json.as_deref(), args.xml.as_deref(), args.html.as_deref()]
        .into_iter()
        .flatten()
        .find(|d| !d.trim().is_empty())
        .filter(|_| args.co)
        .map(|d| Path::new(&full_path(d)).join(format!("{stamp}_LECmd_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }
    let (file, directory) = (given(&args.file), given(&args.directory));
    if file.is_none() && directory.is_none() {
        return help_and_warning(&mut log, "Either -f or -d is required. Exiting");
    }
    if let Some(f) = file {
        // File.Exists: true for a link to nothing, false for a folder
        let exists = std::fs::metadata(f).map_or_else(|_| std::fs::symlink_metadata(f).is_ok(), |m| !m.is_dir());
        if !exists {
            return help_and_warning(&mut log, &format!("File {f} not found. Exiting"));
        }
    }
    if let Some(d) = directory {
        if !Path::new(d).is_dir() {
            return help_and_warning(&mut log, &format!("Directory {d} not found. Exiting"));
        }
    }

    log.info(&format!("LECmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let mut work = Work { failed: Vec::new(), read_errors: 0, processed: Vec::new() };
    if let Some(f) = file {
        process_file(&full_path(f), &args, &active_format, &macs, &mut log, &mut work);
    } else {
        let d = directory.unwrap_or_default();
        log.info(&format!("Looking for lnk files in {d}"));
        log.blank();
        let full = full_path(d);
        let (files, unreadable) = find_lnk_files(&full, if args.all { "*" } else { "*.lnk" });
        for (folder, reason) in unreadable {
            log.error(&format!("Unable to read folder {folder}: {reason}"));
            work.read_errors += 1;
        }
        log.info(&format!("Found {} files", n0(files.len() as u64)));
        log.blank();
        let start = Instant::now();
        for path in &files {
            process_file(path, &args, &active_format, &macs, &mut log, &mut work);
        }
        if args.quiet {
            log.blank();
        }
        log.info(&format!("Processed {} out of {} files in {} seconds", n0((files.len() - work.failed.len()) as u64), n0(files.len() as u64), number_n(start.elapsed().as_secs_f64(), 4)));
        if !work.failed.is_empty() {
            log.blank();
            log.info("Failed files");
            for failed in &work.failed {
                log.block(Level::Info, &format!("  {failed}"));
            }
        }
        let with_problems = work.processed.iter().filter(|l| !l.parse_errors.is_empty()).count();
        if with_problems > 0 {
            log.blank();
            log.warning(&format!("{} file(s) were parsed but have problems or anomalies. See the Anomalies column or the per-file output for details", n0(with_problems as u64)));
        }
    }

    let mut export_errors = 0;
    if !work.processed.is_empty() {
        log.blank();
        if let Err((message, exception)) = export(&work.processed, &args, &stamp, &macs, &mut log, &mut export_errors) {
            export_errors += 1;
            log.block(Level::Error, &format!("Error exporting data! Error: {message}\n{exception}: {message}"));
        }
    }
    if work.read_errors > 0 || export_errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
