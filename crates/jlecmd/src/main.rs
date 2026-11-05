//! JLECmd: Windows jump lists to the console, CSV, JSON and XHTML, with the original's options and output.

mod writer;

use std::collections::VecDeque;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_exception, io_message, utc_now};
use ez_common::dotnet::{n0, number_n, upper_invariant};
use ez_common::json::Value;
use ez_common::net::MORE_THAN_ONE;
use ez_common::{Level, Timestamp};
use jumplist_ez::{AppIdList, AutomaticDestination, CustomDestination, EMPTY_CUSTOM, JumpListError, NO_MAC_ADDRESS, droid_text};
use lnk_ez::{ExtraBlock, HAS_ARGUMENTS, HAS_ICON_LOCATION, HAS_LINK_INFO, HAS_NAME, HAS_RELATIVE_PATH, HAS_WORKING_DIR, LnkFile};
use shellitems_ez::ShellItem;
use shellitems_ez::blocks::{Block, BlockKind};
use shellitems_ez::sheet::PropertyStore;
use shellitems_ez::utils::description_from_guid_and_key;
use writer::NetWriter;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PRECISE_TIME_FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";
const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";
const AUTOMATIC_SIGNATURE: u64 = 0xe11a_b1a1_e011_cfd0;

/// Reads Windows jump lists, with JLECmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    args_override_self = true,
    after_help = "Examples:\n  jlecmd -f /tmp/f01b4d95cf55d32a.customDestinations-ms --mp\n  jlecmd -f /tmp/f01b4d95cf55d32a.automaticDestinations-ms --json /tmp/jsonOutput --pretty\n  jlecmd -d /tmp/CustomDestinations --csv /tmp/out --html /tmp/out -q\n  jlecmd -d /tmp/Recent --dt \"ddd yyyy MM dd HH:mm:ss.fff\""
)]
struct Args {
    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// Process all files in directory vs. only files matching *.automaticDestinations-ms or *.customDestinations-ms
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

    /// File name to save JSON formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    jsonf: Option<String>,

    /// Directory to save xhtml formatted results to
    #[arg(long, value_name = "DIR")]
    html: Option<String>,

    /// When exporting to json, use a more human readable layout
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    pretty: bool,

    /// Do not dump full details about each file processed. Speeds up processing when using --json or --csv
    #[arg(short = 'q', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    quiet: bool,

    /// Include more information about lnk files
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    ld: bool,

    /// Include full information about lnk files (Alternatively, dump lnk files using --dumpTo and process with LECmd)
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    fd: bool,

    /// Path to file containing AppIDs and descriptions (appid|description format). New appIds are added to the built-in list, existing
    /// appIds will have their descriptions updated
    #[arg(long = "appIds", value_name = "FILE")]
    app_ids: Option<String>,

    /// Directory to save exported lnk files
    #[arg(long = "dumpTo", value_name = "DIR")]
    dump_to: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// When true, display higher precision for timestamps
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    mp: bool,

    /// When true, show contents of Directory not accounted for in DestList entries
    #[arg(long = "withDir", action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    with_dir: bool,

    /// Username to include in JSON/CSV output (e.g. the owner of the jump list artifacts)
    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    /// Code page to parse strings
    #[arg(long, default_value_t = 1252, value_name = "NUMBER", allow_negative_numbers = true)]
    cp: i32,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_JLECmd_<version>_ConsoleLog.txt in the output directory (the first of --csv,
    /// --json, --html, --dumpTo given). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

/// An exception: its message and type
struct Failure {
    message: String,
    exception: String,
    read_error: bool,
}

impl Failure {
    fn null_reference() -> Failure {
        Failure { message: NULL_REFERENCE.to_string(), exception: "System.NullReferenceException".to_string(), read_error: false }
    }

    fn io(path: &Path, e: &std::io::Error) -> Failure {
        Failure { message: io_message(path, e), exception: io_exception(e).to_string(), read_error: true }
    }
}

impl From<JumpListError> for Failure {
    fn from(e: JumpListError) -> Failure {
        Failure { message: e.message, exception: e.exception.to_string(), read_error: e.read_error }
    }
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

/// Path.GetFileNameWithoutExtension and Path.GetExtension
fn split_extension(path: &str) -> (&str, &str) {
    let name = base_name(path);
    match name.rfind('.') {
        Some(dot) => (&name[..dot], &name[dot..]),
        None => (name, ""),
    }
}

/// {x:N0} of a value that can be negative
fn n0_signed(v: i64) -> String {
    if v < 0 { format!("-{}", n0(v.unsigned_abs())) } else { n0(v as u64) }
}

fn pad_right(text: &str, width: usize) -> String {
    let length = text.encode_utf16().count();
    if length >= width { text.to_string() } else { format!("{text}{}", " ".repeat(width - length)) }
}

/// {x:G5} of a float, in en-US
fn g5(v: f32) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 { "\u{221e}".to_string() } else { "-\u{221e}".to_string() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0".to_string() } else { "0".to_string() };
    }
    let scientific = format!("{:.4e}", f64::from(v));
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if negative { "-" } else { "" };
    if exponent <= -5 || exponent >= 5 {
        let rest = digits[1..].trim_end_matches('0');
        let point = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{}{point}E{exp_sign}{:02}", &digits[..1], exponent.abs());
    }
    if exponent >= 0 {
        let whole = exponent as usize + 1;
        let rest = digits[whole..].trim_end_matches('0');
        let point = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        return format!("{sign}{}{point}", &digits[..whole]);
    }
    let zeros = "0".repeat((-exponent - 1) as usize);
    format!("{sign}0.{zeros}{}", digits.trim_end_matches('0'))
}

/// int.Parse, with its exceptions' messages
fn int_parse(text: &str) -> Result<i32, Failure> {
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure { message: format!("The input string '{text}' was not in a correct format."), exception: "System.FormatException".to_string(), read_error: false });
    }
    trimmed.parse().map_err(|_| Failure { message: "Value was either too large or too small for an Int32.".to_string(), exception: "System.OverflowException".to_string(), read_error: false })
}

/// Serilog's text for a nullable time
fn date_or_null(t: Option<Timestamp>, format: &str) -> String {
    t.map_or_else(|| "null".to_string(), |t| t.format(format))
}

/// null for a target time in 1601, which means none
fn target_time(t: Timestamp) -> Option<Timestamp> {
    (t.parts().year != 1601).then_some(t)
}

fn target_text(t: Timestamp, format: &str) -> String {
    target_time(t).map_or_else(String::new, |t| t.format(format))
}

/// GetAbsolutePathFromTargetIDs
fn absolute_path(ids: &[ShellItem]) -> String {
    ids.iter().map(|i| i.value.as_str()).collect::<Vec<_>>().join("\\")
}

/// RemoveInvalidXmlChars: each UTF-16 unit that isn't an XML character goes, so the two halves of a surrogate pair do
fn remove_invalid_xml_chars(text: &str) -> String {
    if text.trim().is_empty() {
        return text.to_string();
    }
    text.chars().filter(|c| matches!(*c as u32, 0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd)).collect()
}

/// Text through XmlTextWriter: control characters become references
fn xml_text(value: &str) -> String {
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

/// GetDescriptionFromEnumValue of a drive type: a value the enum doesn't name has no field to look at
fn drive_description(lnk: &LnkFile) -> Result<Option<String>, Failure> {
    match &lnk.volume_info {
        None => Ok(None),
        Some(v) if v.drive_type_is_defined() => Ok(Some(v.drive_type_description())),
        Some(_) => Err(Failure::null_reference()),
    }
}

/// What the CSV columns take from a link
#[derive(Default)]
struct LnkColumns {
    target_created: Option<String>,
    target_modified: Option<String>,
    target_accessed: Option<String>,
    file_size: u32,
    relative_path: Option<String>,
    working_directory: Option<String>,
    file_attributes: Option<String>,
    header_flags: Option<String>,
    drive_type: String,
    volume_serial_number: Option<String>,
    volume_label: Option<String>,
    local_path: Option<String>,
    common_path: Option<String>,
    target_id_absolute_path: Option<String>,
    target_mft_entry_number: Option<String>,
    target_mft_sequence_number: Option<String>,
    machine_id: Option<String>,
    machine_mac_address: Option<String>,
    tracker_created_on: Option<String>,
    extra_blocks_present: Option<String>,
    arguments: Option<String>,
}

impl LnkColumns {
    fn no_lnk() -> LnkColumns {
        LnkColumns { drive_type: "(None)".to_string(), ..LnkColumns::default() }
    }

    /// The columns from the link's header and link information
    fn from_header(lnk: &LnkFile, format: &str) -> Result<LnkColumns, Failure> {
        Ok(LnkColumns {
            target_created: Some(target_text(lnk.header.target_created, format)),
            target_modified: Some(target_text(lnk.header.target_modified, format)),
            target_accessed: Some(target_text(lnk.header.target_accessed, format)),
            file_size: lnk.header.file_size,
            relative_path: lnk.relative_path.clone(),
            file_attributes: Some(lnk.header.file_attributes_text()),
            header_flags: Some(lnk.header.data_flags_text()),
            drive_type: drive_description(lnk)?.unwrap_or_else(|| "(None)".to_string()),
            volume_serial_number: lnk.volume_info.as_ref().map(|v| v.serial_number.clone()),
            volume_label: lnk.volume_info.as_ref().map(|v| v.label.clone()),
            local_path: lnk.local_path.clone(),
            common_path: lnk.common_path.clone(),
            ..LnkColumns::default()
        })
    }

    /// The columns from the rest of the link, which are the same for each kind of row
    fn fill_rest(&mut self, lnk: &LnkFile, format: &str) -> Result<(), Failure> {
        self.arguments = Some(if lnk.header.has_flag(HAS_ARGUMENTS) { lnk.arguments.clone().unwrap_or_default() } else { String::new() });
        self.working_directory = lnk.working_directory.clone();
        self.extra_blocks_present = Some(lnk.extra_blocks.iter().map(ExtraBlock::class_name).collect::<Vec<_>>().join(", "));
        let mut trackers = lnk.extra_blocks.iter().filter_map(|b| if let ExtraBlock::Tracker(t) = b { Some(t) } else { None });
        if let Some(tracker) = trackers.next() {
            if trackers.next().is_some() {
                return Err(Failure { message: MORE_THAN_ONE.to_string(), exception: "System.InvalidOperationException".to_string(), read_error: false });
            }
            self.tracker_created_on = Some(tracker.creation_time.format(format));
            self.machine_id = Some(tracker.machine_id.clone());
            self.machine_mac_address = Some(tracker.mac_address.clone());
        }
        if let Some(last) = lnk.target_ids.last() {
            if let Some(BlockKind::Beef0004 { mft, .. }) = target_blocks(last).iter().rev().map(|b| &b.kind).find(|k| matches!(k, BlockKind::Beef0004 { .. })) {
                self.target_mft_entry_number = mft.entry_number.map(|e| format!("0x{e:X}"));
                self.target_mft_sequence_number = mft.sequence_number.map(|s| format!("0x{s:X}"));
            }
        }
        Ok(())
    }
}

/// AutoCsvOut
struct AutoCsv {
    source: [String; 4],
    app_id: String,
    app_id_description: String,
    has_sps: bool,
    dest_list_version: String,
    last_used_entry_number: String,
    mru: Option<String>,
    entry_number: String,
    creation_time: Option<String>,
    last_modified: Option<String>,
    hostname: String,
    mac_address: String,
    path: String,
    interaction_count: Option<String>,
    pin_status: String,
    file_birth_droid: String,
    file_droid: String,
    volume_birth_droid: String,
    volume_droid: String,
    lnk: LnkColumns,
    notes: Option<String>,
}

const AUTO_COLUMNS: &[&str] = &[
    "SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "AppId", "AppIdDescription", "HasSps", "DestListVersion", "LastUsedEntryNumber", "MRU", "EntryNumber", "CreationTime", "LastModified", "Hostname", "MacAddress", "Path",
    "InteractionCount", "PinStatus", "FileBirthDroid", "FileDroid", "VolumeBirthDroid", "VolumeDroid", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags",
    "DriveType", "VolumeSerialNumber", "VolumeLabel", "LocalPath", "CommonPath", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "MachineID", "MachineMACAddress", "TrackerCreatedOn", "ExtraBlocksPresent", "Arguments", "Notes",
];

const CUSTOM_COLUMNS: &[&str] = &[
    "SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "AppId", "AppIdDescription", "EntryName", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags",
    "DriveType", "VolumeSerialNumber", "VolumeLabel", "LocalPath", "CommonPath", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "TargetMFTSequenceNumber", "MachineID", "MachineMACAddress", "TrackerCreatedOn", "ExtraBlocksPresent", "Arguments",
];

fn csv_line(fields: &[String]) -> String {
    let mut line = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        ez_common::csv::field(&mut line, f);
    }
    line.push_str(ez_common::csv::NEW_LINE);
    line
}

fn opt(o: &Option<String>) -> String {
    o.clone().unwrap_or_default()
}

impl LnkColumns {
    fn csv_target_part(&self, out: &mut Vec<String>) {
        out.extend([
            opt(&self.target_created),
            opt(&self.target_modified),
            opt(&self.target_accessed),
            self.file_size.to_string(),
            opt(&self.relative_path),
            opt(&self.working_directory),
            opt(&self.file_attributes),
            opt(&self.header_flags),
            self.drive_type.clone(),
            opt(&self.volume_serial_number),
            opt(&self.volume_label),
            opt(&self.local_path),
            opt(&self.common_path),
            opt(&self.target_id_absolute_path),
            opt(&self.target_mft_entry_number),
            opt(&self.target_mft_sequence_number),
            opt(&self.machine_id),
            opt(&self.machine_mac_address),
            opt(&self.tracker_created_on),
            opt(&self.extra_blocks_present),
            opt(&self.arguments),
        ]);
    }
}

impl AutoCsv {
    fn fields(&self) -> Vec<String> {
        let mut out = self.source.to_vec();
        out.extend([
            self.app_id.clone(),
            self.app_id_description.clone(),
            (if self.has_sps { "True" } else { "False" }).to_string(),
            self.dest_list_version.clone(),
            self.last_used_entry_number.clone(),
            opt(&self.mru),
            self.entry_number.clone(),
            opt(&self.creation_time),
            opt(&self.last_modified),
            self.hostname.clone(),
            self.mac_address.clone(),
            self.path.clone(),
            opt(&self.interaction_count),
            self.pin_status.clone(),
            self.file_birth_droid.clone(),
            self.file_droid.clone(),
            self.volume_birth_droid.clone(),
            self.volume_droid.clone(),
        ]);
        self.lnk.csv_target_part(&mut out);
        out.push(opt(&self.notes));
        out
    }
}

/// CustomCsvOut
struct CustomCsv {
    source: [String; 4],
    app_id: String,
    app_id_description: String,
    entry_name: String,
    lnk: LnkColumns,
}

impl CustomCsv {
    fn fields(&self) -> Vec<String> {
        let mut out = self.source.to_vec();
        out.extend([self.app_id.clone(), self.app_id_description.clone(), self.entry_name.clone()]);
        self.lnk.csv_target_part(&mut out);
        out
    }
}

/// The source file's path and times, through FileInfo
fn source_columns(path: &str, format: &str) -> [String; 4] {
    let times = lnk_ez::file_times(path);
    let start = Timestamp::from_filetime(0).expect("a valid time");
    let text = |t: Option<Timestamp>| t.unwrap_or(start).format(format);
    [path.to_string(), text(times.created), text(times.modified), text(times.accessed)]
}

/// GetAutoCsvFormat
fn auto_csv(auto: &AutomaticDestination, format: &str, with_dir: bool, log: &mut Logger) -> Result<Vec<AutoCsv>, Failure> {
    let source = source_columns(&auto.source_file, format);
    let mut rows = Vec::new();
    for entry in &auto.entries {
        let lnk = match &entry.lnk {
            None => LnkColumns::no_lnk(),
            Some(lnk) => {
                let mut columns = LnkColumns::from_header(lnk, format)?;
                log.debug(&format!("Getting absolute path. TargetID count: {}", n0(lnk.target_ids.len() as u64)));
                let mut target = absolute_path(&lnk.target_ids);
                if target.is_empty() {
                    target = match &lnk.network_share_info {
                        Some(share) => format!("{}\\{}", share.share_name, opt(&lnk.common_path)),
                        None => format!("{}\\{}", opt(&lnk.local_path), opt(&lnk.common_path)),
                    };
                }
                columns.target_id_absolute_path = Some(target);
                columns.fill_rest(lnk, format)?;
                columns
            }
        };
        let creation = if entry.creation_time.parts().year == 1582 { String::new() } else { entry.creation_time.format(format) };
        rows.push(AutoCsv {
            source: source.clone(),
            app_id: auto.app_id.clone(),
            app_id_description: auto.app_id_description.clone(),
            has_sps: auto.has_sps,
            dest_list_version: auto.dest_list_version.to_string(),
            last_used_entry_number: auto.last_used_entry_number.to_string(),
            mru: Some(entry.mru_position.to_string()),
            entry_number: entry.entry_number_hex(),
            creation_time: Some(creation),
            last_modified: Some(entry.last_modified.format(format)),
            hostname: entry.hostname.clone(),
            mac_address: if entry.mac_address == NO_MAC_ADDRESS { String::new() } else { entry.mac_address.clone() },
            path: entry.path.clone(),
            interaction_count: Some(entry.interaction_count.to_string()),
            pin_status: (if entry.pinned { "True" } else { "False" }).to_string(),
            file_birth_droid: droid_text(&entry.file_birth_droid).to_string(),
            file_droid: droid_text(&entry.file_droid).to_string(),
            volume_birth_droid: droid_text(&entry.volume_birth_droid).to_string(),
            volume_droid: droid_text(&entry.volume_droid).to_string(),
            lnk,
            notes: Some(String::new()),
        });
    }
    if with_dir {
        for d in &auto.directory {
            if d.name == "Root Entry" || d.name == "DestList" || auto.entries.iter().any(|e| e.entry_number_hex() == d.name) {
                continue;
            }
            let Some(f) = auto.lnk_from_directory_name(&d.name)? else { continue };
            let mut lnk = LnkColumns::from_header(&f, format)?;
            let mut target = absolute_path(&f.target_ids);
            if target.is_empty() {
                let share = f.network_share_info.as_ref().map_or("", |s| s.share_name.as_str());
                target = format!("{share}\\\\{}", opt(&f.common_path));
            }
            lnk.target_id_absolute_path = Some(target);
            lnk.fill_rest(&f, format)?;
            rows.push(AutoCsv {
                source: source.clone(),
                app_id: auto.app_id.clone(),
                app_id_description: auto.app_id_description.clone(),
                has_sps: auto.has_sps,
                dest_list_version: auto.dest_list_version.to_string(),
                last_used_entry_number: auto.last_used_entry_number.to_string(),
                mru: None,
                entry_number: d.name.clone(),
                creation_time: match d.creation_time {
                    Some(t) if t.parts().year == 1582 => Some(String::new()),
                    Some(t) => Some(t.format(format)),
                    None => None,
                },
                last_modified: d.modified_time.map(|t| t.format(format)),
                hostname: String::new(),
                mac_address: String::new(),
                path: String::new(),
                interaction_count: None,
                pin_status: String::new(),
                file_birth_droid: String::new(),
                file_droid: String::new(),
                volume_birth_droid: String::new(),
                volume_droid: String::new(),
                lnk,
                notes: Some("Found in Directory, not DestList".to_string()),
            });
        }
    }
    Ok(rows)
}

/// GetCustomCsvFormat
fn custom_csv(custom: &CustomDestination, format: &str) -> Result<Vec<CustomCsv>, Failure> {
    let source = source_columns(&custom.source_file, format);
    let mut rows = Vec::new();
    for entry in &custom.entries {
        for lnk in &entry.lnk_files {
            let mut columns = LnkColumns::from_header(lnk, format)?;
            if !lnk.target_ids.is_empty() {
                columns.target_id_absolute_path = Some(absolute_path(&lnk.target_ids));
            }
            columns.fill_rest(lnk, format)?;
            rows.push(CustomCsv { source: source.clone(), app_id: custom.app_id.clone(), app_id_description: custom.app_id_description.clone(), entry_name: entry.name.clone(), lnk: columns });
        }
    }
    Ok(rows)
}

struct Display<'a> {
    log: &'a mut Logger,
    format: String,
}

impl Display<'_> {
    fn info(&mut self, text: &str) {
        self.log.block(Level::Info, text);
    }

    fn warn(&mut self, text: &str) {
        self.log.block(Level::Warning, text);
    }

    fn blank(&mut self) {
        self.log.blank();
    }

    fn time(&self, t: Timestamp) -> String {
        t.format(&self.format)
    }

    /// The three "Lnk target" lines
    fn target_times(&mut self, lnk: &LnkFile) {
        let format = self.format.clone();
        let shown = |t: Timestamp| date_or_null(target_time(t), &format);
        let (c, m, a) = (shown(lnk.header.target_created), shown(lnk.header.target_modified), shown(lnk.header.target_accessed));
        self.info(&format!("  Lnk target created:  {c}"));
        self.info(&format!("  Lnk target modified: {m}"));
        self.info(&format!("  Lnk target accessed: {a}"));
    }

    fn file_entry(&mut self, item: &ShellItem, blank_after_blocks: bool) {
        self.info(&format!("    Short name: {}", item.short_name.as_deref().unwrap_or("null")));
        match item.last_modification {
            Some(t) => {
                let text = self.time(t);
                self.info(&format!("    Modified:    {text}"));
            }
            None => self.info("    Modified:"),
        }
        self.item_blocks(&item.extension_blocks, blank_after_blocks);
    }

    fn item_blocks(&mut self, blocks: &[Block], blank_after: bool) {
        if blocks.is_empty() {
            return;
        }
        self.info(&format!("    Extension block count: {}", n0(blocks.len() as u64)));
        self.blank();
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
                    self.info(&format!("    GUID: {} ({})", guid.as_deref().unwrap_or("null"), folder.as_deref().unwrap_or("null")));
                }
                BlockKind::FileDocumentType(text) if block.class == "Beef001a" => self.info(&format!("    File document type: {text}")),
                _ => {
                    let text = block.to_text();
                    self.info(&format!("    {text}"));
                }
            }
            if blank_after {
                self.blank();
            }
        }
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
                let suffix = int_parse(key).map_or_else(|_| " ".repeat(35), |k| pad_right(&description_from_guid_and_key(&sheet.guid, k), 35));
                self.info(&format!("     {prefix} {suffix} ==> {value}"));
            }
        }
        if count == 0 {
            self.warn("     (Property store is empty)");
        }
    }

    fn shell_item(&mut self, item: &ShellItem) {
        let value = if item.value.is_empty() { "(None)" } else { item.value.as_str() };
        self.info(&format!("  -{} ==> {value}", item.friendly_name));
        match item.class {
            "ShellBag0X32" | "ShellBag0X36" => self.file_entry(item, true),
            "ShellBag0X31" | "ShellBag0X35" | "ShellBag0X39" | "ShellBag0XB1" => self.file_entry(item, false),
            "ShellBag0X3A" if item.short_name.is_some() => self.file_entry(item, false),
            "ShellBagCFSF" => {
                match item.last_modification {
                    Some(t) => {
                        let text = self.time(t);
                        self.info(&format!("    Modified:    {text}"));
                    }
                    None => self.info("    Modified:"),
                }
                self.item_blocks(&item.extension_blocks, false);
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
                    self.warn("Property stores found! Please email lnk file to saericzimmerman@gmail.com so support can be added!!");
                }
            }
            "ShellBagDamaged" | "ShellBag0X2E" | "ShellBag0X2F" | "ShellBag0X2A" | "ShellBag0X3A" | "ShellBag0X41" | "ShellBag0X42" | "ShellBag0X43" | "ShellBag0X46" | "ShellBag0X47" | "ShellBag0X61" | "ShellBag0X23" | "ShellBag0XC3"
            | "ShellBag0X74" | "ShellBag0X79" | "ShellBag0X4C" | "ShellBagZipContents" => {}
            _ => {
                self.warn(">> UNMAPPED Type! Please email lnk file to saericzimmerman@gmail.com so support can be added!");
                let text = item.to_text();
                self.warn(&format!(">>{text}"));
            }
        }
        self.blank();
    }

    fn extra_block(&mut self, block: &ExtraBlock) -> Result<(), Failure> {
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
                self.blank();
            }
            // the original looks for "ConsoleFEDataBlock", which is not the class's name, and has no case for a damaged block
            ExtraBlock::ConsoleFe { .. } | ExtraBlock::Damaged(_) => {}
            ExtraBlock::Darwin { application_identifier_unicode, .. } => {
                self.info(">> Darwin data block");
                self.info(&format!("   Application ID: {application_identifier_unicode}"));
                self.blank();
            }
            ExtraBlock::EnvironmentVariable { unicode, .. } => {
                self.info(">> Environment variable data block");
                self.info(&format!("   Environment variables: {unicode}"));
                self.blank();
            }
            ExtraBlock::IconEnvironment { unicode, .. } => {
                self.info(">> Icon environment data block");
                self.info(&format!("   Icon path: {unicode}"));
                self.blank();
            }
            ExtraBlock::KnownFolder { id, name, .. } => {
                self.info(">> Known folder data block");
                self.info(&format!("   Known folder GUID: {id} ==> {name}"));
                self.blank();
            }
            ExtraBlock::PropertyStore(store) => {
                if !store.sheets.is_empty() {
                    self.info(">> Property store data block (Format: GUID\\ID Description ==> Value)");
                    let mut count = 0;
                    for sheet in &store.sheets {
                        for (key, value) in &sheet.property_names {
                            count += 1;
                            let prefix = pad_right(&format!("{}\\{key}", sheet.guid), 43);
                            // int.Parse: a named property ends the file
                            let suffix = pad_right(&description_from_guid_and_key(&sheet.guid, int_parse(key)?), 35);
                            self.info(&format!("   {prefix} {suffix} ==> {value}"));
                        }
                    }
                    if count == 0 {
                        self.info("   (Property store is empty)");
                    }
                }
                self.blank();
            }
            ExtraBlock::Shim { layer_name } => {
                self.info(">> Shimcache data block");
                self.info(&format!("   LayerName: {layer_name}"));
                self.blank();
            }
            ExtraBlock::SpecialFolder { id, .. } => {
                self.info(">> Special folder data block");
                self.info(&format!("   Special Folder ID: {id}"));
                self.blank();
            }
            ExtraBlock::Tracker(t) => {
                self.info(">> Tracker database block");
                self.info(&format!("   Machine ID:  {}", t.machine_id));
                self.info(&format!("   MAC Address: {}", t.mac_address));
                // the original's list of vendors is never filled
                self.info("   MAC Vendor:  (Unknown vendor)");
                let text = self.time(t.creation_time);
                self.info(&format!("   Creation:    {text}"));
                self.blank();
                self.info(&format!("   Volume Droid:       {}", t.volume_droid));
                self.info(&format!("   Volume Droid Birth: {}", t.volume_droid_birth));
                self.info(&format!("   File Droid:         {}", t.file_droid));
                self.info(&format!("   File Droid birth:   {}", t.file_droid_birth));
                self.blank();
            }
            ExtraBlock::VistaAndAboveIdList { target_ids, .. } => {
                self.info(">> Vista and above ID List data block");
                for item in target_ids {
                    let value = if item.value.is_empty() { "(None)" } else { item.value.as_str() };
                    self.info(&format!("   {} ==> {value}", item.friendly_name));
                }
                self.blank();
            }
        }
        Ok(())
    }

    /// What DumpLnkDetail and DumpLnkFile show of the link information. The indent differs between them
    fn link_info(&mut self, lnk: &LnkFile, blank_after_heading: bool) -> Result<(), Failure> {
        self.blank();
        self.info("--- Link information ---");
        if blank_after_heading {
            self.blank();
        }
        self.info(&format!("Flags: {}", lnk.location_flags_text()));
        if let Some(volume) = &lnk.volume_info {
            self.blank();
            self.info(">> Volume information");
            let Some(description) = drive_description(lnk)? else { return Err(Failure::null_reference()) };
            self.info(&format!("  Drive type: {description}"));
            self.info(&format!("  Serial number: {}", volume.serial_number));
            let label = if volume.label.is_empty() { "(No label)" } else { volume.label.as_str() };
            self.info(&format!("  Label: {label}"));
        }
        if let Some(share) = &lnk.network_share_info {
            self.blank();
            self.info("  Network share information");
            if !share.device_name.is_empty() {
                self.info(&format!("    Device name: {}", share.device_name));
            }
            self.info(&format!("    Share name: {}", share.share_name));
            self.info(&format!("    Provider type: {}", share.provider_type_text()));
            self.info(&format!("    Share flags: {}", share.share_flags_text()));
            self.blank();
        }
        if let Some(path) = lnk.local_path.as_deref().filter(|p| !p.is_empty()) {
            self.info(&format!("  Local path: {path}"));
        }
        if let Some(path) = lnk.common_path.as_deref().filter(|p| !p.is_empty()) {
            self.info(&format!("  Common path: {path}"));
        }
        Ok(())
    }

    /// The name, relative path, working directory and arguments lines of a link
    fn strings(&mut self, lnk: &LnkFile, indent: &str) {
        let text = |o: &Option<String>| o.as_deref().unwrap_or("null").to_string();
        if lnk.header.has_flag(HAS_NAME) {
            self.info(&format!("{indent}Name: {}", text(&lnk.name)));
        }
        if lnk.header.has_flag(HAS_RELATIVE_PATH) {
            self.info(&format!("{indent}Relative Path: {}", text(&lnk.relative_path)));
        }
        if lnk.header.has_flag(HAS_WORKING_DIR) {
            self.info(&format!("{indent}Working Directory: {}", text(&lnk.working_directory)));
        }
        if lnk.header.has_flag(HAS_ARGUMENTS) {
            self.info(&format!("{indent}Arguments: {}", text(&lnk.arguments)));
        }
    }

    /// DumpLnkDetail
    fn lnk_detail(&mut self, lnk: Option<&LnkFile>) -> Result<(), Failure> {
        let Some(lnk) = lnk else {
            self.warn("(lnk file not present)");
            return Ok(());
        };
        self.strings(lnk, "  ");
        if lnk.header.has_flag(HAS_LINK_INFO) {
            self.link_info(lnk, false)?;
        }
        Ok(())
    }

    /// DumpLnkFile
    fn lnk_file(&mut self, lnk: &LnkFile) -> Result<(), Failure> {
        let format = self.format.clone();
        self.info("--- Header ---");
        self.blank();
        let shown = |t: Timestamp| date_or_null(target_time(t), &format);
        self.info(&format!("  Target created:  {}", shown(lnk.header.target_created)));
        self.info(&format!("  Target modified: {}", shown(lnk.header.target_modified)));
        self.info(&format!("  Target accessed: {}", shown(lnk.header.target_accessed)));
        self.blank();
        self.info(&format!("  File size: {}", n0(u64::from(lnk.header.file_size))));
        self.info(&format!("  Flags: {}", lnk.header.data_flags_text()));
        self.info(&format!("  File attributes: {}", lnk.header.file_attributes_text()));
        if !lnk.header.hot_key.is_empty() {
            self.info(&format!("  Hot key: {}", lnk.header.hot_key));
        }
        self.info(&format!("  Icon index: {}", lnk.header.icon_index));
        if !lnk.header.show_window_is_defined() {
            return Err(Failure::null_reference());
        }
        self.info(&format!("  Show window: {} ({})", lnk.header.show_window_text(), lnk.header.show_window_description()));
        self.blank();
        self.strings(lnk, "");
        if lnk.header.has_flag(HAS_ICON_LOCATION) {
            self.info(&format!("Icon Location: {}", lnk.icon_location.as_deref().unwrap_or("null")));
        }
        if lnk.header.has_flag(HAS_LINK_INFO) {
            self.link_info(lnk, false)?;
        }
        if !lnk.target_ids.is_empty() {
            self.blank();
            self.info("--- Target ID information (Format: Type ==> Value) ---");
            self.blank();
            self.info(&format!("  Absolute path: {}", absolute_path(&lnk.target_ids)));
            self.blank();
            for item in &lnk.target_ids {
                self.shell_item(item);
            }
            self.info("--- End Target ID information ---");
        }
        if !lnk.extra_blocks.is_empty() {
            self.blank();
            self.info("--- Extra blocks information ---");
            self.blank();
            for block in &lnk.extra_blocks {
                self.extra_block(block)?;
            }
        }
        Ok(())
    }

    /// The part of ProcessAutoFile that shows the jump list
    fn automatic(&mut self, auto: &AutomaticDestination, args: &Args) -> Result<(), Failure> {
        self.info(&format!("Source file: {}", auto.source_file));
        self.blank();
        self.info("--- AppId information ---");
        self.info(&format!("  AppID: {}", auto.app_id));
        self.info(&format!("  Description: {}", auto.app_id_description));
        self.blank();
        self.info("--- DestList information ---");
        let count = n0_signed(i64::from(auto.dest_list_count));
        self.info(&format!("  Expected DestList entries:  {count}"));
        self.info(&format!("  Actual DestList entries:    {count}"));
        self.info(&format!("  DestList version:           {}", auto.dest_list_version));
        let adjust = if auto.dest_list_property_store.is_some() && !auto.empty_dest_list_property_store { 3 } else { 2 };
        if more_in_directory(auto, adjust) {
            self.blank();
            self.warn(&more_in_directory_text(auto));
        }
        self.blank();
        if let Some(store) = &auto.dest_list_property_store {
            self.info("   --- DestList Property Store information ---");
            for (name, value) in &store.property_names {
                self.info(&format!("    Property {name}: {value}"));
            }
        }
        self.blank();
        self.info("--- DestList entries ---");
        for entry in &auto.entries {
            self.info(&format!("Entry #: {}", entry.entry_number));
            self.info(&format!("  MRU: {}", entry.mru_position));
            self.info(&format!("  Path: {}", entry.path));
            self.info(&format!("  Pinned: {}", if entry.pinned { "True" } else { "False" }));
            let (created, modified) = (self.time(entry.creation_time), self.time(entry.last_modified));
            self.info(&format!("  Created on:    {created}"));
            self.info(&format!("  Last modified: {modified}"));
            self.info(&format!("  Hostname: {}", entry.hostname));
            self.info(&format!("  Mac Address: {}", if entry.mac_address == NO_MAC_ADDRESS { "" } else { entry.mac_address.as_str() }));
            self.info(&format!("  Interaction count: {}", n0_signed(i64::from(entry.interaction_count))));
            self.blank();
            self.info("--- Lnk information ---");
            if args.fd {
                let Some(lnk) = &entry.lnk else { return Err(Failure::null_reference()) };
                self.target_times(lnk);
                self.blank();
                self.lnk_file(lnk)?;
            } else if args.ld {
                self.lnk_detail(entry.lnk.as_ref())?;
            }
            match entry.lnk.as_ref().filter(|l| !args.fd && !l.target_ids.is_empty()) {
                Some(lnk) => {
                    let mut target = absolute_path(&lnk.target_ids);
                    if target.is_empty() {
                        let Some(share) = &lnk.network_share_info else { return Err(Failure::null_reference()) };
                        target = format!("{}\\\\{}", share.share_name, opt(&lnk.common_path));
                    }
                    self.info(&format!("  Absolute path: {target}"));
                    self.blank();
                }
                None => {
                    self.warn("   (lnk file not present)");
                    self.blank();
                }
            }
            self.blank();
            if let Some(sps) = &entry.sps {
                self.info("   --- Serialized Property Store information ---");
                for (name, value) in &sps.property_names {
                    self.info(&format!("    Property {name}: {value}"));
                }
            }
        }
        if args.with_dir {
            self.info("Directory entries not represented by DestList entries");
            for d in &auto.directory {
                if d.name == "Root Entry" || d.name == "DestList" || auto.entries.iter().any(|e| e.entry_number_hex() == d.name) {
                    continue;
                }
                self.info(&format!("Directory Name: {}", d.name));
                let Some(f) = auto.lnk_from_directory_name(&d.name)? else {
                    self.log.debug(&format!("  No lnk file found for directory entry {}", d.name));
                    continue;
                };
                if args.fd {
                    self.target_times(&f);
                    self.blank();
                    self.lnk_file(&f)?;
                } else {
                    if args.ld {
                        self.lnk_detail(Some(&f))?;
                    }
                    self.blank();
                    let mut target = absolute_path(&f.target_ids);
                    if target.is_empty() {
                        target = format!("{}\\\\{}", f.network_share_info.as_ref().map_or("", |s| s.share_name.as_str()), opt(&f.common_path));
                    }
                    self.info(&format!("  Absolute path: {target}"));
                    self.blank();
                }
            }
        }
        Ok(())
    }

    /// The part of ProcessCustomFile that shows the jump list
    fn custom(&mut self, custom: &CustomDestination, args: &Args) -> Result<(), Failure> {
        self.log.block(Level::Error, &format!("Source file: {}", custom.source_file));
        self.blank();
        self.info("--- AppId information ---");
        self.info(&format!("AppID: {}, Description: {}", custom.app_id, custom.app_id_description));
        self.info("--- DestList information ---");
        self.info(&format!("  Entries:  {}", n0(custom.entries.len() as u64)));
        self.blank();
        for (number, entry) in custom.entries.iter().enumerate() {
            self.info(&format!("  Entry #: {number}, lnk count: {} Rank: {}", n0(entry.lnk_files.len() as u64), g5(entry.rank)));
            if !entry.name.is_empty() {
                self.info(&format!("   Name: {}", entry.name));
            }
            self.blank();
            for (counter, lnk) in entry.lnk_files.iter().enumerate() {
                self.info(&format!("--- Lnk #{} information ---", n0(counter as u64)));
                self.target_times(lnk);
                if args.ld {
                    self.strings(lnk, "  ");
                    if lnk.header.has_flag(HAS_LINK_INFO) {
                        self.link_info(lnk, true)?;
                    }
                }
                if !lnk.target_ids.is_empty() {
                    self.blank();
                    self.info(&format!("  Absolute path: {}", absolute_path(&lnk.target_ids)));
                    self.blank();
                }
            }
            self.blank();
        }
        Ok(())
    }
}

fn more_in_directory(auto: &AutomaticDestination, adjust: i64) -> bool {
    auto.dest_list_count > 0 && i64::from(auto.dest_list_count) != auto.directory.len() as i64 - adjust
}

fn more_in_directory_text(auto: &AutomaticDestination) -> String {
    format!(
        "  There are more items in the Directory ({}) than are contained in the DestList ({}). Use --withDir to view/export them",
        n0_signed(auto.directory.len() as i64 - 2),
        n0_signed(i64::from(auto.dest_list_count))
    )
}

struct Work {
    failed: Vec<String>,
    read_errors: u32,
    automatic: Vec<AutomaticDestination>,
    custom: Vec<CustomDestination>,
}

/// IsAutomaticDestinationFile: an error reading it means no
fn is_automatic(path: &str) -> bool {
    std::fs::read(path).is_ok_and(|b| b.len() >= 8 && u64::from_le_bytes(b[..8].try_into().unwrap()) == AUTOMATIC_SIGNATURE)
}

fn fatal_line(path: &str, failure: &Failure) -> String {
    format!("Error opening {path}. Message: {}\n{}: {}", failure.message, failure.exception, failure.message)
}

/// ProcessAutoFile
fn process_auto(path: &str, args: &Args, format: &str, app_ids: &AppIdList, log: &mut Logger, work: &mut Work) {
    if !args.quiet {
        log.block(Level::Info, &format!("Processing {path}"));
        log.blank();
    }
    let start = Instant::now();
    log.debug(&format!("Opening {path}"));
    let attempt = (|| -> Result<AutomaticDestination, Failure> {
        let raw = std::fs::read(path).map_err(|e| Failure::io(Path::new(path), &e))?;
        let auto = AutomaticDestination::new(&raw, path, args.cp, app_ids)?;
        log.debug(&format!("Opened {path}"));
        if !args.quiet {
            Display { log: &mut *log, format: format.to_string() }.automatic(&auto, args)?;
        }
        Ok(auto)
    })();
    let auto = match attempt {
        Ok(a) => a,
        Err(failure) => {
            work.failed.push(format!("{path} ==> ({})", failure.message));
            log.block(Level::Fatal, &fatal_line(path, &failure));
            log.blank();
            if failure.read_error {
                work.read_errors += 1;
            }
            return;
        }
    };
    if !args.quiet {
        log.blank();
    }
    let adjust = if auto.dest_list_property_store.is_some() && !auto.empty_dest_list_property_store { 3 } else { 2 };
    if more_in_directory(&auto, adjust) {
        log.blank();
        log.block(Level::Warning, &more_in_directory_text(&auto));
    }
    if auto.has_sps || !auto.empty_dest_list_property_store {
        log.block(Level::Warning, "** JumpList has serialized property store(s)! View its contents via -f for details **");
        log.blank();
    }
    log.block(Level::Info, &format!("---------- Processed {} in {} seconds ----------", auto.source_file, number_n(start.elapsed().as_secs_f64(), 8)));
    if !args.quiet {
        log.blank();
    }
    work.automatic.push(auto);
}

/// ProcessCustomFile
fn process_custom(path: &str, args: &Args, format: &str, app_ids: &AppIdList, log: &mut Logger, work: &mut Work) {
    if !args.quiet {
        log.block(Level::Info, &format!("Processing {path}"));
        log.blank();
    }
    let start = Instant::now();
    let attempt = (|| -> Result<CustomDestination, Failure> {
        let raw = std::fs::read(path).map_err(|e| Failure::io(Path::new(path), &e))?;
        let custom = CustomDestination::new(&raw, path, args.cp, app_ids)?;
        if !args.quiet {
            Display { log: &mut *log, format: format.to_string() }.custom(&custom, args)?;
        }
        Ok(custom)
    })();
    let custom = match attempt {
        Ok(c) => c,
        Err(failure) => {
            if failure.message == EMPTY_CUSTOM {
                log.block(Level::Warning, &format!("Error processing {path}. Message: {EMPTY_CUSTOM}"));
            } else {
                work.failed.push(format!("{path} ==> ({})", failure.message));
                log.block(Level::Fatal, &fatal_line(path, &failure));
                if failure.read_error {
                    work.read_errors += 1;
                }
            }
            log.blank();
            return;
        }
    };
    if !args.quiet {
        log.blank();
    }
    log.block(Level::Info, &format!("---------- Processed {} in {} seconds ----------", custom.source_file, number_n(start.elapsed().as_secs_f64(), 8)));
    if !args.quiet {
        log.blank();
    }
    work.custom.push(custom);
}

/// FileSystemName.MatchesSimpleExpression, ignoring case, for `*.*Destinations-ms`
fn matches_jump_list(name: &str) -> bool {
    const SUFFIX: &str = "DESTINATIONS-MS";
    let upper = upper_invariant(name);
    upper.strip_suffix(SUFFIX).is_some_and(|rest| rest.contains('.'))
}

/// FindEntries: what's under a folder that matches, in .NET's order. Folders match as files do, and links to folders aren't followed
fn find_entries(directory: &str, all: bool) -> (Vec<String>, Vec<(String, String)>) {
    let root = if directory.len() > 1 { directory.trim_end_matches('/').to_string() } else { directory.to_string() };
    let mut queue = VecDeque::from([root]);
    let (mut files, mut unreadable) = (Vec::new(), Vec::new());
    while let Some(folder) = queue.pop_front() {
        let entries = match std::fs::read_dir(&folder) {
            Ok(e) => e,
            Err(e) => {
                let text = e.to_string();
                let reason = text.rfind(" (os error").map_or(text.clone(), |i| text[..i].to_string());
                unreadable.push((folder, reason));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let text = path.to_string_lossy().into_owned();
            let is_link = entry.file_type().is_ok_and(|t| t.is_symlink());
            if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) && !is_link {
                queue.push_back(text.clone());
            }
            if all || matches_jump_list(&entry.file_name().to_string_lossy()) {
                files.push(text);
            }
        }
    }
    (files, unreadable)
}

fn io_failure(path: &str, e: &std::io::Error) -> Failure {
    Failure::io(Path::new(path), e)
}

/// The XHTML report's folder, with its style sheets, and index.xhtml started
fn open_xhtml(html: &str, stamp: &str, kind: &str, log: &mut Logger) -> Result<NetWriter, Failure> {
    if !Path::new(html).is_dir() {
        log.info(&format!("{html} does not exist. Creating..."));
        std::fs::create_dir_all(html).map_err(|e| io_failure(html, &e))?;
    }
    // on Windows a path's separators become underscores here; so do they on this system
    let folder = combine(html, &format!("{stamp}_JLECmd_{kind}_Output_for_{}", html.replace(":\\", "_").replace(['\\', '/'], "_")));
    let styles = combine(&folder, "styles");
    std::fs::create_dir_all(&styles).map_err(|e| io_failure(&styles, &e))?;
    let normalize = combine(&styles, "normalize.css");
    std::fs::write(&normalize, include_str!("../data/normalize.css").trim_start_matches('\u{feff}')).map_err(|e| io_failure(&normalize, &e))?;
    let style = combine(&styles, "style.css");
    std::fs::write(&style, include_str!("../data/style.css").trim_start_matches('\u{feff}')).map_err(|e| io_failure(&style, &e))?;
    let path = combine(&folder, "index.xhtml");
    log.info(&format!("Saving HTML output to {path}"));
    let mut w = NetWriter::create(&path, "\u{feff}".as_bytes()).map_err(|e| io_failure(&path, &e))?;
    w.write_text("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<?xml-stylesheet href=\"styles/normalize.css\"?>\n<?xml-stylesheet href=\"styles/style.css\"?>\n<document>").map_err(|e| io_failure(&path, &e))?;
    Ok(w)
}

/// `xml.WriteElementString`
fn element(out: &mut String, indent: &str, name: &str, value: &str) {
    if value.is_empty() {
        out.push_str(&format!("\n{indent}<{name} />"));
    } else {
        out.push_str(&format!("\n{indent}<{name}>{}</{name}>", xml_text(value)));
    }
}

/// The columns of a row that the report shows after the ones that differ by kind
fn element_lnk_rest(out: &mut String, c: &LnkColumns) {
    const I: &str = "            ";
    element(out, I, "FileSize", &c.file_size.to_string());
    element(out, I, "RelativePath", &opt(&c.relative_path));
    element(out, I, "WorkingDirectory", &opt(&c.working_directory));
    element(out, I, "FileAttributes", &opt(&c.file_attributes));
    element(out, I, "HeaderFlags", &opt(&c.header_flags));
    element(out, I, "DriveType", &c.drive_type);
    element(out, I, "VolumeSerialNumber", &opt(&c.volume_serial_number));
    element(out, I, "VolumeLabel", &opt(&c.volume_label));
    element(out, I, "LocalPath", &opt(&c.local_path));
    element(out, I, "CommonPath", &opt(&c.common_path));
    element(out, I, "TargetMFTEntryNumber", &opt(&c.target_mft_entry_number));
    element(out, I, "TargetMFTSequenceNumber", &opt(&c.target_mft_sequence_number));
    element(out, I, "MachineID", &opt(&c.machine_id));
    element(out, I, "MachineMACAddress", &opt(&c.machine_mac_address));
    element(out, I, "TrackerCreatedOn", &opt(&c.tracker_created_on));
    element(out, I, "ExtraBlocksPresent", &opt(&c.extra_blocks_present));
}

fn auto_container(auto: &AutomaticDestination, rows: &[AutoCsv], source: &[String; 4]) -> String {
    let mut s = String::from("\n    <Container>");
    const C: &str = "        ";
    const I: &str = "            ";
    element(&mut s, C, "SourceFile", &auto.source_file);
    element(&mut s, C, "SourceCreated", &source[1]);
    element(&mut s, C, "SourceModified", &source[2]);
    element(&mut s, C, "SourceAccessed", &source[3]);
    element(&mut s, C, "AppId", &auto.app_id);
    element(&mut s, C, "AppIdDescription", &auto.app_id_description);
    element(&mut s, C, "DestListVersion", &auto.dest_list_version.to_string());
    element(&mut s, C, "LastUsedEntryNumber", &auto.last_used_entry_number.to_string());
    for o in rows {
        s.push_str(&format!("\n        <lftColumn>\n            <EntryNumber_large title=\"Entry number\">{}</EntryNumber_large>\n        </lftColumn>\n        <rgtColumn>", xml_text(&o.entry_number)));
        element(&mut s, I, "TargetIDAbsolutePath", &remove_invalid_xml_chars(&opt(&o.lnk.target_id_absolute_path)));
        element(&mut s, I, "CreationTime", &opt(&o.creation_time));
        element(&mut s, I, "LastModified", &opt(&o.last_modified));
        element(&mut s, I, "Hostname", &o.hostname);
        element(&mut s, I, "MacAddress", &o.mac_address);
        element(&mut s, I, "Path", &o.path);
        element(&mut s, I, "PinStatus", &o.pin_status);
        element(&mut s, I, "FileBirthDroid", &o.file_birth_droid);
        element(&mut s, I, "FileDroid", &o.file_droid);
        element(&mut s, I, "VolumeBirthDroid", &o.volume_birth_droid);
        element(&mut s, I, "VolumeDroid", &o.volume_droid);
        if !opt(&o.lnk.arguments).is_empty() {
            element(&mut s, I, "Arguments", &opt(&o.lnk.arguments));
        }
        element(&mut s, I, "TargetCreated", &opt(&o.lnk.target_created));
        element(&mut s, I, "TargetModified", &opt(&o.lnk.target_modified));
        element(&mut s, I, "TargetAccessed", &opt(&o.lnk.target_accessed));
        element(&mut s, I, "InteractionCount", &opt(&o.interaction_count));
        element_lnk_rest(&mut s, &o.lnk);
        s.push_str("\n        </rgtColumn>");
    }
    s.push_str("\n    </Container>");
    s
}

fn custom_container(custom: &CustomDestination, rows: &[CustomCsv], source: &[String; 4]) -> String {
    let mut s = String::from("\n    <Container>");
    const C: &str = "        ";
    const I: &str = "            ";
    s.push_str(&format!("\n        <SourceFile title=\"Note: Location and name of processed Jump List\">{}</SourceFile>", xml_text(&custom.source_file)));
    element(&mut s, C, "SourceCreated", &source[1]);
    element(&mut s, C, "SourceModified", &source[2]);
    element(&mut s, C, "SourceAccessed", &source[3]);
    element(&mut s, C, "AppId", &custom.app_id);
    element(&mut s, C, "AppIdDescription", &custom.app_id_description);
    for (index, o) in rows.iter().enumerate() {
        s.push_str(&format!("\n        <lftColumn>\n            <EntryNumber_large title=\"Note: Lnk position in file\">{index}</EntryNumber_large>\n        </lftColumn>\n        <rgtColumn>"));
        element(&mut s, I, "EntryName", &o.entry_name);
        element(&mut s, I, "TargetIDAbsolutePath", &opt(&o.lnk.target_id_absolute_path));
        if !opt(&o.lnk.arguments).is_empty() {
            element(&mut s, I, "Arguments", &opt(&o.lnk.arguments));
        }
        element(&mut s, I, "TargetCreated", &opt(&o.lnk.target_created));
        element(&mut s, I, "TargetModified", &opt(&o.lnk.target_modified));
        element(&mut s, I, "TargetAccessed", &opt(&o.lnk.target_accessed));
        element_lnk_rest(&mut s, &o.lnk);
        s.push_str("\n        </rgtColumn>");
    }
    s.push_str("\n    </Container>");
    s
}

/// The CSV file with its header, or what ExportAuto does when it can't be written
fn open_csv(csv: &str, args: &Args, stamp: &str, kind: &str, columns: &[&str], log: &mut Logger, export_errors: &mut u32) -> Result<Option<(NetWriter, String)>, Failure> {
    if !Path::new(csv).is_dir() {
        log.info(&format!("{csv} does not exist. Creating..."));
        std::fs::create_dir_all(csv).map_err(|e| io_failure(csv, &e))?;
    }
    let name = match given(&args.csvf) {
        Some(f) => {
            let (stem, extension) = split_extension(f);
            format!("{stem}_{kind}{extension}")
        }
        None => format!("{stamp}_{kind}.csv"),
    };
    let path = combine(csv, &name);
    log.info(&format!("{kind} CSV output will be saved to {path}"));
    let mut header: Vec<String> = Vec::with_capacity(columns.len() + 1);
    if given(&args.user).is_some() {
        header.push("User".to_string());
    }
    header.extend(columns.iter().map(|c| (*c).to_string()));
    let opened = NetWriter::create(&path, &[]).and_then(|mut w| {
        w.write_text(&csv_line(&header))?;
        Ok(w)
    });
    match opened {
        Ok(w) => Ok(Some((w, path))),
        Err(e) => {
            *export_errors += 1;
            let short = if kind == "AutomaticDestinations" { "Automatic" } else { "Custom" };
            let (message, exception) = (io_message(Path::new(&path), &e), io_exception(&e));
            log.block(Level::Error, &format!("Unable to write to {csv}. {short} CSV export canceled. Error: {message}\n{exception}: {message}"));
            Ok(None)
        }
    }
}

/// DumpToJson: the object, or it inside another with the user
fn save_json(value: Value, source_file: &str, json: &str, args: &Args, stamp: &str, kind: &str, log: &mut Logger, export_errors: &mut u32) {
    let attempt = || -> Result<(), Failure> {
        std::fs::create_dir_all(json).map_err(|e| io_failure(json, &e))?;
        let name = match given(&args.jsonf) {
            Some(f) => {
                let (stem, extension) = split_extension(f);
                format!("{stem}_{kind}{extension}")
            }
            None => format!("{stamp}_{}.json", base_name(source_file)),
        };
        let path = combine(json, &name);
        let target = match given(&args.user) {
            Some(user) => Value::object(vec![("User", Value::text(user)), ("JumpList", value)]),
            None => value,
        };
        let text = if args.pretty { target.dump() } else { target.to_json() };
        std::fs::write(&path, text).map_err(|e| io_failure(&path, &e))
    };
    if let Err(failure) = attempt() {
        *export_errors += 1;
        log.block(Level::Error, &format!("Error exporting json for {source_file}. Error: {}\n{}: {}", failure.message, failure.exception, failure.message));
    }
}

fn with_user(args: &Args, fields: Vec<String>) -> Vec<String> {
    match given(&args.user) {
        Some(user) => {
            let mut out = vec![user.to_string()];
            out.extend(fields);
            out
        }
        None => fields,
    }
}

/// ExportAuto. A failure leaves the files as they are: nothing flushes or closes them
fn export_auto(work: &Work, args: &Args, format: &str, stamp: &str, log: &mut Logger, export_errors: &mut u32) -> Result<(), Failure> {
    log.blank();
    let mut csv = None;
    if let Some(folder) = given(&args.csv) {
        csv = open_csv(folder, args, stamp, "AutomaticDestinations", AUTO_COLUMNS, log, export_errors)?;
    }
    if let Some(json) = given(&args.json) {
        if !Path::new(json).is_dir() {
            log.info(&format!("{json} does not exist. Creating..."));
            std::fs::create_dir_all(json).map_err(|e| io_failure(json, &e))?;
        }
        log.info(&format!("Saving Automatic json output to {json}"));
    }
    let mut xml = match given(&args.html) {
        Some(html) => Some(open_xhtml(html, stamp, "Automatic", log)?),
        None => None,
    };
    for auto in &work.automatic {
        if let Some(json) = given(&args.json) {
            save_json(auto.to_value(), &auto.source_file, json, args, stamp, "AutomaticDestinations", log, export_errors);
        }
        let rows = auto_csv(auto, format, args.with_dir, log)?;
        if let Some((w, path)) = &mut csv {
            for row in &rows {
                if let Err(e) = w.write_text(&csv_line(&with_user(args, row.fields()))) {
                    *export_errors += 1;
                    let (message, exception) = (e.to_string(), io_exception(&e));
                    log.block(Level::Error, &format!("Error writing record for {} to {path}. Error: {message}\n{exception}: {message}", auto.source_file));
                }
            }
        }
        if let Some(w) = &mut xml {
            let source = source_columns(&auto.source_file, format);
            w.write_text(&auto_container(auto, &rows, &source)).map_err(|e| io_failure(&auto.source_file, &e))?;
        }
    }
    if let Some((mut w, path)) = csv {
        w.flush().map_err(|e| io_failure(&path, &e))?;
    }
    if let Some(mut w) = xml {
        w.write_text("\n</document>").and_then(|()| w.flush()).map_err(|e| io_failure("index.xhtml", &e))?;
    }
    Ok(())
}

/// ExportCustom. A failure leaves the files as they are: nothing flushes or closes them
fn export_custom(work: &Work, args: &Args, format: &str, stamp: &str, log: &mut Logger, export_errors: &mut u32) -> Result<(), Failure> {
    log.blank();
    let mut csv = None;
    if let Some(folder) = given(&args.csv) {
        csv = open_csv(folder, args, stamp, "CustomDestinations", CUSTOM_COLUMNS, log, export_errors)?;
    }
    if let Some(json) = given(&args.json) {
        if !Path::new(json).is_dir() {
            log.info(&format!("{json} does not exist. Creating..."));
            std::fs::create_dir_all(json).map_err(|e| io_failure(json, &e))?;
        }
        log.info(&format!("Saving Custom json output to {json}"));
    }
    let mut xml = match given(&args.html) {
        Some(html) => Some(open_xhtml(html, stamp, "Custom", log)?),
        None => None,
    };
    for custom in &work.custom {
        if let Some(json) = given(&args.json) {
            save_json(custom.to_value(), &custom.source_file, json, args, stamp, "CustomDestinations", log, export_errors);
        }
        let rows = custom_csv(custom, format)?;
        if let Some((w, path)) = &mut csv {
            for row in &rows {
                if let Err(e) = w.write_text(&csv_line(&with_user(args, row.fields()))) {
                    *export_errors += 1;
                    let (message, exception) = (e.to_string(), io_exception(&e));
                    log.block(Level::Error, &format!("Error writing record for {} to {path}. Error: {message}\n{exception}: {message}", custom.source_file));
                }
            }
        }
        if let Some(w) = &mut xml {
            let source = source_columns(&custom.source_file, format);
            w.write_text(&custom_container(custom, &rows, &source)).map_err(|e| io_failure(&custom.source_file, &e))?;
        }
    }
    if let Some((mut w, path)) = csv {
        w.flush().map_err(|e| io_failure(&path, &e))?;
    }
    if let Some(mut w) = xml {
        w.write_text("\n</document>").and_then(|()| w.flush()).map_err(|e| io_failure("index.xhtml", &e))?;
    }
    Ok(())
}

/// Exporting the lnk files
fn dump_lnks(work: &Work, dump_to: &str, with_dir: bool, log: &mut Logger) -> std::io::Result<()> {
    log.blank();
    log.info(&format!("Dumping lnk files to {dump_to}"));
    std::fs::create_dir_all(dump_to)?;
    for custom in &work.custom {
        for entry in custom.entries.iter().filter(|e| !e.lnk_files.is_empty()) {
            let folder = Path::new(dump_to).join(base_name(&custom.source_file));
            std::fs::create_dir_all(&folder)?;
            entry.dump_all_lnk_files(&folder, &custom.app_id)?;
        }
    }
    for auto in &work.automatic {
        if auto.dest_list_count == 0 && !with_dir {
            continue;
        }
        auto.dump_all_lnk_files(&Path::new(dump_to).join(base_name(&auto.source_file)))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::FAILURE } else { ExitCode::SUCCESS };
        }
    };
    let format = if args.mp { PRECISE_TIME_FORMAT.to_string() } else { args.dt.clone() };
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &format).to_stdout();
    let stamp = utc_now().format("yyyyMMddHHmmss");
    let console_log = [args.csv.as_deref(), args.json.as_deref(), args.html.as_deref(), args.dump_to.as_deref()]
        .into_iter()
        .flatten()
        .find(|d| !d.trim().is_empty())
        .filter(|_| args.co)
        .map(|d| Path::new(&full_path(d)).join(format!("{stamp}_JLECmd_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }
    let (file, directory) = (given(&args.file), given(&args.directory));
    if file.is_none() && directory.is_none() {
        let _ = Args::command().print_long_help();
        println!();
        log.warning("Either -f or -d is required. Exiting");
        log.blank();
        return ExitCode::FAILURE;
    }
    if let Some(f) = file {
        // File.Exists: true for a link to nothing, false for a folder
        let exists = std::fs::metadata(f).map_or_else(|_| std::fs::symlink_metadata(f).is_ok(), |m| !m.is_dir());
        if !exists {
            log.warning(&format!("File {f} not found. Exiting"));
            log.blank();
            return ExitCode::FAILURE;
        }
    }
    if let Some(d) = directory {
        if !Path::new(d).is_dir() {
            log.warning(&format!("Directory {d} not found. Exiting"));
            log.blank();
            return ExitCode::FAILURE;
        }
    }

    log.info(&format!("JLECmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let mut app_ids = AppIdList::default();
    if let Some(extra) = given(&args.app_ids) {
        if std::fs::metadata(extra).is_ok_and(|m| !m.is_dir()) {
            log.info(&format!("Looking for AppIDs in {extra}"));
            match app_ids.load_file(extra) {
                Ok(added) => {
                    log.info(&format!("Loaded {} new AppIDs from {extra}", n0(added)));
                    log.blank();
                }
                Err(e) => {
                    log.error(&format!("Unhandled exception: {}", io_message(Path::new(extra), &e)));
                    return ExitCode::FAILURE;
                }
            }
        } else {
            log.warning(&format!("{extra} does not exist!"));
        }
    }

    let mut work = Work { failed: Vec::new(), read_errors: 0, automatic: Vec::new(), custom: Vec::new() };
    if let Some(f) = file {
        let full = full_path(f);
        if is_automatic(&full) {
            process_auto(&full, &args, &format, &app_ids, &mut log, &mut work);
        } else {
            process_custom(&full, &args, &format, &app_ids, &mut log, &mut work);
        }
    } else {
        let d = directory.unwrap_or_default();
        log.info(&format!("Looking for jump list files in {d}"));
        log.blank();
        let (files, unreadable) = find_entries(&full_path(d), args.all);
        for (folder, reason) in unreadable {
            log.error(&format!("Unable to read folder {folder}: {reason}"));
            work.read_errors += 1;
        }
        log.info(&format!("Found {} files", n0(files.len() as u64)));
        log.blank();
        let start = Instant::now();
        for path in &files {
            if is_automatic(path) {
                process_auto(path, &args, &format, &app_ids, &mut log, &mut work);
            } else {
                process_custom(path, &args, &format, &app_ids, &mut log, &mut work);
            }
        }
        if args.quiet {
            log.blank();
        }
        log.info(&format!("Processed {} out of {} files in {} seconds", n0_signed(files.len() as i64 - work.failed.len() as i64), n0(files.len() as u64), number_n(start.elapsed().as_secs_f64(), 4)));
        if !work.failed.is_empty() {
            log.blank();
            log.info("Failed files");
            for failed in &work.failed {
                log.block(Level::Info, &format!("  {failed}"));
            }
        }
    }

    if let Some(dump_to) = given(&args.dump_to) {
        if let Err(e) = dump_lnks(&work, dump_to, args.with_dir, &mut log) {
            // not caught in the original: the run ends here
            log.error(&format!("Unhandled exception: {}: {e}", io_exception(&e)));
            return ExitCode::FAILURE;
        }
    }

    let mut export_errors = 0;
    if !work.automatic.is_empty() {
        if let Err(failure) = export_auto(&work, &args, &format, &stamp, &mut log, &mut export_errors) {
            export_errors += 1;
            log.block(Level::Error, &format!("Error exporting Automatic Destinations data: {}\n{}: {}", failure.message, failure.exception, failure.message));
        }
    }
    if !work.custom.is_empty() {
        if let Err(failure) = export_custom(&work, &args, &format, &stamp, &mut log, &mut export_errors) {
            export_errors += 1;
            log.block(Level::Error, &format!("Error exporting Custom Destinations data! Error: {}\n{}: {}", failure.message, failure.exception, failure.message));
        }
    }
    if work.read_errors > 0 || export_errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g5_is_as_dotnet_writes_it() {
        assert_eq!(g5(1.0), "1");
        assert_eq!(g5(0.5), "0.5");
        assert_eq!(g5(12345.0), "12345");
        assert_eq!(g5(123456.0), "1.2346E+05");
        assert_eq!(g5(f32::from_bits(1)), "1.4013E-45");
        assert_eq!(g5(0.0), "0");
        assert_eq!(g5(0.00001), "1E-05");
    }

    #[test]
    fn the_mask_needs_a_dot_before_the_suffix() {
        assert!(matches_jump_list("a.automaticDestinations-ms"));
        assert!(matches_jump_list("B.CUSTOMDESTINATIONS-MS"));
        assert!(!matches_jump_list("destinations-ms"));
        assert!(!matches_jump_list("a.lnk"));
    }

    #[test]
    fn surrogates_are_not_xml_characters() {
        assert_eq!(remove_invalid_xml_chars("a\u{1f600}b"), "ab");
        assert_eq!(remove_invalid_xml_chars("a\u{1}b"), "ab");
        assert_eq!(remove_invalid_xml_chars("  "), "  ");
    }
}
