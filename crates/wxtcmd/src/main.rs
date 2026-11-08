//! WxTCmd: the Windows 10/11 Timeline database (ActivitiesCache.db) to CSV, with the original's options and output. See
//! docs/plans/wxtcmd.md.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use activitiescache_ez::{ActivitiesCacheData, Activity, Operation, PackageId, ReadError, activity_type_name, duration};
use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, prepare_temp, remove_temp_if_empty, utc_now};
use ez_common::dotnet::{n0, number_n};
use ez_common::{Level, Timestamp, csv};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reads the Windows 10/11 Timeline database (ActivitiesCache.db), with WxTCmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  wxtcmd -f /cases/C/Users/eric/AppData/Local/ConnectedDevicesPlatform/L.eric/ActivitiesCache.db --csv /tmp/out\n\n  \
                  Database files are typically found at 'C:\\Users\\<profile>\\AppData\\Local\\ConnectedDevicesPlatform\\L.<profile>\\ActivitiesCache.db'"
)]
struct Args {
    /// File to process
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// Folder for the temporary copies of the SQLite databases, which are opened instead of the evidence and deleted when done.
    /// Default: a Temp folder next to this program. A folder that isn't there is created, and removed again when done. If that
    /// folder can't be written to, this program stops: give a writable folder with --temp
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_WxTCmd_<version>_ConsoleLog.txt in the --csv directory. Use --co false to
    /// turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// What a format of no or one character stands for with the invariant culture, which the original formats times in. A longer
/// format is custom: the same as in en-US, which `Timestamp::format` writes, but for the era, A.D. (not AD)
fn invariant_format(format: &str) -> String {
    let mut chars = format.chars();
    let Some(c) = chars.next() else {
        return "MM/dd/yyyy HH:mm:ss zzz".to_string();
    };
    if chars.next().is_some() {
        return invariant_era(format);
    }
    match c {
        'd' => "MM/dd/yyyy",
        'D' => "dddd, dd MMMM yyyy",
        'f' => "dddd, dd MMMM yyyy HH:mm",
        'F' => "dddd, dd MMMM yyyy HH:mm:ss",
        'g' => "MM/dd/yyyy HH:mm",
        'G' => "MM/dd/yyyy HH:mm:ss",
        'm' | 'M' => "MMMM dd",
        't' => "HH:mm",
        'T' => "HH:mm:ss",
        'y' | 'Y' => "yyyy MMMM",
        // o, r, s and u are the same in every culture; the rest are rejected before
        _ => format,
    }
    .to_string()
}

/// A custom format with each era (`g`, `gg`..., `%g`) written as the literal A.D.; quoted text and escapes stay as they are
fn invariant_era(format: &str) -> String {
    let chars: Vec<char> = format.chars().collect();
    let mut out = String::with_capacity(format.len() + 8);
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            quote @ ('\'' | '"') => {
                out.push(quote);
                i += 1;
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        out.push(chars[i]);
                        i += 1;
                    }
                    out.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    out.push(quote);
                    i += 1;
                }
            }
            '\\' => {
                out.extend(chars[i..(i + 2).min(chars.len())].iter());
                i += 2;
            }
            '%' if chars.get(i + 1) == Some(&'g') => {
                out.push_str("'A.D.'");
                i += 2;
            }
            'g' => {
                while chars.get(i) == Some(&'g') {
                    i += 1;
                }
                out.push_str("'A.D.'");
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// How the times are written: the --dt format, or a marker where it is one .NET rejects
struct Times {
    format: String,
    bad: bool,
}

impl Times {
    fn text(&self, seconds: Option<i64>) -> String {
        match seconds {
            None => String::new(),
            Some(_) if self.bad => csv::BAD_DATE.to_string(),
            Some(s) => Timestamp((s - activitiescache_ez::MIN_SECONDS) * ez_common::time::TICKS_PER_SECOND).format(&self.format),
        }
    }
}

/// TimeSpan's constant format ([-][d.]hh:mm:ss), as CsvHelper writes it
fn span(seconds: Option<i64>) -> String {
    let Some(s) = seconds else { return String::new() };
    let sign = if s < 0 { "-" } else { "" };
    let t = s.unsigned_abs();
    let (days, rest) = (t / 86_400, t % 86_400);
    let day_part = if days > 0 { format!("{days}.") } else { String::new() };
    format!("{sign}{day_part}{:02}:{:02}:{:02}", rest / 3600, rest / 60 % 60, rest % 60)
}

fn bool_text(b: bool) -> String {
    (if b { "True" } else { "False" }).to_string()
}

const ACTIVITY_COLUMNS: [&str; 24] = [
    "Id", "ActivityTypeOrg", "ActivityType", "Executable", "DisplayText", "ContentInfo", "Payload", "ClipboardPayload", "StartTime", "EndTime",
    "Duration", "LastModifiedTime", "LastModifiedOnClient", "OriginalLastModifiedOnClient", "ExpirationTime", "CreatedInCloud", "IsLocalOnly",
    "ETag", "PackageIdHash", "PlatformDeviceId", "DevicePlatform", "TimeZone", "AppActivityId", "ClipboardText",
];

const OPERATION_COLUMNS: [&str; 25] = [
    "Id", "ActivityTypeOrg", "ActivityType", "Executable", "DisplayText", "ContentInfo", "Payload", "ClipboardPayload", "StartTime", "EndTime",
    "Duration", "LastModifiedTime", "LastModifiedTimeOnClient", "CreatedTime", "ExpirationTime", "OperationExpirationTime", "OperationOrder",
    "AppId", "OperationType", "Description", "PlatformDeviceId", "DevicePlatform", "TimeZone", "AppActivityId", "ClipboardText",
];

const PACKAGE_COLUMNS: [&str; 5] = ["Id", "Platform", "Name", "AdditionalInformation", "Expires"];

fn activity_fields(a: &Activity, t: &Times) -> Vec<String> {
    vec![
        a.id.clone(),
        a.activity_type.to_string(),
        activity_type_name(a.activity_type),
        a.executable.clone(),
        a.display_text.clone(),
        a.content_info.clone(),
        a.payload.clone(),
        a.clipboard_payload.clone(),
        t.text(a.start_time),
        t.text(a.end_time),
        span(duration(a.start_time, a.end_time)),
        t.text(a.last_modified_time),
        t.text(a.last_modified_on_client),
        t.text(a.original_last_modified_on_client),
        t.text(a.expiration_time),
        t.text(a.created_in_cloud),
        bool_text(a.is_local_only),
        a.etag.to_string(),
        a.package_id_hash.clone(),
        a.platform_device_id.clone(),
        a.device_platform.clone(),
        a.time_zone.clone(),
        a.app_activity_id.clone(),
        a.clipboard_text.clone(),
    ]
}

fn operation_fields(o: &Operation, t: &Times) -> Vec<String> {
    vec![
        o.id.clone(),
        o.activity_type.to_string(),
        activity_type_name(o.activity_type),
        o.executable.clone(),
        o.display_text.clone(),
        o.content_info.clone(),
        o.payload.clone(),
        o.clipboard_payload.clone(),
        t.text(o.start_time),
        t.text(o.end_time),
        span(duration(o.start_time, o.end_time)),
        t.text(o.last_modified_time),
        t.text(o.last_modified_time_on_client),
        t.text(o.created_time),
        t.text(o.expiration_time),
        t.text(o.operation_expiration_time),
        o.operation_order.to_string(),
        o.app_id.clone(),
        o.operation_type.to_string(),
        o.description.clone(),
        o.platform_device_id.clone(),
        o.device_platform.clone(),
        o.time_zone.clone(),
        o.app_activity_id.clone(),
        o.clipboard_text.clone(),
    ]
}

fn package_fields(p: &PackageId, t: &Times) -> Vec<String> {
    vec![p.id.clone(), p.platform.clone(), p.name.clone(), p.additional_information.clone(), t.text(p.expires)]
}

fn csv_line(fields: &[String]) -> String {
    let mut line = String::new();
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        csv::field(&mut line, field);
    }
    line.push_str(csv::NEW_LINE);
    line
}

/// Why a CSV couldn't be written
enum WriteError {
    Io(std::io::Error),
    /// --dt is a format .NET rejects: CsvHelper stopped at the first time, as here
    BadDate,
}

/// One CSV, with a byte order mark, as CsvHelper writes it
fn write_csv<T>(path: &Path, columns: &[&str], rows: &[T], times: &Times, fields: impl Fn(&T, &Times) -> Vec<String>) -> Result<(), WriteError> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(path).map_err(WriteError::Io)?);
    out.write_all(ez_common::cli::BOM).map_err(WriteError::Io)?;
    out.write_all(csv_line(&columns.iter().map(|c| c.to_string()).collect::<Vec<_>>()).as_bytes()).map_err(WriteError::Io)?;
    for row in rows {
        let mut line = csv_line(&fields(row, times));
        if times.bad && line.contains(csv::BAD_DATE) {
            csv::cut_at_bad_date(&mut line);
            out.write_all(line.as_bytes()).map_err(WriteError::Io)?;
            out.flush().map_err(WriteError::Io)?;
            return Err(WriteError::BadDate);
        }
        out.write_all(line.as_bytes()).map_err(WriteError::Io)?;
    }
    out.flush().map_err(WriteError::Io)
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    println!();
    ExitCode::FAILURE
}

/// File.Exists: true for a file (or a link to nothing), false for a folder
fn file_exists(path: &str) -> bool {
    let full = full_path(path);
    std::fs::metadata(&full).map_or_else(|_| std::fs::symlink_metadata(&full).is_ok(), |m| !m.is_dir())
}

fn write_all(data: &ActivitiesCacheData, csv_dir: &str, stamp: &str, user: &str, times: &Times) -> Result<(), String> {
    let dir = Path::new(csv_dir);
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| ez_common::cli::io_message(dir, &e))?;
    }
    let result = (|| {
        if !data.operations.is_empty() {
            write_csv(&dir.join(format!("{stamp}{user}_ActivityOperations.csv")), &OPERATION_COLUMNS, &data.operations, times, operation_fields)?;
        }
        if !data.package_ids.is_empty() {
            write_csv(&dir.join(format!("{stamp}{user}_Activity_PackageIDs.csv")), &PACKAGE_COLUMNS, &data.package_ids, times, package_fields)?;
        }
        if !data.activities.is_empty() {
            write_csv(&dir.join(format!("{stamp}{user}_Activity.csv")), &ACTIVITY_COLUMNS, &data.activities, times, activity_fields)?;
        }
        Ok(())
    })();
    result.map_err(|e| match e {
        WriteError::Io(e) => ez_common::cli::io_message(dir, &e),
        WriteError::BadDate => format!("{} (Input string was not in a correct format: --dt '{}')", csv::WRITER_ERROR, times.format),
    })
}

fn main() -> ExitCode {
    let args = match ez_common::cli::parse_args::<Args>() {
        Ok(a) => a,
        Err(code) => return code,
    };
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &args.dt).to_stdout();
    // one UTC time per run, for the CSV names and the console log
    let stamp = utc_now().format("yyyyMMddHHmmss");
    let console_log = given(&args.csv).filter(|d| args.co && !d.trim().is_empty()).map(|d| Path::new(&full_path(d)).join(format!("{stamp}_WxTCmd_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }
    let Some(file) = given(&args.file) else {
        return help_and_warning(&mut log, "-f is required. Exiting");
    };
    let Some(csv_dir) = given(&args.csv) else {
        return help_and_warning(&mut log, "--csv is required. Exiting");
    };
    if !file_exists(file) {
        return help_and_warning(&mut log, &format!("File '{file}' not found. Exiting"));
    }
    let user = match activitiescache_ez::text::user_profile(file) {
        u if u.is_empty() => u,
        u => format!("_{u}"),
    };

    log.info(&format!("WxTCmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    // the database is read from a copy, made in --temp or Temp next to this program (never the user's temp folder)
    let (temp, temp_created) = match prepare_temp(given(&args.temp), "WxTCmd") {
        Ok(t) => t,
        Err(error) => {
            log.error(&format!("The folder for the temporary copy of the database can't be written to ({error}). Give one with --temp. Exiting"));
            log.blank();
            return ExitCode::FAILURE;
        }
    };
    let start = Instant::now();
    let read = activitiescache_ez::read(Path::new(&full_path(file)), Path::new(&temp));
    remove_temp_if_empty(&temp, temp_created);
    let data = match read {
        Ok(d) => d,
        Err(ReadError::InvalidData(message)) => {
            // not a SQLite database, or too damaged to read: a bad file, not the tool's fault
            log.error(&format!("Error processing database: '{file}': {message}"));
            log.blank();
            return ExitCode::SUCCESS;
        }
        Err(ReadError::Sqlite(message)) => {
            log.error(&format!("Error processing database: {message}"));
            log.blank();
            return ExitCode::SUCCESS;
        }
        Err(ReadError::Io(message)) => {
            log.error(&format!("Error processing database: {message}"));
            log.blank();
            return ExitCode::FAILURE;
        }
    };

    if data.quick_check != "ok" {
        log.warning(&format!("The database is damaged ({}). What could be read is listed", data.quick_check.split('\n').next().unwrap_or_default()));
    }
    if !data.has_timeline_tables() {
        log.error(&format!("'{file}' has none of the Activity, ActivityOperation and Activity_PackageId tables. Is it an ActivitiesCache.db?"));
        log.blank();
        return ExitCode::SUCCESS;
    }
    for table in activitiescache_ez::TABLES {
        if data.missing_tables.contains(&table) {
            log.warning(&format!("{table} table does not exist!"));
            continue;
        }
        let count = match table {
            "ActivityOperation" => data.operations.len(),
            "Activity_PackageId" => data.package_ids.len(),
            _ => data.activities.len(),
        };
        log.info(&format!("{table} entries found: {}", n0(count as u64)));
    }
    for error in &data.table_errors {
        log.error(&format!("Error processing {error}"));
    }
    if !data.parse_errors.is_empty() {
        log.blank();
        log.warning("Values that could not be read (the rows are listed with the rest):");
        for error in &data.parse_errors {
            log.block(Level::Warning, &format!("  {error}"));
        }
    }

    let bad = Timestamp::check_format(&args.dt).is_err();
    let times = Times { format: if bad { args.dt.clone() } else { invariant_format(&args.dt) }, bad };
    if let Err(message) = write_all(&data, csv_dir, &stamp, &user, &times) {
        log.error(&format!("There was an error saving to '{csv_dir}': {message}"));
        log.blank();
        return ExitCode::FAILURE;
    }

    log.blank();
    log.info(&format!("Results saved to: {csv_dir}"));
    log.blank();
    log.info(&format!("Processing complete in {} seconds", number_n(start.elapsed().as_secs_f64(), 4)));
    log.blank();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariant_standard_formats() {
        let t = Times { format: invariant_format("G"), bad: false };
        assert_eq!(t.text(Some(1_646_000_000)), "02/27/2022 22:13:20");
        let t = Times { format: invariant_format(""), bad: false };
        assert_eq!(t.text(Some(1_646_000_000)), "02/27/2022 22:13:20 +00:00");
        let t = Times { format: invariant_format("yyyy-MM-dd HH:mm:ss"), bad: false };
        assert_eq!(Times { format: invariant_format("yyyy g 'g' %g"), bad: false }.text(Some(0x7fff)), "1970 A.D. g A.D.");
        assert_eq!(t.text(Some(activitiescache_ez::MIN_SECONDS)), "0001-01-01 00:00:00");
        assert_eq!(t.text(Some(activitiescache_ez::MAX_SECONDS)), "9999-12-31 23:59:59");
        assert_eq!(t.text(None), "");
    }

    #[test]
    fn spans() {
        assert_eq!(span(Some(65)), "00:01:05");
        assert_eq!(span(Some(-(11 * 86_400 + 13 * 3600 + 46 * 60 + 40))), "-11.13:46:40");
        assert_eq!(span(None), "");
    }
}
