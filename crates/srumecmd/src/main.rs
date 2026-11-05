//! SrumECmd: SRUM databases (SRUDB.dat) to CSV, with the original's options and columns. The original only runs on Windows, as it
//! reads with esent.dll; this reads the file itself, in place, and never writes next to it. See docs/plans/srumecmd.md.

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_exception, io_message, utc_now};
use ez_common::dotnet::{n0, number_n, upper_invariant};
use ez_common::{Level, Timestamp};
use srum_ez::{Cell, Observer, Sheet, Srum, span_text};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reads SRUM databases, with SrumECmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    args_override_self = true,
    after_help = "Examples:\n  srumecmd -f /tmp/SRUDB.dat -r /tmp/SOFTWARE --csv /tmp/out\n  srumecmd -f /tmp/SRUDB.dat --csv /tmp/out\n  srumecmd -d /cases/host1 --csv /tmp/out"
)]
struct Args {
    /// SRUDB.dat file to parse
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// SOFTWARE hive to process. This is optional, but recommended
    #[arg(short = 'r', value_name = "FILE")]
    registry: Option<String>,

    /// Directory to recursively process, looking for SRUDB.dat and SOFTWARE hive. This mode is primarily used with KAPE so both
    /// SRUDB.dat and SOFTWARE hive can be located
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// Accepted for the original's command lines. This port needs no temporary copy: it reads the database in place, without writing
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_SrumECmd_<version>_ConsoleLog.txt in the --csv directory. Use --co false to
    /// turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// The first non-empty file with this name under a folder, as the Windows build finds it: a folder's entries in name order, then
/// its subfolders', not going through links. And the folders that can't be read
fn find_first(directory: &str, wanted: &str) -> (Option<String>, Vec<(String, String)>) {
    let mut queue = VecDeque::from([directory.to_string()]);
    let mut unreadable = Vec::new();
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
        let mut names: Vec<_> = entries.flatten().collect();
        names.sort_by_cached_key(|e| upper_invariant(&e.file_name().to_string_lossy()));
        for entry in names {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                queue.push_back(path.to_string_lossy().into_owned());
            } else if kind.is_file() && upper_invariant(&entry.file_name().to_string_lossy()) == wanted && std::fs::metadata(&path).is_ok_and(|m| m.len() > 0) {
                return (Some(path.to_string_lossy().into_owned()), unreadable);
            }
        }
    }
    (None, unreadable)
}

fn cell_text(cell: &Cell, format: &str) -> String {
    match cell {
        Cell::Int(v) => v.to_string(),
        Cell::OptInt(v) => v.map_or_else(String::new, |v| v.to_string()),
        Cell::Text(t) => t.clone().unwrap_or_default(),
        Cell::Time(t) => t.format(format),
        Cell::OptTime(t) => t.map_or_else(String::new, |t: Timestamp| t.format(format)),
        // CsvHelper's default, with the invariant culture: these are always at offset 0
        Cell::Default(t) => t.map_or_else(String::new, |t: Timestamp| format!("{} +00:00", t.format("MM/dd/yyyy HH:mm:ss"))),
        Cell::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
        Cell::Span(ticks) => span_text(*ticks),
    }
}

fn csv_line(fields: impl Iterator<Item = String>) -> String {
    let mut line = String::new();
    for (i, field) in fields.enumerate() {
        if i > 0 {
            line.push(',');
        }
        ez_common::csv::field(&mut line, &field);
    }
    line.push_str(ez_common::csv::NEW_LINE);
    line
}

/// ExportCsv: one CSV, with a byte order mark
fn export(sheet: &Sheet, folder: &str, stamp: &str, format: &str) -> std::io::Result<()> {
    let path = Path::new(folder).join(format!("{stamp}_SrumECmd_{}_Output.csv", sheet.name));
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    out.write_all(ez_common::cli::BOM)?;
    out.write_all(csv_line(sheet.columns.iter().map(|c| (*c).to_string())).as_bytes())?;
    for row in &sheet.rows {
        out.write_all(csv_line(row.iter().map(|c| cell_text(c, format))).as_bytes())?;
    }
    out.flush()
}

struct LogObserver<'a>(&'a mut Logger);

impl Observer for LogObserver<'_> {
    fn warning(&mut self, message: &str) {
        self.0.block(Level::Warning, message);
    }
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    ExitCode::FAILURE
}

/// A file exists, as File.Exists says
fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).map_or_else(|_| std::fs::symlink_metadata(path).is_ok(), |m| !m.is_dir())
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::FAILURE } else { ExitCode::SUCCESS };
        }
    };
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &args.dt).to_stdout();
    let stamp = utc_now().format("yyyyMMddHHmmss");
    let console_log = given(&args.csv).filter(|_| args.co).map(|d| Path::new(&full_path(d)).join(format!("{stamp}_SrumECmd_{VERSION}_ConsoleLog.txt")));
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
        if !file_exists(f) {
            log.warning(&format!("File '{f}' not found. Exiting"));
            return ExitCode::FAILURE;
        }
    }
    if let Some(d) = directory {
        if !Path::new(d).is_dir() {
            log.warning(&format!("Directory '{d}' not found. Exiting"));
            return ExitCode::FAILURE;
        }
    }
    if let Some(r) = given(&args.registry) {
        if !file_exists(r) {
            log.warning(&format!("SOFTWARE hive '{r}' not found. Exiting"));
            return ExitCode::FAILURE;
        }
    }
    let Some(csv) = given(&args.csv) else {
        return help_and_warning(&mut log, "--csv is required. Exiting");
    };

    log.info(&format!("SrumECmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let start = Instant::now();
    let mut search_errors = 0u64;
    let mut database = file.map(str::to_string);
    let mut hive = given(&args.registry).map(str::to_string);
    if let Some(d) = directory {
        let mut reported = HashSet::new();
        let mut report = |log: &mut Logger, unreadable: Vec<(String, String)>| {
            for (folder, reason) in unreadable {
                if reported.insert(folder.clone()) {
                    log.error(&format!("Unable to read folder {folder}: {reason}"));
                    search_errors += 1;
                }
            }
        };
        let (found, unreadable) = find_first(d, "SRUDB.DAT");
        report(&mut log, unreadable);
        let Some(found) = found else {
            log.warning("Did not locate any files named 'SRUDB.dat'! Exiting");
            if search_errors > 0 {
                log.error(&format!("Could not access all files in '{d}': {} folder(s) could not be read", n0(search_errors)));
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        };
        match ese_ez::read_header(&found) {
            Ok(h) => log.info(&format!("Found SRUM database file '{found}' (State: {}, Format Version: 0x{:x},{})", h.state, h.format_version, h.format_revision)),
            Err(_) => log.info(&format!("Found SRUM database file '{found}'")),
        }
        database = Some(found);
        let (found, unreadable) = find_first(d, "SOFTWARE");
        report(&mut log, unreadable);
        match &found {
            None => log.warning("Did not locate any files named 'SOFTWARE'! Registry data will not be extracted"),
            Some(r) => log.info(&format!("Found SOFTWARE hive '{r}'!")),
        }
        hive = found;
        if search_errors > 0 {
            log.error(&format!("Could not access all files in '{d}': {} folder(s) could not be read", n0(search_errors)));
        }
        log.blank();
    }
    let database = database.unwrap_or_default();

    log.info(&format!("Processing '{database}'..."));
    let read = Srum::read(&database, hive.as_deref(), &mut LogObserver(&mut log));
    let srum = match read {
        Ok(s) => s,
        Err(e) => {
            log.block(Level::Error, &format!("Error processing file! Message: {}.\n\nThe database is probably damaged. This port reads it as it is, and can't repair a copy as the original does with esentutl.exe\n{}: {}", e.message, e.exception, e.message));
            log.blank();
            return if e.read_error || search_errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS };
        }
    };
    log.blank();
    log.info("Processing complete!");
    log.blank();
    for (label, count) in [
        ("Energy Usage count:", srum.energy.rows.len()),
        ("AppTimelineProvider count:", srum.timeline.rows.len()),
        ("vfuprov count:", srum.vfuprov.rows.len()),
        ("App Resource Usage count:", srum.app_resource.rows.len()),
        ("Network Connection count:", srum.connections.rows.len()),
        ("Network Usage count:", srum.usage.rows.len()),
        ("Push Notification count:", srum.push.rows.len()),
    ] {
        log.info(&format!("{label:<30} {}", n0(count as u64)));
    }
    for (label, count) in [
        ("ProcessorTime count:", srum.processor_time.rows.len()),
        ("SizeInBytes count:", srum.size_in_bytes.rows.len()),
        ("TotalUsed count:", srum.total_used.rows.len()),
        ("NetworkBytes count:", srum.network_bytes.rows.len()),
    ] {
        if count > 0 {
            log.info(&format!("{label:<30} {}", n0(count as u64)));
        }
    }
    log.blank();

    if !Path::new(csv).is_dir() {
        log.info(&format!("Path to '{csv}' doesn't exist. Creating..."));
        if std::fs::create_dir_all(csv).is_err() {
            log.fatal(&format!("Unable to create directory '{csv}'. Does a file with the same name exist? Exiting"));
            return ExitCode::FAILURE;
        }
    }
    log.info(&format!("CSV output will be saved to '{csv}'"));
    log.blank();

    let mut export_failed = false;
    for (i, sheet) in srum.sheets().into_iter().enumerate() {
        // the first seven always; the providers seen on Server 2022 only with rows
        if i >= 7 && sheet.rows.is_empty() {
            continue;
        }
        log.debug(&format!("Dumping {} table '{}'", sheet.name, sheet.table_name));
        if let Err(e) = export(sheet, csv, &stamp, &args.dt) {
            export_failed = true;
            let message = io_message(Path::new(csv), &e);
            log.block(Level::Error, &format!("Error exporting '{}' data! Error: {message}\n{}: {message}", sheet.name, io_exception(&e)));
        }
    }

    if !srum.parse_errors.is_empty() {
        log.warning(&format!("{} problem(s) found while reading the database (everything else was exported):", n0(srum.parse_errors.len() as u64)));
        for error in srum.parse_errors.iter().take(50) {
            log.block(Level::Warning, &format!("\t{error}"));
        }
        if srum.parse_errors.len() > 50 {
            log.warning(&format!("\t... and {} more (use --debug to see them all as they happen)", n0(srum.parse_errors.len() as u64 - 50)));
        }
        log.blank();
    }
    if srum.software_hive_not_accessed {
        log.error(&format!("Unable to read SOFTWARE hive '{}': user and network profile names are missing (see above)", hive.as_deref().unwrap_or_default()));
        log.blank();
    }
    log.info(&format!("Processing completed in {} seconds", number_n(start.elapsed().as_secs_f64(), 4)));
    log.blank();
    if export_failed || search_errors > 0 || srum.software_hive_not_accessed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
