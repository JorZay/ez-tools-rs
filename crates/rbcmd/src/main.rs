//! RBCmd: Windows Recycle Bin files to the console and CSV, with the original's options and output.

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_message, utc_now};
use ez_common::csv;
use ez_common::dotnet::{n0, number_n};
use ez_common::{Level, Timestamp};
use recyclebin_ez::{DollarI, Info2};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EMAIL: &str = "saericzimmerman@gmail.com";
const NEGATE_MIN: &str = "Negating the minimum value of a twos complement number is invalid.";

/// Reads Windows Recycle Bin files ($I and INFO2), with RBCmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  rbcmd -f /tmp/INFO2\n  rbcmd -f '/tmp/$I3VPA17' --csv /tmp/csvOutput\n  rbcmd -d /tmp --csv /tmp/csvOutput"
)]
struct Args {
    // an option with a value can only be given once, as in the original; a flag can be repeated
    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Only show the filename being processed vs all output. Useful to speed up exporting to JSON and/or CSV
    #[arg(short = 'q', overrides_with = "quiet", action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    quiet: bool,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// Show debug information during processing
    #[arg(long, overrides_with = "debug", action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, overrides_with = "trace", action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_RBCmd_<version>_ConsoleLog.txt in the --csv directory. Use --co false to turn it off
    #[arg(long, overrides_with = "co", action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

/// A row of the CSV
struct Row {
    source_name: String,
    file_type: &'static str,
    file_name: String,
    file_size: i64,
    deleted_on: String,
    removed: bool,
}

const COLUMNS: [&str; 6] = ["SourceName", "FileType", "FileName", "FileSize", "DeletedOn", "Removed"];

impl Row {
    fn line(&self) -> String {
        let mut out = String::new();
        for (i, value) in [
            self.source_name.as_str(),
            self.file_type,
            self.file_name.as_str(),
            &self.file_size.to_string(),
            self.deleted_on.as_str(),
            if self.removed { "True" } else { "False" },
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 {
                out.push(',');
            }
            csv::field(&mut out, value);
        }
        out.push_str(csv::NEW_LINE);
        out
    }
}

struct Run<'a> {
    log: Logger,
    quiet: bool,
    format: &'a str,
    rows: Vec<Row>,
    failed: Vec<String>,
    /// Files and folders that couldn't be read: exit code 1. Damaged files are only listed as failed
    unread: u32,
}

impl Run<'_> {
    fn info(&mut self, text: &str) {
        self.log.block(Level::Info, text);
    }

    /// A blank line, unless -q
    fn blank_unless_quiet(&mut self) {
        if !self.quiet {
            self.log.blank();
        }
    }

    fn time(&self, t: Timestamp) -> Result<String, String> {
        t.format_en_us(self.format).map_err(str::to_string)
    }

    fn process_file(&mut self, file: &str) {
        let raw = match std::fs::read(full_path(file)) {
            Ok(raw) => raw,
            Err(e) => {
                let message = read_error(file, &e);
                let text = if matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory) {
                    format!("Unable to access {file}. Are you running as an administrator? Error: {message}")
                } else {
                    format!("Unable to read {file}. Error: {message}")
                };
                self.log.block(Level::Error, &text);
                self.failed.push(file.to_string());
                self.unread += 1;
                return;
            }
        };
        // $I files start with a 64-bit format of 1 or 2, INFO2 files with a 32-bit version of 4 or 5
        let format = raw.first_chunk::<8>().map_or(-1, |b| i64::from_le_bytes(*b));
        let version = raw.first_chunk::<4>().map_or(-1, |b| i32::from_le_bytes(*b));
        let shown = if format == 1 || format == 2 {
            DollarI::parse(&raw, file).map(|di| self.show_dollar_i(&di).map(|()| di.parse_errors))
        } else if version == 4 || version == 5 {
            Info2::parse(&raw, file).map(|info| self.show_info2(&info).map(|()| info.parse_errors))
        } else {
            if raw.is_empty() {
                self.log.block(Level::Warning, &format!("{file} is empty"));
            } else {
                self.log.block(Level::Warning, &format!("Unknown header 0x{:X}! Send file to {EMAIL} so support can be added", raw[0]));
            }
            self.failed.push(file.to_string());
            Ok(Ok(Vec::new()))
        };
        match shown {
            Ok(Ok(parse_errors)) => {
                for parse_error in &parse_errors {
                    self.log.block(Level::Warning, &format!("{file}: {parse_error}"));
                }
                // a file that did not parse completely is still exported, and listed as a failed file
                if !parse_errors.is_empty() {
                    self.failed.push(format!("{file} did not parse completely"));
                }
                self.blank_unless_quiet();
            }
            Ok(Err(message)) => {
                self.failed.push(file.to_string());
                self.log.block(Level::Error, &format!("Error processing file {file} Please send it to {EMAIL}. Error: {message}"));
            }
            Err(e) => {
                self.log.block(Level::Error, &format!("Error processing file {file}: {} (offset 0x{:X}, field {})", e.message, e.offset, e.field));
                self.failed.push(file.to_string());
            }
        }
    }

    fn show_dollar_i(&mut self, di: &DollarI) -> Result<(), String> {
        let deleted_on = self.time(di.deleted_on)?;
        self.rows.push(Row {
            source_name: di.source_name.clone(),
            file_type: "$I",
            file_name: di.filename.clone(),
            file_size: di.file_size,
            deleted_on: deleted_on.clone(),
            removed: false,
        });
        for file in &di.directory_files {
            self.rows.push(Row {
                source_name: di.source_name.clone(),
                file_type: "$I",
                file_name: file.file_name.clone(),
                file_size: file.file_size,
                deleted_on: deleted_on.clone(),
                removed: false,
            });
        }
        if self.quiet {
            return Ok(());
        }
        self.info(&format!("Source file: {}", di.source_name));
        self.log.blank();
        let os = if di.format == 2 { "Windows 10/11" } else { "Pre-Windows 10" };
        self.info(&format!("Version: {} ({os})", di.format));
        self.info(&format!("File size: {} ({})", n0_signed(di.file_size), bytes_to_string(di.file_size)?));
        self.info(&format!("File name: {}", di.filename));
        self.info(&format!("Deleted on: {deleted_on}"));
        if !di.directory_files.is_empty() {
            self.log.blank();
            self.info(&format!("Subfiles in {}", di.filename));
        }
        for file in &di.directory_files {
            self.info(&format!("File name: {} Size: {} ({})", file.file_name, n0_signed(file.file_size), bytes_to_string(file.file_size)?));
        }
        Ok(())
    }

    fn show_info2(&mut self, info: &Info2) -> Result<(), String> {
        if !self.quiet {
            self.info(&format!("Source file: {}", info.source_name));
            self.log.blank();
            self.info(&format!("Version: {}", info.version));
            self.log.blank();
            self.info("File records");
        }
        for record in &info.file_records {
            let name = if record.file_name_unicode.is_empty() { &record.file_name_ascii } else { &record.file_name_unicode };
            let deleted_on = self.time(record.deleted_on)?;
            let size = i64::from(record.file_size);
            self.rows.push(Row {
                source_name: info.source_name.clone(),
                file_type: "INFO2",
                file_name: name.clone(),
                file_size: size,
                deleted_on: deleted_on.clone(),
                removed: record.removed,
            });
            if self.quiet {
                continue;
            }
            self.info(&format!("Index: {}", record.index));
            self.info(&format!("Drive #: {}", record.drive_number));
            self.info(&format!("File size: {} ({})", n0_signed(size), bytes_to_string(size)?));
            self.info(&format!("File name: {name}"));
            self.info(&format!("Deleted on: {deleted_on}"));
            if record.removed {
                self.info("Removed: no longer in the Recycle Bin (restored, or the Recycle Bin was emptied)");
            }
            self.log.blank();
        }
        Ok(())
    }
}

/// What the exception from File.ReadAllBytes says
fn read_error(file: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        let full = full_path(file);
        return format!("Could not find file '{full}'.");
    }
    let text = io_message(Path::new(&full_path(file)), e);
    text.rfind(" (os error").map_or_else(|| text.clone(), |end| text[..end].to_string())
}

/// {x:N0} of a value that can be negative
fn n0_signed(v: i64) -> String {
    if v < 0 { format!("-{}", n0(v.unsigned_abs())) } else { n0(v as u64) }
}

/// BytesToString: Math.Abs fails on the smallest long, Math.Round rounds halves to even
fn bytes_to_string(count: i64) -> Result<String, String> {
    const SUFFIXES: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    if count == 0 {
        return Ok("0B".to_string());
    }
    let bytes = count.checked_abs().ok_or(NEGATE_MIN)? as f64;
    let place = (bytes.ln() / 1024f64.ln()).floor() as i32;
    let num = (bytes / 1024f64.powi(place) * 10.0).round_ties_even() / 10.0;
    Ok(format!("{}{}", count.signum() as f64 * num, SUFFIXES[place as usize]))
}

/// GetRecycleBinFiles: `$I*` and INFO2 files (case-sensitive) under a folder, the folder's entries in the order the file
/// system gives them, then the folders found, in turn; the `$I` files come before the INFO2 files. Links to folders aren't
/// followed. Also the folders that couldn't be read
fn recycle_bin_files(given: &str) -> (Vec<String>, Vec<(String, String)>) {
    let full = full_path(given);
    let root = if full.len() > 1 { full.trim_end_matches('/').to_string() } else { full };
    let mut queue = VecDeque::from([root.clone()]);
    let (mut files, mut infos, mut unreadable) = (Vec::new(), Vec::new(), Vec::new());
    while let Some(folder) = queue.pop_front() {
        let entries = match std::fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(e) => {
                let text = e.to_string();
                let reason = text.rfind(" (os error").map_or(text.clone(), |end| text[..end].to_string());
                unreadable.push((if folder == root { given.to_string() } else { folder }, reason));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let text = path.to_string_lossy().into_owned();
            if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
                    queue.push_back(text);
                }
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "INFO2" {
                infos.push(text);
            } else if name.starts_with("$I") {
                files.push(text);
            }
        }
    }
    files.append(&mut infos);
    (files, unreadable)
}

fn write_csv(path: &str, rows: &[Row]) -> std::io::Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
    out.write_all(COLUMNS.join(",").as_bytes())?;
    out.write_all(csv::NEW_LINE.as_bytes())?;
    for row in rows {
        out.write_all(row.line().as_bytes())?;
    }
    out.flush()
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

fn export(run: &mut Run, csv: &str, csvf: Option<&str>, stamp: &str) -> Result<(), ()> {
    let full = full_path(csv);
    if !Path::new(&full).is_dir() {
        run.info(&format!("{csv} does not exist. Creating..."));
        if let Err(e) = std::fs::create_dir_all(&full) {
            let message = io_message(Path::new(&full), &e);
            run.log.block(Level::Error, &format!("Unable to create {csv}. CSV export canceled. Error: {message}"));
            return Err(());
        }
    }
    let name = csvf.map_or_else(|| format!("{stamp}_RBCmd_Output.csv"), |f| f.rsplit('/').next().unwrap_or(f).to_string());
    let combined = if name.is_empty() { csv.to_string() } else { Path::new(csv).join(&name).to_string_lossy().into_owned() };
    let out_file = full_path(&combined);
    run.log.block(Level::Warning, &format!("CSV output will be saved to {out_file}"));
    if let Err(e) = write_csv(&out_file, &run.rows) {
        let message = io_message(Path::new(&out_file), &e);
        run.log.block(Level::Error, &format!("Unable to open {out_file} for writing. CSV export canceled. Error: {message}"));
        return Err(());
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
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &args.dt).to_stdout();
    let stamp = utc_now().format("yyyyMMddHHmmss");
    // the log file also creates the --csv folder, whatever happens next
    let console_log = args
        .csv
        .as_deref()
        .filter(|d| args.co && !d.trim().is_empty())
        .map(|d| Path::new(&full_path(d)).join(format!("{stamp}_RBCmd_{VERSION}_ConsoleLog.txt")));
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
        return ExitCode::FAILURE;
    }
    if let Some(f) = file {
        // File.Exists: true for a link to nothing, false for a folder
        let full = full_path(f);
        let exists = std::fs::metadata(&full).map_or_else(|_| std::fs::symlink_metadata(&full).is_ok(), |m| !m.is_dir());
        if !exists {
            log.block(Level::Warning, &format!("File {f} not found. Exiting"));
            return ExitCode::FAILURE;
        }
    }
    if let Some(d) = directory {
        if !Path::new(&full_path(d)).is_dir() {
            log.block(Level::Warning, &format!("Directory {d} not found. Exiting"));
            return ExitCode::FAILURE;
        }
    }

    log.info(&format!("RBCmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.block(Level::Info, &format!("Command line: {}", command_line.join(" ")));
    if let Some(path) = &console_log {
        log.block(Level::Info, &format!("Console log: {}", path.display()));
    }

    let mut run = Run { log, quiet: args.quiet, format: &args.dt, rows: Vec::new(), failed: Vec::new(), unread: 0 };
    let start = Instant::now();
    let files = if let Some(f) = file {
        vec![f.to_string()]
    } else {
        let d = directory.unwrap_or_default();
        run.log.blank();
        run.info(&format!("Looking for files in {d}"));
        run.blank_unless_quiet();
        let (files, unreadable) = recycle_bin_files(d);
        for (folder, reason) in unreadable {
            run.log.block(Level::Error, &format!("Unable to read folder {folder}: {reason}"));
            run.unread += 1;
        }
        files
    };
    run.info(&format!("Found {} files. Processing...", n0(files.len() as u64)));
    run.blank_unless_quiet();
    for path in &files {
        run.process_file(path);
    }
    let elapsed = start.elapsed().as_secs_f64();

    run.log.blank();
    run.info(&format!(
        "Processed {} out of {} files in {} seconds",
        n0_signed(files.len() as i64 - run.failed.len() as i64),
        n0(files.len() as u64),
        number_n(elapsed, 4)
    ));
    run.log.blank();
    if !run.failed.is_empty() {
        run.log.blank();
        run.info("Failed files");
        for failed in std::mem::take(&mut run.failed) {
            run.info(&format!("  {failed}"));
        }
    }
    if let Some(csv) = given(&args.csv).filter(|_| !files.is_empty()) {
        if export(&mut run, csv, given(&args.csvf), &stamp).is_err() {
            return ExitCode::FAILURE;
        }
    }
    if run.unread > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_as_text() {
        let text = |v| bytes_to_string(v).unwrap();
        assert_eq!(text(0), "0B");
        assert_eq!(text(1023), "1023B");
        assert_eq!(text(1024), "1KB");
        assert_eq!(text(1536), "1.5KB");
        assert_eq!(text(-1536), "-1.5KB");
        assert_eq!(text(1_048_575), "1024KB");
        assert_eq!(text(i64::MAX), "8EB");
        assert_eq!(bytes_to_string(i64::MIN), Err(NEGATE_MIN.to_string()));
    }
}
