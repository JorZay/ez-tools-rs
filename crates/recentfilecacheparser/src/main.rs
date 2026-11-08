//! RecentFileCacheParser: RecentFileCache.bcf files to the console, CSV and JSON, with the original's options and output.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_message, utc_now};
use ez_common::dotnet::number_n;
use ez_common::{Level, Timestamp, csv};
use recentfilecache_ez::RecentFileCacheFile;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DATE_FORMAT: &str = "yyyy-MM-dd HH:mm:ss";
const COLUMNS: [&str; 5] = ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "Filename"];

/// Reads RecentFileCache.bcf files (Windows 7 and Server 2008 R2), with RecentFileCacheParser's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  recentfilecacheparser -f /tmp/RecentFileCache.bcf --csv /tmp/out\n  recentfilecacheparser -f /tmp/RecentFileCache.bcf --json /tmp/jsonOutput --pretty"
)]
struct Args {
    /// File to process. Required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// Directory to save json representation to. Use --pretty for a more human readable layout
    #[arg(long, value_name = "DIR")]
    json: Option<String>,

    /// When exporting to json, use a more human readable layout
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    pretty: bool,

    /// Only show the filename being processed vs all output. Useful to speed up exporting to JSON and/or CSV
    #[arg(short = 'q', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    quiet: bool,

    /// When true, save all console messages to <timestamp>_RecentFileCacheParser_<version>_ConsoleLog.txt in the output directory (the first of --csv, --json given). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// Path.GetFileName
fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Path.Combine, for a name that isn't rooted
fn combine(folder: &str, name: &str) -> String {
    if name.is_empty() { folder.to_string() } else { Path::new(folder).join(name).to_string_lossy().into_owned() }
}

fn time(t: Timestamp) -> String {
    t.format(DATE_FORMAT)
}

/// The CSV: a row per file name, with the source file's
fn csv_text(rfc: &RecentFileCacheFile) -> String {
    let mut out = COLUMNS.join(",");
    out.push_str(csv::NEW_LINE);
    let source = [rfc.source_file.clone(), time(rfc.source.created), time(rfc.source.modified), time(rfc.source.accessed)];
    for name in &rfc.file_names {
        for (i, value) in source.iter().map(String::as_str).chain([name.as_str()]).enumerate() {
            if i > 0 {
                out.push(',');
            }
            csv::field(&mut out, value);
        }
        out.push_str(csv::NEW_LINE);
    }
    out
}

/// Directory.CreateDirectory, when the folder isn't there, with the message the original logs
fn ensure_folder(log: &mut Logger, folder: &str) -> Result<(), String> {
    let full = full_path(folder);
    if Path::new(&full).is_dir() {
        return Ok(());
    }
    log.block(Level::Info, &format!("{folder} does not exist. Creating..."));
    std::fs::create_dir_all(&full).map_err(|e| io_message(Path::new(&full), &e))
}

fn save_csv(log: &mut Logger, rfc: &RecentFileCacheFile, folder: &str, csvf: Option<&str>, stamp: &str) -> bool {
    let name = csvf.map_or_else(|| format!("{stamp}_RecentFileCacheParser_Output.csv"), |f| base_name(f).to_string());
    let out_file = combine(folder, &name);
    let result = ensure_folder(log, folder).and_then(|()| {
        let full = full_path(&out_file);
        log.block(Level::Info, &format!("CSV output will be saved to {full}"));
        std::fs::File::create(&full).and_then(|mut f| f.write_all(csv_text(rfc).as_bytes())).map_err(|e| io_message(Path::new(&full), &e))
    });
    match result {
        Ok(()) => true,
        Err(message) => {
            log.block(Level::Error, &format!("Unable to save CSV to {out_file}. Export canceled. Error: {message}"));
            false
        }
    }
}

fn save_json(log: &mut Logger, rfc: &RecentFileCacheFile, pretty: bool, folder: &str, stamp: &str) -> bool {
    let result = ensure_folder(log, folder).and_then(|()| {
        log.block(Level::Info, &format!("Saving json output to {folder}"));
        let out_file = full_path(&combine(folder, &format!("{stamp}_{}.json", base_name(&rfc.source_file))));
        let value = rfc.to_value();
        let text = if pretty { value.dump() } else { value.to_json() };
        std::fs::write(&out_file, text).map_err(|e| io_message(Path::new(&out_file), &e))
    });
    match result {
        Ok(()) => true,
        Err(message) => {
            log.block(Level::Error, &format!("Error exporting json for {}. Error: {message}", rfc.source_file));
            false
        }
    }
}

/// What File.ReadAllBytes's exception says
fn read_error(file: &str, e: &std::io::Error) -> String {
    let full = full_path(file);
    let text = if e.kind() == std::io::ErrorKind::NotFound { format!("Could not find file '{full}'.") } else { io_message(Path::new(&full), e) };
    text.rfind(" (os error").map_or_else(|| text.clone(), |end| text[..end].to_string())
}

fn main() -> ExitCode {
    let args = match ez_common::cli::parse_args::<Args>() {
        Ok(a) => a,
        Err(code) => return code,
    };
    let mut log = Logger::new(Level::Info, DATE_FORMAT).to_stdout();
    let stamp = utc_now().format("yyyyMMddHHmmss");
    // the log file goes to the first output folder given, which it creates
    let console_log = [args.csv.as_deref(), args.json.as_deref()]
        .into_iter()
        .flatten()
        .find(|d| !d.trim().is_empty())
        .filter(|_| args.co)
        .map(|d| Path::new(&full_path(d)).join(format!("{stamp}_RecentFileCacheParser_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }

    let Some(f) = given(&args.file) else {
        let _ = Args::command().print_long_help();
        log.block(Level::Warning, "-f is required. Exiting");
        log.blank();
        return ExitCode::FAILURE;
    };
    // File.Exists: true for a link to nothing, false for a folder
    let full = full_path(f);
    if !std::fs::metadata(&full).map_or_else(|_| std::fs::symlink_metadata(&full).is_ok(), |m| !m.is_dir()) {
        log.block(Level::Warning, &format!("File {f} not found. Exiting"));
        log.blank();
        return ExitCode::FAILURE;
    }

    log.block(Level::Info, &format!("RecentFileCacheParser (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.block(Level::Info, &format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.block(Level::Info, &format!("Console log: {}", path.display()));
        log.blank();
    }

    let quiet = args.quiet;
    if !quiet {
        log.block(Level::Warning, &format!("Processing {f}"));
        log.blank();
    }
    let start = Instant::now();
    let rfc = match RecentFileCacheFile::load(f) {
        Ok(rfc) => rfc,
        Err(Ok(e)) => {
            let message = read_error(f, &e);
            let text = if matches!(e.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory) {
                format!("Unable to access {f}. Are you running as an administrator? Error: {message}")
            } else {
                format!("Unable to read {f}. Error: {message}")
            };
            log.block(Level::Error, &text);
            return ExitCode::FAILURE;
        }
        Err(Err(e)) => {
            // not a RecentFileCache.bcf: a bad file, not a failure of the tool
            log.block(Level::Error, &format!("Error processing file {f}: {} (offset 0x{:X}, field {})", e.message, e.offset, e.field));
            return ExitCode::SUCCESS;
        }
    };
    if !quiet {
        log.block(Level::Info, &format!("Source file: {}", rfc.source_file));
        log.block(Level::Info, &format!("  Source created:  {}", time(rfc.source.created)));
        log.block(Level::Info, &format!("  Source modified: {}", time(rfc.source.modified)));
        log.block(Level::Info, &format!("  Source accessed: {}", time(rfc.source.accessed)));
        log.blank();
        log.block(Level::Info, &format!("Checksum: 0x{:08X} ({})", rfc.checksum, if rfc.checksum_valid() { "valid" } else { "INVALID" }));
        log.blank();
        log.block(Level::Info, "File names");
        for name in &rfc.file_names {
            log.block(Level::Info, name);
        }
        log.blank();
    }
    if rfc.parsing_error() {
        log.block(Level::Warning, "Problems found while parsing:");
        for problem in &rfc.parse_errors {
            log.block(Level::Warning, &format!("  {problem}"));
        }
        log.blank();
    }
    if quiet {
        log.blank();
    }
    log.block(Level::Info, &format!("---------- Processed {} in {} seconds ----------", rfc.source_file, number_n(start.elapsed().as_secs_f64(), 8)));
    if !quiet {
        log.blank();
    }

    // a file that did not parse completely is still exported: 1 only when an export fails
    let mut ok = true;
    if let Some(folder) = given(&args.csv) {
        ok &= save_csv(&mut log, &rfc, folder, given(&args.csvf), &stamp);
    }
    if let Some(folder) = given(&args.json) {
        ok &= save_json(&mut log, &rfc, args.pretty, folder, &stamp);
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recentfilecache_ez::SourceTimes;

    #[test]
    fn csv_rows_are_quoted_as_csvhelper_does() {
        let mut raw = vec![0xFE, 0xFF, 0xEE, 0xFF];
        raw.resize(20, 0);
        for name in ["a,b", "say \"hi\""] {
            let units: Vec<u16> = name.encode_utf16().collect();
            raw.extend_from_slice(&(units.len() as u32).to_le_bytes());
            units.iter().for_each(|u| raw.extend_from_slice(&u.to_le_bytes()));
            raw.extend_from_slice(&[0, 0]);
        }
        let times = SourceTimes { created: Timestamp(637_134_336_000_000_000), ..SourceTimes::default() };
        let rfc = RecentFileCacheFile::parse(&raw, "/x/r.bcf", times).unwrap();
        assert_eq!(
            csv_text(&rfc),
            "SourceFile,SourceCreated,SourceModified,SourceAccessed,Filename\r\n\
             /x/r.bcf,2020-01-01 00:00:00,0001-01-01 00:00:00,0001-01-01 00:00:00,\"a,b\"\r\n\
             /x/r.bcf,2020-01-01 00:00:00,0001-01-01 00:00:00,0001-01-01 00:00:00,\"say \"\"hi\"\"\"\r\n"
        );
    }
}
