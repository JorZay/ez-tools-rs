//! AppCompatCacheParser: the AppCompatCache (ShimCache) of a SYSTEM hive to CSV, with the original's options and output.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use appcompatcache_ez::{AppCompatCache, CacheEntry, Error, ErrorKind};
use clap::{ArgAction, CommandFactory, Parser};
use ez_common::Level;
use ez_common::cli::log::Logger;
use ez_common::cli::utc_now;
use ez_common::dotnet::n0;
use ez_common::net::path_extension;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COLUMNS: [&str; 8] = ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed", "Duplicate", "SourceFile", "FromSlack"];

/// Parses the AppCompatCache (ShimCache) of a SYSTEM hive to CSV, with AppCompatCacheParser's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  appcompatcacheparser -f /cases/host1/SYSTEM --csv /tmp/out -t -c 2\n  appcompatcacheparser -f /cases/host1/SYSTEM --csv /tmp/out --csvf results.csv"
)]
struct Args {
    /// Full path to SYSTEM hive to process. The live Registry isn't available on this system, so this is needed
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// The ControlSet to parse. Default is to extract all control sets
    #[arg(short = 'c', default_value_t = -1, allow_negative_numbers = true, value_name = "NUMBER")]
    control_set: i32,

    /// Sorts last modified timestamps in descending order
    #[arg(short = 't', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    sort: bool,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// When true, ignore transaction log files for dirty hives
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nl: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_AppCompatCacheParser_<version>_ConsoleLog.txt in the --csv
    /// directory. Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// What the exception .NET throws says for a path that can't be created or written
fn io_error(path: &Path, e: &std::io::Error) -> Error {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let message = match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => format!("Access to the path '{}' is denied.", full.display()),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => format!("Could not find a part of the path '{}'.", full.display()),
        std::io::ErrorKind::AlreadyExists => format!("The file '{}' already exists.", full.display()),
        _ => e.to_string(),
    };
    Error { message, kind: ErrorKind::CouldNotProcess }
}

/// Path.GetFullPath: `.` and `..` are resolved, and a separator at the end is kept
fn full_path(p: &str) -> String {
    use std::path::Component;
    let abs = std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p));
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    let mut text = out.to_string_lossy().into_owned();
    if p.ends_with('/') && !text.ends_with('/') {
        text.push('/');
    }
    text
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Path.GetFileNameWithoutExtension
fn stem(p: &str) -> &str {
    let name = base_name(p);
    let extension = path_extension(name);
    let without = &name[..name.len() - extension.len()];
    without.strip_suffix('.').filter(|_| extension.is_empty()).unwrap_or(without)
}

/// -t: newest last modified time first (entries without one last), and otherwise in the cache's order
fn sorted(entries: &[CacheEntry], sort: bool) -> Vec<&CacheEntry> {
    let mut list: Vec<&CacheEntry> = entries.iter().collect();
    if sort {
        list.sort_by(|a, b| b.last_modified_time_utc.cmp(&a.last_modified_time_utc));
    }
    list
}

fn add_field(line: &mut String, first: bool, text: &str) {
    if !first {
        line.push(',');
    }
    ez_common::csv::field(line, text);
}

/// Everything after the hive is opened
fn write_results(am: &AppCompatCache, args: &Args, file: &str, csv: &str, stamp: &str, log: &mut Logger) -> Result<(), Error> {
    let os = am.operating_system.name();
    let default_name = if args.control_set >= 0 {
        format!("{stamp}_{os}_{}_ControlSet00{}_AppCompatCache.csv", stem(file), args.control_set)
    } else {
        format!("{stamp}_{os}_{}_AppCompatCache.csv", stem(file))
    };
    let name = given(&args.csvf).map_or(default_name, |f| base_name(f).to_string());
    if !Path::new(csv).is_dir() {
        std::fs::create_dir_all(csv).map_err(|e| io_error(Path::new(csv), &e))?;
    }
    let out_file = Path::new(csv).join(name);
    log.debug(&format!("**** Found {} caches", am.caches.len()));

    if am.caches.is_empty() {
        log.blank();
        log.warning("No caches were found!");
        log.blank();
        return Ok(());
    }

    let file_handle = File::create(&out_file).map_err(|e| io_error(&out_file, &e))?;
    let mut out = BufWriter::new(file_handle);
    let mut line = COLUMNS.join(",");
    line.push_str(ez_common::csv::NEW_LINE);
    let mut keys = HashSet::new();

    for cache in &am.caches {
        let control_set = format!("ControlSet00{}", cache.control_set);
        log.info(&format!("Found {} cache entries for {os} in {control_set}", n0(cache.entries.len() as u64)));
        for error in &cache.parse_errors {
            log.warning(&format!("ControlSet00{}: {error}", cache.control_set));
        }
        if !cache.slack_entries.is_empty() {
            log.info(&format!("Recovered {} entries that are no longer in the cache from its value's slack in {control_set}", n0(cache.slack_entries.len() as u64)));
        }
        // entries from slack come after the cache's, in the same order
        for entry in sorted(&cache.entries, args.sort).into_iter().chain(sorted(&cache.slack_entries, args.sort)) {
            // a --dt that .NET rejects: what's whole so far stays, the row it fails on doesn't
            if entry.last_modified_time_utc.is_some() && ez_common::Timestamp::check_format(&args.dt).is_err() {
                out.write_all(line.as_bytes()).and_then(|()| out.flush()).map_err(|e| io_error(&out_file, &e))?;
                return Err(Error { message: ez_common::csv::WRITER_ERROR.to_string(), kind: ErrorKind::Other });
            }
            let key = entry.key();
            let duplicate = keys.contains(&key);
            keys.insert(key);
            add_field(&mut line, true, &entry.control_set.to_string());
            add_field(&mut line, false, &entry.cache_entry_position.to_string());
            add_field(&mut line, false, &entry.path);
            add_field(&mut line, false, &entry.last_modified_time_utc.map(|t| t.format(&args.dt)).unwrap_or_default());
            add_field(&mut line, false, entry.executed.name());
            add_field(&mut line, false, if duplicate { "True" } else { "False" });
            add_field(&mut line, false, file);
            add_field(&mut line, false, if entry.from_slack { "True" } else { "False" });
            line.push_str(ez_common::csv::NEW_LINE);
        }
        out.write_all(line.as_bytes()).map_err(|e| io_error(&out_file, &e))?;
        line.clear();
    }
    out.flush().map_err(|e| io_error(&out_file, &e))?;
    drop(out);

    log.blank();
    log.warning(&format!("Results saved to '{}'", out_file.display()));
    log.blank();
    Ok(())
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

    // one UTC time per run, for the CSV name and the console log
    let stamp = utc_now().format("yyyyMMddHHmmss");
    let csv_for_log = args.csv.as_deref().filter(|c| !c.trim().is_empty());
    let console_log = csv_for_log.filter(|_| args.co).map(|c| Path::new(&full_path(c)).join(format!("{stamp}_AppCompatCacheParser_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        // as the original's log file: it isn't an error if it can't be made
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }

    let Some(csv) = given(&args.csv) else {
        let _ = Args::command().print_long_help();
        println!();
        log.warning("--csv is required. Exiting");
        return ExitCode::FAILURE;
    };
    let Some(file) = given(&args.file) else {
        log.fatal("Live Registry support is not available on non-Windows systems");
        return ExitCode::FAILURE;
    };
    if !Path::new(file).is_file() {
        log.warning(&format!("'{file}' not found. Exiting"));
        return ExitCode::FAILURE;
    }

    log.info(&format!("AppCompatCacheParser (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }
    log.info(&format!("Processing hive '{file}'"));
    log.blank();

    let result = AppCompatCache::open(file, args.control_set, args.nl, &mut |l, m| log.log(l, m)).and_then(|am| write_results(&am, &args, file, csv, &stamp, &mut log));
    let Err(e) = result else { return ExitCode::SUCCESS };

    if !e.message.contains("Sequence numbers do not match and transaction logs were not found in the same direct") {
        log.blank();
        if e.message.contains("Could not find ControlSet") {
            log.fatal(&format!("{}. Exiting", e.message));
        } else if e.kind == ErrorKind::Parse {
            log.error(&e.message);
        } else {
            log.error(&format!("There was an error: {}", e.message));
        }
        log.blank();
    }
    // 1 when the tool fails: a hive that could not be accessed or read, a dirty hive without its logs, a -c ControlSet that
    // is not there, or output that can't be written. A damaged hive or cache is 0
    if e.kind == ErrorKind::CouldNotProcess { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
