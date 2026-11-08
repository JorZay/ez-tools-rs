//! pecmd: Windows Prefetch files shown on the console and exported to CSV (with a time line), JSON and XHTML, as PECmd
//! does it. --vss and --ads are Windows only in the original too.

mod xhtml;

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, Parser};
use ez_common::Level;
use ez_common::cli::log::Logger;
use ez_common::dotnet::{lower_invariant, n0, number_n};
use ez_common::json::ServiceStackObject;
use ez_common::net::path_extension;
use ez_common::time::Timestamp;
use prefetch_ez::{Error, Prefetch, Version, executable_path};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PRECISE_TIME_FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";
/// JSON time stamps: ISO 8601 in UTC
const JSON_DATE_FORMAT: &str = "yyyy-MM-ddTHH:mm:ss.fffffffZ";
/// The message of the exception .NET throws where the file has no header
const NO_HEADER: &str = "Object reference not set to an instance of an object.";

/// Parses Windows Prefetch files and shows or exports them (CSV, JSON, XHTML), with PECmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  pecmd -f /tmp/CALC.EXE-3FBEF7FD.pf\n  pecmd -f /tmp/CALC.EXE-3FBEF7FD.pf --json /tmp/json\n  pecmd -d /cases/Prefetch -k 'system32, fonts'\n  pecmd -d /cases/Prefetch --csv /tmp/out --csvf foo.csv --json /tmp/json"
)]
struct Args {
    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    dir: Option<String>,

    /// Comma separated list of keywords to highlight in output. By default, 'temp' and 'tmp' are highlighted. Any
    /// additional keywords will be added to these
    #[arg(short = 'k', value_name = "KEYWORDS")]
    keywords: Option<String>,

    /// When specified, save prefetch file bytes to the given path. Useful to look at decompressed Win10 files
    #[arg(short = 'o', value_name = "PATH")]
    save: Option<String>,

    /// Do not dump full details about each file processed. Speeds up processing when using --json or --csv
    #[arg(short = 'q', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    quiet: bool,

    /// Directory to save CSV formatted results to
    #[arg(long)]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long)]
    csvf: Option<String>,

    /// Directory to save JSON formatted results to
    #[arg(long)]
    json: Option<String>,

    /// File name to save JSON formatted results to. When present, overrides default name
    #[arg(long)]
    jsonf: Option<String>,

    /// Directory to save xhtml formatted results to
    #[arg(long)]
    html: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss")]
    dt: String,

    /// When true, display higher precision for timestamps
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    mp: bool,

    /// Not supported on this platform (Volume Shadow Copies of a live system); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    vss: bool,

    /// Deduplicate -d based on SHA-1. First file found wins
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    dedupe: bool,

    /// Not supported on this platform (alternate data streams); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    ads: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// Save all console messages to <timestamp>_PECmd_<version>_ConsoleLog.txt in the output directory (the first of
    /// --csv, --json, --html given). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// N0 of an int, which can be negative in a damaged file
fn n0i(n: i32) -> String {
    let text = n0(n.unsigned_abs() as u64);
    if n < 0 { format!("-{text}") } else { text }
}

/// What the exception .NET throws says for a path that can't be created or written
fn io_message(path: &Path, e: &std::io::Error) -> String {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => {
            format!("Access to the path '{}' is denied.", full.display())
        }
        std::io::ErrorKind::NotFound => format!("Could not find a part of the path '{}'.", full.display()),
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotADirectory => {
            format!("The file '{}' already exists.", full.display())
        }
        _ => e.to_string(),
    }
}

/// CsvOut: one prefetch file's row, also what goes in the JSON and XHTML
#[derive(Default)]
struct Row {
    note: Option<String>,
    source_filename: String,
    source_created: String,
    source_modified: String,
    source_accessed: String,
    executable_name: String,
    full_path: String,
    path_validated: bool,
    hash: String,
    size: String,
    version: String,
    run_count: String,
    last_run: String,
    previous_runs: [Option<String>; 7],
    volume0_name: String,
    volume0_serial: String,
    volume0_created: String,
    volume1_name: Option<String>,
    volume1_serial: Option<String>,
    volume1_created: Option<String>,
    directories: Option<String>,
    files_loaded: Option<String>,
    parsing_error: bool,
}

fn bool_text(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

const CSV_HEADER: &str = "Note,SourceFilename,SourceCreated,SourceModified,SourceAccessed,ExecutableName,FullPath,PathValidated,Hash,Size,Version,RunCount,LastRun,PreviousRun0,PreviousRun1,PreviousRun2,PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,Volume0Name,Volume0Serial,Volume0Created,Volume1Name,Volume1Serial,Volume1Created,Directories,FilesLoaded,ParsingError";
const CSV_TIMELINE_HEADER: &str = "RunTime,ExecutableName,SourceFilename,PathValidated";

fn csv_line(out: &mut String, fields: &[&str]) {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        ez_common::csv::field(out, f);
    }
    out.push_str(ez_common::csv::NEW_LINE);
}

impl Row {
    /// GetCsvFormat: Err where the file has no header
    fn new(pf: &Prefetch, dt: &str) -> Result<Row, String> {
        let header = pf.header.as_ref().ok_or(NO_HEADER)?;
        Timestamp::check_format(dt)?;
        let mut row = Row {
            source_filename: pf.source_filename.clone(),
            source_created: pf.source_times.created.format(dt),
            source_modified: pf.source_times.modified.format(dt),
            source_accessed: pf.source_times.accessed.format(dt),
            hash: header.hash.clone(),
            executable_name: header.executable_filename.clone(),
            size: header.file_size.to_string(),
            version: header.version.description().to_string(),
            run_count: pf.run_count.to_string(),
            parsing_error: pf.parsing_error(),
            ..Row::default()
        };
        if let Some(v) = pf.volume_information.first() {
            // year 1601: a FILETIME of about 0
            if v.creation_time.parts().year != 1601 {
                row.volume0_created = v.creation_time.format(dt);
            }
            row.volume0_name = v.device_name.clone();
            row.volume0_serial = v.serial_number.clone();
        }
        if let Some(t) = pf.last_run_times.first() {
            row.last_run = t.format(dt);
        }
        let path = executable_path(pf);
        row.full_path = path.full_path;
        row.path_validated = path.path_validated;
        for (slot, t) in row.previous_runs.iter_mut().zip(pf.last_run_times.iter().skip(1)) {
            *slot = Some(t.format(dt));
        }
        if let Some(v) = pf.volume_information.get(1) {
            row.volume1_created = Some(v.creation_time.format(dt));
            row.volume1_name = Some(v.device_name.clone());
            row.volume1_serial = Some(v.serial_number.clone());
        }
        if pf.volume_information.len() > 2 {
            row.note = Some("File contains > 2 volumes! Please inspect output from main program for full details!".into());
        }
        if pf.parsing_error() {
            return Ok(row);
        }
        row.directories =
            Some(pf.volume_information.iter().map(|v| v.directory_names.join(", ")).collect::<Vec<_>>().concat());
        row.files_loaded = Some(pf.filenames.join(", "));
        Ok(row)
    }

    fn write_csv(&self, out: &mut String) {
        let run = |i: usize| self.previous_runs[i].as_deref().unwrap_or("");
        csv_line(
            out,
            &[
                self.note.as_deref().unwrap_or(""),
                &self.source_filename,
                &self.source_created,
                &self.source_modified,
                &self.source_accessed,
                &self.executable_name,
                &self.full_path,
                bool_text(self.path_validated),
                &self.hash,
                &self.size,
                &self.version,
                &self.run_count,
                &self.last_run,
                run(0),
                run(1),
                run(2),
                run(3),
                run(4),
                run(5),
                run(6),
                &self.volume0_name,
                &self.volume0_serial,
                &self.volume0_created,
                self.volume1_name.as_deref().unwrap_or(""),
                self.volume1_serial.as_deref().unwrap_or(""),
                self.volume1_created.as_deref().unwrap_or(""),
                self.directories.as_deref().unwrap_or(""),
                self.files_loaded.as_deref().unwrap_or(""),
                bool_text(self.parsing_error),
            ],
        );
    }

    fn to_json(&self) -> String {
        let mut o = ServiceStackObject::new();
        o.string("Note", self.note.as_deref())
            .string("SourceFilename", Some(&self.source_filename))
            .string("SourceCreated", Some(&self.source_created))
            .string("SourceModified", Some(&self.source_modified))
            .string("SourceAccessed", Some(&self.source_accessed))
            .string("ExecutableName", Some(&self.executable_name))
            .string("FullPath", Some(&self.full_path))
            .bool("PathValidated", self.path_validated)
            .string("Hash", Some(&self.hash))
            .string("Size", Some(&self.size))
            .string("Version", Some(&self.version))
            .string("RunCount", Some(&self.run_count))
            .string("LastRun", Some(&self.last_run));
        for (i, r) in self.previous_runs.iter().enumerate() {
            o.string(&format!("PreviousRun{i}"), r.as_deref());
        }
        o.string("Volume0Name", Some(&self.volume0_name))
            .string("Volume0Serial", Some(&self.volume0_serial))
            .string("Volume0Created", Some(&self.volume0_created))
            .string("Volume1Name", self.volume1_name.as_deref())
            .string("Volume1Serial", self.volume1_serial.as_deref())
            .string("Volume1Created", self.volume1_created.as_deref())
            .string("Directories", self.directories.as_deref())
            .string("FilesLoaded", self.files_loaded.as_deref())
            .bool("ParsingError", self.parsing_error);
        o.finish()
    }
}

struct Run {
    log: Logger,
    dt: String,
    keywords: Vec<String>,
    quiet: bool,
    processed: Vec<Prefetch>,
    failed: Vec<String>,
    /// Files or folders that could not be opened, read or listed (a damaged file is only listed in `failed`)
    read_errors: u32,
}

fn main() -> ExitCode {
    match ez_common::cli::parse_args::<Args>() {
        Ok(args) => run(args),
        Err(code) => code,
    }
}

fn run(args: Args) -> ExitCode {
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let dt = if args.mp { PRECISE_TIME_FORMAT.to_string() } else { args.dt.clone() };
    let mut log = Logger::new(level, &dt).to_stdout();
    // the time in the output names and the console log's
    let utc_now = Timestamp::now();
    let stamp = utc_now.format("yyyyMMddHHmmss");

    let console_log = if args.co {
        [&args.csv, &args.json, &args.html].into_iter().flatten().find(|d| !d.trim().is_empty()).map(|dir| {
            let dir = std::path::absolute(dir).unwrap_or_else(|_| PathBuf::from(dir));
            if std::fs::create_dir_all(&dir).is_ok() {
                let _ = log.open_file(&dir.join(format!("{stamp}_PECmd_{VERSION}_ConsoleLog.txt")));
            }
            dir.join(format!("{stamp}_PECmd_{VERSION}_ConsoleLog.txt"))
        })
    } else {
        None
    };

    let (file, dir) = (given(&args.file), given(&args.dir));
    if file.is_none() && dir.is_none() {
        use clap::CommandFactory;
        let _ = Args::command().print_help();
        log.warning("Either -f or -d is required. Exiting");
        return ExitCode::FAILURE;
    }
    if let Some(f) = file.filter(|f| !Path::new(f).is_file()) {
        log.warning(&format!("File {f} not found. Exiting"));
        return ExitCode::FAILURE;
    }
    if let Some(d) = dir.filter(|d| !Path::new(d).is_dir()) {
        log.warning(&format!("Directory {d} not found. Exiting"));
        return ExitCode::FAILURE;
    }

    let mut keywords = vec!["temp".to_string(), "tmp".to_string()];
    if let Some(k) = given(&args.keywords) {
        for kw in lower_invariant(k).split(',').filter(|kw| !kw.is_empty()) {
            let kw = kw.trim().to_string();
            if !keywords.contains(&kw) {
                keywords.push(kw);
            }
        }
    }

    log.info(&format!(
        "pecmd version {VERSION} (a Rust port of PECmd)\n\nPECmd: Eric Zimmerman (saericzimmerman@gmail.com)\nhttps://github.com/EricZimmerman/PECmd"
    ));
    log.blank();
    log.info(&format!("Command line: {}", std::env::args().skip(1).collect::<Vec<_>>().join(" ")));
    if let Some(p) = &console_log {
        log.blank();
        log.info(&format!("Console log: {}", p.display()));
    }
    if args.vss {
        log.warning("--vss is not supported on non-Windows platforms. Disabling...");
    }
    if args.ads {
        log.warning("--ads is not supported on non-Windows platforms. Disabling...");
    }
    log.blank();
    log.info(&format!("Keywords: {}", keywords.join(", ")));
    log.blank();

    let mut run = Run { log, dt, keywords, quiet: args.quiet, processed: vec![], failed: vec![], read_errors: 0 };
    let mut export_errors = 0;

    if let Some(f) = file {
        if let Some(pf) = run.load_file(f) {
            if let Some(o) = given(&args.save) {
                if let Err(e) = save_prefetch(o, &pf, &mut run.log) {
                    run.log.error(&format!("Unable to save prefetch file. Error: {e}"));
                    export_errors += 1;
                }
            }
            run.processed.push(pf);
        }
    } else if let Some(d) = dir {
        run.process_directory(d, args.dedupe);
    }

    if !run.processed.is_empty() {
        run.log.blank();
        if let Err(e) = run.export(&args, &stamp, &mut export_errors) {
            run.log.error(&format!("Error exporting data: {e}"));
            export_errors += 1;
        }
    }

    // damaged files are listed under Failed files but are not a failure of the run
    if run.read_errors > 0 || export_errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// PrefetchFile.SavePrefetch, in the folder of the path given. As in the original, a name without a folder can't be
/// saved: its folder is empty, which .NET's Directory.CreateDirectory refuses.
fn save_prefetch(o: &str, pf: &Prefetch, log: &mut Logger) -> Result<(), String> {
    let path = Path::new(o);
    let parent = path.parent().unwrap_or(Path::new(""));
    if parent.as_os_str().is_empty() {
        return Err("The value cannot be an empty string. (Parameter 'path')".into());
    }
    if !parent.is_dir() {
        std::fs::create_dir_all(parent).map_err(|e| io_message(parent, &e))?;
    }
    log.debug(&format!("Writing raw bytes to {o}"));
    std::fs::write(path, &pf.raw_bytes).map_err(|e| io_message(path, &e))?;
    log.info(&format!("Saved prefetch bytes to {o}"));
    Ok(())
}

/// The entries under a folder whose names end in .pf (folders too, as the original finds them), each folder's in NTFS
/// order, as on Windows, subfolders after. The paths start with the folder as it was given.
fn find_entries(directory: &str, log: &mut Logger, read_errors: &mut u32) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = std::collections::VecDeque::from([directory.to_string()]);
    let mut unreadable = Vec::new();
    while let Some(folder) = pending.pop_front() {
        let entries = match ez_common::cli::read_dir_ntfs_order(std::path::Path::new(&folder)) {
            Ok(e) => e,
            Err(e) => {
                let reason = if e.kind() == std::io::ErrorKind::PermissionDenied { "Permission denied".to_string() } else { e.to_string() };
                unreadable.push((folder, reason));
                continue;
            }
        };
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if folder.ends_with('/') { format!("{folder}{name}") } else { format!("{folder}/{name}") };
            // a link to a folder is followed, as .NET does
            if Path::new(&path).is_dir() {
                pending.push_back(path.clone());
            }
            if name.len() >= 3 && name.is_char_boundary(name.len() - 3) && name[name.len() - 3..].eq_ignore_ascii_case(".pf") {
                found.push(path);
            }
        }
    }
    for (folder, reason) in unreadable {
        log.error(&format!("Unable to read folder {folder}: {reason}"));
        *read_errors += 1;
    }
    found
}

fn sha1_hex(b: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(b).iter().map(|x| format!("{x:02X}")).collect()
}

impl Run {
    fn process_directory(&mut self, d: &str, dedupe: bool) {
        self.log.info(&format!("Looking for prefetch files in {d}"));
        self.log.blank();
        let files = find_entries(d, &mut self.log, &mut self.read_errors);
        self.log.blank();
        self.log.info(&format!("Found {} Prefetch files", n0(files.len() as u64)));
        self.log.blank();

        let start = Instant::now();
        let mut seen = std::collections::HashSet::new();
        for file in &files {
            if !Path::new(file).is_file() {
                self.log.warning(&format!("File {file} does not seem to exist any more! Skipping"));
                continue;
            }
            if dedupe {
                let sha = match std::fs::read(file) {
                    Ok(b) => sha1_hex(&b),
                    Err(e) => {
                        let message = io_message(Path::new(file), &e);
                        self.log.error(&format!("Unable to read {file} to check for duplicates. Message: {message}"));
                        self.log.blank();
                        self.failed.push(format!("{file} ==> ({message})"));
                        self.read_errors += 1;
                        continue;
                    }
                };
                if !seen.insert(sha.clone()) {
                    self.log.debug(&format!("Skipping {file} as a file with SHA-1 {sha} has already been processed"));
                    continue;
                }
            }
            if let Some(pf) = self.load_file(file) {
                self.processed.push(pf);
            }
        }
        if self.quiet {
            self.log.blank();
        }
        self.log.info(&format!(
            "Processed {} out of {} files in {} seconds",
            n0i(files.len() as i32 - self.failed.len() as i32),
            n0(files.len() as u64),
            number_n(start.elapsed().as_secs_f64(), 4)
        ));
        if !self.failed.is_empty() {
            self.log.blank();
            self.log.warning("Failed files");
            for f in std::mem::take(&mut self.failed) {
                self.log.info(&format!("  {f}"));
            }
        }
    }

    /// LoadFile: None when the file can't be opened, or can't be shown
    fn load_file(&mut self, file: &str) -> Option<Prefetch> {
        if !self.quiet {
            self.log.info(&format!("Processing {file}"));
            self.log.blank();
        }
        let start = Instant::now();
        let log = &mut self.log;
        let opened = prefetch_ez::open(file, &mut |level, message| log.log(level, message));
        let error = match opened {
            Ok(pf) => {
                let mut listed = false;
                if pf.parsing_error() {
                    self.failed.push(format!("{file} is corrupt and did not parse completely!"));
                    listed = true;
                    self.log.fatal(&format!("{file} FILE DID NOT PARSE COMPLETELY!"));
                    self.log.blank();
                }
                // The original only finds out in -q at the export, which then loses every file's output. Here -q skips
                // the file as a run without it does.
                let shown = if !self.quiet {
                    self.display_file(&pf)
                } else if pf.header.is_none() {
                    Err(NO_HEADER)
                } else {
                    Ok(())
                };
                match shown {
                    Ok(()) => {
                        self.log.info(&format!(
                            "---------- Processed {file} in {} seconds ----------",
                            number_n(start.elapsed().as_secs_f64(), 8)
                        ));
                        return Some(pf);
                    }
                    Err(e) => (e.to_string(), listed, false),
                }
            }
            Err(Error::Parse { message }) => (message, false, false),
            Err(Error::Io { message }) => (message, false, true),
        };
        let (message, listed, read_error) = error;
        self.log.error(&format!("Error opening {file}. Message: {message}"));
        self.log.blank();
        if !listed {
            self.failed.push(format!("{file} ==> ({message})"));
        }
        if read_error {
            self.read_errors += 1;
        }
        None
    }

    fn has_keyword(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        self.keywords.iter().any(|k| lower.contains(k.as_str()))
    }

    /// DisplayFile: Err where the file has no header
    fn display_file(&mut self, pf: &Prefetch) -> Result<(), &'static str> {
        let dt = self.dt.clone();
        let log = &mut self.log;
        if pf.parsing_error() {
            log.warning(&format!("{} FILE DID NOT PARSE COMPLETELY!", pf.source_filename));
            for e in &pf.parse_errors {
                log.warning(&format!("  {e}"));
            }
            log.blank();
            log.warning("PARTIAL OUTPUT SHOWN BELOW");
            log.blank();
        }
        log.info(&format!("Created on: {}", pf.source_times.created.format(&dt)));
        log.info(&format!("Modified on: {}", pf.source_times.modified.format(&dt)));
        log.info(&format!("Last accessed on: {}", pf.source_times.accessed.format(&dt)));
        log.blank();

        let header = pf.header.as_ref().ok_or(NO_HEADER)?;
        log.info(&format!("Executable name: {}", header.executable_filename));
        log.info(&format!("Hash: {}", header.hash));
        log.info(&format!("File size (bytes): {}", n0i(header.file_size)));
        log.info(&format!("Version: {}", header.version.description()));
        log.blank();

        log.info(&format!("Run count: {}", n0i(pf.run_count)));
        match pf.last_run_times.first() {
            Some(t) => log.info(&format!("Last run: {}", t.format(&dt))),
            None => log.info("Last run: (none)"),
        }
        if pf.last_run_times.len() > 1 {
            let others: Vec<String> = pf.last_run_times[1..].iter().map(|t| t.format(&dt)).collect();
            log.info(&format!("Other run times: {}", others.join(", ")));
        }
        log.blank();
        log.info("Volume information:");
        log.blank();
        for (i, v) in pf.volume_information.iter().enumerate() {
            log.info(&format!(
                "#{i}: Name: {} Serial: {} Created: {} Directories: {} File references: {}",
                v.device_name,
                v.serial_number,
                v.creation_time.format(&dt),
                n0(v.directory_names.len() as u64),
                n0(v.file_references.len() as u64)
            ));
        }
        log.blank();

        // version 17 has -1 for total directories, so it is calculated
        let total_dirs = if header.version == Version::WinXpOrWin2K3 {
            pf.volume_information.iter().map(|v| v.directory_names.len() as i32).sum()
        } else {
            pf.total_directory_count
        };
        self.log.info(&format!("Directories referenced: {}", n0i(total_dirs)));
        self.log.blank();
        let mut index = 0;
        for v in &pf.volume_information {
            for name in &v.directory_names {
                if self.has_keyword(name) {
                    self.log.fatal(&format!("{index:02}: {name} (Keyword True)"));
                } else {
                    self.log.info(&format!("{index:02}: {name}"));
                }
                index += 1;
            }
        }
        self.log.blank();

        self.log.info(&format!("Files referenced: {}", n0(pf.filenames.len() as u64)));
        self.log.blank();
        for (index, name) in pf.filenames.iter().enumerate() {
            if name.ends_with(&header.executable_filename) {
                self.log.info(&format!("{index:02}: {name} (Executable: True) "));
            } else if self.has_keyword(name) {
                self.log.info(&format!("{index:02}: {name} (Keyword: True)"));
            } else {
                self.log.info(&format!("{index:02}: {name}"));
            }
        }
        self.log.blank();
        self.log.blank();
        Ok(())
    }

    /// The exports. Err stops them all (nothing more is written); what was buffered is lost, as in the original
    fn export(&mut self, args: &Args, stamp: &str, export_errors: &mut u32) -> Result<(), String> {
        let log = &mut self.log;
        let mut json_out: Option<(File, PathBuf, String)> = None;
        if let Some(json) = given(&args.json) {
            let dir = Path::new(json);
            if !dir.is_dir() {
                log.info(&format!("{json} does not exist. Creating..."));
                std::fs::create_dir_all(dir).map_err(|e| io_message(dir, &e))?;
            }
            let name = match given(&args.jsonf) {
                Some(f) => file_name(f).to_string(),
                None => format!("{stamp}_PECmd_Output.json"),
            };
            let out = dir.join(name);
            log.info(&format!("Saving json output to {}", out.display()));
            let file = File::create(&out).map_err(|e| io_message(&out, &e))?;
            json_out = Some((file, out, String::new()));
        }

        let mut csv_out: Option<(File, PathBuf, String)> = None;
        let mut timeline_out: Option<(File, PathBuf, String)> = None;
        if let Some(csv) = given(&args.csv) {
            let (name, timeline) = match given(&args.csvf) {
                Some(f) => {
                    let ext = path_extension(f);
                    let name = file_name(f);
                    let stem = name.strip_suffix(ext).unwrap_or(name);
                    (name.to_string(), format!("{stem}_Timeline{ext}"))
                }
                None => (format!("{stamp}_PECmd_Output.csv"), format!("{stamp}_PECmd_Output_Timeline.csv")),
            };
            let dir = Path::new(csv);
            let (out, out_timeline) = (dir.join(name), dir.join(timeline));
            if !dir.is_dir() {
                log.info(&format!("Path to {csv} does not exist. Creating..."));
                std::fs::create_dir_all(dir).map_err(|e| io_message(dir, &e))?;
            }
            log.info(&format!("CSV output will be saved to {}", out.display()));
            log.info(&format!("CSV time line output will be saved to {}", out_timeline.display()));
            let opened = File::create(&out).map_err(|e| io_message(&out, &e)).and_then(|file| {
                csv_out = Some((file, out.clone(), format!("{CSV_HEADER}\r\n")));
                File::create(&out_timeline).map_err(|e| io_message(&out_timeline, &e))
            });
            match opened {
                Ok(file) => timeline_out = Some((file, out_timeline, format!("{CSV_TIMELINE_HEADER}\r\n"))),
                Err(e) => {
                    log.error(&format!(
                        "Unable to open {} for writing. CSV export canceled. Error: {e}",
                        out.display()
                    ));
                    *export_errors += 1;
                }
            }
        }

        let mut html_out: Option<xhtml::Document> = None;
        if let Some(html) = given(&args.html) {
            html_out = Some(xhtml::Document::create(html, stamp, log)?);
        }

        if given(&args.csv).is_none() && given(&args.json).is_none() && given(&args.html).is_none() {
            return Ok(());
        }

        for pf in &self.processed {
            let row = Row::new(pf, &self.dt)?;
            if let Some((_, _, text)) = &mut timeline_out {
                let executable = match (row.full_path.is_empty(), pf.header.as_ref()) {
                    (true, Some(h)) => h.executable_filename.as_str(),
                    _ => row.full_path.as_str(),
                };
                for t in &pf.last_run_times {
                    csv_line(
                        text,
                        &[&t.format(&self.dt), executable, &pf.source_filename, bool_text(row.path_validated)],
                    );
                }
            }
            if let Some((_, _, text)) = &mut csv_out {
                row.write_csv(text);
            }
            if let Some((_, _, text)) = &mut json_out {
                let _ = write!(text, "{}{}", Row::new(pf, JSON_DATE_FORMAT)?.to_json(), ez_common::dotnet::NEW_LINE);
            }
            if let Some(doc) = &mut html_out {
                doc.container(&row);
            }
        }

        for (mut file, path, text) in [csv_out, timeline_out, json_out].into_iter().flatten() {
            file.write_all(text.as_bytes()).map_err(|e| io_message(&path, &e))?;
        }
        if let Some(doc) = html_out {
            doc.finish()?;
        }
        Ok(())
    }
}

/// Path.GetFileName
fn file_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}
