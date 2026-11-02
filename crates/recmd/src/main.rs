//! recmd: registry hives searched, dumped and processed with batch files (to CSV or JSON), as RECmd does it.

mod batch;
mod details;
#[cfg(feature = "sync")]
mod sync;

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use batch::{Batch, BatchKey, Row};
use clap::{ArgAction, Parser};
use ez_common::Level;
use ez_common::cli::BOM;
use ez_common::cli::log::Logger;
use ez_common::dotnet::{n0, number_n};
use ez_common::net::NetResult;
use ez_common::time::Timestamp;
use registry_ez::hive::{HitType, Hive, KeyId, SearchHit, lower, strip_root, upper};
use registry_ez::replay::LogFile;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Searches registry hives, dumps keys and values, and processes batch files (to CSV or JSON), with RECmd's options
/// and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  recmd -f 'UsrClass 1.dat' --sk URL --recover false --nl\n  recmd -f 'UsrClass 1.dat' --regex --sv '(App|Display)Name'\n  recmd -d /triage --bn BatchExamples/DFIRBatch.reb --csv /out"
)]
struct Args {
    /// Hive to search. -f or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to look for hives (recursively). -f or -d is required
    #[arg(short = 'd', value_name = "DIR")]
    dir: Option<String>,

    /// Display details for key name. Includes subkeys and values
    #[arg(long)]
    kn: Option<String>,

    /// Value name. Only this value will be dumped
    #[arg(long)]
    vn: Option<String>,

    /// Use settings from supplied file to find keys/values. See included sample file for examples
    #[arg(long)]
    bn: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long)]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long)]
    csvf: Option<String>,

    /// Saves --vn value data in binary form to file. Expects path to a FILE
    #[arg(long = "saveTo")]
    save_to: Option<String>,

    /// Directory to save JSON formatted results to
    #[arg(long)]
    json: Option<String>,

    /// File name to save JSON formatted results to. When present, overrides default name
    #[arg(long)]
    jsonf: Option<String>,

    /// Show more details when displaying results
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    details: bool,

    /// Find Base64 encoded values with size >= Base64 (specified in bytes)
    #[arg(long, default_value_t = 0)]
    base64: i32,

    /// Find values with data size >= MinSize (specified in bytes)
    #[arg(long = "minSize", default_value_t = 0)]
    min_size: i32,

    /// Search for <string> in keys, values, data, and slack
    #[arg(long)]
    sa: Option<String>,

    /// Search for <string> in value record's key names
    #[arg(long)]
    sk: Option<String>,

    /// Search for <string> in value record's value names
    #[arg(long)]
    sv: Option<String>,

    /// Search for <string> in value record's value data
    #[arg(long)]
    sd: Option<String>,

    /// Search for <string> in value record's value slack
    #[arg(long)]
    ss: Option<String>,

    /// If true, --sd and --ss search value will not be interpreted as ASCII or Unicode byte strings
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    literal: bool,

    /// If true, do not show data when using --sd or --ss
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nd: bool,

    /// If present, treat <string> in --sk, --sv, --sd, and --ss as a regular expression
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    regex: bool,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss.fffffff")]
    dt: String,

    /// When true, allow transaction log files to not exist for dirty hives
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nl: bool,

    /// If true, recover deleted keys/values
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    recover: bool,

    /// Not supported (Volume Shadow Copies of a live system); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    vss: bool,

    /// Deduplicate -f or -d based on SHA-1. First file found wins
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    dedupe: bool,

    /// Download the latest batch files from https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples into
    /// BatchExamples next to this program, then exit
    #[cfg(feature = "sync")]
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    sync: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// Save all console messages to <timestamp>_RECmd_<version>_ConsoleLog.txt in the output directory (the first of
    /// --csv, --json given, else the folder of --saveTo). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    // deep hives are walked recursively, as the library does
    let child = std::thread::Builder::new().stack_size(256 << 20).spawn(move || run(args)).expect("thread");
    match child.join() {
        Ok(Ok(code)) => code,
        Ok(Err(message)) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
        Err(_) => ExitCode::FAILURE,
    }
}

/// What processing a hive found wrong (the exception DoWork catches)
struct Failure {
    message: String,
    /// The hive could not be read (access failure)
    access: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure { message, access: false }
    }
}

const DIRTY_NO_LOGS: &str =
    "Sequence numbers do not match and transaction logs were not found in the same directory as the hive. Aborting";

struct Run {
    args: Args,
    log: Logger,
    batch: Option<Batch>,
    rows: Vec<Row>,
    seen_hashes: HashSet<String>,
    total_hits: usize,
    hives_with_hits: usize,
    hive_info_with_hits: Vec<String>,
    search_used: bool,
    errors: u32,
}

fn run(mut args: Args) -> Result<ExitCode, String> {
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let mut log = Logger::new(level, &args.dt).to_stdout();
    let run_time = Timestamp::now();
    if args.co {
        let dir = [&args.csv, &args.json].into_iter().flatten().find(|d| !d.trim().is_empty()).map(PathBuf::from).or_else(|| {
            args.save_to.as_ref().filter(|s| !s.is_empty()).map(|s| {
                let p = std::path::absolute(s).unwrap_or_else(|_| PathBuf::from(s));
                p.parent().map(Path::to_path_buf).unwrap_or_default()
            })
        });
        if let Some(dir) = dir {
            let dir = std::path::absolute(&dir).unwrap_or(dir);
            if std::fs::create_dir_all(&dir).is_ok() {
                let p = dir.join(format!("{}_RECmd_{VERSION}_ConsoleLog.txt", run_time.format("yyyyMMddHHmmss")));
                let _ = log.open_file(&p);
            }
        }
    }

    #[cfg(feature = "sync")]
    if args.sync {
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("BatchExamples")))
            .unwrap_or_else(|| PathBuf::from("BatchExamples"));
        if let Err(e) = sync::sync_batch_files(&dir, &mut log) {
            log.error(&format!("There was an error checking for updates: {e}"));
            return Ok(ExitCode::FAILURE);
        }
        return Ok(ExitCode::SUCCESS);
    }

    log.info(&format!(
        "recmd version {VERSION} (a Rust port of RECmd)\n\nRECmd: Eric Zimmerman (saericzimmerman@gmail.com)\nhttps://github.com/EricZimmerman/RECmd\n\nNote: Enclose all strings containing spaces (and all RegEx) with double quotes"
    ));
    log.info("");
    log.info(&format!("Command line: {}", std::env::args().skip(1).collect::<Vec<_>>().join(" ")));
    log.info("");
    if let Some(p) = log.file_path() {
        log.info(&format!("Console log: {}", p.display()));
        log.info("");
    }
    if args.vss {
        log.warning("--vss is not supported by this version (it is for live systems); ignored");
        log.info("");
    }

    let mut batch = None;
    if let Some(bn) = args.bn.clone().filter(|s| !s.is_empty()) {
        if !Path::new(&bn).is_file() {
            log.error(&format!("Batch file {bn} does not exist"));
            return Ok(ExitCode::FAILURE);
        }
        let (csv, json) = (non_empty(&args.csv), non_empty(&args.json));
        if !csv && !json {
            log.error("Either --csv or --json is required when using --bn. Exiting");
            return Ok(ExitCode::FAILURE);
        }
        if csv && json {
            log.error("Only use one of --csv or --json when using --bn. Exiting");
            return Ok(ExitCode::FAILURE);
        }
        match batch::read_and_validate(&bn, &mut log) {
            Some(b) => batch = Some(b),
            None => return Ok(ExitCode::FAILURE),
        }
    }

    let mut errors = 0u32;
    let mut hives: Vec<String> = Vec::new();
    if let Some(f) = args.file.clone().filter(|s| !s.is_empty()) {
        if !Path::new(&f).is_file() {
            log.error(&format!("File {f} does not exist"));
            return Ok(ExitCode::FAILURE);
        }
        if !min_switches(&args) {
            return Ok(missing_switches(&mut log));
        }
        hives.push(f);
    } else if let Some(d) = args.dir.clone().filter(|s| !s.is_empty()) {
        if !Path::new(&d).is_dir() {
            log.error(&format!("Directory {d} does not exist"));
            log.info("");
            return Ok(ExitCode::FAILURE);
        }
        if !min_switches(&args) {
            return Ok(missing_switches(&mut log));
        }
        hives = find_hives(&d, &mut log, &mut errors);
        log.info("");
        log.info(&format!("Total hives found: {}", n0(hives.len() as u64)));
    } else {
        use clap::CommandFactory;
        let _ = Args::command().print_help();
        return Ok(ExitCode::FAILURE);
    }

    if hives.is_empty() {
        log.warning("No hives were found. Exiting...");
        return Ok(if errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS });
    }

    // --sa searches with the same term everywhere
    if let Some(sa) = args.sa.clone().filter(|s| !s.is_empty()) {
        args.sk = Some(sa.clone());
        args.sv = Some(sa.clone());
        args.sd = Some(sa.clone());
        args.ss = Some(sa);
    }

    let mut run = Run {
        args,
        log,
        batch,
        rows: Vec::new(),
        seen_hashes: HashSet::new(),
        total_hits: 0,
        hives_with_hits: 0,
        hive_info_with_hits: Vec::new(),
        search_used: false,
        errors,
    };
    let mut failed = 0u32;
    let mut access_failed = 0u32;
    let mut total_seconds = 0f64;
    for hive_path in &hives {
        run.log.info("");
        run.log.info(&format!("Processing hive {hive_path}"));
        if !Path::new(hive_path).is_file() {
            run.log.warning(&format!("{hive_path} does not exist. Skipping"));
            continue;
        }
        let start = Instant::now();
        let mut hive_read = false;
        match run.process(hive_path, &mut hive_read) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(f) => {
                let dirty = f.message.contains("Sequence numbers do not match and transaction");
                if !dirty {
                    if f.message.contains("Data in byte array is not a Registry hive") && run.args.file.as_deref().is_none_or(str::is_empty)
                    {
                        run.log.debug(&format!("Skipping {hive_path}: {}", f.message));
                        continue;
                    }
                    run.log.error(&format!("There was an error processing {hive_path}: {}", f.message));
                }
                failed += 1;
                if !hive_read || f.access || dirty {
                    access_failed += 1;
                }
            }
        }
        total_seconds += start.elapsed().as_secs_f64();
    }

    let log = &mut run.log;
    if let Some(bn) = run.args.bn.as_deref().filter(|s| !s.is_empty()) {
        log.info("");
        let pairs = if run.rows.len() == 1 { "pair" } else { "pairs" };
        let files = if hives.len() == 1 { "file" } else { "files" };
        log.info(&format!(
            "Found {} key/value {pairs} across {} {files}",
            n0(run.rows.len() as u64),
            n0(hives.len() as u64)
        ));
        log.info(&format!("Total search time: {} seconds", number_n(total_seconds, 3)));
        if !run.rows.is_empty() {
            if let Err(e) = write_batch(&run.args, bn, &run.rows, run_time, log) {
                log.error(&format!("Error exporting batch results: {e}"));
                run.errors += 1;
            }
        }
    }
    if run.search_used && run.args.dir.as_deref().is_some_and(|d| !d.is_empty()) {
        log.info("");
        let hits = if run.total_hits == 1 { "hit" } else { "hits" };
        let with = if run.hives_with_hits == 1 { "hive" } else { "hives" };
        let files = if hives.len() == 1 { "file" } else { "files" };
        log.info("---------------------------------------------");
        log.info(&format!("Directory: {}", run.args.dir.as_deref().unwrap()));
        log.info("");
        log.info(&format!(
            "Found {} {hits} in {} {with} out of {} {files}",
            n0(run.total_hits as u64),
            n0(run.hives_with_hits as u64),
            n0(hives.len() as u64)
        ));
        for h in &run.hive_info_with_hits {
            log.info(h);
        }
        log.info("");
        log.info(&format!("Total search time: {} seconds", number_n(total_seconds, 3)));
    }
    log.info("");
    if failed > 0 {
        log.warning(&format!("{} hive(s) could not be processed", n0(failed as u64)));
        log.info("");
    }
    Ok(if access_failed > 0 || run.errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

fn non_empty(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|s| !s.is_empty())
}

fn min_switches(a: &Args) -> bool {
    [&a.sk, &a.sd, &a.sv, &a.ss, &a.sa, &a.kn, &a.bn].iter().any(|s| non_empty(s)) || a.min_size != 0 || a.base64 != 0
}

fn missing_switches(log: &mut Logger) -> ExitCode {
    use clap::CommandFactory;
    log.info("");
    let _ = Args::command().print_help();
    log.warning("One of the following switches is required: --sa | --sk | --sv | --sd | --ss | --kn | --base64 | --minSize | --bn");
    log.info("");
    ExitCode::FAILURE
}

/// FileSystemName.MatchesSimpleExpression, ignoring case: `*` is any run of characters, `?` any one
fn matches_mask(mask: &str, name: &str) -> bool {
    let m: Vec<char> = upper(mask).chars().collect();
    let n: Vec<char> = upper(name).chars().collect();
    let (mut mi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if mi < m.len() && (m[mi] == '?' || m[mi] == n[ni]) {
            mi += 1;
            ni += 1;
        } else if mi < m.len() && m[mi] == '*' {
            star = Some(mi);
            mi += 1;
            mark = ni;
        } else if let Some(s) = star {
            mi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while mi < m.len() && m[mi] == '*' {
        mi += 1;
    }
    mi == m.len()
}

const MASKS: &[&str] = &[
    "*USRCLASS.DAT",
    "*USER.DAT",
    "*SYSTEM",
    "*SAM",
    "*SOFTWARE",
    "*DEFAULT",
    "*AMCACHE.HVE",
    "*SYSCACHE.hve",
    "*SECURITY",
    "*DRIVERS",
    "*COMPONENTS",
    "*UserClasses.dat",
    "*settings.dat",
    "*Registry.dat",
];
const IGNORED_EXTENSIONS: &[&str] = &[".DLL", ".LOG", ".LOG1", ".LOG2", ".CSV", ".BLF", ".REGTRANS-MS", ".EXE", ".TXT", ".INI"];

/// FindFiles: files whose names match the hive masks, in the folder and its subfolders (each folder's entries in the
/// order the file system gives them, subfolders after), 4 bytes or more, without an ignored extension
fn find_hives(d: &str, log: &mut Logger, errors: &mut u32) -> Vec<String> {
    let root = full_path(d);
    let mut found = Vec::new();
    let mut pending = VecDeque::from([root]);
    let mut unreadable = Vec::new();
    while let Some(dir) = pending.pop_front() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                unreadable.push((dir.clone(), io_reason(&e)));
                continue;
            }
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                pending.push_back(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if MASKS.iter().any(|m| matches_mask(m, &name)) {
                found.push(path);
            }
        }
    }
    for (folder, reason) in &unreadable {
        log.error(&format!("Unable to read folder {}: {reason}", folder.display()));
    }
    *errors += unreadable.len() as u32;
    found
        .into_iter()
        .filter(|p| {
            let s = p.to_string_lossy();
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            if size < 4 {
                log.debug(&format!("Skipping {s} with size {}", n0(size)));
                return false;
            }
            let ext = ez_common::net::path_extension(&s);
            if IGNORED_EXTENSIONS.contains(&upper(ext).as_str()) {
                log.debug(&format!("Skipping {s} since its extension ({ext}) is in ignoreMasks"));
                return false;
            }
            true
        })
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

/// Path.GetFullPath: absolute, with `.` and `..` resolved (not symbolic links)
fn full_path(p: &str) -> PathBuf {
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
    out
}

fn io_reason(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "Permission denied".into(),
        _ => e.to_string(),
    }
}

/// LogFiles: the hive's .LOG, .LOG1 and .LOG2 (any case, not empty) in its folder, by name
fn log_files(dirname: &str, hive_base: &str) -> Vec<String> {
    let mut logs = Vec::new();
    let Ok(entries) = std::fs::read_dir(dirname) else { return logs };
    let prefix = upper(&format!("{hive_base}.LOG"));
    let base_len = hive_base.encode_utf16().count();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let un = upper(&name);
        if !un.starts_with(&prefix) || name.encode_utf16().count() > base_len + 5 {
            continue;
        }
        let suffix = &un[prefix.len()..];
        if matches!(suffix, "" | "1" | "2") && entry.metadata().map(|m| m.len()).unwrap_or(0) > 0 {
            logs.push(Path::new(dirname).join(&name).to_string_lossy().into_owned());
        }
    }
    logs.sort_by_key(|a| upper(a));
    logs
}

fn sha1_hex(b: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(b).iter().map(|x| format!("{x:02X}")).collect()
}

fn read_hive_file(path: &str) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| {
        let message = match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                let full = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
                format!("Access to the path '{}' is denied.", full.display())
            }
            _ => e.to_string(),
        };
        Failure { message, access: true }
    })
}

impl Run {
    fn drain(&mut self, hive: &Hive) {
        for d in hive.take_messages() {
            self.log.log(d.level, &d.message);
        }
    }

    /// One hive: Ok(false) when it is skipped (a duplicate, or a key or value not found)
    fn process(&mut self, hive_path: &str, hive_read: &mut bool) -> Result<bool, Failure> {
        let bytes = read_hive_file(hive_path)?;
        if self.args.dedupe {
            let sha = sha1_hex(&bytes);
            if !self.seen_hashes.insert(sha.clone()) {
                self.log.debug(&format!("Skipping {hive_path} as a file with SHA-1 {sha} has already been processed"));
                return Ok(false);
            }
        }
        *hive_read = true;
        let mut hive = match Hive::new(bytes, hive_path) {
            Ok(h) => h,
            Err(e) => {
                if e.contains("bad signature") {
                    self.log.error("Data in byte array is not a Registry hive (bad signature)");
                }
                return Err(e.into());
            }
        };
        hive.recover_deleted = self.args.recover;

        let dirname = match Path::new(hive_path).parent().map(|p| p.to_string_lossy().into_owned()) {
            Some(p) if !p.is_empty() => p,
            _ => ".".to_string(),
        };
        let hive_base = Path::new(hive_path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let seq_differ = hive.header.primary_sequence_number != hive.header.secondary_sequence_number;
        let bad_checksum = !hive.header.checksum_ok();
        let logs = if seq_differ || bad_checksum { log_files(&dirname, &hive_base) } else { vec![] };
        if !seq_differ && bad_checksum && logs.is_empty() {
            self.log.warning(
                "The hive's header checksum is wrong and no transaction logs were found in the same directory. Continuing...",
            );
        }
        if seq_differ || bad_checksum && !logs.is_empty() {
            if logs.is_empty() {
                if !self.args.nl {
                    self.log.warning(
                        "Registry hive is dirty and no transaction logs were found in the same directory! LOGs should have same base name as the hive. Aborting!!",
                    );
                    return Err(DIRTY_NO_LOGS.to_string().into());
                }
                self.log.warning(
                    "Registry hive is dirty and no transaction logs were found in the same directory. Data may be missing! Continuing anyways...",
                );
            } else {
                if !seq_differ {
                    return Err("Sequence numbers match! Hive is not dirty".to_string().into());
                }
                let mut files = Vec::new();
                for l in &logs {
                    let b = read_hive_file(l)?;
                    if !b.is_empty() {
                        files.push(LogFile { name: l.clone(), bytes: b });
                    }
                }
                let r = hive.process_transaction_logs(files);
                self.drain(&hive);
                r?;
            }
        }
        let r = hive.parse();
        self.drain(&hive);
        r?;
        self.log.info("");

        let a = &self.args;
        let searching = [&a.sk, &a.sv, &a.sd, &a.ss].iter().any(|s| non_empty(s));
        if searching {
            self.search(&hive, hive_path)?;
        }
        if let Some(kn) = self.args.kn.clone().filter(|s| !s.is_empty()) {
            return self.key_dump(&hive, &kn);
        } else if self.args.min_size > 0 {
            self.search_used = true;
            let hits = hive.find_by_value_size(self.args.min_size);
            self.drain(&hive);
            self.size_hits(&hive, hive_path, hits?, self.args.min_size)?;
        } else if self.args.base64 > 0 {
            self.search_used = true;
            let hits = hive.find_base64(self.args.base64);
            self.drain(&hive);
            self.size_hits(&hive, hive_path, hits?, self.args.base64)?;
        } else if non_empty(&self.args.bn) {
            let batch = self.batch.take().unwrap();
            let r = self.process_batch(&hive, &batch);
            self.batch = Some(batch);
            self.drain(&hive);
            r?;
        }
        Ok(true)
    }

    fn deleted_suffix(hive: &Hive, k: KeyId) -> &'static str {
        if hive.is_deleted(k) { " (Deleted: True)" } else { "" }
    }

    fn search(&mut self, hive: &Hive, hive_path: &str) -> Result<(), Failure> {
        self.search_used = true;
        let regex = self.args.regex;
        let compile = |p: &str| -> Result<fancy_regex::Regex, Failure> {
            fancy_regex::Regex::new(&format!("(?i){p}")).map_err(|e| Failure::from(format!("Invalid pattern '{p}': {e}")))
        };
        let mut hits: Vec<SearchHit> = Vec::new();
        let (sk, sv, sd, ss) = (self.args.sk.clone(), self.args.sv.clone(), self.args.sd.clone(), self.args.ss.clone());
        if let Some(t) = sk.filter(|s| !s.is_empty()) {
            let re = if regex { Some(compile(&t)?) } else { None };
            hits.extend(hive.find_in_key_name(&t, re.as_ref()));
        }
        if let Some(t) = sv.filter(|s| !s.is_empty()) {
            let re = if regex { Some(compile(&t)?) } else { None };
            let r = hive.find_in_value_name(&t, re.as_ref());
            self.drain(hive);
            hits.extend(r?);
        }
        if let Some(t) = sd.clone().filter(|s| !s.is_empty()) {
            let re = if regex { Some(compile(&t)?) } else { None };
            let term_re = compile(&t).ok();
            let r = hive.find_in_value_data(&t, re.as_ref(), self.args.literal, term_re.as_ref());
            self.drain(hive);
            hits.extend(r?);
        }
        if let Some(t) = ss.clone().filter(|s| !s.is_empty()) {
            let re = if regex { Some(compile(&t)?) } else { None };
            let term_re = compile(&t).ok();
            let r = hive.find_in_value_slack(&t, re.as_ref(), self.args.literal, term_re.as_ref());
            self.drain(hive);
            hits.extend(r?);
        }
        if hits.is_empty() {
            self.log.info("\tNothing found");
        } else {
            let what = if hits.len() == 1 { "hit" } else { "hits" };
            let m = format!("\tFound {} search {what} in {hive_path}", n0(hits.len() as u64));
            self.log.info(&m);
            self.hive_info_with_hits.push(m);
            self.hives_with_hits += 1;
            self.total_hits += hits.len();
        }
        let has_sd = sd.is_some_and(|s| !s.is_empty());
        let has_ss = ss.is_some_and(|s| !s.is_empty());
        for h in &hits {
            let key = strip_root(&hive.keys[h.key].path);
            let del = Self::deleted_suffix(hive, h.key);
            let value_name = |v: Option<usize>| -> NetResult<String> {
                v.map(|v| hive.vks[v].name().map(str::to_string)).unwrap_or(Ok(String::new()))
            };
            let line = match h.location {
                HitType::KeyName => Some(format!("\tKey: {key}{del}")),
                HitType::ValueName => Some(format!("\tKey: {key}, Value: {}{del}", value_name(h.value)?)),
                HitType::ValueData | HitType::ValueSlack if self.args.nd => {
                    Some(format!("\tKey: {key}, Value: {}{del}", value_name(h.value)?))
                }
                HitType::ValueData => match h.value {
                    Some(v) if has_sd => {
                        let data = hive.value_data(v)?.text();
                        Some(format!("\tKey: {key}, Value: {}, Data: {data}{del}", value_name(h.value)?))
                    }
                    _ => None,
                },
                HitType::ValueSlack => match h.value {
                    Some(v) if has_ss => {
                        let slack = ez_common::net::hex(&hive.value_slack(v)?);
                        Some(format!("\tKey: {key}, Value: {}, Slack: {slack}{del}", value_name(h.value)?))
                    }
                    _ => None,
                },
            };
            self.drain(hive);
            if let Some(l) = line {
                self.log.info(&l);
            }
        }
        Ok(())
    }

    fn size_hits(&mut self, hive: &Hive, hive_path: &str, hits: Vec<(KeyId, usize)>, size: i32) -> Result<(), Failure> {
        if hits.is_empty() {
            self.log.info("Nothing found");
        } else {
            let what = if hits.len() == 1 { "hit" } else { "hits" };
            self.log.info(&format!(
                "Found {} search {what} with size greater or equal to {} bytes in {hive_path}",
                n0(hits.len() as u64),
                ez_common::dotnet::number_n(size as f64, 0)
            ));
            self.hives_with_hits += 1;
            self.total_hits += hits.len();
        }
        for (k, v) in hits {
            let raw = hive.value_raw(v)?;
            let d = format!(
                "Key: {}, Value: {}, Size: {}{}",
                strip_root(&hive.keys[k].path),
                hive.vks[v].name()?,
                n0(raw.len() as u64),
                Self::deleted_suffix(hive, k)
            );
            self.log.info(&d);
        }
        self.log.info("");
        Ok(())
    }

    /// --kn (and --vn, --saveTo, --json, --details)
    fn key_dump(&mut self, hive: &Hive, kn: &str) -> Result<bool, Failure> {
        self.search_used = true;
        let dt = self.args.dt.clone();
        let mut key = hive.get_key(kn);
        if key.is_none() && upper(kn) == "ROOT" {
            let root = hive.root.unwrap();
            self.log.info(&format!("\tUsing 'ROOT' alias. Actual ROOT key name: {}", hive.key_name(root)));
            key = Some(root);
        }
        let Some(k) = key else {
            self.log.warning(&format!("Key {kn} not found"));
            return Ok(false);
        };
        let mut value = None;
        if let Some(vn) = self.args.vn.clone().filter(|s| !s.is_empty()) {
            for &v in &hive.keys[k].values {
                if hive.vks[v].name()? == vn {
                    value = Some(v);
                    break;
                }
            }
            let Some(v) = value else {
                self.log.warning(&format!("Value {vn} not found for key {kn}"));
                return Ok(false);
            };
            if let Some(save_to) = self.args.save_to.clone().filter(|s| !s.is_empty()) {
                let base = Path::new(&save_to).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                if base.is_empty() {
                    return Err("The value cannot be an empty string. (Parameter 'path')".to_string().into());
                }
                if !Path::new(&base).is_dir() {
                    std::fs::create_dir_all(&base).map_err(|e| Failure::from(e.to_string()))?;
                }
                self.log.info(&format!("Saving contents of {} to {save_to}'", hive.vks[v].name()?));
                self.log.info("");
                let raw = hive.value_raw(v)?;
                if let Err(e) = std::fs::write(&save_to, raw) {
                    self.log.error(&format!("Save failed to {save_to}. Error: {e}"));
                    self.errors += 1;
                }
            }
        }
        let del = Self::deleted_suffix(hive, k);
        let path = strip_root(&hive.keys[k].path).to_string();
        let last_write = |k: KeyId| -> NetResult<String> { Ok(hive.nk(k).last_write()?.format(&dt)) };
        match value {
            None => {
                if let Some(json) = self.args.json.clone().filter(|s| !s.is_empty()) {
                    if !Path::new(&json).is_dir() {
                        std::fs::create_dir_all(&json).map_err(|e| Failure::from(e.to_string()))?;
                    }
                    let name = match self.args.jsonf.as_deref().filter(|s| !s.is_empty()) {
                        Some(f) => Path::new(f).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                        None => format!("{}.json", file_name_safe(hive.key_name(k))),
                    };
                    let out = Path::new(&json).join(name);
                    let r = details::key_json(hive, k).and_then(|j| {
                        self.log.info(&format!("Saving key to json file {}", out.display()));
                        self.log.info("");
                        std::fs::write(&out, j).map_err(|e| e.to_string())
                    });
                    if let Err(e) = r {
                        self.log.error(&format!("Error saving key {} to directory {json}: {e}", hive.keys[k].path));
                        self.errors += 1;
                    }
                }
                if self.args.details {
                    let text = details::key_text(hive, k);
                    self.drain(hive);
                    self.log.info(&text?);
                } else {
                    self.log.info(&format!("\tKey path: {path}{del}"));
                    self.log.info(&format!("\tLast write time: {}", last_write(k)?));
                    self.log.info("");
                    self.log.info(&format!("\tSubkey count: {}", n0(hive.keys[k].subkeys.len() as u64)));
                    self.log.info(&format!("\tValues count: {}", n0(hive.keys[k].values.len() as u64)));
                    self.log.info("");
                    for (i, &sk) in hive.keys[k].subkeys.iter().enumerate() {
                        let sdel = Self::deleted_suffix(hive, sk);
                        self.log.info(&format!("\t------------ Subkey #{}{sdel} ------------", n0(i as u64)));
                        self.log.info(&format!(
                            "\tName: {} (Last write: {}) Value count: {}",
                            hive.key_name(sk),
                            last_write(sk)?,
                            n0(hive.keys[sk].values.len() as u64)
                        ));
                        self.log.info("");
                    }
                    self.log.info("");
                    for (i, &v) in hive.keys[k].values.iter().enumerate() {
                        self.log.info(&format!("\t------------ Value #{}{del} ------------", n0(i as u64)));
                        self.log.info(&format!("\tName: {} ({})", hive.vks[v].name()?, hive.vks[v].type_name()));
                        let data = hive.value_data(v)?.text();
                        let slack = slack_text(&hive.value_slack(v)?);
                        self.drain(hive);
                        self.log.info(&format!("\tData: {data} {slack}"));
                        self.log.info("");
                    }
                }
            }
            Some(v) => {
                self.log.info(&format!("\tKey path: {path}{del}"));
                self.log.info(&format!("\tLast write time: {}", last_write(k)?));
                self.log.info("");
                self.log.info(&format!("\tValue name: {} ({})", hive.vks[v].name()?, hive.vks[v].type_name()));
                let data = hive.value_data(v)?.text();
                let slack = slack_text(&hive.value_slack(v)?);
                self.drain(hive);
                self.log.info(&format!("\tValue data: {data} {slack}"));
            }
        }
        self.log.info("");
        Ok(true)
    }

    /// ProcessBatch
    fn process_batch(&mut self, hive: &Hive, batch: &Batch) -> Result<(), Failure> {
        for key in batch.keys.as_deref().unwrap_or(&[]) {
            let key_path = key.key_path.as_deref().unwrap_or("");
            if hive.hive_type as i64 != key.hive_type {
                self.log.debug(&format!(
                    "Skipping key {key_path} because the current hive ({}) is not of the right type ({})",
                    hive.hive_type.name(),
                    key.hive_type_name()
                ));
                continue;
            }
            self.log.debug(&format!("Processing {key_path} (HiveType match)"));
            if key_path == "*" {
                let Some(root) = hive.root else { continue };
                self.batch_key(hive, root, key)?;
            } else if key_path.contains('*') {
                let paths = hive.expand_key_path(key_path);
                self.log.log(Level::Trace, &format!("Expanded {key_path} to {}", paths.join(" | ")));
                for p in paths {
                    let Some(k) = hive.get_key(&p) else {
                        self.log.warning(&format!("\tKey {p} not found in {}", hive.path));
                        continue;
                    };
                    let mut found_value = false;
                    if let Some(vn) = key.value_name.as_deref().filter(|s| !s.is_empty()) {
                        let want = upper(vn);
                        let mut found = None;
                        for &v in &hive.keys[k].values {
                            if upper(hive.vks[v].name()?) == want {
                                found = Some(v);
                                break;
                            }
                        }
                        if found.is_none() {
                            self.log.debug(&format!("\tValue {vn} not found in key {}", strip_root(&hive.keys[k].path)));
                            continue;
                        }
                        found_value = true;
                    }
                    if found_value {
                        self.log.info(&format!(
                            "Found key {} and value {}!",
                            strip_root(&hive.keys[k].path),
                            key.value_name.as_deref().unwrap_or("")
                        ));
                    } else {
                        self.log.info(&format!("Found key {}!", strip_root(&hive.keys[k].path)));
                    }
                    self.batch_key(hive, k, key)?;
                }
            } else {
                let Some(k) = hive.get_key(key_path) else {
                    self.log.debug(&format!("Key {key_path} not found in {}", hive.path));
                    continue;
                };
                self.batch_key(hive, k, key)?;
            }
        }
        Ok(())
    }

    /// ProcessBatchKey
    fn batch_key(&mut self, hive: &Hive, k: KeyId, key: &BatchKey) -> Result<(), Failure> {
        match key.value_name.as_deref().filter(|s| !s.is_empty()) {
            Some(vn) => {
                if batch::find_value(hive, k, vn)?.is_some() {
                    self.dump_key(hive, k, key)?;
                }
            }
            None => self.dump_key(hive, k, key)?,
        }
        if key.recursive {
            for &sk in &hive.keys[k].subkeys.clone() {
                self.batch_key(hive, sk, key)?;
            }
        }
        Ok(())
    }

    /// BatchDumpKey (no plugins are loaded: the values themselves)
    fn dump_key(&mut self, hive: &Hive, k: KeyId, key: &BatchKey) -> Result<(), Failure> {
        let mut values: Vec<Option<usize>> = Vec::new();
        if let Some(vn) = key.value_name.as_deref().filter(|s| !s.is_empty()) {
            let want = lower(vn);
            for &v in &hive.keys[k].values {
                if lower(hive.vks[v].name()?) == want {
                    values.push(Some(v));
                    break;
                }
            }
        } else if hive.keys[k].values.is_empty() {
            values.push(None);
        } else {
            values.extend(hive.keys[k].values.iter().map(|&v| Some(v)));
        }
        for v in values {
            let mut warnings = Vec::new();
            let row = batch::build_row(hive, k, key, v, &self.args.dt, &mut warnings);
            self.drain(hive);
            for w in warnings {
                self.log.warning(&w);
            }
            self.rows.push(row?);
        }
        Ok(())
    }
}

fn slack_text(slack: &[u8]) -> String {
    if slack.is_empty() { String::new() } else { format!("(Slack: {})", ez_common::net::hex(slack)) }
}

/// StripInvalidCharsFromFileName(name, "_") on Linux ('/' and NUL), then without NULs at the ends and '%'
fn file_name_safe(name: &str) -> String {
    name.replace(['/', '\0'], "_").trim_matches('\0').replace('%', "")
}

/// The batch CSV or JSON file
fn write_batch(args: &Args, bn: &str, rows: &[Row], run_time: Timestamp, log: &mut Logger) -> Result<(), String> {
    let stem = Path::new(bn).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let (dir, custom, ext) = if let Some(csv) = args.csv.as_deref().filter(|s| !s.is_empty()) {
        (csv, args.csvf.as_deref(), "csv")
    } else {
        (args.json.as_deref().unwrap_or(""), args.jsonf.as_deref(), "json")
    };
    if !Path::new(dir).is_dir() {
        log.info(&format!("Path to {dir} doesn't exist. Creating..."));
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let name = match custom.filter(|s| !s.is_empty()) {
        Some(f) => Path::new(f).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        None => format!("{}_RECmd_Batch_{stem}_Output.{ext}", run_time.format("yyyyMMddHHmmss")),
    };
    let out = Path::new(dir).join(name);
    log.info("");
    log.info(&format!("Saving batch mode {} file to {}", ext.to_uppercase(), out.display()));
    let mut text = String::new();
    if ext == "csv" {
        text.push_str(batch::CSV_HEADER);
        text.push_str(ez_common::csv::NEW_LINE);
        for r in rows {
            r.csv(&mut text, &args.dt);
        }
    } else {
        for r in rows {
            text.push_str(&r.json());
            text.push('\n');
        }
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out).map_err(|e| e.to_string())?);
    f.write_all(BOM).and_then(|_| f.write_all(text.as_bytes())).and_then(|_| f.flush()).map_err(|e| e.to_string())
}
