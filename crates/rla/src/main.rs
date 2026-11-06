//! rla: replays the transaction logs of dirty Registry hives and saves the hives, with the original's options and output.

mod names;

use std::collections::VecDeque;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::Level;
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_message, utc_now};
use ez_common::dotnet::{n0, number_n};
use ez_common::net::path_extension;
use registry_ez::hive::{Hive, fold};
use registry_ez::replay::LogFile;

use names::OutputNames;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NOT_A_HIVE: &str = "Data in byte array is not a Registry hive";
const REGF: &[u8; 4] = b"regf";

/// Replays the transaction logs of dirty Registry hives and saves the hives, with rla's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  rla -f '/cases/host1/UsrClass 1.dat' --out /tmp/out\n  rla -d /cases/host1 --out /tmp/out"
)]
struct Args {
    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    dir: Option<String>,

    /// Directory to save hives to, dirty ones with their transaction logs applied (see --ca)
    #[arg(long, value_name = "DIR")]
    out: Option<String>,

    /// When true, always copy hives to --out directory, even if they aren't dirty
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    ca: bool,

    /// When true and --nop is true, name profile based hives (NTUSER.DAT, UsrClass.dat) drive_profile_name, so they don't
    /// collide
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    cn: bool,

    /// When true, save hives directly in --out. When false, save them under their original path in --out (/cases/SAM as
    /// <out>/cases/SAM)
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nop: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_rla_<version>_ConsoleLog.txt in the --out directory. Use --co
    /// false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// File.Exists: anything there that isn't a folder (symbolic links are followed)
fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| !m.is_dir())
}

/// Why a hive could not be processed. `access`: it, its logs or the output could not be read or written (exit code 1),
/// as opposed to contents that are bad (exit code 0)
struct Failure {
    message: String,
    access: bool,
}

fn access_failure(path: &Path, e: &std::io::Error) -> Failure {
    Failure { message: io_message(path, e), access: true }
}

// What the original's Windows build looks for under -d: a hive can have any name holding one of these, as long as its
// signature says it is one. The original's Linux build only takes the exact names (NTUSER.DAT, SYSTEM...)
const NAME_PARTS: &[&str] = &["USRCLASS", "NTUSER", "SYSTEM", "SAM", "SOFTWARE", "AMCACHE", "SYSCACHE", "SECURITY", "DRIVERS", "DEFAULT", "COMPONENTS"];
const IGNORED_EXTENSIONS: &[&str] = &[".LOG1", ".LOG2", ".DLL", ".LOG", ".CSV", ".BLF", ".REGTRANS-MS", ".EXE", ".TXT", ".INI"];

/// Whether a file is a hive to process. One that can't be read counts, so that it is reported when it is processed
fn looks_like_hive(path: &Path, name: &str, log: &mut Logger) -> bool {
    let shown = path.display();
    let extension = path_extension(name);
    if IGNORED_EXTENSIONS.contains(&fold(extension).as_str()) {
        log.debug(&format!("Skipping {shown} since its extension ({extension}) is in ignoreMasks"));
        return false;
    }
    let upper = fold(name);
    if !NAME_PARTS.iter().any(|part| upper.contains(part)) {
        return false;
    }
    let mut signature = [0u8; 4];
    let read = std::fs::File::open(path).and_then(|mut f| {
        let n = f.read(&mut signature)?;
        Ok(n)
    });
    match read {
        Ok(4) if &signature == REGF => true,
        Ok(_) => {
            log.debug(&format!("Skipping {shown}: it does not have a hive's signature"));
            false
        }
        Err(_) => true,
    }
}

/// The hives in a folder and its subfolders: each folder's files in the order the file system gives them, subfolders
/// after. Symbolic links to folders aren't followed. Folders that can't be read are logged and returned as a count
fn find_hives(d: &str, log: &mut Logger) -> (Vec<String>, usize) {
    let mut found = Vec::new();
    let mut unreadable = Vec::new();
    let mut pending = VecDeque::from([Path::new(&full_path(d)).to_path_buf()]);
    while let Some(dir) = pending.pop_front() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                unreadable.push((dir, e));
                continue;
            }
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else { continue };
            let path = entry.path();
            if file_type.is_dir() {
                pending.push_back(path);
            } else if !path.is_dir() && looks_like_hive(&path, &entry.file_name().to_string_lossy(), log) {
                found.push(path.to_string_lossy().into_owned());
            }
        }
    }
    for (folder, e) in &unreadable {
        let reason = if e.kind() == std::io::ErrorKind::PermissionDenied { "Permission denied".to_string() } else { e.to_string() };
        log.error(&format!("Unable to read folder {}: {reason}", folder.display()));
    }
    (found, unreadable.len())
}

/// LogFiles: the hive's transaction logs (.LOG, .LOG1, .LOG2, in any case) next to it that aren't empty, by name. As the
/// original, a link's own size is what counts as empty
fn log_files(dirname: &str, hive_base: &str) -> Vec<String> {
    let prefix = fold(&format!("{hive_base}.LOG"));
    let mut logs: Vec<(String, String)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dirname) else { return vec![] };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let key = fold(&name);
        let is_log = key.strip_prefix(&prefix).is_some_and(|suffix| matches!(suffix, "" | "1" | "2"));
        if is_log && !path.is_dir() && entry.metadata().is_ok_and(|m| m.len() > 0) {
            logs.push((key, path.to_string_lossy().into_owned()));
        }
    }
    logs.sort_by(|a, b| a.0.cmp(&b.0));
    logs.into_iter().map(|(_, path)| path).collect()
}

fn drain(hive: &Hive, log: &mut Logger) {
    for d in hive.take_messages() {
        log.log(d.level, &d.message);
    }
}

/// Applies the logs of a dirty hive: its bytes then are the result (unchanged when no log could be applied)
fn apply_logs(hive: &mut Hive, logs: &[String], log: &mut Logger) -> Result<(), Failure> {
    // ProcessTransactionLogs for a list of files. This comes first there, so a hive that is only dirty because of its
    // checksum isn't replayed
    if hive.header.primary_sequence_number == hive.header.secondary_sequence_number {
        return Err(Failure { message: "Sequence numbers match! Hive is not dirty".into(), access: false });
    }
    let mut files = Vec::new();
    for name in logs {
        let bytes = std::fs::read(name).map_err(|e| access_failure(Path::new(name), &e))?;
        if !bytes.is_empty() {
            files.push(LogFile { name: name.clone(), bytes });
        }
    }
    let result = hive.process_transaction_logs(files);
    drain(hive, log);
    result.map_err(|message| Failure { message, access: false })
}

/// What the loop counts for one hive
enum Outcome {
    Done,
    /// Not saved, without that being a failure
    Skipped,
    Failed { access: bool },
}

struct Run<'a> {
    args: &'a Args,
    out: &'a str,
    names: OutputNames,
}

impl Run<'_> {
    fn process(&mut self, hive_path: &str, log: &mut Logger) -> Outcome {
        let bytes = match std::fs::read(hive_path) {
            Ok(b) => b,
            Err(e) => return error_processing(hive_path, access_failure(Path::new(hive_path), &e), log),
        };
        let mut hive = match Hive::new(bytes, hive_path) {
            Ok(h) => h,
            Err(message) => {
                if message.contains(NOT_A_HIVE) {
                    log.error(&message);
                    // a file in -d with a hive's name that isn't one
                    if given(&self.args.file).is_none() {
                        log.debug(&format!("\tSkipping {hive_path}: {message}"));
                        return Outcome::Skipped;
                    }
                }
                return error_processing(hive_path, Failure { message, access: false }, log);
            }
        };

        let path = Path::new(hive_path);
        let dirname = path.parent().map(|p| p.to_string_lossy().into_owned()).filter(|p| !p.is_empty()).unwrap_or_else(|| ".".into());
        let hive_base = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

        // dirty: the sequence numbers differ, or the header's checksum is wrong and there are logs to take it from
        let logs = log_files(&dirname, &hive_base);
        let sequence_differs = hive.header.primary_sequence_number != hive.header.secondary_sequence_number;
        let dirty = sequence_differs || !hive.header.checksum_ok() && !logs.is_empty();
        let ca = self.args.ca;

        if dirty && logs.is_empty() {
            if !ca {
                log.info(&format!(
                    "\tHive {hive_path} is dirty and no transaction logs were found in the same directory. --ca is false. Skipping..."
                ));
                // the hive is not bad, its logs are missing (give them, or use --ca): exit code 1
                return Outcome::Failed { access: true };
            }
            log.info(&format!("\tHive {hive_path} is dirty, but no logs were found in the same directory. --ca is true. Copying..."));
        } else if dirty {
            if let Err(f) = apply_logs(&mut hive, &logs, log) {
                log.error(&format!("\tTransaction logs for {hive_path} could not be applied: {}", f.message));
                return Outcome::Failed { access: f.access };
            }
        } else if ca {
            log.info(&format!("\tHive {hive_path} is not dirty, but --ca is True. Copying..."));
        } else {
            log.info(&format!("\tHive {hive_path} is not dirty and --ca is False. Skipping..."));
            return Outcome::Skipped;
        }

        // the path under --out, with a number when another hive in this run got the same name
        let out_file = self.names.get(hive_path, self.out, self.args.nop, self.args.cn);
        log.info(&format!("\tSaving updated hive to {out_file}"));
        match save(&out_file, &hive.bytes) {
            Ok(()) => Outcome::Done,
            Err(f) => error_processing(hive_path, f, log),
        }
    }
}

fn save(out_file: &str, bytes: &[u8]) -> Result<(), Failure> {
    let out_path = Path::new(out_file);
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty() && !p.is_dir()) {
        std::fs::create_dir_all(parent).map_err(|e| access_failure(parent, &e))?;
    }
    std::fs::write(out_path, bytes).map_err(|e| access_failure(out_path, &e))
}

fn error_processing(hive_path: &str, failure: Failure, log: &mut Logger) -> Outcome {
    log.error(&format!("\tThere was an error processing {hive_path}: {}", failure.message));
    Outcome::Failed { access: failure.access }
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
    let mut log = Logger::new(level, "").to_stdout();

    let out_for_log = args.out.as_deref().filter(|o| !o.trim().is_empty() && args.co);
    let console_log = out_for_log.map(|o| Path::new(&full_path(o)).join(format!("{}_rla_{VERSION}_ConsoleLog.txt", utc_now().format("yyyyMMddHHmmss"))));
    if let Some(path) = &console_log {
        // as the original's log file: it isn't an error if it can't be made
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }

    let file = given(&args.file);
    let dir = given(&args.dir);
    let out = given(&args.out);
    if (file.is_some() || dir.is_some()) && out.is_none() {
        let _ = Args::command().print_long_help();
        println!();
        log.warning("--out is required. Exiting");
        log.blank();
        return ExitCode::FAILURE;
    }

    log.blank();
    log.info(&format!("rla (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let mut hives = Vec::new();
    let mut unreadable = 0;
    if let Some(f) = file {
        if !file_exists(f) {
            log.error(&format!("File {f} does not exist"));
            log.blank();
            return ExitCode::FAILURE;
        }
        hives.push(f.to_string());
    } else if let Some(d) = dir {
        if !Path::new(d).is_dir() {
            log.error(&format!("Directory {d} does not exist"));
            log.blank();
            return ExitCode::FAILURE;
        }
        let out = out.unwrap_or_default();
        if !Path::new(out).is_dir() {
            log.info(&format!("Creating --out directory {out}..."));
            if let Err(e) = std::fs::create_dir_all(out) {
                log.error(&io_message(Path::new(out), &e));
                log.blank();
                return ExitCode::FAILURE;
            }
        } else if args.cn && has_files(out) {
            log.warning(&format!("{out} contains files! This may cause --cn to revert back to uncompressed names. Ideally, {out} should be empty"));
            log.blank();
        }
        log.info(&format!("Searching {d} for hives..."));
        (hives, unreadable) = find_hives(d, &mut log);
        log.info(&format!("\tHives found: {}", n0(hives.len() as u64)));
    } else {
        let _ = Args::command().print_long_help();
        return ExitCode::FAILURE;
    }

    if hives.is_empty() {
        log.warning("No hives were found. Exiting...");
        return if unreadable > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS };
    }

    let start = Instant::now();
    let mut run = Run { args: &args, out: out.unwrap_or_default(), names: OutputNames::default() };
    let mut failed = 0u64;
    let mut access_failed = 0u64;
    for hive in &hives {
        log.blank();
        log.info(&format!("Processing hive {hive}"));
        if !file_exists(hive) {
            log.warning(&format!("{hive} does not exist. Skipping"));
            continue;
        }
        if let Outcome::Failed { access } = run.process(hive, &mut log) {
            failed += 1;
            access_failed += u64::from(access);
        }
    }

    log.blank();
    log.info(&format!("Total processing time: {} seconds", number_n(start.elapsed().as_secs_f64(), 3)));
    log.blank();
    if failed > 0 {
        log.warning(&format!("{} hive(s) could not be processed", n0(failed)));
        log.blank();
    }
    if access_failed > 0 || unreadable > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// Directory.GetFiles(folder).Length > 0
fn has_files(folder: &str) -> bool {
    std::fs::read_dir(folder).is_ok_and(|mut entries| entries.any(|e| e.is_ok_and(|e| !e.path().is_dir())))
}
