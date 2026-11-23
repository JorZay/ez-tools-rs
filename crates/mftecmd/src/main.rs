//! mftecmd: NTFS metadata files ($MFT, $J, $LogFile, $Boot, $SDS, $I30) to CSV, JSON and bodyfile, as MFTECmd
//! writes them.

mod dump;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, Parser};
use ez_common::Level;
use ez_common::cli::BOM;
use ez_common::cli::log::Logger;
use ez_common::dotnet::n0;
use ez_common::time::Timestamp;
use ntfs_ez::mft::{Mft, export};
use rayon::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SDS_SIG: i32 = 0x32FEC6CBu32 as i32;

/// Parses NTFS metadata files ($MFT, $J, $LogFile, $Boot, $SDS, $I30) into CSV, JSON and bodyfile, with MFTECmd's
/// options and output.
#[derive(Parser, Debug)]
#[command(version, after_help = "Examples:\n  mftecmd -f '/cases/C/$MFT' --csv out\n  mftecmd -f '/cases/C/$J' -m '/cases/C/$MFT' --csv out\n  mftecmd -f '/cases/C/$MFT' --body out --bdl c")]
struct Args {
    /// File to process ($MFT | $J | $LogFile | $Boot | $SDS | $I30). This or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<PathBuf>,

    /// Directory to search recursively for $MFT files (named $MFT*). All of them go into one CSV/JSON/bodyfile, with
    /// SourceFile saying which $MFT each row is from
    #[arg(short = 'd', value_name = "DIR")]
    dir: Option<PathBuf>,

    /// $MFT file to use when -f points to a $J, $LogFile or $I30 file, to resolve parent paths. For $J, the paths are
    /// as they were when each record was written
    #[arg(short = 'm', value_name = "FILE")]
    mft: Option<PathBuf>,

    /// When true, do not write CSV, JSON or bodyfile output for the $MFT specified with -m (it is only used for the
    /// paths)
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    mno: bool,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<PathBuf>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// Directory to save JSON formatted results to
    #[arg(long, value_name = "DIR")]
    json: Option<PathBuf>,

    /// File name to save JSON formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    jsonf: Option<String>,

    /// Directory to save bodyfile formatted results to. --bdl is also required
    #[arg(long, value_name = "DIR")]
    body: Option<PathBuf>,

    /// File name to save body formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    bodyf: Option<String>,

    /// Drive letter (C, D, etc.) to use with bodyfile
    #[arg(long, value_name = "LETTER")]
    bdl: Option<String>,

    /// Use LF vs CRLF for newlines in the bodyfile
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    blf: bool,

    /// Directory to save an exported $MFT FILE record to. --do is also required
    #[arg(long, value_name = "DIR")]
    dd: Option<PathBuf>,

    /// Offset of the $MFT FILE record to dump, as decimal or hex (5120 or 0x1400)
    #[arg(long = "do", value_name = "OFFSET")]
    dump_offset: Option<String>,

    /// Dump full details for $MFT entry/sequence #: 'Entry' or 'Entry-Seq', decimal or hex (5, 624-5, 0x270-0x5)
    #[arg(long, value_name = "ENTRY")]
    de: Option<String>,

    /// Dump $MFT resident files to the 'Resident' subdirectory of --json or --csv
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    dr: bool,

    /// With --de on a directory, also list its contents
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    fls: bool,

    /// Dump full details for a Security Id from $SDS, as decimal or hex (624 or 0x270)
    #[arg(long, value_name = "ID")]
    ds: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, value_name = "FORMAT", default_value = "yyyy-MM-dd HH:mm:ss.fffffff")]
    dt: String,

    /// Include DOS file name types in $MFT output
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    sn: bool,

    /// Generate condensed file listing of parsed $MFT contents. Requires --csv
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    fl: bool,

    /// Include all timestamps from 0x30 attribute vs only when they differ from 0x10 in the $MFT
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    at: bool,

    /// Recover slack space from FILE records when processing $MFT files
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    rs: bool,

    /// Include resident data in JSON/CSV output
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    ir: bool,

    /// Comma-separated list of extensions to include for resident data (e.g., '.txt,.ps1,.bat'). If omitted, includes all
    #[arg(long, value_name = "EXTS")]
    re: Option<String>,

    /// Maximum size in bytes for resident data to include (max: 1024000)
    #[arg(long, value_name = "BYTES", default_value_t = 1024)]
    rm: i32,

    /// Only include $MFT records whose $STANDARD_INFO created or modified time is on or after this (UTC unless an offset is given)
    #[arg(long, value_name = "DATE")]
    cutoff: Option<String>,

    /// Not supported (live systems only); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL", hide = true)]
    vss: bool,

    /// Not supported (live systems only); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL", hide = true)]
    dedupe: bool,

    /// Not needed (a .NET memory setting); ignored
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL", hide = true)]
    lowmem: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// Save all console messages to <timestamp>_MFTECmd_<version>_ConsoleLog.txt in the output directory. Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Mft,
    LogFile,
    UsnJournal,
    Boot,
    Sds,
    I30,
    Unknown,
}

impl FileType {
    fn name(self) -> &'static str {
        match self {
            FileType::Mft => "Mft",
            FileType::LogFile => "LogFile",
            FileType::UsnJournal => "UsnJournal",
            FileType::Boot => "Boot",
            FileType::Sds => "Sds",
            FileType::I30 => "I30",
            FileType::Unknown => "Unknown",
        }
    }
}

/// GetFileType: the type from the first 50 bytes. Err(true) for an empty file (exit 0), Err(false) for one that
/// could not be read (exit 1).
fn file_type(path: &Path, log: &mut Logger) -> Result<FileType, bool> {
    let mut buf = Vec::with_capacity(50);
    match File::open(path) {
        Ok(f) => {
            use std::io::Read;
            if let Err(e) = f.take(50).read_to_end(&mut buf) {
                log.error(&format!("\nError opening file {}. Does it exist? Error: {e} Exiting\n", path.display()));
                return Err(false);
            }
        }
        Err(e) => {
            log.error(&format!("\nError opening file {}. Does it exist? Error: {e} Exiting\n", path.display()));
            return Err(false);
        }
    }
    if buf.len() < 20 {
        log.info(&format!("\nNot enough data found in {}. Is the file empty? Exiting\n", path.display()));
        return Err(true);
    }
    let i32_at = |o: usize| i32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let i16_at = |o: usize| i16::from_le_bytes([buf[o], buf[o + 1]]);
    let (major, minor) = (i16_at(4), i16_at(6));
    Ok(match i32_at(0) {
        0x58444e49 => FileType::I30,
        0x52545352 | 0x444B4843 => FileType::LogFile,
        0x454C4946 => FileType::Mft,
        SDS_SIG => FileType::Sds,
        0 => {
            if major != 0 || minor != 0 {
                FileType::Unknown
            } else {
                FileType::UsnJournal
            }
        }
        _ => {
            if i32_at(3) == 0x5346544E {
                FileType::Boot
            } else if major == 2 && minor == 0 {
                FileType::UsnJournal
            } else if u64::from_le_bytes(buf[8..16].try_into().unwrap()) == 0 {
                FileType::Sds
            } else {
                FileType::Unknown
            }
        }
    })
}

/// ERZHelpers' BytesToSizeAsString
fn size_string(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let s = format!("{:.1}", v);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    format!("{s}{}", UNITS[i])
}

fn main() -> ExitCode {
    let args = match ez_common::cli::parse_args::<Args>() {
        Ok(a) => a,
        Err(code) => return code,
    };
    match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

struct Run {
    args: Args,
    log: Logger,
    run_time: Timestamp,
    cutoff: Option<Timestamp>,
    /// The $MFT loaded (for -m)
    mft: Option<Mft>,
    /// --csvf, --jsonf and --bodyf name the output of -f; a -m $MFT keeps the default names
    custom_names: bool,
}

fn create_dir(dir: &Path, option: &str, log: &mut Logger) -> bool {
    if dir.is_dir() {
        return true;
    }
    log.info(&format!("Path to {} doesn't exist. Creating...", dir.display()));
    if let Err(e) = std::fs::create_dir_all(dir) {
        log.error(&format!("Unable to create directory {} ({option}). Does a file with the same name exist? Exiting: {e}", dir.display()));
        return false;
    }
    true
}

fn run(args: Args) -> Result<ExitCode, String> {
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
        let dir = [&args.csv, &args.json, &args.body, &args.dd].into_iter().flatten().next();
        if let Some(dir) = dir {
            if std::fs::create_dir_all(dir).is_ok() {
                let p = dir.join(format!("{}_MFTECmd_{VERSION}_ConsoleLog.txt", run_time.format("yyyyMMddHHmmss")));
                let _ = log.open_file(&p);
            }
        }
    }

    if args.file.is_none() && args.dir.is_none() {
        return Err("-f or -d is required. Exiting (see --help)".into());
    }
    if args.file.is_some() && args.dir.is_some() {
        return Err("-f and -d can't be used together. Exiting".into());
    }
    if let Some(d) = &args.dir {
        if !d.is_dir() {
            log.warning(&format!("Directory {} not found. Exiting", d.display()));
            return Ok(ExitCode::FAILURE);
        }
    }
    if args.mno && args.mft.is_none() {
        return Err("--mno requires -m. Exiting".into());
    }
    let file = args.file.clone().unwrap_or_default();
    if args.dir.is_none() && !file.exists() {
        log.warning(&format!("File {} not found. Exiting", file.display()));
        return Ok(ExitCode::FAILURE);
    }

    log.info(&format!(
        "mftecmd version {VERSION} (a Rust port of MFTECmd)\n\nMFTECmd: Eric Zimmerman (saericzimmerman@gmail.com)\nhttps://github.com/EricZimmerman/MFTECmd\n"
    ));
    log.info(&format!("Command line: {}\n", std::env::args().skip(1).collect::<Vec<_>>().join(" ")));
    if let Some(p) = log.file_path() {
        log.info(&format!("Console log: {}\n", p.display()));
    }
    for (flag, on) in [("--vss", args.vss), ("--dedupe", args.dedupe), ("--lowmem", args.lowmem)] {
        if on {
            log.warning(&format!("{flag} is not supported by this version (it is for live systems); ignored\n"));
        }
    }

    let cutoff = match &args.cutoff {
        Some(s) => match Timestamp::parse(s) {
            Some(t) => Some(t),
            None => return Err(format!("Cannot parse argument '{s}' for option '--cutoff'")),
        },
        None => None,
    };

    if let Some(d) = args.dir.clone() {
        let mut r = Run { args, log, run_time, cutoff, mft: None, custom_names: true };
        return process_mft_directory(&mut r, &d);
    }

    let ft = match file_type(&file, &mut log) {
        Ok(t) => t,
        Err(empty) => return Ok(if empty { ExitCode::SUCCESS } else { ExitCode::FAILURE }),
    };
    log.info(&format!("File type: {}\n", ft.name()));

    let mut r = Run { args, log, run_time, cutoff, mft: None, custom_names: true };
    let ok = match ft {
        FileType::Mft => {
            let a = &r.args;
            if a.csv.is_none() && a.json.is_none() && a.de.is_none() && a.body.is_none() && a.dd.is_none() {
                return Err("--csv, --json, --body, --dd, or --de is required. Exiting".into());
            }
            if a.body.is_some() && a.bdl.as_deref().is_none_or(str::is_empty) {
                return Err("--bdl is required when using --body. Exiting".into());
            }
            if a.dump_offset.is_some() && a.dd.is_none() {
                return Err("--dd option missing. Exiting".into());
            }
            if a.dd.is_some() && a.dump_offset.is_none() {
                return Err("--do is required when using --dd. Exiting".into());
            }
            let out = MftOut::from_args(&r.args);
            process_mft(&mut r, &file, &out)
        }
        FileType::Boot => process_boot(&mut r, &file),
        FileType::UsnJournal | FileType::LogFile => {
            if r.args.csv.is_none() && r.args.json.is_none() {
                return Err("--csv or --json is required. Exiting".into());
            }
            let mut ok = true;
            if let Some(m) = r.args.mft.clone() {
                match load_mft_for_paths(&mut r, &m) {
                    Ok(loaded) => ok &= loaded,
                    Err(code) => return Ok(code),
                }
            }
            if ft == FileType::UsnJournal {
                ok &= process_j(&mut r, &file);
            } else {
                ok &= process_logfile(&mut r, &file);
            }
            ok
        }
        FileType::Sds => {
            if r.args.csv.is_none() && r.args.json.is_none() && r.args.ds.is_none() {
                return Err("--csv, --json or --ds is required. Exiting".into());
            }
            process_sds(&mut r, &file)
        }
        FileType::I30 => {
            if r.args.csv.is_none() && r.args.json.is_none() {
                return Err("--csv or --json is required. Exiting".into());
            }
            let mut ok = true;
            if let Some(m) = r.args.mft.clone() {
                // the $MFT gives the parent paths (issue #194)
                match load_mft_for_paths(&mut r, &m) {
                    Ok(loaded) => ok &= loaded,
                    Err(code) => return Ok(code),
                }
            }
            ok & process_i30(&mut r, &file)
        }
        FileType::Unknown => {
            r.log.error(&format!("Unknown file type! Send {} to saericzimmerman@gmail.com for assistance. Exiting", file.display()));
            true
        }
    };
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn out_name(r: &Run, dir: &Path, custom: &Option<String>, kind: &str, ext: &str) -> PathBuf {
    match custom.as_deref().filter(|s| !s.is_empty()) {
        Some(name) => dir.join(Path::new(name).file_name().unwrap_or_default()),
        None => dir.join(format!("{}_MFTECmd_{kind}_Output.{ext}", r.run_time.format("yyyyMMddHHmmss"))),
    }
}

fn open_out(path: &Path, bom: bool) -> std::io::Result<BufWriter<File>> {
    let mut w = BufWriter::with_capacity(1 << 20, File::create(path)?);
    if bom {
        w.write_all(BOM)?;
    }
    Ok(w)
}

/// Where an $MFT's outputs go
struct MftOut {
    csv: Option<PathBuf>,
    json: Option<PathBuf>,
    body: Option<PathBuf>,
    /// --dr: the Resident folder
    resident: Option<PathBuf>,
}

impl MftOut {
    fn from_args(a: &Args) -> MftOut {
        MftOut {
            csv: a.csv.clone(),
            json: a.json.clone(),
            body: a.body.clone(),
            resident: a.dr.then(|| a.json.clone().or(a.csv.clone()).map(|d| d.join("Resident"))).flatten(),
        }
    }
}

/// LoadMftForPaths: the $MFT given with -m, which gives the paths for $J, $LogFile and $I30. It is exported too, with
/// its default names (--csvf/--jsonf/--bodyf are for -f), unless --mno is given. Ok(false) when its export failed;
/// Err with the exit code to stop with.
fn load_mft_for_paths(r: &mut Run, m: &Path) -> Result<bool, ExitCode> {
    if !m.exists() {
        r.log.error(&format!("MFT file {} does not exist! Verify path and try again. Exiting\n", m.display()));
        return Err(ExitCode::FAILURE);
    }
    match file_type(m, &mut r.log) {
        Ok(FileType::Mft) => {}
        other => {
            r.log.error(&format!("File {} is not an MFT file!! Verify path and try again. Exiting", m.display()));
            return Err(if matches!(other, Err(false)) { ExitCode::FAILURE } else { ExitCode::SUCCESS });
        }
    }
    let mut out = MftOut::from_args(&r.args);
    if r.args.mno {
        (out.csv, out.json, out.body) = (None, None, None);
    }
    r.custom_names = false;
    let ok = process_mft(r, m, &out);
    r.custom_names = true;
    if r.mft.is_none() {
        // the $MFT could not be loaded: 1 when it could not be read, 0 when it is damaged
        return Err(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE });
    }
    Ok(ok)
}

/// -d (issue #109): every $MFT under `d` into one output of each kind. Each is processed into a numbered folder of a
/// temporary folder in each output folder, then the outputs are joined by file name (CSVs keep one header line).
fn process_mft_directory(r: &mut Run, d: &Path) -> Result<ExitCode, String> {
    let a = &r.args;
    if a.csv.is_none() && a.json.is_none() && a.body.is_none() {
        return Err("--csv, --json or --body is required with -d. Exiting".into());
    }
    if a.body.is_some() && a.bdl.as_deref().is_none_or(str::is_empty) {
        return Err("--bdl is required when using --body. Exiting".into());
    }
    for (used, name) in [(a.mft.is_some(), "-m"), (a.vss, "--vss"), (a.de.is_some(), "--de"), (a.dd.is_some(), "--dd"), (a.dr, "--dr")] {
        if used {
            return Err(format!("{name} can't be used with -d. Exiting"));
        }
    }

    let (candidates, folder_errors) = find_mft_files(d);
    for e in &folder_errors {
        r.log.error(e);
    }
    let mut mft_files = Vec::new();
    for c in candidates {
        match file_type(&c, &mut r.log) {
            Ok(FileType::Mft) => mft_files.push(c),
            Ok(t) => r.log.warning(&format!("Skipping {}: not an $MFT ({})", c.display(), t.name())),
            Err(_) => r.log.warning(&format!("Skipping {}: not an $MFT (unknown, empty or unreadable)", c.display())),
        }
    }
    r.log.info(&format!("Found {} under {}", plural(mft_files.len(), "$MFT file"), d.display()));
    r.log.info("");
    if mft_files.is_empty() {
        // nothing to do is not a failure of the tool; a folder that could not be read is
        return Ok(if folder_errors.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE });
    }

    let run_time = r.run_time.format("yyyyMMddHHmmss");
    let temp_root = |dir: &Path| dir.join(format!(".MFTECmd_{run_time}_d"));
    let mut out_dirs: Vec<PathBuf> = Vec::new();
    for dir in [&r.args.csv, &r.args.json, &r.args.body].into_iter().flatten() {
        let full = std::path::absolute(dir).unwrap_or_else(|_| dir.clone());
        if !out_dirs.iter().any(|o| ez_common::dotnet::ordinal_ignore_case(&o.to_string_lossy()) == ez_common::dotnet::ordinal_ignore_case(&full.to_string_lossy())) {
            out_dirs.push(full);
        }
    }

    let mut ok = folder_errors.is_empty();
    let count = mft_files.len();
    for (i, f) in mft_files.iter().enumerate() {
        r.log.info(&format!("Processing {} ({} of {count})...", f.display(), i + 1));
        let part = |dir: &Option<PathBuf>| dir.as_ref().map(|d| temp_root(d).join(format!("{i:04}")));
        let out = MftOut { csv: part(&r.args.csv), json: part(&r.args.json), body: part(&r.args.body), resident: None };
        ok &= process_mft(r, f, &out);
        r.mft = None;
    }

    r.log.info("");
    let mut combine = || -> std::io::Result<()> {
        for dir in &out_dirs {
            for joined in combine_parts(&temp_root(dir), dir)? {
                r.log.info(&format!("Output for all {}: {}", plural(count, "$MFT"), joined.display()));
            }
        }
        Ok(())
    };
    if let Err(e) = combine() {
        r.log.error(&format!("Error writing the combined output: {e}"));
        ok = false;
    }
    for dir in &out_dirs {
        let root = temp_root(dir);
        if root.is_dir() {
            if let Err(e) = std::fs::remove_dir_all(&root) {
                r.log.warning(&format!("Could not delete the temporary folder {}: {e}", root.display()));
            }
        }
    }
    r.log.info("");
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn plural(count: usize, one: &str) -> String {
    if count == 1 { format!("1 {one}") } else { format!("{} {one}s", n0(count as u64)) }
}

/// Files under `dir` named $MFT* (not $MFTMirr), sorted (OrdinalIgnoreCase); and the folders that could not be read
fn find_mft_files(dir: &Path) -> (Vec<PathBuf>, Vec<String>) {
    use ez_common::dotnet::ordinal_ignore_case;
    let mut found = Vec::new();
    let mut errors = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = match std::fs::read_dir(&current).and_then(|rd| rd.collect::<std::io::Result<Vec<_>>>()) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("Unable to read folder {}: {e}", current.display()));
                continue;
            }
        };
        for e in entries {
            let path = e.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let name = ordinal_ignore_case(&e.file_name().to_string_lossy());
            if name.starts_with("$MFT") && !name.starts_with("$MFTMIRR") {
                found.push(path);
            }
        }
    }
    found.sort_by_cached_key(|p| ordinal_ignore_case(&p.to_string_lossy()).encode_utf16().collect::<Vec<u16>>());
    (found, errors)
}

/// Joins the files in each of `temp_root`'s numbered folders into `out_dir`, by file name (OrdinalIgnoreCase, in
/// that order), in folder order. CSVs keep only the first file's header line (the rest are copied from after their
/// first LF). Returns the joined files.
fn combine_parts(temp_root: &Path, out_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    use ez_common::dotnet::ordinal_ignore_case;
    use std::collections::BTreeMap;
    let mut joined = Vec::new();
    if !temp_root.is_dir() {
        return Ok(joined);
    }
    let mut parts: Vec<PathBuf> = std::fs::read_dir(temp_root)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    parts.sort_by_key(|p| p.to_string_lossy().encode_utf16().collect::<Vec<u16>>());
    let mut by_name: BTreeMap<Vec<u16>, (String, Vec<PathBuf>)> = BTreeMap::new();
    for part in parts {
        for e in std::fs::read_dir(&part)? {
            let path = e?.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            by_name.entry(ordinal_ignore_case(&name).encode_utf16().collect()).or_insert_with(|| (name, Vec::new())).1.push(path);
        }
    }
    for (_, (name, files)) in by_name {
        let target = out_dir.join(&name);
        let is_csv = ordinal_ignore_case(&name).ends_with(".CSV");
        let mut output = BufWriter::new(File::create(&target)?);
        for (i, f) in files.iter().enumerate() {
            let data = std::fs::read(f)?;
            let start = if i > 0 && is_csv { data.iter().position(|&b| b == b'\n').map_or(data.len(), |p| p + 1) } else { 0 };
            output.write_all(&data[start..])?;
        }
        output.flush()?;
        joined.push(target);
    }
    Ok(joined)
}

/// ProcessMft: loads the $MFT (kept in r.mft) and writes its outputs; false when it could not be read or an export
/// failed
fn process_mft(r: &mut Run, file: &Path, out: &MftOut) -> bool {
    let sw = Instant::now();
    let load = ntfs_ez::mft::LoadOptions { recover_slack: r.args.rs, date_format: r.args.dt.clone() };
    let mft = match Mft::open_with(file, &load) {
        Ok(m) => m,
        Err(e) => {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return matches!(e, ntfs_ez::mft::Error::Invalid(_));
        }
    };
    for w in &mft.warnings {
        r.log.warning(w);
    }
    r.log.info(&format!("Processed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let ok = mft_outputs(r, &mft, file, out);
    r.mft = Some(mft);
    ok
}

fn custom(r: &Run, name: &Option<String>) -> Option<String> {
    if r.custom_names { name.clone() } else { None }
}

fn mft_outputs(r: &mut Run, mft: &Mft, file: &Path, outs: &MftOut) -> bool {

    let source = file.to_string_lossy().into_owned();
    r.log.info(&format!(
        "{source}: FILE records found: {} (Free records: {}) File size: {}",
        n0(mft.in_use.len() as u64),
        n0(mft.free.len() as u64),
        size_string(mft.file_size())
    ));
    if !mft.damaged.is_empty() {
        r.log.warning(&format!(
            "{source}: {} FILE record(s) have damaged attributes; the rest of each record was used. See the ParseErrors column, or use --debug",
            n0(mft.damaged.len() as u64)
        ));
        for &b in &mft.damaged {
            let fr = mft.record(b);
            r.log.debug(&format!(
                "  Entry/seq 0x{:X}-0x{:X} at offset 0x{:X}: {}",
                fr.entry_number,
                fr.sequence_number,
                fr.offset,
                fr.parse_errors.join("; ")
            ));
        }
    }
    if let Some(c) = r.cutoff {
        r.log.info(&format!("Only including records created or modified on or after {} (--cutoff)", c.format("yyyy-MM-dd HH:mm:ss")));
    }

    let a = &r.args;
    let dt = a.dt.clone();
    let mut exported = true;

    let mut body = None;
    if let Some(dir) = outs.body.clone() {
        if !create_dir(&dir, "--body", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &custom(r, &r.args.bodyf), "$MFT", "body");
        r.log.info(&format!("\tBodyfile output will be saved to {}", p.display()));
        match open_out(&p, true) {
            Ok(w) => body = Some(w),
            Err(e) => {
                r.log.error(&format!("\nError setting up bodyfile export. Error: {e}"));
                exported = false;
            }
        }
    }
    let mut csv = None;
    let mut listing = None;
    if let Some(dir) = outs.csv.clone() {
        if !create_dir(&dir, "--csv", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &custom(r, &r.args.csvf), "$MFT", "csv");
        r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
        if r.args.fl {
            let fl = if custom(r, &r.args.csvf).as_deref().is_some_and(|s| !s.is_empty()) {
                let stem = p.file_stem().unwrap_or_default().to_string_lossy();
                let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
                p.with_file_name(format!("{stem}_FileListing{ext}"))
            } else {
                PathBuf::from(p.to_string_lossy().replace("$MFT_Output", "$MFT_Output_FileListing"))
            };
            r.log.info(&format!("\tCSV file listing output will be saved to {}", fl.display()));
            match open_out(&fl, true).and_then(|mut w| w.write_all(export::FILE_LISTING_HEADER.as_bytes()).map(|_| w)) {
                Ok(w) => listing = Some(w),
                Err(e) => {
                    r.log.error(&format!("\nError setting up file listing export. Error: {e}"));
                    exported = false;
                }
            }
        }
        match open_out(&p, true).and_then(|mut w| w.write_all(export::csv_header(r.args.ir).as_bytes()).map(|_| w)) {
            Ok(w) => csv = Some(w),
            Err(e) => {
                r.log.error(&format!("\nError setting up CSV export. Error: {e}"));
                exported = false;
            }
        }
    }
    let mut json = None;
    if let Some(dir) = outs.json.clone() {
        if !create_dir(&dir, "--json", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &custom(r, &r.args.jsonf), "$MFT", "json");
        r.log.info(&format!("\tJSON output will be saved to {}", p.display()));
        match open_out(&p, false) {
            Ok(w) => json = Some(w),
            Err(e) => {
                r.log.error(&format!("\nError exporting to JSON. Error: {e}"));
                exported = false;
            }
        }
    }

    let resident_dir = outs.resident.clone();
    if let Some(d) = &resident_dir {
        r.log.info(&format!("\tResident data will be saved to {}", d.display()));
        let _ = std::fs::create_dir_all(d);
    }

    // a --dt that .NET rejects fails on the first row
    if csv.is_some() && Timestamp::check_format(&r.args.dt).is_err() {
        if let Some(w) = &mut csv {
            let _ = w.flush();
        }
        r.log.error(&format!("Error exporting data. Please report to saericzimmerman@gmail.com. Error: {}", ez_common::csv::WRITER_ERROR));
        return false;
    }

    if body.is_some() || csv.is_some() || json.is_some() {
        let options = export::ExportOptions {
            include_short: r.args.sn,
            all_timestamps: r.args.at,
            include_resident: r.args.ir,
            resident_extensions: r.args.re.clone(),
            resident_max_size: r.args.rm,
            cutoff: r.cutoff,
            dump_resident: resident_dir.is_some(),
            source_file: source.clone(),
            date_format: r.args.dt.clone(),
        };
        let bdl = r.args.bdl.as_deref().unwrap_or("").chars().next().map(|c| c.to_string()).unwrap_or_default();
        let nl = if r.args.blf { "\n" } else { "\r\n" };
        let (want_csv, want_json, want_fl, want_body) = (csv.is_some(), json.is_some(), listing.is_some(), body.is_some());
        let blocks: Vec<u32> = mft.in_use.iter().chain(mft.free.iter()).copied().collect();

        'outer: for batch in blocks.chunks(8192) {
            let parts: Vec<Result<([String; 4], Vec<(String, Vec<u8>)>), String>> = batch
                .par_iter()
                .map(|&b| {
                    let fr = mft.full_record(b);
                    let out = export::record_rows(mft, &fr, &options)?;
                    let mut s: [String; 4] = Default::default();
                    for row in &out.rows {
                        if want_csv {
                            export::write_csv(&mut s[0], row, &dt, options.include_resident);
                        }
                        if want_json {
                            export::write_json(&mut s[1], row);
                        }
                        if want_fl {
                            export::write_file_listing(&mut s[2], row, &dt);
                        }
                        if want_body {
                            export::write_body(&mut s[3], row, &bdl, nl);
                        }
                    }
                    Ok((s, out.resident_files))
                })
                .collect();
            for part in parts {
                let (s, files) = match part {
                    Ok(p) => p,
                    Err(e) => {
                        r.log.error(&format!("Error exporting data. Please report to saericzimmerman@gmail.com. Error: {e}"));
                        exported = false;
                        break 'outer;
                    }
                };
                let res: std::io::Result<()> = (|| {
                    if let Some(w) = &mut csv {
                        w.write_all(s[0].as_bytes())?;
                    }
                    if let Some(w) = &mut json {
                        w.write_all(s[1].as_bytes())?;
                    }
                    if let Some(w) = &mut listing {
                        w.write_all(s[2].as_bytes())?;
                    }
                    if let Some(w) = &mut body {
                        w.write_all(s[3].as_bytes())?;
                    }
                    if let Some(d) = &resident_dir {
                        for (name, data) in &files {
                            std::fs::write(d.join(name), data)?;
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = res {
                    r.log.error(&format!("Error exporting data. Error: {e}"));
                    exported = false;
                    break 'outer;
                }
            }
        }
    }
    for w in [&mut csv, &mut json, &mut listing, &mut body].into_iter().flatten() {
        if let Err(e) = w.flush() {
            r.log.error(&format!("Error writing output: {e}"));
            exported = false;
        }
    }
    r.log.info("");

    if let (Some(dd), Some(offset)) = (r.args.dd.clone(), r.args.dump_offset.clone()) {
        r.log.info("");
        let parsed = match offset.strip_prefix("0x") {
            Some(h) => i64::from_str_radix(h, 16).ok(),
            None => offset.parse::<i64>().ok(),
        };
        let Some(offset) = parsed else {
            r.log.warning(&format!("Could not parse {offset} to valid value. Exiting"));
            return false;
        };
        let size = mft.in_use.first().map(|&b| mft.record(b).allocated_record_size as i64).unwrap_or(1024);
        let start = (offset * size).max(0) as usize;
        let bytes = mft.bytes();
        let chunk = &bytes[start.min(bytes.len())..(start + 1024).min(bytes.len())];
        let out = dd.join(format!("MFTECmd_FILE_Offset0x{offset:X}.bin"));
        let _ = std::fs::create_dir_all(&dd);
        match std::fs::write(&out, chunk) {
            Ok(()) => r.log.info(&format!("FILE record at offset 0x{offset:X} dumped to {}\n", out.display())),
            Err(e) => {
                r.log.error(&format!("Unable to write {}: {e}", out.display()));
                return false;
            }
        }
    }
    if let Some(de) = r.args.de.clone() {
        let dt = r.args.dt.clone();
        if !dump::dump_entry(mft, &de, r.args.fls, &dt, &mut r.log) {
            return false;
        }
    }
    exported
}

/// ReportProblems: a warning with the count; the problems with --debug
fn report_problems(log: &mut Logger, file: &Path, what: &str, problems: &[String]) {
    if problems.is_empty() {
        return;
    }
    log.warning(&format!(
        "{}: {} problem(s) with {what} were found and skipped. Use --debug to see them",
        file.display(),
        n0(problems.len() as u64)
    ));
    for p in problems {
        log.debug(&format!("  {p}"));
    }
}

fn read_file(r: &mut Run, file: &Path) -> Option<Vec<u8>> {
    match std::fs::read(file) {
        Ok(b) => Some(b),
        Err(e) => {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            None
        }
    }
}

fn csv_line(fields: &[String]) -> String {
    let mut s = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        ez_common::csv::field(&mut s, f);
    }
    s.push_str("\r\n");
    s
}

fn bool_text(b: bool) -> String {
    if b { "True".into() } else { "False".into() }
}

fn process_boot(r: &mut Run, file: &Path) -> bool {
    let sw = Instant::now();
    let Some(bytes) = read_file(r, file) else { return false };
    let b = match ntfs_ez::boot::Boot::parse(&bytes) {
        Ok(b) => b,
        Err(e) => {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return true;
        }
    };
    for w in &b.warnings {
        r.log.warning(w);
    }
    r.log.info(&format!("\nProcessed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let mut csv = None;
    let mut ok = true;
    if let Some(dir) = r.args.json.clone() {
        use ez_common::json::ServiceStackObject;
        let cluster = b.bytes_per_sector.wrapping_mul(b.sectors_per_cluster);
        let mut j = ServiceStackObject::new();
        j.string("EntryPoint", Some(&b.boot_entry_point))
            .string("Signature", Some(&b.file_system_signature))
            .number("BytesPerSector", b.bytes_per_sector)
            .number("SectorsPerCluster", b.sectors_per_cluster)
            .number("ClusterSize", cluster)
            .number("ReservedSectors", b.reserved_sectors)
            .number("TotalSectors", b.total_sectors)
            .number("MftClusterBlockNumber", b.mft_cluster_block_number)
            .number("MftMirrClusterBlockNumber", b.mirror_mft_cluster_block_number)
            .number("MftEntrySize", b.mft_entry_size)
            .number("IndexEntrySize", b.index_entry_size)
            .string("VolumeSerialNumberRaw", Some(&format!("0x{:X}", b.volume_serial_number_raw)))
            .string("VolumeSerialNumber", Some(&b.volume_serial_number(false, false)))
            .string("VolumeSerialNumber32", Some(&b.volume_serial_number(true, false)))
            .string("VolumeSerialNumber32Reverse", Some(&b.volume_serial_number(true, true)))
            .string("SectorSignature", Some(&b.sector_signature_text()))
            .string("SourceFile", Some(&file.to_string_lossy()));
        let line = format!("{}{}", j.finish(), ez_common::dotnet::NEW_LINE);
        ok &= write_json_lines(r, &dir, "$Boot", &line);
    }
    if let Some(dir) = r.args.csv.clone() {
        if !create_dir(&dir, "--csv", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.csvf, "$Boot", "csv");
        r.log.info(&format!("CSV output will be saved to {}\n", p.display()));
        match open_out(&p, true) {
            Ok(w) => csv = Some(w),
            Err(e) => {
                r.log.error(&format!("There was an error loading the file! Error: {e}"));
                return false;
            }
        }
    }
    let cluster = b.bytes_per_sector.wrapping_mul(b.sectors_per_cluster);
    let source = file.to_string_lossy().into_owned();
    let l = &mut r.log;
    l.info(&format!("Boot file: {source}\n"));
    l.info(&format!("Boot entry point: {}", b.boot_entry_point));
    l.info(&format!("File system signature: {}\n", b.file_system_signature));
    l.info(&format!("Bytes per sector: {}", n0i(b.bytes_per_sector as i64)));
    l.info(&format!("Sectors per cluster: {}", n0i(b.sectors_per_cluster as i64)));
    l.info(&format!("Cluster size: {}\n", n0i(cluster as i64)));
    l.info(&format!("Total sectors: {}", n0i(b.total_sectors)));
    l.info(&format!("Reserved sectors: {}\n", n0i(b.reserved_sectors as i64)));
    l.info(&format!("$MFT cluster block #: {}", n0i(b.mft_cluster_block_number)));
    l.info(&format!("$MFTMirr cluster block #: {}\n", n0i(b.mirror_mft_cluster_block_number)));
    l.info(&format!("FILE entry size: {}", n0i(b.mft_entry_size as i64)));
    l.info(&format!("Index entry size: {}\n", n0i(b.index_entry_size as i64)));
    l.info(&format!("Volume serial number raw: 0x{:X}", b.volume_serial_number_raw));
    l.info(&format!("Volume serial number: {}", b.volume_serial_number(false, false)));
    l.info(&format!("Volume serial number 32-bit: {}", b.volume_serial_number(true, false)));
    l.info(&format!("Volume serial number 32-bit reversed: {}\n", b.volume_serial_number(true, true)));
    l.info(&format!("Sector signature: {}\n", b.sector_signature_text()));
    if let Some(mut w) = csv {
        let header = "EntryPoint,Signature,BytesPerSector,SectorsPerCluster,ClusterSize,ReservedSectors,TotalSectors,MftClusterBlockNumber,MftMirrClusterBlockNumber,MftEntrySize,IndexEntrySize,VolumeSerialNumberRaw,VolumeSerialNumber,VolumeSerialNumber32,VolumeSerialNumber32Reverse,SectorSignature,SourceFile\r\n";
        let line = csv_line(&[
            b.boot_entry_point.clone(),
            b.file_system_signature.clone(),
            b.bytes_per_sector.to_string(),
            b.sectors_per_cluster.to_string(),
            cluster.to_string(),
            b.reserved_sectors.to_string(),
            b.total_sectors.to_string(),
            b.mft_cluster_block_number.to_string(),
            b.mirror_mft_cluster_block_number.to_string(),
            b.mft_entry_size.to_string(),
            b.index_entry_size.to_string(),
            format!("0x{:X}", b.volume_serial_number_raw),
            b.volume_serial_number(false, false),
            b.volume_serial_number(true, false),
            b.volume_serial_number(true, true),
            b.sector_signature_text(),
            source,
        ]);
        if let Err(e) = w.write_all(header.as_bytes()).and_then(|_| w.write_all(line.as_bytes())).and_then(|_| w.flush()) {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return false;
        }
    }
    ok
}

/// .NET's N0 for signed numbers
fn n0i(v: i64) -> String {
    if v < 0 { format!("-{}", n0(v.unsigned_abs())) } else { n0(v as u64) }
}

fn process_sds(r: &mut Run, file: &Path) -> bool {
    use ntfs_ez::mft::security::{CONTROL_NAMES, MASK_NAMES, ACE_FLAG_NAMES, Acl, AclType};
    use ntfs_ez::mft::sid_types::sid_description;
    use ez_common::net::flags_name;
    let sw = Instant::now();
    let Some(bytes) = read_file(r, file) else { return false };
    let sds = ntfs_ez::sds::Sds::parse(&bytes);
    report_problems(&mut r.log, file, "entries", &sds.parse_errors);
    r.log.info(&format!("\nProcessed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let source = file.to_string_lossy().into_owned();
    r.log.info(&format!("SDS entries found in {source}: {}", n0(sds.entries.len() as u64)));
    let mut ok = true;
    if r.args.csv.is_some() || r.args.json.is_some() {
        let mut out = String::from("Hash,Id,Offset,OwnerSid,GroupSid,Control,SaclAceCount,UniqueSaclAceTypes,DaclAceCount,UniqueDaclAceTypes,FileOffset,SourceFile,FromMirror\r\n");
        let mut json = String::new();
        for e in &sds.entries {
            let sd = &e.security_descriptor;
            let unique = |acl: &Acl| {
                let mut seen: Vec<&str> = Vec::new();
                for a in acl.aces() {
                    if !seen.contains(&a.type_name()) {
                        seen.push(a.type_name());
                    }
                }
                seen.join("|")
            };
            let (mut sacl_count, mut sacl_types) = (0u16, None);
            if let Some(s) = sd.sacl().filter(|s| !s.raw.is_empty()) {
                sacl_count = s.ace_count();
                sacl_types = Some(unique(&s));
            }
            let (mut dacl_count, mut dacl_types) = (0u16, None);
            if let Some(d) = sd.dacl() {
                dacl_count = d.ace_count();
                dacl_types = Some(unique(&d));
            }
            let (hash, owner, group) = (e.hash(), sd.owner_sid(), sd.group_sid());
            let control = flags_name(sd.control() as i64, CONTROL_NAMES).replace(", ", "|");
            out.push_str(&csv_line(&[
                hash.clone(),
                e.id.to_string(),
                e.offset.to_string(),
                owner.clone(),
                group.clone(),
                control.clone(),
                sacl_count.to_string(),
                sacl_types.clone().unwrap_or_default(),
                dacl_count.to_string(),
                dacl_types.clone().unwrap_or_default(),
                e.file_offset.to_string(),
                source.clone(),
                bool_text(e.from_mirror),
            ]));
            let mut j = ez_common::json::ServiceStackObject::new();
            j.string("Hash", Some(&hash))
                .number("Id", e.id)
                .number("Offset", e.offset)
                .string("OwnerSid", Some(&owner))
                .string("GroupSid", Some(&group))
                .string("Control", Some(&control))
                .number("SaclAceCount", sacl_count)
                .string("UniqueSaclAceTypes", sacl_types.as_deref())
                .number("DaclAceCount", dacl_count)
                .string("UniqueDaclAceTypes", dacl_types.as_deref())
                .number("FileOffset", e.file_offset)
                .string("SourceFile", Some(&source))
                .bool("FromMirror", e.from_mirror);
            json.push_str(&j.finish());
            json.push_str(ez_common::dotnet::NEW_LINE);
        }
        if let Some(dir) = r.args.csv.clone() {
            if !create_dir(&dir, "--csv", &mut r.log) {
                return false;
            }
            let p = out_name(r, &dir, &r.args.csvf, "$SDS", "csv");
            r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
            if let Err(e) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
                r.log.error(&format!("Error exporting to CSV. Please report to saericzimmerman@gmail.com. Error: {e}"));
                ok = false;
            }
        }
        if let Some(dir) = r.args.json.clone() {
            ok &= write_json_lines(r, &dir, "$SDS", &json);
        }
        r.log.info("");
    }
    if let Some(ds) = r.args.ds.clone() {
        let parsed = match ds.to_uppercase().strip_prefix("0X") {
            Some(h) => i32::from_str_radix(h, 16).ok(),
            None => ds.trim().parse::<i32>().ok(),
        };
        let Some(id) = parsed else {
            r.log.warning(&format!("Could not parse {ds} to valid value. Exiting"));
            return false;
        };
        let Some(e) = sds.entries.iter().find(|e| e.id as i64 == id as i64) else {
            r.log.warning(&format!("Could not find entry with Id: {id}"));
            return ok;
        };
        let sd = &e.security_descriptor;
        let l = &mut r.log;
        l.info(&format!("\nDetails for security record # {} (0x{:X}), Found in {source}", e.id, e.id));
        l.info(&format!("Hash value: {}, Offset: 0x{:X}", e.hash(), e.offset));
        l.info(&format!("Control flags: {}\n", flags_name(sd.control() as i64, CONTROL_NAMES).replace(", ", " | ")));
        let owner = sd.owner_sid();
        l.info(&format!("Owner SID: {}", sid_description(&owner).map(str::to_string).unwrap_or(owner)));
        let group = sd.group_sid();
        l.info(&format!("Group SID: {}", sid_description(&group).map(str::to_string).unwrap_or(group)));
        let dump = |l: &mut Logger, acl: &Acl| {
            let aces = acl.aces();
            l.info(&format!("ACE record count: {}", n0(aces.len() as u64)));
            l.info(&format!("ACL type: {}\n", if acl.acl_type == AclType::Security { "Security" } else { "Discretionary" }));
            for (i, a) in aces.iter().enumerate() {
                l.info(&format!("------------ Ace record #{i} ------------"));
                l.info(&format!("Type: {}", a.type_name()));
                l.info(&format!("Flags: {}", flags_name(a.flags() as i64, ACE_FLAG_NAMES).replace(", ", " | ")));
                l.info(&format!("Mask: {}", flags_name(a.mask() as i32 as i64, MASK_NAMES).replace(", ", " | ")));
                let sid = a.sid();
                l.info(&format!("SID: {}\n", sid_description(&sid).map(str::to_string).unwrap_or(sid)));
            }
        };
        if let Some(d) = sd.dacl() {
            l.info("\nDiscretionary Access Control List");
            dump(l, &d);
        }
        if let Some(s) = sd.sacl() {
            l.info("\nSystem Access Control List");
            dump(l, &s);
        }
    }
    ok
}

fn process_i30(r: &mut Run, file: &Path) -> bool {
    use ntfs_ez::mft::attributes::{NAME_TYPE_NAMES, SI_FLAG_NAMES};
    use ez_common::net::flags_name;
    let sw = Instant::now();
    let Some(bytes) = read_file(r, file) else { return false };
    let i30 = match ntfs_ez::i30::I30::parse(&bytes) {
        Ok(i) => i,
        Err(e) => {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return true;
        }
    };
    for w in &i30.warnings {
        r.log.warning(w);
    }
    report_problems(&mut r.log, file, "pages or entries", &i30.parse_errors);
    r.log.info(&format!("\nProcessed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let active = i30.entries.iter().filter(|e| !e.from_slack).count();
    r.log.info(&format!(
        "$I30 contains {} active and {} slack entries",
        n0(active as u64),
        n0((i30.entries.len() - active) as u64)
    ));
    // with -m: the path of the directory each entry is in (issue #194); empty without -m
    let parent_paths: Vec<String> = i30
        .entries
        .iter()
        .map(|e| r.mft.as_ref().map(|m| m.full_path(e.file_info.as_ref().unwrap().parent.key()).into_owned()).unwrap_or_default())
        .collect();
    let source = file.to_string_lossy().into_owned();
    let mut ok = true;
    if let Some(dir) = r.args.json.clone() {
        ok &= write_i30_json(r, &dir, &i30, &parent_paths, &source);
    }
    let Some(dir) = r.args.csv.clone() else {
        r.log.info("");
        return ok;
    };
    if !create_dir(&dir, "--csv", &mut r.log) {
        return false;
    }
    let p = out_name(r, &dir, &r.args.csvf, "$I30", "csv");
    r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
    let dt = r.args.dt.clone();
    let bad_dt = Timestamp::check_format(&dt).is_err();
    let used = if bad_dt { ez_common::csv::BAD_DATE } else { dt.as_str() };
    let time = |raw: i64| Timestamp::from_filetime(raw).filter(|_| raw > 0).map(|t| t.format(used)).unwrap_or_default();
    let mut out = String::from("Offset,FromSlack,SelfMftEntry,SelfMftSequence,FileName,Flags,NameType,ParentMftEntry,ParentMftSequence,CreatedOn,ContentModifiedOn,RecordModifiedOn,LastAccessedOn,PhysicalSize,LogicalSize,SourceFile,ParentPath\r\n");
    for (e, parent_path) in i30.entries.iter().zip(&parent_paths) {
        let fi = e.file_info.as_ref().unwrap();
        out.push_str(&csv_line(&[
            e.absolute_offset.to_string(),
            bool_text(e.from_slack),
            e.mft_reference_self.map(|m| m.entry.to_string()).unwrap_or_default(),
            e.mft_reference_self.map(|m| m.sequence.to_string()).unwrap_or_default(),
            fi.file_name.clone(),
            flags_name(fi.flags as i64, SI_FLAG_NAMES).replace(", ", "|"),
            flags_name(fi.name_type as i64, NAME_TYPE_NAMES),
            fi.parent.entry.to_string(),
            fi.parent.sequence.to_string(),
            time(fi.created),
            time(fi.content_modified),
            time(fi.record_modified),
            time(fi.last_accessed),
            fi.physical_size.to_string(),
            fi.logical_size.to_string(),
            source.clone(),
            parent_path.clone(),
        ]));
        if bad_dt && out.contains(ez_common::csv::BAD_DATE) {
            break;
        }
    }
    let failed = bad_dt && out.contains(ez_common::csv::BAD_DATE);
    ez_common::csv::cut_at_bad_date(&mut out);
    if let Err(e) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
        r.log.error(&format!("Error writing {}: {e}", p.display()));
        return false;
    }
    if failed {
        r.log.error(&format!("Error exporting data. Please report to saericzimmerman@gmail.com. Error: {}", ez_common::csv::WRITER_ERROR));
        return false;
    }
    r.log.info("");
    ok
}

/// JSON lines (ServiceStack: properties in order, nulls left out, NameType by name)
fn write_json_lines(r: &mut Run, dir: &Path, kind: &str, lines: &str) -> bool {
    if !create_dir(dir, "--json", &mut r.log) {
        return false;
    }
    let p = out_name(r, dir, &r.args.jsonf, kind, "json");
    r.log.info(&format!("\tJSON output will be saved to {}", p.display()));
    if let Err(e) = open_out(&p, false).and_then(|mut w| w.write_all(lines.as_bytes()).and_then(|_| w.flush())) {
        r.log.error(&format!("\nError exporting to JSON. Please report to saericzimmerman@gmail.com. Error: {e}"));
        return false;
    }
    true
}

fn json_time(j: &mut ez_common::json::ServiceStackObject, name: &str, raw: i64) {
    if let Some(t) = Timestamp::from_filetime(raw).filter(|_| raw > 0) {
        j.raw(name, &format!("\"{}\"", t.to_json_string()));
    }
}

fn write_i30_json(r: &mut Run, dir: &Path, i30: &ntfs_ez::i30::I30, parent_paths: &[String], source: &str) -> bool {
    use ez_common::json::ServiceStackObject;
    use ez_common::net::flags_name;
    use ntfs_ez::mft::attributes::{NAME_TYPE_NAMES, SI_FLAG_NAMES};
    let mut out = String::new();
    for (e, parent_path) in i30.entries.iter().zip(parent_paths) {
        let fi = e.file_info.as_ref().unwrap();
        let mut j = ServiceStackObject::new();
        j.number("Offset", e.absolute_offset).bool("FromSlack", e.from_slack);
        if let Some(m) = e.mft_reference_self {
            j.number("SelfMftEntry", m.entry).number("SelfMftSequence", m.sequence);
        }
        j.string("FileName", Some(&fi.file_name))
            .string("Flags", Some(&flags_name(fi.flags as i64, SI_FLAG_NAMES).replace(", ", "|")))
            .string("NameType", Some(&flags_name(fi.name_type as i64, NAME_TYPE_NAMES)))
            .number("ParentMftEntry", fi.parent.entry)
            .number("ParentMftSequence", fi.parent.sequence);
        json_time(&mut j, "CreatedOn", fi.created);
        json_time(&mut j, "ContentModifiedOn", fi.content_modified);
        json_time(&mut j, "RecordModifiedOn", fi.record_modified);
        json_time(&mut j, "LastAccessedOn", fi.last_accessed);
        j.number("PhysicalSize", fi.physical_size)
            .number("LogicalSize", fi.logical_size)
            .string("SourceFile", Some(source))
            .string("ParentPath", Some(parent_path));
        out.push_str(&j.finish());
        out.push_str(ez_common::dotnet::NEW_LINE);
    }
    write_json_lines(r, dir, "$I30", &out)
}

/// LoadLogFile: parses with 4096 byte clusters, then again with the cluster size that makes the logged FILE records'
/// target entries match their entry numbers best
fn load_logfile(bytes: &[u8]) -> Result<ntfs_ez::logfile::LogFile, String> {
    use ntfs_ez::logfile::{DEFAULT_FILE_RECORD_SIZE, LogFile};
    let log = LogFile::parse(bytes, 4096)?;
    let samples: Vec<(i64, u16, u16, u32)> = log
        .records
        .iter()
        .filter_map(|r| r.ntfs.as_ref())
        .filter_map(|n| n.file_record.as_ref().filter(|f| f.entry_number > 0).map(|f| (n.target_vcn, n.cluster_block_offset, n.target_block_size, f.entry_number)))
        .take(5000)
        .collect();
    if samples.is_empty() {
        return Ok(log);
    }
    let matches = |cluster: i64| {
        samples
            .iter()
            .filter(|(vcn, cbo, tbs, e)| {
                let size = if *tbs > 0 { *tbs as i64 * 512 } else { DEFAULT_FILE_RECORD_SIZE };
                vcn.wrapping_mul(cluster).wrapping_add(*cbo as i64 * 512) / size == *e as i64
            })
            .count()
    };
    let (mut best, mut best_matches) = (4096i64, matches(4096));
    let mut c = 512i64;
    while c <= 2 * 1024 * 1024 {
        let m = matches(c);
        if m > best_matches {
            best = c;
            best_matches = m;
        }
        c *= 2;
    }
    if best == 4096 {
        return Ok(log);
    }
    LogFile::parse(bytes, best)
}

/// ProcessLogFile: one row per log record, by LSN
fn process_logfile(r: &mut Run, file: &Path) -> bool {
    use ntfs_ez::logfile_rows::{CSV_HEADER, LogFileRows, write_csv, write_json};
    let sw = Instant::now();
    let Some(bytes) = read_file(r, file) else { return false };
    let log = match load_logfile(&bytes) {
        Ok(l) => l,
        Err(e) => {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return true;
        }
    };
    for w in &log.warnings {
        r.log.warning(w);
    }
    r.log.info(&format!("\nProcessed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let source = file.to_string_lossy().into_owned();
    r.log.info(&format!(
        "{source}: LFS version {}.{}, page size 0x{:X}, cluster size {}{}",
        log.major_version,
        log.minor_version,
        log.page_size,
        n0(log.cluster_size as u64),
        if log.restart_area.clean_dismount() { ", cleanly dismounted" } else { "" }
    ));
    if log.records.is_empty() {
        r.log.info("Log records found: 0");
    } else {
        r.log.info(&format!(
            "Log records found: {} (LSN {} to {}, current LSN {})",
            n0(log.records.len() as u64),
            n0(log.records.first().unwrap().lsn),
            n0(log.records.last().unwrap().lsn),
            n0(log.restart_area.current_lsn)
        ));
    }
    report_problems(&mut r.log, file, "pages or records", &log.parse_errors);
    let mut rows = LogFileRows::new(&log, r.mft.as_ref(), &source);
    let all: Vec<_> = log.records.iter().map(|rec| rows.row(rec)).collect();
    let dt = r.args.dt.clone();
    let mut ok = true;
    if let Some(dir) = r.args.csv.clone() {
        if !create_dir(&dir, "--csv", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.csvf, "$LogFile", "csv");
        r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
        let mut out = String::from(CSV_HEADER);
        let bad_dt = Timestamp::check_format(&dt).is_err();
        let used = if bad_dt { ez_common::csv::BAD_DATE } else { dt.as_str() };
        let mut failed = false;
        for row in &all {
            write_csv(&mut out, row, used);
            if bad_dt && out.contains(ez_common::csv::BAD_DATE) {
                failed = true;
                break;
            }
        }
        ez_common::csv::cut_at_bad_date(&mut out);
        if let Err(e) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to CSV. Error: {e}"));
            ok = false;
        } else if failed {
            r.log.error(&format!("Error exporting to CSV. Please report to saericzimmerman@gmail.com. Error: {}", ez_common::csv::WRITER_ERROR));
            ok = false;
        }
    }
    if let Some(dir) = r.args.json.clone() {
        if !create_dir(&dir, "--json", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.jsonf, "$LogFile", "json");
        r.log.info(&format!("\tJSON output will be saved to {}", p.display()));
        let mut out = String::new();
        for row in &all {
            write_json(&mut out, row);
        }
        if let Err(e) = open_out(&p, false).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to JSON. Error: {e}"));
            ok = false;
        }
    }
    r.log.info("");
    ok
}

/// ProcessJ: the $J's records, with parent paths rewound through the journal when there is an $MFT (-m)
fn process_j(r: &mut Run, file: &Path) -> bool {
    use ez_common::json::ServiceStackObject;
    use ez_common::net::{flags_name, path_extension};
    use ntfs_ez::usn::{FILE_ATTRIBUTE_NAMES, UPDATE_REASON_NAMES, Usn};
    let sw = Instant::now();
    let Some(bytes) = read_file(r, file) else { return false };
    let usn = Usn::parse(&bytes);
    report_problems(&mut r.log, file, "records", &usn.parse_errors);
    r.log.info(&format!("\nProcessed {} in {:.4} seconds\n", file.display(), sw.elapsed().as_secs_f64()));
    let source = file.to_string_lossy().into_owned();
    let entries = &usn.entries;
    r.log.info(&format!("Usn entries found in {source}: {}", n0(entries.len() as u64)));

    let mut parent_paths: Option<Vec<String>> = None;
    if let Some(mft) = &r.mft {
        let sw = Instant::now();
        let paths = ntfs_ez::usn::rewind_parent_paths(mft, entries);
        let elapsed = sw.elapsed().as_secs_f64();
        let mut current: std::collections::HashMap<ntfs_ez::mft::Key, String> = std::collections::HashMap::new();
        let mut changed = 0u64;
        for (e, p) in entries.iter().zip(&paths) {
            let k = ntfs_ez::mft::Key { entry: e.parent_file_reference.entry_number, sequence: e.parent_file_reference.sequence_number as i32 };
            let path = current.entry(k).or_insert_with(|| mft.full_path(k).into_owned());
            if path != p {
                changed += 1;
            }
        }
        r.log.info(&format!(
            "\tParent paths rewound through the journal in {elapsed:.4} seconds. {} differ from the $MFT alone (directories since deleted, reused, renamed or moved)",
            n0(changed)
        ));
        parent_paths = Some(paths);
    }

    let dt = r.args.dt.clone();
    let time = |e: &ntfs_ez::usn::UsnEntry| e.update_timestamp.and_then(Timestamp::from_filetime).unwrap_or(Timestamp::MIN);
    let mut ok = true;
    if let Some(dir) = r.args.csv.clone() {
        if !create_dir(&dir, "--csv", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.csvf, "$J", "csv");
        r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
        let bad_dt = Timestamp::check_format(&dt).is_err();
        let mut out = String::from("Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,OffsetToData,SourceFile\r\n");
        for (i, e) in entries.iter().enumerate() {
            out.push_str(&csv_line(&[
                e.name.clone(),
                path_extension(&e.name).to_string(),
                e.file_reference.entry_number.to_string(),
                e.file_reference.sequence_number.to_string(),
                e.parent_file_reference.entry_number.to_string(),
                e.parent_file_reference.sequence_number.to_string(),
                parent_paths.as_ref().map(|p| p[i].clone()).unwrap_or_default(),
                e.update_sequence_number.to_string(),
                time(e).format(if bad_dt { ez_common::csv::BAD_DATE } else { &dt }),
                flags_name(e.update_reasons as i64, UPDATE_REASON_NAMES).replace(", ", "|"),
                flags_name(e.file_attributes as i64, FILE_ATTRIBUTE_NAMES).replace(", ", "|"),
                e.offset_to_data.to_string(),
                source.clone(),
            ]));
            if bad_dt {
                break;
            }
        }
        ez_common::csv::cut_at_bad_date(&mut out);
        if let Err(err) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to CSV. Error: {err}"));
            ok = false;
        } else if bad_dt && !entries.is_empty() {
            r.log.error(&format!("Error exporting to CSV. Please report to saericzimmerman@gmail.com. Error: {}", ez_common::csv::WRITER_ERROR));
            ok = false;
        }
    }
    if let Some(dir) = r.args.json.clone() {
        if !create_dir(&dir, "--json", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.jsonf, "$J", "json");
        r.log.info(&format!("\tJSON output will be saved to {}", p.display()));
        let mut out = String::new();
        for (i, e) in entries.iter().enumerate() {
            let mut j = ServiceStackObject::new();
            let empty = String::new();
            j.string("Name", Some(&e.name))
                .string("Extension", Some(path_extension(&e.name)))
                .number("EntryNumber", e.file_reference.entry_number)
                .number("SequenceNumber", e.file_reference.sequence_number)
                .number("ParentEntryNumber", e.parent_file_reference.entry_number)
                .number("ParentSequenceNumber", e.parent_file_reference.sequence_number)
                .string("ParentPath", Some(parent_paths.as_ref().map(|p| &p[i]).unwrap_or(&empty)))
                .number("UpdateSequenceNumber", e.update_sequence_number);
            if let Some(t) = e.update_timestamp.and_then(Timestamp::from_filetime) {
                j.raw("UpdateTimestamp", &format!("\"{}\"", t.to_json_string()));
            }
            j.string("UpdateReasons", Some(&flags_name(e.update_reasons as i64, UPDATE_REASON_NAMES).replace(", ", "|")))
                .string("FileAttributes", Some(&flags_name(e.file_attributes as i64, FILE_ATTRIBUTE_NAMES).replace(", ", "|")))
                .number("OffsetToData", e.offset_to_data)
                .string("SourceFile", Some(&source));
            out.push_str(&j.finish());
            out.push_str(ez_common::dotnet::NEW_LINE);
        }
        if let Err(err) = open_out(&p, false).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to JSON. Error: {err}"));
            ok = false;
        }
    }
    r.log.info("");
    ok
}
