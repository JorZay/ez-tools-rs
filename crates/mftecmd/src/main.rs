//! mftecmd: NTFS metadata files ($MFT, $J, $LogFile, $Boot, $SDS, $I30) to CSV, JSON and bodyfile, as MFTECmd
//! writes them.

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
    /// File to process ($MFT | $J | $LogFile | $Boot | $SDS | $I30)
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<PathBuf>,

    /// $MFT file to use when -f points to a $J or $LogFile file, to resolve parent paths
    #[arg(short = 'm', value_name = "FILE")]
    mft: Option<PathBuf>,

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
    let args = Args::parse();
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
    let mut log = Logger::new(level, &args.dt);
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

    let Some(file) = args.file.clone() else {
        return Err("-f is required. Exiting (see --help)".into());
    };
    if !file.exists() {
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
            process_mft(&mut r, &file)
        }
        FileType::Boot => process_boot(&mut r, &file),
        FileType::UsnJournal | FileType::LogFile => {
            if r.args.csv.is_none() && r.args.json.is_none() {
                return Err("--csv or --json is required. Exiting".into());
            }
            let mut ok = true;
            if let Some(m) = r.args.mft.clone() {
                if !m.exists() {
                    r.log.error(&format!("MFT file {} does not exist! Verify path and try again. Exiting\n", m.display()));
                    return Ok(ExitCode::FAILURE);
                }
                match file_type(&m, &mut r.log) {
                    Ok(FileType::Mft) => {}
                    other => {
                        r.log.error(&format!("File {} is not an MFT file!! Verify path and try again. Exiting", m.display()));
                        return Ok(if matches!(other, Err(false)) { ExitCode::FAILURE } else { ExitCode::SUCCESS });
                    }
                }
                r.custom_names = false;
                ok &= process_mft(&mut r, &m);
                r.custom_names = true;
                if r.mft.is_none() {
                    return Ok(if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE });
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
            if r.args.csv.is_none() && r.args.ds.is_none() {
                return Err("--csv or --ds is required. Exiting".into());
            }
            process_sds(&mut r, &file)
        }
        FileType::I30 => {
            if r.args.csv.is_none() {
                return Err("--csv is required. Exiting".into());
            }
            process_i30(&mut r, &file)
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

/// ProcessMft: loads the $MFT (kept in r.mft) and writes its outputs; false when it could not be read or an export
/// failed
fn process_mft(r: &mut Run, file: &Path) -> bool {
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
    let ok = mft_outputs(r, &mft, file);
    r.mft = Some(mft);
    ok
}

fn custom(r: &Run, name: &Option<String>) -> Option<String> {
    if r.custom_names { name.clone() } else { None }
}

fn mft_outputs(r: &mut Run, mft: &Mft, file: &Path) -> bool {

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
    if let Some(dir) = a.body.clone() {
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
    if let Some(dir) = r.args.csv.clone() {
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
    if let Some(dir) = r.args.json.clone() {
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

    let resident_dir = r.args.dr.then(|| r.args.json.clone().or(r.args.csv.clone()).map(|d| d.join("Resident"))).flatten();
    if let Some(d) = &resident_dir {
        r.log.info(&format!("\tResident data will be saved to {}", d.display()));
        let _ = std::fs::create_dir_all(d);
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
    if r.args.de.is_some() {
        r.log.error("--de is not supported by this version yet");
        return false;
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
    true
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
    if let Some(dir) = r.args.csv.clone() {
        if !create_dir(&dir, "--csv", &mut r.log) {
            return false;
        }
        let p = out_name(r, &dir, &r.args.csvf, "$SDS", "csv");
        r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
        let mut out = String::from("Hash,Id,Offset,OwnerSid,GroupSid,Control,SaclAceCount,UniqueSaclAceTypes,DaclAceCount,UniqueDaclAceTypes,FileOffset,SourceFile,FromMirror\r\n");
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
            let (mut sacl_count, mut sacl_types) = (0u16, String::new());
            if let Some(s) = sd.sacl().filter(|s| !s.raw.is_empty()) {
                sacl_count = s.ace_count();
                sacl_types = unique(&s);
            }
            let (mut dacl_count, mut dacl_types) = (0u16, String::new());
            if let Some(d) = sd.dacl() {
                dacl_count = d.ace_count();
                dacl_types = unique(&d);
            }
            out.push_str(&csv_line(&[
                e.hash(),
                e.id.to_string(),
                e.offset.to_string(),
                sd.owner_sid(),
                sd.group_sid(),
                flags_name(sd.control() as i64, CONTROL_NAMES).replace(", ", "|"),
                sacl_count.to_string(),
                sacl_types,
                dacl_count.to_string(),
                dacl_types,
                e.file_offset.to_string(),
                source.clone(),
                bool_text(e.from_mirror),
            ]));
        }
        if let Err(e) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("There was an error loading the file! Error: {e}"));
            return false;
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
            return true;
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
    true
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
    let dir = r.args.csv.clone().unwrap();
    if !create_dir(&dir, "--csv", &mut r.log) {
        return false;
    }
    let p = out_name(r, &dir, &r.args.csvf, "$I30", "csv");
    r.log.info(&format!("\tCSV output will be saved to {}", p.display()));
    let dt = r.args.dt.clone();
    let time = |raw: i64| Timestamp::from_filetime(raw).filter(|_| raw > 0).map(|t| t.format(&dt)).unwrap_or_default();
    let source = file.to_string_lossy().into_owned();
    let mut out = String::from("Offset,FromSlack,SelfMftEntry,SelfMftSequence,FileName,Flags,NameType,ParentMftEntry,ParentMftSequence,CreatedOn,ContentModifiedOn,RecordModifiedOn,LastAccessedOn,PhysicalSize,LogicalSize,SourceFile\r\n");
    for e in &i30.entries {
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
        ]));
    }
    if let Err(e) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
        r.log.error(&format!("Error writing {}: {e}", p.display()));
        return false;
    }
    r.log.info("");
    true
}

fn process_logfile(r: &mut Run, _file: &Path) -> bool {
    r.log.error("$LogFile files are not supported by this version yet");
    false
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
                time(e).format(&dt),
                flags_name(e.update_reasons as i64, UPDATE_REASON_NAMES).replace(", ", "|"),
                flags_name(e.file_attributes as i64, FILE_ATTRIBUTE_NAMES).replace(", ", "|"),
                e.offset_to_data.to_string(),
                source.clone(),
            ]));
        }
        if let Err(err) = open_out(&p, true).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to CSV. Error: {err}"));
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
            out.push('\n');
        }
        if let Err(err) = open_out(&p, false).and_then(|mut w| w.write_all(out.as_bytes()).and_then(|_| w.flush())) {
            r.log.error(&format!("\nError exporting to JSON. Error: {err}"));
            ok = false;
        }
    }
    r.log.info("");
    ok
}
