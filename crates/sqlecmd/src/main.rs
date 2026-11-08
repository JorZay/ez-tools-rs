//! SQLECmd: runs the maps on SQLite databases, to CSV, JSON and blob files, with the original's options and output.

#[cfg(feature = "sync")]
mod sync;

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, prepare_temp, remove_temp_if_empty, utc_now};
use ez_common::dotnet::{lower_invariant, n0, number_n, upper_invariant};
use ez_common::json::service_stack_string;
use ez_common::{Level, Timestamp};
use sha1::{Digest, Sha1};
use sqlmap_ez::{BlobColumn, Database, MapFile, NetError, QueryInfo, Sink, Table, Value, is_sqlite_file, load_maps};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STAMP: &str = "yyyyMMddHHmmssffffff";

/// Finds SQLite databases and runs the queries in SQLECmd's maps against them, with SQLECmd's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    after_help = "Examples:\n  sqlecmd -f /tmp/someFile.db --csv /tmp/out\n  sqlecmd -d /tmp/evidence --csv /tmp/out\n  sqlecmd -d /tmp/evidence --hunt --csv /tmp/out\n  sqlecmd -d /tmp/evidence --csv /tmp/out --ifn"
)]
struct Args {
    /// File to process. Either this or -d is required
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Directory to recursively process. Either this or -f is required
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// Directory to save JSON formatted results to
    #[arg(long, value_name = "DIR")]
    json: Option<String>,

    /// Directory to save blob data to
    #[arg(long, value_name = "DIR")]
    blobdir: Option<String>,

    /// If true, disables blob extraction from query results
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    noblob: bool,

    /// If true, the name of each database is added to the names of its CSV and blob files, so databases processed with the
    /// same map can be told apart
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    ifn: bool,

    /// Deduplicate -f or -d files based on SHA-1. First file found wins
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    dedupe: bool,

    /// When true, all files are looked at regardless of name and file header is used to identify SQLite files, else
    /// filename in map is used to find databases
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    hunt: bool,

    /// The path where SQL maps are located. Defaults to 'Maps' folder where program was executed
    #[arg(long, value_name = "DIR")]
    maps: Option<String>,

    /// Folder for the temporary copies of the SQLite databases, which are opened instead of the evidence and deleted when
    /// done. Default: a Temp folder next to this program. A folder that isn't there is created, and removed again when
    /// done. If that folder can't be written to, this program stops: give a writable folder with --temp
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// If true, the latest maps from https://github.com/EricZimmerman/SQLECmd/tree/master/SQLMap/Maps are downloaded and
    /// local maps updated (needs a build with the `sync` feature)
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    sync: bool,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_SQLECmd_<version>_ConsoleLog.txt in the output directory (the
    /// first of --csv, --json, --blobdir given). Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

fn program_folder() -> PathBuf {
    std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}

/// Path.Combine
fn combine(folder: &str, name: &str) -> String {
    Path::new(folder).join(name).to_string_lossy().into_owned()
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The characters Windows doesn't allow in a file name, as SQLECmd's guide lists them (on Linux .NET only knows `/` and NUL)
fn invalid_in_file_name(c: char) -> bool {
    matches!(c, '"' | '<' | '>' | '|' | ':' | '*' | '?' | '\\' | '/') || (c as u32) < 32
}

/// SanitizeFilenamePart
fn sanitize(input: &str, max_length: usize) -> Option<String> {
    if input.chars().all(char::is_whitespace) {
        return None;
    }
    let replaced: String = input.chars().map(|c| if invalid_in_file_name(c) || c == ' ' { '_' } else { c }).collect();
    let mut sanitized = replaced.trim_matches('_').to_string();
    if sanitized.encode_utf16().count() > max_length {
        let units: Vec<u16> = sanitized.encode_utf16().take(max_length).collect();
        sanitized = String::from_utf16_lossy(&units);
    }
    let sanitized = sanitized.trim_matches('_').to_string();
    if sanitized.replace('_', "").chars().all(char::is_whitespace) {
        return None;
    }
    Some(sanitized)
}

/// FileSystemName.MatchesSimpleExpression, ignoring case
fn matches_simple(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            Some('?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some('\\') if p.len() > 1 => n.first() == Some(&p[1]) && go(&p[2..], &n[1..]),
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    let p: Vec<char> = upper_invariant(pattern).chars().collect();
    let n: Vec<char> = upper_invariant(name).chars().collect();
    go(&p, &n)
}

/// strerror's text, as Win32Exception gives it
fn os_reason(e: &std::io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error") {
        Some(i) => text[..i].to_string(),
        None => text,
    }
}

/// File.Exists: true for a link to nothing, false for a folder
fn file_exists(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => !m.is_dir(),
        Err(_) => std::fs::symlink_metadata(path).is_ok(),
    }
}

/// A file or folder that can't be read
struct Unreadable {
    folder: String,
    reason: String,
}

/// EntryFinder: the files under a folder matching a pattern, in the order .NET's enumerator gives them on Windows: a
/// folder's entries in NTFS order, then its subfolders in turn
fn find_entries(directory: &str, pattern: &str) -> (Vec<String>, Vec<Unreadable>) {
    let root = full_path(directory);
    let root = if root.len() > 1 { root.trim_end_matches('/').to_string() } else { root };
    let mut queue = VecDeque::from([root]);
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    while let Some(folder) = queue.pop_front() {
        let entries = match ez_common::cli::read_dir_ntfs_order(std::path::Path::new(&folder)) {
            Ok(e) => e,
            Err(e) => {
                unreadable.push(Unreadable { folder, reason: os_reason(&e) });
                continue;
            }
        };
        for entry in entries {
            let path = entry.path();
            let text = path.to_string_lossy().into_owned();
            if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                queue.push_back(text);
            } else if matches_simple(pattern, &entry.file_name().to_string_lossy()) {
                files.push(text);
            }
        }
    }
    (files, unreadable)
}

/// A copy of a database (with its -wal and -journal) in a new folder, deleted when dropped: only the copy is opened,
/// since SQLite would checkpoint a -wal into the evidence
struct DatabaseCopy {
    folder: PathBuf,
    path: PathBuf,
}

impl DatabaseCopy {
    fn create(database: &str, temp: &str) -> Result<DatabaseCopy, NetError> {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let folder = Path::new(temp).join(format!("SQLECmd-{stamp:024x}{:08x}", std::process::id()));
        std::fs::create_dir_all(&folder).map_err(|e| NetError::from_io(&folder, &e))?;
        let path = folder.join(base_name(database));
        let copy = DatabaseCopy { folder, path };
        for suffix in ["", "-wal", "-journal"] {
            let source = format!("{database}{suffix}");
            if file_exists(&source) {
                let target = format!("{}{suffix}", copy.path.display());
                std::fs::copy(&source, &target).map_err(|e| NetError::from_io(Path::new(&source), &e))?;
            }
        }
        Ok(copy)
    }
}

impl Drop for DatabaseCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

/// What all the databases share
struct Run<'a> {
    log: Logger,
    maps: Vec<MapFile>,
    csv: Option<&'a str>,
    json: Option<&'a str>,
    blobdir: Option<&'a str>,
    dedupe: bool,
    hunt: bool,
    noblob: bool,
    ifn: bool,
    temp: String,
    temp_created: bool,
    json_writer: Option<BufWriter<File>>,
    processed: u64,
    unmatched: Vec<String>,
    unmatched_seen: HashSet<String>,
    seen_hashes: HashSet<String>,
    unreadable_folders: HashSet<String>,
    failed_files: u64,
    access_errors: u64,
    export_errors: u64,
    query_errors: u64,
}

impl Run<'_> {
    fn exception(&mut self, level: Level, message: &str, e: &NetError) {
        self.log.exception(level, message, &e.exception);
    }

    fn find(&mut self, directory: &str, pattern: &str) -> Vec<String> {
        let (files, unreadable) = find_entries(directory, pattern);
        let mut count = 0u64;
        for u in unreadable {
            if self.unreadable_folders.insert(upper_invariant(&u.folder)) {
                self.log.error(&format!("Unable to read folder {}: {}", u.folder, u.reason));
                count += 1;
            }
        }
        if count > 0 {
            self.access_errors += 1;
            self.log.error(&format!("Could not access all files in {directory}: {} folder(s) could not be read", n0(count)));
        }
        files
    }

    fn process_failed(&mut self, file: &str, e: &NetError) {
        if e.access {
            self.access_errors += 1;
        } else {
            self.failed_files += 1;
        }
        self.exception(Level::Error, &format!("Error processing {file}: {}", e.message), e);
    }

    /// SqLiteFile.IsSqLiteFile: false for what isn't there or can't be opened, with a message
    fn is_sqlite(&mut self, file: &str) -> bool {
        if !file_exists(file) {
            self.log.warning(&format!("{file} not found!"));
            return false;
        }
        match is_sqlite_file(Path::new(file)) {
            Ok(result) => result,
            Err(e) => {
                let message = if e.kind() == std::io::ErrorKind::NotFound {
                    format!("Could not find file '{}'.", full_path(file))
                } else {
                    ez_common::cli::io_message(Path::new(file), &e)
                };
                self.log.error(&format!("Error accessing {file}: {message}"));
                false
            }
        }
    }

    /// -f, or the files under -d
    fn process_all(&mut self, f: Option<&str>, d: &str) {
        if let Some(f) = f {
            // a file given with -f must be a database (under -d, other files are skipped)
            if !self.is_sqlite(f) {
                if File::open(f).is_err() {
                    // that logged why it could not be read
                    self.access_errors += 1;
                    return;
                }
                self.failed_files += 1;
                self.log.error(&format!("{f} is not a SQLite file"));
                return;
            }
            if let Err(e) = self.process_file(&full_path(f)) {
                self.process_failed(f, &e);
            }
            return;
        }

        self.log.info(&format!("Looking for files in {d}"));
        self.log.blank();
        let mut files = Vec::new();
        if self.hunt {
            files = self.find(d, "*");
        } else {
            let names: Vec<String> = self.maps.iter().map(|m| m.file_name_text().to_string()).collect();
            for name in names {
                files.extend(self.find(d, &name));
            }
        }
        for file in files {
            if let Err(e) = self.process_file(&file) {
                self.process_failed(&file, &e);
            }
        }
    }

    fn sha1_of(&self, file: &str) -> Result<String, NetError> {
        let bytes = std::fs::read(file).map_err(|e| NetError::from_io(Path::new(file), &e))?;
        Ok(Sha1::digest(&bytes).iter().map(|x| format!("{x:02X}")).collect())
    }

    fn process_file(&mut self, file: &str) -> Result<(), NetError> {
        self.log.debug(&format!("Checking if {file} is a SQLite file"));
        if !self.is_sqlite(file) {
            if file_exists(file) && File::open(file).is_err() {
                // that logged why it could not be read
                self.access_errors += 1;
                return Ok(());
            }
            let message = format!("\t{file} is not a SQLite file! Skipping...");
            if self.hunt {
                self.log.debug(&message);
            } else {
                self.log.warning(&message);
            }
            return Ok(());
        }
        self.log.debug(&format!("{file} is a SQLite file!"));

        if self.dedupe {
            let sha = self.sha1_of(file)?;
            if self.seen_hashes.contains(&sha) {
                self.log.warning(&format!("Skipping {file} as a file with SHA-1 {sha} has already been processed"));
                self.log.blank();
                return Ok(());
            }
            self.log.debug(&format!("Adding {file} SHA-1 {sha} to seen hashes collection"));
            self.seen_hashes.insert(sha);
        }

        self.log.info(&format!("Processing {file}..."));
        self.processed += 1;

        let name = lower_invariant(base_name(file));
        let indexes: Vec<usize> = (0..self.maps.len()).filter(|i| self.hunt || lower_invariant(self.maps[*i].file_name_text()) == name).collect();
        let db_name_part = if self.ifn { format!("_{}", sanitize(base_name(file), 100).unwrap_or_else(|| "db".to_string())) } else { String::new() };

        let copy = DatabaseCopy::create(file, &self.temp)?;
        let db = Database::open(&copy.path)?;

        let mut found_map = false;
        let mut identify_errors = 0;
        let mut identify_error = None;
        let mismatch_level = if self.hunt { Level::Debug } else { Level::Warning };

        for &i in &indexes {
            let map = self.maps[i].clone();
            self.log.debug(&format!("Processing map {} with Id {}", map.description_text(), map.id_text()));
            let base_time = utc_now();
            self.log.debug(&format!("\tVerifying database via {}", map.identify_query_text()));

            let id = match db.scalar(map.identify_query_text()) {
                Ok(id) => id,
                Err(e) => {
                    identify_errors += 1;
                    self.log.block(mismatch_level, &format!("\tIdentifyQuery for map {} with Id {} failed: {}", map.description_text(), map.id_text(), e.message));
                    identify_error = Some(e);
                    continue;
                }
            };
            if id.as_deref().map(lower_invariant) != Some(lower_invariant(map.identify_value_text())) {
                // when hunting, every map is tried against every database, so a mismatch is normal
                self.log.block(
                    mismatch_level,
                    &format!(
                        "\tFor map w/ description {}, got value {} from IdentityQuery, but expected {}. Queries will not be processed!",
                        map.description_text(),
                        id.as_deref().unwrap_or(""),
                        map.identify_value_text()
                    ),
                );
                continue;
            }
            found_map = true;

            self.log.info(&format!("\tMap queries found: {}. Processing queries...", n0(map.query_list().count() as u64)));
            for query in map.query_list() {
                self.log.debug(&format!("Processing query {}", query.name_text()));
                if let Err(e) = self.run_query(&db, &map, query, file, base_time, &db_name_part) {
                    self.exception(Level::Fatal, &format!("Error processing map {} with Id {} for query {}", map.description_text(), map.id_text(), query.name_text()), &e);
                    self.log.error(&format!("\t{}", e.message.replace("\r\n", "\r\n\t")));
                    // output that can't be written is a failure; a query that fails on this database is not
                    if e.access {
                        self.export_errors += 1;
                    } else {
                        self.query_errors += 1;
                    }
                }
            }
        }

        if !indexes.is_empty() && identify_errors == indexes.len() {
            // not one IdentifyQuery could run, so the database itself cannot be read (corrupt, encrypted, ...)
            let inner = identify_error.expect("an identify query failed");
            return Err(NetError::unable_to_read(&inner));
        }

        if !found_map {
            self.log.info(&format!("\tNo maps found for {file}. Adding to unmatched database list"));
            if self.unmatched_seen.insert(lower_invariant(file)) {
                self.unmatched.push(file.to_string());
            }
        }
        self.log.blank();
        Ok(())
    }

    /// The folder blobs go to
    fn blob_folder(&self) -> &str {
        self.blobdir.or(self.csv).or(self.json).unwrap_or_default()
    }

    fn extract_blobs(&mut self, table: &Table, map: &MapFile, query: &QueryInfo, base_time: Timestamp, db_name_part: &str) {
        let out_dir = self.blob_folder().to_string();
        self.log.info(&format!("\tProcessing blobs for query {} into directory {out_dir}", query.name_text()));
        let mut counter = 0u64;
        let columns: Vec<&BlobColumn> = query.blob_list().collect();
        for row in 0..table.row_count() {
            for blob in &columns {
                let column = blob.blob_column.as_deref().unwrap_or_default();
                let Some(Value::Blob(data)) = table.get(row, column) else { continue };
                if data.is_empty() {
                    continue;
                }
                counter += 1;
                let name_part = blob.name_column.as_deref().filter(|n| !n.is_empty()).and_then(|n| table.get(row, n)).filter(|v| !matches!(v, Value::Null)).and_then(|v| sanitize(&v.display_text(), 50));
                let identifier = name_part.unwrap_or_else(|| counter.to_string());
                let extension = blob.blob_extension.as_deref().filter(|e| !e.is_empty()).map_or(".blob".to_string(), |e| format!(".{e}"));
                let file_name = format!("{}_{}_{}_{}_{identifier}_{column}{db_name_part}{extension}", base_time.format(STAMP), map.prefix_text(), query.base_name_text(), map.id_text());
                let full = combine(&out_dir, &file_name);
                match std::fs::write(&full, data) {
                    Ok(()) => self.log.info(&format!("\tDumping blob from column {column} to {full}")),
                    Err(e) => {
                        let error = NetError::from_io(Path::new(&full), &e);
                        self.exception(Level::Error, &format!("\tError processing blob column {column} for query {}: {}", query.name_text(), error.message), &error);
                        self.export_errors += 1;
                    }
                }
            }
        }
    }

    fn run_query(&mut self, db: &Database, map: &MapFile, query: &QueryInfo, file: &str, base_time: Timestamp, db_name_part: &str) -> Result<(), NetError> {
        let mut results = db.query(query.query_text())?;

        let has_blob_columns = query.blob_list().next().is_some();
        if has_blob_columns && !self.noblob {
            self.extract_blobs(&results, map, query, base_time, db_name_part);
        }
        if has_blob_columns {
            let mut keys = HashSet::new();
            for blob in query.blob_list() {
                let column = blob.blob_column.as_deref().unwrap_or_default();
                if !keys.insert(upper_invariant(column)) {
                    return Err(NetError::duplicate_key(column));
                }
            }
            for row in 0..results.row_count() {
                results.remove_blobs(row, |name| keys.contains(&upper_invariant(name)));
            }
        }

        if let Some(csv) = self.csv {
            let out_name = format!("{}_{}_{}_{}{db_name_part}.csv", base_time.format(STAMP), map.prefix_text(), query.base_name_text(), map.id_text());
            let full = combine(csv, &out_name);
            if results.is_empty() {
                self.log.warning(&format!("\t {} did not return any results. CSV will not be saved", query.name_text()));
                return Ok(());
            }
            self.log.info(&format!("\tDumping {} to {full}", query.name_text()));
            results.set_all("SourceFile", &Value::Text(file.to_string()));
            write_csv(&results, Path::new(&full))?;
        }
        if self.json_writer.is_some() {
            if results.is_empty() {
                self.log.warning(&format!("\t {} did not return any results. JSON will not be saved", query.name_text()));
                return Ok(());
            }
            results.set_all("SourceFile", &Value::Text(file.to_string()));
            results.set_all("MapDescription", &Value::Text(map.description_text().to_string()));
            let path = Path::new(self.json.unwrap_or_default());
            let writer = self.json_writer.as_mut().expect("checked above");
            write_json(&results, writer).map_err(|e| NetError::from_io(path, &e))?;
        }
        Ok(())
    }

    fn dump_unmatched(&mut self, database: &str) -> Result<(), NetError> {
        std::fs::create_dir_all(&self.temp).map_err(|e| NetError::from_io(Path::new(&self.temp), &e))?;
        let result = (|| {
            let copy = DatabaseCopy::create(database, &self.temp)?;
            let db = Database::open(&copy.path)?;
            db.table_names()
        })();
        remove_temp_if_empty(&self.temp, self.temp_created);
        self.log.info(&format!("\tFile name: {database}, Tables: {}", result?.join(",")));
        Ok(())
    }
}

/// As CsvHelper writes dynamic rows: the header from the first row, and each row with the values it still has
fn write_csv(table: &Table, path: &Path) -> Result<(), NetError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| NetError::from_io(path, &e))?;
    let mut out = BufWriter::new(file);
    let mut line = String::new();
    for (i, (name, _)) in table.cells(0).enumerate() {
        if i > 0 {
            line.push(',');
        }
        ez_common::csv::field(&mut line, name);
    }
    line.push_str(ez_common::csv::NEW_LINE);
    for row in 0..table.row_count() {
        for (i, (_, value)) in table.cells(row).enumerate() {
            if i > 0 {
                line.push(',');
            }
            ez_common::csv::field(&mut line, &value.csv_text());
        }
        line.push_str(ez_common::csv::NEW_LINE);
        out.write_all(line.as_bytes()).map_err(|e| NetError::from_io(path, &e))?;
        line.clear();
    }
    out.flush().map_err(|e| NetError::from_io(path, &e))
}

fn write_json(table: &Table, out: &mut BufWriter<File>) -> std::io::Result<()> {
    let mut line = String::new();
    for row in 0..table.row_count() {
        line.clear();
        line.push('{');
        for (i, (name, value)) in table.cells(row).enumerate() {
            if i > 0 {
                line.push(',');
            }
            service_stack_string(&mut line, name);
            line.push(':');
            value.write_json(&mut line);
        }
        line.push('}');
        line.push_str(ez_common::dotnet::NEW_LINE);
        out.write_all(line.as_bytes())?;
    }
    out.flush()
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    log.blank();
    ExitCode::FAILURE
}

/// Makes an output folder that isn't there
fn make_folder(log: &mut Logger, folder: &str) -> bool {
    if Path::new(folder).is_dir() {
        return true;
    }
    log.info(&format!("Path to {folder} doesn't exist. Creating..."));
    match std::fs::create_dir_all(folder) {
        Ok(()) => true,
        Err(e) => {
            let error = NetError::from_io(Path::new(folder), &e);
            log.exception(Level::Fatal, &format!("Unable to create directory {folder}. Does a file with the same name exist? Exiting"), &error.exception);
            log.blank();
            false
        }
    }
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
    let mut log = Logger::new(level, "yyyy-MM-dd HH:mm:ss").to_stdout();

    // one UTC time per run, for the JSON file's name and the console log
    let run_time = utc_now();
    let csv = given(&args.csv);
    let json = given(&args.json);
    let blobdir = given(&args.blobdir);
    let console_log = [args.csv.as_deref(), args.json.as_deref(), args.blobdir.as_deref()]
        .into_iter()
        .flatten()
        .find(|d| !d.trim().is_empty())
        .filter(|_| args.co)
        .map(|d| Path::new(&full_path(d)).join(format!("{}_SQLECmd_{VERSION}_ConsoleLog.txt", run_time.format("yyyyMMddHHmmss"))));
    if let Some(path) = &console_log {
        // as the original's log file: it isn't an error if it can't be made
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }

    let banner = format!("SQLECmd (Rust) version {VERSION}");
    if args.sync {
        log.info(&banner);
        #[cfg(feature = "sync")]
        {
            return match sync::sync_maps(&program_folder().join("Maps"), &mut log) {
                Ok(()) => {
                    log.blank();
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    log.error(&format!("Unable to download maps: {e}"));
                    log.blank();
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(feature = "sync"))]
        {
            log.error("This build has no --sync: build it with the `sync` feature");
            log.blank();
            return ExitCode::FAILURE;
        }
    }

    let (file, directory) = (given(&args.file), given(&args.directory));
    if file.is_none() && directory.is_none() {
        return help_and_warning(&mut log, "-f or -d is required. Exiting");
    }
    if csv.is_none() && json.is_none() {
        return help_and_warning(&mut log, "--csv or --json is required. Exiting");
    }

    log.info(&banner);
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let start = Instant::now();
    let maps_folder = args.maps.clone().unwrap_or_else(|| program_folder().join("Maps").to_string_lossy().into_owned());
    let mut maps = Vec::new();
    if Path::new(&maps_folder).is_dir() {
        let full = full_path(&maps_folder);
        log.debug(&format!("Loading maps from {full}"));
        let loaded = load_maps(&full, &mut log);
        if loaded.had_errors {
            return ExitCode::FAILURE;
        }
        maps = loaded.maps;
        log.info(&format!("Maps loaded: {}", n0(maps.len() as u64)));
    } else {
        log.warning(&format!("Maps directory {maps_folder} does not exist! Database maps will not be loaded!!"));
    }

    for folder in [csv, json, blobdir].into_iter().flatten() {
        if !make_folder(&mut log, folder) {
            return ExitCode::FAILURE;
        }
    }

    let mut json_writer = None;
    if let Some(json) = json {
        let full = combine(json, &format!("{}_SQLECmd_Output.json", run_time.format(STAMP)));
        match OpenOptions::new().write(true).create_new(true).open(&full) {
            Ok(f) => json_writer = Some(BufWriter::new(f)),
            Err(e) => {
                let error = NetError::from_io(Path::new(&full), &e);
                log.exception(Level::Fatal, &format!("Unable to create {full}: {}. Exiting", error.message), &error.exception);
                log.blank();
                return ExitCode::FAILURE;
            }
        }
        log.info(&format!("\tSaving all JSON results to {full}"));
    }

    if let Some(f) = file {
        if !file_exists(f) {
            log.warning(&format!("{f} does not exist! Exiting"));
            log.blank();
            return ExitCode::FAILURE;
        }
    } else if !directory.is_some_and(|d| Path::new(d).is_dir()) {
        log.warning(&format!("Directory {} does not exist! Exiting", directory.unwrap_or_default()));
        log.blank();
        return ExitCode::FAILURE;
    }

    // the databases are read from copies, made in --temp or Temp next to this program (never the user's temp folder)
    let (temp, temp_created) = match prepare_temp(given(&args.temp), "SQLECmd") {
        Ok(t) => t,
        Err(error) => {
            log.error(&format!("The folder for the temporary copies of the databases can't be written to ({error}). Give one with --temp. Exiting"));
            log.blank();
            return ExitCode::FAILURE;
        }
    };

    let mut run = Run {
        log,
        maps,
        csv,
        json,
        blobdir,
        dedupe: args.dedupe,
        hunt: args.hunt,
        noblob: args.noblob,
        ifn: args.ifn,
        temp,
        temp_created,
        json_writer,
        processed: 0,
        unmatched: Vec::new(),
        unmatched_seen: HashSet::new(),
        seen_hashes: HashSet::new(),
        unreadable_folders: HashSet::new(),
        failed_files: 0,
        access_errors: 0,
        export_errors: 0,
        query_errors: 0,
    };
    run.process_all(file, directory.unwrap_or_default());
    remove_temp_if_empty(&run.temp, run.temp_created);
    run.json_writer = None;
    let elapsed = start.elapsed().as_secs_f64();

    if !run.unmatched.is_empty() {
        run.log.blank();
        run.log.fatal("At least one database was found with no corresponding map (Use --debug for more details about discovery process)");
        for database in run.unmatched.clone() {
            if let Err(e) = run.dump_unmatched(&database) {
                run.log.info(&format!("\tFile name: {database}, Tables: (unable to read: {})", e.message));
            }
        }
    }

    run.log.blank();
    let noun = if run.processed == 1 { "file" } else { "files" };
    run.log.info(&format!("Processed {} {noun} in {} seconds", n0(run.processed), number_n(elapsed, 4)));
    run.log.blank();

    // exit code 1 only when this tool could not do its job; files that are not SQLite or are damaged, and queries that
    // fail on a database, are listed but give 0
    if run.failed_files + run.access_errors > 0 {
        run.log.warning(&format!("{} file(s) could not be processed. See the errors above", n0(run.failed_files + run.access_errors)));
        run.log.blank();
    }
    if run.export_errors + run.query_errors > 0 {
        run.log.warning(&format!("{} query/export error(s). See the errors above", n0(run.export_errors + run.query_errors)));
        run.log.blank();
    }
    if run.access_errors > 0 || run.export_errors > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
