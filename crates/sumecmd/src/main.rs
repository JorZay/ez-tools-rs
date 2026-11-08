//! SumECmd: User Access Logging databases (SystemIdentity.mdb, Current.mdb and the yearly {GUID}.mdb) to CSV, with the original's
//! options and columns. The original only runs on Windows, as it reads with esent.dll; this reads the files itself, in place, and
//! never writes next to them. See docs/plans/sumecmd.md.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::{full_path, io_exception, io_message, utc_now};
use ez_common::dotnet::{n0, number_n};
use ez_common::net::guid;
use ez_common::{Level, Timestamp};
use sum_ez::{ClientEntry, DayEntry, Observer, Sum, SumError};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reads User Access Logging (SUM) databases, with SumECmd's options and output.
#[derive(Parser, Debug)]
#[command(version, after_help = "Examples:\n  sumecmd -d /cases/host1/Windows/System32/LogFiles/Sum --csv /tmp/out")]
struct Args {
    /// Directory to process, looking for SystemIdentity.mdb, Current.mdb, etc. Required
    #[arg(short = 'd', value_name = "DIR")]
    directory: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// Generate CSV with day level details. Default is TRUE
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    wd: bool,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// Accepted for the original's command lines. This port needs no temporary copies: it reads the databases in place, without
    /// writing
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_SumECmd_<version>_ConsoleLog.txt in the --csv directory. Use --co false to
    /// turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// A field of a CSV row: text, or a time written with --dt
enum Field {
    Text(String),
    Time(Timestamp),
}

fn text(s: impl Into<String>) -> Field {
    Field::Text(s.into())
}

fn opt<T: ToString>(v: &Option<T>) -> Field {
    Field::Text(v.as_ref().map_or_else(String::new, ToString::to_string))
}

/// Why an export failed
enum ExportError {
    Io(std::io::Error),
    /// --dt is a format .NET rejects: CsvHelper stopped at the first time, as here
    BadDate,
}

/// A CSV file as SumECmd writes it: UTF-8 with a byte order mark, CsvHelper's quoting
struct Csv {
    out: BufWriter<File>,
    rows: u64,
}

impl Csv {
    fn create(path: &Path, header: &[&str]) -> Result<Csv, ExportError> {
        let mut out = BufWriter::new(File::create(path).map_err(ExportError::Io)?);
        out.write_all(ez_common::cli::BOM).map_err(ExportError::Io)?;
        let mut csv = Csv { out, rows: 0 };
        csv.write_line(&header.iter().map(|h| text(*h)).collect::<Vec<_>>(), "")?;
        csv.rows = 0;
        Ok(csv)
    }

    /// A row; with a bad --dt, what CsvHelper had of it before its first time, and then the error
    fn write_line(&mut self, fields: &[Field], format: &str) -> Result<(), ExportError> {
        let bad = Timestamp::check_format(format).is_err();
        let mut line = String::new();
        for (i, f) in fields.iter().enumerate() {
            let value = match f {
                Field::Text(t) => t.clone(),
                Field::Time(_) if bad => {
                    self.out.write_all(line.as_bytes()).map_err(ExportError::Io)?;
                    self.out.flush().map_err(ExportError::Io)?;
                    return Err(ExportError::BadDate);
                }
                Field::Time(t) => t.format(format),
            };
            if i > 0 {
                line.push(',');
            }
            ez_common::csv::field(&mut line, &value);
        }
        line.push_str(ez_common::csv::NEW_LINE);
        self.out.write_all(line.as_bytes()).map_err(ExportError::Io)?;
        self.rows += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<(), ExportError> {
        self.out.flush().map_err(ExportError::Io)
    }
}

const CLIENT_HEADER: [&str; 10] = ["RoleGuid", "RoleDescription", "AuthenticatedUserName", "TotalAccesses", "InsertDate", "LastAccess", "IpAddress", "ClientName", "TenantId", "SourceFile"];

fn client_fields(c: &ClientEntry, role: &str, description: &str, source: &str) -> Vec<Field> {
    vec![
        text(role),
        text(description),
        opt(&c.authenticated_user_name),
        text(c.total_accesses.to_string()),
        Field::Time(c.insert_date),
        Field::Time(c.last_access),
        text(c.ip_address.clone()),
        opt(&c.client_name),
        text(guid(&c.tenant_id)),
        text(source),
    ]
}

fn day_fields(d: &DayEntry, client: Vec<Field>) -> Vec<Field> {
    let mut fields = vec![text(d.date.format("yyyy-MM-dd")), text(d.count.to_string()), text(d.day_number.to_string())];
    fields.extend(client);
    fields
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

/// The CSVs of the detail tables, each created with its first row
#[derive(Default)]
struct Details {
    clients: Option<Csv>,
    clients_detail: Option<Csv>,
    dns: Option<Csv>,
    roles: Option<Csv>,
    vms: Option<Csv>,
}

impl Details {
    fn finish(self) -> Result<(), ExportError> {
        for csv in [self.clients, self.dns, self.vms, self.roles, self.clients_detail].into_iter().flatten() {
            csv.finish()?;
        }
        Ok(())
    }
}

struct Exporter<'a> {
    folder: &'a str,
    stamp: &'a str,
    format: &'a str,
}

impl Exporter<'_> {
    fn path(&self, kind: &str, name: &str) -> std::path::PathBuf {
        Path::new(self.folder).join(format!("{}_SumECmd_{kind}_{name}_Output.csv", self.stamp))
    }

    fn detail(&self, log: &mut Logger, slot: &mut Option<Csv>, name: &str, header: &[&str]) -> Result<(), ExportError> {
        if slot.is_none() {
            let path = self.path("DETAIL", name);
            log.debug(&format!("Setting up {name} output file: '{}'", path.display()));
            *slot = Some(Csv::create(&path, header)?);
        }
        Ok(())
    }

    /// One summary CSV (written even when it has no rows)
    fn summary(&self, name: &str, header: &[&str], rows: Vec<Vec<Field>>) -> Result<(), ExportError> {
        let mut csv = Csv::create(&self.path("SUMMARY", name), header)?;
        for row in rows {
            csv.write_line(&row, self.format)?;
        }
        csv.finish()
    }

    fn details(&self, log: &mut Logger, sum: &Sum, wd: bool) -> Result<(), ExportError> {
        let mut d = Details::default();
        let result = self.write_details(log, sum, wd, &mut d);
        let totals = [("Client", d.clients.as_ref().map(|c| c.rows)), ("Client detail", d.clients_detail.as_ref().map(|c| c.rows)), ("DNS", d.dns.as_ref().map(|c| c.rows)), ("Role", d.roles.as_ref().map(|c| c.rows)), ("VM", d.vms.as_ref().map(|c| c.rows))];
        let finished = d.finish();
        result?;
        finished?;
        log.blank();
        log.info("Export totals");
        for (label, rows) in totals {
            if let Some(rows) = rows {
                log.info(&format!("Found {} {label} entries", n0(rows)));
            }
        }
        Ok(())
    }

    fn write_details(&self, log: &mut Logger, sum: &Sum, wd: bool, d: &mut Details) -> Result<(), ExportError> {
        let unknown = "(Unknown Role Guid)";
        let description = |role: &sum_ez::Guid| sum.role_name(role).map_or_else(|| unknown.to_string(), |r| r.role_name.clone().unwrap_or_default());
        for db in &sum.processed_databases {
            let source = file_name(&db.file_name);
            log.info(&format!("Exporting Client info from '{source}'..."));
            for (role, clients) in &db.clients {
                for client in clients {
                    self.detail(log, &mut d.clients, "Clients", &CLIENT_HEADER)?;
                    if wd {
                        let mut header = vec!["Date", "Count", "DayNumber"];
                        header.extend(CLIENT_HEADER);
                        self.detail(log, &mut d.clients_detail, "ClientsDetailed", &header)?;
                    }
                    let (role_text, role_description) = (guid(role), description(role));
                    if wd {
                        let csv = d.clients_detail.as_mut().expect("created above");
                        for day in &client.day_info {
                            csv.write_line(&day_fields(day, client_fields(client, &role_text, &role_description, &source)), self.format)?;
                        }
                    }
                    d.clients.as_mut().expect("created above").write_line(&client_fields(client, &role_text, &role_description, &source), self.format)?;
                }
            }
            if !db.dns_info.is_empty() {
                log.info(&format!("Exporting DNS info from '{source}'..."));
            }
            for dns in &db.dns_info {
                self.detail(log, &mut d.dns, "DnsInfo", &["HostName", "Address", "LastSeen", "SourceFile"])?;
                d.dns.as_mut().expect("created above").write_line(&[opt(&dns.host_name), opt(&dns.address), Field::Time(dns.last_seen), text(source.clone())], self.format)?;
            }
            if !db.role_accesses.is_empty() {
                log.info(&format!("Exporting Role access info from '{source}'..."));
            }
            for ra in &db.role_accesses {
                self.detail(log, &mut d.roles, "RoleAccesses", &["RoleGuid", "RoleDescription", "FirstSeen", "LastSeen", "SourceFile"])?;
                let fields = [text(guid(&ra.role_guid)), text(description(&ra.role_guid)), Field::Time(ra.first_seen), Field::Time(ra.last_seen), text(source.clone())];
                d.roles.as_mut().expect("created above").write_line(&fields, self.format)?;
            }
            if !db.vm_info.is_empty() {
                log.info(&format!("Exporting Vm info from '{source}'..."));
            }
            for vm in &db.vm_info {
                self.detail(log, &mut d.vms, "VmInfo", &["VmGuid", "CreationTime", "LastSeenActive", "BiosGuid", "SerialNumber", "SourceFile"])?;
                let fields = [text(guid(&vm.vm_guid)), Field::Time(vm.creation_time), Field::Time(vm.last_seen_active), text(guid(&vm.bios_guid)), opt(&vm.serial_number), text(source.clone())];
                d.vms.as_mut().expect("created above").write_line(&fields, self.format)?;
            }
            log.info("-----------------------------------------------------------------------------------------------------");
        }
        Ok(())
    }
}

fn bool_text(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

fn system_identity_rows(sum: &Sum) -> Vec<Vec<Field>> {
    sum.system_identity_infos
        .iter()
        .map(|s| {
            vec![
                Field::Time(s.creation_time),
                text(s.os_major.to_string()),
                text(s.os_minor.to_string()),
                text(s.os_build.to_string()),
                opt(&s.system_dns_host_name),
                opt(&s.system_domain_name),
                opt(&s.system_manufacturer),
                opt(&s.system_product_name),
                opt(&s.system_serial_number),
                opt(&s.system_smbios_uuid),
                opt(&s.os_serial_number),
                opt(&s.os_last_boot_up_time),
                opt(&s.os_country_code),
                opt(&s.os_current_time_zone),
                opt(&s.os_daylight_in_effect.map(bool_text)),
                opt(&s.os_product_type),
                opt(&s.os_suite_mask),
                opt(&s.os_platform_id),
                opt(&s.service_pack_major),
                opt(&s.service_pack_minor),
                opt(&s.physical_processor_count),
                opt(&s.cores_per_physical_processor),
                opt(&s.logical_processors_per_physical_processor),
                opt(&s.maximum_memory),
            ]
        })
        .collect()
}

const SYSTEM_IDENTITY_HEADER: [&str; 24] = [
    "CreationTime",
    "OsMajor",
    "OsMinor",
    "OsBuild",
    "SystemDnsHostName",
    "SystemDomainName",
    "SystemManufacturer",
    "SystemProductName",
    "SystemSerialNumber",
    "SystemSmbiosUuid",
    "OsSerialNumber",
    "OsLastBootUpTime",
    "OsCountryCode",
    "OsCurrentTimeZone",
    "OsDaylightInEffect",
    "OsProductType",
    "OsSuiteMask",
    "OsPlatformId",
    "ServicePackMajor",
    "ServicePackMinor",
    "PhysicalProcessorCount",
    "CoresPerPhysicalProcessor",
    "LogicalProcessorsPerPhysicalProcessor",
    "MaximumMemory",
];

struct LogObserver<'a>(&'a mut Logger);

impl Observer for LogObserver<'_> {
    fn log(&mut self, level: Level, message: &str) {
        self.0.log(level, message);
    }
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    log.blank();
    ExitCode::FAILURE
}

fn export_error(log: &mut Logger, what: String, folder: &str, error: ExportError, format: &str) {
    match error {
        ExportError::Io(e) => {
            let message = io_message(Path::new(folder), &e);
            log.block(Level::Error, &format!("{what}: {message}\n{}: {message}", io_exception(&e)));
        }
        ExportError::BadDate => {
            log.block(Level::Error, &format!("{what}: {}\nInput string was not in a correct format: --dt '{format}'", ez_common::csv::WRITER_ERROR));
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
    let mut log = Logger::new(level, &args.dt).to_stdout();
    let stamp = utc_now().format("yyyyMMddHHmmss");
    let console_log = given(&args.csv).filter(|c| args.co && !c.trim().is_empty()).map(|d| Path::new(&full_path(d)).join(format!("{stamp}_SumECmd_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }
    let Some(directory) = given(&args.directory) else {
        return help_and_warning(&mut log, "-d is required. Exiting");
    };
    if !Path::new(directory).is_dir() {
        log.warning(&format!("Directory '{directory}' not found. Exiting"));
        log.blank();
        return ExitCode::FAILURE;
    }
    let Some(csv) = given(&args.csv) else {
        return help_and_warning(&mut log, "--csv is required. Exiting");
    };

    log.info(&format!("SumECmd (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let start = Instant::now();
    log.info(&format!("Processing '{directory}'..."));
    log.blank();
    let read = Sum::read(directory, &mut LogObserver(&mut log));
    let sum = match read {
        Ok(s) => s,
        Err(SumError::NothingToRead(m)) => {
            log.error(&m);
            log.blank();
            return ExitCode::SUCCESS;
        }
        Err(e @ (SumError::Io { .. } | SumError::DirectoryNotFound(_))) => {
            log.error(&format!("Error processing '{directory}'! Message: {e}"));
            log.blank();
            return ExitCode::FAILURE;
        }
        Err(e @ SumError::Other(_)) => {
            log.error(&format!("Error processing '{directory}'! Message: {e}"));
            log.blank();
            return ExitCode::SUCCESS;
        }
    };
    log.blank();
    log.info("Processing complete!");
    log.blank();
    log.info("Summary info:");
    for (label, count) in [
        ("Role info count:", sum.role_infos.len()),
        ("System Identity info count:", sum.system_identity_infos.len()),
        ("Chained DB info count:", sum.chained_dbs.len()),
        ("Processed DB info count:", sum.processed_databases.len()),
    ] {
        log.info(&format!("{label:<30} {}", n0(count as u64)));
    }
    log.blank();

    if !sum.failed_databases.is_empty() && sum.parse_errors.iter().any(|e| e.contains("could not be opened")) {
        log.info("A database that can't be opened may be damaged: this port reads it as it is, and can't repair a copy as the original does with 'esentutl.exe /p'");
        log.blank();
    }
    if !sum.processed_databases.is_empty() {
        log.info("The following databases were processed:");
        for db in &sum.processed_databases {
            log.info(&format!("\t{} (year {}, from {})", db.file_name, db.year, db.year_source));
        }
        log.blank();
    }

    log.info("Exporting data...");
    let mut export_failed = false;
    let exporter = Exporter { folder: csv, stamp: &stamp, format: &args.dt };
    if let Err(e) = std::fs::create_dir_all(csv) {
        export_error(&mut log, format!("Error exporting data to '{csv}'"), csv, ExportError::Io(e), &args.dt);
        export_failed = true;
    } else {
        let roles = sum.role_infos.iter().map(|r| vec![text(guid(&r.role_guid)), opt(&r.role_name), opt(&r.product_name)]).collect();
        let chained = sum.chained_dbs.iter().map(|c| vec![text(c.year.to_string()), text(c.file_name.clone())]).collect();
        let summaries: [(&str, &[&str], Vec<Vec<Field>>); 3] = [("SystemIdentInfo", &SYSTEM_IDENTITY_HEADER, system_identity_rows(&sum)), ("RoleInfos", &["RoleGuid", "RoleName", "ProductName"], roles), ("ChainedDbInfo", &["Year", "FileName"], chained)];
        for (name, header, rows) in summaries {
            if let Err(e) = exporter.summary(name, header, rows) {
                export_error(&mut log, format!("Error exporting '{name}' data! Error"), csv, e, &args.dt);
                export_failed = true;
            }
        }
        if let Err(e) = exporter.details(&mut log, &sum, args.wd) {
            export_error(&mut log, format!("Error exporting data to '{csv}'"), csv, e, &args.dt);
            export_failed = true;
        }
    }

    if !sum.parse_errors.is_empty() {
        log.blank();
        log.warning(&format!("{} problem(s) found while reading the databases (everything else was exported):", n0(sum.parse_errors.len() as u64)));
        for error in sum.parse_errors.iter().take(50) {
            log.block(Level::Warning, &format!("\t{error}"));
        }
        if sum.parse_errors.len() > 50 {
            log.warning(&format!("\t... and {} more (use --debug to see them all as they happen)", n0(sum.parse_errors.len() as u64 - 50)));
        }
    }
    log.blank();
    log.info(&format!("Processing completed in {} seconds", number_n(start.elapsed().as_secs_f64(), 4)));
    log.blank();
    if export_failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
