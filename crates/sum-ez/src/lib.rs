//! User Access Logging (UAL, `C:\Windows\System32\LogFiles\Sum` on Windows Server) databases, as Eric Zimmerman's SumData reads them:
//! `SystemIdentity.mdb` (the server, its roles and the yearly databases), `Current.mdb` and the yearly `{GUID}.mdb` databases (clients,
//! DNS, role accesses and virtual machines).
//!
//! The original reads copies of the databases through Windows' esent.dll, after replaying their transaction logs into the copies and
//! repairing a copy that is still dirty with `esentutl /p`. This reads the files as they are with `ese-ez`, and never writes. See
//! docs/plans/sumecmd.md. Nothing here prints or exits: messages go to an [`Observer`].

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use ese_ez::{Column, Database, Row, Table};
use ez_common::dotnet::{n0, ordinal_ignore_case};
use ez_common::{Level, Timestamp};

const SYSTEM_IDENTITY_NAME: &str = "SystemIdentity.mdb";
const CURRENT_NAME: &str = "Current.mdb";
/// ESE's base name for UAL's transaction logs, and the files the original copies with the databases
const LOG_BASE_NAME: &str = "Svc";
/// esent.dll's default page size, which the original's ESE instance keeps
const ENGINE_PAGE_SIZE: usize = 4096;
const LOG_EXTENSIONS: [&str; 3] = [".log", ".chk", ".jrs"];

pub type Guid = [u8; 16];

/// Gets the messages the original logs while it reads (Serilog's levels)
pub trait Observer {
    fn log(&mut self, level: Level, message: &str);
}

/// A day of a client's day counts (Day1 is January 1st of the database's year)
#[derive(Clone, Debug)]
pub struct DayEntry {
    pub day_number: i32,
    pub date: Timestamp,
    pub count: i32,
}

/// A row of CLIENTS
#[derive(Clone, Debug)]
pub struct ClientEntry {
    pub authenticated_user_name: Option<String>,
    pub total_accesses: i32,
    pub insert_date: Timestamp,
    pub last_access: Timestamp,
    pub ip_address: String,
    pub client_name: Option<String>,
    pub tenant_id: Guid,
    pub day_info: Vec<DayEntry>,
}

/// A row of DNS
#[derive(Clone, Debug)]
pub struct DnsEntry {
    pub host_name: Option<String>,
    pub address: Option<String>,
    pub last_seen: Timestamp,
}

/// A row of ROLE_ACCESS
#[derive(Clone, Debug)]
pub struct RoleAccessEntry {
    pub role_guid: Guid,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

/// A row of VIRTUALMACHINES
#[derive(Clone, Debug)]
pub struct VmEntry {
    pub vm_guid: Guid,
    pub creation_time: Timestamp,
    pub last_seen_active: Timestamp,
    pub bios_guid: Guid,
    pub serial_number: Option<String>,
}

/// Current.mdb or a yearly database, read
#[derive(Clone, Debug)]
pub struct ChainedDatabase {
    /// The path in the folder read
    pub file_name: String,
    /// The year of the day counts
    pub year: i32,
    /// Where the year comes from: CHAINED_DATABASES, or the data
    pub year_source: String,
    pub dns_info: Vec<DnsEntry>,
    pub role_accesses: Vec<RoleAccessEntry>,
    pub vm_info: Vec<VmEntry>,
    /// The clients by role, the roles in the order they were first met
    pub clients: Vec<(Guid, Vec<ClientEntry>)>,
}

/// A row of CHAINED_DATABASES
#[derive(Clone, Debug)]
pub struct ChainedDbInfo {
    pub year: i32,
    pub file_name: String,
}

/// A row of ROLE_IDS
#[derive(Clone, Debug)]
pub struct RoleInfo {
    pub role_guid: Guid,
    pub role_name: Option<String>,
    pub product_name: Option<String>,
}

/// A row of SYSTEM_IDENTITY
#[derive(Clone, Debug, Default)]
pub struct SystemIdentInfo {
    pub creation_time: Timestamp,
    pub os_major: i32,
    pub os_minor: i32,
    pub os_build: i32,
    pub system_dns_host_name: Option<String>,
    pub system_domain_name: Option<String>,
    pub system_manufacturer: Option<String>,
    pub system_product_name: Option<String>,
    pub system_serial_number: Option<String>,
    pub system_smbios_uuid: Option<String>,
    pub os_serial_number: Option<String>,
    pub os_last_boot_up_time: Option<String>,
    pub os_country_code: Option<String>,
    pub os_current_time_zone: Option<i16>,
    pub os_daylight_in_effect: Option<bool>,
    pub os_product_type: Option<u8>,
    pub os_suite_mask: Option<u16>,
    pub os_platform_id: Option<u16>,
    pub service_pack_major: Option<u8>,
    pub service_pack_minor: Option<u8>,
    pub physical_processor_count: Option<u8>,
    pub cores_per_physical_processor: Option<u8>,
    pub logical_processors_per_physical_processor: Option<u8>,
    pub maximum_memory: Option<i64>,
}

/// Why the folder couldn't be read at all
#[derive(Debug)]
pub enum SumError {
    /// The folder isn't there
    DirectoryNotFound(String),
    /// Neither SystemIdentity.mdb nor Current.mdb is in it
    NothingToRead(String),
    /// A file or the folder could not be read (the original fails in copying it)
    Io { path: String, error: std::io::Error },
    /// What else stops the original: a year a date can't have
    Other(String),
}

impl std::fmt::Display for SumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SumError::DirectoryNotFound(m) | SumError::NothingToRead(m) | SumError::Other(m) => f.write_str(m),
            SumError::Io { path, error } => f.write_str(&ez_common::cli::io_message(Path::new(path), error)),
        }
    }
}

/// The databases of a folder, read
#[derive(Debug, Default)]
pub struct Sum {
    pub system_identity_infos: Vec<SystemIdentInfo>,
    pub role_infos: Vec<RoleInfo>,
    pub chained_dbs: Vec<ChainedDbInfo>,
    pub processed_databases: Vec<ChainedDatabase>,
    /// Databases, tables and rows that could not be read (everything else was kept)
    pub parse_errors: Vec<String>,
    /// What was found about the databases' state
    pub warnings: Vec<String>,
    /// Databases that are missing or could not be opened at all
    pub failed_databases: Vec<String>,
}

/// The columns of a table by name, as ManagedEsent's GetColumnDictionary has them (case is ignored)
struct Columns<'t>(HashMap<String, &'t Column>);

impl<'t> Columns<'t> {
    fn of(table: &'t Table) -> Columns<'t> {
        Columns(table.columns.iter().map(|c| (ordinal_ignore_case(&c.name), c)).collect())
    }

    fn get(&self, name: &str) -> Option<&'t Column> {
        self.0.get(&ordinal_ignore_case(name)).copied()
    }
}

/// A column's value; None when the column isn't in the table or its value is null
fn raw<'a>(row: &Row<'a>, cols: &Columns, name: &str) -> Result<Option<Cow<'a, [u8]>>, String> {
    match cols.get(name) {
        Some(c) => row.read(c),
        None => Ok(None),
    }
}

/// ManagedEsent's RetrieveColumnAsXxx for a value of N bytes: a shorter value is an error (EsentInvalidColumnException), a longer
/// one gives its first N bytes
fn fixed<const N: usize>(row: &Row, cols: &Columns, name: &str) -> Result<Option<[u8; N]>, String> {
    match raw(row, cols, name)? {
        None => Ok(None),
        Some(v) if v.len() < N => Err(format!("Column {name} has {} bytes, fewer than its type needs ({N})", v.len())),
        Some(v) => Ok(Some(v[..N].try_into().unwrap())),
    }
}

fn guid(row: &Row, cols: &Columns, name: &str) -> Result<Guid, String> {
    Ok(fixed::<16>(row, cols, name)?.unwrap_or_default())
}

fn byte(row: &Row, cols: &Columns, name: &str) -> Result<Option<u8>, String> {
    Ok(fixed::<1>(row, cols, name)?.map(|b| b[0]))
}

fn u16_value(row: &Row, cols: &Columns, name: &str) -> Result<Option<u16>, String> {
    Ok(fixed::<2>(row, cols, name)?.map(u16::from_le_bytes))
}

/// RetrieveColumnAsString (UTF-16, an odd last byte left out) without its NUL padding; None when the column or its value is missing
fn text(row: &Row, cols: &Columns, name: &str) -> Result<Option<String>, String> {
    Ok(raw(row, cols, name)?.map(|v| {
        let units: Vec<u16> = v.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units).trim_matches('\0').to_string()
    }))
}

/// ConvertBytesToIpAddress: more than 10 bytes are IPv6 (hex, a colon after every two bytes), others IPv4
fn ip_address(raw: Option<&[u8]>) -> String {
    let Some(bytes) = raw else { return String::new() };
    if bytes.len() > 10 {
        let mut s = String::new();
        for (i, b) in bytes.iter().enumerate() {
            s.push_str(&format!("{b:02X}"));
            if (i + 1) % 2 == 0 {
                s.push(':');
            }
        }
        s.trim_matches(':').to_string()
    } else {
        let s: Vec<String> = bytes.iter().map(u8::to_string).collect();
        s.join(".")
    }
}

/// What reading keeps besides the data: problems, and where messages go
struct Context<'o> {
    parse_errors: Vec<String>,
    warnings: Vec<String>,
    failed: Vec<String>,
    observer: &'o mut dyn Observer,
    /// Whether transaction logs (Svc*.log) are next to the databases
    has_logs: bool,
}

impl Context<'_> {
    fn error(&mut self, message: String) {
        self.observer.log(Level::Warning, &message);
        self.parse_errors.push(message);
    }

    fn warning(&mut self, message: String) {
        self.observer.log(Level::Warning, &message);
        self.warnings.push(message);
    }

    fn log(&mut self, level: Level, message: &str) {
        self.observer.log(level, message);
    }

    /// A FILETIME as UTC; the minimum when missing, or (reported) out of range
    fn file_time(&mut self, row: &Row, cols: &Columns, name: &str, db_name: &str, table_name: &str) -> Result<Timestamp, String> {
        let Some(raw) = fixed::<8>(row, cols, name)?.map(i64::from_le_bytes) else { return Ok(Timestamp::MIN) };
        match Timestamp::from_filetime(raw) {
            Some(t) => Ok(t),
            None => {
                self.error(format!("{db_name} {table_name}: {name} 0x{raw:X} is not a valid time"));
                Ok(Timestamp::MIN)
            }
        }
    }

    /// Opens a database, or reports why it can't be
    fn open(&mut self, path: &str) -> Result<Option<Database>, SumError> {
        let data = std::fs::read(path).map_err(|error| SumError::Io { path: path.to_string(), error })?;
        // the original's ESE instance has esent.dll's default page size, and can't attach a database with another
        let header_page_size = data.get(236..240).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
        let is_ese = data.get(4..8) == Some(&0x89ab_cdefu32.to_le_bytes()[..]);
        let opened = if is_ese && header_page_size != Some(ENGINE_PAGE_SIZE) { Err("The database page size does not match the engine".to_string()) } else { Database::new(data) };
        match opened {
            Ok(db) => {
                if !db.is_clean() {
                    let name = file_name(path);
                    let state = db.state();
                    self.warning(if self.has_logs {
                        format!("'{name}' was not shut down cleanly ({state}) and transaction logs are next to it: they are not replayed, so what only they hold is missing (the original replays them into a copy)")
                    } else {
                        format!("'{name}' was not shut down cleanly ({state}): it is read as it is (the original repairs a copy with esentutl /p)")
                    });
                }
                Ok(Some(db))
            }
            Err(e) => {
                self.error(format!("'{path}' could not be opened: {e}"));
                self.failed.push(path.to_string());
                Ok(None)
            }
        }
    }

    /// Every row of a table, each one on its own: a row that fails is reported and the next one is read
    fn read_table(&mut self, db: &Database, db_name: &str, table_name: &str, read_row: &mut dyn FnMut(&mut Self, &Row, &Columns) -> Result<(), String>) {
        let wanted = ordinal_ignore_case(table_name);
        let Some(table) = db.tables().iter().find(|t| ordinal_ignore_case(&t.name) == wanted) else {
            self.log(Level::Debug, &format!("{db_name} has no table {table_name}"));
            return;
        };
        let cols = Columns::of(table);
        let mut count = 0u64;
        let walked = db.for_each_row(table, &mut |row| {
            count += 1;
            if let Err(e) = read_row(self, &row, &cols) {
                self.error(format!("{db_name} {table_name} row {count}: {e}"));
            }
            Ok(())
        });
        if let Err(e) = walked {
            self.error(format!("{db_name} {table_name}: reading stopped after {} rows: {e}", n0(count)));
        }
    }
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

fn same_name(a: &str, b: &str) -> bool {
    ordinal_ignore_case(a) == ordinal_ignore_case(b)
}

/// Directory.GetFiles(directory): the files of a folder (not its folders), in the order Windows lists them
fn files_of(directory: &str) -> Result<Vec<(String, String)>, SumError> {
    let entries = ez_common::cli::read_dir_ntfs_order(Path::new(directory)).map_err(|error| SumError::Io { path: directory.to_string(), error })?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.path();
        let is_dir = match entry.file_type() {
            Ok(t) if t.is_symlink() => std::fs::metadata(&path).is_ok_and(|m| m.is_dir()),
            Ok(t) => t.is_dir(),
            Err(_) => false,
        };
        if !is_dir {
            files.push((entry.file_name().to_string_lossy().into_owned(), path.to_string_lossy().into_owned()));
        }
    }
    Ok(files)
}

/// The year of a database that doesn't say: the latest year in its times, else the year after the newest chained database, else the
/// year the file was last written
fn year_from_data(db: &ChainedDatabase, chained: &[ChainedDbInfo]) -> (i32, &'static str) {
    let times = db.clients.iter().flat_map(|(_, c)| c.iter().map(|c| c.last_access)).chain(db.role_accesses.iter().map(|r| r.last_seen)).chain(db.dns_info.iter().map(|d| d.last_seen));
    if let Some(max) = times.filter(|t| *t > Timestamp::MIN && t.parts().year > 1601).max() {
        return (max.parts().year, "the year of the latest access in it");
    }
    if let Some(max) = chained.iter().map(|c| c.year).max() {
        return (max + 1, "the year after the newest chained database");
    }
    let written = std::fs::metadata(&db.file_name).and_then(|m| m.modified()).ok();
    let year = written.and_then(|w| w.duration_since(std::time::UNIX_EPOCH).ok()).map_or(1601, |d| Timestamp(621_355_968_000_000_000 + (d.as_nanos() / 100) as i64).parts().year);
    (year, "the year the database file was last written")
}

/// .NET's message when a year or a day is outside what a date can hold
const BAD_DATE: &str = "Year, Month, and Day parameters describe an un-representable DateTime.";
const BAD_ADD: &str = "The added or subtracted value results in an un-representable DateTime. (Parameter 'value')";
const TICKS_PER_DAY: i64 = 864_000_000_000;

impl Sum {
    /// Reads the databases in `directory`: SystemIdentity.mdb, Current.mdb, the chained (yearly) databases it lists, and any other
    /// `.mdb` there. A database, table or row that can't be read is reported in [`parse_errors`](Self::parse_errors) and the rest is kept
    pub fn read(directory: &str, observer: &mut dyn Observer) -> Result<Sum, SumError> {
        if !Path::new(directory).is_dir() {
            return Err(SumError::DirectoryNotFound(format!("Directory '{directory}' not found!")));
        }
        let files = files_of(directory)?;
        let mdb_files: Vec<(String, String)> = files.iter().filter(|(n, _)| ordinal_ignore_case(n).ends_with(".MDB")).cloned().collect();
        let find = |wanted: &str| mdb_files.iter().find(|(n, _)| same_name(n, wanted)).map(|(_, p)| p.clone());
        let (sys_ident, current) = (find(SYSTEM_IDENTITY_NAME), find(CURRENT_NAME));
        if sys_ident.is_none() && current.is_none() {
            return Err(SumError::NothingToRead(format!("Neither '{SYSTEM_IDENTITY_NAME}' nor '{CURRENT_NAME}' was found in '{directory}'!")));
        }
        // the original copies every database and the transaction logs first: one it can't read stops it
        let logs = files.iter().filter(|(n, _)| {
            let upper = ordinal_ignore_case(n);
            upper.starts_with(&ordinal_ignore_case(LOG_BASE_NAME)) && LOG_EXTENSIONS.iter().any(|e| upper.ends_with(&ordinal_ignore_case(e)))
        });
        let logs: Vec<&(String, String)> = logs.collect();
        let has_logs = logs.iter().any(|(n, _)| ordinal_ignore_case(n).ends_with(".LOG"));
        for (_, path) in mdb_files.iter().chain(logs) {
            std::fs::File::open(path).map_err(|error| SumError::Io { path: path.clone(), error })?;
        }

        let mut sum = Sum::default();
        let mut cx = Context { parse_errors: Vec::new(), warnings: Vec::new(), failed: Vec::new(), observer, has_logs };
        let result = sum.read_all(&mut cx, directory, &mdb_files, sys_ident, current);
        sum.parse_errors = cx.parse_errors;
        sum.warnings = cx.warnings;
        sum.failed_databases = cx.failed;
        result.map(|()| sum)
    }

    fn read_all(&mut self, cx: &mut Context, directory: &str, mdb_files: &[(String, String)], sys_ident: Option<String>, current: Option<String>) -> Result<(), SumError> {
        let combine = |name: &str| Path::new(directory).join(name).to_string_lossy().into_owned();
        match sys_ident {
            Some(path) => {
                cx.log(Level::Info, &format!("Found '{path}'. Processing..."));
                self.read_system_identity(cx, &path)?;
            }
            None => {
                cx.error(format!("'{SYSTEM_IDENTITY_NAME}' not found in '{directory}': no role names, system identity or chained database list"));
                cx.failed.push(combine(SYSTEM_IDENTITY_NAME));
            }
        }
        match current {
            Some(path) => {
                cx.log(Level::Info, &format!("Found '{path}'. Processing..."));
                self.read_database(cx, &path, None)?;
            }
            None => {
                cx.error(format!("'{CURRENT_NAME}' not found in '{directory}'"));
                cx.failed.push(combine(CURRENT_NAME));
            }
        }
        for info in self.chained_dbs.clone() {
            let Some((_, path)) = mdb_files.iter().find(|(n, _)| same_name(n, &info.file_name)) else {
                cx.log(Level::Info, &format!("Chained database '{}' for year {} does not exist! Skipping...", combine(&info.file_name), info.year));
                continue;
            };
            cx.log(Level::Info, &format!("Found '{path}' for year {}. Processing...", info.year));
            self.read_database(cx, path, Some(info.year))?;
        }
        for (name, path) in mdb_files {
            if same_name(name, SYSTEM_IDENTITY_NAME) || same_name(name, CURRENT_NAME) || self.chained_dbs.iter().any(|c| same_name(&c.file_name, name)) {
                continue;
            }
            cx.log(Level::Info, &format!("Found '{path}', not listed in CHAINED_DATABASES. Processing..."));
            self.read_database(cx, path, None)?;
        }
        Ok(())
    }

    /// The role name of a role GUID (the first listed)
    pub fn role_name(&self, role: &Guid) -> Option<&RoleInfo> {
        self.role_infos.iter().find(|r| &r.role_guid == role)
    }

    fn read_database(&mut self, cx: &mut Context, path: &str, year: Option<i32>) -> Result<(), SumError> {
        let Some(db) = cx.open(path)? else { return Ok(()) };
        let db_name = file_name(path);
        let mut out = ChainedDatabase { file_name: path.to_string(), year: 0, year_source: String::new(), dns_info: Vec::new(), role_accesses: Vec::new(), vm_info: Vec::new(), clients: Vec::new() };
        // the day counts of each client (by its role and place), dated once the year is known; those of a row that failed half way
        // are counted too (None), as the original keeps them
        let mut days: Vec<(Option<(usize, usize)>, i32, i32)> = Vec::new();

        cx.log(Level::Debug, "Getting Clients info");
        cx.read_table(&db, &db_name, "CLIENTS", &mut |cx, row, cols| {
            let user = text(row, cols, "AuthenticatedUserName")?;
            let client_name = text(row, cols, "ClientName")?;
            let insert_date = cx.file_time(row, cols, "InsertDate", &db_name, "CLIENTS")?;
            let last_access = cx.file_time(row, cols, "LastAccess", &db_name, "CLIENTS")?;
            let role = guid(row, cols, "RoleGuid")?;
            let tenant_id = guid(row, cols, "TenantId")?;
            let address = raw(row, cols, "Address")?;
            let mut total = fixed::<4>(row, cols, "TotalAccesses")?.map_or(0, u32::from_le_bytes);
            if total > i32::MAX as u32 {
                cx.error(format!("{db_name} CLIENTS: TotalAccesses {total} is larger than {}; {} is used", i32::MAX, i32::MAX));
                total = i32::MAX as u32;
            }
            let role_at = match out.clients.iter().position(|(g, _)| *g == role) {
                Some(i) => i,
                None => {
                    out.clients.push((role, Vec::new()));
                    out.clients.len() - 1
                }
            };
            let entry = ClientEntry { authenticated_user_name: user, total_accesses: total as i32, insert_date, last_access, ip_address: ip_address(address.as_deref()), client_name, tenant_id, day_info: Vec::new() };
            let first_day = days.len();
            for i in 1..=366 {
                let name = format!("Day{i}");
                if cols.get(&name).is_none() {
                    continue;
                }
                match u16_value(row, cols, &name) {
                    Ok(Some(count)) => days.push((None, i, i32::from(count))),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            }
            let place = (role_at, out.clients[role_at].1.len());
            for d in &mut days[first_day..] {
                d.0 = Some(place);
            }
            out.clients[role_at].1.push(entry);
            cx.log(Level::Trace, "Added client info");
            Ok(())
        });

        cx.log(Level::Debug, "Getting DNS info");
        cx.read_table(&db, &db_name, "DNS", &mut |cx, row, cols| {
            let address = text(row, cols, "Address")?;
            let host_name = text(row, cols, "HostName")?;
            let last_seen = cx.file_time(row, cols, "LastSeen", &db_name, "DNS")?;
            out.dns_info.push(DnsEntry { host_name, address, last_seen });
            cx.log(Level::Trace, "Added DNS info");
            Ok(())
        });

        cx.log(Level::Debug, "Getting Role Access info");
        cx.read_table(&db, &db_name, "ROLE_ACCESS", &mut |cx, row, cols| {
            let first_seen = cx.file_time(row, cols, "FirstSeen", &db_name, "ROLE_ACCESS")?;
            let last_seen = cx.file_time(row, cols, "LastSeen", &db_name, "ROLE_ACCESS")?;
            let role_guid = guid(row, cols, "RoleGuid")?;
            out.role_accesses.push(RoleAccessEntry { role_guid, first_seen, last_seen });
            cx.log(Level::Trace, "Added role access info");
            Ok(())
        });

        cx.log(Level::Debug, "Getting Virtual Machines info");
        cx.read_table(&db, &db_name, "VIRTUALMACHINES", &mut |cx, row, cols| {
            let serial_number = text(row, cols, "SerialNumber")?;
            let creation_time = cx.file_time(row, cols, "CreationTime", &db_name, "VIRTUALMACHINES")?;
            let last_seen_active = cx.file_time(row, cols, "LastSeenActive", &db_name, "VIRTUALMACHINES")?;
            let bios_guid = guid(row, cols, "BIOSGuid")?;
            let vm_guid = guid(row, cols, "VmGuid")?;
            out.vm_info.push(VmEntry { vm_guid, creation_time, last_seen_active, bios_guid, serial_number });
            cx.log(Level::Trace, "Added VM info");
            Ok(())
        });

        let year = match year {
            Some(y) => {
                out.year_source = "CHAINED_DATABASES".to_string();
                y
            }
            None => {
                let (y, source) = year_from_data(&out, &self.chained_dbs);
                out.year_source = source.to_string();
                if !days.is_empty() {
                    cx.log(Level::Info, &format!("{db_name}: day counts are dated in {y} ({source})"));
                }
                y
            }
        };
        out.year = year;
        let Some(jan1) = Timestamp::from_parts(year, 1, 1, 0, 0, 0, 0) else {
            return Err(SumError::Other(BAD_DATE.to_string()));
        };
        for (place, day, count) in days {
            let ticks = jan1.ticks() + i64::from(day - 1) * TICKS_PER_DAY;
            if ticks > ez_common::time::MAX_TICKS {
                return Err(SumError::Other(BAD_ADD.to_string()));
            }
            if let Some((r, c)) = place {
                out.clients[r].1[c].day_info.push(DayEntry { day_number: day, date: Timestamp(ticks), count });
            }
        }
        self.processed_databases.push(out);
        Ok(())
    }

    fn read_system_identity(&mut self, cx: &mut Context, path: &str) -> Result<(), SumError> {
        let Some(db) = cx.open(path)? else { return Ok(()) };
        let db_name = file_name(path);

        cx.log(Level::Debug, "Getting System identity info");
        let infos = &mut self.system_identity_infos;
        cx.read_table(&db, &db_name, "SYSTEM_IDENTITY", &mut |cx, row, cols| {
            let creation_time = cx.file_time(row, cols, "CreationTime", &db_name, "SYSTEM_IDENTITY")?;
            let os_major = i32::from(byte(row, cols, "OSMajor")?.unwrap_or(0));
            let os_minor = i32::from(byte(row, cols, "OSMinor")?.unwrap_or(0));
            let os_build = i32::from(u16_value(row, cols, "OSBuildNumber")?.unwrap_or(0));
            let si = SystemIdentInfo {
                creation_time,
                os_major,
                os_minor,
                os_build,
                system_dns_host_name: text(row, cols, "SystemDNSHostName")?,
                system_domain_name: text(row, cols, "SystemDomainName")?,
                system_manufacturer: text(row, cols, "SystemManufacturer")?,
                system_product_name: text(row, cols, "SystemProductName")?,
                system_serial_number: text(row, cols, "SystemSerialNumber")?,
                system_smbios_uuid: text(row, cols, "SystemSMBIOSUUID")?,
                os_serial_number: text(row, cols, "OSSerialNumber")?,
                os_last_boot_up_time: text(row, cols, "OSLastBootUpTime")?,
                os_country_code: text(row, cols, "OSCountryCode")?,
                os_current_time_zone: fixed::<2>(row, cols, "OSCurrentTimeZone")?.map(i16::from_le_bytes),
                os_daylight_in_effect: byte(row, cols, "OSDaylightInEffect")?.map(|b| b != 0),
                os_product_type: byte(row, cols, "OSProductType")?,
                os_suite_mask: u16_value(row, cols, "OSSuiteMask")?,
                os_platform_id: u16_value(row, cols, "OSPlatformId")?,
                service_pack_major: byte(row, cols, "ServicePackMajor")?,
                service_pack_minor: byte(row, cols, "ServicePackMinor")?,
                physical_processor_count: byte(row, cols, "PhysicalProcessorCount")?,
                cores_per_physical_processor: byte(row, cols, "CoresPerPhysicalProcessor")?,
                logical_processors_per_physical_processor: byte(row, cols, "LogicalProcessorsPerPhysicalProcessor")?,
                maximum_memory: fixed::<8>(row, cols, "MaximumMemory")?.map(i64::from_le_bytes),
            };
            infos.push(si);
            cx.log(Level::Trace, "Added system identity info");
            Ok(())
        });

        cx.log(Level::Debug, "Getting Role Id info");
        let roles = &mut self.role_infos;
        cx.read_table(&db, &db_name, "ROLE_IDS", &mut |cx, row, cols| {
            let role_guid = guid(row, cols, "RoleGuid")?;
            let product_name = text(row, cols, "ProductName")?;
            let role_name = text(row, cols, "RoleName")?;
            roles.push(RoleInfo { role_guid, role_name, product_name });
            cx.log(Level::Trace, "Added role info");
            Ok(())
        });

        cx.log(Level::Debug, "Getting Chained database info");
        let chained = &mut self.chained_dbs;
        cx.read_table(&db, &db_name, "CHAINED_DATABASES", &mut |cx, row, cols| {
            let year = u16_value(row, cols, "Year")?;
            let file_name = text(row, cols, "FileName")?.filter(|f| !f.is_empty());
            let (Some(year), Some(file_name)) = (year, file_name) else {
                return Err(format!("no {}", if year.is_none() { "Year" } else { "FileName" }));
            };
            chained.push(ChainedDbInfo { year: i32::from(year), file_name });
            cx.log(Level::Trace, "Added chained db info");
            Ok(())
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_addresses() {
        assert_eq!(ip_address(None), "");
        assert_eq!(ip_address(Some(&[])), "");
        assert_eq!(ip_address(Some(&[10, 0, 0, 5])), "10.0.0.5");
        let v6: Vec<u8> = (1..=16).collect();
        assert_eq!(ip_address(Some(&v6)), "0102:0304:0506:0708:090A:0B0C:0D0E:0F10");
        // 11 bytes: hex, the last one alone
        assert_eq!(ip_address(Some(&[0xab; 11])), "ABAB:ABAB:ABAB:ABAB:ABAB:AB");
    }
}
