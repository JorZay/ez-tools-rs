//! SRUM databases (SRUDB.dat), as Eric Zimmerman's SrumData reads them: the id map, then one table per provider. A table or row
//! that can't be read is reported and the rest is kept. Reads with `ese-ez`, in place and never writing, so its logs aren't
//! replayed and a dirty database shows what had reached it. Nothing here prints or exits.

pub mod names;

use std::collections::HashMap;

use ese_ez::{Column, Database, Row, Table};
use ez_common::Timestamp;
use ez_common::dotnet::from_oa_date;
use ez_common::net::unicode_string;
use registry_ez::hive::Hive;

use names::{interface_type_name, sid_type_name};

/// A cell of a CSV, as its class's property would write it
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    Int(i64),
    /// An int? that may be missing
    OptInt(Option<i32>),
    Text(Option<String>),
    /// A time the tool formats with --dt
    Time(Timestamp),
    /// EventTimestamp: as Time, or nothing
    OptTime(Option<Timestamp>),
    /// ExeTimestamp: CsvHelper's default for a DateTimeOffset
    Default(Option<Timestamp>),
    Bool(bool),
    /// A TimeSpan's ticks
    Span(i64),
}

/// One CSV: its name in the file's, the table it's from, its columns and rows
pub struct Sheet {
    pub name: &'static str,
    pub table_name: &'static str,
    pub columns: &'static [&'static str],
    pub rows: Vec<Vec<Cell>>,
}

/// What Windows names these tables
pub const NETWORK_USAGE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
pub const PUSH_NOTIFICATION: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}";
pub const NETWORK_CONNECTION: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";
pub const APP_RESOURCE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
pub const VFUPROV: &str = "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}";
pub const TIMELINE: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";
pub const ENERGY: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}";
pub const ENERGY_LT: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT";
pub const ENERGY_BOTH: &str = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}_{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT";
pub const PROCESSOR_TIME: &str = "{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}";
pub const SIZE_IN_BYTES: &str = "{841A7317-3805-518B-C2EA-AD224CB4AF84}";
pub const TOTAL_USED: &str = "{17F4D97B-F26A-5E79-3A82-90040A47D13D}";
pub const NETWORK_BYTES: &str = "{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}";

const ENERGY_COLUMNS: &[&str] = &[
    "Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "IsLt", "ConfigurationHash", "EventTimestamp", "StateTransition", "ChargeLevel", "CycleCount", "DesignedCapacity",
    "FullChargedCapacity", "ActiveAcTime", "ActiveDcTime", "ActiveDischargeTime", "ActiveEnergy", "CsAcTime", "CsDcTime", "CsDischargeTime", "CsEnergy",
];
const TIMELINE_COLUMNS: &[&str] = &[
    "Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "EndTime", "DurationMs", "InFocusS", "PsmForegroundS", "UserInputS", "KeyboardInputS", "MouseInputS", "DisplayRequiredS",
    "AudioInS", "AudioOutS",
];
const VFUPROV_COLUMNS: &[&str] = &["Id", "Timestamp", "UserId", "AppId", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "StartTime", "EndTime", "Flags", "Duration"];
const APP_RESOURCE_COLUMNS: &[&str] = &[
    "Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "BackgroundBytesRead", "BackgroundBytesWritten", "BackgroundContextSwitches", "BackgroundCycleTime",
    "BackgroundNumberOfFlushes", "BackgroundNumReadOperations", "BackgroundNumWriteOperations", "FaceTime", "ForegroundBytesRead", "ForegroundBytesWritten", "ForegroundContextSwitches", "ForegroundCycleTime", "ForegroundNumberOfFlushes",
    "ForegroundNumReadOperations", "ForegroundNumWriteOperations",
];
const CONNECTION_COLUMNS: &[&str] = &[
    "Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "ConnectedTime", "ConnectStartTime", "InterfaceLuid", "InterfaceType", "L2ProfileFlags", "L2ProfileId", "ProfileName",
];
const USAGE_COLUMNS: &[&str] = &[
    "Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "BytesReceived", "BytesSent", "InterfaceLuid", "InterfaceType", "L2ProfileFlags", "L2ProfileId", "ProfileName",
];
const PUSH_COLUMNS: &[&str] = &["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "NetworkType", "NotificationType", "PayloadSize"];
const PROCESSOR_COLUMNS: &[&str] = &["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "ProcessorTime"];
const SIZE_COLUMNS: &[&str] = &["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "SizeInBytes"];
const TOTAL_COLUMNS: &[&str] = &["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "Total", "Used"];
const BYTES_COLUMNS: &[&str] = &["Id", "Timestamp", "ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "Sid", "UserName", "UserId", "AppId", "BytesInBound", "BytesOutBound", "BytesTotal"];

/// AppInfo: an entry of the id map that isn't a SID
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppInfo {
    pub exe_info: String,
    pub description: Option<String>,
    pub timestamp: Option<Timestamp>,
    pub unknown: Option<String>,
}

/// DateTimeOffset.TryParseExact(text, "yyyy/MM/dd:HH:mm:ss", AssumeUniversal)
fn parse_app_time(text: &str) -> Option<Timestamp> {
    let b = text.as_bytes();
    if b.len() != 19 || b[4] != b'/' || b[7] != b'/' || b[10] != b':' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        if part.bytes().all(|c| c.is_ascii_digit()) { part.parse().ok() } else { None }
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if year == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Timestamp::from_parts(year as i32, month, day, hour, minute, second, 0)
}

impl AppInfo {
    /// new AppInfo: a `!!name!time!x!description` is taken apart, anything else is the name
    pub fn new(exe_info: &str) -> AppInfo {
        let mut info = AppInfo { exe_info: exe_info.to_string(), ..AppInfo::default() };
        let Some(rest) = exe_info.strip_prefix("!!") else { return info };
        let segments: Vec<&str> = rest.split('!').collect();
        if segments.len() < 4 {
            return info;
        }
        let mut name = if segments[0].is_empty() { "!".to_string() } else { segments[0].to_string() };
        let count = segments.len();
        for segment in &segments[1..count - 3] {
            name.push('!');
            name.push_str(segment);
        }
        info.exe_info = name;
        info.unknown = Some(segments[count - 2].to_string());
        info.description = Some(segments[count - 1].to_string());
        info.timestamp = parse_app_time(segments[count - 3]);
        info
    }
}

/// UserInfo: a SID of the id map
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserInfo {
    pub sid: String,
    pub user_name: String,
    pub sid_type: &'static str,
}

/// Srum.ConvertHexStringToSidString
pub fn sid_from_bytes(hex: Option<&[u8]>) -> String {
    let Some(hex) = hex.filter(|h| h.len() > 8) else { return String::new() };
    let authority = i32::from_be_bytes(hex[4..8].try_into().unwrap());
    let mut sid = format!("S-{}-{authority}", hex[0]);
    for chunk in hex[8..].chunks_exact(4) {
        sid.push('-');
        sid.push_str(&u32::from_le_bytes(chunk.try_into().unwrap()).to_string());
    }
    sid
}

/// TimeSpan.ToString("c") of some ticks
pub fn span_text(ticks: i64) -> String {
    let sign = if ticks < 0 { "-" } else { "" };
    let t = ticks.unsigned_abs();
    let (days, rest) = (t / 864_000_000_000, t % 864_000_000_000);
    let (hours, minutes, seconds, fraction) = (rest / 36_000_000_000, rest / 600_000_000 % 60, rest / 10_000_000 % 60, rest % 10_000_000);
    let day_part = if days > 0 { format!("{days}.") } else { String::new() };
    let fraction_part = if fraction > 0 { format!(".{fraction:07}") } else { String::new() };
    format!("{sign}{day_part}{hours:02}:{minutes:02}:{seconds:02}{fraction_part}")
}

/// What the caller is told as it happens, as the original logs it
pub trait Observer {
    fn warning(&mut self, message: &str);
}

/// What a SOFTWARE hive adds: user names by SID, Wi-Fi profile names by index, and what couldn't be read of them
#[derive(Debug, Default)]
pub struct SoftwareNames {
    pub sid_to_user: HashMap<String, String>,
    pub ssids: HashMap<i32, String>,
    pub problems: Vec<String>,
}

impl SoftwareNames {
    /// ReadSoftwareHive. An error says why the hive couldn't be read at all, and whether it's because it couldn't be accessed
    pub fn read(path: &str) -> Result<SoftwareNames, (String, bool)> {
        let bytes = std::fs::read(path).map_err(|e| (e.to_string(), true))?;
        if bytes.len() >= 4 && bytes[..4] != *b"regf" {
            return Err((format!("{path} is not a Registry hive (bad signature)"), false));
        }
        let mut hive = Hive::new(bytes, path).map_err(|e| (e.to_string(), false))?;
        hive.recover_deleted = false;
        hive.parse().map_err(|e| (e.to_string(), false))?;
        let mut names = SoftwareNames::default();
        let value = |hive: &Hive, key: usize, name: &str| hive.keys[key].values.iter().copied().find(|&v| hive.vks[v].name().is_ok_and(|n| n == name));
        if let Some(list) = hive.get_key("Microsoft\\Windows NT\\CurrentVersion\\ProfileList") {
            for &key in &hive.keys[list].subkeys {
                if let Some(v) = value(&hive, key, "ProfileImagePath") {
                    match hive.value_data(v) {
                        Ok(data) => {
                            let text = data.text();
                            let user = text.rsplit(['\\', '/']).next().unwrap_or_default().to_string();
                            names.sid_to_user.insert(hive.key_name(key).to_string(), user);
                        }
                        Err(e) => names.problems.push(format!("SOFTWARE hive: profile '{}': {e}", hive.key_name(key))),
                    }
                }
            }
        }
        let Some(interfaces) = hive.get_key("Microsoft\\WlanSvc\\Interfaces") else { return Ok(names) };
        for &interface in &hive.keys[interfaces].subkeys {
            let Some(profiles) = hive.keys[interface].subkeys.iter().copied().find(|&k| hive.key_name(k) == "Profiles") else { continue };
            for &profile in &hive.keys[profiles].subkeys {
                let attempt = (|| -> Result<(), String> {
                    let Some(index_value) = value(&hive, profile, "ProfileIndex") else { return Ok(()) };
                    let Some(meta) = hive.keys[profile].subkeys.iter().copied().find(|&k| hive.key_name(k) == "MetaData") else { return Ok(()) };
                    let Some(hints) = value(&hive, meta, "Channel Hints") else { return Ok(()) };
                    let raw = hive.value_raw(hints)?;
                    if raw.len() < 4 {
                        return Ok(());
                    }
                    let length = i32::from_le_bytes(raw[..4].try_into().unwrap());
                    if length < 0 || i64::from(length) > raw.len() as i64 - 4 {
                        return Err(format!("Channel Hints says the name has {length} bytes, but the value has {}", raw.len()));
                    }
                    let name: String = raw[4..4 + length as usize].iter().map(|&b| if b < 0x80 { b as char } else { '?' }).collect();
                    let index_text = hive.value_data(index_value)?.text();
                    let index: i32 = index_text.trim().parse().map_err(|_| format!("ProfileIndex '{index_text}' is not a number"))?;
                    names.ssids.entry(index).or_insert(name);
                    Ok(())
                })();
                if let Err(e) = attempt {
                    names.problems.push(format!("SOFTWARE hive: Wi-Fi profile '{}': {e}", hive.keys[profile].path));
                }
            }
        }
        Ok(names)
    }
}

/// The result of reading a database
pub struct Srum {
    pub state: String,
    pub format_version: u32,
    pub format_revision: u32,
    pub energy: Sheet,
    pub timeline: Sheet,
    pub vfuprov: Sheet,
    pub app_resource: Sheet,
    pub connections: Sheet,
    pub usage: Sheet,
    pub push: Sheet,
    pub processor_time: Sheet,
    pub size_in_bytes: Sheet,
    pub total_used: Sheet,
    pub network_bytes: Sheet,
    pub parse_errors: Vec<String>,
    pub warnings: Vec<String>,
    pub software_hive_not_accessed: bool,
    apps: HashMap<i32, AppInfo>,
    users: HashMap<i32, UserInfo>,
    sid_to_user: HashMap<String, String>,
    ssids: HashMap<i32, String>,
    missing_ids: u64,
}

/// An exception that stops the database being read: its message, and whether it couldn't be read as opposed to being damaged
#[derive(Debug)]
pub struct SrumError {
    pub message: String,
    pub read_error: bool,
    pub exception: &'static str,
}

fn sheet(name: &'static str, table_name: &'static str, columns: &'static [&'static str]) -> Sheet {
    Sheet { name, table_name, columns, rows: Vec::new() }
}

/// A row's values by name. A missing column or a null gives what the original's Row gives
struct Values<'a, 'b> {
    table: &'b Table,
    row: Row<'a>,
}

impl Values<'_, '_> {
    fn bytes(&self, column: &Column) -> Result<Option<&[u8]>, String> {
        self.row.value(column)
    }

    fn int_or_null(&self, name: &str) -> Result<Option<i32>, String> {
        let Some(column) = self.table.column(name) else { return Ok(None) };
        match self.bytes(column)? {
            None => Ok(None),
            Some(b) => Ok(Some(i32::from_le_bytes(b.try_into().map_err(|_| format!("Column {name} is {} bytes, not 4", b.len()))?))),
        }
    }

    fn int(&self, name: &str) -> Result<i32, String> {
        Ok(self.int_or_null(name)?.unwrap_or(0))
    }

    fn long(&self, name: &str) -> Result<i64, String> {
        let Some(column) = self.table.column(name) else { return Ok(0) };
        match self.bytes(column)? {
            None => Ok(0),
            Some(b) => Ok(i64::from_le_bytes(b.try_into().map_err(|_| format!("Column {name} is {} bytes, not 8", b.len()))?)),
        }
    }
}

/// The id, app and user columns every class has, in their usual order
fn identity(id: i64, timestamp: Timestamp, app: Option<&AppInfo>, user: Option<&UserInfo>, user_id: i32, app_id: i32) -> Vec<Cell> {
    let mut cells = vec![Cell::Int(id), Cell::Time(timestamp)];
    cells.extend(exe_cells(app, user));
    cells.push(Cell::Int(i64::from(user_id)));
    cells.push(Cell::Int(i64::from(app_id)));
    cells
}

/// ExeInfo, ExeInfoDescription, ExeTimestamp, SidType, Sid and UserName
fn exe_cells(app: Option<&AppInfo>, user: Option<&UserInfo>) -> Vec<Cell> {
    vec![
        Cell::Text(app.map(|a| a.exe_info.clone())),
        Cell::Text(app.and_then(|a| a.description.clone())),
        Cell::Default(app.and_then(|a| a.timestamp)),
        Cell::Text(Some(user.map_or("UnknownOrUserSid", |u| u.sid_type).to_string())),
        Cell::Text(user.map(|u| u.sid.clone())),
        Cell::Text(user.map(|u| u.user_name.clone())),
    ]
}

/// SrumTime.FromFileTime
fn from_file_time(raw: i64) -> Timestamp {
    Timestamp::from_filetime(raw).unwrap_or(Timestamp::MIN)
}

impl Srum {
    fn empty(db: &Database) -> Srum {
        Srum {
            state: db.state(),
            format_version: db.format_version,
            format_revision: db.format_revision,
            energy: sheet("EnergyUsage", ENERGY_BOTH, ENERGY_COLUMNS),
            timeline: sheet("AppTimelineProvider", TIMELINE, TIMELINE_COLUMNS),
            vfuprov: sheet("vfuprov", VFUPROV, VFUPROV_COLUMNS),
            app_resource: sheet("AppResourceUseInfo", APP_RESOURCE, APP_RESOURCE_COLUMNS),
            connections: sheet("NetworkConnections", NETWORK_CONNECTION, CONNECTION_COLUMNS),
            usage: sheet("NetworkUsages", NETWORK_USAGE, USAGE_COLUMNS),
            push: sheet("PushNotifications", PUSH_NOTIFICATION, PUSH_COLUMNS),
            processor_time: sheet("ProcessorTime", PROCESSOR_TIME, PROCESSOR_COLUMNS),
            size_in_bytes: sheet("SizeInBytes", SIZE_IN_BYTES, SIZE_COLUMNS),
            total_used: sheet("TotalUsed", TOTAL_USED, TOTAL_COLUMNS),
            network_bytes: sheet("NetworkBytes", NETWORK_BYTES, BYTES_COLUMNS),
            parse_errors: Vec::new(),
            warnings: Vec::new(),
            software_hive_not_accessed: false,
            apps: HashMap::new(),
            users: HashMap::new(),
            sid_to_user: HashMap::new(),
            ssids: HashMap::new(),
            missing_ids: 0,
        }
    }

    /// The sheets in the order the tool writes them
    pub fn sheets(&self) -> [&Sheet; 11] {
        [&self.energy, &self.timeline, &self.vfuprov, &self.app_resource, &self.connections, &self.usage, &self.push, &self.processor_time, &self.size_in_bytes, &self.total_used, &self.network_bytes]
    }

    fn error(&mut self, message: String, observer: &mut dyn Observer) {
        observer.warning(&message);
        self.parse_errors.push(message);
    }

    fn warn(&mut self, message: String, observer: &mut dyn Observer) {
        observer.warning(&message);
        self.warnings.push(message);
    }

    /// new Srum: the database at a path, and optionally a SOFTWARE hive for user and Wi-Fi profile names
    pub fn read(file: &str, software_hive: Option<&str>, observer: &mut dyn Observer) -> Result<Srum, SrumError> {
        let data = std::fs::read(file).map_err(|e| SrumError { message: e.to_string(), read_error: true, exception: "System.IO.IOException" })?;
        let db = Database::new(data).map_err(|message| SrumError { message, read_error: false, exception: "Microsoft.Isam.Esent.Interop.EsentErrorException" })?;
        let mut srum = Srum::empty(&db);
        if let Some(hive) = software_hive {
            match SoftwareNames::read(hive) {
                Ok(names) => {
                    for problem in names.problems {
                        srum.error(problem, observer);
                    }
                    srum.sid_to_user = names.sid_to_user;
                    srum.ssids = names.ssids;
                }
                Err((message, access)) => {
                    srum.software_hive_not_accessed = access;
                    srum.error(format!("SOFTWARE hive '{hive}': {message}. User and network profile names may be missing"), observer);
                }
            }
        }
        if !db.is_clean() {
            srum.warn(format!("The database's state is '{}': it is read as it is, without replaying its transaction logs, so what only they have is missing", db.state()), observer);
        }
        srum.read_tables(&db, observer);
        Ok(srum)
    }

    /// new Srum on a database already in memory
    pub fn from_database(db: &Database, observer: &mut dyn Observer) -> Srum {
        let mut srum = Srum::empty(db);
        srum.read_tables(db, observer);
        srum
    }

    /// The id map's raw entries: index, type and blob, for comparing how they read with the original's classes
    pub fn raw_id_map(db: &Database) -> Vec<(i32, Option<u8>, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let Some(table) = db.table("SruDbIdMapTable") else { return out };
        let _ = db.for_each_row(table, &mut |row| {
            let r = Values { table, row };
            let kind = r.table.column("IdType").and_then(|c| r.bytes(c).ok().flatten()).and_then(|b| b.first().copied());
            let blob = r.table.column("IdBlob").and_then(|c| r.bytes(c).ok().flatten()).map(<[u8]>::to_vec);
            out.push((r.int("IdIndex").unwrap_or(0), kind, blob));
            Ok(())
        });
        out
    }

    fn read_tables(&mut self, db: &Database, observer: &mut dyn Observer) {
        self.build_id_map(db, observer);
        self.read_network_usage(db, observer);
        self.read_app_resource(db, observer);
        self.read_connections(db, observer);
        self.read_push(db, observer);
        self.read_energy(db, observer);
        self.read_vfuprov(db, observer);
        self.read_timeline(db, observer);
        self.read_newer(db, observer);
    }

    /// ReadTable: every row on its own; a table that isn't there is skipped
    fn read_table(&mut self, db: &Database, name: &str, observer: &mut dyn Observer, read_row: &mut dyn FnMut(&mut Srum, &Values, &mut dyn Observer) -> Result<(), String>) {
        let Some(table) = db.table(name) else { return };
        self.missing_ids = 0;
        let mut number: u64 = 0;
        let mut problems = Vec::new();
        let walked = db.for_each_row(table, &mut |row| {
            number += 1;
            if let Err(e) = read_row(self, &Values { table, row }, observer) {
                problems.push(format!("{name} row {number}: {e}"));
            }
            Ok(())
        });
        for problem in problems {
            self.error(problem, observer);
        }
        if let Err(e) = walked {
            self.error(format!("{name}: reading stopped after {} rows: {e}", ez_common::dotnet::n0(number)), observer);
        }
        if self.missing_ids > 0 {
            let message = format!("{name}: {} app or user id(s) are not in SruDbIdMapTable; those app or user columns are empty", ez_common::dotnet::n0(self.missing_ids));
            self.warn(message, observer);
        }
    }

    fn build_id_map(&mut self, db: &Database, observer: &mut dyn Observer) {
        self.read_table(db, "SruDbIdMapTable", observer, &mut |srum, r, _| {
            let id_type = match r.table.column("IdType") {
                Some(c) => r.bytes(c)?.and_then(|b| b.first().copied()),
                None => None,
            };
            let index = r.int("IdIndex")?;
            let blob = match r.table.column("IdBlob") {
                Some(c) => r.bytes(c)?,
                None => None,
            };
            let Some(id_type) = id_type else { return Err(format!("IdIndex {index} has no IdType")) };
            if id_type == 3 {
                let sid = sid_from_bytes(blob);
                let user_name = srum.sid_to_user.get(&sid).cloned().unwrap_or_default();
                if srum.users.contains_key(&index) {
                    return Err(format!("An item with the same key has already been added. Key: {index}"));
                }
                let sid_type = sid_type_name(&sid);
                srum.users.insert(index, UserInfo { sid, user_name, sid_type });
            } else {
                let text = blob.map(|b| unicode_string(b, 0, b.len() as i64).unwrap_or_default()).unwrap_or_default();
                if srum.apps.contains_key(&index) {
                    return Err(format!("An item with the same key has already been added. Key: {index}"));
                }
                srum.apps.insert(index, AppInfo::new(text.trim_matches('\0')));
            }
            Ok(())
        });
    }

    /// App and User: the entries of the id map, each one not there counted
    fn lookup(&mut self, app_id: i32, user_id: i32) -> (Option<AppInfo>, Option<UserInfo>) {
        let app = self.apps.get(&app_id).cloned();
        if app.is_none() {
            self.missing_ids += 1;
        }
        let user = self.users.get(&user_id).cloned();
        if user.is_none() {
            self.missing_ids += 1;
        }
        (app, user)
    }

    fn time(&mut self, r: &Values, table: &str, name: &str, observer: &mut dyn Observer) -> Result<Timestamp, String> {
        let Some(column) = r.table.column(name) else { return Ok(Timestamp::MIN) };
        let Some(b) = r.bytes(column)? else { return Ok(Timestamp::MIN) };
        let raw: [u8; 8] = b.try_into().map_err(|_| format!("Column {name} is {} bytes, not 8", b.len()))?;
        match from_oa_date(f64::from_le_bytes(raw)) {
            Ok(t) => Ok(t),
            Err(e) => {
                self.error(format!("{table}: {name} is not a valid time ({e})"), observer);
                Ok(Timestamp::MIN)
            }
        }
    }

    fn file_time(&mut self, r: &Values, table: &str, name: &str, observer: &mut dyn Observer) -> Result<i64, String> {
        let raw = r.long(name)?;
        if Timestamp::from_filetime(raw).is_none() {
            self.error(format!("{table}: {name} 0x{raw:X} is not a valid time"), observer);
        }
        Ok(raw)
    }

    fn profile_name(&self, id: i32) -> String {
        self.ssids.get(&id).cloned().unwrap_or_default()
    }

    /// Dictionary.Add, keyed by the row's id
    fn add(rows: &mut Vec<Vec<Cell>>, seen: &mut std::collections::HashSet<i64>, id: i64, cells: Vec<Cell>) -> Result<(), String> {
        if !seen.insert(id) {
            return Err(format!("An item with the same key has already been added. Key: {id}"));
        }
        rows.push(cells);
        Ok(())
    }

    fn read_network_usage(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, NETWORK_USAGE, observer, &mut |s, r, o| {
            let (app_id, user_id, profile) = (r.int("AppId")?, r.int("UserId")?, r.int("L2ProfileId")?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, NETWORK_USAGE, "TimeStamp", o)?;
            let (received, sent, luid, flags) = (r.long("BytesRecvd")?, r.long("BytesSent")?, r.long("InterfaceLuid")?, r.int("L2ProfileFlags")?);
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
            cells.extend([
                Cell::Int(received),
                Cell::Int(sent),
                Cell::Int(luid),
                Cell::Text(Some(interface_type_name((luid >> 48) as i16))),
                Cell::Int(i64::from(flags)),
                Cell::Int(i64::from(profile)),
                Cell::Text(Some(s.profile_name(profile))),
            ]);
            Self::add(&mut s.usage.rows, &mut seen, id, cells)
        });
    }

    fn read_app_resource(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, APP_RESOURCE, observer, &mut |s, r, o| {
            let (app_id, user_id) = (r.int("AppId")?, r.int("UserId")?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, APP_RESOURCE, "TimeStamp", o)?;
            let mut extra = Vec::new();
            for (name, is_long) in [
                ("BackgroundBytesRead", true),
                ("BackgroundBytesWritten", true),
                ("BackgroundContextSwitches", false),
                ("BackgroundCycleTime", true),
                ("BackgroundNumberOfFlushes", false),
                ("BackgroundNumReadOperations", false),
                ("BackgroundNumWriteOperations", false),
                ("FaceTime", true),
                ("ForegroundBytesRead", true),
                ("ForegroundBytesWritten", true),
                ("ForegroundContextSwitches", false),
                ("ForegroundCycleTime", true),
                ("ForegroundNumberOfFlushes", false),
                ("ForegroundNumReadOperations", false),
                ("ForegroundNumWriteOperations", false),
            ] {
                extra.push(Cell::Int(if is_long { r.long(name)? } else { i64::from(r.int(name)?) }));
            }
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
            cells.extend(extra);
            Self::add(&mut s.app_resource.rows, &mut seen, id, cells)
        });
    }

    fn read_connections(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, NETWORK_CONNECTION, observer, &mut |s, r, o| {
            let (app_id, user_id, profile) = (r.int("AppId")?, r.int("UserId")?, r.int("L2ProfileId")?);
            let start = from_file_time(s.file_time(r, NETWORK_CONNECTION, "ConnectStartTime", o)?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, NETWORK_CONNECTION, "TimeStamp", o)?;
            let (connected, luid, flags) = (r.int("ConnectedTime")?, r.long("InterfaceLuid")?, r.int("L2ProfileFlags")?);
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
            cells.extend([
                Cell::Int(i64::from(connected)),
                Cell::Time(start),
                Cell::Int(luid),
                Cell::Text(Some(interface_type_name((luid >> 48) as i16))),
                Cell::Int(i64::from(flags)),
                Cell::Int(i64::from(profile)),
                Cell::Text(Some(s.profile_name(profile))),
            ]);
            Self::add(&mut s.connections.rows, &mut seen, id, cells)
        });
    }

    fn read_push(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, PUSH_NOTIFICATION, observer, &mut |s, r, o| {
            let (app_id, user_id) = (r.int("AppId")?, r.int("UserId")?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, PUSH_NOTIFICATION, "TimeStamp", o)?;
            let (network, kind, payload) = (r.int("NetworkType")?, r.int("NotificationType")?, r.int("PayloadSize")?);
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
            cells.extend([Cell::Int(i64::from(network)), Cell::Int(i64::from(kind)), Cell::Int(i64::from(payload))]);
            Self::add(&mut s.push.rows, &mut seen, id, cells)
        });
    }

    /// The energy tables. Their rows don't get the id map's names in the original
    fn read_energy(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        let mut last_seen: i32 = 0;
        self.read_table(db, ENERGY_LT, observer, &mut |s, r, o| {
            let id = r.int("AutoIncId")?;
            let time = s.time(r, ENERGY_LT, "TimeStamp", o)?;
            let mut cells = identity(i64::from(id), time, None, None, r.int("UserId")?, r.int("AppId")?);
            cells.extend([Cell::Bool(true), Cell::Int(r.long("ConfigurationHash")?), Cell::OptTime(None), Cell::Int(-1), Cell::Int(-1)]);
            for name in ["CycleCount", "DesignedCapacity", "FullChargedCapacity", "ActiveAcTime", "ActiveDcTime", "ActiveDischargeTime", "ActiveEnergy", "CsAcTime", "CsDcTime", "CsDischargeTime", "CsEnergy"] {
                cells.push(Cell::Int(i64::from(r.int(name)?)));
            }
            Self::add(&mut s.energy.rows, &mut seen, i64::from(id), cells)?;
            last_seen = id;
            Ok(())
        });
        self.read_table(db, ENERGY, observer, &mut |s, r, o| {
            let event = r.long("EventTimestamp")?;
            if event > 0 && Timestamp::from_filetime(event).is_none() {
                s.error(format!("{ENERGY}: EventTimestamp 0x{event:X} is not a valid time"), o);
            }
            let mut id = r.int("AutoIncId")?;
            let time = s.time(r, ENERGY, "TimeStamp", o)?;
            let (user_id, app_id, hash) = (r.int("UserId")?, r.int("AppId")?, r.long("ConfigurationHash")?);
            let mut rest = vec![
                Cell::Bool(false),
                Cell::Int(hash),
                Cell::OptTime((event > 0).then(|| from_file_time(event))),
                Cell::Int(i64::from(r.int("StateTransition")?)),
                Cell::Int(i64::from(r.int("ChargeLevel")?)),
                Cell::Int(i64::from(r.int("CycleCount")?)),
                Cell::Int(i64::from(r.int("DesignedCapacity")?)),
                Cell::Int(i64::from(r.int("FullChargedCapacity")?)),
            ];
            rest.extend(std::iter::repeat_n(Cell::Int(-1), 8));
            if seen.contains(&i64::from(id)) {
                while seen.contains(&i64::from(last_seen)) {
                    last_seen += 1;
                }
                o.warning(&format!("Id {id} in use from LT table. Incrementing by {last_seen}"));
                id = id.wrapping_add(last_seen);
            }
            let mut cells = identity(i64::from(id), time, None, None, user_id, app_id);
            cells.extend(rest);
            Self::add(&mut s.energy.rows, &mut seen, i64::from(id), cells)
        });
    }

    fn read_vfuprov(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, VFUPROV, observer, &mut |s, r, o| {
            let (app_id, user_id) = (r.int("AppId")?, r.int("UserId")?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, VFUPROV, "TimeStamp", o)?;
            let flags = r.int("Flags")?;
            let start = from_file_time(s.file_time(r, VFUPROV, "StartTime", o)?);
            let end = from_file_time(s.file_time(r, VFUPROV, "EndTime", o)?);
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = vec![Cell::Int(id), Cell::Time(time), Cell::Int(i64::from(user_id)), Cell::Int(i64::from(app_id))];
            cells.extend(exe_cells(app.as_ref(), user.as_ref()));
            cells.extend([Cell::Time(start), Cell::Time(end), Cell::Int(i64::from(flags)), Cell::Span(end.ticks() - start.ticks())]);
            Self::add(&mut s.vfuprov.rows, &mut seen, id, cells)
        });
    }

    fn read_timeline(&mut self, db: &Database, observer: &mut dyn Observer) {
        let mut seen = std::collections::HashSet::new();
        self.read_table(db, TIMELINE, observer, &mut |s, r, o| {
            let (app_id, user_id) = (r.int("AppId")?, r.int("UserId")?);
            let id = i64::from(r.int("AutoIncId")?);
            let time = s.time(r, TIMELINE, "TimeStamp", o)?;
            let duration = r.int("DurationMS")?;
            let end = from_file_time(s.file_time(r, TIMELINE, "EndTime", o)?);
            let mut extra = Vec::new();
            for name in ["InFocusS", "PSMForegroundS", "UserInputS", "KeyboardInputS", "MouseInputS", "DisplayRequiredS", "AudioInS", "AudioOutS"] {
                extra.push(Cell::OptInt(r.int_or_null(name)?));
            }
            let (app, user) = s.lookup(app_id, user_id);
            let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
            cells.extend([Cell::Time(end), Cell::Int(i64::from(duration))]);
            cells.extend(extra);
            Self::add(&mut s.timeline.rows, &mut seen, id, cells)
        });
    }

    fn read_newer(&mut self, db: &Database, observer: &mut dyn Observer) {
        fn newer(s: &mut Srum, db: &Database, observer: &mut dyn Observer, table: &'static str, longs: &'static [&'static str], rows_of: fn(&mut Srum) -> &mut Vec<Vec<Cell>>) {
            let mut seen = std::collections::HashSet::new();
            s.read_table(db, table, observer, &mut |s, r, o| {
                let id = i64::from(r.int("AutoIncId")?);
                let time = s.time(r, table, "TimeStamp", o)?;
                let (user_id, app_id) = (r.int("UserId")?, r.int("AppId")?);
                let mut extra = Vec::new();
                for name in longs {
                    extra.push(Cell::Int(r.long(name)?));
                }
                let (app, user) = s.lookup(app_id, user_id);
                let mut cells = identity(id, time, app.as_ref(), user.as_ref(), user_id, app_id);
                cells.extend(extra);
                Srum::add(rows_of(s), &mut seen, id, cells)
            });
        }
        newer(self, db, observer, PROCESSOR_TIME, &["ProcessorTime"], |s| &mut s.processor_time.rows);
        newer(self, db, observer, SIZE_IN_BYTES, &["SizeInBytes"], |s| &mut s.size_in_bytes.rows);
        newer(self, db, observer, TOTAL_USED, &["Total", "Used"], |s| &mut s.total_used.rows);
        newer(self, db, observer, NETWORK_BYTES, &["BytesInBound", "BytesOutBound", "BytesTotal"], |s| &mut s.network_bytes.rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_info_takes_the_bangs_apart() {
        let a = AppInfo::new("!!svchost.exe!1972/12/14:16:22:50!1c36!Host");
        assert_eq!(a.exe_info, "svchost.exe");
        assert_eq!(a.description.as_deref(), Some("Host"));
        assert_eq!(a.unknown.as_deref(), Some("1c36"));
        assert_eq!(a.timestamp, Timestamp::from_parts(1972, 12, 14, 16, 22, 50, 0));
        // a name with ! in it, and one that starts with it
        assert_eq!(AppInfo::new("!!a!b!2000/01/02:03:04:05!x!d").exe_info, "a!b");
        assert_eq!(AppInfo::new("!!!b!2000/01/02:03:04:05!x!d").exe_info, "!!b");
        // a bad time stays out; too few pieces leaves the text alone
        assert_eq!(AppInfo::new("!!a!not a time!x!d").timestamp, None);
        assert_eq!(AppInfo::new("!!a!b").exe_info, "!!a!b");
        assert_eq!(AppInfo::new("C:\\x.exe").exe_info, "C:\\x.exe");
    }

    #[test]
    fn sids_read_as_the_original_writes_them() {
        assert_eq!(sid_from_bytes(Some(&[1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0])), "S-1-5-18");
        assert_eq!(sid_from_bytes(Some(&[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0])), "S-1-5-32-544");
        assert_eq!(sid_from_bytes(Some(&[1, 2, 3, 4, 5, 6, 7, 8])), "");
        assert_eq!(sid_from_bytes(None), "");
        // whole sub authorities only
        assert_eq!(sid_from_bytes(Some(&[1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0, 9])), "S-1-5-18");
    }

    #[test]
    fn sid_types_keep_the_originals_mistakes() {
        assert_eq!(sid_type_name("S-1-5-18"), "LocalSystem");
        assert_eq!(sid_type_name("S-1-3-4"), "OwnerServer");
        assert_eq!(sid_type_name("S-1-5-21-1-2-3-500"), "Administrator");
        assert_eq!(sid_type_name("S-1-5-21-1-2-3-1001"), "UnknownOrUserSid");
        assert_eq!(sid_type_name("S-1-5-5-0-1"), "LogonId");
        assert_eq!(sid_type_name(""), "UnknownOrUserSid");
    }

    #[test]
    fn interface_types_have_names_or_numbers() {
        assert_eq!(interface_type_name(6), "IF_TYPE_ETHERNET_CSMACD");
        assert_eq!(interface_type_name(71), "IF_TYPE_IEEE80211");
        assert_eq!(interface_type_name(0), "0");
        assert_eq!(interface_type_name(-1), "-1");
    }

    #[test]
    fn spans_are_written_as_timespan_does() {
        assert_eq!(span_text(0), "00:00:00");
        assert_eq!(span_text(36_000_000_000 + 600_000_000 + 10_000_000), "01:01:01");
        assert_eq!(span_text(864_000_000_000 + 1), "1.00:00:00.0000001");
        assert_eq!(span_text(-10_000_000), "-00:00:01");
    }
}
