//! AmcacheNew: the `Root\Inventory*` keys (Windows 10 and later), and the same logic over the databases: a row is a
//! key and a column is a value.

use std::collections::HashMap;

use ez_common::{Level, Timestamp};
use registry_ez::{Hive, KeyId};

use crate::parse;
use crate::{DatabaseTable, Error, Observer, Sink, open_hive};

#[derive(Debug, Clone, Default)]
pub struct FileEntryNew {
    pub binary_type: String,
    pub bin_file_version: String,
    pub bin_product_version: String,
    pub sha1: String,
    pub is_os_component: bool,
    pub is_pe_file: bool,
    pub language: i32,
    pub link_date: Option<Timestamp>,
    pub long_path_hash: String,
    pub full_path: String,
    pub name: String,
    pub application_name: String,
    pub product_name: String,
    pub product_version: String,
    pub program_id: String,
    pub publisher: String,
    pub size: i64,
    pub usn: u64,
    pub version: String,
    pub file_extension: String,
    pub description: String,
    pub original_file_name: String,
    pub file_key_last_write: Timestamp,
    pub sha256: String,
    pub key_name: String,
    pub appx_package_full_name: String,
    pub appx_package_relative_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProgramsEntryNew {
    pub bundle_manifest_path: String,
    pub hidden_arp: bool,
    pub inbox_modern_app: bool,
    pub install_date: Option<Timestamp>,
    pub install_date_arp_last_modified: String,
    pub install_date_msi: Option<Timestamp>,
    pub install_date_from_link_file: String,
    pub language: i32,
    pub manifest_path: String,
    pub msi_package_code: String,
    pub msi_product_code: String,
    pub name: String,
    pub os_version_at_install_time: String,
    pub package_full_name: String,
    pub program_id: String,
    pub program_instance_id: String,
    pub publisher: String,
    pub registry_key_path: String,
    pub root_dir_path: String,
    pub source: String,
    pub store_app_type: String,
    pub program_type: String,
    pub uninstall_string: String,
    pub version: String,
    pub manufacturer: String,
    pub key_last_write: Timestamp,
    pub file_entries: Vec<FileEntryNew>,
    pub key_name: String,
    pub user_sid: String,
    pub msi_install_date: Option<Timestamp>,
}

#[derive(Debug, Clone, Default)]
pub struct Shortcut {
    pub key_name: String,
    pub lnk_name: String,
    pub key_last_write: Timestamp,
    pub shortcut_target_path: String,
    pub shortcut_aumid: String,
    pub shortcut_program_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceContainer {
    pub key_name: String,
    pub key_last_write: Timestamp,
    pub categories: String,
    pub discovery_method: String,
    pub friendly_name: String,
    pub icon: String,
    pub is_active: bool,
    pub is_connected: bool,
    pub is_machine_container: bool,
    pub is_networked: bool,
    pub is_paired: bool,
    pub manufacturer: String,
    pub model_id: String,
    pub model_name: String,
    pub model_number: String,
    pub primary_category: String,
    pub state: String,
}

#[derive(Debug, Clone, Default)]
pub struct DevicePnp {
    pub key_name: String,
    pub key_last_write: Timestamp,
    pub bus_reported_description: String,
    pub class: String,
    pub class_guid: String,
    pub compid: String,
    pub container_id: String,
    pub description: String,
    pub device_state: String,
    pub driver_id: String,
    pub driver_name: String,
    pub driver_package_strong_name: String,
    pub driver_ver_date: String,
    pub driver_ver_version: String,
    pub enumerator: String,
    pub hwid: String,
    pub inf: String,
    pub install_state: String,
    pub manufacturer: String,
    pub matching_id: String,
    pub model: String,
    pub parent_id: String,
    pub problem_code: String,
    pub provider: String,
    pub service: String,
    pub stackid: String,
    pub install_date: String,
    pub first_install_date: String,
    pub extended_infs: String,
    pub upper_class_filters: String,
    pub lower_class_filters: String,
    pub upper_filters: String,
    pub lower_filters: String,
    pub device_interface_classes: String,
    pub location_paths: String,
}

#[derive(Debug, Clone, Default)]
pub struct DriverBinary {
    pub key_name: String,
    pub key_last_write: Timestamp,
    pub driver_check_sum: i32,
    pub driver_company: String,
    pub driver_id: String,
    pub driver_in_box: bool,
    pub driver_is_kernel_mode: bool,
    pub driver_last_write_time: Option<Timestamp>,
    pub driver_name: String,
    pub driver_package_strong_name: String,
    pub driver_signed: bool,
    pub driver_time_stamp: Option<Timestamp>,
    pub driver_type: String,
    pub driver_version: String,
    pub image_size: i32,
    pub inf: String,
    pub product: String,
    pub product_version: String,
    pub service: String,
    pub wdf_version: String,
}

#[derive(Debug, Clone, Default)]
pub struct DriverPackage {
    pub key_name: String,
    pub key_last_write: Timestamp,
    pub class: String,
    pub class_guid: String,
    pub date: Option<Timestamp>,
    pub directory: String,
    pub driver_in_box: bool,
    pub hwids: String,
    pub inf: String,
    pub provider: String,
    pub submission_id: String,
    pub sysfile: String,
    pub version: String,
    pub driver_package_strong_name: String,
    pub flight_ids: String,
    pub recovery_ids: String,
    pub is_active: String,
}

#[derive(Default)]
pub struct AmcacheNew {
    pub unassociated_file_entries: Vec<FileEntryNew>,
    pub programs_entries: Vec<ProgramsEntryNew>,
    pub device_containers: Vec<DeviceContainer>,
    pub device_pnps: Vec<DevicePnp>,
    pub drive_binaries: Vec<DriverBinary>,
    pub driver_packages: Vec<DriverPackage>,
    pub short_cuts: Vec<Shortcut>,
    pub total_file_entries: i32,
    /// The hive also has Root\File or Root\Programs entries (see AmcacheOld)
    pub has_old_format_entries: bool,
    /// Dates that could not be read and were left empty
    pub invalid_dates: i32,
    /// Entries (keys or rows) that could not be parsed and were left out (deleted keys in a hive not counted)
    pub entries_not_parsed: i32,
    /// Databases only: the databases that could not be read at all (an empty one is not counted)
    pub databases_not_read: i32,
    /// Databases only: of those, the ones that could not be opened or copied, as opposed to damaged ones
    pub databases_not_accessed: i32,
    /// Databases only: the tables with no class here, as they are, and the Metadata tables
    pub other_tables: Vec<DatabaseTable>,
}

/// A hive key or a database row
pub(crate) struct InventoryItem {
    pub key_name: String,
    pub key_path: String,
    pub last_write: Timestamp,
    pub is_deleted: bool,
    pub values: Vec<InventoryValue>,
}

/// A hive value or a database column, with its data as the registry has it (numbers in decimal)
pub(crate) struct InventoryValue {
    pub name: String,
    pub data: String,
    pub is_deleted: bool,
}

pub(crate) trait Reporter {
    fn not_tracked(&mut self, category: &str, item: &InventoryItem, value: &InventoryValue);
    fn unknown(&mut self, category: &str, item: &InventoryItem, value: &InventoryValue, only_when_not_deleted: bool);
    fn error(&mut self, category: &str, item: &InventoryItem, message: &str);
    fn errors(&self) -> i32;
}

/// As the hive was always reported: per key
struct HiveReporter<'s, 'a> {
    errors: i32,
    sink: &'s Sink<'a>,
}

impl Reporter for HiveReporter<'_, '_> {
    fn not_tracked(&mut self, category: &str, item: &InventoryItem, value: &InventoryValue) {
        self.sink.log(
            Level::Debug,
            &format!("Non-tracked data when processing {category} at path {}: {}==>{}", item.key_path, value.name, value.data),
        );
    }

    fn unknown(&mut self, category: &str, item: &InventoryItem, value: &InventoryValue, only_when_not_deleted: bool) {
        if only_when_not_deleted && value.is_deleted {
            return;
        }
        let message = if category == "InventoryApplication" {
            format!("Unknown value name in InventoryApplication at path {}: {}", item.key_path, value.name)
        } else {
            format!("Unknown value name when processing {category} at path {}: {}", item.key_path, value.name)
        };
        self.sink.log(Level::Warning, &message);
    }

    fn error(&mut self, category: &str, item: &InventoryItem, message: &str) {
        if item.is_deleted {
            return;
        }
        self.errors += 1;
        self.sink.log(Level::Error, &format!("Error parsing {category} at {}. Error: {message}", item.key_path));
        self.sink.log(Level::Error, "Please send the following text to saericzimmerman@gmail.com");
        self.sink.log(Level::Error, &format!("Key data: {}", values_text(item)));
    }

    fn errors(&self) -> i32 {
        self.errors
    }
}

pub(crate) fn values_text(item: &InventoryItem) -> String {
    item.values.iter().map(|v| format!("{}={}", v.name, v.data)).collect::<Vec<_>>().join(", ")
}

/// FromKey. A value whose name can't be read stops everything, as this runs outside the try of each entry
fn from_key(hive: &Hive, key: KeyId, sink: &Sink) -> Result<InventoryItem, String> {
    let nk = hive.nk(key);
    let mut values = Vec::with_capacity(hive.keys[key].values.len());
    for &v in &hive.keys[key].values {
        let vk = &hive.vks[v];
        let data = hive.value_data(v)?.text(hive.date_culture);
        sink.drain(hive);
        values.push(InventoryValue { name: vk.name()?.to_string(), data, is_deleted: vk.is_free() });
    }
    Ok(InventoryItem {
        key_name: hive.key_name(key).to_string(),
        key_path: hive.keys[key].path.clone(),
        last_write: nk.last_write()?,
        is_deleted: nk.is_free(),
        values,
    })
}

pub(crate) type Items<'i> = &'i mut dyn Iterator<Item = Result<InventoryItem, String>>;

impl AmcacheNew {
    pub fn open(path: &str, no_logs: bool, observer: Observer) -> Result<AmcacheNew, Error> {
        let sink = Sink::new(observer);
        let hive = open_hive(path, no_logs, false, &sink)?;
        let mut am = AmcacheNew::default();
        let has_subkeys = |p: &str| hive.get_key(p).is_some_and(|k| !hive.keys[k].subkeys.is_empty());
        am.has_old_format_entries = has_subkeys("Root\\File") || has_subkeys("Root\\Programs");
        let mut reporter = HiveReporter { errors: 0, sink: &sink };

        let items = |key: KeyId| {
            let sink = &sink;
            let hive = &hive;
            hive.keys[key].subkeys.iter().map(move |&k| from_key(hive, k, sink))
        };

        sink.log(Level::Debug, "Getting Programs data");
        match hive.get_key("Root\\InventoryApplication") {
            Some(k) => am.add_programs(&mut items(k), &mut reporter, &sink)?,
            None => sink.log(Level::Warning, "Hive does not contain a Root\\InventoryApplication key"),
        }

        sink.log(Level::Debug, "Getting Files data");
        match hive.get_key("Root\\InventoryApplicationFile") {
            Some(k) => am.add_files(&mut items(k), &mut reporter, &sink)?,
            None => sink.log(Level::Warning, "Hive does not contain a Root\\InventoryApplicationFile key"),
        }

        sink.log(Level::Debug, "Getting Shortcut data");
        if let Some(k) = hive.get_key("Root\\InventoryApplicationShortcut") {
            am.add_shortcuts(&mut items(k), false)?;
        }

        sink.log(Level::Debug, "Getting InventoryDeviceContainer data");
        if let Some(k) = hive.get_key("Root\\InventoryDeviceContainer") {
            am.add_device_containers(&mut items(k), &mut reporter)?;
        }

        sink.log(Level::Debug, "Getting InventoryDevicePnp data");
        if let Some(k) = hive.get_key("Root\\InventoryDevicePnp") {
            am.add_device_pnps(&mut items(k), &mut reporter)?;
        }

        sink.log(Level::Debug, "Getting InventoryDriverBinary data");
        if let Some(k) = hive.get_key("Root\\InventoryDriverBinary") {
            am.add_driver_binaries(&mut items(k), &mut reporter, &sink)?;
        }

        sink.log(Level::Debug, "Getting InventoryDriverPackage data");
        if let Some(k) = hive.get_key("Root\\InventoryDriverPackage") {
            am.add_driver_packages(&mut items(k), &mut reporter, &sink)?;
        }

        am.entries_not_parsed = reporter.errors();
        Ok(am)
    }

    /// ParseDate: a date that isn't valid is left empty and counted, instead of losing the entry
    fn parse_date(&mut self, item: &InventoryItem, value: &InventoryValue, sink: &Sink) -> Option<Timestamp> {
        if value.data.is_empty() {
            return None;
        }
        let parsed = parse::date_time(&value.data);
        if parsed.is_none() {
            sink.log(Level::Debug, &format!("{} at {} is not a valid date: {}", value.name, item.key_path, value.data));
            self.invalid_dates += 1;
        }
        parsed
    }

    pub(crate) fn add_programs(&mut self, items: Items, reporter: &mut dyn Reporter, sink: &Sink) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let mut p = ProgramsEntryNew { key_name: item.key_name.clone(), key_last_write: item.last_write, ..Default::default() };
            let mut failed = None;
            for value in &item.values {
                let d = value.data.clone();
                match value.name.as_str() {
                    "BundleManifestPath" => p.bundle_manifest_path = d,
                    "HiddenArp" => p.hidden_arp = d == "1",
                    "InboxModernApp" => p.inbox_modern_app = d == "1",
                    "InstallDate" => p.install_date = self.parse_date(&item, value, sink),
                    "Language" => {
                        p.language = if d.is_empty() {
                            0
                        } else {
                            match parse::int(&d) {
                                Ok(l) => l,
                                Err(e) => {
                                    failed = Some(e);
                                    break;
                                }
                            }
                        }
                    }
                    "ManifestPath" => p.manifest_path = d,
                    "MsiPackageCode" => p.msi_package_code = d,
                    "MsiProductCode" => p.msi_product_code = d,
                    "Name" => p.name = d,
                    "OSVersionAtInstallTime" => p.os_version_at_install_time = d,
                    "PackageFullName" => p.package_full_name = d,
                    "ProgramId" => p.program_id = d,
                    "ProgramInstanceId" => p.program_instance_id = d,
                    "Publisher" => p.publisher = d,
                    "RegistryKeyPath" => p.registry_key_path = d,
                    "RootDirPath" => p.root_dir_path = d,
                    "Source" => p.source = d,
                    "StoreAppType" => p.store_app_type = d,
                    "Type" => p.program_type = d,
                    "UninstallString" => p.uninstall_string = d,
                    "Version" => p.version = d,
                    "InstallDateArpLastModified" => {
                        if !d.is_empty() {
                            p.install_date_arp_last_modified = d;
                        }
                    }
                    "InstallDateMsi" => p.install_date_msi = self.parse_date(&item, value, sink),
                    "InstallDateFromLinkFile" => {
                        if !d.is_empty() {
                            p.install_date_from_link_file = d;
                        }
                    }
                    "DriverVerVersion" | "BusReportedDescription" | "HWID" | "COMPID" | "STACKID" | "UpperClassFilters" | "UpperFilters"
                    | "LowerFilters" | "BinFileVersion" | "SentDetailedInv" | "ProductName" | "Provider" | "Inf" | "(default)" => {
                        reporter.not_tracked("InventoryApplication", &item, value);
                    }
                    "MsiInstallDate" => p.msi_install_date = self.parse_date(&item, value, sink),
                    "UserSid" => p.user_sid = d,
                    "Manufacturer" => {
                        if !d.is_empty() {
                            p.manufacturer = d;
                        }
                    }
                    _ => reporter.unknown("InventoryApplication", &item, value, false),
                }
            }
            match failed {
                None => self.programs_entries.push(p),
                Some(e) => reporter.error("ProgramsEntry", &item, &e),
            }
        }
        Ok(())
    }

    pub(crate) fn add_files(&mut self, items: Items, reporter: &mut dyn Reporter, sink: &Sink) -> Result<(), Error> {
        // ProgramId to program, for the files of each program (the first program with an id)
        let mut programs: HashMap<String, usize> = HashMap::new();
        for (i, p) in self.programs_entries.iter().enumerate() {
            programs.entry(p.program_id.clone()).or_insert(i);
        }

        for item in items {
            let item = item.map_err(Error::from)?;
            let mut f = FileEntryNew { key_name: item.key_name.clone(), file_key_last_write: item.last_write, ..Default::default() };
            let mut file_id = String::new();
            let mut linked = false;

            for value in &item.values {
                let d = value.data.clone();
                match value.name.as_str() {
                    "BinaryType" => f.binary_type = d,
                    "BinFileVersion" => f.bin_file_version = d,
                    "BinProductVersion" => f.bin_product_version = d,
                    "FileId" => file_id = d,
                    "IsOsComponent" => f.is_os_component = d == "1",
                    "IsPeFile" => f.is_pe_file = d == "1",
                    "Language" => match parse::int(&d) {
                        Ok(l) => f.language = l,
                        Err(e) => {
                            reporter.error("FileEntry", &item, &e);
                            break;
                        }
                    },
                    "LinkDate" => {
                        if !d.is_empty() {
                            f.link_date = Some(parse::date_time(&d).unwrap_or_else(|| {
                                sink.log(Level::Debug, &format!("LinkDate appears to not be a valid timestamp! Setting to 0. Data found: {d}"));
                                Timestamp::MIN
                            }));
                        }
                    }
                    "LongPathHash" => f.long_path_hash = d,
                    "LowerCaseLongPath" => f.full_path = d,
                    "Name" => f.name = d,
                    "ProductName" => f.product_name = d,
                    "ProductVersion" => f.product_version = d,
                    "ProgramId" => {
                        linked = linked || programs.contains_key(&d);
                        f.program_id = d;
                    }
                    "Publisher" => f.publisher = d,
                    "Size" => {
                        let parsed = if d.starts_with("0x") { parse::long_hex(&d.replace("0x", "")) } else { parse::long(&d).ok() };
                        if let Some(size) = parsed {
                            f.size = size;
                        }
                    }
                    "BusReportedDescription" | "FileSize" | "Model" | "Manufacturer" | "ParentId" | "MatchingID" | "ClassGuid" | "DriverName"
                    | "Enumerator" | "Service" | "DeviceState" | "InstallState" | "DriverVerVersion" | "DriverPackageStrongName" | "DriverVerDate"
                    | "ContainerId" | "HiddenArp" | "Inf" | "LowerFilters" | "ProblemCode" | "LocationPaths" | "Provider" | "Class" => {
                        reporter.not_tracked("FileEntry", &item, value);
                    }
                    "OriginalFileName" => f.original_file_name = d,
                    "AppxPackageFullName" => f.appx_package_full_name = d,
                    "AppxPackageRelativeId" => f.appx_package_relative_id = d,
                    "Description" => f.description = d,
                    "Version" => f.version = d,
                    "Usn" => match parse::ulong(&d) {
                        Ok(u) => f.usn = u,
                        Err(e) => {
                            reporter.error("FileEntry", &item, &e);
                            break;
                        }
                    },
                    // the databases have it (a column of its own); FileId is still 0000 + SHA-1
                    "Sha256" => f.sha256 = d,
                    _ => reporter.unknown("FileEntry", &item, value, value.is_deleted),
                }
            }

            self.total_file_entries += 1;

            if file_id.chars().count() > 4 {
                f.sha1 = ez_common::dotnet::lower_invariant(&file_id.chars().skip(4).collect::<String>());
            }
            f.file_extension = parse::windows_extension(&f.full_path).to_string();

            match programs.get(&f.program_id).filter(|_| linked) {
                Some(&program) => {
                    f.application_name = self.programs_entries[program].name.clone();
                    self.programs_entries[program].file_entries.push(f);
                }
                None => {
                    f.application_name = "Unassociated".into();
                    self.unassociated_file_entries.push(f);
                }
            }
        }
        Ok(())
    }

    /// `by_name` is for databases: the path is the ShortcutPath column. A hive key has it as its only value
    pub(crate) fn add_shortcuts(&mut self, items: Items, by_name: bool) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let get = |name: &str| item.values.iter().find(|v| v.name == name).map(|v| v.data.clone()).unwrap_or_default();
            let lnk_name = if by_name {
                get("ShortcutPath")
            } else {
                item.values.first().map(|v| v.data.clone()).unwrap_or_default()
            };
            self.short_cuts.push(Shortcut {
                key_name: item.key_name.clone(),
                lnk_name,
                key_last_write: item.last_write,
                shortcut_target_path: get("ShortcutTargetPath"),
                shortcut_aumid: get("ShortcutAumid"),
                shortcut_program_id: get("ShortcutProgramId"),
            });
        }
        Ok(())
    }

    pub(crate) fn add_device_containers(&mut self, items: Items, reporter: &mut dyn Reporter) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let mut c = DeviceContainer { key_name: item.key_name.clone(), key_last_write: item.last_write, ..Default::default() };
            for value in &item.values {
                let d = value.data.clone();
                match value.name.as_str() {
                    "Categories" => c.categories = d,
                    "DiscoveryMethod" => c.discovery_method = d,
                    "FriendlyName" => c.friendly_name = d,
                    "Icon" => c.icon = d,
                    "IsActive" => c.is_active = d == "1",
                    "IsConnected" => c.is_connected = d == "1",
                    "IsMachineContainer" => c.is_machine_container = d == "1",
                    "IsNetworked" => c.is_networked = d == "1",
                    "IsPaired" => c.is_paired = d == "1",
                    "Manufacturer" => c.manufacturer = d,
                    "ModelId" => c.model_id = d,
                    "ModelName" => c.model_name = d,
                    "ModelNumber" => c.model_number = d,
                    "PrimaryCategory" => c.primary_category = d,
                    "State" => c.state = d,
                    "(default)" | "Model" | "BusReportedDescription" | "Version" | "LowerClassFilters" | "ManifestPath" | "UpperClassFilters" => {
                        reporter.not_tracked("DeviceContainer", &item, value);
                    }
                    _ => reporter.unknown("DeviceContainer", &item, value, false),
                }
            }
            self.device_containers.push(c);
        }
        Ok(())
    }

    pub(crate) fn add_device_pnps(&mut self, items: Items, reporter: &mut dyn Reporter) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let mut p = DevicePnp { key_name: item.key_name.clone(), key_last_write: item.last_write, ..Default::default() };
            for value in &item.values {
                let d = value.data.clone();
                match value.name.as_str() {
                    "BusReportedDescription" => p.bus_reported_description = d,
                    "Class" => p.class = d,
                    "ClassGuid" => p.class_guid = d,
                    "COMPID" => p.compid = d,
                    "ContainerId" => p.container_id = d,
                    "Description" => p.description = d,
                    "DeviceState" => p.device_state = d,
                    "DriverId" => p.driver_id = d,
                    "DriverName" => p.driver_name = d,
                    "DriverPackageStrongName" => p.driver_package_strong_name = d,
                    "DriverVerDate" => p.driver_ver_date = d,
                    "DriverVerVersion" => p.driver_ver_version = d,
                    "Enumerator" => p.enumerator = d,
                    "HWID" => p.hwid = d,
                    "Inf" => p.inf = d,
                    "InstallState" => p.install_state = d,
                    "Manufacturer" => p.manufacturer = d,
                    "MatchingID" => p.matching_id = d,
                    "Model" => p.model = d,
                    "ParentId" => p.parent_id = d,
                    "ProblemCode" => p.problem_code = d,
                    "Provider" => p.provider = d,
                    "Service" => p.service = d,
                    "STACKID" => p.stackid = d,
                    "InstallDate" => p.install_date = d,
                    "FirstInstallDate" => p.first_install_date = d,
                    "ExtendedInfs" => p.extended_infs = d,
                    "UpperClassFilters" => p.upper_class_filters = d,
                    "LowerClassFilters" => p.lower_class_filters = d,
                    "UpperFilters" => p.upper_filters = d,
                    "LowerFilters" => p.lower_filters = d,
                    "DeviceInterfaceClasses" => p.device_interface_classes = d,
                    "LocationPaths" => p.location_paths = d,
                    "(default)" | "DeviceExtDriversFlightIds" | "DeviceDriverFlightId" => reporter.not_tracked("DevicePnp", &item, value),
                    _ => reporter.unknown("DevicePnp", &item, value, false),
                }
            }
            self.device_pnps.push(p);
        }
        Ok(())
    }

    pub(crate) fn add_driver_binaries(&mut self, items: Items, reporter: &mut dyn Reporter, sink: &Sink) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let mut b = DriverBinary { key_name: item.key_name.clone(), key_last_write: item.last_write, ..Default::default() };
            let mut read = |am: &mut AmcacheNew, value: &InventoryValue, reporter: &mut dyn Reporter| -> Result<(), String> {
                let d = value.data.clone();
                match value.name.as_str() {
                    "DriverCheckSum" => b.driver_check_sum = parse::int(&d)?,
                    "DriverCompany" => b.driver_company = d,
                    "DriverId" => {
                        if d.chars().count() < 4 {
                            return Err("startIndex cannot be larger than length of string. (Parameter 'startIndex')".into());
                        }
                        b.driver_id = d.chars().skip(4).collect();
                    }
                    "DriverInBox" => b.driver_in_box = d == "1",
                    "DriverIsKernelMode" => b.driver_is_kernel_mode = d == "1",
                    "DriverLastWriteTime" => b.driver_last_write_time = am.parse_date(&item, value, sink),
                    "DriverName" => b.driver_name = d,
                    "DriverPackageStrongName" => b.driver_package_strong_name = d,
                    "DriverSigned" => b.driver_signed = d == "1",
                    "DriverTimeStamp" => {
                        let seconds = parse::long(&d)?;
                        if seconds > 0 {
                            b.driver_time_stamp = Some(parse::from_unix_seconds(seconds)?);
                        }
                    }
                    "DriverType" => b.driver_type = d,
                    "DriverVersion" => b.driver_version = d,
                    "ImageSize" => b.image_size = parse::int(&d)?,
                    "Inf" => b.inf = d,
                    "Product" => b.product = d,
                    "ProductVersion" => b.product_version = d,
                    "Service" => b.service = d,
                    "WdfVersion" => b.wdf_version = d,
                    "(default)" | "COMPID" | "HWID" => reporter.not_tracked("DriverBinary", &item, value),
                    _ => reporter.unknown("DriverBinary", &item, value, false),
                }
                Ok(())
            };
            let mut failed = None;
            for value in &item.values {
                if let Err(e) = read(self, value, reporter) {
                    failed = Some(e);
                    break;
                }
            }
            match failed {
                None => self.drive_binaries.push(b),
                Some(e) => reporter.error("DriverBinary", &item, &e),
            }
        }
        Ok(())
    }

    pub(crate) fn add_driver_packages(&mut self, items: Items, reporter: &mut dyn Reporter, sink: &Sink) -> Result<(), Error> {
        for item in items {
            let item = item.map_err(Error::from)?;
            let mut p = DriverPackage { key_name: item.key_name.clone(), key_last_write: item.last_write, ..Default::default() };
            for value in &item.values {
                let d = value.data.clone();
                match value.name.as_str() {
                    "Class" => p.class = d,
                    "ClassGuid" => p.class_guid = d,
                    "Date" => p.date = self.parse_date(&item, value, sink),
                    "Directory" => p.directory = d,
                    "DriverInBox" => p.driver_in_box = d == "1",
                    "Hwids" => p.hwids = d,
                    "Inf" => p.inf = d,
                    "Provider" => p.provider = d,
                    "SubmissionId" => p.submission_id = d,
                    "SYSFILE" => p.sysfile = d,
                    "Version" => p.version = d,
                    "DriverPackageStrongName" => p.driver_package_strong_name = d,
                    "FlightIds" => p.flight_ids = d,
                    "RecoveryIds" => p.recovery_ids = d,
                    "IsActive" => p.is_active = d,
                    "LowerFilters" | "Language" => reporter.not_tracked("DriverPackage", &item, value),
                    _ => reporter.unknown("DriverPackage", &item, value, false),
                }
            }
            self.driver_packages.push(p);
        }
        Ok(())
    }
}
