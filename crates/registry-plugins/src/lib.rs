//! Decoders for specific registry keys, as Eric Zimmerman's RegistryPlugins read them for RECmd. Nothing is printed and
//! no file is written: a plugin gives rows, errors and the messages of the libraries it uses, and its host reports them.

mod accounts;
mod amcache;
mod apps;
mod devices;
mod execution;
mod helpers;
mod history;
mod mru;
mod network;
mod shell;
mod system;
mod uwp_settings;

use ez_common::json::ServiceStackObject;
use ez_common::net::NetResult;
use ez_common::{Level, Timestamp, csv};
use fancy_regex::Regex;
use registry_ez::hive::lower;
use registry_ez::{Hive, KeyId};

/// A property of a plugin's ValuesOut
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Text(Option<String>),
    Bool(bool),
    Int(i32),
    Long(i64),
    OptInt(Option<i32>),
    Time(Option<Timestamp>),
    /// A [Flags] enum: its names in CSV, its number in JSON
    Flags(String, i32),
    /// A list of objects: only JSON shows it, written as this JSON
    JsonOnly(String),
}

impl From<Option<String>> for Cell {
    fn from(v: Option<String>) -> Cell {
        Cell::Text(v)
    }
}

impl From<String> for Cell {
    fn from(v: String) -> Cell {
        Cell::Text(Some(v))
    }
}

impl From<&str> for Cell {
    fn from(v: &str) -> Cell {
        Cell::Text(Some(v.to_string()))
    }
}

impl From<bool> for Cell {
    fn from(v: bool) -> Cell {
        Cell::Bool(v)
    }
}

impl From<i32> for Cell {
    fn from(v: i32) -> Cell {
        Cell::Int(v)
    }
}

impl From<i64> for Cell {
    fn from(v: i64) -> Cell {
        Cell::Long(v)
    }
}

impl From<Option<i32>> for Cell {
    fn from(v: Option<i32>) -> Cell {
        Cell::OptInt(v)
    }
}

impl From<Option<Timestamp>> for Cell {
    fn from(v: Option<Timestamp>) -> Cell {
        Cell::Time(v)
    }
}

impl From<Timestamp> for Cell {
    fn from(v: Timestamp) -> Cell {
        Cell::Time(Some(v))
    }
}

/// A row of a plugin (a ValuesOut)
#[derive(Debug, Clone, PartialEq)]
pub struct ValuesOut {
    /// The properties, in the order the class declares them
    pub columns: Vec<(&'static str, Cell)>,
    pub batch_key_path: Option<String>,
    pub batch_value_name: Option<String>,
    pub batch_value_data1: String,
    pub batch_value_data2: Option<String>,
    pub batch_value_data3: Option<String>,
    /// The class declares BatchKeyPath and BatchValueName before its other properties (UserAssist)
    pub batch_first: bool,
    /// BatchValueData1 is null, not empty (DHCPNetworkHint): only the batch JSON shows it
    pub data1_null: bool,
}

impl ValuesOut {
    /// The columns' order in the plugin's CSV. RECmd gives BatchKeyPath index 0 and BatchValueName index 1, the others keep
    /// their place in the class, and CsvHelper sorts them by index: the first column, BatchKeyPath, the second column,
    /// BatchValueName, then the rest. That sort (List.Sort) only keeps ties in order up to 16 items: in the one class with
    /// more, UserAccounts' 31, BatchValueName comes before the second column.
    fn csv_order(&self) -> impl Iterator<Item = CsvColumn<'_>> {
        let (first, rest) = self.columns.split_at(if self.batch_first { 0 } else { self.columns.len().min(2) });
        let mut order = Vec::with_capacity(self.columns.len() + 2);
        order.extend(first.first().map(CsvColumn::Column));
        order.push(CsvColumn::KeyPath);
        if self.columns.len() + 2 > 16 {
            order.push(CsvColumn::ValueName);
            order.extend(first.get(1).map(CsvColumn::Column));
        } else {
            order.extend(first.get(1).map(CsvColumn::Column));
            order.push(CsvColumn::ValueName);
        }
        order.extend(rest.iter().filter(|c| !matches!(c.1, Cell::JsonOnly(_))).map(CsvColumn::Column));
        order.into_iter()
    }

    /// The header of the plugin's CSV
    pub fn csv_header(&self) -> String {
        let names: Vec<&str> = self
            .csv_order()
            .map(|c| match c {
                CsvColumn::KeyPath => "BatchKeyPath",
                CsvColumn::ValueName => "BatchValueName",
                CsvColumn::Column((name, _)) => name,
            })
            .collect();
        names.join(",")
    }

    /// A line of the plugin's CSV, without its line ending. Time stamps have this format whatever --dt says (RECmd's
    /// converter for them doesn't get it)
    pub fn csv_line(&self, out: &mut String) {
        for (i, column) in self.csv_order().enumerate() {
            if i > 0 {
                out.push(',');
            }
            match column {
                CsvColumn::KeyPath => csv::field(out, self.batch_key_path.as_deref().unwrap_or("")),
                CsvColumn::ValueName => csv::field(out, self.batch_value_name.as_deref().unwrap_or("")),
                CsvColumn::Column((_, Cell::Text(v))) => csv::field(out, v.as_deref().unwrap_or("")),
                CsvColumn::Column((_, Cell::Bool(v))) => out.push_str(if *v { "True" } else { "False" }),
                CsvColumn::Column((_, Cell::Int(v))) => out.push_str(&v.to_string()),
                CsvColumn::Column((_, Cell::Long(v))) => out.push_str(&v.to_string()),
                CsvColumn::Column((_, Cell::OptInt(v))) => out.push_str(&v.map(|n| n.to_string()).unwrap_or_default()),
                CsvColumn::Column((_, Cell::Flags(names, _))) => csv::field(out, names),
                CsvColumn::Column((_, Cell::JsonOnly(_))) => {}
                CsvColumn::Column((_, Cell::Time(v))) => csv::field(out, &v.map(|t| t.format("yyyy-MM-dd HH:mm:ss.fffffff")).unwrap_or_default()),
            }
        }
    }

    /// A line of the plugin's JSON: every property but BatchValueData1 to 3, nulls included
    pub fn json_line(&self) -> String {
        fn text(o: &mut ServiceStackObject, name: &str, v: Option<&str>) {
            match v {
                Some(_) => o.string(name, v),
                None => o.raw(name, "null"),
            };
        }
        let mut o = ServiceStackObject::new();
        if self.batch_first {
            text(&mut o, "BatchKeyPath", self.batch_key_path.as_deref());
            text(&mut o, "BatchValueName", self.batch_value_name.as_deref());
        }
        for (name, cell) in &self.columns {
            match cell {
                Cell::Text(v) => text(&mut o, name, v.as_deref()),
                Cell::Bool(v) => {
                    o.bool(name, *v);
                }
                Cell::Int(v) => {
                    o.number(name, v);
                }
                Cell::Long(v) => {
                    o.number(name, v);
                }
                Cell::OptInt(Some(v)) => {
                    o.number(name, v);
                }
                Cell::OptInt(None) => {
                    o.raw(name, "null");
                }
                Cell::Flags(_, v) => {
                    o.number(name, v);
                }
                Cell::JsonOnly(v) => {
                    o.raw(name, v);
                }
                Cell::Time(Some(t)) => {
                    o.raw(name, &format!("\"{}\"", t.to_json_string()));
                }
                Cell::Time(None) => {
                    o.raw(name, "null");
                }
            }
        }
        if !self.batch_first {
            text(&mut o, "BatchKeyPath", self.batch_key_path.as_deref());
            text(&mut o, "BatchValueName", self.batch_value_name.as_deref());
        }
        o.finish()
    }
}

enum CsvColumn<'a> {
    KeyPath,
    ValueName,
    Column(&'a (&'static str, Cell)),
}

/// What ProcessValues leaves: the rows, the Errors list, and the messages of libraries it used, in order
#[derive(Debug, Default)]
pub struct Output {
    pub rows: Vec<ValuesOut>,
    pub errors: Vec<String>,
    pub messages: Vec<(Level, String)>,
}

/// An exception a plugin doesn't catch is an Err: the message RECmd's hive failure reports
pub type Process = fn(&Hive, KeyId, &mut Output) -> NetResult<()>;

/// A plugin. The table below is in the order of their dll names (as Windows lists them), which is the order RECmd loads
/// and so runs them in
pub struct Plugin {
    /// The class's name, which names its output files
    pub type_name: &'static str,
    /// PluginName, for messages
    pub plugin_name: &'static str,
    pub key_paths: &'static [&'static str],
    pub value_name: Option<&'static str>,
    pub process: Process,
}

const fn plugin(
    type_name: &'static str,
    plugin_name: &'static str,
    key_paths: &'static [&'static str],
    value_name: Option<&'static str>,
    process: Process,
) -> Plugin {
    Plugin { type_name, plugin_name, key_paths, value_name, process }
}

pub static PLUGINS: &[Plugin] = &[
    plugin("SevenZipCopyHistory", "7-Zip copy history", &[r"Software\7-Zip\FM"], Some("CopyHistory"), history::seven_zip_copy),
    plugin("SevenZipFolderHistory", "7-Zip folder history", &[r"Software\7-Zip\FM"], Some("FolderHistory"), history::seven_zip_folder),
    plugin("SevenZip", "7-Zip archive history", &[r"Software\7-Zip\Compression"], Some("ArcHistory"), history::seven_zip_archive),
    plugin("SevenZipPathHistory", "7-Zip extraction path history", &[r"Software\7-Zip\Extraction"], Some("PathHistory"), history::seven_zip_path),
    plugin("Adobe", "Adobe program information", &[r"Software\Adobe"], None, mru::adobe),
    plugin("AdobeTrustManager", "Adobe User Accessed Websites", &[r"Software\Adobe"], None, apps::adobe_trust_manager),
    plugin("InventoryApplication", "Amcache-InventoryApplication", &[r"ROOT\InventoryApplication"], None, amcache::application),
    plugin("InventoryApplicationFile", "Amcache-InventoryApplicationFile", &[r"ROOT\InventoryApplicationFile"], None, amcache::application_file),
    plugin("InventoryApplicationShortcut", "Amcache-InventoryApplicationShortcut", &[r"ROOT\InventoryApplicationShortcut"], None, amcache::application_shortcut),
    plugin("InventoryDeviceContainer", "Amcache-InventoryDeviceContainer", &[r"ROOT\InventoryDeviceContainer"], None, amcache::device_container),
    plugin("InventoryDevicePnp", "Amcache-InventoryDevicePnp", &[r"ROOT\InventoryDevicePnp"], None, amcache::device_pnp),
    plugin("InventoryDriverBinary", "Amcache-InventoryDriverBinary", &[r"ROOT\InventoryDriverBinary"], None, amcache::driver_binary),
    plugin("Mare", "Amcache-Mare", &[r"Root\Mare"], None, amcache::mare),
    plugin("AppCompat", "AppCompatCache", &[r"ControlSet00*\Control\Session Manager\AppCompatCache"], Some("AppCompatCache"), system::app_compat_cache),
    plugin("AppCompatFlags", "AppCompatFlags", &[r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CIT\System"], None, execution::app_compat_flags),
    plugin("AppCompatFlags2", "AppCompatFlags2", &[r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"], None, apps::app_compat_flags2),
    plugin(
        "ApplicationSettingsContainer",
        "ApplicationSettingsContainer",
        &[r"LocalState", r"RoamingState", r"LocalState\*", r"RoamingState\*"],
        None,
        uwp_settings::application_settings_container,
    ),
    plugin("AppPaths", "AppPaths", &[r"Microsoft\Windows\CurrentVersion\App Paths", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"], None, apps::app_paths),
    plugin("Ares", "Ares P2P information", &[r"Software\Ares"], None, mru::ares),
    plugin(
        "BamDam",
        "BamDam",
        &[r"ControlSet00*\Services\bam\UserSettings\*", r"ControlSet00*\Services\dam\UserSettings\*", r"ControlSet00*\Services\bam\State\UserSettings\*"],
        None,
        system::bam_dam,
    ),
    plugin("BluetoothBthPort", "BluetoothBthPort", &[r"ControlSet00*\Services\BTHPORT\Parameters\Devices"], None, system::bluetooth),
    plugin("CIDSizeMRU", "ComDlg32 CIDSizeMRU", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU"], None, mru::cid_size_mru),
    plugin("DeviceClasses", "DeviceClasses", &[r"ControlSet00*\Control\DeviceClasses"], None, system::device_classes),
    plugin("DHCPNetworkHint", "DHCPNetworkHints", &[r"ControlSet00*\Services\Tcpip\Parameters\Interfaces"], None, devices::dhcp_network_hint),
    plugin("DsrmAdminLogonBehaviour", "DsrmAdminLogonBehaviour Value", &[r"ControlSet00*\Control\Lsa"], Some("DsrmAdminLogonBehavior"), system::dsrm),
    plugin("ETW", "ETW", &[r"ControlSet001\Control\WMI\Autologger\EventLog-Application", r"ControlSet001\Control\WMI\Autologger\EventLog-System"], None, system::etw),
    plugin("FeatureUsage", "FeatureUsage", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage"], None, history::feature_usage),
    plugin("FileExts", "File Extensions", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"], None, mru::file_exts),
    plugin(
        "FirewallRules",
        "FirewallRules",
        &[
            r"ControlSet00*\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
            r"ControlSet00*\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules",
            r"ControlSet00*\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules",
        ],
        None,
        devices::firewall_rules,
    ),
    plugin("FirstFolder", "First folder", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder"], None, mru::first_folder),
    plugin("IconLayouts", "IconLayouts", &[r"Software\Microsoft\Windows\Shell\Bags\1\Desktop"], None, mru::icon_layouts),
    plugin("JumplistData", "JumplistData", &[r"Software\Microsoft\Windows\CurrentVersion\Search\JumplistData"], None, history::jumplist_data),
    plugin("KnownNetworks", "Known networks", &[r"Microsoft\Windows NT\CurrentVersion\NetworkList"], None, devices::known_networks),
    plugin("LastVisitedMRU", "ComDlg32 LastVisitedMRU", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"], None, mru::last_visited_mru),
    plugin(
        "LastVisitedPidlMRU",
        "ComDlg32 LastVisitedPidlMRU",
        &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy"],
        None,
        shell::last_visited_pidl_mru,
    ),
    plugin("NetworkAdapters", "NetworkAdapters", &[r"ControlSet00*\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"], None, network::adapters),
    plugin("NetworkSettings", "NetworkSettings", &[r"ControlSet00*\Services\Tcpip\Parameters\Interfaces"], None, network::settings),
    plugin("NetworkSetup2", "NetworkSetup2", &[r"ControlSet00*\Control\NetworkSetup2"], None, network::setup2),
    plugin(
        "OfficeMRU",
        "Office MRU",
        &[r"Software\Microsoft\Office\*\*\User MRU\*\File MRU", r"Software\Microsoft\Office\*\*\User MRU\*\Place MRU", r"Software\Microsoft\Office\*\*\File MRU", r"Software\Microsoft\Office\*\*\Place MRU"],
        None,
        mru::office_mru,
    ),
    plugin("OpenSaveMRU", "ComDlg32 OpenSaveMRU", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"], None, mru::open_save_mru),
    plugin("OpenSavePidlMRU", "ComDlg32 OpenSavePidlMRU", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"], None, shell::open_save_pidl_mru),
    plugin("Products", "Products", &[r"Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products", r"Classes\Installer\Products"], None, apps::products),
    plugin("ProfileList", "ProfileList", &[r"Microsoft\Windows NT\CurrentVersion\ProfileList"], None, system::profile_list),
    plugin("RADAR", "RADAR", &[r"Microsoft\RADAR\HeapLeakDetection", r"WOW6432Node\Microsoft\RADAR\HeapLeakDetection"], None, apps::radar),
    plugin("RecentApps", "RecentApps", &[r"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"], None, mru::recent_apps),
    plugin(
        "RecentDocs",
        "Recent documents",
        &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\*"],
        None,
        shell::recent_docs,
    ),
    plugin("RunMRU", "RunMRU", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"], None, history::run_mru),
    plugin("UserAccounts", "User accounts", &[r"SAM\Domains\Account\Users"], None, accounts::user_accounts),
    plugin("SAMBuiltin", "SAMBuiltin", &[r"SAM\Domains\Builtin\Aliases"], None, devices::sam_builtin),
    plugin("SCSI", "SCSI", &[r"ControlSet00*\Enum\SCSI"], None, devices::scsi),
    plugin("Services", "Services", &[r"ControlSet00*\Services"], None, devices::services),
    plugin("SWD", "SWD", &[r"ControlSet00*\Enum\SWD"], None, devices::swd),
    plugin("SyscacheObjectTable", "Syscache.hve ObjectTable", &[r"DefaultObjectStore\ObjectTable"], None, devices::syscache_object_table),
    plugin("Taskband", "Taskband", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"], Some("Favorites"), shell::taskband),
    plugin("TaskCache", "TaskCache", &[r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"], None, execution::task_cache),
    plugin(
        "TaskFlowShellActivities",
        "Taskflow Shell Activities",
        &[r"Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.taskflow.shellactivities\Current"],
        None,
        mru::task_flow,
    ),
    plugin("TerminalServerClient", "TerminalServerClient", &[r"Software\Microsoft\Terminal Server Client"], None, network::terminal_server_client),
    plugin("TimeZoneInfo", "TimeZoneInformation", &[r"ControlSet00*\Control\TimeZoneInformation"], None, devices::time_zone),
    plugin(
        "TrustedDocuments",
        "TrustedDocuments",
        &[
            r"Software\Microsoft\Office\15.0\Word\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\15.0\Excel\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\15.0\PowerPoint\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\15.0\Access\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\15.0\OneNote\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\16.0\Access\Security\Trusted Documents\TrustRecords",
            r"Software\Microsoft\Office\16.0\OneNote\Security\Trusted Documents\TrustRecords",
        ],
        None,
        mru::trusted_documents,
    ),
    plugin("TypedURLs", "TypedURLs", &[r"Software\Microsoft\Internet Explorer\TypedURLs"], None, history::typed_urls),
    plugin(
        "UnInstall",
        "Uninstall",
        &[r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"Microsoft\Windows\CurrentVersion\Uninstall", r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"],
        None,
        apps::uninstall,
    ),
    plugin("USB", "USB", &[r"ControlSet00*\Enum\USB"], None, devices::usb),
    plugin("USBSTOR", "USBSTOR", &[r"ControlSet00*\Enum\USBSTOR"], None, devices::usbstor),
    plugin(
        "UserAssist",
        "UserAssist",
        &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count"],
        None,
        mru::user_assist,
    ),
    plugin("VolumeInfoCache", "VolumeInfoCache", &[r"Microsoft\Windows Search\VolumeInfoCache"], None, system::volume_info_cache),
    plugin(
        "WindowsApp",
        "Windows App",
        &[
            r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository",
            r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository",
        ],
        None,
        apps::windows_app,
    ),
    plugin("WindowsPortableDevices", "Windows Portable Devices", &[r"Microsoft\Windows Portable Devices"], None, system::portable_devices),
    plugin("WinRAR", "WinRAR", &[r"Software\WinRAR"], None, history::winrar),
    plugin("WordWheelQuery", "WordWheelQuery", &[r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"], None, mru::word_wheel_query),
];

/// A key path of a plugin, ready to compare
enum Matcher {
    /// With a wildcard: `*` is `.+?`, the end of the regular expression is the end of the path
    Wildcard(Regex),
    /// The path, in lowercase
    Plain(String),
}

struct Compiled {
    plugin: &'static Plugin,
    matcher: Matcher,
    /// Plugin.ValueName, in lowercase
    value_name: Option<String>,
}

/// Decides which plugins handle a key: GetPluginsToActivate
pub struct Activation {
    paths: Vec<Compiled>,
}

impl Default for Activation {
    fn default() -> Self {
        Self::new()
    }
}

impl Activation {
    pub fn new() -> Activation {
        let mut paths = Vec::new();
        for plugin in PLUGINS {
            for path in plugin.key_paths {
                let matcher = if path.contains('*') {
                    // .NET reads a brace that isn't a quantifier as itself; the expression here needs them escaped
                    let pattern = path.replace('*', ".+?").replace('\\', "\\\\").replace('{', "\\{").replace('}', "\\}");
                    Matcher::Wildcard(Regex::new(&format!("(?i){pattern}\\z")).expect("the plugins' key paths are valid"))
                } else {
                    Matcher::Plain(lower(path))
                };
                paths.push(Compiled { plugin, matcher, value_name: plugin.value_name.map(lower) });
            }
        }
        Activation { paths }
    }

    /// The plugins for a key (its path without the root key) and the batch key's ValueName. A plugin with two paths that
    /// both match is there twice, as in the original.
    pub fn plugins_for(&self, key_path: &str, batch_value_name: Option<&str>) -> Vec<&'static Plugin> {
        let key_lower = lower(key_path);
        let batch_lower = batch_value_name.map(lower);
        let same_value = |c: &Compiled| batch_lower.is_some() && c.value_name == batch_lower;
        let mut active = Vec::new();
        for c in &self.paths {
            let hit = match &c.matcher {
                Matcher::Wildcard(regex) => {
                    regex.is_match(key_path).unwrap_or(false) && (c.value_name.is_none() || same_value(c))
                }
                Matcher::Plain(path) => {
                    path.contains(&key_lower) && ((c.value_name.is_none() && *path == key_lower) || same_value(c))
                }
            };
            if hit {
                active.push(c.plugin);
            }
        }
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(key: &str, value: Option<&str>) -> Vec<&'static str> {
        Activation::new().plugins_for(key, value).iter().map(|p| p.type_name).collect()
    }

    #[test]
    fn wildcards_match_to_the_end_of_the_path_in_any_case() {
        assert_eq!(names(r"controlset001\services\BAM\State\UserSettings\S-1-5-18", None), ["BamDam"]);
        assert!(names(r"ControlSet001\Services\bam\State\UserSettings", None).is_empty());
        assert_eq!(names(r"ControlSet002\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}", None), ["NetworkAdapters"]);
    }

    #[test]
    fn a_plugin_for_one_value_needs_the_batch_key_to_name_it() {
        assert!(names(r"Software\7-Zip\Compression", None).is_empty());
        assert_eq!(names(r"Software\7-Zip\Compression", Some("archistory")), ["SevenZip"]);
        // the original only asks that the plugin's path contains the key's, so a parent key is enough
        assert_eq!(names(r"Software\7-Zip", Some("ArcHistory")), ["SevenZip"]);
    }

    #[test]
    fn whole_key_plugins_need_the_whole_path() {
        assert_eq!(names(r"Software\WinRAR", None), ["WinRAR"]);
        assert!(names(r"Software", None).is_empty());
        // SOFTWARE\Microsoft\... contains this path, but only the plugin's own entry for it is equal
        assert_eq!(names(r"Microsoft\Windows\CurrentVersion\Uninstall", None), ["UnInstall"]);
    }

    #[test]
    fn output_lines_as_recmd_writes_them() {
        let row = ValuesOut {
            columns: vec![
                ("Name", "a,b".into()),
                ("Missing", Cell::Text(None)),
                ("On", true.into()),
                ("Position", 3.into()),
                ("When", Cell::Time(None)),
            ],
            batch_key_path: Some("K".into()),
            batch_value_name: None,
            batch_value_data1: String::new(),
            batch_value_data2: None,
            batch_value_data3: None,
            batch_first: false,
            data1_null: false,
        };
        assert_eq!(row.csv_header(), "Name,BatchKeyPath,Missing,BatchValueName,On,Position,When");
        let mut line = String::new();
        row.csv_line(&mut line);
        assert_eq!(line, "\"a,b\",K,,,True,3,");
        assert_eq!(
            row.json_line(),
            r#"{"Name":"a,b","Missing":null,"On":true,"Position":3,"When":null,"BatchKeyPath":"K","BatchValueName":null}"#
        );
    }
}
