//! AmcacheParser: Amcache.hve and the Inventory*.db databases to CSV, with the original's options and output.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use amcache_ez::{
    AmcacheNew, AmcacheOld, DatabaseTable, DeviceContainer, DevicePnp, DriverBinary, DriverPackage, Error, FileEntryNew, FileEntryOld, ProgramsEntryNew,
    ProgramsEntryOld, Shortcut, Value, database_files, from_file_time_value, has_databases, is_new_format,
};
use clap::{ArgAction, CommandFactory, Parser};
use ez_common::cli::log::Logger;
use ez_common::cli::utc_now;
use ez_common::dotnet::{lower_invariant, n0, number_n};
use ez_common::net::path_extension;
use ez_common::{Level, Timestamp};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PRECISE_TIME_FORMAT: &str = "yyyy-MM-dd HH:mm:ss.fffffff";
/// CsvHelper's own format for a DateTimeOffset, where the original gives none
const INVARIANT_DATE: &str = "MM/dd/yyyy HH:mm:ss zzz";

/// Parses Amcache.hve (Windows 7 to 11) and the Inventory*.db databases, with AmcacheParser's options and output.
#[derive(Parser, Debug)]
#[command(
    version,
    args_override_self = true,
    after_help = "Examples:\n  amcacheparser -f /tmp/amcache/AmcacheWin10.hve --csv /tmp/out\n  amcacheparser -f /tmp/amcache/AmcacheWin10.hve -i --csv /tmp/out --csvf foo.csv\n  amcacheparser -f /tmp/amcache/AmcacheWin10.hve -w /tmp/whitelist.txt --csv /tmp/out\n  amcacheparser -f /tmp/Programs -i --csv /tmp/out    (Amcache.hve and the Inventory*.db databases)"
)]
struct Args {
    /// Amcache.hve to parse (Windows 7 to 11), the folder it's in (C:\Windows\AppCompat\Programs), or one of the
    /// Inventory*.db SQLite databases there (Windows 11 26H1 and later). The databases next to a hive are read too
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<String>,

    /// Include file entries for Programs entries
    #[arg(short = 'i', action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    include: bool,

    /// Path to file containing SHA-1 hashes to *exclude* from the results. Blacklisting overrides whitelisting
    #[arg(short = 'w', value_name = "FILE")]
    whitelist: Option<String>,

    /// Path to file containing SHA-1 hashes to *include* from the results. Blacklisting overrides whitelisting
    #[arg(short = 'b', value_name = "FILE")]
    blacklist: Option<String>,

    /// Directory to save CSV formatted results to
    #[arg(long, value_name = "DIR")]
    csv: Option<String>,

    /// File name to save CSV formatted results to. When present, overrides default name
    #[arg(long, value_name = "NAME")]
    csvf: Option<String>,

    /// The custom date/time format to use when displaying time stamps
    #[arg(long, default_value = "yyyy-MM-dd HH:mm:ss", value_name = "FORMAT")]
    dt: String,

    /// When true, display higher precision for timestamps
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    mp: bool,

    /// When true, ignore transaction log files for dirty hives. Default is FALSE
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    nl: bool,

    /// Folder for the temporary copies of the SQLite databases, which are opened instead of the evidence and deleted
    /// when done. Default: a Temp folder next to this program. A folder that isn't there is created, and removed again
    /// when done. If that folder can't be written to, this program stops: give a writable folder with --temp
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// Show debug information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    debug: bool,

    /// Show trace information during processing
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = false, default_missing_value = "true", value_name = "BOOL")]
    trace: bool,

    /// When true, save all console messages to <timestamp>_AmcacheParser_<version>_ConsoleLog.txt in the --csv directory.
    /// Use --co false to turn it off
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, default_value_t = true, default_missing_value = "true", value_name = "BOOL")]
    co: bool,
}

fn given(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// What the exception .NET throws says for a path that can't be created or written
fn io_message(path: &Path, e: &std::io::Error) -> String {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => format!("Access to the path '{}' is denied.", full.display()),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => format!("Could not find a part of the path '{}'.", full.display()),
        std::io::ErrorKind::AlreadyExists => format!("The file '{}' already exists.", full.display()),
        _ => e.to_string(),
    }
}

fn io_error(path: &Path, e: &std::io::Error) -> Error {
    Error { message: io_message(path, e), could_not_process: true }
}

/// Path.GetFullPath: `.` and `..` are resolved, and a separator at the end is kept
fn full_path(p: &str) -> String {
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
    let mut text = out.to_string_lossy().into_owned();
    if p.ends_with('/') && !text.ends_with('/') {
        text.push('/');
    }
    text
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Path.GetFileNameWithoutExtension
fn stem(p: &str) -> &str {
    let name = base_name(p);
    let extension = path_extension(name);
    let without = &name[..name.len() - extension.len()];
    // a name ending in a dot loses it too
    without.strip_suffix('.').filter(|_| extension.is_empty()).unwrap_or(without)
}

fn full_ext(p: &str) -> &str {
    path_extension(base_name(p))
}

/// The P3 format
fn p3(v: f64) -> String {
    if v.is_nan() { "NaN".into() } else { format!("{}%", number_n(v * 100.0, 3)) }
}

fn yes_no(b: bool) -> String {
    if b { "True".into() } else { "False".into() }
}

fn date(t: Option<Timestamp>, dt: &str) -> String {
    t.map(|t| t.format(dt)).unwrap_or_default()
}

fn number<T: ToString>(n: Option<T>) -> String {
    n.map(|v| v.to_string()).unwrap_or_default()
}

/// File.ReadLines, with the encoding from the byte order mark
fn read_lines(path: &str) -> Result<Vec<String>, Error> {
    let bytes = std::fs::read(path).map_err(|e| io_error(Path::new(path), &e))?;
    let utf16 = |rest: &[u8], big: bool| {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| if big { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) }).collect();
        String::from_utf16_lossy(&units)
    };
    let text = match bytes.as_slice() {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        all => String::from_utf8_lossy(all).into_owned(),
    };
    let mut lines: Vec<String> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l).to_string()).flat_map(|l| l.split('\r').map(str::to_string).collect::<Vec<_>>()).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    Ok(lines)
}

/// A CSV as CsvHelper writes it
fn write_csv<T>(path: &Path, headers: &[&str], rows: impl Iterator<Item = T>, cell: impl Fn(&T, &str) -> String) -> Result<(), Error> {
    let file = File::create(path).map_err(|e| io_error(path, &e))?;
    let mut out = BufWriter::new(file);
    let mut line = String::new();
    let mut write_line = |line: &str| out.write_all(line.as_bytes()).map_err(|e| io_error(path, &e));
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        ez_common::csv::field(&mut line, h);
    }
    line.push_str(ez_common::csv::NEW_LINE);
    write_line(&line)?;
    for row in rows {
        line.clear();
        for (i, h) in headers.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            ez_common::csv::field(&mut line, &cell(&row, h));
        }
        line.push_str(ez_common::csv::NEW_LINE);
        write_line(&line)?;
    }
    drop(write_line);
    out.flush().map_err(|e| io_error(path, &e))
}

const FILE_NEW_COLUMNS: &[&str] = &[
    "ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name", "FileExtension", "LinkDate", "ProductName", "Size", "Version",
    "ProductVersion", "LongPathHash", "BinaryType", "IsPeFile", "BinFileVersion", "BinProductVersion", "Usn", "Language", "Description", "OriginalFileName", "Publisher", "Sha256",
    "KeyName", "AppxPackageFullName", "AppxPackageRelativeId",
];
const PROGRAM_NEW_COLUMNS: &[&str] = &[
    "ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDateArpLastModified", "InstallDate", "InstallDateMsi", "OSVersionAtInstallTime",
    "InstallDateFromLinkFile", "BundleManifestPath", "HiddenArp", "InboxModernApp", "Language", "ManifestPath", "MsiPackageCode", "MsiProductCode", "PackageFullName",
    "ProgramInstanceId", "RegistryKeyPath", "RootDirPath", "Type", "Source", "StoreAppType", "UninstallString", "Manufacturer", "KeyName", "UserSid", "MsiInstallDate",
];
const SHORTCUT_COLUMNS: &[&str] = &["KeyName", "LnkName", "KeyLastWriteTimestamp", "ShortcutTargetPath", "ShortcutAumid", "ShortcutProgramId"];
const DRIVER_BINARY_COLUMNS: &[&str] = &[
    "KeyName", "KeyLastWriteTimestamp", "DriverTimeStamp", "DriverLastWriteTime", "DriverName", "DriverInBox", "DriverIsKernelMode", "DriverSigned", "DriverCheckSum", "DriverCompany",
    "DriverId", "DriverPackageStrongName", "DriverType", "DriverVersion", "ImageSize", "Inf", "Product", "ProductVersion", "Service", "WdfVersion",
];
const DEVICE_CONTAINER_COLUMNS: &[&str] = &[
    "KeyName", "KeyLastWriteTimestamp", "Categories", "DiscoveryMethod", "FriendlyName", "Icon", "IsActive", "IsConnected", "IsMachineContainer", "IsNetworked", "IsPaired", "Manufacturer",
    "ModelId", "ModelName", "ModelNumber", "PrimaryCategory", "State",
];
const DRIVER_PACKAGE_COLUMNS: &[&str] = &[
    "KeyName", "KeyLastWriteTimestamp", "Date", "Class", "Directory", "DriverInBox", "Hwids", "Inf", "Provider", "SubmissionId", "SYSFILE", "Version", "ClassGuid", "DriverPackageStrongName",
    "FlightIds", "RecoveryIds", "IsActive",
];
const DEVICE_PNP_COLUMNS: &[&str] = &[
    "KeyName", "KeyLastWriteTimestamp", "BusReportedDescription", "Class", "ClassGuid", "Compid", "ContainerId", "Description", "DriverId", "DriverPackageStrongName", "DriverName",
    "DriverVerDate", "DriverVerVersion", "Enumerator", "HWID", "Inf", "InstallState", "Manufacturer", "MatchingId", "Model", "ParentId", "ProblemCode", "Provider", "Service", "Stackid",
    "DeviceState", "InstallDate", "FirstInstallDate", "ExtendedInfs", "UpperClassFilters", "LowerClassFilters", "UpperFilters", "LowerFilters", "DeviceInterfaceClasses", "LocationPaths",
];
const FILE_OLD_UNASSOCIATED_COLUMNS: &[&str] = &[
    "ProgramName", "ProgramID", "VolumeID", "VolumeIDLastWriteTimestamp", "FileID", "FileIDLastWriteTimestamp", "SHA1", "FullPath", "FileExtension", "MFTEntryNumber", "MFTSequenceNumber",
    "FileSize", "FileVersionString", "FileVersionNumber", "FileDescription", "SizeOfImage", "PEHeaderHash", "PEHeaderChecksum", "BinProductVersion", "BinFileVersion", "LinkerVersion",
    "BinaryType", "IsLocal", "GuessProgramID", "Created", "LastModified", "LastModifiedStore", "LinkDate", "LanguageID", "ProductName", "CompanyName", "SwitchBackContext",
];
const FILE_OLD_ASSOCIATED_COLUMNS: &[&str] = &[
    "ProgramName", "ProgramID", "ProductName", "VolumeID", "CompanyName", "VolumeIDLastWriteTimestamp", "FileID", "FileIDLastWriteTimestamp", "SHA1", "FullPath", "FileExtension", "MFTEntryNumber",
    "MFTSequenceNumber", "FileSize", "FileVersionString", "FileVersionNumber", "FileDescription", "SwitchBackContext", "SizeOfImage", "PEHeaderHash", "PEHeaderChecksum", "BinProductVersion",
    "BinFileVersion", "LinkerVersion", "BinaryType", "IsLocal", "GuessProgramID", "Created", "LastModified", "LastModifiedStore", "LinkDate", "LanguageID",
];
const PROGRAM_OLD_COLUMNS: &[&str] = &[
    "ProgramID", "LastWriteTimestamp", "ProgramName_0", "ProgramVersion_1", "VendorName_2", "InstallDateEpoch_a", "UnknownGuid_10", "InstallDateEpoch_b", "LanguageCode_3", "UnknownGuid_12",
    "InstallSource_6", "UninstallGuid_11", "UninstallRegistryKey_7", "UnknownDword_5", "PathsList_d", "UnknownDword_13", "UnknownDword_14", "UnknownDword_15", "UnknownBytes_16", "UnknownQWord_17",
    "UnknownDword_18", "UninstallGuid_f",
];

fn file_new_cell(e: &FileEntryNew, column: &str, dt: &str) -> String {
    match column {
        "ApplicationName" => e.application_name.clone(),
        "ProgramId" => e.program_id.clone(),
        "FileKeyLastWriteTimestamp" => e.file_key_last_write.format(dt),
        "SHA1" => e.sha1.clone(),
        "IsOsComponent" => yes_no(e.is_os_component),
        "FullPath" => e.full_path.clone(),
        "Name" => e.name.clone(),
        "FileExtension" => e.file_extension.clone(),
        "LinkDate" => date(e.link_date, dt),
        "ProductName" => e.product_name.clone(),
        "Size" => e.size.to_string(),
        "Version" => e.version.clone(),
        "ProductVersion" => e.product_version.clone(),
        "LongPathHash" => e.long_path_hash.clone(),
        "BinaryType" => e.binary_type.clone(),
        "IsPeFile" => yes_no(e.is_pe_file),
        "BinFileVersion" => e.bin_file_version.clone(),
        "BinProductVersion" => e.bin_product_version.clone(),
        "Usn" => e.usn.to_string(),
        "Language" => e.language.to_string(),
        "Description" => e.description.clone(),
        "OriginalFileName" => e.original_file_name.clone(),
        "Publisher" => e.publisher.clone(),
        "Sha256" => e.sha256.clone(),
        "KeyName" => e.key_name.clone(),
        "AppxPackageFullName" => e.appx_package_full_name.clone(),
        "AppxPackageRelativeId" => e.appx_package_relative_id.clone(),
        _ => unreachable!("{column}"),
    }
}

fn program_new_cell(p: &ProgramsEntryNew, column: &str, dt: &str) -> String {
    match column {
        "ProgramId" => p.program_id.clone(),
        "KeyLastWriteTimestamp" => p.key_last_write.format(dt),
        "Name" => p.name.clone(),
        "Version" => p.version.clone(),
        "Publisher" => p.publisher.clone(),
        "InstallDateArpLastModified" => p.install_date_arp_last_modified.clone(),
        "InstallDate" => date(p.install_date, dt),
        // no format in the original: CsvHelper's own
        "InstallDateMsi" => date(p.install_date_msi, INVARIANT_DATE),
        "OSVersionAtInstallTime" => p.os_version_at_install_time.clone(),
        "InstallDateFromLinkFile" => p.install_date_from_link_file.clone(),
        "BundleManifestPath" => p.bundle_manifest_path.clone(),
        "HiddenArp" => yes_no(p.hidden_arp),
        "InboxModernApp" => yes_no(p.inbox_modern_app),
        "Language" => p.language.to_string(),
        "ManifestPath" => p.manifest_path.clone(),
        "MsiPackageCode" => p.msi_package_code.clone(),
        "MsiProductCode" => p.msi_product_code.clone(),
        "PackageFullName" => p.package_full_name.clone(),
        "ProgramInstanceId" => p.program_instance_id.clone(),
        "RegistryKeyPath" => p.registry_key_path.clone(),
        "RootDirPath" => p.root_dir_path.clone(),
        "Type" => p.program_type.clone(),
        "Source" => p.source.clone(),
        "StoreAppType" => p.store_app_type.clone(),
        "UninstallString" => p.uninstall_string.clone(),
        "Manufacturer" => p.manufacturer.clone(),
        "KeyName" => p.key_name.clone(),
        "UserSid" => p.user_sid.clone(),
        "MsiInstallDate" => date(p.msi_install_date, dt),
        _ => unreachable!("{column}"),
    }
}

fn shortcut_cell(s: &Shortcut, column: &str, dt: &str) -> String {
    match column {
        "KeyName" => s.key_name.clone(),
        "LnkName" => s.lnk_name.clone(),
        "KeyLastWriteTimestamp" => s.key_last_write.format(dt),
        "ShortcutTargetPath" => s.shortcut_target_path.clone(),
        "ShortcutAumid" => s.shortcut_aumid.clone(),
        "ShortcutProgramId" => s.shortcut_program_id.clone(),
        _ => unreachable!("{column}"),
    }
}

fn driver_binary_cell(b: &DriverBinary, column: &str, dt: &str) -> String {
    match column {
        "KeyName" => b.key_name.clone(),
        "KeyLastWriteTimestamp" => b.key_last_write.format(dt),
        "DriverTimeStamp" => date(b.driver_time_stamp, dt),
        "DriverLastWriteTime" => date(b.driver_last_write_time, dt),
        "DriverName" => b.driver_name.clone(),
        "DriverInBox" => yes_no(b.driver_in_box),
        "DriverIsKernelMode" => yes_no(b.driver_is_kernel_mode),
        "DriverSigned" => yes_no(b.driver_signed),
        "DriverCheckSum" => b.driver_check_sum.to_string(),
        "DriverCompany" => b.driver_company.clone(),
        "DriverId" => b.driver_id.clone(),
        "DriverPackageStrongName" => b.driver_package_strong_name.clone(),
        "DriverType" => b.driver_type.clone(),
        "DriverVersion" => b.driver_version.clone(),
        "ImageSize" => b.image_size.to_string(),
        "Inf" => b.inf.clone(),
        "Product" => b.product.clone(),
        "ProductVersion" => b.product_version.clone(),
        "Service" => b.service.clone(),
        "WdfVersion" => b.wdf_version.clone(),
        _ => unreachable!("{column}"),
    }
}

fn device_container_cell(c: &DeviceContainer, column: &str, dt: &str) -> String {
    match column {
        "KeyName" => c.key_name.clone(),
        "KeyLastWriteTimestamp" => c.key_last_write.format(dt),
        "Categories" => c.categories.clone(),
        "DiscoveryMethod" => c.discovery_method.clone(),
        "FriendlyName" => c.friendly_name.clone(),
        "Icon" => c.icon.clone(),
        "IsActive" => yes_no(c.is_active),
        "IsConnected" => yes_no(c.is_connected),
        "IsMachineContainer" => yes_no(c.is_machine_container),
        "IsNetworked" => yes_no(c.is_networked),
        "IsPaired" => yes_no(c.is_paired),
        "Manufacturer" => c.manufacturer.clone(),
        "ModelId" => c.model_id.clone(),
        "ModelName" => c.model_name.clone(),
        "ModelNumber" => c.model_number.clone(),
        "PrimaryCategory" => c.primary_category.clone(),
        "State" => c.state.clone(),
        _ => unreachable!("{column}"),
    }
}

fn driver_package_cell(p: &DriverPackage, column: &str, dt: &str) -> String {
    match column {
        "KeyName" => p.key_name.clone(),
        "KeyLastWriteTimestamp" => p.key_last_write.format(dt),
        "Date" => date(p.date, dt),
        "Class" => p.class.clone(),
        "Directory" => p.directory.clone(),
        "DriverInBox" => yes_no(p.driver_in_box),
        "Hwids" => p.hwids.clone(),
        "Inf" => p.inf.clone(),
        "Provider" => p.provider.clone(),
        "SubmissionId" => p.submission_id.clone(),
        "SYSFILE" => p.sysfile.clone(),
        "Version" => p.version.clone(),
        "ClassGuid" => p.class_guid.clone(),
        "DriverPackageStrongName" => p.driver_package_strong_name.clone(),
        "FlightIds" => p.flight_ids.clone(),
        "RecoveryIds" => p.recovery_ids.clone(),
        "IsActive" => p.is_active.clone(),
        _ => unreachable!("{column}"),
    }
}

fn device_pnp_cell(p: &DevicePnp, column: &str, dt: &str) -> String {
    match column {
        "KeyName" => p.key_name.clone(),
        "KeyLastWriteTimestamp" => p.key_last_write.format(dt),
        "BusReportedDescription" => p.bus_reported_description.clone(),
        "Class" => p.class.clone(),
        "ClassGuid" => p.class_guid.clone(),
        "Compid" => p.compid.clone(),
        "ContainerId" => p.container_id.clone(),
        "Description" => p.description.clone(),
        "DriverId" => p.driver_id.clone(),
        "DriverPackageStrongName" => p.driver_package_strong_name.clone(),
        "DriverName" => p.driver_name.clone(),
        "DriverVerDate" => p.driver_ver_date.clone(),
        "DriverVerVersion" => p.driver_ver_version.clone(),
        "Enumerator" => p.enumerator.clone(),
        "HWID" => p.hwid.clone(),
        "Inf" => p.inf.clone(),
        "InstallState" => p.install_state.clone(),
        "Manufacturer" => p.manufacturer.clone(),
        "MatchingId" => p.matching_id.clone(),
        "Model" => p.model.clone(),
        "ParentId" => p.parent_id.clone(),
        "ProblemCode" => p.problem_code.clone(),
        "Provider" => p.provider.clone(),
        "Service" => p.service.clone(),
        "Stackid" => p.stackid.clone(),
        "DeviceState" => p.device_state.clone(),
        "InstallDate" => p.install_date.clone(),
        "FirstInstallDate" => p.first_install_date.clone(),
        "ExtendedInfs" => p.extended_infs.clone(),
        "UpperClassFilters" => p.upper_class_filters.clone(),
        "LowerClassFilters" => p.lower_class_filters.clone(),
        "UpperFilters" => p.upper_filters.clone(),
        "LowerFilters" => p.lower_filters.clone(),
        "DeviceInterfaceClasses" => p.device_interface_classes.clone(),
        "LocationPaths" => p.location_paths.clone(),
        _ => unreachable!("{column}"),
    }
}

fn file_old_cell(e: &FileEntryOld, column: &str, dt: &str) -> String {
    match column {
        "ProgramName" => e.program_name.clone(),
        "ProgramID" => e.program_id.clone(),
        "VolumeID" => e.volume_id.clone(),
        "VolumeIDLastWriteTimestamp" => e.volume_id_last_write.format(dt),
        "FileID" => e.file_id.clone(),
        "FileIDLastWriteTimestamp" => e.file_id_last_write.format(dt),
        "SHA1" => e.sha1.clone(),
        "FullPath" => e.full_path.clone(),
        "FileExtension" => e.file_extension.clone(),
        "MFTEntryNumber" => e.mft_entry_number.to_string(),
        "MFTSequenceNumber" => e.mft_sequence_number.to_string(),
        "FileSize" => number(e.file_size),
        "FileVersionString" => e.file_version_string.clone(),
        "FileVersionNumber" => e.file_version_number.clone(),
        "FileDescription" => e.file_description.clone(),
        "SizeOfImage" => number(e.size_of_image),
        "PEHeaderHash" => e.pe_header_hash.clone(),
        "PEHeaderChecksum" => number(e.pe_header_checksum),
        "BinProductVersion" => e.bin_product_version.to_string(),
        "BinFileVersion" => e.bin_file_version.to_string(),
        "LinkerVersion" => e.linker_version.to_string(),
        "BinaryType" => e.binary_type.to_string(),
        "IsLocal" => e.is_local.to_string(),
        "GuessProgramID" => e.guess_program_id.to_string(),
        "Created" => date(e.created, dt),
        "LastModified" => date(e.last_modified, dt),
        "LastModifiedStore" => date(e.last_modified_store, dt),
        "LinkDate" => date(e.link_date, dt),
        "LanguageID" => number(e.language_id),
        "ProductName" => e.product_name.clone(),
        "CompanyName" => e.company_name.clone(),
        "SwitchBackContext" => e.switch_back_context.clone(),
        _ => unreachable!("{column}"),
    }
}

fn program_old_cell(p: &ProgramsEntryOld, column: &str, dt: &str) -> String {
    match column {
        "ProgramID" => p.program_id.clone(),
        "LastWriteTimestamp" => p.last_write.format(dt),
        "ProgramName_0" => p.program_name_0.clone(),
        "ProgramVersion_1" => p.program_version_1.clone(),
        "VendorName_2" => p.vendor_name_2.clone(),
        "InstallDateEpoch_a" => date(p.install_date_epoch_a, dt),
        "UnknownGuid_10" => p.unknown_guid_10.clone(),
        "InstallDateEpoch_b" => date(p.install_date_epoch_b, dt),
        "LanguageCode_3" => p.language_code_3.clone(),
        "UnknownGuid_12" => p.unknown_guid_12.clone(),
        "InstallSource_6" => p.install_source_6.clone(),
        "UninstallGuid_11" => p.uninstall_guid_11.clone(),
        "UninstallRegistryKey_7" => p.uninstall_registry_key_7.clone(),
        "UnknownDword_5" => p.unknown_dword_5.to_string(),
        "PathsList_d" => p.paths_list_d.clone(),
        "UnknownDword_13" => p.unknown_dword_13.to_string(),
        "UnknownDword_14" => p.unknown_dword_14.to_string(),
        "UnknownDword_15" => p.unknown_dword_15.to_string(),
        "UnknownBytes_16" => format!("0x{}", p.unknown_bytes_16.iter().map(|b| format!("{b:02X}")).collect::<String>()),
        "UnknownQWord_17" => p.unknown_qword_17.to_string(),
        "UnknownDword_18" => p.unknown_dword_18.to_string(),
        "UninstallGuid_f" => p.uninstall_guid_f.clone(),
        _ => unreachable!("{column}"),
    }
}

/// What every CSV needs
struct Output<'a> {
    stamp: &'a str,
    csv: &'a str,
    csvf: Option<&'a str>,
    dt: &'a str,
    include: bool,
    /// The hashes in the -w or -b file
    hashes: &'a HashSet<String>,
    use_blacklist: bool,
    blacklist_given: bool,
}

impl Output<'_> {
    fn path(&self, hive_name: &str, suffix: &str, kind: &str) -> PathBuf {
        let name = match self.csvf {
            Some(f) => format!("{}{suffix}_{kind}{}", stem(f), full_ext(f)),
            None => format!("{}_{hive_name}_{kind}.csv", self.stamp),
        };
        Path::new(self.csv).join(name)
    }

    fn keeps(&self, sha1: &str) -> bool {
        self.hashes.contains(sha1) == self.use_blacklist
    }

    /// Ok(false) when the CSV folder can't be created, which ends the run
    fn make_folder(&self, log: &mut Logger) -> bool {
        if Path::new(self.csv).is_dir() {
            return true;
        }
        match std::fs::create_dir_all(self.csv) {
            Ok(()) => true,
            Err(e) => {
                let message = io_message(Path::new(self.csv), &e);
                log.error(&format!("There was an error creating directory {}. Error: {message} Exiting", self.csv));
                log.blank();
                false
            }
        }
    }

    fn write_percentage(&self, shown: usize, total: i32, log: &mut Logger) {
        let per = shown as f64 / total as f64;
        log.blank();
        let list = if self.blacklist_given { "blacklist" } else { "whitelist" };
        let title = if self.blacklist_given { "Blacklist" } else { "Whitelist" };
        log.info(&format!("{title} hash count: {}", n0(self.hashes.len() as u64)));
        log.blank();
        log.info(&format!("Percentage of total shown based on {list}: {} ({} savings)", p3(per), p3(1.0 - per)));
    }

    /// WriteOldFormat
    fn write_old(&self, am: &AmcacheOld, source: &str, hive_name: &str, suffix: &str, log: &mut Logger) -> Result<bool, Error> {
        let dt = self.dt;
        let clean: Vec<&FileEntryOld> = am.unassociated_file_entries.iter().filter(|e| self.keeps(&e.sha1)).collect();
        if !self.make_folder(log) {
            return Ok(false);
        }
        let program_files = am.programs_entries.iter().flat_map(|p| &p.file_entries).filter(|e| self.keeps(&e.sha1)).count();

        write_csv(&self.path(hive_name, suffix, "UnassociatedFileEntries"), FILE_OLD_UNASSOCIATED_COLUMNS, clean.iter(), |e, c| file_old_cell(e, c, dt))?;
        if self.include {
            write_csv(&self.path(hive_name, suffix, "ProgramEntries"), PROGRAM_OLD_COLUMNS, am.programs_entries.iter(), |p, c| program_old_cell(p, c, dt))?;
            let associated = am.programs_entries.iter().flat_map(|p| &p.file_entries).filter(|e| self.keeps(&e.sha1));
            write_csv(&self.path(hive_name, suffix, "AssociatedFileEntries"), FILE_OLD_ASSOCIATED_COLUMNS, associated, |e, c| file_old_cell(e, c, dt))?;
        }

        log.blank();
        if suffix.is_empty() {
            log.info(&format!("{source} is in old format (registry hive, Root\\File and Root\\Programs keys)"));
        } else {
            log.info(&format!("{source} also has old format entries (Root\\File and Root\\Programs keys), as hives upgraded from Windows 8 can"));
        }
        log.blank();
        log.info(&format!("Total file entries found: {}", n0(am.total_file_entries as u64)));
        if self.include {
            log.info(&format!(
                "Found {} unassociated file entries and {} program file entries (across {} program entries)",
                n0(clean.len() as u64),
                n0(program_files as u64),
                n0(am.programs_entries.len() as u64)
            ));
        } else if am.unassociated_file_entries.len() == 1 {
            log.info(&format!("Found {} unassociated file entry", n0(clean.len() as u64)));
        } else {
            log.info(&format!("Found {} unassociated file entries", n0(clean.len() as u64)));
        }
        if !self.hashes.is_empty() {
            self.write_percentage(program_files + clean.len(), am.total_file_entries, log);
        }
        Ok(true)
    }

    /// WriteNewFormat
    fn write_new(&self, am: &AmcacheNew, source: &str, hive_name: &str, suffix: &str, log: &mut Logger) -> Result<bool, Error> {
        let dt = self.dt;
        let clean: Vec<&FileEntryNew> = am.unassociated_file_entries.iter().filter(|e| self.keeps(&e.sha1)).collect();
        if !self.make_folder(log) {
            return Ok(false);
        }
        let program_files = am.programs_entries.iter().flat_map(|p| &p.file_entries).filter(|e| self.keeps(&e.sha1)).count();

        write_csv(&self.path(hive_name, suffix, "UnassociatedFileEntries"), FILE_NEW_COLUMNS, clean.iter(), |e, c| file_new_cell(e, c, dt))?;
        if self.include {
            write_csv(&self.path(hive_name, suffix, "ProgramEntries"), PROGRAM_NEW_COLUMNS, am.programs_entries.iter(), |p, c| program_new_cell(p, c, dt))?;
            let associated = am.programs_entries.iter().flat_map(|p| &p.file_entries).filter(|e| self.keeps(&e.sha1));
            write_csv(&self.path(hive_name, suffix, "AssociatedFileEntries"), FILE_NEW_COLUMNS, associated, |e, c| file_new_cell(e, c, dt))?;
        }
        write_csv(&self.path(hive_name, suffix, "ShortCuts"), SHORTCUT_COLUMNS, am.short_cuts.iter(), |s, c| shortcut_cell(s, c, dt))?;
        write_csv(&self.path(hive_name, suffix, "DriverBinaries"), DRIVER_BINARY_COLUMNS, am.drive_binaries.iter(), |b, c| driver_binary_cell(b, c, dt))?;
        write_csv(&self.path(hive_name, suffix, "DeviceContainers"), DEVICE_CONTAINER_COLUMNS, am.device_containers.iter(), |d, c| device_container_cell(d, c, dt))?;
        write_csv(&self.path(hive_name, suffix, "DriverPackages"), DRIVER_PACKAGE_COLUMNS, am.driver_packages.iter(), |p, c| driver_package_cell(p, c, dt))?;
        write_csv(&self.path(hive_name, suffix, "DevicePnps"), DEVICE_PNP_COLUMNS, am.device_pnps.iter(), |p, c| device_pnp_cell(p, c, dt))?;

        log.blank();
        if suffix.is_empty() {
            log.info(&format!("{source} is in new format (registry hive, Root\\Inventory* keys)"));
        } else {
            log.info(&format!("{source} has the new format SQLite databases (Inventory*.db)"));
        }
        log.blank();
        log.info(&format!("Total file entries found: {}", n0(am.total_file_entries as u64)));
        if am.invalid_dates > 0 {
            log.warning(&format!("Dates that are not valid were left empty: {} (use --debug to see them)", n0(am.invalid_dates as u64)));
        }
        let counts = [
            ("shortcuts", am.short_cuts.len()),
            ("device containers", am.device_containers.len()),
            ("device PnPs", am.device_pnps.len()),
            ("drive binaries", am.drive_binaries.len()),
            ("driver packages", am.driver_packages.len()),
        ];
        for (name, count) in counts {
            if count > 0 {
                log.info(&format!("Total {name} found: {}", n0(count as u64)));
            }
        }
        log.blank();
        if self.include {
            log.info(&format!(
                "Found {} unassociated file entry and {} program file entries (across {} program entries)",
                n0(clean.len() as u64),
                n0(program_files as u64),
                n0(am.programs_entries.len() as u64)
            ));
        } else {
            log.info(&format!("Found {} unassociated file entry", n0(clean.len() as u64)));
        }
        if !self.hashes.is_empty() {
            self.write_percentage(program_files + clean.len(), am.total_file_entries, log);
        }
        Ok(true)
    }

    /// WriteDatabaseTables: one CSV per table with no class, and one for the Metadata tables of all of them
    fn write_tables(&self, tables: &[DatabaseTable], hive_name: &str, suffix: &str, log: &mut Logger) -> Result<(), Error> {
        for table in tables {
            let name = table_name(&table.name);
            let path = self.path(hive_name, suffix, name);
            let columns: Vec<&str> = table.columns.iter().map(String::as_str).collect();
            let time_index = table.columns.iter().position(|c| c == "LastModified");
            let is_metadata = table.name == "Metadata";

            let file = File::create(&path).map_err(|e| io_error(&path, &e))?;
            let mut out = BufWriter::new(file);
            let mut line = String::new();
            for (i, c) in columns.iter().enumerate() {
                if i > 0 {
                    line.push(',');
                }
                ez_common::csv::field(&mut line, c);
            }
            line.push_str(ez_common::csv::NEW_LINE);
            for row in &table.rows {
                for (n, value) in row.iter().enumerate() {
                    if n > 0 {
                        line.push(',');
                    }
                    ez_common::csv::field(&mut line, &table_cell(row, n, value, is_metadata, time_index, self.dt));
                }
                line.push_str(ez_common::csv::NEW_LINE);
            }
            out.write_all(line.as_bytes()).and_then(|()| out.flush()).map_err(|e| io_error(&path, &e))?;
            log.info(&format!("{name}: {} rows", n0(table.rows.len() as u64)));
        }
        Ok(())
    }
}

/// InventoryMiscellaneousUser_0 is InventoryMiscellaneousUser
fn table_name(name: &str) -> &str {
    match name.rsplit_once('_') {
        Some((base, digits)) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    }
}

fn is_file_time_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("time") || lower.contains("sync")
}

/// 1990 to 2100 as a FILETIME
fn is_plausible_file_time(value: i64) -> bool {
    (0x01B41E2A18D64000..=0x022F716377640000).contains(&value)
}

fn table_cell(row: &[Value], n: usize, value: &Value, is_metadata: bool, time_index: Option<usize>, dt: &str) -> String {
    // Metadata: lastFullSync, LastScanTime, ProgramIdListEventSentTime are FILETIMEs (as text)
    if is_metadata && n == 2 {
        if let (Value::Text(name), Value::Text(text)) = (&row[1], value) {
            if is_file_time_name(name) && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(file_time) = text.parse::<i64>() {
                    if is_plausible_file_time(file_time) {
                        return from_file_time_value(file_time).format(dt);
                    }
                }
            }
        }
    }
    if Some(n) == time_index {
        if let Value::Integer(v) = value {
            let time = from_file_time_value(*v);
            return if time == Timestamp::MIN { String::new() } else { time.format(dt) };
        }
    }
    match value {
        Value::Null => String::new(),
        Value::Integer(v) => v.to_string(),
        Value::Real(v) => ez_common::dotnet::dotnet_f64(*v),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => b.iter().map(|x| format!("{x:02X}")).collect(),
    }
}

/// TempFolder.Prepare: the folder for the copies of the databases, whether this run created it, or why it can't be used
fn prepare_temp(given_folder: Option<&str>) -> Result<(String, bool), String> {
    let folder = match given_folder {
        Some(f) => full_path(f),
        None => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            exe.parent().unwrap_or(Path::new(".")).join("Temp").to_string_lossy().into_owned()
        }
    };
    let created = !Path::new(&folder).is_dir();
    let attempt = || -> std::io::Result<()> {
        std::fs::create_dir_all(&folder)?;
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let probe = Path::new(&folder).join(format!("AmcacheParser-write-test-{stamp:032x}{:08x}", std::process::id()));
        std::fs::write(&probe, [])?;
        std::fs::remove_file(&probe)
    };
    match attempt() {
        Ok(()) => Ok((folder, created)),
        Err(e) => Err(format!("{folder}: {}", io_message(Path::new(&folder), &e))),
    }
}

/// TempFolder.RemoveIfEmpty: only if this run created it (another run may still be using it)
fn remove_temp_if_empty(folder: &str, created: bool) {
    if created {
        let _ = std::fs::remove_dir(folder);
    }
}

/// The -b file, or else the -w file
fn read_hashes(args: &Args, log: &mut Logger) -> Result<(HashSet<String>, bool), Error> {
    let mut hashes = HashSet::new();
    let mut use_blacklist = false;
    if let Some(b) = given(&args.blacklist) {
        if Path::new(b).is_file() {
            hashes.extend(read_lines(b)?.iter().map(|l| lower_invariant(l)));
            use_blacklist = true;
        } else {
            log.warning(&format!("{b} does not exist"));
        }
    } else if let Some(w) = given(&args.whitelist) {
        if Path::new(w).is_file() {
            hashes.extend(read_lines(w)?.iter().map(|l| lower_invariant(l)));
        } else {
            log.warning(&format!("{w} does not exist"));
        }
    }
    Ok((hashes, use_blacklist))
}

fn help_and_warning(log: &mut Logger, message: &str) -> ExitCode {
    let _ = Args::command().print_long_help();
    println!();
    log.warning(message);
    ExitCode::FAILURE
}

/// What the try block of DoWork ends with
enum Done {
    Exit(u8),
}

struct Run<'a> {
    args: &'a Args,
    log: Logger,
    start: Instant,
}

impl Run<'_> {
    fn results(&mut self, csv: &str) {
        self.log.blank();
        self.log.info(&format!("Results saved to: {csv}"));
        self.log.blank();
        self.log.info(&format!("Total parsing time: {} seconds", number_n(self.start.elapsed().as_secs_f64(), 3)));
        self.log.blank();
    }

    #[allow(clippy::too_many_arguments)]
    fn work(&mut self, f: &str, csv: &str, stamp: &str, dt: &str, database_directory: &str, databases: bool, hive_given: bool, temp: Option<&(String, bool)>) -> Result<Done, Error> {
        let args = self.args;
        let mut failed = false;
        let new_format = !hive_given || databases || is_new_format(f, args.nl, &mut |l, m| self.log.log(l, m));
        if new_format {
            let (hashes, use_blacklist) = read_hashes(args, &mut self.log)?;
            let output = Output {
                stamp,
                csv,
                csvf: given(&args.csvf),
                dt,
                include: args.include,
                hashes: &hashes,
                use_blacklist,
                blacklist_given: given(&args.blacklist).is_some(),
            };
            let hive_name = if hive_given { stem(f).to_string() } else { "Amcache".to_string() };

            if hive_given {
                self.log.debug("Processing new format hive");
                let opened = AmcacheNew::open(f, args.nl, &mut |l, m| self.log.log(l, m));
                let am_new = match opened {
                    Ok(a) => Some(a),
                    Err(e) if databases => {
                        // the databases can still be read
                        self.log.error(&format!("{f} could not be read: {}", e.message));
                        failed |= e.could_not_process;
                        None
                    }
                    Err(e) => return Err(e),
                };
                if let Some(am) = am_new {
                    if am.programs_entries.is_empty() && am.unassociated_file_entries.is_empty() {
                        self.log.warning("Hive did not contain program entries nor file entries");
                    }
                    if !output.write_new(&am, f, &hive_name, "", &mut self.log)? {
                        return Ok(Done::Exit(1));
                    }
                    // hives upgraded from Windows 8 can have the old keys too
                    if am.has_old_format_entries {
                        let old = AmcacheOld::open(f, args.nl, &mut |l, m| self.log.log(l, m))?;
                        if !output.write_old(&old, f, &format!("{hive_name}_OldFormat"), "_OldFormat", &mut self.log)? {
                            return Ok(Done::Exit(1));
                        }
                    }
                }
            }

            if databases {
                self.log.blank();
                self.log.info(&format!("Processing the Amcache databases in {database_directory}"));
                let (folder, created) = temp.expect("the temporary folder is prepared when there are databases");
                let result = AmcacheNew::from_databases(database_directory, Some(folder), &mut |l, m| self.log.log(l, m));
                remove_temp_if_empty(folder, *created);
                let am = result?;
                let name = format!("{hive_name}_Databases");
                if !output.write_new(&am, database_directory, &name, "_Databases", &mut self.log)? {
                    return Ok(Done::Exit(1));
                }
                output.write_tables(&am.other_tables, &name, "_Databases", &mut self.log)?;
                // a database that could not be opened or copied; damaged ones are listed, but are not the tool's fault
                failed |= am.databases_not_accessed > 0;
            } else if !hive_given {
                self.log.warning(&format!("No Amcache databases (Inventory*.db) found in {database_directory}"));
            }

            self.results(csv);
            return Ok(Done::Exit(u8::from(failed)));
        }

        self.log.debug("Processing old format hive");
        let am = AmcacheOld::open(f, args.nl, &mut |l, m| self.log.log(l, m))?;
        if am.programs_entries.is_empty() && am.unassociated_file_entries.is_empty() {
            self.log.warning("Hive did not contain program entries nor file entries. Exiting");
            self.log.blank();
            return Ok(Done::Exit(0));
        }
        let elapsed = self.start.elapsed().as_secs_f64();
        let (hashes, use_blacklist) = read_hashes(args, &mut self.log)?;
        let output = Output {
            stamp,
            csv,
            csvf: given(&args.csvf),
            dt,
            include: args.include,
            hashes: &hashes,
            use_blacklist,
            blacklist_given: given(&args.blacklist).is_some(),
        };
        if !output.write_old(&am, f, stem(f), "", &mut self.log)? {
            return Ok(Done::Exit(1));
        }
        self.log.blank();
        self.log.info(&format!("Results saved to: {csv}"));
        self.log.blank();
        self.log.info(&format!("Total parsing time: {} seconds", number_n(elapsed, 3)));
        self.log.blank();
        Ok(Done::Exit(0))
    }
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::FAILURE } else { ExitCode::SUCCESS };
        }
    };
    let start = Instant::now();
    let level = if args.trace {
        Level::Trace
    } else if args.debug {
        Level::Debug
    } else {
        Level::Info
    };
    let dt = if args.mp { PRECISE_TIME_FORMAT.to_string() } else { args.dt.clone() };
    let mut log = Logger::new(level, &dt).to_stdout();

    // one UTC time per run, for the CSV names and the console log
    let now = utc_now();
    let stamp = now.format("yyyyMMddHHmmss");
    let csv_for_log = args.csv.as_deref().filter(|c| !c.trim().is_empty());
    let console_log = csv_for_log.filter(|_| args.co).map(|c| Path::new(&full_path(c)).join(format!("{stamp}_AmcacheParser_{VERSION}_ConsoleLog.txt")));
    if let Some(path) = &console_log {
        // as the original's log file: it isn't an error if it can't be made
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = log.open_file(path);
    }

    let Some(file) = given(&args.file) else {
        return help_and_warning(&mut log, "-f is required. Exiting");
    };
    let Some(csv) = given(&args.csv) else {
        return help_and_warning(&mut log, "--csv is required. Exiting");
    };
    if !Path::new(file).exists() {
        log.error(&format!("{file} not found. Exiting"));
        log.blank();
        return ExitCode::FAILURE;
    }

    log.info(&format!("AmcacheParser (Rust) version {VERSION}"));
    log.blank();
    let command_line: Vec<String> = std::env::args().skip(1).collect();
    log.info(&format!("Command line: {}", command_line.join(" ")));
    log.blank();
    if let Some(path) = &console_log {
        log.info(&format!("Console log: {}", path.display()));
        log.blank();
    }

    let f = full_path(file);
    // from Windows 11 26H1 on, Inventory*.db databases next to Amcache.hve have what was in its Root keys. -f can also
    // be that folder, or one of the databases
    let database_directory = if Path::new(&f).is_dir() {
        f.clone()
    } else {
        Path::new(&f).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
    };
    let databases = has_databases(&database_directory);
    let hive_given = Path::new(&f).is_file() && !f.to_ascii_lowercase().ends_with(".db");

    let mut found = Vec::new();
    if hive_given {
        found.push(format!("registry hive ({})", base_name(&f)));
    }
    if databases {
        found.push(format!("SQLite databases ({} .db files)", n0(database_files(&database_directory).len() as u64)));
    }
    log.info(&format!("Amcache data found: {}", if found.is_empty() { "none".to_string() } else { found.join(" and ") }));
    log.blank();

    // the databases are read from copies, made in --temp or Temp next to this program
    let temp = if databases {
        match prepare_temp(given(&args.temp)) {
            Ok(t) => Some(t),
            Err(error) => {
                log.error(&format!("The folder for the temporary copies of the databases can't be written to ({error}). Give one with --temp. Exiting"));
                log.blank();
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let mut run = Run { args: &args, log, start };
    match run.work(&f, csv, &stamp, &dt, &database_directory, databases, hive_given, temp.as_ref()) {
        Ok(Done::Exit(code)) => ExitCode::from(code),
        Err(e) => {
            if !e.message.contains("Sequence numbers do not match and transaction logs were not found in the same directory as the hive. Abort") {
                run.log.error(&format!("There was an error: {}", e.message));
                run.log.blank();
                run.log.error(&format!("Please send {f} to saericzimmerman@gmail.com in order to fix the issue"));
            }
            // a damaged hive is not the tool's fault (0); access, IO, output or a dirty hive without its logs is (1)
            if e.could_not_process { ExitCode::FAILURE } else { ExitCode::SUCCESS }
        }
    }
}
