//! Plugins for the system and its devices: AppCompatCache, BamDam, Bluetooth, DeviceClasses, DsrmAdminLogonBehaviour,
//! ETW, ProfileList, VolumeInfoCache, WindowsPortableDevices.

use std::sync::OnceLock;

use ez_common::Timestamp;
use ez_common::net::{self, NetResult};
use fancy_regex::Regex;
use registry_ez::cells::{en_us_date, filetime};
use registry_ez::hive::upper;
use registry_ez::{Hive, KeyId};

use crate::helpers::{
    NO_MATCH, OUT_OF_BOUNDS, data, last_write, path, per_subkey, row, s, subkey, subkeys, text, time, to_int64, try_parse_i32, value,
    values,
};
use crate::Output;

const MULTIPLE: &str = "Multiple";

pub fn app_compat_cache(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    const VALUE_NAME: &str = "AppCompatCache";
    let v = value(hive, key, VALUE_NAME)?.ok_or(NO_MATCH)?;
    // ControlSet001: 1. Digits other than ASCII ones, or too many, leave -1
    let control_set = hive.keys[key]
        .path
        .split('\\')
        .find(|part| part.contains("ControlSet"))
        .and_then(|part| part.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
        .unwrap_or(-1);
    let environment = hive.keys[key].parent.and_then(|parent| {
        subkeys(hive, parent).iter().copied().find(|&k| upper(hive.key_name(k)) == "ENVIRONMENT")
    });
    let architecture = match environment {
        Some(e) => text(hive, e, "PROCESSOR_ARCHITECTURE")?,
        None => None,
    };
    let is32 = architecture.as_deref() == Some("x86");
    let raw = hive.value_raw(v)?;
    let mut messages = Vec::new();
    let mut observer = |level, message: &str| messages.push((level, message.to_string()));
    let cache = appcompatcache_ez::AppCompatCache::from_bytes(&raw, control_set, is32, &mut observer);
    out.messages.append(&mut messages);
    let cache = match cache {
        Ok(c) => c,
        Err(e) => {
            out.errors.push(format!("Error processing AppCompatCache: {}", e.message));
            return Ok(());
        }
    };
    for c in &cache.caches {
        out.errors.extend(c.parse_errors.iter().cloned());
        for entry in c.entries.iter().chain(&c.slack_entries) {
            let executed = entry.executed.name();
            let modified = entry.last_modified_time_utc;
            let slack = if entry.from_slack { ", from slack" } else { "" };
            out.rows.push(row(
                vec![
                    ("CacheEntryPosition", entry.cache_entry_position.into()),
                    ("ProgramName", entry.path.as_str().into()),
                    ("ModifiedTime", modified.into()),
                    ("Executed", executed.into()),
                    ("FromSlack", entry.from_slack.into()),
                ],
                Some(path(hive, key)),
                Some(VALUE_NAME.into()),
                entry.path.clone(),
                Some(format!("Modified: {}", time(modified))),
                Some(format!("Position: {}, Executed: {executed}{slack}", entry.cache_entry_position)),
            ));
        }
    }
    Ok(())
}

pub fn bam_dam(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &v in values(hive, key) {
        let name = hive.vks[v].name()?.to_string();
        if name == "Version" || name == "SequenceNumber" {
            continue;
        }
        let executed = hive.value_raw(v).and_then(|raw| net::i64_at(&raw, 0)).and_then(filetime);
        match executed {
            Ok(executed) => {
                let data1 = format!("Program: {name}");
                out.rows.push(row(
                    vec![("Program", name.as_str().into()), ("ExecutionTime", executed.into())],
                    Some(path(hive, key)),
                    Some(name),
                    data1,
                    Some(format!("Execution time: {}", time(Some(executed)))),
                    None,
                ));
            }
            Err(e) => out.errors.push(format!("Value name: {name}, message: {e}")),
        }
    }
    Ok(())
}

fn bluetooth_values(hive: &Hive, key: KeyId, origin: &str) -> NetResult<Option<crate::ValuesOut>> {
    let Some(name) = value(hive, key, "Name")? else { return Ok(None) };
    let last_seen: Option<Timestamp> = match value(hive, key, "LastSeen")? {
        Some(v) => Some(filetime(net::u64_at(&hive.value_raw(v)?, 0)? as i64)?),
        None => None,
    };
    let name = net::cp1252(&hive.value_raw(name)?);
    let data1 = format!("Name: {name}");
    Ok(Some(row(
        vec![("Name", name.into()), ("Address", origin.into()), ("LastSeen", last_seen.into())],
        Some(path(hive, key)),
        Some("Name/LastSeen".into()),
        data1,
        Some(format!("Last seen: {}", time(last_seen))),
        Some(format!("Address: {origin}")),
    )))
}

pub fn bluetooth(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        for &sk in subkeys(hive, key) {
            if subkeys(hive, sk).is_empty() {
                continue;
            }
            let origin = hive.key_name(sk);
            out.rows.extend(bluetooth_values(hive, sk, origin)?);
            for &inner in subkeys(hive, sk) {
                if subkeys(hive, inner).is_empty() {
                    continue;
                }
                out.rows.extend(bluetooth_values(hive, inner, origin)?);
            }
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing Bluetooth Devices key: {e}"));
    }
    Ok(())
}

/// The class GUIDs DeviceClasses reads, in upper case
const DEVICE_GUIDS: [&str; 5] = [
    "{10497B1B-BA51-44E5-8318-A65C837B6661}",
    "{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}",
    "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}",
    "{6AC27878-A6FA-4155-BA85-F98F491D4F33}",
    "{A5DCBF10-6530-11D2-901F-00C04FB951ED}",
];

/// The text after the first `##` or (which wins) `??`
fn after_marker(name: &str) -> Option<&str> {
    let mut found = None;
    for marker in ["##", "??"] {
        if name.contains(marker) {
            found = name.split(marker).nth(1);
        }
    }
    found
}

fn device_class(hive: &Hive, sk: KeyId, guid_folder: &str) -> NetResult<crate::ValuesOut> {
    let filter = hive.key_name(sk).replace("##?#", "");
    let parts: Vec<&str> = filter.split('#').collect();
    let device_type = *parts.first().ok_or(OUT_OF_BOUNDS)?;
    let mut name = *parts.get(1).ok_or(OUT_OF_BOUNDS)?;
    let mut serial = *parts.get(2).ok_or(OUT_OF_BOUNDS)?;
    let ts = last_write(hive, sk)?;
    if let Some(rest) = after_marker(&filter) {
        let result: Vec<&str> = rest.split('#').collect();
        name = result.get(1).ok_or(OUT_OF_BOUNDS)?;
        serial = result.get(2).ok_or(OUT_OF_BOUNDS)?;
    }
    Ok(row(
        vec![
            ("Timestamp", ts.into()),
            ("GuidFolder", guid_folder.into()),
            ("Type", device_type.into()),
            ("Name", name.into()),
            ("SerialNumber", serial.into()),
        ],
        Some(path(hive, sk)),
        Some(MULTIPLE.into()),
        format!("Type: {device_type} Name: {name} SerialNumber: {serial}"),
        Some(format!("Timestamp: {}", time(Some(ts)))),
        Some(String::new()),
    ))
}

pub fn device_classes(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &class in subkeys(hive, key) {
        let folder = hive.key_name(class);
        if !DEVICE_GUIDS.contains(&upper(folder).as_str()) {
            continue;
        }
        for &sk in subkeys(hive, class) {
            match device_class(hive, sk, folder) {
                Ok(r) => out.rows.push(r),
                Err(e) => {
                    // what's left of this class is skipped, the next class is read
                    out.errors.push(format!("Error processing DeviceClasses key: {e}"));
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn dsrm(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &v in values(hive, key) {
        let name = hive.vks[v].name()?.to_string();
        let upper_name = upper(&name);
        if upper_name != "DSRMADMINLOGONBEHAVIOR" && upper_name != "DSRMADMINLOGONBEHAVIOUR" {
            continue;
        }
        let value_data = data(hive, v)?;
        let persistence = match try_parse_i32(&value_data) {
            Some(n) => n == 1 || n == 2,
            None => {
                out.errors.push(format!(
                    "Error: Could not parse '{name}' value data '{value_data}' to an integer in key '{}'.",
                    hive.keys[key].path
                ));
                false
            }
        };
        let last_written = last_write(hive, key)?;
        let data1 = format!("Value: {value_data}");
        out.rows.push(row(
            vec![
                ("ValueName", name.as_str().into()),
                ("ValueData", value_data.into()),
                ("LastWriteTime", last_written.into()),
                ("PersistenceDetection", persistence.into()),
            ],
            Some(path(hive, key)),
            Some(name),
            data1,
            Some(format!("Last write: {}", last_written.format("yyyy-MM-dd HH:mm:ss"))),
            Some(
                if persistence {
                    "Potential Persistence: DsrmAdminLogonBehavior value found (1 or 2)"
                } else {
                    "DsrmAdminLogonBehavior value found"
                }
                .to_string(),
            ),
        ));
    }
    Ok(())
}

/// RegistryKey.GetValue(name)?.ToString() ?? "": any case
fn get_value(hive: &Hive, key: KeyId, name: &str) -> NetResult<String> {
    let want = upper(name);
    for &v in values(hive, key) {
        if upper(hive.vks[v].name()?) == want {
            return data(hive, v);
        }
    }
    Ok(String::new())
}

pub fn etw(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &sk in subkeys(hive, key) {
        let one = || -> NetResult<crate::ValuesOut> {
            let enabled = get_value(hive, sk, "Enabled")?;
            let enable_property = get_value(hive, sk, "EnableProperty")?;
            let written = en_us_date(last_write(hive, sk)?);
            let guid = hive.key_name(sk).to_string();
            let provider = guidmapping_ez::description_or_unmapped(&guid);
            let data1 = format!("Provider: {provider}");
            let data2 = format!("Enabled: {enabled}");
            let data3 = format!("EnabledProperty: {enable_property}");
            Ok(row(
                vec![
                    ("LastWriteTimestamp", written.into()),
                    ("Guid", guid.into()),
                    ("Provider", provider.into()),
                    ("Enabled", enabled.into()),
                    ("EnabledProperty", enable_property.into()),
                ],
                Some(path(hive, sk)),
                Some("Provider".into()),
                data1,
                Some(data2),
                Some(data3),
            ))
        };
        match one() {
            Ok(r) => out.rows.push(r),
            Err(e) => out.errors.push(e),
        }
    }
    Ok(())
}

/// GetDateTime: the two halves in hexadecimal, one after the other (the low half isn't padded, as in the original)
fn high_low(high: Option<String>, low: Option<String>) -> NetResult<Option<Timestamp>> {
    let (Some(high), Some(low)) = (high, low) else { return Ok(None) };
    let hex = format!("{:X}{:X}", to_int64(Some(&high))?, to_int64(Some(&low))?);
    let value = u64::from_str_radix(&hex, 16).map_err(|_| "Value was either too large or too small for a UInt64.".to_string())?;
    filetime(value as i64).map(Some)
}

pub fn profile_list(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing ProfileList key", |sk| {
        let key_name = hive.key_name(sk).to_string();
        let image_path = text(hive, sk, "ProfileImagePath")?;
        let load_high = text(hive, sk, "LocalProfileLoadTimeHigh")?;
        let load_low = text(hive, sk, "LocalProfileLoadTimeLow")?;
        let unload_high = text(hive, sk, "LocalProfileUnloadTimeHigh")?;
        let unload_low = text(hive, sk, "LocalProfileUnloadTimeLow")?;
        let ts = last_write(hive, sk)?;
        let load = high_low(load_high, load_low)?;
        let unload = high_low(unload_high, unload_low)?;
        let data1 = format!("KeyName: {key_name}");
        let data3 = format!("ProfileImagePath: {}", s(&image_path));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("KeyName", key_name.into()),
                ("ProfileImagePath", image_path.into()),
                ("LastLogonTime", load.into()),
                ("LastLogoffTime", unload.into()),
            ],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(format!("Timestamp: {}", time(Some(ts)))),
            Some(data3),
        )))
    });
    Ok(())
}

pub fn volume_info_cache(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing VolumeInfoCache key", |sk| {
        let drive_name = hive.key_name(sk).to_string();
        let label = text(hive, sk, "VolumeLabel")?;
        let drive_type = text(hive, sk, "DriveType")?.map(|d| {
            match d.as_str() {
                "0" => "Unknown",
                "1" => "NoRootDirectory",
                "2" => "Removable",
                "3" => "Fixed",
                "4" => "Network",
                "5" => "CDROM",
                "6" => "RAM",
                other => other,
            }
            .to_string()
        });
        let ts = last_write(hive, sk)?;
        let data1 = format!("DriveName: {drive_name} VolumeLabel: {} DriveType: {}", s(&label), s(&drive_type));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("DriveName", drive_name.into()),
                ("VolumeLabel", label.into()),
                ("DriveType", drive_type.into()),
            ],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(format!("Timestamp: {}", time(Some(ts)))),
            Some(String::new()),
        )))
    });
    Ok(())
}

fn device_guid(name: &str) -> Option<String> {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = REGEX.get_or_init(|| {
        Regex::new(r"[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]").expect("valid")
    });
    regex.find(name).ok().flatten().map(|m| m.as_str().to_string())
}

pub fn portable_devices(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let Some(devices) = subkey(hive, key, "Devices") else { return Ok(()) };
    per_subkey(hive, devices, out, "Error processing USB key", |sk| {
        let key_name = hive.key_name(sk);
        let friendly = text(hive, sk, "FriendlyName")?;
        let (mut device, mut serial): (Option<String>, Option<String>) = (None, None);
        if let Some(name) = after_marker(key_name) {
            let result: Vec<&str> = name.split('#').collect();
            device = Some(result.get(1).ok_or(OUT_OF_BOUNDS)?.to_string());
            serial = Some(result.get(2).ok_or(OUT_OF_BOUNDS)?.to_string());
        }
        let guid = device_guid(key_name);
        let ts = last_write(hive, sk)?;
        let data1 = format!("Device: {} SerialNumber: {} Guid: {}", s(&device), s(&serial), s(&guid));
        let data2 = format!("FriendlyName: {}", s(&friendly));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("Device", device.into()),
                ("SerialNumber", serial.into()),
                ("Guid", guid.into()),
                ("FriendlyName", friendly.into()),
            ],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(data2),
            Some(format!("Timestamp: {}", time(Some(ts)))),
        )))
    });
    Ok(())
}
