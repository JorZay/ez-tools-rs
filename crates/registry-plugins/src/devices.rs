//! Plugins for the machine (SYSTEM, SOFTWARE, SAM, Syscache): devices, services, networks and more.

use ez_common::Timestamp;
use ez_common::net::{self, NetResult};
use registry_ez::cells::filetime;
use registry_ez::hive::upper;
use registry_ez::{Hive, KeyId, VkId};

use crate::helpers::{NO_MATCH, OUT_OF_BOUNDS, byte_at, data, hex_byte, last_write, parse_i32, parse_i64, path, row, subkey, subkeys, text, time, unicode_at, value, values};
use crate::{Output, ValuesOut};

const PROPERTIES_NAME: &str = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}";
const PROPERTIES_TIME: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";

fn get_data(hive: &Hive, serial: KeyId, guid: &str, number: &str) -> NetResult<Option<Vec<u8>>> {
    let found = subkey(hive, serial, "Properties").and_then(|k| subkey(hive, k, guid)).and_then(|k| subkey(hive, k, number));
    let Some(found) = found else { return Ok(None) };
    match value(hive, found, "(default)")? {
        Some(v) => hive.value_raw(v).map(Some),
        None => Ok(None),
    }
}

/// GetUTC: a FILETIME of exactly 8 bytes
fn get_utc(raw: Option<&[u8]>) -> NetResult<Option<Timestamp>> {
    match raw {
        Some(raw) if raw.len() == 8 => Ok(Some(filetime(net::i64_at(raw, 0)?)?)),
        _ => Ok(None),
    }
}

struct DeviceTimes {
    installed: Option<Timestamp>,
    first_installed: Option<Timestamp>,
    last_connected: Option<Timestamp>,
    last_removed: Option<Timestamp>,
}

fn device_times(hive: &Hive, serial: KeyId) -> NetResult<DeviceTimes> {
    let time_of = |number: &str| -> NetResult<Option<Timestamp>> { get_utc(get_data(hive, serial, PROPERTIES_TIME, number)?.as_deref()) };
    Ok(DeviceTimes { installed: time_of("0064")?, first_installed: time_of("0065")?, last_connected: time_of("0066")?, last_removed: time_of("0067")? })
}

/// SplitData: what follows the last `;`
fn split_data(text: Option<String>) -> Option<String> {
    text.map(|t| t.rsplit(';').next().unwrap_or_default().to_string())
}

fn times_text(t: &DeviceTimes, between: &str) -> String {
    format!(
        "Installed: {}{between}FirstInstalled: {}{between}LastConnected: {}{between}LastRemoved: {}",
        time(t.installed),
        time(t.first_installed),
        time(t.last_connected),
        time(t.last_removed)
    )
}

pub fn usb(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &device in subkeys(hive, key) {
        let read = |out: &mut Output| -> NetResult<()> {
            let key_name = hive.key_name(device);
            for &sub in subkeys(hive, device) {
                let serial = hive.key_name(sub);
                let parent = text(hive, sub, "ParentIdPrefix")?;
                let service = text(hive, sub, "Service")?;
                let description = split_data(text(hive, sub, "DeviceDesc")?);
                let friendly = split_data(text(hive, sub, "FriendlyName")?);
                let location = text(hive, sub, "LocationInformation")?;
                let name = get_data(hive, sub, PROPERTIES_NAME, "0004")?.map(|raw| net::utf16(&raw));
                let t = device_times(hive, sub)?;
                let s = |v: &Option<String>| v.clone().unwrap_or_default();
                out.rows.push(row(
                    vec![
                        ("KeyName", key_name.into()),
                        ("SerialNumber", serial.into()),
                        ("ParentidPrefix", parent.clone().into()),
                        ("Service", service.clone().into()),
                        ("DeviceDesc", description.clone().into()),
                        ("FriendlyName", friendly.clone().into()),
                        ("DeviceName", name.clone().into()),
                        ("LocationInformation", location.clone().into()),
                        ("Installed", t.installed.into()),
                        ("FirstInstalled", t.first_installed.into()),
                        ("LastConnected", t.last_connected.into()),
                        ("LastRemoved", t.last_removed.into()),
                    ],
                    Some(path(hive, sub)),
                    Some("Multiple".to_string()),
                    format!("KeyName: {key_name} SerialNumber: {serial} ParentIdPrefix: {} Service: {}", s(&parent), s(&service)),
                    Some(format!("DeviceDesc: {} FriendlyName: {} DeviceName: {} Location Information: {}", s(&description), s(&friendly), s(&name), s(&location))),
                    Some(times_text(&t, " ")),
                ));
            }
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing USB key: {e}"));
        }
    }
    Ok(())
}

fn disk_details(hive: &Hive, device: KeyId) -> NetResult<(String, Option<Timestamp>)> {
    let first = *subkeys(hive, device).first().ok_or("Sequence contains no elements")?;
    let mut disk_id = String::new();
    let mut initial = None;
    if let Some(parameters) = subkey(hive, first, "Device Parameters") {
        if let Some(v) = subkey(hive, parameters, "Partmgr").map(|k| value(hive, k, "DiskId")).transpose()?.flatten() {
            disk_id = data(hive, v)?;
        }
        if let Some(v) = subkey(hive, parameters, "Storport").map(|k| value(hive, k, "InitialTimestamp")).transpose()?.flatten() {
            initial = get_utc(Some(&hive.value_raw(v)?))?;
        }
    }
    Ok((disk_id, initial))
}

pub fn usbstor(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &device in subkeys(hive, key) {
        if subkeys(hive, device).is_empty() {
            continue;
        }
        let read = |out: &mut Output| -> NetResult<()> {
            let words: Vec<&str> = hive.key_name(device).split('&').collect();
            if words.len() != 4 {
                return Ok(());
            }
            for &sub in subkeys(hive, device) {
                let serial = hive.key_name(sub);
                let name = get_data(hive, sub, PROPERTIES_NAME, "0004")?.map_or_else(String::new, |raw| net::utf16(&raw));
                let t = device_times(hive, sub)?;
                let stamp = last_write(hive, device)?;
                let (disk_id, _) = disk_details(hive, device)?;
                out.rows.push(row(
                    vec![
                        ("Timestamp", stamp.into()),
                        ("Manufacturer", words[1].into()),
                        ("Title", words[2].into()),
                        ("Version", words[3].into()),
                        ("SerialNumber", serial.into()),
                        ("DeviceName", name.as_str().into()),
                        ("DiskId", disk_id.as_str().into()),
                        ("Installed", t.installed.into()),
                        ("FirstInstalled", t.first_installed.into()),
                        ("LastConnected", t.last_connected.into()),
                        ("LastRemoved", t.last_removed.into()),
                    ],
                    Some(path(hive, device)),
                    Some("Multiple".to_string()),
                    format!("Manufacturer: {} Title: {} Version: {} SerialNumber: {serial} DeviceName: {name} DiskId: {disk_id}", words[1], words[2], words[3]),
                    Some(format!("Timestamp: {}", time(Some(stamp)))),
                    Some(times_text(&t, "")),
                ));
            }
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing USBSTOR key: {e}"));
        }
    }
    Ok(())
}

pub fn scsi(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &device in subkeys(hive, key) {
        if subkeys(hive, device).is_empty() {
            continue;
        }
        let read = |out: &mut Output| -> NetResult<()> {
            let words: Vec<&str> = hive.key_name(device).split('&').collect();
            if words.len() != 3 {
                return Ok(());
            }
            for &sub in subkeys(hive, device) {
                let serial = hive.key_name(sub);
                let name = get_data(hive, sub, PROPERTIES_NAME, "0004")?.map_or_else(String::new, |raw| net::utf16(&raw));
                let t = device_times(hive, sub)?;
                let stamp = last_write(hive, device)?;
                let (disk_id, initial) = disk_details(hive, device)?;
                out.rows.push(row(
                    vec![
                        ("Timestamp", stamp.into()),
                        ("Manufacturer", words[1].into()),
                        ("Title", words[2].into()),
                        ("SerialNumber", serial.into()),
                        ("DeviceName", name.as_str().into()),
                        ("DiskId", disk_id.as_str().into()),
                        ("InitialTimestamp", initial.into()),
                        ("Installed", t.installed.into()),
                        ("FirstInstalled", t.first_installed.into()),
                        ("LastConnected", t.last_connected.into()),
                        ("LastRemoved", t.last_removed.into()),
                    ],
                    Some(path(hive, device)),
                    Some("Multiple".to_string()),
                    format!("Manufacturer: {} Title: {} SerialNumber: {serial} DeviceName: {name} DiskId: {disk_id}", words[1], words[2]),
                    Some(format!("Timestamp: {} InitialTimestamp: {}", time(Some(stamp)), time(initial))),
                    Some(times_text(&t, "")),
                ));
            }
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing SCSI key: {e}"));
        }
    }
    Ok(())
}

pub fn swd(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &group in subkeys(hive, key) {
        let read = |out: &mut Output| -> NetResult<()> {
            let kind = hive.key_name(group);
            for &sub in subkeys(hive, group) {
                let key_name = hive.key_name(sub);
                let service = text(hive, sub, "Service")?;
                let description = split_data(text(hive, sub, "DeviceDesc")?);
                let friendly = split_data(text(hive, sub, "FriendlyName")?);
                let t = device_times(hive, sub)?;
                let s = |v: &Option<String>| v.clone().unwrap_or_default();
                out.rows.push(row(
                    vec![
                        ("Type", kind.into()),
                        ("KeyName", key_name.into()),
                        ("Service", service.clone().into()),
                        ("DeviceDesc", description.clone().into()),
                        ("FriendlyName", friendly.clone().into()),
                        ("Installed", t.installed.into()),
                        ("FirstInstalled", t.first_installed.into()),
                        ("LastConnected", t.last_connected.into()),
                        ("LastRemoved", t.last_removed.into()),
                    ],
                    Some(path(hive, sub)),
                    Some("Multiple".to_string()),
                    format!("Type: {kind} KeyName: {key_name} Service: {}", s(&service)),
                    Some(format!("DeviceDesc: {} FriendlyName: {}", s(&description), s(&friendly))),
                    Some(times_text(&t, " ")),
                ));
            }
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing SWD key: {e}"));
        }
    }
    Ok(())
}

/// Values.FirstOrDefault(t => t.ValueName.Equals(name, OrdinalIgnoreCase))
fn value_ignoring_case(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<VkId>> {
    let want = upper(name);
    for &v in values(hive, key) {
        if upper(hive.vks[v].name()?) == want {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

fn start_mode_name(mode: i32) -> String {
    match mode {
        0 => "Boot".to_string(),
        1 => "System".to_string(),
        2 => "Automatic".to_string(),
        3 => "Manual".to_string(),
        4 => "Disabled".to_string(),
        other => other.to_string(),
    }
}

/// A [Flags] enum's ToString: the names, or the number when a bit has no name
fn service_type_name(kind: i32) -> String {
    const NAMES: &[(i32, &str)] = &[(1, "KernelDriver"), (2, "FileSystemDriver"), (4, "Adapter"), (8, "RecognizerDriver"), (16, "Win32OwnProcess"), (32, "Win32ShareProcess"), (256, "InteractiveProcess")];
    let mut left = kind;
    let mut names = Vec::new();
    for (bit, name) in NAMES {
        if left & bit != 0 {
            names.push(*name);
            left &= !bit;
        }
    }
    if left != 0 || names.is_empty() { kind.to_string() } else { names.join(", ") }
}

pub fn services(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let read = |out: &mut Output| -> NetResult<()> {
        for &sub in subkeys(hive, key) {
            let name_write = last_write(hive, sub)?;
            let name = hive.key_name(sub);
            let optional = |value_name: &str| -> NetResult<String> {
                match value_ignoring_case(hive, sub, value_name)? {
                    Some(v) => data(hive, v),
                    None => Ok(String::new()),
                }
            };
            let description = optional("Description")?;
            let display = optional("DisplayName")?;
            let dll_key = optional("ServiceDll")?;
            let group = text(hive, sub, "Group")?.unwrap_or_default();
            let image = optional("ImagePath")?;
            let privileges = optional("RequiredPrivileges")?;
            let kind = match value_ignoring_case(hive, sub, "Type")? {
                Some(v) => parse_i32(&data(hive, v)?)?,
                None => 4,
            };
            let start = match value_ignoring_case(hive, sub, "Start")? {
                Some(v) => parse_i32(&data(hive, v)?)?,
                None => 4,
            };
            let parameters = subkeys(hive, sub).iter().copied().find(|&k| upper(hive.key_name(k)) == "PARAMETERS");
            let parameters_write = parameters.map(|k| last_write(hive, k)).transpose()?;
            let parameter_dll = match parameters {
                Some(k) => match value_ignoring_case(hive, k, "SERVICEDLL")? {
                    Some(v) => data(hive, v)?,
                    None => String::new(),
                },
                None => String::new(),
            };
            let mut dll = String::new();
            if !dll_key.is_empty() {
                dll = format!("{} ServiceDll: {dll_key} / Parameter ServiceDll: ", hive.key_name(key));
            }
            dll.push_str(&parameter_dll);
            out.rows.push(row(
                vec![
                    ("Name", name.into()),
                    ("Description", description.as_str().into()),
                    ("DisplayName", display.as_str().into()),
                    ("StartMode", start_mode_name(start).into()),
                    ("ServiceType", crate::Cell::Flags(service_type_name(kind), kind)),
                    ("NameKeyLastWrite", name_write.into()),
                    ("ParametersKeyLastWrite", parameters_write.into()),
                    ("Group", group.into()),
                    ("ImagePath", image.as_str().into()),
                    ("ServiceDLL", dll.as_str().into()),
                    ("RequiredPrivileges", privileges.into()),
                ],
                Some(path(hive, key)),
                Some("None".to_string()),
                format!("Name: {name} Desc: {description}"),
                Some(format!("Name last write: {}, Parameters last write: {}", time(Some(name_write)), time(parameters_write))),
                Some(format!("Image path: {image} ServiceDLL: {dll}")),
            ));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing Services key: {e}"));
    }
    Ok(())
}

fn dhcp_values(hive: &Hive, key: KeyId, origin: &str) -> NetResult<Option<ValuesOut>> {
    let Some(v) = value(hive, key, "DhcpNetworkHint")? else { return Ok(None) };
    let mut reversed: Vec<u16> = data(hive, v)?.encode_utf16().collect();
    reversed.reverse();
    let mut bytes = Vec::with_capacity(reversed.len() / 2);
    for pair in reversed.chunks_exact(2) {
        bytes.push(hex_byte(pair)?);
    }
    let hint: String = net::cp1252(&bytes).chars().rev().collect();
    let optional = |name: &str| -> NetResult<String> { Ok(text(hive, key, name)?.unwrap_or_default()) };
    let gateway = optional("DhcpDefaultGateway")?;
    let address = optional("DhcpIPAddress")?;
    let server = optional("DhcpServer")?;
    // DateTimeOffset.Now, without the value
    let lease = |name: &str| -> NetResult<Timestamp> {
        match value(hive, key, name)? {
            Some(v) => Ok(Timestamp(621_355_968_000_000_000 + i64::from(parse_i32(&data(hive, v)?)?) * 10_000_000)),
            None => Ok(Timestamp::now()),
        }
    };
    let obtained = lease("LeaseObtainedTime")?;
    let expires = lease("LeaseTerminatesTime")?;
    let domain = optional("DhcpDomain")?;
    let mut r = row(
        vec![
            ("NetworkHint", hint.into()),
            ("DHCPAddress", address.into()),
            ("DHCPServer", server.into()),
            ("DHCPDomain", domain.into()),
            ("LeaseObtained", obtained.into()),
            ("LeaseExpires", expires.into()),
            ("DefaultGateway", gateway.into()),
            ("Interface", origin.into()),
            ("InterfaceSubkey", hive.key_name(key).into()),
        ],
        Some(path(hive, key)),
        Some("Multiple".to_string()),
        String::new(),
        None,
        None,
    );
    r.data1_null = true;
    Ok(Some(r))
}

pub fn dhcp_network_hint(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let read = |out: &mut Output| -> NetResult<()> {
        for &sub in subkeys(hive, key) {
            if subkeys(hive, sub).is_empty() {
                continue;
            }
            let origin = hive.key_name(sub);
            out.rows.extend(dhcp_values(hive, sub, origin)?);
            for &inner in subkeys(hive, sub) {
                out.rows.extend(dhcp_values(hive, inner, origin)?);
            }
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing Interfaces key: {e}"));
    }
    Ok(())
}

fn protocol_name(number: &str) -> &str {
    match number {
        "1" => "ICMP",
        "2" => "IGMP",
        "3" => "GGP",
        "4" => "IPv4",
        "5" => "ST",
        "6" => "TCP",
        "17" => "UDP",
        "18" => "MUX",
        "27" => "RDP",
        "41" => "IPv6",
        "47" => "GRE",
        "58" => "IPv6-ICMP",
        "92" => "MTP",
        "121" => "SMP",
        "143" => "Ethernet",
        other => other,
    }
}

pub fn firewall_rules(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &v in values(hive, key) {
        let read = |out: &mut Output| -> NetResult<()> {
            let rules = data(hive, v)?;
            let field = |name: &str| -> String {
                let marker = format!("{name}=");
                let mut found: Vec<&str> = Vec::new();
                for part in rules.split('|') {
                    if part.contains(&marker) {
                        let mut pieces = part.split('=');
                        let first = pieces.next().unwrap_or_default();
                        let second = pieces.next().unwrap_or_default();
                        found.push(if first == "Protocol" { protocol_name(second) } else { second });
                    }
                }
                found.join(",")
            };
            let (action, active, dir, protocol, lport, rport, name, desc, app) =
                (field("Action"), field("Active"), field("Dir"), field("Protocol"), field("LPort"), field("RPort"), field("Name"), field("Desc"), field("App"));
            out.rows.push(row(
                vec![
                    ("Action", action.as_str().into()),
                    ("Active", active.as_str().into()),
                    ("Dir", dir.as_str().into()),
                    ("Protocol", protocol.as_str().into()),
                    ("LPort", lport.as_str().into()),
                    ("RPort", rport.as_str().into()),
                    ("Name", name.as_str().into()),
                    ("Desc", desc.as_str().into()),
                    ("App", app.as_str().into()),
                ],
                Some(path(hive, key)),
                Some("Multiple".to_string()),
                format!("Action: {action} Active: {active}"),
                Some(format!("Dir: {dir} Protocol: {protocol} Name: {name}")),
                Some(format!("LPort: {lport} RPort: {rport} Desc: {desc} App: {app}")),
            ));
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing FirewallRules key: {e}"));
        }
    }
    Ok(())
}

/// GetDateFrom128Bit: a SYSTEMTIME, as the local time it is
fn date_from_128_bit(raw: &[u8]) -> NetResult<Timestamp> {
    let field = |i: i64| -> NetResult<i32> { Ok(i32::from(net::i16_at(raw, i)?)) };
    let (year, month, _, day, hour, minute, second, ms) = (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?, field(10)?, field(12)?, field(14)?);
    let bad = || "Year, Month, and Day parameters describe an un-representable DateTime.".to_string();
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) || day < 1 || day as u32 > ez_common::time::days_in_month(year, month as u32) {
        return Err(bad());
    }
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..60).contains(&second) || !(0..1000).contains(&ms) {
        return Err("Hour, Minute, and Second parameters describe an un-representable DateTime.".to_string());
    }
    Timestamp::from_parts(year, month as u32, day as u32, hour as u32, minute as u32, second as u32, ms as u32 * 10_000).ok_or_else(bad)
}

struct Network {
    name: String,
    first_network: String,
    kind: String,
    first_connect: Timestamp,
    last_connected: Timestamp,
    managed: bool,
    dns_suffix: String,
    gateway: String,
    profile: String,
    key_path: String,
}

fn network_kind(number: i32) -> String {
    match number {
        71 => "Wireless".to_string(),
        6 => "Wired".to_string(),
        23 => "WWAN".to_string(),
        n if n > 0 => n.to_string(),
        _ => "Unknown".to_string(),
    }
}

fn network_rows(networks: Vec<Network>, out: &mut Output) {
    for n in networks {
        let (first, last) = (n.first_connect, n.last_connected);
        out.rows.push(row(
            vec![
                ("FirstNetwork", n.first_network.as_str().into()),
                ("NetworkName", n.name.as_str().into()),
                ("NameType", n.kind.as_str().into()),
                ("FirstConnectLOCAL", first.into()),
                ("LastConnectedLOCAL", last.into()),
                ("Managed", n.managed.into()),
                ("DNSSuffix", n.dns_suffix.as_str().into()),
                ("GatewayMacAddress", n.gateway.as_str().into()),
                ("ProfileGUID", n.profile.as_str().into()),
            ],
            Some(n.key_path.clone()),
            Some("Multiple".to_string()),
            format!("Name: {} Type: {}", n.name, n.kind),
            Some(format!("First Connect LOCAL: {} Last Connect LOCAL: {}", time(Some(first)), time(Some(last)))),
            Some(format!("Gateway MAC: {}", n.gateway)),
        ));
    }
}

pub fn known_networks(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut networks: Vec<Network> = Vec::new();
    let Some(profiles) = subkey(hive, key, "Profiles") else {
        out.errors.push("'Profiles' key missing!' ".to_string());
        return Ok(());
    };
    let required = |k: KeyId, name: &str| -> NetResult<VkId> { value(hive, k, name)?.ok_or_else(|| NO_MATCH.to_string()) };
    for &sub in subkeys(hive, profiles) {
        let one = || -> NetResult<Network> {
            let raw_created = hive.value_raw(required(sub, "DateCreated")?)?;
            let last_value = required(sub, "DateLastConnected")?;
            let raw_last = hive.value_raw(last_value)?;
            let managed = data(hive, last_value)? == "0";
            let profile_name = data(hive, required(sub, "ProfileName")?)?;
            let name = if managed { String::new() } else { profile_name };
            let kind = parse_i32(&data(hive, required(sub, "NameType")?)?)?;
            Ok(Network {
                name,
                first_network: String::new(),
                kind: network_kind(kind),
                first_connect: date_from_128_bit(&raw_created)?,
                last_connected: date_from_128_bit(&raw_last)?,
                managed,
                dns_suffix: String::new(),
                gateway: String::new(),
                profile: hive.key_name(sub).to_string(),
                key_path: path(hive, sub),
            })
        };
        match one() {
            Ok(n) => networks.push(n),
            Err(e) => out.errors.push(format!("Error processing Profiles subkey '{}': {e}", hive.key_name(sub))),
        }
    }
    let Some(signatures) = subkey(hive, key, "Signatures") else {
        out.errors.push("'Signatures' key missing!' ".to_string());
        network_rows(networks, out);
        return Ok(());
    };
    for (kind, managed) in [("Unmanaged", false), ("Managed", true)] {
        let Some(group) = subkey(hive, signatures, kind) else {
            out.errors.push(format!("'{kind}' key missing!' "));
            network_rows(networks, out);
            return Ok(());
        };
        for &sub in subkeys(hive, group) {
            let one = || -> NetResult<(String, String, String, String)> {
                Ok((data(hive, required(sub, "DefaultGatewayMac")?)?, data(hive, required(sub, "DnsSuffix")?)?, data(hive, required(sub, "ProfileGuid")?)?, data(hive, required(sub, "FirstNetwork")?)?))
            };
            match one() {
                Ok((gateway, dns, profile, first)) => {
                    if let Some(n) = networks.iter_mut().find(|n| n.profile == profile) {
                        n.gateway = gateway;
                        n.dns_suffix = dns;
                        n.first_network = first;
                        n.managed = managed;
                    }
                }
                Err(e) => out.errors.push(format!("Error processing {kind} subkey '{}': {e}", hive.key_name(sub))),
            }
        }
    }
    network_rows(networks, out);
    Ok(())
}

/// The users of an alias
fn alias_users(raw: &[u8], count: i32) -> NetResult<String> {
    let mut result = Vec::new();
    let mut used = 0i32;
    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    for _ in 0..count {
        let offset = net::i32_at(raw, 0x28)?.wrapping_add(52).wrapping_add(used);
        let kind = net::i32_at(raw, i64::from(offset))?;
        let copy = |size: usize| -> NetResult<&[u8]> {
            let start = usize::try_from(offset).map_err(|_| "Non-negative number required. (Parameter 'sourceIndex')".to_string())?;
            raw.get(start..start + size).ok_or_else(|| "Source array was not long enough. Check the source index, length, and the array's lower bounds. (Parameter 'sourceArray')".to_string())
        };
        if kind == 0x101 {
            let b = copy(12)?;
            let authority = u32::from_le_bytes([b[7], b[6], b[5], b[4]]);
            result.push(format!("S-{}-{authority}-{}", b[0], le(&b[8..])));
            used = used.wrapping_add(12);
        } else if kind == 0x501 {
            let b = copy(28)?;
            let authority = u32::from_le_bytes([b[7], b[6], b[5], b[4]]);
            result.push(format!("S-{}-{authority}-{}-{}-{}-{}-{}", b[0], le(&b[8..]), le(&b[12..]), le(&b[16..]), le(&b[20..]), le(&b[24..])));
            used = used.wrapping_add(28);
        }
    }
    Ok(result.join(", "))
}

pub fn sam_builtin(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &sub in subkeys(hive, key) {
        let read = |out: &mut Output| -> NetResult<()> {
            let Some(v) = value(hive, sub, "C")? else { return Ok(()) };
            let raw = hive.value_raw(v)?;
            let at = |i: i64| net::i32_at(&raw, i);
            let (name_offset, name_length, comment_offset, comment_length) = (at(0x10)?, at(0x14)?, at(0x1c)?, at(0x20)?);
            let group = unicode_at(&raw, i64::from(name_offset.wrapping_add(0x34)), i64::from(name_length))?;
            let comment = unicode_at(&raw, i64::from(comment_offset.wrapping_add(0x34)), i64::from(comment_length))?;
            let users = alias_users(&raw, at(0x30)?)?;
            out.rows.push(row(
                vec![("GroupName", group.as_str().into()), ("Comment", comment.as_str().into()), ("Users", users.as_str().into())],
                Some(path(hive, key)),
                Some("Multiple".to_string()),
                format!("GroupName: {group}"),
                Some(format!("Comment: {comment}")),
                Some(format!("Users: {users}")),
            ));
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing SAMBuiltin: {e}"));
        }
    }
    Ok(())
}

pub fn syscache_object_table(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &sub in subkeys(hive, key) {
        let read = |out: &mut Output| -> NetResult<()> {
            let (mut object_id, mut lru, mut usn, mut usn_id) = (0i64, 0i64, 0i64, 0i64);
            let mut file_id = vec![0u8; 8];
            let (mut ae_file, mut ae_program) = (String::new(), String::new());
            for &v in values(hive, sub) {
                match hive.vks[v].name()? {
                    "_ObjectId_" => object_id = parse_i64(Some(&data(hive, v)?))?,
                    "_ObjectLru_" => lru = parse_i64(Some(&data(hive, v)?))?,
                    "_FileId_" => file_id = hive.value_raw(v)?,
                    "_Usn_" => usn = parse_i64(Some(&data(hive, v)?))?,
                    "_UsnJournalId_" => usn_id = parse_i64(Some(&data(hive, v)?))?,
                    "AeFileID" => ae_file = net::utf16(&hive.value_raw(v)?).trim_matches('\0').to_string(),
                    "AeProgramID" => ae_program = net::utf16(&hive.value_raw(v)?).trim_matches('\0').to_string(),
                    _ => {}
                }
            }
            let sequence = net::u16_at(&file_id, 6)?;
            let low = u64::from(net::u32_at(&file_id, 0)?);
            let high = u64::from(net::u16_at(&file_id, 4)?);
            let entry = low.wrapping_add(high.wrapping_mul(16_777_216)) as u32 as i32;
            let units: Vec<u16> = ae_file.encode_utf16().collect();
            let sha = if units.len() > 4 { registry_ez::hive::lower(&String::from_utf16_lossy(&units[4..])) } else { String::new() };
            let stamp = last_write(hive, sub)?;
            let full = path(hive, sub);
            let stripped = full.split_once('\\').map_or(full.as_str(), |(_, rest)| rest);
            let sequence = i32::from(sequence);
            out.rows.push(row(
                vec![
                    ("KeyPath", stripped.into()),
                    ("ObjectId", object_id.into()),
                    ("ObjectLru", lru.into()),
                    ("Usn", usn.into()),
                    ("UsnJournalId", usn_id.into()),
                    ("MftEntryNumber", entry.into()),
                    ("MftSequenceNumber", sequence.into()),
                    ("Sha1", sha.as_str().into()),
                    ("AeProgramId", ae_program.into()),
                    ("LastWriteTime", stamp.into()),
                ],
                Some(path(hive, key)),
                Some("None".to_string()),
                format!("MFT Entry/Seq: {entry}/{sequence}"),
                Some(format!("SHA-1: {sha}")),
                Some(format!("Last write: {}", time(Some(stamp)))),
            ));
            Ok(())
        };
        if let Err(e) = read(out) {
            out.errors.push(format!("Error processing Syscache ObjectTable entry in key {}: {e}", hive.key_name(sub)));
        }
    }
    Ok(())
}

pub fn time_zone(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut current = String::new();
    let mut read = |out: &mut Output| -> NetResult<()> {
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            current.clone_from(&name);
            let shown = match name.as_str() {
                "TimeZoneKeyName" | "StandardName" | "DaylightName" => data(hive, v)?,
                "Bias" | "StandardBias" | "DaylightBias" | "ActiveTimeBias" => net::i32_at(&hive.value_raw(v)?, 0)?.to_string(),
                "StandardStart" | "DaylightStart" => {
                    let raw = hive.value_raw(v)?;
                    let (month, week, hour, minute, second) = (byte_at(&raw, 2)?, byte_at(&raw, 4)?, byte_at(&raw, 6)?, byte_at(&raw, 8)?, byte_at(&raw, 10)?);
                    let ms = net::i16_at(&raw, 12)?;
                    let day = *raw.get(14).ok_or(OUT_OF_BOUNDS)?;
                    format!("Month {month}, week of month {week}, day of week {day}, Hours:Minutes:Seconds:Milliseconds {hour}:{minute}:{second}:{ms}")
                }
                _ => continue,
            };
            let original = data(hive, v)?;
            out.rows.push(row(
                vec![("ValueName", name.as_str().into()), ("ValueData", shown.as_str().into()), ("ValueDataRaw", original.as_str().into())],
                Some(path(hive, key)),
                Some(name.clone()),
                shown.clone(),
                Some(original.clone()),
                Some(String::new()),
            ));
        }
        Ok(())
    };
    if let Err(e) = read(out) {
        out.errors.push(format!("Error processing TimeZoneInformation value '{current}': {e}"));
    }
    Ok(())
}
