//! Plugins for networks and remote connections: NetworkAdapters, NetworkSettings, NetworkSetup2, TerminalServerClient.

use std::collections::HashMap;
use std::sync::OnceLock;

use ez_common::Timestamp;
use ez_common::net::{self, NetResult};
use fancy_regex::Regex;
use registry_ez::{Hive, KeyId};

use crate::helpers::{data, last_write, parse_i32, path, per_subkey, row, s, subkey, subkeys, text, time, utf16_len, value, values};
use crate::Output;

const MULTIPLE: &str = "Multiple";

/// `^00\d\d$` as .NET reads it: `$` also before a last line feed
fn adapter_name(name: &str) -> bool {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"^00\d\d\n?\z").expect("valid")).is_match(name).unwrap_or(false)
}

pub fn adapters(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing {4d36e972-e325-11ce-bfc1-08002be10318} key", |sk| {
        if !adapter_name(hive.key_name(sk)) {
            return Ok(None);
        }
        let description = text(hive, sk, "DriverDesc")?;
        let date = text(hive, sk, "DriverDate")?;
        let version = text(hive, sk, "DriverVersion")?;
        let instance = text(hive, sk, "DeviceInstanceID")?;
        let provider = text(hive, sk, "ProviderName")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!(
            "DriveName: {} DriverDate: {} DriverVersion: {} ProviderName: {}",
            s(&description),
            s(&date),
            s(&version),
            s(&provider)
        );
        let data2 = format!("DeviceInstanceid: {}", s(&instance));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("DriverDesc", description.into()),
                ("DriverDate", date.into()),
                ("DriverVersion", version.into()),
                ("ProviderName", provider.into()),
                ("DeviceInstanceid", instance.into()),
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

/// DateTimeOffset.FromUnixTimeSeconds(BitConverter.ToUInt32(value, 0)), when the value is there
fn lease(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<Timestamp>> {
    let Some(v) = value(hive, key, name)? else { return Ok(None) };
    let seconds = net::u32_at(&hive.value_raw(v)?, 0)? as i64;
    Ok(Some(Timestamp(621_355_968_000_000_000 + seconds * 10_000_000)))
}

pub fn settings(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing Interfaces key", |sk| {
        let ip = text(hive, sk, "IPAddress")?;
        let mask = text(hive, sk, "SubnetMask")?;
        let dhcp_mask = text(hive, sk, "DhcpSubnetMask")?;
        let dhcp_server = text(hive, sk, "DhcpServer")?;
        let dhcp_name_server = text(hive, sk, "DhcpNameServer")?;
        let dhcp_ip = text(hive, sk, "DhcpIPAddress")?;
        let dhcp_gateway = text(hive, sk, "DhcpDefaultGateway")?;
        let obtained = lease(hive, sk, "LeaseObtainedTime")?;
        let terminates = lease(hive, sk, "LeaseTerminatesTime")?;
        let enabled = text(hive, sk, "EnableDHCP")?.as_deref() == Some("1");
        let data1 = format!("IPAddress: {} SubnetMask: {}", s(&ip), s(&mask));
        let data2 = format!(
            "DHCPSubnetMask: {} DHCPServer: {} DHCPNameServer: {} DHCPIPAddress: {} DHCPDefaultGateway: {}",
            s(&dhcp_mask),
            s(&dhcp_server),
            s(&dhcp_name_server),
            s(&dhcp_ip),
            s(&dhcp_gateway)
        );
        let data3 = format!(
            "LeaseObtainedTime: {} LeaseTerminatesTime: {} EnabledDHCP: {}",
            time(obtained),
            time(terminates),
            if enabled { "True" } else { "False" }
        );
        Ok(Some(row(
            vec![
                ("IPAddress", ip.into()),
                ("SubnetMask", mask.into()),
                ("DHCPSubnetMask", dhcp_mask.into()),
                ("DHCPServer", dhcp_server.into()),
                ("DHCPNameServer", dhcp_name_server.into()),
                ("DHCPIPAddress", dhcp_ip.into()),
                ("DHCPDefaultGateway", dhcp_gateway.into()),
                ("LeaseObtainedTime", obtained.into()),
                ("LeaseTerminatesTime", terminates.into()),
                ("EnabledDHCP", enabled.into()),
            ],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(data2),
            Some(data3),
        )))
    });
    Ok(())
}

pub fn setup2(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let Some(interfaces) = subkey(hive, key, "Interfaces") else { return Ok(()) };
    per_subkey(hive, interfaces, out, "Error processing NetworkSetup2 key", |i| {
        let Some(kernel) = subkey(hive, i, "Kernel") else { return Ok(None) };
        let protocols = text(hive, kernel, "ProtocolList")?;
        let alias = text(hive, kernel, "IfAlias")?;
        let description = text(hive, kernel, "IfDescr")?;
        let if_type = text(hive, kernel, "IfType")?;
        let permanent = text(hive, kernel, "PermanentAddress")?;
        let current = text(hive, kernel, "CurrentAddress")?;
        let data1 = format!("ProtocolList: {} Alias: {}", s(&protocols), s(&alias));
        let data2 = format!("Description: {} Type: {}", s(&description), s(&if_type));
        let data3 = format!("PermanentAddress: {} CurrentAddress (Mac Address): {}", s(&permanent), s(&current));
        Ok(Some(row(
            vec![
                ("ProtocolList", protocols.into()),
                ("Alias", alias.into()),
                ("Description", description.into()),
                ("Type", if_type.into()),
                ("PermanentAddress", permanent.into()),
                ("CurrentAddress", current.into()),
            ],
            Some(path(hive, i)),
            Some(MULTIPLE.into()),
            data1,
            Some(data2),
            Some(data3),
        )))
    });
    Ok(())
}

pub fn terminal_server_client(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        let Some(default_key) = subkey(hive, key, "Default") else { return Ok(()) };
        let mut order: HashMap<String, i32> = HashMap::new();
        for &v in values(hive, default_key) {
            let value_name = hive.vks[v].name()?;
            let length = utf16_len(value_name);
            if length < 3 {
                // value_name.Remove(0, 3)
                return Err(format!("count ('3') must be less than or equal to '{length}'. (Parameter 'count')\nActual value was 3."));
            }
            let units: Vec<u16> = value_name.encode_utf16().skip(3).collect();
            let position = String::from_utf16_lossy(&units);
            let name = data(hive, v)?;
            let position = parse_i32(&position)?;
            if order.contains_key(&name) {
                return Err(format!("An item with the same key has already been added. Key: {name}"));
            }
            order.insert(name, position);
        }
        let Some(servers) = subkey(hive, key, "Servers") else { return Ok(()) };
        for &server in subkeys(hive, servers) {
            let host = hive.key_name(server).to_string();
            let mru = order.get(&host).copied().unwrap_or(-1);
            let hint = value(hive, server, "UsernameHint")?;
            let username = match hint {
                Some(v) => data(hive, v)?,
                None => "<None>".to_string(),
            };
            let modified = last_write(hive, server)?;
            let value_name = match hint {
                Some(v) => Some(hive.vks[v].name()?.to_string()),
                None => None,
            };
            let data2 = format!("User: {username}, MRU: {mru}");
            out.rows.push(row(
                vec![
                    ("HostName", host.as_str().into()),
                    ("Username", username.into()),
                    ("MRUPosition", mru.into()),
                    ("LastModified", modified.into()),
                ],
                Some(path(hive, key)),
                value_name,
                host,
                Some(data2),
                Some(format!("Last modified: {}", time(Some(modified)))),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing Terminal Server Client key: {e}"));
    }
    Ok(())
}
