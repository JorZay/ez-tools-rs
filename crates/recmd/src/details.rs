//! --kn output beyond the summary: the key as JSON (SimpleKey).

use ez_common::json::service_stack_string;
use registry_ez::hive::{Hive, KeyId};

/// SimpleKey as ServiceStack writes it (byte arrays as base64)
pub fn key_json(hive: &Hive, k: KeyId) -> Result<String, String> {
    let mut out = String::new();
    write_key(hive, k, &mut out)?;
    Ok(out)
}

fn write_key(hive: &Hive, k: KeyId, out: &mut String) -> Result<String, String> {
    out.push_str("{\"KeyPath\":");
    service_stack_string(out, &hive.keys[k].path);
    out.push_str(",\"KeyName\":");
    service_stack_string(out, hive.key_name(k));
    out.push_str(&format!(",\"LastWriteTimestamp\":\"{}\",\"SubKeys\":[", hive.nk(k).last_write()?.to_json_string()));
    for (i, &sk) in hive.keys[k].subkeys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_key(hive, sk, out)?;
    }
    out.push_str("],\"Values\":[");
    for (i, &v) in hive.keys[k].values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let vk = &hive.vks[v];
        out.push_str("{\"ValueName\":");
        service_stack_string(out, vk.name()?);
        out.push_str(",\"ValueType\":");
        service_stack_string(out, &vk.type_name());
        out.push_str(",\"ValueData\":");
        service_stack_string(out, &hive.value_data(v)?.text());
        out.push_str(&format!(
            ",\"DataRaw\":\"{}\",\"Slack\":\"{}\"}}",
            base64(&hive.value_raw(v)?),
            base64(&hive.value_slack(v)?)
        ));
    }
    out.push_str("]}");
    Ok(String::new())
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}
