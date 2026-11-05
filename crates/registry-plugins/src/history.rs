//! Plugins for what a user typed, ran or opened (NTUSER.DAT): 7-Zip, WinRAR, RunMRU, TypedURLs, JumplistData, FeatureUsage.

use ez_common::net::{self, NetResult};
use ez_common::Timestamp;
use registry_ez::{Hive, KeyId, VkId};

use crate::helpers::{data, last_write, path, row, s, subkeys, time, value, values};
use crate::Output;

/// The largest FILETIME DateTimeOffset can hold (DateTimeOffset.MaxValue.ToFileTime())
const MAX_FILETIME: i64 = 2_650_467_743_999_999_999;

fn seven_zip(
    hive: &Hive,
    key: KeyId,
    out: &mut Output,
    value_name: &str,
    column: &'static str,
    label: &str,
    what: &str,
) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        let Some(v) = value(hive, key, value_name)? else { return Ok(()) };
        let name = hive.vks[v].name()?.to_string();
        for item in net::utf16(&hive.value_raw(v)?).split('\0') {
            if item.trim().is_empty() {
                continue;
            }
            out.rows.push(row(
                vec![(column, item.into())],
                Some(path(hive, key)),
                Some(name.clone()),
                format!("{label}: {item}"),
                Some(String::new()),
                Some(String::new()),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing 7-Zip {what}: {e}"));
    }
    Ok(())
}

pub fn seven_zip_archive(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    seven_zip(hive, key, out, "ArcHistory", "ArchiveName", "Archive", "archive history")
}

pub fn seven_zip_copy(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    seven_zip(hive, key, out, "CopyHistory", "CopyPath", "Path", "copy history")
}

pub fn seven_zip_folder(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    seven_zip(hive, key, out, "FolderHistory", "FolderPath", "Folder", "folder history")
}

pub fn seven_zip_path(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    seven_zip(hive, key, out, "PathHistory", "ExtractionPath", "Path", "extraction path history")
}

pub fn winrar(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let add = |v: VkId, subkey: KeyId, rows: &mut Vec<crate::ValuesOut>| -> NetResult<()> {
        let item = data(hive, v)?;
        let data1 = format!("Path: {item}");
        rows.push(row(
            vec![("Path", item.into())],
            Some(path(hive, subkey)),
            Some("Multiple".into()),
            data1,
            Some(String::new()),
            Some(String::new()),
        ));
        Ok(())
    };
    for &sk in subkeys(hive, key) {
        let mut one = || -> NetResult<()> {
            if hive.key_name(sk) == "ArcHistory" {
                for &v in values(hive, sk) {
                    add(v, sk, &mut out.rows)?;
                }
            } else if hive.key_name(sk) == "DialogEditHistory" {
                for &i in subkeys(hive, sk) {
                    for &v in values(hive, i) {
                        add(v, sk, &mut out.rows)?;
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = one() {
            out.errors.push(format!("Error processing WinRAR key: {e}"));
        }
    }
    Ok(())
}

pub fn run_mru(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let current_key = hive.key_name(key).to_string();
    let mut list: Vec<(i32, crate::ValuesOut)> = Vec::new();
    let mut read = || -> NetResult<()> {
        // each UTF-16 unit of MRUList is one entry
        let order: Vec<Vec<u16>> = match value(hive, key, "MRUList")? {
            Some(v) => data(hive, v)?.encode_utf16().map(|u| vec![u]).collect(),
            None => vec![],
        };
        for &v in values(hive, key) {
            let name = hive.vks[v].name()?.to_string();
            if name == "MRUList" {
                continue;
            }
            let units: Vec<u16> = name.encode_utf16().collect();
            let mru = order.iter().position(|o| *o == units).map_or(-1, |p| p as i32);
            let opened_on: Option<Timestamp> = if mru == 0 { Some(last_write(hive, key)?) } else { None };
            let vd = data(hive, v)?;
            let executable = vd.strip_suffix("\\1").unwrap_or(&vd).to_string();
            let data1 = format!("Executable: {executable}");
            list.push((
                mru,
                row(
                    vec![
                        ("ValueName", name.as_str().into()),
                        ("MruPosition", mru.into()),
                        ("Executable", executable.into()),
                        ("OpenedOn", opened_on.into()),
                    ],
                    Some(path(hive, key)),
                    Some(name),
                    data1,
                    Some(format!("Opened on: {}", time(opened_on))),
                    Some(format!("MRU: {mru}")),
                ),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing RunMRU subkey {current_key}: {e}"));
    }
    list.sort_by_key(|(mru, _)| *mru);
    out.rows.extend(list.into_iter().map(|(_, r)| r));
    Ok(())
}

pub fn typed_urls(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        let parent = hive.keys[key].parent;
        let times = parent.and_then(|p| crate::helpers::subkey(hive, p, "TypedURLsTime"));
        for &v in values(hive, key) {
            let url = data(hive, v)?;
            let name = hive.vks[v].name()?.to_string();
            let raw = match times {
                Some(t) => value(hive, t, &name)?.map(|tv| hive.value_raw(tv)).transpose()?,
                None => None,
            };
            let file_time = match raw {
                Some(raw) if raw.len() >= 8 => net::i64_at(&raw, 0)?,
                _ => 0,
            };
            let mut ts = None;
            if file_time > 0 && file_time <= MAX_FILETIME {
                ts = registry_ez::cells::filetime(file_time).ok().filter(|t| t.parts().year != 1601);
            }
            let slack = net::utf16(&hive.value_slack(v)?).replace('\0', " ");
            let slack = slack.trim();
            out.rows.push(row(
                vec![("Timestamp", ts.into()), ("Url", url.as_str().into()), ("Slack", slack.into())],
                Some(path(hive, key)),
                Some(name),
                url,
                Some(format!("Timestamp: {}", time(ts))),
                Some(format!("Slack: {slack}")),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing TypedURLs key: {e}"));
    }
    Ok(())
}

pub fn jumplist_data(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        for &v in values(hive, key) {
            let raw = hive.value_raw(v)?;
            let name = hive.vks[v].name()?.to_string();
            let executed = if raw.len() < 8 {
                // DateTimeOffset.MinValue
                Timestamp(0)
            } else {
                registry_ez::cells::filetime(net::i64_at(&raw, 0)?)?
            };
            let data1 = format!("Name: {name}");
            out.rows.push(row(
                vec![("JumpListName", name.as_str().into()), ("ExecutedOn", executed.into())],
                Some(path(hive, key)),
                Some(name),
                data1,
                Some(format!("Executed: {}", time(Some(executed)))),
                Some(String::new()),
            ));
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing JumplistData key: {e}"));
    }
    Ok(())
}

pub fn feature_usage(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &sk in subkeys(hive, key) {
        let mut one = || -> NetResult<()> {
            for &v in values(hive, sk) {
                let subkey_name = hive.key_name(sk).to_string();
                let name = Some(hive.vks[v].name()?.to_string());
                let count = Some(data(hive, v)?);
                let data1 = format!("KeyPath: {subkey_name}");
                let data2 = format!("ValueName: {}", s(&name));
                let data3 = format!("Count: {}", s(&count));
                out.rows.push(row(
                    vec![("KeyPath", subkey_name.into()), ("ValueName", name.into()), ("Count", count.into())],
                    Some(path(hive, sk)),
                    Some("Multiple".into()),
                    data1,
                    Some(data2),
                    Some(data3),
                ));
            }
            Ok(())
        };
        if let Err(e) = one() {
            out.errors.push(format!("Error processing FeatureUsage key: {e}"));
        }
    }
    Ok(())
}
