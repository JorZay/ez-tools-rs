//! Plugins for installed programs: Uninstall, Products, AppPaths, WindowsApp, AppCompatFlags2, RADAR, Adobe's websites.

use ez_common::Timestamp;
use ez_common::net::NetResult;
use registry_ez::{Hive, KeyId};

use crate::helpers::{
    NULL_REFERENCE, filetime_text, last_write, path, per_subkey, row, s, subkey, subkeys, text, time, utf16_len, utf16_prefix,
    values,
};
use crate::{Cell, Output};

const MULTIPLE: &str = "Multiple";

pub fn uninstall(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing Uninstall key", |sk| {
        let key_name = hive.key_name(sk).to_string();
        let display_name = text(hive, sk, "DisplayName")?;
        let display_version = text(hive, sk, "DisplayVersion")?;
        let publisher = text(hive, sk, "Publisher")?;
        let install_date = text(hive, sk, "InstallDate")?;
        let install_source = text(hive, sk, "InstallSource")?;
        let install_location = text(hive, sk, "InstallLocation")?;
        let uninstall_string = text(hive, sk, "UninstallString")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!(
            "KeyName: {key_name} DisplayName: {} DisplayVersion: {} Publisher: {} InstallDate: {}",
            s(&display_name),
            s(&display_version),
            s(&publisher),
            s(&install_date)
        );
        let data3 = format!(
            "InstallSource: {} InstallLocation: {} UninstallString: {}",
            s(&install_source),
            s(&install_location),
            s(&uninstall_string)
        );
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("KeyName", key_name.into()),
                ("DisplayName", display_name.into()),
                ("DisplayVersion", display_version.into()),
                ("Publisher", publisher.into()),
                ("InstallDate", install_date.into()),
                ("InstallSource", install_source.into()),
                ("InstallLocation", install_location.into()),
                ("UninstallString", uninstall_string.into()),
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

#[allow(clippy::too_many_arguments)]
fn product_row(
    key_path: String,
    display_name: Option<String>,
    package_name: Option<String>,
    install_date: Option<String>,
    publisher: Option<String>,
    language: Option<String>,
    install_location: Option<String>,
    install_source: Option<String>,
    comments: Option<String>,
    ts: Timestamp,
) -> crate::ValuesOut {
    let data1 = format!(
        "DisplayName: {} PackageName: {} InstallDate: {} Publisher: {} Language: {}",
        s(&display_name),
        s(&package_name),
        s(&install_date),
        s(&publisher),
        s(&language)
    );
    let data3 = format!("InstallLocation: {} InstallSource: {} Comments: {}", s(&install_location), s(&install_source), s(&comments));
    row(
        vec![
            ("Timestamp", ts.into()),
            ("DisplayName", display_name.into()),
            ("PackageName", package_name.into()),
            ("InstallDate", install_date.into()),
            ("Publisher", publisher.into()),
            ("Language", language.into()),
            ("InstallLocation", install_location.into()),
            ("InstallSource", install_source.into()),
            ("Comments", comments.into()),
        ],
        Some(key_path),
        Some(MULTIPLE.into()),
        data1,
        Some(format!("Timestamp: {}", time(Some(ts)))),
        Some(data3),
    )
}

pub fn products(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let classes = hive.keys[key].path.contains("Classes");
    per_subkey(hive, key, out, "Error processing Products key", |sk| {
        if classes {
            let product_name = text(hive, sk, "ProductName")?;
            let language = text(hive, sk, "Language")?;
            let (package_name, last_used_source) = match subkey(hive, sk, "SourceList") {
                Some(list) => (text(hive, list, "PackageName")?, text(hive, list, "LastUsedSource")?),
                None => (None, None),
            };
            let ts = last_write(hive, sk)?;
            return Ok(Some(product_row(
                path(hive, sk),
                product_name,
                package_name,
                None,
                None,
                language,
                None,
                last_used_source,
                None,
                ts,
            )));
        }
        let Some(properties) = subkey(hive, sk, "InstallProperties") else { return Ok(None) };
        let display_name = text(hive, properties, "DisplayName")?;
        // the package name column has DisplayVersion in the original
        let package_name = text(hive, properties, "DisplayVersion")?;
        let install_date = text(hive, properties, "InstallDate")?;
        let publisher = text(hive, properties, "Publisher")?;
        let language = text(hive, properties, "Language")?;
        let install_location = text(hive, properties, "InstallLocation")?;
        let install_source = text(hive, properties, "InstallSource")?;
        let comments = text(hive, properties, "Comments")?;
        let ts = last_write(hive, properties)?;
        Ok(Some(product_row(
            path(hive, sk),
            display_name,
            package_name,
            install_date,
            publisher,
            language,
            install_location,
            install_source,
            comments,
            ts,
        )))
    });
    Ok(())
}

pub fn app_paths(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing AppPaths key", |sk| {
        let file_name = hive.key_name(sk).to_string();
        let path1 = text(hive, sk, "(default)")?;
        let path2 = text(hive, sk, "Path")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("FileName: {file_name} Path1: {} Path2: {}", s(&path1), s(&path2));
        Ok(Some(row(
            vec![("Timestamp", ts.into()), ("FileName", file_name.into()), ("Path1", path1.into()), ("Path2", path2.into())],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(format!("Timestamp: {}", time(Some(ts)))),
            Some(String::new()),
        )))
    });
    Ok(())
}

pub fn windows_app(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let (Some(families), Some(packages)) = (subkey(hive, key, "Families"), subkey(hive, key, "Packages")) else {
        return Ok(());
    };
    for &family in subkeys(hive, families) {
        per_subkey(hive, family, out, "Error processing WindowsApp key", |app| {
            let install_time = filetime_text(text(hive, app, "InstallTime")?.as_deref())?;
            let key_name = hive.key_name(app).to_string();
            let (display_name, root_folder) = match subkey(hive, packages, &key_name) {
                Some(package) => (text(hive, package, "DisplayName")?, text(hive, package, "PackageRootFolder")?),
                None => (None, None),
            };
            let data1 = format!("KeyName: {key_name} DisplayName: {} PackageRootFolder: {}", s(&display_name), s(&root_folder));
            Ok(Some(row(
                vec![
                    ("KeyName", key_name.into()),
                    ("DisplayName", display_name.into()),
                    ("InstallTime", install_time.into()),
                    ("PackageRootFolder", root_folder.into()),
                ],
                Some(path(hive, family)),
                Some(MULTIPLE.into()),
                data1,
                Some(format!("InstallTime: {}", time(Some(install_time)))),
                Some(String::new()),
            )))
        });
    }
    Ok(())
}

pub fn app_compat_flags2(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &sk in subkeys(hive, key) {
        let mut one = || -> NetResult<()> {
            let mut add = |v: usize| -> NetResult<()> {
                let name = hive.vks[v].name()?.to_string();
                let data1 = format!("Path: {name}");
                out.rows.push(row(
                    vec![("Path", name.into())],
                    Some(path(hive, sk)),
                    Some(MULTIPLE.into()),
                    data1,
                    Some(String::new()),
                    Some(String::new()),
                ));
                Ok(())
            };
            if hive.key_name(sk) == "Layers" {
                for &v in values(hive, sk) {
                    add(v)?;
                }
            } else if hive.key_name(sk) == "Compatibility Assistant" {
                for &i in subkeys(hive, sk) {
                    for &v in values(hive, i) {
                        add(v)?;
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = one() {
            out.errors.push(format!("Error processing AppCompatFlags key: {e}"));
        }
    }
    Ok(())
}

fn radar_row(hive: &Hive, sk: KeyId, kind: &str, detected: Option<Timestamp>) -> crate::ValuesOut {
    let filename = hive.key_name(sk).to_string();
    let data1 = format!("Filename: {filename}");
    row(
        vec![("KeyName", kind.into()), ("Filename", filename.into()), ("LastDetectionTime", detected.into())],
        Some(path(hive, sk)),
        Some(MULTIPLE.into()),
        data1,
        Some(format!("LastDetectionTime: {}", time(detected))),
        Some(format!("KeyName: {kind}")),
    )
}

/// Without either subkey the original throws, so the hive fails and no row of this key is kept
pub fn radar(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let diagnosed = subkey(hive, key, "DiagnosedApplications");
    let reflection = subkey(hive, key, "ReflectionApplications");
    let diagnosed = diagnosed.ok_or(NULL_REFERENCE)?;
    let mut local = crate::Output::default();
    per_subkey(hive, diagnosed, &mut local, "Error processing RADAR key", |sk| {
        let detected = filetime_text(text(hive, sk, "LastDetectionTime")?.as_deref())?;
        Ok(Some(radar_row(hive, sk, "DiagnosedApplications", Some(detected))))
    });
    let reflection = reflection.ok_or(NULL_REFERENCE)?;
    per_subkey(hive, reflection, &mut local, "Error processing RADAR key", |sk| {
        Ok(Some(radar_row(hive, sk, "ReflectionApplications", None)))
    });
    out.rows.append(&mut local.rows);
    out.errors.append(&mut local.errors);
    Ok(())
}

pub fn adobe_trust_manager(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    let mut read = || -> NetResult<()> {
        for &product in subkeys(hive, key) {
            for &version in subkeys(hive, product) {
                let perms = subkey(hive, version, "TrustManager").and_then(|t| subkey(hive, t, "cDefaultLaunchURLPerms"));
                let Some(perms) = perms else { continue };
                let host_perms = text(hive, perms, "tHostPerms")?.ok_or(NULL_REFERENCE)?;
                for website in host_perms.split('|') {
                    if website.contains("version") {
                        continue;
                    }
                    let length = utf16_len(website);
                    if length < 2 {
                        // website.Substring(0, website.Length - 2)
                        let negative = length as i64 - 2;
                        return Err(format!("length ('{negative}') must be a non-negative value. (Parameter 'length')\nActual value was {negative}."));
                    }
                    let site = utf16_prefix(website, length - 2);
                    let user_choice = match website.encode_utf16().last() {
                        Some(0x32) => "Allow",
                        Some(0x33) => "Block",
                        _ => "Undefined",
                    };
                    let data1 = format!("Website: {site}");
                    out.rows.push(row(
                        vec![("Website", Cell::from(site)), ("UserChoice", user_choice.into())],
                        Some(path(hive, perms)),
                        Some(hive.key_name(perms).to_string()),
                        data1,
                        Some(format!("User Choice: {user_choice}")),
                        Some(String::new()),
                    ));
                }
            }
        }
        Ok(())
    };
    if let Err(e) = read() {
        out.errors.push(format!("Error processing Adobe products: {e}"));
    }
    Ok(())
}
