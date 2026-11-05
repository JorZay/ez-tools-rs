//! The Amcache-Inventory* and Amcache-Mare plugins (Amcache.hve).

use ez_common::net::NetResult;
use registry_ez::{Hive, KeyId};

use crate::helpers::{last_write, path, per_subkey, row, s, text, time};
use crate::{Cell, Output};

const MULTIPLE: &str = "Multiple";

pub fn application(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryApplication key", |sk| {
        let name = text(hive, sk, "Name")?;
        let version = text(hive, sk, "Version")?;
        let publisher = text(hive, sk, "Publisher")?;
        let source = text(hive, sk, "Source")?;
        let root_dir = text(hive, sk, "RootDirPath")?;
        let uninstall = text(hive, sk, "UninstallString")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("Name: {} Version: {} Publisher: {}", s(&name), s(&version), s(&publisher));
        let data2 = format!("Source: {} RootDirPath: {} UninstallString: {}", s(&source), s(&root_dir), s(&uninstall));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("Name", name.into()),
                ("Version", version.into()),
                ("Publisher", publisher.into()),
                ("Source", source.into()),
                ("RootDirPath", root_dir.into()),
                ("UninstallString", uninstall.into()),
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

/// `.ValueData.Replace("0000", "")` of a hash
fn sha1(hive: &Hive, key: KeyId, name: &str) -> NetResult<Option<String>> {
    Ok(text(hive, key, name)?.map(|v| v.replace("0000", "")))
}

pub fn application_file(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryApplicationFile key", |sk| {
        let long_path = text(hive, sk, "LowerCaseLongPath")?;
        let name = text(hive, sk, "Name")?;
        let product = text(hive, sk, "ProductName")?;
        let publisher = text(hive, sk, "Publisher")?;
        let version = text(hive, sk, "Version")?;
        let hash = sha1(hive, sk, "FileId")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("Path: {} Name: {} ProductName: {}", s(&long_path), s(&name), s(&product));
        let data2 = format!("Publisher: {} Version: {} SHA1: {}", s(&publisher), s(&version), s(&hash));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("Path", long_path.into()),
                ("Name", name.into()),
                ("ProductName", product.into()),
                ("Publisher", publisher.into()),
                ("Version", version.into()),
                ("SHA1", hash.into()),
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

pub fn application_shortcut(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryApplicationShortcut key", |sk| {
        let shortcut = text(hive, sk, "ShortcutPath")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("Path: {}", s(&shortcut));
        Ok(Some(row(
            vec![("Timestamp", ts.into()), ("Path", shortcut.into())],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            data1,
            Some(String::new()),
            Some(format!("Timestamp: {}", time(Some(ts)))),
        )))
    });
    Ok(())
}

pub fn device_container(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryDeviceContainer key", |sk| {
        let model_name = text(hive, sk, "ModelName")?;
        let friendly = text(hive, sk, "FriendlyName")?;
        let model_number = text(hive, sk, "ModelNumber")?;
        let manufacturer = text(hive, sk, "Manufacturer")?;
        let category = text(hive, sk, "PrimaryCategory")?;
        let model_id = text(hive, sk, "ModelId")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("ModelName: {} FriendlyName: {} ModelNumber: {}", s(&model_name), s(&friendly), s(&model_number));
        let data2 = format!("Manufacturer: {} PrimaryCategory: {} ModelID: {}", s(&manufacturer), s(&category), s(&model_id));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("ModelName", model_name.into()),
                ("FriendlyName", friendly.into()),
                ("ModelNumber", model_number.into()),
                ("Manufacturer", manufacturer.into()),
                ("PrimaryCategory", category.into()),
                ("ModelID", model_id.into()),
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

pub fn device_pnp(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryDevicePnp key", |sk| {
        let model = text(hive, sk, "Model")?;
        let manufacturer = text(hive, sk, "Manufacturer")?;
        let description = text(hive, sk, "Description")?;
        let install_date = text(hive, sk, "InstallDate")?;
        let parent = text(hive, sk, "ParentId")?;
        let matching = text(hive, sk, "MatchingID")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("Model: {} Manufacturer: {} Description: {}", s(&model), s(&manufacturer), s(&description));
        let data2 = format!("InstallDate: {} ParentID: {} MatchingID: {}", s(&install_date), s(&parent), s(&matching));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("Model", model.into()),
                ("Manufacturer", manufacturer.into()),
                ("Description", description.into()),
                ("InstallDate", install_date.into()),
                ("ParentID", parent.into()),
                ("MatchingID", matching.into()),
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

pub fn driver_binary(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing InventoryDriverBinary key", |sk| {
        let driver_path = hive.key_name(sk).to_string();
        let driver_last_write = text(hive, sk, "DriverLastWriteTime")?;
        let company = text(hive, sk, "DriverCompany")?;
        let name = text(hive, sk, "DriverName")?;
        let version = text(hive, sk, "DriverVersion")?;
        let product = text(hive, sk, "Product")?;
        let product_version = text(hive, sk, "ProductVersion")?;
        let hash = sha1(hive, sk, "DriverId")?;
        let ts = last_write(hive, sk)?;
        let data1 = format!("DriverCompany: {} Product: {} ProductVersion: {}", s(&company), s(&product), s(&product_version));
        let data2 = format!("DriverName: {} DriverVersion: {} SHA1: {}", s(&name), s(&version), s(&hash));
        let data3 = format!("Timestamp: {}, DriverLastWriteTime: {}", time(Some(ts)), s(&driver_last_write));
        Ok(Some(row(
            vec![
                ("Timestamp", ts.into()),
                ("DriverLastWriteTime", driver_last_write.into()),
                ("DriverCompany", company.into()),
                ("Product", product.into()),
                ("ProductVersion", product_version.into()),
                ("DriverName", name.into()),
                ("DriverVersion", version.into()),
                ("Path", driver_path.into()),
                ("SHA1", hash.into()),
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

pub fn mare(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    per_subkey(hive, key, out, "Error processing Mare key", |sk| {
        let Some(restore) = text(hive, sk, "restore")? else { return Ok(None) };
        let Some((unknown, target)) = restore.rsplit_once('|') else { return Ok(None) };
        Ok(Some(row(
            vec![("Unknown", Cell::from(unknown)), ("Path", Cell::from(target))],
            Some(path(hive, sk)),
            Some(MULTIPLE.into()),
            format!("Unknown: {unknown}"),
            Some(format!("Path: {target}")),
            Some(String::new()),
        )))
    });
    Ok(())
}
