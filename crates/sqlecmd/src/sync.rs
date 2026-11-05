//! --sync: the latest maps from the SQLECmd repository (its master branch as a zip), into Maps next to the executable, as
//! SQLECmd's --sync does.

use std::io::{Cursor, Read};
use std::path::Path;

use ez_common::cli::log::Logger;

const URL: &str = "https://github.com/EricZimmerman/SQLECmd/archive/master.zip";
const FOLDER: &str = "SQLECmd-master/SQLMap/Maps/";

pub fn sync_maps(dir: &Path, log: &mut Logger) -> Result<(), String> {
    log.blank();
    log.info("Checking for updated maps at https://github.com/EricZimmerman/SQLECmd/tree/master/SQLMap/Maps...");
    log.blank();
    let zip = ureq::get(URL).call().map_err(|e| e.to_string())?.body_mut().with_config().limit(512 << 20).read_to_vec().map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("Unable to create {}: {e}", dir.display()))?;

    let (mut new, mut updated) = (Vec::new(), Vec::new());
    let mut found = false;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let Some(name) = entry.name().strip_prefix(FOLDER).map(str::to_string) else { continue };
        found = true;
        // only files directly in the folder, with plain names
        if name.is_empty() || name.contains(['/', '\\']) || !entry.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let dest = dir.join(&name);
        match std::fs::read(&dest) {
            Ok(old) if old == bytes => {}
            Ok(_) => updated.push(name.clone()),
            Err(_) => new.push(name.clone()),
        }
        std::fs::write(&dest, bytes).map_err(|e| format!("Unable to write {}: {e}", dest.display()))?;
    }
    if !found {
        return Err("The downloaded archive does not contain SQLMap/Maps".to_string());
    }

    if new.is_empty() && updated.is_empty() {
        log.blank();
        log.info("No new maps available");
        log.blank();
        return Ok(());
    }
    log.info("Updates found!");
    log.blank();
    for (title, list) in [("New maps", &new), ("Updated maps", &updated)] {
        if !list.is_empty() {
            log.info(title);
            for m in list {
                let stem = Path::new(m).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                log.info(&stem);
            }
            log.blank();
        }
    }
    log.blank();
    Ok(())
}
