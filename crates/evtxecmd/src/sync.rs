//! --sync: the latest maps from the EvtxECmd repository, as EvtxECmd's --sync gets them (its master branch as a zip).

use std::io::{Cursor, Read};
use std::path::Path;

use crate::log::Logger;

const URL: &str = "https://github.com/EricZimmerman/evtx/archive/master.zip";
const MAPS: &str = "evtx-master/evtx/Maps/";

pub fn sync_maps(dir: &Path, log: &mut Logger) -> Result<(), String> {
    log.info(&format!("Checking for updated maps at {URL}..."));
    let zip = ureq::get(URL)
        .call()
        .map_err(|e| e.to_string())?
        .body_mut()
        .with_config()
        .limit(512 << 20)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("Unable to create {}: {e}", dir.display()))?;

    let (mut new, mut updated) = (Vec::new(), Vec::new());
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let Some(name) = entry.name().strip_prefix(MAPS).map(str::to_string) else { continue };
        // only files directly in the folder, with plain names
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') || !entry.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let dest = dir.join(&name);
        match std::fs::read(&dest) {
            Ok(old) if old == bytes => continue,
            Ok(_) => updated.push(name.clone()),
            Err(_) => new.push(name.clone()),
        }
        std::fs::write(&dest, bytes).map_err(|e| format!("Unable to write {}: {e}", dest.display()))?;
    }

    if new.is_empty() && updated.is_empty() {
        log.info("\nNo new maps available");
        return Ok(());
    }
    log.info("Updates found!");
    for (title, list) in [("New maps", &new), ("Updated maps", &updated)] {
        if !list.is_empty() {
            log.info(&format!("\n{title}"));
            for m in list {
                log.info(m.trim_end_matches(".map"));
            }
        }
    }
    log.info(&format!("\nUse them with --maps {}", dir.display()));
    Ok(())
}
