//! Finding event logs, and files that are byte-for-byte copies of each other.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

/// The event logs given: files as they are, folders searched recursively for `*.evtx` (any case). Symbolic links
/// in folders are not followed, so loops cannot occur. A path given twice is used once.
#[derive(Debug, Default)]
pub struct Discovered {
    pub files: Vec<PathBuf>,
    /// Paths that do not exist, and folders that could not be read (the search goes on)
    pub errors: Vec<(PathBuf, io::Error)>,
}

pub fn find_event_logs(files: &[PathBuf], dirs: &[PathBuf]) -> Discovered {
    let mut d = Discovered::default();
    let mut seen = HashSet::new();
    let mut add = |d: &mut Discovered, p: PathBuf| {
        let key = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if seen.insert(key) {
            d.files.push(p);
        }
    };

    for f in files {
        match std::fs::metadata(f) {
            Ok(m) if m.is_file() => add(&mut d, absolute(f)),
            Ok(_) => d.errors.push((f.clone(), io::Error::new(io::ErrorKind::InvalidInput, "not a file"))),
            Err(e) => d.errors.push((f.clone(), e)),
        }
    }
    for dir in dirs {
        match std::fs::metadata(dir) {
            Ok(m) if m.is_dir() => {
                let mut found = Vec::new();
                walk(&absolute(dir), &mut found, &mut d.errors);
                for f in found {
                    add(&mut d, f);
                }
            }
            Ok(_) => d.errors.push((dir.clone(), io::Error::new(io::ErrorKind::InvalidInput, "not a folder"))),
            Err(e) => d.errors.push((dir.clone(), e)),
        }
    }
    d
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Files in name order, then subfolders in name order
fn walk(dir: &Path, found: &mut Vec<PathBuf>, errors: &mut Vec<(PathBuf, io::Error)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push((dir.to_path_buf(), e));
            return;
        }
    };
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push((dir.to_path_buf(), e));
                continue;
            }
        };
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            dirs.push(path);
        } else if ft.is_file() && path.extension().is_some_and(|e| e.eq_ignore_ascii_case("evtx")) {
            files.push(path);
        }
    }
    // case-insensitive name order, as Windows lists folders (and EvtxECmd reads them)
    let key = |p: &PathBuf| {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        (name.to_lowercase(), name)
    };
    files.sort_by_key(key);
    dirs.sort_by_key(key);
    found.extend(files);
    for d in dirs {
        walk(&d, found, errors);
    }
}

/// For each file, the index of an earlier file with the same bytes (only files of the same size are hashed, with
/// BLAKE3). A file that cannot be read is not a copy of anything.
pub fn identical_files(files: &[PathBuf]) -> Vec<Option<usize>> {
    use rayon::prelude::*;
    let sizes: Vec<Option<u64>> = files.iter().map(|f| std::fs::metadata(f).ok().map(|m| m.len())).collect();
    let mut by_size: HashMap<u64, usize> = HashMap::new();
    for s in sizes.iter().flatten() {
        *by_size.entry(*s).or_default() += 1;
    }
    let hashes: Vec<Option<blake3::Hash>> = files
        .par_iter()
        .zip(&sizes)
        .map(|(f, s)| {
            let s = (*s)?;
            if by_size[&s] < 2 {
                return None;
            }
            let mut h = blake3::Hasher::new();
            h.update_mmap(f).ok()?;
            Some(h.finalize())
        })
        .collect();

    let mut first: HashMap<blake3::Hash, usize> = HashMap::new();
    hashes
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let h = (*h)?;
            match first.get(&h) {
                Some(&j) => Some(j),
                None => {
                    first.insert(h, i);
                    None
                }
            }
        })
        .collect()
}
