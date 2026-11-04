//! The executable's full path among the files a prefetch file lists, checked against its hash (PECmd's
//! ExecutablePathResolver).

use ez_common::dotnet::upper_invariant;

use crate::{Prefetch, hash};

/// The path found (several joined with ", " when none could be validated; empty when there is none)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutablePath {
    pub full_path: String,
    pub path_validated: bool,
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    upper_invariant(s).starts_with(&upper_invariant(prefix))
}

fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    upper_invariant(s).ends_with(&upper_invariant(suffix))
}

fn candidate_priority(path: &str) -> usize {
    if ends_with_ignore_case(path, ".exe") {
        0
    } else if ends_with_ignore_case(path, ".tmp") {
        1
    } else if ends_with_ignore_case(path, ".bin") {
        2
    } else {
        3
    }
}

fn has_executable_name(path: &str, executable: &str) -> bool {
    if path.trim().is_empty() {
        return false;
    }
    let filename = path.rsplit(['\\', '/']).next().unwrap_or(path);
    if upper_invariant(filename) == upper_invariant(executable) {
        return true;
    }
    // the header holds the first 29 characters of a longer name
    executable.encode_utf16().count() == 29 && starts_with_ignore_case(filename, executable) && candidate_priority(filename) < 3
}

/// The paths whose hash is checked: the path itself, and for `\VOLUME{...}` paths (Windows 10 and later, which hash
/// the native device path, whose number isn't kept) `\DEVICE\HARDDISKVOLUME1` to 255
fn matches_hash(path: &str, expected: u32, version: crate::Version) -> bool {
    if hash::calculate(path, version) == expected {
        return true;
    }
    if !starts_with_ignore_case(path, r"\VOLUME{") {
        return false;
    }
    let Some(end) = path.find('}') else { return false };
    let rest = &path[end + 1..];
    if rest.is_empty() {
        return false;
    }
    (1..=255).any(|n| hash::calculate(&format!(r"\DEVICE\HARDDISKVOLUME{n}{rest}"), version) == expected)
}

/// ExecutablePathResolver.Resolve
pub fn executable_path(pf: &Prefetch) -> ExecutablePath {
    let Some(header) = &pf.header else { return ExecutablePath::default() };
    if header.executable_filename.trim().is_empty() {
        return ExecutablePath::default();
    }
    let mut by_priority: [Vec<&str>; 4] = Default::default();
    for filename in &pf.filenames {
        if !has_executable_name(filename, &header.executable_filename) {
            continue;
        }
        let candidates = &mut by_priority[candidate_priority(filename)];
        if !candidates.iter().any(|c| upper_invariant(c) == upper_invariant(filename)) {
            candidates.push(filename);
        }
    }
    let Some(preferred) = by_priority.iter().find(|c| !c.is_empty()) else { return ExecutablePath::default() };
    for candidate in preferred {
        if matches_hash(candidate, header.hash_value, header.version) {
            return ExecutablePath { full_path: candidate.to_string(), path_validated: true };
        }
    }
    ExecutablePath { full_path: preferred.join(", "), path_validated: false }
}
