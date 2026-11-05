//! OutputNames: where a hive is saved under --out.

use std::collections::HashSet;
use std::sync::LazyLock;

use ez_common::cli::full_path;
use ez_common::net::path_extension;
use fancy_regex::Regex;
use registry_ez::hive::fold;

const SEPARATORS: [char; 2] = ['\\', '/'];
const UNDETERMINED: &str = "Undetermined";

// Users\eric, Documents and Settings\eric, Windows\ServiceProfiles\LocalService (with either separator)
static PROFILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[\\/])(?:Users|Documents and Settings|ServiceProfiles)[\\/]([^\\/]+)[\\/]").unwrap());
// a folder named for the drive, as KAPE makes (E:\triage\C\Users\...), else the path's drive (C:\...)
static DRIVE_FOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[\\/]([A-Za-z])[\\/](?:Users|Documents and Settings|Windows)[\\/]").unwrap());
static DRIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z]):").unwrap());

fn first_group(re: &Regex, text: &str) -> Option<String> {
    re.captures(text).ok().flatten().and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

fn is_profile_hive(file_name: &str) -> bool {
    let name = fold(file_name);
    name.contains("NTUSER") || name.contains("USRCLASS")
}

fn profile(hive: &str) -> String {
    first_group(&PROFILE, hive).unwrap_or_else(|| UNDETERMINED.into())
}

fn drive(hive: &str) -> String {
    first_group(&DRIVE_FOLDER, hive).or_else(|| first_group(&DRIVE, hive)).unwrap_or_else(|| UNDETERMINED.into())
}

/// Path.Combine, of parts that aren't rooted
fn combine(left: &str, right: &str) -> String {
    if left.is_empty() || left.ends_with('/') { format!("{left}{right}") } else { format!("{left}/{right}") }
}

/// Path.GetDirectoryName
fn directory_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => match path[..i].trim_end_matches('/') {
            "" => "/",
            dir => dir,
        },
        None => "",
    }
}

/// Path.GetFileNameWithoutExtension and Path.GetExtension
fn stem_and_extension(path: &str) -> (&str, &str) {
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = path_extension(name);
    let without = &name[..name.len() - extension.len()];
    (without.strip_suffix('.').filter(|_| extension.is_empty()).unwrap_or(without), extension)
}

/// The names given so far in this run
#[derive(Default)]
pub struct OutputNames {
    used: HashSet<String>,
}

impl OutputNames {
    /// `nop` false: the hive's path under `out_dir`, without the drive's colon. `nop` true: just the name, in `out_dir`;
    /// with `cn`, profile hives (NTUSER.DAT, UsrClass.dat) are named drive_profile_name. A name already used in this run
    /// gets a number (SAM_2)
    pub fn get(&mut self, hive: &str, out_dir: &str, nop: bool, cn: bool) -> String {
        // either separator, so Windows paths work everywhere
        let file_name = hive.rsplit(SEPARATORS).next().unwrap_or(hive);
        let path = if !nop {
            let full = full_path(hive);
            let parts = full.split(SEPARATORS).filter(|p| !p.is_empty()).map(|p| p.trim_end_matches(':')).filter(|p| !p.is_empty() && *p != "?" && *p != ".");
            parts.fold(out_dir.to_string(), |path, part| combine(&path, part))
        } else if cn && is_profile_hive(file_name) {
            combine(out_dir, &format!("{}_{}_{file_name}", drive(hive), profile(hive)))
        } else {
            combine(out_dir, file_name)
        };
        self.unique(path)
    }

    fn unique(&mut self, path: String) -> String {
        let mut candidate = path.clone();
        let mut n = 2;
        while !self.used.insert(fold(&candidate)) {
            let (stem, extension) = stem_and_extension(&path);
            candidate = combine(directory_name(&path), &format!("{stem}_{n}{extension}"));
            n += 1;
        }
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OutputNamesTests
    #[test]
    fn path_is_recreated() {
        let expected = "/out/tmp/triage/C/Windows/System32/config/SAM";
        let hive = "/tmp/triage/C/Windows/System32/config/SAM";
        assert_eq!(OutputNames::default().get(hive, "/out", false, true), expected);
        assert_eq!(OutputNames::default().get(hive, "/out", false, false), expected);
        assert_eq!(OutputNames::default().get("/tmp/./x/../SAM", "/out/", false, true), "/out/tmp/SAM");
    }

    #[test]
    fn same_name_gets_a_number() {
        let mut names = OutputNames::default();
        assert_eq!(names.get("a/SAM", "/out", true, false), "/out/SAM");
        assert_eq!(names.get("b/SAM", "/out", true, false), "/out/SAM_2");
        assert_eq!(names.get("c/SAM", "/out", true, false), "/out/SAM_3");
        assert_eq!(names.get("d/NTUSER.DAT", "/out", true, false), "/out/NTUSER.DAT");
        assert_eq!(names.get("e/ntuser.dat", "/out", true, false), "/out/ntuser_2.dat");
    }

    #[test]
    fn profile_hives() {
        for (hive, d, p) in [
            (r"C:\Users\eric\NTUSER.DAT", "C", "eric"),
            (r"C:\Users\eric\AppData\Local\Microsoft\Windows\UsrClass.dat", "C", "eric"),
            (r"E:\triage\C\Users\eric\NTUSER.DAT", "C", "eric"),
            (r"E:\Documents and Settings\bob\NTUSER.DAT", "E", "bob"),
            (r"C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT", "C", "LocalService"),
            ("/mnt/evidence/C/Users/eric/NTUSER.DAT", "C", "eric"),
            ("/mnt/evidence/NTUSER.DAT", "Undetermined", "Undetermined"),
        ] {
            assert_eq!(drive(hive), d, "{hive}");
            assert_eq!(profile(hive), p, "{hive}");
        }
    }

    #[test]
    fn profile_hives_with_nop() {
        let mut names = OutputNames::default();
        assert_eq!(names.get(r"C:\Users\eric\NTUSER.DAT", "/out", true, true), "/out/C_eric_NTUSER.DAT");
        assert_eq!(names.get(r"C:\Users\bob\NTUSER.DAT", "/out", true, true), "/out/C_bob_NTUSER.DAT");
        assert_eq!(names.get(r"C:\Windows\System32\config\SYSTEM", "/out", true, true), "/out/SYSTEM");
        assert_eq!(names.get(r"C:\Users\eric\NTUSER.DAT", "/out", true, false), "/out/NTUSER.DAT");
        assert_eq!(names.get(r"C:\Users\bob\NTUSER.DAT", "/out", true, false), "/out/NTUSER_2.DAT");
    }
}
