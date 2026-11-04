//! The hash Windows puts in a prefetch file's name and header (PrefetchHash): of the executable's upper-case NT device
//! path, e.g. `\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE`. Hosting processes and packaged apps also hash part
//! of their command line, so their hash can't be reproduced from the path alone.

use ez_common::dotnet::upper_invariant;

use crate::Version;

/// The hash of `device_path` with the algorithm `version` uses
pub fn calculate(device_path: &str, version: Version) -> u32 {
    if version == Version::WinXpOrWin2K3 { calculate_xp(device_path) } else { calculate_vista(device_path) }
}

fn mix(mut hash: u32, device_path: &str) -> u32 {
    for c in upper_invariant(device_path).encode_utf16() {
        // UTF-16LE bytes, low byte first
        hash = hash.wrapping_mul(37).wrapping_add(c as u8 as u32);
        hash = hash.wrapping_mul(37).wrapping_add((c >> 8) as u32);
    }
    hash
}

/// Windows XP and Server 2003 (format version 17)
pub fn calculate_xp(device_path: &str) -> u32 {
    let mut hash = mix(0, device_path).wrapping_mul(314159269);
    if hash > 0x80000000 {
        hash = 0u32.wrapping_sub(hash);
    }
    hash % 1000000007
}

/// Windows Vista and later (format versions 23 to 31)
pub fn calculate_vista(device_path: &str) -> u32 {
    mix(314159, device_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_as_the_prefetch_library() {
        assert_eq!(calculate_xp(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE"), 0x087B4001);
        assert_eq!(calculate_xp(r"\device\harddiskvolume1\windows\system32\cmd.exe"), 0x087B4001);
        assert_eq!(calculate_vista(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE"), 0x4A81B364);
        assert_eq!(calculate(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE", Version::Win10OrWin11), 0x89305D47);
    }
}
