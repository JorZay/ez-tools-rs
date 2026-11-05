//! GUIDs and what they name, as GuidMapping (Eric Zimmerman's, MIT) has them: its two lists, unchanged, are in `data/`.

use std::collections::HashMap;
use std::sync::OnceLock;

const GUIDS: &str = include_str!("../data/GuidToName.txt");
const PREFIXES: &str = include_str!("../data/GuidPrefixToName.txt");

struct Lists {
    /// By the GUID as 'D' formats it. The first entry of a GUID wins
    guids: HashMap<String, &'static str>,
    /// A family of GUIDs by the start they share, longest first
    prefixes: Vec<(&'static str, &'static str)>,
}

fn lines(text: &'static str) -> impl Iterator<Item = &'static str> {
    text.strip_prefix('\u{FEFF}').unwrap_or(text).lines()
}

/// 'first|second', both trimmed; the description isn't empty
fn segments(line: &'static str) -> Option<(&'static str, &'static str)> {
    let (first, second) = line.split_once('|')?;
    if second.contains('|') {
        return None;
    }
    let description = second.trim();
    if description.is_empty() { None } else { Some((first.trim(), description)) }
}

/// The start of a GUID as 'D' formats it: lowercase, with its hyphens, at least 8 characters and not a whole GUID
fn is_prefix(candidate: &str) -> bool {
    (8..36).contains(&candidate.len())
        && candidate.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(&c) }
        })
}

fn lists() -> &'static Lists {
    static LISTS: OnceLock<Lists> = OnceLock::new();
    LISTS.get_or_init(|| {
        let mut guids = HashMap::new();
        for (id, description) in lines(GUIDS).filter_map(segments) {
            if let Some(id) = hyphenated(id) {
                guids.entry(id).or_insert(description);
            }
        }
        let mut prefixes: Vec<_> = lines(PREFIXES).filter_map(segments).filter(|(p, _)| is_prefix(p)).collect();
        prefixes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Lists { guids, prefixes }
    })
}

/// A GUID in the 'D' format, in lowercase
fn hyphenated(s: &str) -> Option<String> {
    let valid = s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { c.is_ascii_hexdigit() });
    valid.then(|| s.to_ascii_lowercase())
}

/// Guid.TryParse for the formats with and without braces, parentheses and hyphens (N, D, B, P), as 'D' writes the GUID.
/// The X format (`{0x...,0x...,{0x...}}`) isn't read: no registry key or stream of the ports is named like that.
pub fn parse(guid: &str) -> Option<String> {
    let inner = match (guid.as_bytes().first(), guid.as_bytes().last()) {
        (Some(b'{'), Some(b'}')) | (Some(b'('), Some(b')')) if guid.len() == 38 => &guid[1..37],
        _ => guid,
    };
    if inner.len() == 32 && inner.bytes().all(|c| c.is_ascii_hexdigit()) {
        let l = inner.to_ascii_lowercase();
        return Some(format!("{}-{}-{}-{}-{}", &l[..8], &l[8..12], &l[12..16], &l[16..20], &l[20..]));
    }
    hyphenated(inner)
}

/// TryGetDescription: the GUID itself, else the family it belongs to by its prefix
pub fn description(guid: &str) -> Option<&'static str> {
    let id = parse(guid.trim_matches(char::is_whitespace))?;
    let lists = lists();
    lists
        .guids
        .get(&id)
        .copied()
        .or_else(|| lists.prefixes.iter().find(|(prefix, _)| id.starts_with(prefix)).map(|(_, description)| *description))
}

/// GetDescriptionFromGuid
pub fn description_or_unmapped(guid: &str) -> String {
    match description(guid) {
        Some(d) => d.to_string(),
        None => format!("Unmapped GUID: {guid}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_guid_in_any_format() {
        let name = "Java Plug-in 1.5.0_07";
        assert_eq!(description("cafeefac-0015-0000-0007-abcdeffedcbc"), Some(name));
        assert_eq!(description("{CAFEEFAC-0015-0000-0007-ABCDEFFEDCBC}"), Some(name));
        assert_eq!(description(" (cafeefac-0015-0000-0007-abcdeffedcbc) "), Some(name));
        assert_eq!(description("cafeefac001500000007abcdeffedcbc"), Some(name));
    }

    #[test]
    fn a_family_is_found_by_its_prefix() {
        assert_eq!(description("{04271989-0000-0000-0000-000000000000}"), Some("OneDrive (per-account sync root)"));
    }

    #[test]
    fn unknown_or_invalid_guids_are_unmapped() {
        let guid = "{00000000-0000-0000-0000-000000000001}";
        assert_eq!(description_or_unmapped(guid), format!("Unmapped GUID: {guid}"));
        assert_eq!(description_or_unmapped("nope"), "Unmapped GUID: nope");
    }
}
