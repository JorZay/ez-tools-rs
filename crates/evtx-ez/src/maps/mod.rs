//! EvtxECmd maps: YAML files (`Channel_Provider_EventID.map`) that pick values out of events into the mapped
//! fields (UserName, RemoteHost, ExecutableInfo, PayloadData1-6, MapDescription).
//!
//! A map's `Maps` combine XPath `Values` into a property with `PropertyValue` (`%name%` placeholders); its `Lookups`
//! translate values; a value's `Refine` regex keeps only what it matches.

pub mod model;
pub mod xpath;

use std::collections::HashMap;
use std::path::Path;

use model::EventLogMap;
use xpath::{NavDoc, XPath};

use crate::record::EventRecord;
use crate::{Diagnostic, Level};

/// .NET's message for a null reference, which a map with missing parts gives for each event it is used for
const NULL_REFERENCE: &str = "Object reference not set to an instance of an object.";

struct CompiledValue {
    name: Option<String>,
    source: String,
    xpath: XPath,
    /// None when there is no Refine, or it is not a valid regex (it is then not used)
    refine: Option<fancy_regex::Regex>,
}

struct CompiledEntry {
    property: String,
    property_value: String,
    values: Option<Vec<CompiledValue>>,
}

struct CompiledMap {
    map: EventLogMap,
    entries: Option<Vec<CompiledEntry>>,
}

/// Maps that could not be used, and other messages, from loading maps
#[derive(Debug, Default, Clone)]
pub struct LoadReport {
    /// File name and what is wrong with it (errors stop EvtxECmd)
    pub errors: Vec<(String, Vec<String>)>,
    /// Maps skipped because one for the same event was loaded already
    pub warnings: Vec<String>,
}

impl LoadReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Loaded maps, keyed by event id, channel and provider
#[derive(Default)]
pub struct MapSet {
    maps: HashMap<String, CompiledMap>,
}

impl std::fmt::Debug for MapSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapSet").field("len", &self.maps.len()).finish()
    }
}

/// .NET's ToUpperInvariant: each character's simple uppercase
fn upper_invariant(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut u = c.to_uppercase();
            match (u.next(), u.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        })
        .collect()
}

fn key(event_id: i32, channel: &str, provider: &str) -> String {
    format!("{event_id}-{}-{}", upper_invariant(channel), upper_invariant(provider))
}

impl MapSet {
    /// Every `*.map` in a folder (not its subfolders)
    pub fn load_dir(path: impl AsRef<Path>) -> std::io::Result<(MapSet, LoadReport)> {
        let mut sources = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".map") && entry.file_type()?.is_file() {
                let bytes = std::fs::read(entry.path())?;
                sources.push((name, String::from_utf8_lossy(&bytes).trim_start_matches('\u{FEFF}').to_string()));
            }
        }
        Ok(Self::from_sources(sources.iter().map(|(n, t)| (n.as_str(), t.as_str()))))
    }

    /// Maps from file names and their text. They are added in name order; a second map for the same event (id,
    /// channel and provider) is skipped with a warning.
    pub fn from_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> (MapSet, LoadReport) {
        use rayon::prelude::*;
        let mut sources: Vec<_> = sources.into_iter().collect();
        sources.sort_by(|a, b| a.0.cmp(b.0));
        let parsed: Vec<_> = sources.par_iter().map(|(_, text)| model::parse(text)).collect();

        let mut set = MapSet::default();
        let mut report = LoadReport::default();
        for ((name, _), map) in sources.iter().zip(parsed) {
            let map = match map {
                Ok(m) => m,
                Err(e) => {
                    report.errors.push((name.to_string(), vec![format!("Syntax error: {e}")]));
                    continue;
                }
            };
            let mut errors = model::validate(&map);
            let compiled = if errors.is_empty() { compile(map, &mut errors) } else { None };
            let Some(compiled) = compiled else {
                report.errors.push((name.to_string(), errors));
                continue;
            };
            let m = &compiled.map;
            let (channel, provider) = (m.channel.as_deref().unwrap_or(""), m.provider.as_deref().unwrap_or(""));
            let k = key(m.event_id, channel, provider);
            if set.maps.contains_key(&k) {
                report.warnings.push(format!(
                    "A map for event id {} with Channel {channel} and Provider {provider} already exists. Map {name} will be skipped",
                    m.event_id
                ));
                continue;
            }
            set.maps.insert(k, compiled);
        }
        (set, report)
    }

    pub fn len(&self) -> usize {
        self.maps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// Fills the record's mapped fields from its map, if there is one. An error (from a map with missing parts)
    /// means the record could not be read, as in EvtxECmd.
    pub(crate) fn apply(&self, r: &mut EventRecord, diagnostics: &mut Vec<Diagnostic>) -> Result<(), String> {
        if self.maps.is_empty() {
            return Ok(());
        }
        let (Some(channel), Some(provider)) = (&r.channel, &r.provider) else {
            return Ok(());
        };
        let Some(cm) = self.maps.get(&key(r.event_id, channel, provider)) else {
            return Ok(());
        };
        let map = &cm.map;

        let mut assignments: Vec<(String, String)> = Vec::new();
        {
            let doc = NavDoc::new(r.root());
            let entries = cm.entries.as_ref().ok_or(NULL_REFERENCE)?;
            for entry in entries {
                let values = entry.values.as_ref().ok_or(NULL_REFERENCE)?;
                let mut props: Vec<(String, Option<String>)> = Vec::new();
                for me in values {
                    let value: Option<String> = match me.xpath.map_value(&doc) {
                        Some(mut v) => {
                            if let Some(re) = &me.refine {
                                let matched: Vec<&str> =
                                    re.find_iter(&v).filter_map(|m| m.ok()).map(|m| m.as_str()).collect();
                                if !matched.is_empty() {
                                    v = matched.join(" | ");
                                }
                            }
                            lookup(map, me.name.as_deref(), v)?
                        }
                        None => {
                            diagnostics.push(Diagnostic {
                                level: Level::Warning,
                                message: format!(
                                    "Record # {} (Event Record Id: {}): In map for event {}, Property {} not found! Replacing with empty string",
                                    r.record_number,
                                    r.event_record_id.as_deref().unwrap_or(""),
                                    map.event_id,
                                    me.source
                                ),
                            });
                            Some(String::new())
                        }
                    };
                    let name = me.name.clone().ok_or("Value cannot be null. (Parameter 'key')")?;
                    match props.iter_mut().find(|(k, _)| *k == name) {
                        Some(p) => p.1 = value,
                        None => props.push((name, value)),
                    }
                }

                // we have the values, now substitute
                let mut property_value = entry.property_value.clone();
                for (k, v) in &props {
                    property_value = property_value.replace(&format!("%{k}%"), v.as_deref().unwrap_or(""));
                }
                if props.is_empty() {
                    // prevents variables from showing up in the CSV
                    continue;
                }
                assignments.push((upper_invariant(&entry.property), property_value));
            }
        }

        r.map_description = map.description.clone();
        for (property, value) in assignments {
            match property.as_str() {
                "USERNAME" => r.user_name = Some(value),
                "REMOTEHOST" => r.remote_host = Some(value),
                "EXECUTABLEINFO" => r.executable_info = Some(value),
                "PAYLOADDATA1" => r.payload_data[0] = Some(value),
                "PAYLOADDATA2" => r.payload_data[1] = Some(value),
                "PAYLOADDATA3" => r.payload_data[2] = Some(value),
                "PAYLOADDATA4" => r.payload_data[3] = Some(value),
                "PAYLOADDATA5" => r.payload_data[4] = Some(value),
                "PAYLOADDATA6" => r.payload_data[5] = Some(value),
                _ => diagnostics.push(Diagnostic {
                    level: Level::Warning,
                    message: format!("Unknown property name {property}! Dropping mapping value of {value}"),
                }),
            }
        }
        Ok(())
    }
}

/// A value through the map's lookup for it (when there is one): the lookup's value, or its default and the value
fn lookup(map: &EventLogMap, name: Option<&str>, value: String) -> Result<Option<String>, String> {
    let Some(lookups) = &map.lookups else {
        return Ok(Some(value));
    };
    let mut found = None;
    for l in lookups {
        let l = l.as_ref().ok_or(NULL_REFERENCE)?;
        let (Some(ln), Some(n)) = (&l.name, name) else {
            return Err(NULL_REFERENCE.into());
        };
        if upper_invariant(ln) == upper_invariant(n) {
            if found.is_some() {
                return Err("Sequence contains more than one matching element".into());
            }
            found = Some(l);
        }
    }
    let Some(l) = found else {
        return Ok(Some(value));
    };
    let values = l.values.as_ref().ok_or(NULL_REFERENCE)?;
    Ok(match values.iter().find(|(k, _)| *k == value) {
        Some((_, looked)) => looked.clone(),
        None => Some(format!("{} ({value})", l.default.as_deref().unwrap_or(""))),
    })
}

/// Compiles the XPaths and Refine regexes; None (with the errors) when an XPath is not valid
fn compile(map: EventLogMap, errors: &mut Vec<String>) -> Option<CompiledMap> {
    let entries = map.maps.as_ref().map(|maps| {
        maps.iter()
            .flatten()
            .map(|m| CompiledEntry {
                property: m.property.clone().unwrap_or_default(),
                property_value: m.property_value.clone().unwrap_or_default(),
                values: m.values.as_ref().map(|values| {
                    values
                        .iter()
                        .flatten()
                        .filter_map(|v| {
                            let source = v.value.clone().unwrap_or_default();
                            match XPath::compile(&source) {
                                Ok(xpath) => Some(CompiledValue {
                                    name: v.name.clone(),
                                    refine: v
                                        .refine
                                        .as_deref()
                                        .filter(|r| !r.is_empty())
                                        .and_then(|r| fancy_regex::Regex::new(&format!("(?i){r}")).ok()),
                                    source,
                                    xpath,
                                }),
                                Err(e) => {
                                    errors.push(format!(
                                        "Value {} is not a valid XPath ({source}): {e}",
                                        v.name.as_deref().unwrap_or("")
                                    ));
                                    None
                                }
                            }
                        })
                        .collect()
                }),
            })
            .collect()
    });
    if !errors.is_empty() {
        return None;
    }
    Some(CompiledMap { map, entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_as_yamldotnet_reads_it() {
        let m = model::parse(
            "Author: me\nDescription: d\nEventId: 7\nChannel: C\nProvider: P\nMaps:\n  -\n    Property: PayloadData1\n    PropertyValue: \"%a%\"\n    Values:\n      -\n        Name: a\n        Value: \"/Event/EventData/Data[@Name=\\\"A\\\"]\"\n        Refine:\nLookups:\n  -\n    Name: a\n    Default: Unknown\n    Values:\n      0x10: sixteen\n      012: twelve\n",
        )
        .unwrap();
        assert_eq!(m.event_id, 7);
        let v = m.maps.as_ref().unwrap()[0].as_ref().unwrap().values.as_ref().unwrap()[0].clone().unwrap();
        assert_eq!(v.value.as_deref(), Some("/Event/EventData/Data[@Name=\"A\"]"));
        assert_eq!(v.refine, None);
        let l = m.lookups.as_ref().unwrap()[0].as_ref().unwrap();
        assert_eq!(l.values.as_ref().unwrap()[0].0, "0x10");
        assert_eq!(l.values.as_ref().unwrap()[1].0, "012");
        assert!(model::validate(&m).is_empty());
    }

    #[test]
    fn unknown_properties_and_bad_maps() {
        assert!(model::parse("Author: me\nColour: blue\n").unwrap_err().contains("Property 'Colour' not found"));
        let m = model::parse("EventId: 1\nChannel: C\nProvider: P\nDescription: d\nMaps:\n  -\n    Property: Bogus\n    PropertyValue: x\n").unwrap();
        let errors = model::validate(&m);
        assert!(errors.iter().any(|e| e.contains("'Author' must not be empty")));
        assert!(errors.iter().any(|e| e.contains("must be one of the following")));
    }

    #[test]
    fn repo_maps_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../maps");
        let (set, report) = MapSet::load_dir(dir).unwrap();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(set.len(), 472);
    }
}
