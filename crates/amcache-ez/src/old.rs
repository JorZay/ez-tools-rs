//! AmcacheOld: `Root\File` and `Root\Programs` (Windows 7 and 8, and hives upgraded from them).

use std::collections::HashMap;

use ez_common::{Level, Timestamp};
use registry_ez::{Hive, KeyId, VkId};

use crate::parse;
use crate::{Error, Observer, Sink, open_hive};

const NOT_SET: &str = "Object reference not set to an instance of an object.";

#[derive(Debug, Clone, Default)]
pub struct FileEntryOld {
    pub mft_entry_number: i32,
    pub mft_sequence_number: i32,
    pub product_name: String,
    pub company_name: String,
    pub file_version_string: String,
    pub file_version_number: String,
    pub file_description: String,
    pub full_path: String,
    pub file_extension: String,
    pub pe_header_hash: String,
    pub program_id: String,
    pub sha1: String,
    pub file_id: String,
    pub volume_id: String,
    pub switch_back_context: String,
    pub program_name: String,
    pub bin_product_version: i64,
    pub bin_file_version: u64,
    pub linker_version: i32,
    pub binary_type: i32,
    pub is_local: i32,
    pub guess_program_id: i32,
    pub language_id: Option<i32>,
    pub file_size: Option<i32>,
    pub size_of_image: Option<i32>,
    pub pe_header_checksum: Option<u32>,
    pub volume_id_last_write: Timestamp,
    pub file_id_last_write: Timestamp,
    pub link_date: Option<Timestamp>,
    pub last_modified: Option<Timestamp>,
    pub last_modified_store: Option<Timestamp>,
    pub created: Option<Timestamp>,
}

#[derive(Debug, Clone, Default)]
pub struct ProgramsEntryOld {
    pub program_name_0: String,
    pub program_version_1: String,
    pub vendor_name_2: String,
    pub language_code_3: String,
    pub install_source_6: String,
    pub uninstall_registry_key_7: String,
    pub unknown_guid_10: String,
    pub unknown_guid_12: String,
    pub uninstall_guid_11: String,
    pub unknown_dword_5: i32,
    pub unknown_dword_13: i32,
    pub unknown_dword_14: i32,
    pub unknown_dword_15: i32,
    pub unknown_bytes_16: Vec<u8>,
    pub unknown_qword_17: i64,
    pub unknown_dword_18: i32,
    pub install_date_epoch_a: Option<Timestamp>,
    pub install_date_epoch_b: Option<Timestamp>,
    pub paths_list_d: String,
    pub uninstall_guid_f: String,
    pub program_id: String,
    pub last_write: Timestamp,
    pub file_entries: Vec<FileEntryOld>,
}

pub struct AmcacheOld {
    pub unassociated_file_entries: Vec<FileEntryOld>,
    pub programs_entries: Vec<ProgramsEntryOld>,
    pub total_file_entries: i32,
    /// Keys that could not be parsed and were left out
    pub entries_not_parsed: i32,
}

fn data(hive: &Hive, v: VkId, sink: &Sink) -> Result<String, String> {
    let text = hive.value_data(v)?.text(hive.date_culture);
    sink.drain(hive);
    Ok(text)
}

/// The ctor's check of the Files value (each `source@file` chunk, up to the first empty one)
fn check_files(raw: &str) -> Result<(), String> {
    for chunk in raw.split(' ') {
        if chunk.trim().is_empty() {
            break;
        }
        if !chunk.contains('@') {
            return Err("Index was outside the bounds of the array.".into());
        }
    }
    Ok(())
}

/// The MFT sequence and entry numbers in a key name, as FileEntryOld's ctor reads them. The trailing zeros of the
/// sequence's four digits are dropped: that is how the original gets `2` from `0002` and from `2000`
fn mft_numbers(key_name: &str) -> Result<(i32, i32), String> {
    let chars: Vec<char> = key_name.chars().collect();
    let padded: Vec<char> = std::iter::repeat_n('0', 8usize.saturating_sub(chars.len())).chain(chars).collect();
    let first: String = padded[..4].iter().collect();
    let rest: String = padded[4..].iter().collect();
    let seq = first.trim_end_matches('0');
    let seq = if seq.is_empty() { "0" } else { seq };
    Ok((parse::convert_to_int32_hex(seq)?, parse::convert_to_int32_hex(&rest)?))
}

impl AmcacheOld {
    pub fn open(path: &str, no_logs: bool, observer: Observer) -> Result<AmcacheOld, Error> {
        let sink = Sink::new(observer);
        let hive = open_hive(path, no_logs, false, &sink)?;
        let mut am = AmcacheOld { unassociated_file_entries: vec![], programs_entries: vec![], total_file_entries: 0, entries_not_parsed: 0 };

        let (Some(file_key), Some(programs_key)) = (hive.get_key("Root\\File"), hive.get_key("Root\\Programs")) else {
            sink.log(Level::Error, "Hive does not contain a File and/or Programs key. Processing cannot continue");
            return Ok(am);
        };

        sink.log(Level::Debug, "Getting Programs data");
        for &key in &hive.keys[programs_key].subkeys {
            match read_program(&hive, key, &sink) {
                Ok(p) => am.programs_entries.push(p),
                Err(e) => am.report("ProgramsEntry", &hive, key, &e, &sink),
            }
        }

        // ProgramsEntries.SingleOrDefault: how many programs have each id
        let mut programs: HashMap<String, (usize, usize)> = HashMap::new();
        for (i, p) in am.programs_entries.iter().enumerate() {
            programs.entry(p.program_id.clone()).or_insert((i, 0)).1 += 1;
        }

        sink.log(Level::Debug, "Getting Files data");
        for &volume in &hive.keys[file_key].subkeys {
            for &file in &hive.keys[volume].subkeys {
                if let Err(e) = am.read_file(&hive, volume, file, &programs, &sink) {
                    am.report("FileEntry", &hive, file, &e, &sink);
                }
            }
        }
        Ok(am)
    }

    fn report(&mut self, category: &str, hive: &Hive, key: KeyId, message: &str, sink: &Sink) {
        self.entries_not_parsed += 1;
        sink.log(Level::Error, &format!("Error parsing {category} at {}. Error: {message}", hive.keys[key].path));
        sink.log(Level::Error, "Please send the following text to saericzimmerman@gmail.com");
        // Serilog catches what ToString() throws and logs this instead
        let text = registry_ez::details::key_text(hive, key).unwrap_or_else(|e| {
            let exception = if e.starts_with("Unable to cast") { "InvalidCastException" } else { "ArgumentException" };
            format!("Capturing the property value threw an exception: {exception}")
        });
        sink.drain(hive);
        sink.log(Level::Error, &format!("Key data: {text}"));
    }

    fn read_file(&mut self, hive: &Hive, volume: KeyId, file: KeyId, programs: &HashMap<String, (usize, usize)>, sink: &Sink) -> Result<(), String> {
        let single = |id: &str| -> Result<Option<usize>, String> {
            match programs.get(id) {
                None => Ok(None),
                Some((_, n)) if *n > 1 => Err("Sequence contains more than one matching element".into()),
                Some((i, _)) => Ok(Some(*i)),
            }
        };
        let mut e = FileEntryOld::default();
        let mut sha = String::new();
        let mut linked = false;

        for &v in &hive.keys[file].values {
            let name = hive.vks[v].name()?.to_string();
            let key_val = parse::int_hex(&name)?;
            let d = || data(hive, v, sink);
            match key_val {
                0 => e.product_name = d()?,
                0x1 => e.company_name = d()?,
                0x2 => e.file_version_number = d()?,
                0x3 => e.language_id = Some(parse::int(&d()?)?),
                0x4 => e.switch_back_context = d()?,
                0x5 => e.file_version_string = d()?,
                0x6 => e.file_size = Some(parse::int(&d()?)?),
                0x7 => e.size_of_image = Some(parse::int(&d()?)?),
                0x8 => e.pe_header_hash = d()?,
                0x9 => e.pe_header_checksum = Some(parse::uint(&d()?)?),
                0xa => e.bin_product_version = parse::long(&d()?)?,
                0xb => e.bin_file_version = parse::ulong(&d()?)?,
                0xc => e.file_description = d()?,
                0xd => e.linker_version = parse::int(&d()?)?,
                0xf => e.link_date = Some(parse::from_unix_seconds(parse::long(&d()?)?)?),
                0x10 => e.binary_type = parse::int(&d()?)?,
                0x11 => e.last_modified = Some(parse::from_file_time(parse::long(&d()?)?)?),
                0x12 => e.created = Some(parse::from_file_time(parse::long(&d()?)?)?),
                0x15 => e.full_path = d()?,
                0x16 => e.is_local = parse::int(&d()?)?,
                0x106 => e.guess_program_id = parse::int(&d()?)?,
                0x17 => e.last_modified_store = Some(parse::from_file_time(parse::long(&d()?)?)?),
                0x100 => {
                    e.program_id = d()?;
                    if single(&e.program_id)?.is_some() {
                        linked = true;
                    }
                }
                0x101 => sha = d()?,
                other => sink.log(
                    Level::Warning,
                    &format!("Unknown value name when processing FileEntry at path {}: 0x{other:X}", hive.keys[file].path),
                ),
            }
        }

        if e.full_path.is_empty() {
            return Ok(());
        }

        self.total_file_entries += 1;

        if sha.chars().count() > 4 {
            e.sha1 = ez_common::dotnet::lower_invariant(&sha.chars().skip(4).collect::<String>());
        }
        e.file_extension = parse::windows_extension(&e.full_path).to_string();
        e.file_id = hive.key_name(file).to_string();
        e.file_id_last_write = hive.nk(file).last_write()?;
        e.volume_id = hive.key_name(volume).to_string();
        e.volume_id_last_write = hive.nk(volume).last_write()?;
        (e.mft_sequence_number, e.mft_entry_number) = mft_numbers(hive.key_name(file))?;

        if linked {
            let program = single(&e.program_id)?.ok_or(NOT_SET)?;
            e.program_name = self.programs_entries[program].program_name_0.clone();
            self.programs_entries[program].file_entries.push(e);
        } else {
            e.program_name = "Unassociated".into();
            self.unassociated_file_entries.push(e);
        }
        Ok(())
    }
}

fn read_program(hive: &Hive, key: KeyId, sink: &Sink) -> Result<ProgramsEntryOld, String> {
    let mut p = ProgramsEntryOld { program_id: hive.key_name(key).to_string(), ..Default::default() };
    let mut raw_files = String::new();
    let seconds = |text: String| -> Result<Option<Timestamp>, String> {
        let s = parse::long(&text)?;
        if s > 0 { parse::from_unix_seconds(s).map(Some) } else { Ok(None) }
    };

    for &v in &hive.keys[key].values {
        let name = hive.vks[v].name()?.to_string();
        let d = || data(hive, v, sink);
        match name.as_str() {
            "0" => p.program_name_0 = d()?,
            "1" => p.program_version_1 = d()?,
            "2" => p.vendor_name_2 = d()?,
            "3" => p.language_code_3 = d()?,
            "5" => p.unknown_dword_5 = parse::int(&d()?)?,
            "6" => p.install_source_6 = d()?,
            "7" => p.uninstall_registry_key_7 = d()?,
            // sometimes the number is way too big, and it is left empty
            "a" => {
                if let Ok(Some(t)) = seconds(d()?) {
                    p.install_date_epoch_a = Some(t);
                }
            }
            "b" => p.install_date_epoch_b = seconds(d()?)?.or(p.install_date_epoch_b),
            "d" => p.paths_list_d = d()?,
            "f" => p.uninstall_guid_f = d()?,
            "10" => p.unknown_guid_10 = d()?,
            "11" => p.uninstall_guid_11 = d()?,
            "12" => p.unknown_guid_12 = d()?,
            // as in the original, 14 and 15 are stored in the variable of 13 and the Dword14 and 15 columns stay 0
            "13" | "14" | "15" => p.unknown_dword_13 = parse::int(&d()?)?,
            "16" => p.unknown_bytes_16 = hive.value_raw(v)?,
            "17" => p.unknown_qword_17 = parse::long(&d()?)?,
            "18" => p.unknown_dword_18 = parse::int(&d()?)?,
            "Files" => raw_files = d()?,
            _ => sink.log(Level::Warning, &format!("Unknown value name in Program at path {}: {name}", hive.keys[key].path)),
        }
    }

    check_files(&raw_files)?;
    p.last_write = hive.nk(key).last_write()?;
    Ok(p)
}
