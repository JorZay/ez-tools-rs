//! Evidence of programs running: TaskCache's scheduled tasks and AppCompatFlags' LZNT1 compressed paths.

use ez_common::net::{self, NetResult};
use registry_ez::cells::filetime;
use registry_ez::{Hive, KeyId, VkId};

use crate::helpers::{data, path, row, subkeys, time, unicode_at, utf16_len, value, values};
use crate::{Cell, Output, ValuesOut};

pub fn task_cache(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &task in subkeys(hive, key) {
        let name = hive.key_name(task).to_string();
        match read_task(hive, task, &name) {
            Ok(Some(row)) => out.rows.push(row),
            Ok(None) => {}
            Err(e) => out.errors.push(format!("Error processing TaskCache key '{name}': {e}")),
        }
    }
    Ok(())
}

fn optional_data(hive: &Hive, v: Option<VkId>) -> NetResult<Option<String>> {
    v.map(|v| data(hive, v)).transpose()
}

fn read_task(hive: &Hive, task: KeyId, name: &str) -> NetResult<Option<ValuesOut>> {
    let source = value(hive, task, "Source")?;
    let author = value(hive, task, "Author")?;
    let description = value(hive, task, "Description")?;
    let security_descriptor = value(hive, task, "SecurityDescriptor")?;
    let task_path = value(hive, task, "Path")?;
    let actions = value(hive, task, "Actions")?;

    let Some(dynamic_info) = value(hive, task, "DynamicInfo")? else { return Ok(None) };
    let raw = hive.value_raw(dynamic_info)?;
    // 0x1C bytes (Windows 7: no last stop time) or 0x24
    if raw.len() < 0x1C {
        return Err(format!("DynamicInfo has {} bytes, not at least 28", raw.len()));
    }
    let version = net::i32_at(&raw, 0)?;
    let created = filetime(net::i64_at(&raw, 4)?)?;
    let last_start = positive_time(net::i64_at(&raw, 0xC)?)?;
    let last_stop = if raw.len() >= 0x24 { positive_time(net::i64_at(&raw, 0x1C)?)? } else { None };
    let last_action_result = net::i32_at(&raw, 0x18)?;
    let task_state = net::i32_at(&raw, 0x14)?;

    let (command, arguments) = match actions {
        Some(v) => {
            let raw = hive.value_raw(v)?;
            if raw.len() >= 4 {
                // what was read before a failure stays only in the original's fields it reaches: command is overwritten
                // and arguments, the last thing it reads, is never set
                read_actions(&raw).unwrap_or_else(|_| ("Error parsing Actions binary".to_string(), String::new()))
            } else {
                Default::default()
            }
        }
        None => Default::default(),
    };

    let source = optional_data(hive, source)?;
    let description = optional_data(hive, description)?;
    let security_descriptor = optional_data(hive, security_descriptor)?;
    let author = optional_data(hive, author)?;
    let task_path = optional_data(hive, task_path)?;

    let data2 = format!("Last start: {}, Last stop: {}", time(last_start), time(last_stop));
    let data3 = format!("Path: {}, Command: {command}, Arguments: {arguments}", task_path.as_deref().unwrap_or(""));
    Ok(Some(row(
        vec![
            ("Version", version.into()),
            ("KeyName", name.into()),
            ("Path", task_path.into()),
            ("CreatedOn", created.into()),
            ("LastStart", last_start.into()),
            ("LastStop", last_stop.into()),
            ("TaskState", task_state.into()),
            ("LastActionResult", last_action_result.into()),
            ("Source", source.into()),
            ("Description", description.into()),
            ("Command", command.into()),
            ("Arguments", arguments.into()),
            ("SecurityDescriptor", security_descriptor.into()),
            ("Author", author.into()),
        ],
        Some(path(hive, task)),
        Some(hive.vks[dynamic_info].name()?.to_string()),
        format!("Created on: {}", time(Some(created))),
        Some(data2),
        Some(data3),
    )))
}

fn positive_time(raw: i64) -> NetResult<Option<ez_common::Timestamp>> {
    if raw > 0 { filetime(raw).map(Some) } else { Ok(None) }
}

/// A command or its arguments, if its length is one and fits. The sums are C#'s ints, which wrap
fn action_text(raw: &[u8], offset: i32, length: i32) -> NetResult<String> {
    if length > 0 && offset.wrapping_add(length) <= raw.len() as i32 {
        Ok(unicode_at(raw, i64::from(offset), i64::from(length))?.trim_end_matches('\0').to_string())
    } else {
        Ok(String::new())
    }
}

/// The command and arguments of an Execution Action (0x6666), after the context
fn read_actions(raw: &[u8]) -> NetResult<(String, String)> {
    let context_length = net::i32_at(raw, 2)?;
    let magic_offset = context_length.wrapping_add(6);
    if magic_offset.wrapping_add(2) > raw.len() as i32 || net::i16_at(raw, i64::from(magic_offset))? != 0x6666 {
        return Ok(Default::default());
    }
    let command_length_offset = magic_offset.wrapping_add(6);
    let command_length = net::i32_at(raw, i64::from(command_length_offset))?;
    let command_offset = command_length_offset.wrapping_add(4);
    let command = action_text(raw, command_offset, command_length)?;
    let arguments_length_offset = command_offset.wrapping_add(command_length);
    let arguments_length = net::i32_at(raw, i64::from(arguments_length_offset))?;
    let arguments = action_text(raw, arguments_length_offset.wrapping_add(4), arguments_length)?;
    Ok((command, arguments))
}

pub fn app_compat_flags(hive: &Hive, key: KeyId, out: &mut Output) -> NetResult<()> {
    for &v in values(hive, key) {
        if let Err(e) = read_compressed_paths(hive, key, v, out) {
            out.errors.push(format!("Error processing AppCompatFlags value '{}': {e}", hive.vks[v].name()?));
        }
    }
    Ok(())
}

fn read_compressed_paths(hive: &Hive, key: KeyId, v: VkId, out: &mut Output) -> NetResult<()> {
    let raw = hive.value_raw(v)?;
    if raw.len() < 8 {
        return Ok(());
    }
    // compressed size, decompressed size, LZNT1 data
    let compressed_size = net::i32_at(&raw, 0)?;
    let decompressed_size = net::i32_at(&raw, 4)?;
    if compressed_size <= 0 || decompressed_size <= 0 || decompressed_size > 0x100_0000 {
        return Ok(());
    }
    let decompressed = lznt1_decompress(&raw, 8, compressed_size, decompressed_size as usize);
    let text = net::utf16(&decompressed[..decompressed.len() & !1]);
    let Some(start) = text.find("\\DEV") else { return Ok(()) };
    let name = hive.vks[v].name()?;
    for executable in text[start..].split('\0') {
        if utf16_len(executable) < 8 {
            continue;
        }
        out.rows.push(row(
            vec![("Executable", executable.into()), ("ValueName", Cell::Text(Some(name.to_string())))],
            Some(path(hive, key)),
            None,
            executable.to_string(),
            Some(String::new()),
            Some(String::new()),
        ));
    }
    Ok(())
}

/// LZNT1 ([MS-XCA] 2.5), as the plugin's own decompressor reads it: what it writes, at most `capacity` bytes. Damage ends
/// the data rather than failing it.
fn lznt1_decompress(data: &[u8], offset: i32, count: i32, capacity: usize) -> Vec<u8> {
    const CHUNK_SIZE: usize = 0x1000;
    // offset + count is an int: with a count near its limit it is negative, so nothing is read
    let Ok(end) = usize::try_from(offset.wrapping_add(count)) else { return Vec::new() };
    let end = end.min(data.len());
    let mut pos = offset as usize;
    let mut output = Vec::new();

    while pos + 2 <= end {
        let header = usize::from(u16::from_le_bytes([data[pos], data[pos + 1]]));
        pos += 2;
        // a zero header ends the data
        if header == 0 {
            break;
        }
        let chunk_end = end.min(pos + (header & 0x0FFF) + 1);
        let chunk_start = output.len();

        if header & 0x8000 == 0 {
            let length = (chunk_end - pos).min(capacity - output.len());
            output.extend_from_slice(&data[pos..pos + length]);
            pos = chunk_end;
            continue;
        }

        while pos < chunk_end && output.len() < capacity {
            let mut flags = data[pos];
            pos += 1;
            let mut bit = 0;
            while bit < 8 && pos < chunk_end && output.len() < capacity {
                if flags & 1 == 0 {
                    output.push(data[pos]);
                    pos += 1;
                } else {
                    if pos + 2 > chunk_end {
                        return output;
                    }
                    let token = usize::from(u16::from_le_bytes([data[pos], data[pos + 1]]));
                    pos += 2;
                    // the further into the chunk, the more bits the displacement has (4 to 12)
                    let mut length_bits = 12;
                    let mut written = (output.len() - chunk_start).wrapping_sub(1) as isize;
                    while written >= 0x10 {
                        length_bits -= 1;
                        written >>= 1;
                    }
                    let displacement = (token >> length_bits) + 1;
                    let copy_length = (token & ((1 << length_bits) - 1)) + 3;
                    if displacement > output.len() - chunk_start {
                        return output;
                    }
                    // byte by byte, as the copy can overlap what it writes
                    let mut copied = 0;
                    while copied < copy_length && output.len() < capacity && output.len() - chunk_start < CHUNK_SIZE {
                        output.push(output[output.len() - displacement]);
                        copied += 1;
                    }
                }
                bit += 1;
                flags >>= 1;
            }
        }
        pos = chunk_end;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::lznt1_decompress;

    fn run(data: &[u8], capacity: usize) -> Vec<u8> {
        lznt1_decompress(data, 0, data.len() as i32, capacity)
    }

    #[test]
    fn an_uncompressed_chunk_is_copied_up_to_the_capacity() {
        let data = [0x03, 0x30, b'a', b'b', b'c', b'd'];
        assert_eq!(run(&data, 10), b"abcd");
        assert_eq!(run(&data, 2), b"ab");
    }

    #[test]
    fn a_token_copies_what_it_overlaps() {
        // a literal, then a copy of 5 from one byte back: displacement 1 is 0, length 5 is 2
        let data = [0x03, 0xB0, 0b10, b'x', 0x02, 0x00];
        assert_eq!(run(&data, 10), b"xxxxxx");
    }

    #[test]
    fn a_displacement_before_the_chunk_ends_the_data() {
        let data = [0x03, 0xB0, 0b10, b'x', 0x02, 0xF0];
        assert_eq!(run(&data, 10), b"x");
    }

    #[test]
    fn a_zero_header_ends_the_data() {
        assert_eq!(run(&[0, 0, 3, 0x30, 1, 2, 3, 4], 10), b"");
    }

    #[test]
    fn a_count_that_overflows_reads_nothing() {
        assert_eq!(lznt1_decompress(&[3, 0x30, 1, 2, 3, 4], 8, i32::MAX, 10), b"");
    }
}
