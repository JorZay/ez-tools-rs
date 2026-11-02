//! Transaction log replay (LogReplay): the new format (HvLE entries, .LOG1/.LOG2, Windows 8.1 and later) and the
//! old one (a DIRT bitmap of dirty pages), as the Registry library applies them.

use ez_common::Level;

const BASE_BLOCK_SIZE: usize = 4096;
const LOG_BASE_BLOCK_SIZE: usize = 512;
const HIVE_BIN_ALIGNMENT: u32 = 4096;
const MARVIN_SEED: u64 = 0x82EF4D887A4E55C5;

/// A transaction log's name and bytes
pub struct LogFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub struct ReplayResult {
    pub bytes: Option<Vec<u8>>,
    pub recovered: bool,
    pub last_sequence_number: Option<u32>,
    pub logs_applied: Vec<String>,
    pub messages: Vec<String>,
    /// Debug messages ("stopping at offset...")
    pub debug: Vec<(Level, String)>,
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn i64le(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[derive(Clone)]
struct BaseBlock {
    valid: bool,
    dirty: bool,
    primary_sequence: u32,
    secondary_sequence: u32,
    last_written: i64,
    hive_bins_data_size: u32,
    flags: u32,
}

impl BaseBlock {
    fn new(b: &[u8], primary: bool) -> BaseBlock {
        let valid = b.len() >= 512 && u32le(b, 508) == checksum(b) && &b[0..4] == b"regf";
        let primary_sequence = u32le(b, 4);
        let secondary_sequence = u32le(b, 8);
        let mut last_written = i64le(b, 12);
        let mut hive_bins_data_size = u32le(b, 40);
        let flags = if b.len() >= 148 { u32le(b, 144) } else { 0 };
        if primary && !valid {
            hive_bins_data_size = ((b.len() - BASE_BLOCK_SIZE.min(b.len())) / 4096 * 4096) as u32;
            last_written = if b.len() >= BASE_BLOCK_SIZE + 0x1C { i64le(b, BASE_BLOCK_SIZE + 0x14) } else { 0 };
        }
        BaseBlock {
            valid,
            dirty: !valid || primary_sequence != secondary_sequence,
            primary_sequence,
            secondary_sequence,
            last_written,
            hive_bins_data_size,
            flags,
        }
    }
}

fn checksum(b: &[u8]) -> u32 {
    let mut x = 0u32;
    for i in (0..508).step_by(4) {
        x ^= u32le(b, i);
    }
    match x {
        0 => 1,
        0xFFFFFFFF => 0xFFFFFFFE,
        x => x,
    }
}

struct State<'a> {
    primary: BaseBlock,
    bytes: Vec<u8>,
    apply_count: u32,
    last_sequence: Option<u32>,
    hive_bins_data_size: u32,
    flags: u32,
    old_log_base: Option<&'a [u8]>,
    new_log_base: Option<&'a [u8]>,
    result: ReplayResult,
}

impl State<'_> {
    fn write(&mut self, offset: usize, source: &[u8], source_offset: usize, length: usize) {
        if offset + length > self.bytes.len() {
            self.bytes.resize(offset + length, 0);
        }
        self.bytes[offset..offset + length].copy_from_slice(&source[source_offset..source_offset + length]);
    }
}

/// NotEligibleException's message
struct NotEligible(String);

/// LogReplay.Replay. Logs are matched to .LOG, .LOG1 and .LOG2 by their names; the bytes of the result are None
/// when nothing was applied.
pub fn replay(primary: &[u8], logs: &[LogFile]) -> ReplayResult {
    let result =
        ReplayResult { bytes: None, recovered: false, last_sequence_number: None, logs_applied: vec![], messages: vec![], debug: vec![] };
    let primary_bb = BaseBlock::new(primary, true);
    let mut state = State {
        hive_bins_data_size: primary_bb.hive_bins_data_size,
        flags: primary_bb.flags,
        primary: primary_bb,
        bytes: primary.to_vec(),
        apply_count: 0,
        last_sequence: None,
        old_log_base: None,
        new_log_base: None,
        result,
    };
    if !state.primary.dirty {
        state.result.messages.push("The hive is not dirty".into());
        return state.result;
    }
    let present: Vec<usize> = (0..logs.len()).filter(|&i| !logs[i].bytes.is_empty()).collect();
    let named = |ext: &str| {
        present.iter().copied().find(|&i| logs[i].name.to_uppercase().ends_with(&ext.to_uppercase()))
    };
    let log = named(".LOG");
    let mut log1 = named(".LOG1");
    let mut log2 = named(".LOG2");
    let others: Vec<usize> =
        present.iter().copied().filter(|&i| Some(i) != log && Some(i) != log1 && Some(i) != log2).collect();
    if log1.is_none() {
        log1 = others.first().copied();
    }
    if log2.is_none() {
        let idx = if log1 == others.first().copied() { 1 } else { 0 };
        log2 = others.get(idx).copied();
    }
    let get = |i: Option<usize>| i.map(|i| &logs[i]);
    let (log, log1, log2) = (get(log), get(log1), get(log2));

    let new_log = is_new_log(log, &mut state.result);
    let new_log1 = is_new_log(log1, &mut state.result);
    let new_log2 = is_new_log(log2, &mut state.result);
    let old_log = is_old_log(log, &mut state.result);
    let old_log1 = is_old_log(log1, &mut state.result);
    let old_log2 = is_old_log(log2, &mut state.result);

    let outcome = if new_log1 && new_log2 {
        apply_new_logs(&mut state, log1.unwrap(), log2.unwrap())
    } else if new_log1 || new_log2 {
        apply_new_log(&mut state, if new_log1 { log1.unwrap() } else { log2.unwrap() })
    } else if new_log {
        apply_new_log(&mut state, log.unwrap())
    } else if old_log1 && old_log2 {
        let (l1, l2) = (log1.unwrap(), log2.unwrap());
        let ts1 = BaseBlock::new(&l1.bytes, false).last_written;
        let ts2 = BaseBlock::new(&l2.bytes, false).last_written;
        apply_old_log(&mut state, if ts1 >= ts2 { l1 } else { l2 })
    } else if old_log1 || old_log2 {
        apply_old_log(&mut state, if old_log1 { log1.unwrap() } else { log2.unwrap() })
    } else if old_log {
        apply_old_log(&mut state, log.unwrap())
    } else {
        state.result.messages.push("No transaction log that can be applied was found".into());
        Ok(())
    };
    if let Err(NotEligible(m)) = outcome {
        state.result.messages.push(m);
    }
    if state.apply_count == 0 {
        return state.result;
    }
    state.result.recovered = true;
    state.result.last_sequence_number = state.last_sequence;
    let bytes = finish_base_block(&mut state);
    state.result.bytes = Some(bytes);
    state.result
}

fn is_new_log(log: Option<&LogFile>, result: &mut ReplayResult) -> bool {
    let Some(log) = log else { return false };
    let b = &log.bytes;
    if b.len() <= LOG_BASE_BLOCK_SIZE + 40 || &b[0..4] != b"regf" || u32le(b, 28) != 6 {
        return false;
    }
    if BaseBlock::new(b, false).dirty {
        result.messages.push(format!("{}: its base block is invalid or dirty, so it is not used", file_name(&log.name)));
        return false;
    }
    true
}

fn is_old_log(log: Option<&LogFile>, result: &mut ReplayResult) -> bool {
    let Some(log) = log else { return false };
    let b = &log.bytes;
    if b.len() < LOG_BASE_BLOCK_SIZE + 4 || &b[0..4] != b"regf" {
        return false;
    }
    let t = u32le(b, 28);
    if t != 1 && t != 2 {
        return false;
    }
    let bb = BaseBlock::new(b, false);
    if bb.dirty {
        result.messages.push(format!("{}: its base block is invalid or dirty, so it is not used", file_name(&log.name)));
        return false;
    }
    b.len() as i64 >= dirty_pages_start(bb.hive_bins_data_size) + 512 && &b[LOG_BASE_BLOCK_SIZE..LOG_BASE_BLOCK_SIZE + 4] == b"DIRT"
}

fn is_earlier(a: u32, b: u32) -> bool {
    if a >= b { a - b > 0x7FFFFFFF } else { b - a <= 0x7FFFFFFF }
}

fn apply_new_logs<'a>(state: &mut State<'a>, log1: &'a LogFile, log2: &'a LogFile) -> Result<(), NotEligible> {
    let seq1 = u32le(&log1.bytes, 4);
    let seq2 = u32le(&log2.bytes, 4);
    let (first, second) = if is_earlier(seq1, seq2) { (log1, log2) } else { (log2, log1) };
    if !state.primary.valid {
        return apply_new_log(state, second);
    }
    if let Err(NotEligible(m)) = apply_new_log(state, first) {
        state.result.messages.push(m);
        return apply_new_log(state, second);
    }
    if let Some(last) = state.last_sequence {
        if u32le(&second.bytes, 4) == last.wrapping_add(1) {
            return apply_new_log(state, second);
        }
    }
    Ok(())
}

fn apply_new_log<'a>(state: &mut State<'a>, log: &'a LogFile) -> Result<(), NotEligible> {
    let b = &log.bytes;
    let bb = BaseBlock::new(b, false);
    let name = file_name(&log.name);
    if state.apply_count >= 2 {
        return Err(NotEligible(format!("{name}: no more than two logs can be applied")));
    }
    if let Some(last) = state.last_sequence {
        if is_earlier(bb.primary_sequence, last.wrapping_add(1)) {
            return Err(NotEligible(format!("{name}: its entries are not after the last one applied")));
        }
    }
    if state.primary.valid && is_earlier(bb.primary_sequence, state.primary.secondary_sequence) {
        return Err(NotEligible(format!(
            "{name}: its entries (from sequence number {}) are older than the hive ({})",
            bb.primary_sequence, state.primary.secondary_sequence
        )));
    }
    state.new_log_base = Some(b);
    state.flags = bb.flags;
    let applied = apply_entries(state, b, bb.primary_sequence, name);
    state.apply_count += 1;
    state.result.logs_applied.push(log.name.clone());
    let m = if applied > 0 {
        format!(
            "{name}: applied {} log entries (sequence numbers {} to {})",
            ez_common::dotnet::n0(applied as u64),
            bb.primary_sequence,
            state.last_sequence.map(|s| s.to_string()).unwrap_or_default()
        )
    } else {
        format!("{name}: no log entries to apply")
    };
    state.result.messages.push(m);
    Ok(())
}

fn apply_entries(state: &mut State, b: &[u8], first_sequence: u32, name: &str) -> u32 {
    let mut expected = first_sequence;
    let mut position = LOG_BASE_BLOCK_SIZE;
    let mut applied = 0;
    while position + 40 <= b.len() {
        if let Some(problem) = invalid_entry(b, position, expected) {
            state.result.debug.push((Level::Debug, format!("{name}: stopping at offset 0x{position:X}: {problem}")));
            break;
        }
        let size = u32le(b, position + 4) as usize;
        let count = u32le(b, position + 20) as usize;
        let pages = position + 40 + 8 * count;
        let refs: Vec<(u32, u32)> =
            (0..count).map(|i| (u32le(b, position + 40 + 8 * i), u32le(b, position + 44 + 8 * i))).collect();
        if refs.iter().map(|r| r.1 as u64).sum::<u64>() + pages as u64 > b.len() as u64 {
            state
                .result
                .messages
                .push(format!("{name}: the dirty pages of the entry with sequence number {expected} are past the end of the log"));
            break;
        }
        state.last_sequence = Some(expected);
        state.flags = (state.flags & !1) | (u32le(b, position + 8) & 1);
        state.hive_bins_data_size = u32le(b, position + 16);
        let mut delta = 0usize;
        for (offset, size) in refs {
            state.write(BASE_BLOCK_SIZE + offset as usize, b, pages + delta, size as usize);
            delta += size as usize;
        }
        applied += 1;
        position += size;
        expected = expected.wrapping_add(1);
    }
    applied
}

fn invalid_entry(b: &[u8], position: usize, expected: u32) -> Option<String> {
    if &b[position..position + 4] != b"HvLE" {
        return Some("no log entry signature".into());
    }
    let size = u32le(b, position + 4);
    if size < 512 || size % 512 != 0 {
        return Some(format!("invalid size 0x{size:X}"));
    }
    if position as u64 + size as u64 > b.len() as u64 {
        return Some(format!("the entry (0x{size:X} bytes) is past the end of the log"));
    }
    let hive_bins_data_size = u32le(b, position + 16);
    if hive_bins_data_size < HIVE_BIN_ALIGNMENT || hive_bins_data_size % HIVE_BIN_ALIGNMENT != 0 {
        return Some(format!("invalid hive bins data size 0x{hive_bins_data_size:X}"));
    }
    let count = u32le(b, position + 20);
    if count == 0 || 40 + 8 * count as u64 > size as u64 {
        return Some(format!("invalid dirty pages count {count}"));
    }
    let hash1 = u64le(b, position + 24);
    let hash2 = u64le(b, position + 32);
    if marvin(&b[position..position + 32], MARVIN_SEED) != hash2
        || marvin(&b[position + 40..position + size as usize], MARVIN_SEED) != hash1
    {
        return Some("invalid hashes".into());
    }
    let sequence = u32le(b, position + 12);
    if sequence == expected { None } else { Some(format!("sequence number {sequence} where {expected} was expected")) }
}

fn dirty_pages_start(hive_bins_data_size: u32) -> i64 {
    let unaligned = LOG_BASE_BLOCK_SIZE as i64 + 4 + (hive_bins_data_size / 4096) as i64;
    (unaligned + 511) / 512 * 512
}

fn apply_old_log<'a>(state: &mut State<'a>, log: &'a LogFile) -> Result<(), NotEligible> {
    let b = &log.bytes;
    let bb = BaseBlock::new(b, false);
    let name = file_name(&log.name);
    if bb.last_written < state.primary.last_written {
        return Err(NotEligible(format!("{name}: it is older than the hive")));
    }
    state.old_log_base = Some(b);
    state.hive_bins_data_size = bb.hive_bins_data_size;
    state.flags = bb.flags;
    let bitmap_length = (bb.hive_bins_data_size / 4096) as u64;
    let pages = dirty_pages_start(bb.hive_bins_data_size) as u64;
    let mut n = 0u64;
    let mut applied = 0u64;
    for bit in 0..bitmap_length * 8 {
        if (b[LOG_BASE_BLOCK_SIZE + 4 + (bit / 8) as usize] >> (bit % 8)) & 1 == 0 {
            continue;
        }
        let from = pages + n * 512;
        if from + 512 > b.len() as u64 {
            state.result.messages.push(format!("{name}: dirty page {n} is past the end of the log"));
            break;
        }
        state.write(BASE_BLOCK_SIZE + (bit * 512) as usize, b, from as usize, 512);
        n += 1;
        applied += 1;
    }
    state.apply_count += 1;
    state.result.logs_applied.push(log.name.clone());
    state.result.messages.push(format!("{name}: applied {} dirty pages (old format)", ez_common::dotnet::n0(applied)));
    Ok(())
}

fn finish_base_block(state: &mut State) -> Vec<u8> {
    let mut bytes = std::mem::take(&mut state.bytes);
    let mut base = vec![0u8; BASE_BLOCK_SIZE];
    if state.primary.valid {
        base.copy_from_slice(&bytes[..BASE_BLOCK_SIZE]);
    } else {
        let source = state.old_log_base.or(state.new_log_base).unwrap();
        base[..LOG_BASE_BLOCK_SIZE].copy_from_slice(&source[..LOG_BASE_BLOCK_SIZE]);
    }
    let sequence = state.last_sequence.unwrap_or_else(|| u32le(&base, 4));
    base[4..8].copy_from_slice(&sequence.to_le_bytes());
    base[8..12].copy_from_slice(&sequence.to_le_bytes());
    base[40..44].copy_from_slice(&state.hive_bins_data_size.to_le_bytes());
    base[144..148].copy_from_slice(&state.flags.to_le_bytes());
    base[28..32].copy_from_slice(&0u32.to_le_bytes());
    let c = checksum(&base);
    base[508..512].copy_from_slice(&c.to_le_bytes());
    if bytes.len() < BASE_BLOCK_SIZE {
        bytes.resize(BASE_BLOCK_SIZE, 0);
    }
    bytes[..BASE_BLOCK_SIZE].copy_from_slice(&base);
    bytes
}

/// Marvin32, the hash of log entries
fn marvin(data: &[u8], seed: u64) -> u64 {
    fn block(p0: &mut u32, p1: &mut u32) {
        *p1 ^= *p0;
        *p0 = p0.rotate_left(20);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(9);
        *p1 ^= *p0;
        *p0 = p0.rotate_left(27);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(19);
    }
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes(c.try_into().unwrap()));
        block(&mut p0, &mut p1);
    }
    let rest = chunks.remainder();
    let last: u32 = match rest.len() {
        0 => 0x80,
        1 => 0x8000 | rest[0] as u32,
        2 => 0x800000 | u16::from_le_bytes([rest[0], rest[1]]) as u32,
        _ => 0x80000000 | ((rest[2] as u32) << 16) | u16::from_le_bytes([rest[0], rest[1]]) as u32,
    };
    p0 = p0.wrapping_add(last);
    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);
    ((p1 as u64) << 32) | p0 as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marvin_as_the_registry_library() {
        // from the Registry library's Marvin.ComputeHash, with the log seed, on 0..9 bytes of this data
        let data = [0xaf, 0x42, 0x7e, 0xa8, 0xd1, 0x0f, 0xc7, 0x11, 0x22];
        let expected: [u64; 10] = [
            0xb39efca403966e08,
            0xb4a6e6f533e761b2,
            0x93d854c6e3afa7e3,
            0x6ddb6ccaba8b10a9,
            0x63802c52175481ca,
            0x5d7e9ab31fb2705e,
            0x5b165e1ee7fcfbb7,
            0xe2522857ca7474f9,
            0xb9605bfc86239f1d,
            0x7e73abc1bf20592e,
        ];
        for (n, e) in expected.iter().enumerate() {
            assert_eq!(marvin(&data[..n], MARVIN_SEED), *e, "{n} bytes");
        }
    }
}
