//! Windows Prefetch (.pf) files, format versions 17 (XP/2003) to 30/31 (Windows 10/11), as the Prefetch library parses
//! them. A file that can't be used at all is an error; anything wrong after that goes in [`Prefetch::parse_errors`]
//! and leaves that section empty or partly filled. Nothing here prints: messages go to the observer you pass.

pub mod hash;
pub mod resolve;
mod xpress;

use std::path::Path;

use ez_common::Level;
use ez_common::net::utf16;
use ez_common::time::Timestamp;

pub use resolve::{ExecutablePath, executable_path};

const SIGNATURE: &[u8; 4] = b"SCCA";
// Real prefetch files are at most a few MB; these stop a corrupt size field or a large non-prefetch input from
// forcing a huge allocation
const MAX_DECOMPRESSED_SIZE: u32 = 64 * 1024 * 1024;
const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;
const HEADER_SIZE: i64 = 84;

/// What receives the library's log messages
pub type Observer<'a> = &'a mut dyn FnMut(Level, &str);

/// Why a file could not be opened
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The data isn't usable at all (PrefetchParseException)
    Parse { message: String },
    /// The file could not be opened or read
    Io { message: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse { message } | Error::Io { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

fn parse_error(message: impl Into<String>) -> Error {
    Error::Parse { message: message.into() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    WinXpOrWin2K3 = 17,
    VistaOrWin7 = 23,
    Win8xOrWin2012x = 26,
    Win10OrWin11 = 30,
    Win11 = 31,
}

impl Version {
    pub fn description(self) -> &'static str {
        match self {
            Version::WinXpOrWin2K3 => "Windows XP or Windows Server 2003",
            Version::VistaOrWin7 => "Windows Vista or Windows 7",
            Version::Win8xOrWin2012x => "Windows 8.0, Windows 8.1, or Windows Server 2012(R2)",
            Version::Win10OrWin11 => "Windows 10 or Windows 11",
            Version::Win11 => "Windows 11",
        }
    }

    fn layout(self) -> Layout {
        match self {
            Version::WinXpOrWin2K3 => Layout {
                file_information_size: 68,
                has_total_directory_count: false,
                last_run_times_offset: 36,
                last_run_times_count: 1,
                run_count_offset: 60,
                run_count_may_move: false,
                file_metric_size: 20,
                trace_chain_size: 12,
                volume_entry_size: 40,
            },
            Version::VistaOrWin7 => Layout {
                file_information_size: 156,
                has_total_directory_count: true,
                last_run_times_offset: 44,
                last_run_times_count: 1,
                run_count_offset: 68,
                run_count_may_move: false,
                file_metric_size: 32,
                trace_chain_size: 12,
                volume_entry_size: 104,
            },
            Version::Win8xOrWin2012x => Layout {
                file_information_size: 224,
                has_total_directory_count: true,
                last_run_times_offset: 44,
                last_run_times_count: 8,
                run_count_offset: 124,
                run_count_may_move: false,
                file_metric_size: 32,
                trace_chain_size: 12,
                volume_entry_size: 104,
            },
            Version::Win10OrWin11 | Version::Win11 => Layout {
                file_information_size: 224,
                has_total_directory_count: true,
                last_run_times_offset: 44,
                last_run_times_count: 8,
                run_count_offset: 124,
                run_count_may_move: true,
                file_metric_size: 32,
                trace_chain_size: 8,
                volume_entry_size: 96,
            },
        }
    }
}

/// What differs between the format versions
struct Layout {
    file_information_size: i64,
    has_total_directory_count: bool,
    last_run_times_offset: usize,
    last_run_times_count: usize,
    run_count_offset: usize,
    run_count_may_move: bool,
    file_metric_size: i64,
    trace_chain_size: i64,
    volume_entry_size: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: Version,
    pub signature: String,
    pub file_size: i32,
    pub executable_filename: String,
    /// The hash in hexadecimal, as in the file's name
    pub hash: String,
    pub hash_value: u32,
}

/// A 48-bit MFT entry number and a sequence number (None when 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftInformation {
    pub entry_number: u64,
    pub sequence_number: Option<u16>,
}

impl MftInformation {
    fn new(b: &[u8]) -> MftInformation {
        let low = i32_at(b, 0) as u32 as u64;
        let high = u16_at(b, 4) as u64;
        let sequence = u16_at(b, 6);
        MftInformation { entry_number: low | high << 32, sequence_number: (sequence != 0).then_some(sequence) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetric {
    pub filename_string_offset: i32,
    pub filename_string_size: i32,
    pub mft_info: Option<MftInformation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceChain {
    pub next_array_entry_index: i32,
    pub total_block_load_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub device_offset: i32,
    /// [`Timestamp::MIN`] when the time in the file is out of range
    pub creation_time: Timestamp,
    pub serial_number: String,
    pub device_name: String,
    pub file_references: Vec<MftInformation>,
    pub directory_names: Vec<String>,
}

/// The source file's time stamps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceTimes {
    pub created: Timestamp,
    pub modified: Timestamp,
    pub accessed: Timestamp,
}

#[derive(Debug, Clone, Default)]
pub struct Prefetch {
    /// The file's bytes, decompressed
    pub raw_bytes: Vec<u8>,
    pub source_filename: String,
    pub source_times: SourceTimes,
    /// None when the file is too short to hold it; nothing else is parsed then
    pub header: Option<Header>,
    pub file_metrics_offset: i32,
    pub file_metrics_count: i32,
    pub trace_chains_offset: i32,
    pub trace_chains_count: i32,
    pub filename_strings_offset: i32,
    pub filename_strings_size: i32,
    pub volumes_info_offset: i32,
    pub volume_count: i32,
    pub volumes_info_size: i32,
    /// -1 in version 17, which doesn't have it
    pub total_directory_count: i32,
    pub last_run_times: Vec<Timestamp>,
    pub volume_information: Vec<VolumeInfo>,
    pub run_count: i32,
    pub parse_errors: Vec<String>,
    pub filenames: Vec<String>,
    pub file_metrics: Vec<FileMetric>,
    pub trace_chains: Vec<TraceChain>,
}

impl Prefetch {
    pub fn parsing_error(&self) -> bool {
        !self.parse_errors.is_empty()
    }
}

fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn i64_at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Helpers.Slice: `count` bytes at `offset`, or the message of the exception thrown when they aren't in `buffer`
fn slice<'a>(buffer: &'a [u8], offset: i64, count: i64, field: &str) -> Result<&'a [u8], String> {
    if offset < 0 || count < 0 || offset + count > buffer.len() as i64 {
        return Err(format!(
            "Invalid {field} data (offset {offset}, length {count}, available {}) - is this file corrupt?",
            buffer.len()
        ));
    }
    Ok(&buffer[offset as usize..(offset + count) as usize])
}

/// Reads a prefetch file, decompressing it first if it is a Windows 10/11 (MAM) file
pub fn open(path: impl AsRef<Path>, observer: Observer) -> Result<Prefetch, Error> {
    let path = path.as_ref();
    let name = path.to_string_lossy();
    observer(Level::Debug, &format!("Opening {name}"));
    let bytes = read_file(path)?;
    let times = source_times(path);
    parse(bytes, &name, times, observer)
}

/// What .NET's exceptions say for a file that can't be read
fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let io = |e: std::io::Error| Error::Io { message: io_message(path, &e) };
    let mut file = std::fs::File::open(path).map_err(io)?;
    let length = file.metadata().map_err(io)?.len();
    check_length(length)?;
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes).map_err(io)?;
    Ok(bytes)
}

fn io_message(path: &Path, e: &std::io::Error) -> String {
    let full = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => {
            format!("Access to the path '{}' is denied.", full.display())
        }
        std::io::ErrorKind::NotFound => format!("Could not find file '{}'.", full.display()),
        _ => e.to_string(),
    }
}

fn check_length(length: u64) -> Result<(), Error> {
    if length < 8 {
        return Err(parse_error(format!("File is too small to be a prefetch file ({length} bytes)")));
    }
    if length > MAX_FILE_SIZE {
        return Err(parse_error(format!("File size {length} is larger than the {MAX_FILE_SIZE} byte limit")));
    }
    Ok(())
}

/// The file's time stamps as .NET gives them: on Unix, where it doesn't read the birth time, the creation time is the
/// older of the last write and last change times
pub fn source_times(path: &Path) -> SourceTimes {
    let Ok(m) = std::fs::metadata(path) else { return SourceTimes::default() };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let modified = (m.mtime(), m.mtime_nsec());
        let changed = (m.ctime(), m.ctime_nsec());
        let created = modified.min(changed);
        SourceTimes {
            created: from_unix(created.0, created.1),
            modified: from_unix(modified.0, modified.1),
            accessed: from_unix(m.atime(), m.atime_nsec()),
        }
    }
    #[cfg(not(unix))]
    {
        let time = |t: std::io::Result<std::time::SystemTime>| {
            t.ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| from_unix(d.as_secs() as i64, d.subsec_nanos() as i64))
                .unwrap_or_default()
        };
        SourceTimes { created: time(m.created()), modified: time(m.modified()), accessed: time(m.accessed()) }
    }
}

fn from_unix(seconds: i64, nanos: i64) -> Timestamp {
    const UNIX_EPOCH_AS_FILETIME: i64 = 116_444_736_000_000_000;
    Timestamp::from_filetime(UNIX_EPOCH_AS_FILETIME + seconds * 10_000_000 + nanos / 100).unwrap_or_default()
}

fn is_compressed(b: &[u8]) -> bool {
    b.starts_with(b"MAM")
}

fn check_signature(b: &[u8]) -> Result<(), Error> {
    if b.len() < 8 {
        return Err(parse_error(format!("File is too small to be a prefetch file ({} bytes)", b.len())));
    }
    if &b[4..8] != SIGNATURE {
        return Err(parse_error("Invalid signature! Should be 'SCCA'"));
    }
    Ok(())
}

fn decompress(b: &[u8]) -> Result<Vec<u8>, Error> {
    // Low nibble is the compression format (4 = XPRESS Huffman); the high bit means a CRC32 follows the size
    let format = b[3] & 0x0F;
    if format != 4 {
        return Err(parse_error(format!("Unsupported MAM compression format {format}")));
    }
    let size = i32_at(b, 4) as u32;
    if size > MAX_DECOMPRESSED_SIZE {
        return Err(parse_error(format!(
            "Decompressed size {size} is larger than the {MAX_DECOMPRESSED_SIZE} byte limit"
        )));
    }
    let data_offset = if b[3] & 0x80 != 0 { 12 } else { 8 };
    if b.len() < data_offset {
        return Err(parse_error("Compressed file is truncated"));
    }
    xpress::decompress(&b[data_offset..], size as usize).map_err(|e| parse_error(format!("Decompression failed: {e}")))
}

/// Parses a prefetch file's bytes; `source_filename` and `times` are only reported
pub fn parse(mut bytes: Vec<u8>, source_filename: &str, times: SourceTimes, observer: Observer) -> Result<Prefetch, Error> {
    check_length(bytes.len() as u64)?;
    if is_compressed(&bytes) {
        observer(Level::Debug, &format!("Found Windows 1x prefetch file. Decompressing {source_filename}"));
        bytes = decompress(&bytes)?;
    }
    check_signature(&bytes)?;
    let version = match i32_at(&bytes, 0) {
        17 => Version::WinXpOrWin2K3,
        23 => Version::VistaOrWin7,
        26 => Version::Win8xOrWin2012x,
        30 => Version::Win10OrWin11,
        31 => Version::Win11,
        other => return Err(parse_error(format!("Unknown version '{other:08X}'"))),
    };
    let mut pf = Prefetch { source_filename: source_filename.to_string(), source_times: times, ..Prefetch::default() };
    pf.parse_sections(&bytes, version, observer);
    pf.raw_bytes = bytes;
    Ok(pf)
}

impl Prefetch {
    fn add_error(&mut self, message: String, observer: Observer) {
        observer(Level::Error, &format!("Error processing {}. {message}", self.source_filename));
        self.parse_errors.push(message);
    }

    /// TryParse: true when the section was read; else its problem is added to the errors
    fn section(&mut self, name: &str, result: Result<(), String>, observer: Observer) -> bool {
        match result {
            Ok(()) => true,
            Err(e) => {
                self.add_error(format!("{name}: {e}"), observer);
                false
            }
        }
    }

    fn parse_sections(&mut self, raw: &[u8], version: Version, observer: Observer) {
        let layout = version.layout();
        // The header and file information block hold every offset and count, so nothing else can be parsed without them
        let header = self.parse_header(raw, version);
        if !self.section("Header", header, observer) {
            return;
        }
        let info = self.parse_file_information(raw, &layout, observer);
        if !self.section("File information", info, observer) {
            return;
        }
        let metrics = self.parse_file_metrics(raw, &layout);
        self.section("File metrics", metrics, observer);
        let chains = self.parse_trace_chains(raw, &layout);
        self.section("Trace chains", chains, observer);
        let names = self.parse_filenames(raw);
        self.section("Filename strings", names, observer);
        let volumes = self.parse_volumes(raw, &layout, observer);
        self.section("Volume information", volumes, observer);
    }

    fn parse_header(&mut self, raw: &[u8], version: Version) -> Result<(), String> {
        let b = slice(raw, 0, HEADER_SIZE, "Header")?;
        // 30 UTF-16 characters; a name that fills the field has no terminator
        let name = utf16(&b[16..76]);
        let name = name.split('\0').next().unwrap_or("").trim().to_string();
        let hash_value = i32_at(b, 76) as u32;
        self.header = Some(Header {
            version,
            signature: String::from_utf8_lossy(&b[4..8]).into_owned(),
            file_size: i32_at(b, 12),
            executable_filename: name,
            hash: format!("{hash_value:X}"),
            hash_value,
        });
        Ok(())
    }

    fn parse_file_information(&mut self, raw: &[u8], layout: &Layout, observer: Observer) -> Result<(), String> {
        let info = slice(raw, HEADER_SIZE, layout.file_information_size, "File information")?;
        self.file_metrics_offset = i32_at(info, 0);
        self.file_metrics_count = i32_at(info, 4);
        self.trace_chains_offset = i32_at(info, 8);
        self.trace_chains_count = i32_at(info, 12);
        self.filename_strings_offset = i32_at(info, 16);
        self.filename_strings_size = i32_at(info, 20);
        self.volumes_info_offset = i32_at(info, 24);
        self.volume_count = i32_at(info, 28);
        self.volumes_info_size = i32_at(info, 32);
        // Version 17 has no directory count (its last run time is at offset 36)
        self.total_directory_count = if layout.has_total_directory_count { i32_at(info, 36) } else { -1 };
        for i in 0..layout.last_run_times_count {
            let raw_time = i64_at(info, layout.last_run_times_offset + i * 8);
            // Versions with a single run time always report it; with 8 slots, unused ones are 0
            if raw_time == 0 && layout.last_run_times_count > 1 {
                continue;
            }
            match Timestamp::from_filetime(raw_time) {
                Some(t) => self.last_run_times.push(t),
                None => self.add_error(format!("Last run time {i} is out of range (0x{raw_time:X})"), observer),
            }
        }
        self.run_count = i32_at(info, layout.run_count_offset);
        // Newer Windows 10/11 builds moved the run count back 8 bytes; the old location then holds a nonzero value
        // 4 bytes before it
        if layout.run_count_may_move && i32_at(info, layout.run_count_offset - 4) != 0 {
            self.run_count = i32_at(info, layout.run_count_offset - 8);
        }
        Ok(())
    }

    fn parse_file_metrics(&mut self, raw: &[u8], layout: &Layout) -> Result<(), String> {
        let size = layout.file_metric_size;
        let bytes = slice(raw, self.file_metrics_offset as i64, self.file_metrics_count as i64 * size, "File metrics")?;
        for b in bytes.chunks_exact(size as usize) {
            self.file_metrics.push(if size == 20 {
                FileMetric { filename_string_offset: i32_at(b, 8), filename_string_size: i32_at(b, 12), mft_info: None }
            } else {
                FileMetric {
                    filename_string_offset: i32_at(b, 12),
                    filename_string_size: i32_at(b, 16),
                    mft_info: Some(MftInformation::new(&b[24..32])),
                }
            });
        }
        Ok(())
    }

    fn parse_trace_chains(&mut self, raw: &[u8], layout: &Layout) -> Result<(), String> {
        let size = layout.trace_chain_size;
        let bytes = slice(raw, self.trace_chains_offset as i64, self.trace_chains_count as i64 * size, "Trace chains")?;
        for b in bytes.chunks_exact(size as usize) {
            self.trace_chains.push(if size == 8 {
                TraceChain { next_array_entry_index: 0, total_block_load_count: i32_at(b, 0) }
            } else {
                TraceChain { next_array_entry_index: i32_at(b, 0), total_block_load_count: i32_at(b, 4) }
            });
        }
        Ok(())
    }

    fn parse_filenames(&mut self, raw: &[u8]) -> Result<(), String> {
        let b = slice(raw, self.filename_strings_offset as i64, self.filename_strings_size as i64, "Filename strings")?;
        self.filenames.extend(utf16(b).split('\0').filter(|s| !s.is_empty()).map(str::to_string));
        Ok(())
    }

    fn parse_volumes(&mut self, raw: &[u8], layout: &Layout, observer: Observer) -> Result<(), String> {
        let volumes = slice(raw, self.volumes_info_offset as i64, self.volumes_info_size as i64, "Volume information")?;
        for j in 0..self.volume_count.max(0) {
            let entry = slice(volumes, j as i64 * layout.volume_entry_size, layout.volume_entry_size, &format!("Volume {j}"))?;
            // Offsets inside a volume entry are relative to the start of the volume information
            let device_offset = i32_at(entry, 0);
            let device_chars = i32_at(entry, 4);
            let raw_created = i64_at(entry, 8);
            let serial_number = format!("{:X}", i32_at(entry, 16));
            let device =
                slice(volumes, device_offset as i64, device_chars as i64 * 2, &format!("Volume {j} device path"))?;
            let created = Timestamp::from_filetime(raw_created);
            if created.is_none() {
                self.add_error(format!("Volume {j}: creation time is out of range (0x{raw_created:X})"), observer);
            }
            let mut volume = VolumeInfo {
                device_offset,
                creation_time: created.unwrap_or(Timestamp::MIN),
                serial_number,
                device_name: utf16(device),
                file_references: vec![],
                directory_names: vec![],
            };
            let references = self.parse_file_references(raw, &mut volume, i32_at(entry, 20), i32_at(entry, 24));
            self.section(&format!("Volume {j} file references"), references, observer);
            let directories = self.parse_directory_strings(raw, &mut volume, i32_at(entry, 28), i32_at(entry, 32));
            self.section(&format!("Volume {j} directory strings"), directories, observer);
            self.volume_information.push(volume);
        }
        Ok(())
    }

    fn parse_file_references(&self, raw: &[u8], volume: &mut VolumeInfo, offset: i32, size: i32) -> Result<(), String> {
        if size == 0 {
            return Ok(());
        }
        let refs = slice(raw, self.volumes_info_offset as i64 + offset as i64, size as i64, "File references")?;
        // Version 1 (prefetch version 17) has an 8-byte header; version 3 (23 and later) adds 8 unknown bytes
        let version = i32_at(slice(refs, 0, 4, "File references version")?, 0);
        let count = i32_at(slice(refs, 4, 4, "File references count")?, 0);
        let start = if version >= 3 { 16 } else { 8 };
        let entries = slice(refs, start, count as i64 * 8, "File references")?;
        volume.file_references.extend(entries.chunks_exact(8).map(MftInformation::new));
        Ok(())
    }

    fn parse_directory_strings(&self, raw: &[u8], volume: &mut VolumeInfo, offset: i32, count: i32) -> Result<(), String> {
        // Each string is a UInt16 character count, then the UTF-16 characters and a NUL terminator
        let mut pos = self.volumes_info_offset as i64 + offset as i64;
        for k in 0..count.max(0) {
            let field = format!("Directory string {k}");
            let chars = u16_at(slice(raw, pos, 2, &field)?, 0) as i64;
            pos += 2;
            let byte_count = chars * 2 + 2;
            let text = utf16(slice(raw, pos, byte_count, &field)?);
            volume.directory_names.push(text.trim_matches('\0').to_string());
            pos += byte_count;
        }
        Ok(())
    }
}
