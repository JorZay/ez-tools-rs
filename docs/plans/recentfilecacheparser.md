# Plan: porting RecentFileCacheParser to Rust

Status: done (2026-11-08), against RecentFileCacheParser `f953a6028c09a57006be1fec365a69cda7c87acf`, version 2026.10.2. Crates
`recentfilecache-ez` and `recentfilecacheparser`.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| RecentFileCache (`RecentFileCacheFile`, `Crc32`, the parse exception) | ~230 | `recentfilecache-ez` |
| RecentFileCacheParser (`Program.cs`, `CsvOut`, `ConsoleLog`) | ~480 | `recentfilecacheparser` |

Options: `-f`, `--csv`, `--csvf`, `--json`, `--pretty`, `-q`, `--co`. Outputs: console, one CSV, one JSON file (ServiceStack's
`ToJson()`, or `Dump()` with `--pretty`), console log. No `--dt`: dates are always `yyyy-MM-dd HH:mm:ss` (ISO with 7 decimals in the JSON).

The library is in the tool's own repository and uses no package from NuGet, so one commit pins everything.

## Format

A 20 byte header: signature `0xFFEEFFFE`, three DWORDs (0x2211, 3, 1 in every sample), and at 0x10 a CRC-32 (zlib's) of the file with
those 4 bytes left out. Then entries to the end of the file: an Int32 character count, UTF-16LE characters and a NUL character.

## Kept from the original

- Too small (under 20 bytes) or a bad signature: the error is shown, nothing is exported and the exit code is 0. Everything after the
  header is reported in `ParseErrors` and the rest exported: a checksum mismatch, a length that runs past the end (stops there), a cut
  NUL (the name is kept), a non-NUL terminator (goes on), trailing bytes. Invalid UTF-16 becomes U+FFFD, as `Encoding.Unicode`.
- Exit code 1 for a missing `-f`, a file that isn't there (or a folder), a file that can't be read, and a failed export. A failed CSV
  export doesn't stop the JSON one.
- The JSON is the whole object: `SourceFile`, the three source times, `Checksum`, `CalculatedChecksum`, `ChecksumValid`, `FileNames`,
  `ParseErrors`, `ParsingError`; no BOM, no line end at the end. The CSV has no BOM.
- The source times are `FileInfo`'s, of a link itself for a link. On Linux .NET doesn't read the birth time: the creation time is the
  older of the last write and last change times.
- `--co` (on by default) logs to the first of `--csv` and `--json`, which it creates at the start, so "does not exist. Creating..." only
  shows for the other folder or with `--co false`. The log exists even when the run stops at a missing file.
- `--csvf` is reduced to its file name; one that ends with a separator leaves no name and the export fails.

## Known differences

- Banner, help and argument error texts are this port's. The console log's name has this port's version, and neither the console nor
  the log has .NET's stack traces. Not checked for administrator rights (the original only warns).

## Results

`tools/parity-recentfilecache.sh` compares the CSV, the JSON, the console log (without line times and stack traces), the console after the
banner and the exit code with the Linux build; `tools/gen-recentfilecache-cases.py` builds the inputs. No real `RecentFileCache.bcf` was
in the evidence, so the inputs are upstream's 3 test files and generated ones.

Linux, 2,209 runs, 4,261 output files identical, 0 differences:

| Input | Reached |
|---|---|
| Upstream's 2 samples and its LNK file | Valid checksums, a bad signature |
| 34 generated files | Header only, empty names, 3,000 entries, a 40,000 character name, names with commas, quotes, CR, LF, tabs, spaces at either end, braces, colons, control characters, non-ASCII and a surrogate pair, lone surrogates; bad and zero checksums, every kind of bad length, cut and non-NUL terminators, 1 to 3 trailing bytes, empty, 1 and 19 byte files, bad signatures |
| The 648 cuts of the two samples (every length) | Every parse error but a bad signature |
| 400 randomly damaged copies of the two samples, half with a fixed checksum | Lengths, terminators, trailing bytes, checksums |
| 38 option runs | No `-f`, missing file, a folder, `--csvf` with a path, with a separator at the end and empty, `--csv ''`, `--co`/`--pretty`/`-q` with values, both outputs in one folder, nested new folders, relative and `..` paths, a file in the way, repeated and unknown options |

Windows (the build of the same commit, on the VM; `SourceFile` and the source times masked, as they are each machine's own), 576 runs, 778
output files identical, exit codes the same: the 34 generated files, upstream's 3, the 142 cuts of `RecentFileCache 2.bcf` and 100 damaged
copies, each with `--csv --json` and `--json --pretty -q`, and 18 of the option runs. This checks CRLF in `--pretty` and the CSV.

Also compared by hand: a link as `-f` (the link's own times) and a file whose birth time is older than its last change (not used on
Linux, as by .NET). Not checked: a real `RecentFileCache.bcf` from Windows 7, which nothing at hand has. Reading a file without permission was compared too (same message, exit 1).
