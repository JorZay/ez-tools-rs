# Plan: porting RBCmd to Rust

Status: done (2026-11-06), against RBCmd `f2ed07ab4634064e7dbc02a1155fd70b7ff3f51b`, version 2026.10.1. Crates `recyclebin-ez` and `rbcmd`.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| RecycleBin (`DollarI`, `Info2`, `Helpers`, the parse exception) | ~400 | `recyclebin-ez` |
| RBCmd (`Program.cs`, `CsvOut`, `ConsoleLog`) | ~800 | `rbcmd` |

Options: `-f`, `-d`, `-q`, `--csv`, `--csvf`, `--dt`, `--debug`, `--trace`, `--co`. Outputs: console, one CSV, console log.

RBCmd uses no library from NuGet: the RecycleBin library is in its own repository, so one commit pins everything.

## Reference

RBCmd targets `net10.0` as well as `net472`, and runs here on .NET 10. `-d` differs between the two: `net10.0` uses a
`FileSystemEnumerator`, `net472` AlphaFS.

## Kept from the original

- A file's type comes from its content, not its name: a 64-bit 1 or 2 is `$I`, a 32-bit 4 or 5 is INFO2, so a file named
  INFO2 can be read as `$I` and the other way round.
- `-d` is case-sensitive: `$I*` and `INFO2`, not `$i*` or `info2`. `-f` looks for the `$R` folder in any case.
- `$I` files come first, then the INFO2 files, whatever the order they were found in.
- A file that didn't parse completely is exported and also listed as failed, so "Processed" counts it out.
- Damaged files don't change the exit code, files and folders that can't be read do (1).
- A size of the smallest long (`-9223372036854775808`) fails on the console, in `BytesToString`, after the row was added, so with
  `-q` the same file is fine.
- A bad `--dt` fails every file: no rows, exit code 0. An INFO2 file without records isn't affected.
- `--co` makes the `--csv` folder at the start, so "does not exist. Creating..." only shows with `--co false`, and the folder and
  the log exist even when the run stops at a missing file.
- `$R` folders: links to folders are followed and a link's size is its own, not its target's. One failure loses the whole list.
- INFO2's ANSI names: bytes over 0x7F are `?`.
- `--dt` is .NET's `DateTimeOffset.ToString` in en-US: an empty format, and the standard ones, with U+202F before AM and PM, as ICU
  has it here. `U` is an error for this type. This is `Timestamp::format_en_us` in `ez-common`.

## Known differences

- `-d` doesn't follow links to folders, where the Linux original does. The Windows build (`net472`, `SkipReparsePoints`) doesn't,
  and RECmd and JLECmd's ports already do the same. Links to files are read.
- A folder under `-d` that can't be read is named in the error. The Linux original names the `-d` folder instead, as it has already
  cleared the name when the folder is opened; the Windows code names the folder. Same files and exit code.
- `--co false --co false` is accepted, the original refuses it. Other options with a value, given twice, are refused by both.
- Banner, help and argument error texts are this port's. The console log's name has this port's version, and neither the console
  nor the log has .NET's stack traces.

## Results

`tools/parity-rbcmd.sh` compares the CSV, the console log (without line times and stack traces), the console after the banner and the
exit code. `tools/gen-rbcmd-cases.py` builds the generated files.

143 runs, 182 output files identical, 0 differences, about 3,480 rows:

| Input | Reached |
|---|---|
| Two real KAPE extractions, `-d`, 3 runs each | 193 `$I` files, all format 2, none with a `$R` folder, no INFO2 |
| Upstream's 12 samples, each kind of option | Formats 1 and 2, INFO2 with 800 byte records, removed records |
| 117 generated files | Sizes around each unit, odd names, all length and time limits, short files, unknown headers, record sizes, `$R` folders |
| 4 sets of 600 damaged files (real samples, generated files) | Every parse error and failure path; in one set, 119 files of 600 parse cleanly |
| 19 `--dt` formats (standard, custom, invalid) on two sets | All formats and both .NET errors |
| Options and failures | No arguments, repeats, bad values, relative and `..` paths, file in the way, read-only folder |

All messages but one were checked as reached in the original's output: `Unsupported $I format` can't be reached through the tool,
as only 1 and 2 get that far, so it's covered by a unit test. Links and permissions were compared by hand, showing only the
differences above: reading a file without permission is identical.

Not checked: the Windows builds (a real INFO2 from Windows 9x is only in generated form, and upstream's INFO2 samples are XP's).
