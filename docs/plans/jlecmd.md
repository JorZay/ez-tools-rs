# JLECmd port

Status: done (2026-11-05), against JLECmd `256962fcb3690d779faba11726dd63ee500ae2a7`, version 2026.10.6. Crates `olecf-ez`, `jumplist-ez` and `jlecmd`,
on top of `lnk-ez` and `shellitems-ez`.

## What is ported

| Original (C#, EricZimmerman) | Rust |
|---|---|
| OleCf 2026.10.1 (`afd5ee9`, not its latest commit): compound files | `olecf-ez` |
| JumpList 2026.10.10: DestList, AppIDs, custom destinations | `jumplist-ez` |
| JLECmd `Program.cs`, `ConsoleLog` | `jlecmd` |

Options: `-f`, `-d`, `--all`, `--csv/--csvf`, `--json/--jsonf`, `--pretty`, `--html`, `-q`, `--ld`, `--fd`, `--appIds`, `--dumpTo`, `--dt`, `--mp`,
`--withDir`, `--user`, `--cp`, `--debug/--trace`, `--co`.

## What was new

**The JSON is the whole object graph.** Unlike LECmd's flat rows, `--json` serializes `AutomaticDestination` and `CustomDestination` with ServiceStack, down to
every LNK, shell item and block, with `__type` on anything held through an interface or abstract class. So `shellitems-ez` and `lnk-ez` now keep each class's
serialized properties, and `ez_common::json::Value` writes the graph as JSON (`ToJson`) or laid out JSV (`Dump`, for `--pretty`). Each class's property order
is in `own_properties` in `shellitems-ez/src/items/mod.rs`, in the order .NET's reflection gives. ServiceStack details that matter:

- Null properties are left out. A non-nullable `DateTimeOffset` holding its default, the minimum, is left out too; a nullable one holding it is written.
- `[Flags]` enums are numbers, others are names. GUIDs have no dashes. `byte[]` is base64.
- Floats: `3e-45` in JSON, `3E-45` in JSV, except `float.MaxValue` and `MinValue`, which stay lower case in both.
- `InternalId` is a new GUID for each shell item in each run, in the original too, so it never matches and the parity script masks it.

## The original's behaviour that was kept

These look like bugs, and are copied so output files match:

- **No vendor names:** `MacList` is never filled, so `--fd` always shows `MAC Vendor: (Unknown vendor)`.
- **`** JumpList has serialized property store(s)! **`** shows for nearly every file: `EmptyDestListPropertyStore` is false when there's no such stream.
- **`--fd` always adds `(lnk file not present)`**, and a DestList entry with no LNK fails the whole file.
- **`--fd` with a named property in a `PropertyStoreDataBlock`** fails the whole file (`int.Parse`).
- **`--withDir` with a `DestListPropertyStore` stream** tries to read it as an LNK: without `-q` that file fails; with `-q` the whole export is abandoned.
- **An undefined drive type, or two tracker blocks,** abandon the whole CSV and XHTML export of that kind (a `NullReferenceException` and `SingleOrDefault`).
- **An abandoned export leaves its files unflushed:** `crates/jlecmd/src/writer.rs` follows what `StreamWriter` and `FileStream` buffer, so the same bytes reach the disk.
- **`--all`** counts folders as files, so each one is listed under failed files, and the exit code is 1.

## Checks

Compared with the reference build, with `TZ=UTC` and `LANG=en_US.UTF-8`, by `tools/parity-jlecmd.sh`: every output file, the console after the banner, and the
exit code.

| Check | Size | Result |
|---|---|---|
| Upstream's samples, every option | 7 runs | Identical |
| Shell items through ServiceStack (`dump_items <file> json`, and the `dump json` harness) | 241,308 samples and generated items, 85 classes | Identical |
| Generated jump lists, half of them damaged (`tools/gen-jlecmd-cases.py`) | 3 seeds, 7 runs each, 2,700 files, about 7,350 output files | See below |
| Real KAPE extractions (`--csv --json --html --dumpTo`, `--pretty --withDir`, `--ld --mp`, `--fd --withDir`) | 4 runs, 12,523 output files | Identical |

The generated runs differ in 9 files out of about 7,350, all from an abandoned export: 8 by a second in `SourceAccessed`, where a read on tmpfs changed the
access time, and 1 as described under "Known differences".

**Coverage.** The real extractions have 179 automatic files with 12,864 rows, and 58 custom files with 214 rows, but reach only 23 classes. The generated items
reach the other shell item and block classes, so those were compared on data that isn't real, as for LECmd. `--cp` and `--user` were also run on generated files.
LECmd's parity was rerun after the changes to the shared libraries: no differences but `SourceAccessed`.

## Known differences

- **What an abandoned export leaves behind.** If the runtime's garbage collector happens to finalize the abandoned `FileStream`, the original writes out what it
  still held. So its partial file can be longer, by up to 4,096 bytes, and this port's is then a prefix of it. Seen once in 21 runs. Whether it happens varies between runs of the original.
- **`--debug`** doesn't print the original's `PrintDump` of each entry.
- **The XHTML folder's name**, as in LECmd: underscores for a path's separators, as on Windows.
- **`-d` enumerates as the net10 build does**, folders included with `--all`, and doesn't follow links to folders, as on Windows. The net472 build lists only files.
- **The machine's time zone**, as in LECmd: `TZ=UTC` shows no difference, and the same items hold local time in the original otherwise.
- **`DateTimeOffset.TryParse` in zip contents**, as in LECmd, and culture rules in `Path.StartsWith("knownfolder")`, which is a plain comparison here.
- **The console log's name** has this port's version, as in the other tools.
