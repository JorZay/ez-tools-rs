# Plan: porting RECmd to Rust

Status: core done (2026-11-02): `registry-ez` and `recmd` without plugins. Next: rla, then the plugins.

## Done: the core

- `registry-ez`: hbins, nk/vk/lk/sk/lists, slack carving, deleted keys and values, value data of every type (big
  data, UWP types), transaction log replay (HvLE with Marvin32, and DIRT), the searches.
- `recmd`: `-f/-d`, `--bn` (CSV and JSON), `--sa/--sk/--sv/--sd/--ss` with `--regex/--literal/--nd`, `--kn/--vn/--saveTo`,
  `--json` for keys, `--details`, `--minSize`, `--base64`, `--nl`, `--recover`, `--dedupe`, `--dt`, `--co`, and `--sync`
  (feature `sync`). Keys that plugins handle show their values (no plugins yet).
- Parity (`tools/parity-recmd.sh`): 83 runs on the 28 Registry.Test hives and the DFIR Artifact Museum's dirty SYSTEM
  (with its logs) identical to RECmd 2026.10.3, output files and console: batch files (DFIRBatch, and every key of
  every hive, ~2 million rows), searches, key dumps, `--details` (14 million lines for SOFTWARE). 2.7x faster.
- Differences: culture-dependent text is en-US as .NET writes it on Linux (`7/3/2014 6:05:37 PM +00:00`, with a
  narrow no-break space; N and P with 3 decimals); BinaryConvert `Sid` gives the SID (as RECmd on Windows does, not the
  Linux build's "only available on Windows" note); `--vss` is ignored; .NET stack traces after errors are not
  printed; YAML syntax error messages are the Rust parser's.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust crate | What |
|---|---|---|---|
| Registry | ~9,200 | `registry-ez` (library) | Hive parsing (base block, hbins, nk/vk/sk/lk cells, lists), value data, value slack, transaction log replay (new `HvLE` and old `DIRT` formats), deleted key/value recovery |
| RECmd | ~3,500 | `recmd` (CLI) + timeline code in `registry-ez` | Batch mode (`.reb` YAML), searches, key dumps, CSV/JSON output |
| rla | ~900 | `rla` (CLI) | Replays transaction logs and saves clean hives |
| RegistryPluginBase + 75 RegistryPlugin.* | ~14,300 | `registry-ez::plugins` | Decoders for specific keys (UserAssist, Bam, MRUs, SAM, USB, Amcache...) |
| AppCompatCache | ~1,200 | `appcompatcache-ez` (library) | ShimCache parsing, for the AppCompatCache plugin (and a later AppCompatCacheParser port) |
| ExtensionBlocks + GuidMapping | ~19,300 | `shellitems-ez` (library) | Shell items and extension blocks, for the shell-item plugins (and later SBECmd, LECmd, JLECmd) |
| BatchExamples | 22 `.reb` files | `batch/` folder, built in | The community batch files (MIT), like EvtxECmd's maps |

Same organization as EvtxECmd: the libraries never print or exit (they report through an observer and return
errors), and the CLIs are thin clients.

## Rules kept from the original

- Batch CSV columns and their order (KAPE and scripts read them): HivePath, HiveType, Description, Category, KeyPath,
  ValueName, ValueType, ValueData, ValueData2, ValueData3, Comment, Recursive, Deleted, LastWriteTimestamp,
  PluginDetailFile. Plugin rows have ValueType `(plugin)`; each plugin's full output goes to its own CSV
  (`DumpPluginValues`), named as the original names them.
- Dirty hives (sequence numbers differ, or a bad checksum with logs present): logs `.LOG`, `.LOG1`, `.LOG2` next to
  the hive, any case, empty ones skipped. A dirty hive without logs is an error unless `--nl`.
- Log replay follows Maxim Suhanov's regf specification (CC BY 4.0), as the original does. yarp (GPL-3.0) may be used
  only as a black box for comparisons; never as code.
- `--recover` (deleted keys and values) on by default.
- Value lookups take the first value with a name (a key can have the same name twice).
- Names with the compressed flag are Latin-1, not Windows-1252.
- Exit codes 0 and 1 with the original's meanings (damaged hive: reported, exit 0; unreadable file or folder, bad
  batch file, output not written: exit 1).
- Input may be corrupt or hostile: truncated files, impossible sizes, list cycles, keys listed twice are reported
  and skipped, never a crash.

## Phases

1. **Hive parser** (`registry-ez`): base block, hbins, cells, lists, key tree, value data and slack, Latin-1/UTF-16
   names, damaged-hive handling. Test: the 28 test hives in Registry.Test (and the DFIR Artifact Museum hive in
   RECmd.Test): every key path, last write time, value name, type, size and data equal to the original's.
2. **Transaction logs and deleted records**: new and old log formats, two-log ordering, hive growth, base block
   repair; deleted keys/values from free cells and slack. Test: the original's replayed hive bytes equal ours;
   recovered keys/values equal.
3. **Batch mode, no plugins**: `.reb` parsing and validation, wildcards, recursion, `ValueName`, `IncludeBinary`,
   `BinaryConvert`, value formatting, CSV/JSON as RECmd writes them, multiple hives, console log file. Keys that a
   plugin handles show raw values until phase 5. Test: RECmd's batch CSV byte for byte with plugins disabled.
4. **Searches and key dumps** (if wanted): `--sa/--sk/--sv/--sd/--ss`, `--regex`, `--literal`, `--base64`,
   `--minSize`, `--nd`, `--details`; `--kn/--vn/--saveTo`. And `rla` (if wanted).
5. **Plugins, in waves**, each wave compared with the original plugin's output (values as multisets, errors as sets,
   as the RegistryPlugins repo validates them):
   1. Simple decoders (most plugins): Bam, TypedURLs, RunMRU, WordWheelQuery, TimeZoneInformation, ProfileList,
      Services, Uninstall, NetworkAdapters, KnownNetworks, FeatureUsage, ...
   2. MRU lists: RecentDocs, OpenSaveMRU, OfficeMRU, CIDSizeMRU, 7-Zip, WinRAR, ...
   3. Artifact parsers: AppCompatCache (with `appcompatcache-ez`), SAM, USB/USBSTOR/SCSI/DeviceClasses, Amcache (7),
      UserAssist, TaskCache, ...
   4. Shell items: `shellitems-ez` (ExtensionBlocks), then LastVisitedPidlMRU, OpenSavePidlMRU, Taskband.
6. **Parity and performance**: a `tools/parity-recmd.sh` like EvtxECmd's (the original needs its Plugins folder,
   built from RegistryPlugins with `CopyPlugins.ps1`), runs on real hives, timings.

## Reference build

The originals pin .NET 10; this machine has the .NET 9 SDK: build scratch copies retargeted to `net9.0` (as for
EvtxECmd), or install the .NET 10 SDK. RECmd needs the plugins next to it (`Plugins/RegistryPlugin.*.dll`).

## Open decisions (defaults in bold, to confirm)

1. Phasing: **core first, plugins in waves** / everything before first use / core only.
2. Features besides batch mode: searches, key dumps (`--kn/--vn/--saveTo`), `rla`, `--sync`. Default: **all, as
   phase 4, after batch mode**; `--sync` as an optional build feature.
3. Copies of the same hive (live + shadow copies): **identical files read once, plus `--merge`** that collapses rows
   equal across copies (hive type, key path, value name, data, last write time; position fields excluded), listing
   every HivePath / identical files only / every copy.
4. Repository: decided (2026-11-02): one workspace, shared with the other tools (see mftecmd.md, Layout).

Also needed: real hives to test with (extractions with their `.LOG1`/`.LOG2`, ideally with shadow copies).
