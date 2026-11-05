# Plan: porting RECmd to Rust

Status: core done (2026-11-02): `registry-ez` and `recmd`. Plugins in progress (2026-11-04): the 36 small ones are done, 33 are left (see "Plugins"). rla is not started.

## Done: the core

- `registry-ez`: hbins, nk/vk/lk/sk/lists, slack carving, deleted keys and values, value data of every type (big
  data, UWP types), transaction log replay (HvLE with Marvin32, and DIRT), the searches.
- `recmd`: `-f/-d`, `--bn` (CSV and JSON), `--sa/--sk/--sv/--sd/--ss` with `--regex/--literal/--nd`, `--kn/--vn/--saveTo`,
  `--json` for keys, `--details`, `--minSize`, `--base64`, `--nl`, `--recover`, `--dedupe`, `--dt`, `--co`, and `--sync`
  (feature `sync`). Keys handled by a plugin that isn't ported yet show their values.
- Parity (`tools/parity-recmd.sh`): 83 runs on the 28 Registry.Test hives and the DFIR Artifact Museum's dirty SYSTEM
  (with its logs) identical to RECmd 2026.10.3, output files and console: batch files (DFIRBatch, and every key of
  every hive, ~2 million rows), searches, key dumps, `--details` (14 million lines for SOFTWARE). 2.7x faster.
- Differences: culture-dependent text is en-US as .NET writes it on Linux (`7/3/2014 6:05:37 PM +00:00`, with a
  narrow no-break space; N and P with 3 decimals), where the original follows the machine's language. BinaryConvert `Sid` gives the SID (as RECmd on Windows does, not the
  Linux build's "only available on Windows" note); `--vss` is ignored; .NET stack traces after errors are not
  printed; YAML syntax error messages are the Rust parser's.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust crate | What |
|---|---|---|---|
| Registry | ~9,200 | `registry-ez` (library) | Hive parsing (base block, hbins, nk/vk/sk/lk cells, lists), value data, value slack, transaction log replay (new `HvLE` and old `DIRT` formats), deleted key/value recovery |
| RECmd | ~3,500 | `recmd` (CLI) + timeline code in `registry-ez` | Batch mode (`.reb` YAML), searches, key dumps, CSV/JSON output |
| rla | ~900 | `rla` (CLI) | Replays transaction logs and saves clean hives |
| RegistryPluginBase + 69 RegistryPlugin.* | ~12,100 | `registry-plugins` | Decoders for specific keys (UserAssist, Bam, MRUs, SAM, USB, Amcache...). Its own crate, as it needs `appcompatcache-ez`, which needs `registry-ez` |
| AppCompatCache | ~1,200 | `appcompatcache-ez` (library) | ShimCache parsing, for the AppCompatCache plugin (and a later AppCompatCacheParser port) |
| GuidMapping | 175 + data | `guidmapping-ez` | GUID names (ETW, later UserAssist and the shell items) |
| ExtensionBlocks | ~19,100 | `shellitems-ez` (library) | Shell items and extension blocks, for the shell-item plugins (and later SBECmd, LECmd, JLECmd) |
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

## Plugins

Upstream has 69, about 12,100 lines. Rated from their size and how much they parse:

| Group | Count | Plugins | Status |
|---|---|---|---|
| Small | 36 | 7-Zip (4), Adobe.TrustManager-Websites, Amcache (7), AppCompatCache, AppCompatFlags2, AppPaths, Bam, BluetoothServicesBthPort, DeviceClasses, DsrmAdminLogonBehaviour, ETW, FeatureUsage, JumplistData, NetworkAdapters, NetworkSettings, NetworkSetup2, Products, ProfileList, RADAR, RunMRU, TerminalServerClient, TypedURLs, Uninstall, VolumeInfoCache, WindowsApp, WindowsPortableDevices, WinRAR | Done |
| Medium | 25 | Adobe, Ares, CIDSizeMRU, DHCPNetworkHint, FileExts, FirewallRules, FirstFolder, IconLayouts, KnownNetworks, LastVisitedMRU, OfficeMRU, OpenSaveMRU, RecentApps, SAMBuiltin, SCSI, Services, SWD, SyscacheObjectTable, TaskFlowShellActivities, TimeZoneInformation, TrustedDocuments, USB, USBSTOR, UserAssist, WordWheelQuery | To do |
| Large | 4 | ApplicationSettingsContainer, SAM, TaskCache, AppCompatFlags (LZNT1) | To do |
| Need `shellitems-ez` | 4 | LastVisitedPidlMRU, OpenSavePidlMRU, Taskband, RecentDocs (`Beef0004` only) | Waits for LECmd's library |

How the framework behaves, each seen in the original's output:

- A plugin that handles a key replaces its raw values with `(plugin)` rows, even when it gives no rows at all. `DisablePlugin: true` turns that off for one batch key.
- Which plugins run is GetPluginsToActivate as written, including its odd cases: a plugin for one value runs on a parent key of its path, when the batch key names that value.
- A plugin's file is `<out>/<time>/<time>_<class>_<hive>.csv`, or `<csvf stem>_<class>.<ext>` with `--csvf`. Calls append, the header only once.
- The plugin's CSV has the first column, BatchKeyPath, the second column, BatchValueName, then the rest: RECmd gives the two batch columns indexes 0 and 1, and the others keep theirs.
- Its time stamps ignore `--dt`, since RECmd's converter never receives it. The batch CSV follows `--dt`.
- What a plugin doesn't catch (RADAR without its subkeys, for one) fails the hive and makes the exit code 1. Earlier rows of that hive stay.
- Differences: on Linux the original makes a folder of the `/` in the file's name; this port writes an underscore there, as Windows does. Plugins run in the order Windows lists their dlls, by name, where Linux's order depends on the file system. The X format of a GUID (`{0x...}`) isn't read by `guidmapping-ez`.

Parity: `tools/parity-recmd.sh` against RECmd with only the ported plugins in its `Plugins` folder, so the keys of the others are compared as raw values on both sides. Build them with `dotnet build RegistryPlugins.slnx -c Release` and copy each plugin's own dll from `bin/Release/netstandard2.0`. Upstream's test corpus is private and its repository only has three hives, so a generated hive with every plugin's keys, including odd and damaged values, is what reaches them all (`tools/gen-recmd-plugin-hives.py` writes the hives, a batch file and the cases).

Results for the 36 (2026-11-04), against RECmd 2026.10.3 with `RegistryPlugins` `bf564d6`: 34 runs on the generated hives and 117 on real ones (the Registry.Test hives with DFIRBatch, Kroll_Batch, InstalledSoftware and a batch file of all the plugins' keys; upstream's 3 plugin hives; the museum's dirty SYSTEM; the 8 AppCompatCache samples) are identical: files, console and exit codes. Of 200 generated hives with random bytes damaged, all files and exit codes are identical; 7 differ on the console, because the original logs `Error getting ValueData` twice per read (KeyValue.ValueData reads the record twice) where this port logs it once. The same difference is noted for AmcacheParser, and it is left as it is.

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
