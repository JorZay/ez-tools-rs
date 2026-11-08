# Plan: porting RECmd to Rust

Status: core done (2026-11-02): `registry-ez` and `recmd`. All 69 plugins done (2026-11-05, see "Plugins"). rla done (2026-11-05, see "rla").

## Done: the core

- `registry-ez`: hbins, nk/vk/lk/sk/lists, slack carving, deleted keys and values, value data of every type (big
  data, UWP types), transaction log replay (HvLE with Marvin32, and DIRT), the searches.
- `recmd`: `-f/-d`, `--bn` (CSV and JSON), `--sa/--sk/--sv/--sd/--ss` with `--regex/--literal/--nd`, `--kn/--vn/--saveTo`,
  `--json` for keys, `--details`, `--minSize`, `--base64`, `--nl`, `--recover`, `--dedupe`, `--dt`, `--co`, and `--sync`
  (feature `sync`). Keys handled by a plugin that isn't ported yet show their values.
- Parity (`tools/parity-recmd.sh`): 83 runs on the 28 Registry.Test hives and the DFIR Artifact Museum's dirty SYSTEM
  (with its logs) identical to RECmd 2026.10.3, output files and console: batch files (DFIRBatch, and every key of
  every hive, ~2 million rows), searches, key dumps, `--details` (14 million lines for SOFTWARE). 2.7x faster.
- Differences: culture-dependent text is en-US as .NET writes it on Windows (`7/3/2014 6:05:37 PM +00:00`, with a
  plain space; N and P with 2 decimals), where the original follows the machine's language. BinaryConvert `Sid` gives the SID (as RECmd on Windows does, not the
  Linux build's "only available on Windows" note); `--vss` is ignored; .NET stack traces after errors are not
  printed; YAML syntax error messages are the Rust parser's.
- `-d` finds hives as the original's Windows build (changed 2026-11-05, on the same rule as rla): any name holding USRCLASS, NTUSER,
  SYSTEM, SAM, SOFTWARE, AMCACHE, SYSCACHE, SECURITY, DRIVERS, COMPONENTS, DEFAULT, USER, USERCLASSES, SETTINGS or REGISTRY, with the
  `regf` signature, and links to folders aren't followed. The Linux build takes names ending in its masks and follows those links.
  This can only add hives: on the Registry.Test folder 22 hives where the Linux build opens 8 (of which 710 rows become 930, DFIRBatch). A file with a hive's
  name that isn't a hive is no longer opened, so counts on the console leave it out. Checked: on a tree of exact names, CSV, JSON and
  searches are the same as the Linux reference (JSON but for the known `/` in plugin file names); on the Registry.Test folder, the batch
  CSV and all plugin CSVs (1,174 rows) are the same rows as the reference run with `-f` on each of the 22 hives.

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
   `--minSize`, `--nd`, `--details`; `--kn/--vn/--saveTo`. And `rla` (done).
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

## rla

`crates/rla`, from the same RECmd commit (rla 2026.10.1, Registry 2026.10.1): `-f`, `-d`, `--out`, `--ca`, `--cn`, `--nop`, `--debug`, `--trace`, `--co`. The replay is `registry-ez`'s; this crate finds hives and logs, decides where each hive is saved (`names.rs`, with upstream's `OutputNamesTests`) and writes it.

Parity: `tools/gen-rla-cases.py` makes the corpus and `tools/parity-rla.sh` compares saved files (names and bytes) and exit codes against the .NET 10 reference. 482 runs, 0 differences (2026-11-05), and the original replayed logs in 223 of them: the 28 Registry.Test files; the museum's dirty SYSTEM with 14 arrangements of its logs; files too short to be hives; bad arguments and outputs; a KAPE-like tree under `-d`; 40 logs built with valid checksums and hashes, reaching each check of the replay in both formats; and 300 of those with random values and bytes. Console output is the same in all but 6: the help (this port's), and the 5 `-d` runs below. Console lines of `--debug` runs aren't compared, as they start with a time. Two real KAPE extractions (2026-11-05) gave the same saved files and exit codes in 267 runs: `-f --ca` on each of 261 hives and 6 `-d` runs, with logs replayed in 21 hives.

Differences from the Linux reference, on purpose, following the original's Windows build:

- `-d` takes any file whose name holds a hive's name (`NTUSER1.DAT`, `SYSTEM.old`) and that has the `regf` signature, where the Linux build takes exact names only. So it can save more hives, and a file with a hive's name that isn't a hive is never opened. `crates/rla/tests/cli.rs` checks this, as the reference can't.
- `-d` doesn't follow links to folders, where the Linux build does and saves those hives twice. Links to files are followed, as the Linux build does (the Windows build skips them).
- `-d` creates `--out` before searching, even when nothing is found, and says so; it warns if `--out` already has files (with `--co` on that is always, as its log is there).

Other differences: a folder that can't be read is named in the error, where the Linux build names the folder searched. `--help` is this port's. Live systems aren't read: a hive that can't be read is reported, with exit code 1.

Kept from the original, though odd: a hive with matching sequence numbers, a wrong checksum and logs is reported as "Sequence numbers match! Hive is not dirty" and not saved, though the comment there says the logs should fix it.

## Plugins

Upstream has 69, about 12,100 lines. Rated from their size and how much they parse:

| Group | Count | Plugins | Status |
|---|---|---|---|
| Small | 36 | 7-Zip (4), Adobe.TrustManager-Websites, Amcache (7), AppCompatCache, AppCompatFlags2, AppPaths, Bam, BluetoothServicesBthPort, DeviceClasses, DsrmAdminLogonBehaviour, ETW, FeatureUsage, JumplistData, NetworkAdapters, NetworkSettings, NetworkSetup2, Products, ProfileList, RADAR, RunMRU, TerminalServerClient, TypedURLs, Uninstall, VolumeInfoCache, WindowsApp, WindowsPortableDevices, WinRAR | Done |
| Medium | 25 | Adobe, Ares, CIDSizeMRU, DHCPNetworkHint, FileExts, FirewallRules, FirstFolder, IconLayouts, KnownNetworks, LastVisitedMRU, OfficeMRU, OpenSaveMRU, RecentApps, SAMBuiltin, SCSI, Services, SWD, SyscacheObjectTable, TaskFlowShellActivities, TimeZoneInformation, TrustedDocuments, USB, USBSTOR, UserAssist, WordWheelQuery | Done (2026-11-05) |
| Large | 4 | ApplicationSettingsContainer, SAM, TaskCache, AppCompatFlags (LZNT1) | Done (2026-11-05) |
| Need `shellitems-ez` | 4 | LastVisitedPidlMRU, OpenSavePidlMRU, Taskband, RecentDocs (`Beef0004` only) | Done (2026-11-05) |

How the framework behaves, each seen in the original's output:

- A plugin that handles a key replaces its raw values with `(plugin)` rows, even when it gives no rows at all. `DisablePlugin: true` turns that off for one batch key.
- Which plugins run is GetPluginsToActivate as written, including its odd cases: a plugin for one value runs on a parent key of its path, when the batch key names that value.
- A plugin's file is `<out>/<time>/<time>_<class>_<hive>.csv`, or `<csvf stem>_<class>.<ext>` with `--csvf`. Calls append, the header only once.
- The plugin's CSV has the first column, BatchKeyPath, the second column, BatchValueName, then the rest: RECmd gives the two batch columns indexes 0 and 1, and the others keep theirs. CsvHelper's sort (List.Sort) only keeps ties in order up to 16 items, so UserAccounts, the one class with more (31), has BatchValueName before its second column.
- Its time stamps ignore `--dt`, since RECmd's converter never receives it. The batch CSV follows `--dt`.
- What a plugin doesn't catch (RADAR without its subkeys, for one) fails the hive and makes the exit code 1. Earlier rows of that hive stay.
- Differences: on Linux the original makes a folder of the `/` in the file's name; this port writes an underscore there, as Windows does. Plugins run in the order Windows lists their dlls, by name, where Linux's order depends on the file system. The X format of a GUID (`{0x...}`) isn't read by `guidmapping-ez`.

Parity: `tools/parity-recmd.sh` against RECmd with only the ported plugins in its `Plugins` folder, so the keys of the others are compared as raw values on both sides. Build them with `dotnet build RegistryPlugins.slnx -c Release` and copy each plugin's own dll from `bin/Release/netstandard2.0`. Upstream's test corpus is private and its repository only has three hives, so a generated hive with every plugin's keys, including odd and damaged values, is what reaches them all (`tools/gen-recmd-plugin-hives.py` writes the hives, a batch file and the cases).

Results for the 36 (2026-11-04), against RECmd 2026.10.3 with `RegistryPlugins` `bf564d6`: 34 runs on the generated hives and 117 on real ones (the Registry.Test hives with DFIRBatch, Kroll_Batch, InstalledSoftware and a batch file of all the plugins' keys; upstream's 3 plugin hives; the museum's dirty SYSTEM; the 8 AppCompatCache samples) are identical: files, console and exit codes. Of 200 generated hives with random bytes damaged, all files and exit codes are identical; 7 differ on the console, because the original logs `Error getting ValueData` twice per read (KeyValue.ValueData reads the record twice) where this port logs it once. The same difference is noted for AmcacheParser, and it is left as it is.

Results for the 4 shell item plugins (2026-11-05), same versions, ExtensionBlocks 2026.10.9: all output files identical in 70 runs on generated hives (hand-built odd values, all of ExtensionBlocks' sample items, and 7,500 randomly damaged items per plugin), 300 on damaged Taskband values, and 57 on the Registry.Test hives with the batch examples, which have real rows of all four (75,218 CSV lines of OpenSavePidlMRU). The only difference there is the known one for a repeated option (`--nl --nl`). `ShellItem.value_is_null` was added because JSON shows `LnkName` as null where the original leaves `Value` null; it matches the reference on 121,189 items.

Known differences: `Details` has `\n` line ends as the Linux reference does, where the original on Windows writes `\r\n`. RecentDocs' `Path.GetExtension` is the Windows one (`\` and `:` end a file name), so `a.b\c` has no extension here and `.b\c` on Linux. Extensions sort by `compare_culture`, which orders letters beyond Latin-1 by code point rather than by ICU's table.

Results for the 25 medium plugins (2026-11-05), same versions: 0 differences in output file contents in 58 runs on generated hives (normal, odd and missing values for every plugin), 200 on randomly damaged ones, 113 on the Registry.Test hives (the batch examples, and a batch file of every plugin's key), and 62 rechecking the other plugins' cases. Real rows came for 17 of the 25: CIDSizeMRU, FileExts, FirewallRules, FirstFolder, KnownNetworks, OfficeMRU, SAMBuiltin, SCSI, Services, SWD, TimeZoneInformation, TrustedDocuments, USB, USBSTOR, UserAssist, WordWheelQuery and Ares. The hives have nothing for Adobe, DHCPNetworkHint, IconLayouts, LastVisitedMRU, OpenSaveMRU, RecentApps, SyscacheObjectTable and TaskFlowShellActivities, so those were only compared on generated data.

Known differences: DHCPNetworkHint gives the current time for a lease value that isn't there, as the original does, so those two columns can't match between any two runs. Rows of a batch file are in Windows' dll order where the Linux reference uses the disk's, which shows when two plugins read one key (DHCPNetworkHint and NetworkSettings): the same rows, in another order. Error messages of unusual damage can differ from .NET's wording on the console, not in files.

Results for the 4 large plugins (2026-11-05), same versions: 0 differences in output file contents or exit codes in 30 runs on hand-built hives (all 37 RegUwp types with normal, odd and damaged values; users, groups and SIDs of SAM; Actions layouts of TaskCache; LZNT1 streams made by a compressor in the generator), 480 on randomly damaged ones, 116 on the Registry.Test and RegistryPlugins.Test hives with DFIRBatch, Kroll_Batch and a batch file of every plugin's key, and 706 rechecking the other plugins' generated cases. Each of the 1,332 runs reports the same number of errors per plugin as the reference; only the wording of .NET's messages differs. Real rows came for UserAccounts and TaskCache. The hives have nothing for ApplicationSettingsContainer (no settings.dat) or AppCompatFlags (no `CIT\System` key), so those two were only compared on generated data.

Known differences: UserAccounts' `Year > 1700` checks are in UTC where the original uses the machine's time zone, which only matters within hours of the start of 1700. A group with a member count of 2147483647 and a member of unknown type never ends in the original (read from its source, not run); here the group's list of members just ends there, as with any other count.

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

## Real extractions (2026-11-05)

Two KAPE extractions (31 GB, one with 3 shadow copies), not in this repository. 750 runs of RECmd: the 261 hives with DFIRBatch and Kroll_Batch, searches on the main hives, and `-d` on each extraction. Output files and exit codes are identical. A batch file of every plugin's key gives rows from 58 of the 69 plugins; the extractions have no rows for AppCompatFlags, Ares, DHCPNetworkHint, DsrmAdminLogonBehaviour, LastVisitedMRU, OpenSaveMRU, the 4 7-Zip plugins and SyscacheObjectTable, so those remain checked on generated data only.

- **Plugin order.** Where two plugins share a key (Adobe and AdobeTrustManager on `Software\Adobe`), the original runs them in the order the file system lists its Plugins folder, so its batch rows depend on the folder. NTFS lists names sorted, which is this port's order. Compare with a Plugins folder created in that order (`LC_ALL=C sort -f`): on btrfs the listing follows creation order, and a plain copy can differ.
- **Console.** The original logs `Error getting ValueData` several times per value where this port logs it once (known), and under `-d` it also tries files that aren't hives (7 and 2 here) and reports them, where the Windows build skips them.

## Accented letters (2026-11-05)

Checked against .NET 10: case mapping on every code point, `CompareTo` and `InvariantCultureIgnoreCase` on 140,909 pairs of accented strings, and 547 runs on a hive with accented key names, value names and data (Latin-1 and UTF-16 names, composed and decomposed forms), plus 628 on the plugin hives with accented text in their values. Sorting uses ICU4X's root collation, as .NET uses ICU's; only 2 of the pairs differ, both with stacked combining marks. Output files are identical.

Known differences that remain:

- **Regex case rules.** Rust's `(?i)` and .NET's `IgnoreCase` differ for `i`/`I`/`İ` (.NET matches them together), `s`/`S`/`ſ`, `β`/`ϐ` and `σ`/`ς` (Rust matches them together). This changes hits of `--regex` searches and of `--sd`/`--ss`, which use a regex inside, only on data holding those letters. Common accented letters match the same. `\w` and `\b` also differ on some of the 65,000 BMP characters, but gave the same results on the Latin test strings.
- **Names that aren't valid UTF-8 (Linux only).** Neither tool processes a folder or hive so named. This port logs it (`Unable to read folder`, and exit code 1 in LECmd) where the original skips the folder silently.

