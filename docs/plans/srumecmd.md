# SrumECmd port

Status: done (2026-11-05), against EricZimmerman/Srum `6dbb636b4fe734874c3439e1f0db5cb7dce618ab`, SrumECmd 2026.10.1. Crates `ese-ez`, `srum-ez` and
`srumecmd`. The original stops on anything but Windows; on 2026-11-08 it was run on Windows 11 25H2 (a self-contained `win-x64` build of the same commit) and its
CSVs are byte for byte identical to this port's on every database here, 1.58 million rows. "Checks" says what was compared with what.

## What is ported

| Original (C#, EricZimmerman) | Rust |
|---|---|
| ManagedEsent and Windows' `esent.dll`, through `EseWorkspace` | `ese-ez`, a reader of its own |
| `SrumData/Srum.cs`: tables, id map, apps, SIDs, SOFTWARE hive | `srum-ez` |
| `SrumECmd/Program.cs`, `ConsoleLog` | `srumecmd` |

Options: `-f`, `-d`, `-r`, `--csv`, `--dt`, `--temp`, `--debug/--trace`, `--co`. CSVs: `<time>_SrumECmd_<name>_Output.csv`, with a byte order mark, for EnergyUsage,
AppTimelineProvider, vfuprov, AppResourceUseInfo, NetworkConnections, NetworkUsages and PushNotifications always, and ProcessorTime, SizeInBytes, TotalUsed and
NetworkBytes when they have rows.

## The ESE reader

`ese-ez` reads the header, the catalog (`MSysObjects`, page 4), each table's B-tree in key order, and fixed, variable and tagged columns. It is read-only and takes the
file as it is. Every offset is checked, so damage is an error and not a panic. Deleted records are skipped, as ESE does.

Left out on purpose, because no database here has them, so code for them couldn't be tested. Each gives a row error naming the column, and the rest is read:

- **Long values** (separate trees for values too large for a page).
- **Compressed values** (7-bit and Xpress).
- **Values with several parts** (multi-valued tagged columns).

`SumECmd`'s databases may need them, which would be the time to add them, with real samples to check against. Across the 12 databases below, about 3.8 million
rows, none of the three occurs and no table has a long value tree.

Pages written by newer ESE versions (seen on Windows 11 25H2, format `0x620,300,620`) keep the number of reserved tags in bits 12 to 14 of the page header's tag
count (`itagState` in Microsoft's ESE source, `cpage.hxx`); the reader masks the count and starts after those tags. Older pages leave the bits 0 and have one.

Also not done: page checksums aren't verified, and pages of 16 KB and more are handled by what's known of the format but have no sample; all databases here have 4 KB pages.

## Checks

| Check | Against | Size | Result |
|---|---|---|---|
| **Whole tool, `-f` (and `-r` where there is a hive)** | **The original, run on Windows 11 25H2** | **The 9 samples, 5 databases from 2 real KAPE extractions, and the VM's own database (25H2); 113 CSV files, 1,575,448 rows** | **Byte for byte identical** |
| Whole tool, `-d`, and the default `--dt` | The original on Windows | 2 extraction folders, the VM's folder, the 9 samples in one tree (the same database chosen); 39 CSV files | Identical |
| Row counts per table | Upstream's `SampleTests`, on the public DFIR Artifact Museum samples | 9 samples, 7 tables each | All equal |
| Exact values on Server 2022 (the newer tables) | The same tests | 1 sample | All equal |
| Dirty and clean copies of one database | Each other | 3 pairs (the header of one "dirty" copy says clean) | Identical CSVs |
| CSV format: each row rebuilt with `SrumData`'s classes and written by `CsvHelper` with `ExportCsv`'s maps | The original's code, without `esent.dll` | 67 files and 20,068 sample rows; 39 files and 1,551,247 real rows | Identical |
| Id map: `AppInfo`, SID text, SID types | The original's classes | All entries of 9 samples | Identical |
| SOFTWARE hive: user names by SID | The original's `ReadSoftwareHive`, by reflection | 6 real hives, 94 users | Identical |
| Real KAPE extractions | Sense: dates, names, the databases not changed by reading (SHA-256) | 5 databases | No read problems; dates fit; unchanged |
| Damage: random bytes, page fields and truncation | No panic, no hang | 300 runs | None |

What this shows and doesn't:

- **The format of the CSVs is the original's own**, because its code wrote the comparison file. What goes into them is only compared by counts, the exact Server 2022 values and clean and dirty pairs.
- **Values were compared with the original's**, on Windows, through `esent.dll` itself. The first run found the 25H2 page format above: this port stopped on the VM's database with "Page 4 says it has 4103 tags"; nothing older has it.
- **Wi-Fi profile names** went untested on real data: none of the 6 hives has any.
- **Windows 8** databases went untested: the samples and extractions are Windows 10, 11 and Server.

## Differences from the original

- **No log replay and no repair.** The original copies the database, replays `SRU*.log` into the copy, and repairs it with `esentutl /p` if that fails. This reads the file as it is, and warns if its state isn't Clean Shutdown. On the samples whose state really is dirty (2), nothing is lost, as their clean twins show, and the original on Windows, which replays their logs, gives the same CSVs. A live database is rarely dirty on disk: SRUM attaches it only to flush (0.35 s on the VM), and copies taken from a shadow copy and after killing the service were both clean. A database whose newest pages are only in its logs would lack those rows: run `esentutl /r` on Windows first if that matters. The ESE log format isn't documented, and a replay couldn't be checked here.
- **`--temp` is accepted and ignored.** Nothing is copied, and nothing is written next to the database.
- **`-d`** follows the Windows (net472) build: non-empty files only, and no folder or link is taken for a database. Folders are read in NTFS order, as on Windows (`ez_common::cli::read_dir_ntfs_order`), so the same database is found first.
- **The console:** `-d`'s line shows the format version from the header, where the original runs `esentutl /mh` and shows the version that attached it and the local engine's. Messages about the copy and the repair don't apply. An unexpected column size has this port's own wording.
- **The local time zone:** the original takes an ESE time as local in EnergyUsage, which only shows with an offset in `--dt` on a machine not on UTC.
- **Memory:** about 1 GB for a 120 MB database with 350,000 rows, as all rows are kept until they are written.
- **The console log's name** has this port's version, as in the other tools.

## Comparison harnesses

Not in this repository, as they use the original's assemblies: two small .NET programs reference `reference-builds/SrumECmd/SrumData.dll`, rebuild rows with its
classes and print how it reads the id map (`crates/srum-ez/examples/dump_id_map.rs` prints the same from this port). Use `--dt "yyyy-MM-dd HH:mm:ss.fffffff"`, so
each time can be read back whole.
