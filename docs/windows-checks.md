# Checks against the originals on Windows

The other comparisons run the originals' Linux builds. On 2026-11-08 every port was also compared with its original running on Windows 11 25H2
(build 26200, en-US, UTC), to check what only shows there.

## How

- **The originals:** each built from the commit in `docs/upstream.md` with `dotnet publish -c Release -f net10.0 -r win-x64 --self-contained`,
  from a checkout with CRLF line endings, as Git for Windows makes it. This matters: LECmd and JLECmd split their MAC vendor list on
  `Environment.NewLine`, so a build from an LF checkout finds no vendor on Windows. Batch files and maps were CRLF too, on both sides.
- **The data:** the VM's own artifacts, taken from a shadow copy (hives with their logs, Amcache with its 25H2 `Inventory*.db` databases,
  437 prefetch files, 213 event logs, SRUM, 96 LNK files and jump lists, Edge's SQLite databases), the registry files of two real KAPE
  extractions (122 hives), and the SRUM databases of `docs/plans/srumecmd.md`.
- **The comparison:** every output file, after masking what differs between two machines by nature: the input and output folders (and
  their separators), time stamps in file names, the copied files' own times (`SourceCreated`, `SourceModified`, `SourceAccessed`), LECmd's
  hash of the source path in XML file names, and the random `InternalId` in JLECmd's JSON.

## Results

| Tool | Runs | Result |
|---|---|---|
| AmcacheParser | `Amcache.hve -i`; one of the 25H2 `Inventory*.db` databases | Identical (58 files) |
| AppCompatCacheParser | SYSTEM | Identical |
| EvtxECmd | 213 logs, CSV and JSON | CSV identical (98,041 lines); JSON: line breaks (below) |
| JLECmd | Jump lists: CSV, JSON, `--fd` | Identical (26 files) |
| LECmd | LNK files: CSV, JSON, XML, `--all` | Identical but for JSON line breaks (below) |
| PECmd | 437 prefetch files: CSV, time line, JSON | Identical but for JSON line breaks (below) |
| RBCmd | The VM's Recycle Bin | Identical; it held no deleted files |
| RECmd | `-d` with DFIRBatch and Kroll_Batch on the VM and the extractions; SIDs with `BinaryConvert: SID` | SIDs identical; the rest differs by AM/PM and line breaks only (below) |
| rla | `-d` on the VM and on 122 hives of the extractions | Identical, every saved hive |
| SQLECmd | `-d` on the VM | Identical but for the known order of Favicons rows with equal keys (`docs/plans/sqlecmd.md`) |
| SrumECmd | `-f`, `-r`, `-d`, `--dt` (`docs/plans/srumecmd.md`, `docs/cli-options.md`) | Identical but for AM/PM (below) |

MFTECmd wasn't run: the NTFS metadata files can't be copied from a running Windows as files.

## What was fixed

- **The order of `-d`.** The originals find files breadth first, a folder's entries in the order NTFS lists them: by upper-cased name.
  The ports kept each folder in the order the file system gives it, as the Linux originals do, which on Linux is no particular order.
  They now sort each folder as NTFS does (`ez_common::cli::read_dir_ntfs_order`): PECmd, LECmd, JLECmd, SQLECmd, RBCmd (also the files
  of a deleted folder), RECmd, rla and SrumECmd. The Linux originals can now list the same files in another order than the ports.
- **SrumECmd** on 25H2 databases and with a bad `--dt` (`docs/plans/srumecmd.md`, `docs/cli-options.md`).

## What differs on Windows, and not on Linux

Two things where .NET itself behaves differently on Windows. The ports follow the Linux originals in both:

- **AM and PM.** A standard date format (`G`, `t`, the default `ToString()` of a date in RECmd's plugins...) has a space before AM and
  PM on Windows, where .NET takes its culture data from Windows; ICU, which .NET uses on Linux, has U+202F (narrow no-break space).
- **Line breaks in values.** `Environment.NewLine` is `\r\n` on Windows and `\n` on Linux. It shows inside values the originals build line
  by line (RECmd's plugin details, LastVisitedPidlMRU and OpenSavePidlMRU), and between records of the JSON files of EvtxECmd, LECmd and
  PECmd.
