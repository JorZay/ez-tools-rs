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
| AmcacheParser | `Amcache.hve -i`; one of the 25H2 `Inventory*.db` databases | Identical |
| AppCompatCacheParser | SYSTEM | Identical |
| EvtxECmd | 213 logs: CSV, JSON; `--fj` | Identical (104,440 records) |
| JLECmd | Jump lists: CSV, JSON, `--pretty`, `--html`, `--fd` | Identical |
| LECmd | LNK files: CSV, JSON, `--pretty`, XML, `--html`, `--all`; a link with CR, LF and CRLF in its values | Identical |
| PECmd | 437 prefetch files: CSV, time line, JSON, `--html` | Identical |
| RBCmd | The VM's Recycle Bin | Identical; it held no deleted files |
| RECmd | `-d` with DFIRBatch and Kroll_Batch, CSV and JSON, on the VM and the extractions; SIDs with `BinaryConvert: SID`; `--kn` with `--json`, also of a key named with `"<>\|:*?%` and a tab | Identical |
| rla | `-d` on the VM and on 122 hives of the extractions | Identical, every saved hive |
| SQLECmd | `-d` on the VM, CSV and JSON | Identical but for the known order of Favicons rows with equal keys (`docs/plans/sqlecmd.md`) |
| SrumECmd | `-f`, `-r`, `-d`, `--dt` (`docs/plans/srumecmd.md`, `docs/cli-options.md`) | Identical |
| RecentFileCacheParser | Generated and damaged files, upstream's samples: CSV, JSON, `--pretty`, options (`docs/plans/recentfilecacheparser.md`) | Identical (576 runs) |
| WxTCmd | The VM's own `ActivitiesCache.db`, upstream's samples, 8 databases of the extractions, generated and damaged ones; 29 `--dt` values and every option (`docs/plans/wxtcmd.md`) | Identical |
| SumECmd (2026-11-09) | A real Server 2022 extraction, 3 public samples, 21 folders built with `esent.dll`; every option (`docs/plans/sumecmd.md`) | Identical but for rows only in transaction logs, which this port doesn't replay |

MFTECmd wasn't run: the NTFS metadata files can't be copied from a running Windows as files.

## What was fixed

- **The order of `-d`.** The originals find files breadth first, a folder's entries in the order NTFS lists them: by upper-cased name.
  The ports kept each folder in the order the file system gives it, as the Linux originals do, which on Linux is no particular order.
  They now sort each folder as NTFS does (`ez_common::cli::read_dir_ntfs_order`): PECmd, LECmd, JLECmd, SQLECmd, RBCmd (also the files
  of a deleted folder), RECmd, rla and SrumECmd. The Linux originals can now list the same files in another order than the ports.
- **SrumECmd** on 25H2 databases and with a bad `--dt` (`docs/plans/srumecmd.md`, `docs/cli-options.md`).
- **.NET's Windows rules**, below.

## Where .NET on Windows differs from .NET on Linux

The ports write what the originals write on Windows, where they are meant to run. The Linux builds of the originals differ from that
in these, all .NET's own and none the tools' (a probe program built for both showed which culture rules differ; sorting and case
mapping don't):

- **AM and PM.** A standard date format (`G`, `g`, `f`, `F`, `t`, `T`, an empty one, the default `ToString()` of a date in RECmd's
  plugins...) has a plain space before AM and PM on Windows. ICU, which .NET uses on Linux, has U+202F (narrow no-break space).
- **N and P.** Without a precision, these have 2 decimals on Windows and 3 on Linux. Only a console message uses one.
- **`Environment.NewLine`** is `\r\n` on Windows and `\n` on Linux. It ends each record of the JSON files (`TextWriter.WriteLine`: EvtxECmd,
  LECmd, PECmd, RECmd, SQLECmd, MFTECmd), each line of ServiceStack's `Dump()` (`--pretty`), each line of the `--html` reports
  (`XmlTextWriter`'s indenting) and each line break in a value of LECmd's `--xml` (`XmlWriter` writes them as `NewLineChars`), and the
  lines of text the libraries build with `AppendLine`, such as shell items' details in RECmd's plugins (`ez_common::dotnet::NEW_LINE`).
- **Text resources** are built into the originals as they are in the checkout, which has CRLF on Windows: the styles of LECmd's and
  JLECmd's `--html` reports, and the MAC vendor and AppID lists, which LECmd and JLECmd split on `Environment.NewLine`.
- **Invalid file name characters.** RECmd's `--kn` names its JSON file after the key, replacing `Path.GetInvalidFileNameChars`: on
  Windows `"<>|:*?\/`, NUL and the control characters; on Linux `/` and NUL.

The Linux parity scripts in `tools` compare the ports with the Linux builds, so they make both sides the same in the first and third
before comparing (`tools/platform.sh`); the comparison here, on Windows, is exact.
