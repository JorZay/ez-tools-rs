# Plan: porting MFTECmd to Rust

Status: done (2026-11-02). All phases below are ported and compared with the original.

## Decisions

- Same functionality and output as MFTECmd: the same options, CSV/JSON/bodyfile byte for byte, the same exit codes.
  No multi-file runs or merging: one `-f` per run, with `-m $MFT` for $J and $LogFile, as the original.
- Not ported: `--vss`, `--dedupe` (live systems and shadow copies), `--lowmem` (.NET garbage collection), raw reads
  of locked files, telemetry.
- One workspace for all the tools (see Layout).

## What is ported

| Original (C#, EricZimmerman/MFT and MFTECmd) | Lines | Rust |
|---|---|---|
| MFT ($MFT: FILE records, attributes, paths, slack) | ~5,300 | `ntfs-ez::mft` |
| MFT.LogFile ($LogFile: restart areas, pages, records, open attribute tables) | ~1,500 | `ntfs-ez::logfile` |
| Usn ($UsnJrnl:$J) | ~550 | `ntfs-ez::usn` |
| Secure ($Secure:$SDS) | ~480 | `ntfs-ez::sds` |
| Boot ($Boot) | ~300 | `ntfs-ez::boot` |
| I30 (directory index allocations, slack entries) | ~240 | `ntfs-ez::i30` |
| MFTECmd (CLI, $J path rewind, $LogFile rows, outputs) | ~4,600 | `mftecmd` |

Options: `-f`, `-m`, `--csv/--csvf`, `--json/--jsonf`, `--body/--bodyf/--bdl/--blf`, `--de`, `--fls`, `--dd/--do`,
`--dr`, `--ds`, `--dt`, `--sn`, `--fl`, `--at`, `--rs`, `--ir/--re/--rm`, `--cutoff`, `--debug/--trace`, `--co`.
File type detected from the content, as `GetFileType` does.

2026.11 (upstream `2612386`, MFTECmd 2026.11.1): `-d <folder>` (every file named `$MFT*` but `$MFTMirr*` under it that is an $MFT, each
processed into a numbered folder of `.MFTECmd_<time>_d` in each output folder, then joined by file name, CSVs keeping one header, and the
temporary folder deleted; not with `-m`, `--vss`, `--de`, `--dd`, `--dr`); `-m` with `-f $I30` (a new last column, `ParentPath`, empty
without `-m`); `--mno` (the `-m` $MFT is only used for the paths); JSON for $Boot, $SDS and $I30; JSON enums by name (`SiFlags`,
`NameType`, as in the CSV); `ResidentDataDecoded` after `ParseErrors` (`ntfs-ez::mft::resident`: Recycle Bin `$I` files, in use and
free, always; with `--ir`, UTF-16 text the ASCII column can't show). Kept as the original does it: the joined bodyfile of `-d` has each
part's byte order mark, and a `--bodyf` ending in `.csv` loses each later part's first line (the join skips a CSV's header). Compared
with the original on the repositories' samples, a `-d` folder (nested, `$mft_old`, a `$MFTMirr` and a non-$MFT `$MFT*`), $I30 with
and without `-m`, and two real extractions (870 `$I` rows): all 143 outputs identical.

## Rules kept from the original

- CSV columns and their order per type (`MFTRecordOut`, `JEntryOut`, `LogFileOut`, `I30Out`, `SdsOut`, `BootOut`);
  the $MFT CSV ends with `ParseErrors`, with the three `ResidentData*` columns before it only with `--ir`.
- Output names `<timestamp>_MFTECmd_<type>_Output.<ext>`; JSON one object per line (ServiceStack style).
- `-m` with `-f $J`/`$LogFile` also exports the $MFT with default names.
- $J `ParentPath` rewinding (newest to oldest in USN order, issue #56) with an $MFT; empty without one.
- Exit codes 0 and 1: damaged, empty or unknown files are reported and exit 0.
- Input may be corrupt or hostile: bounded lengths, no loops without progress, errors per record.

## Phases

1. Workspace reorganization (below), no behavior change.
2. $MFT: records, fixups, attributes, attribute lists, extension records, paths; CSV/JSON/bodyfile, `--sn`, `--at`,
   `--fl`, `--rs`, `--ir/--re/--rm`, `--cutoff`.
3. $Boot, $SDS (`--ds`), $I30 (with slack).
4. $J, with `-m` and path rewinding.
5. Dump options: `--de`, `--fls`, `--dd/--do`, `--dr`.
6. $LogFile, with `-m`.
7. Parity script against the original on the example files and the repos' samples; timings.

Each phase is checked against the original's output on the same files.

## Layout (one workspace)

```
ez-tools-rs/                (this repository, renamed)
  crates/
    ez-common/              console log, .NET date formats, CSV/JSON writers, output names, file discovery
    evtx-ez/   evtxecmd/    (existing)
    ntfs-ez/   mftecmd/
    registry-ez/ recmd/     (later; see recmd.md)
  maps/  tools/  docs/plans/
```
