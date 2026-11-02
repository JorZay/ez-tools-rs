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
