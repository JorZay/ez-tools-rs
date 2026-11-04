# Plan: porting SrumECmd to Rust

Status: planned, not started. One decision is needed first: see "Decisions". Upstream: EricZimmerman/Srum
`6dbb636b4fe734874c3439e1f0db5cb7dce618ab`.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| `SrumData/Srum.cs` (tables, id map, app and SID decoding) | ~2,470 | `srum-ez` |
| `SrumECmd/Program.cs`, `ConsoleLog`, `TempFolder` | ~870 | `srumecmd` |
| `EseWorkspace` over ManagedEsent and Windows' `esent.dll` | ~260 + Windows | `ese-ez`, new |

The original code is small. The work is that it hands all database reading to `esent.dll`, so this port needs its own ESE
reader. `SumECmd` uses the same `EseWorkspace`, so `ese-ez` makes it cheap afterwards.

Options: `-f`, `-d`, `-r` (SOFTWARE hive, through `registry-ez`), `--csv`, `--dt`, `--temp`, `--debug/--trace`, `--co`.

CSVs, each named `<time>_SrumECmd_<name>_Output.csv`: EnergyUsage, AppTimelineProvider, vfuprov, AppResourceUseInfo,
NetworkConnections, NetworkUsages, PushNotifications, ProcessorTime, SizeInBytes, TotalUsed, NetworkBytes.

## The ESE reader

What exists, checked 2026-11-04:

| Option | Reads | Replays logs | Notes |
|---|---|---|---|
| `esent.dll` (the original) | everything | yes | Windows only |
| `libesedb` (C bindings) | most | no | LGPL-3.0, not pure Rust |
| `ese-parser` 0.1 | pages only | no | no B-tree walk yet |
| `ese-core` 0.2.2 (under `srum-parser`) | catalog, B-tree, fixed, variable and tagged columns | no | Apache-2.0; no long value or compression code found |
| Own `ese-ez` | what SRUM and SUM need | to be written | same design as the other crates |

**Recommendation: write `ese-ez`**, with `ese-core` and libesedb's documentation of the format as guides, and libesedb's
`esedbexport` as an independent cross-check. `ese-core` alone doesn't cover long values or compression, which SRUM's blob
columns may need, and this project keeps damaged input handling and error messages under its own control. Depending on a
young crate for the hardest part of the tool, then having to patch it, seems the worse trade.

## Steps

1. **`ese-ez`, clean databases.** Header (with what `esentutl /mh` shows: state and versions), pages for each format version,
   the catalog, B-tree walk, fixed, variable and tagged columns, long values, compressed columns. Every page and record is
   bounds checked: damage is reported and the rest is read.
2. **`srum-ez`.** `SruDbIdMapTable` (types 0 to 4, `AppInfo`, SIDs), then each provider, column by column, with `ParseErrors`
   and `Warnings` as in the original. Optional SOFTWARE hive for user and Wi-Fi profile names.
3. **`srumecmd`.** Options, console, CSVs with the classes' column order.
4. **`ese-ez`, log replay.** Replay `SRU*.log` into a copy for dirty databases. This is the largest unknown: the log format
   is the least documented part of ESE. Copies only, never next to the evidence, as in the original.
5. **Docs and parity script.**

Steps 1 to 3 give a tool that handles every clean database, and they are worth committing alone.

## Checks

**The original can't run here.** It stops on anything but Windows ("Non-Windows platforms not supported"), and its tests need
Windows too, so there is no reference on this machine and no parity like the other tools have without a Windows system.

Without one, these remain:

- **Row counts from upstream's `SampleTests`:** 9 DFIR Artifact Museum samples (MIT; Windows 10, 11 and Server 2022), with the
  expected count per table, and some exact values for Server 2022.
- **Clean and dirty pairs:** the same database, clean and dirty, for 3 of the systems. After replay, the two must give the
  same output, which tests replay without needing Windows.
- **`esedbexport`:** table contents compared with `ese-ez` on the samples, for an independent reader.
- **Damage:** samples with bytes flipped and truncated: no panics, and what can be read still comes out.

These prove the data is read correctly, but not that CSVs are byte-identical to the original, as formatting choices and
messages can't be compared.

## Risks

- **Log replay** might turn out to be too large or too unreliable. Fallback: read the database as it is, with a warning, and
  document that `esentutl /r` on Windows should be run first.
- **`esentutl /p` repair** of a dirty database without logs won't be ported: it is a Windows tool that rewrites the database. The
  port reads what it can and says so. Its output will differ from the original's on those files.
- **Format versions:** ESE's page and record formats vary with the Windows version, and the samples only cover Windows 10, 11
  and Server 2022, so Windows 8 goes untested.
- **Compression:** the samples will show which columns use it. If none do, it's still needed for other systems, without samples.

## Decisions

1. **Can you provide a Windows machine or VM?** This decides how far the checks can go. With one, the original can be run on
   the samples, and I can compare byte for byte; `.NET` on Windows would also give the exact messages. Without one, the
   checks above are what's possible, and that would be stated as a limit of this port. Recommended: yes, if it's available.
2. **Own `ese-ez`, as recommended above?**
3. **Is log replay in scope?** Recommended: yes, but after the clean path works, with the fallback above if it fails.

## Order

LECmd first (`docs/plans/lecmd.md`): it has a reference here and unlocks JLECmd, SBECmd and RECmd's shell item plugins, while
this tool waits on decision 1 and carries the largest unknown. SrumECmd can start right after, or in parallel if you need
the exfiltration evidence sooner. It ranks 8th to LECmd's 9th.
