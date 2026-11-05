# Plan: porting LECmd to Rust

Status: done (2026-11-05), against LECmd `b5bbf29e4b58384fe7bd4384cb4851960c31dc83`, version 2026.10.4. Crates `shellitems-ez`, `lnk-ez`
and `lecmd`. Results and known differences are under "Results". Line counts are from the upstream clones of 2026-11-04.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| GuidMapping (14,469 GUID names, 2 prefixes) | Done | `guidmapping-ez` |
| ExtensionBlocks: 32 `0xbeef` blocks, property sheets and stores | ~8,100 | `shellitems-ez::blocks` |
| ExtensionBlocks: shell items (`ShellItems/`, 88 files) | ~11,100 | `shellitems-ez::items` |
| Lnk (MS-SHLLINK: header, ID lists, LinkInfo, strings, extra data) | ~2,300 | `lnk-ez` |
| LECmd (`Program.cs`, 26,230 line MAC vendor list, CSS) | ~1,900 + data | `lecmd` |

About 23,000 lines, nearly all of it in the shell items and blocks. That part is the reason to do this tool early:
JLECmd, SBECmd and the shell item plugins of RECmd all need the same library, so `shellitems-ez` is written once, here.

Options: `-f`, `-d`, `-r` (removable only), `-q`, `--all`, `--nid`, `--neb`, `--csv/--csvf`, `--json`, `--pretty`, `--xml`,
`--html`, `--dt`, `--mp`, `--cp`, `--debug/--trace`, `--co`.

Outputs: console (`DisplayLnk`), CSV, JSON lines (`ToJson`, or `Dump` with `--pretty`), one XML file per link
(`ToXml`), XHTML report with its CSS, console log.

## Pin the right source first

LECmd uses the libraries through NuGet versions: **Lnk 2026.10.11, ExtensionBlocks 2026.10.9, GuidMapping 2026.10.2**. Porting from
any other commit would give differences that look like bugs, so step 0 is confirming each one and recording it in
`docs/upstream.md`. The clones of 2026-11-04:

- Lnk: `dab1c8ab9c1c18d2cf89a4938ab95794d17d3a44`, the tag 2026.10.11.
- GuidMapping: `e2c93615a491ca43197b36960a436b559062cb52`, the tag 2026.10.2.
- ExtensionBlocks: `897bbe3`, the tag 2026.10.9. HEAD at the time, `6dd29c0318c15d16ac86755dba021f35913461d1`, is **not** what LECmd uses.
- LECmd: `b5bbf29e4b58384fe7bd4384cb4851960c31dc83`.

## Reference

LECmd targets `net10.0` as well as `net472`, and nothing it uses needs Windows, so the reference builds and runs here with
.NET 10, as for PECmd. On Linux it enumerates with `System.IO`; the Windows build uses AlphaFS.

## Steps

1. **Reference and harness.** Build LECmd. Write a scratch dump program over the three packages that prints every shell item's
   and extra block's `ToString()`, which is how upstream checks its own changes: it finds differences in the library long
   before the CLI is finished.
2. **`shellitems-ez`, blocks.** `BeefBase`, the simple blocks, `Beef0004` (in almost every item, so its speed matters),
   then property sheets and stores with the property name table in `Utils` (~4,400 lines, mostly data).
3. **`shellitems-ez`, items.** `ShellItemFactory` and the items by type, signature and layout. Largest first: `0x00`, `0x79`,
   `0x1f`, then `0x2e`, `0x32`, MTP, CFSF, CD burning, zip and archive contents.
4. **`lnk-ez`.** Header, ID list, LinkInfo, StringData, extra blocks, and its error model: fatal problems are errors, and
   damaged parts go to `ParseErrors` while the rest of the file is still read.
5. **`lecmd`.** Console first, then CSV, JSON, XML, XHTML.
6. **Parity script** (`tools/parity-lecmd.sh`), then the docs, as for the other tools.

Steps 2 and 3 are good commit points. Each is usable and testable alone.

## Checks

- **Samples:** `Lnk.Test/TestFiles`, 1,002 real and damaged links from XP to Windows 10; `ExtensionBlocks.Test/TestFiles/ShellItemSamples.txt`
  (base64 shell items).
- **Upstream's tests:** `SpecComplianceTests` (581 lines, builds links in memory), `TestMain`, `ShellItemTests` (579 lines), `SharedTests`.
- **Parity:** every sample one by one and as a folder, with `--all`, `--nid`, `--neb`, `-r`, `--pretty`, `--mp`, `--dt`, `--cp`.
  CSV, JSON, XML, XHTML, console and exit code byte for byte, with `SourceAccessed` masked (each read can change it).
- **Damage:** the shell item samples and links randomly damaged, with a time limit: no panics and no endless loops. Upstream
  warns that sizes in the data must not drive a loop that doesn't move forward.
- **Check coverage:** count which item and block types the reference reported, so a clean result can be trusted.

## Risks

- **Culture in the library.** `Utils.DateTimeFormat` left unset means the culture's own pattern with milliseconds and the
  offset, and it reaches the text of blocks and items. Same choice as RECmd: en-US, as .NET writes it, and the parity reference
  runs with `LANG=en_US.UTF-8`.
- **Code pages (`--cp`).** ANSI strings use any Windows code page, where `ez-common` only has 1252. This needs `encoding_rs` or a table,
  and .NET's handling of bad bytes has to be matched.
- **Small differences in text.** The `ToString()` of a property sheet is long and full of .NET number and array formatting.
  Most parity work is expected here.
- **Sample gaps.** Upstream's largest corpus is private (about 1,500 links and jump lists), and `ITA_LNKs` isn't in the
  repository. Items that only appear there go untested, so real links from your own cases would help.
- **Windows and Linux differences.** Where the Linux reference differs from the Windows build because of path handling, this
  port follows Windows where that is more complete, as `FileExtension` does in AmcacheParser, and each case gets documented.

## Results

Compared with the reference built from the same commits on .NET 10, with `LANG=en_US.UTF-8` and `TZ=UTC`, excluding the banner, timings and stack
traces. Every result below is 0 differences:

| Check | Size |
|---|---|
| Upstream's shell item samples, one by one (`ToString()`, every block) | All of `ShellItemSamples.txt` plus those inside the links |
| Upstream's links, as read by the library | All 1,002 |
| Whole tool over the samples: every output and option (`tools/parity-lecmd.sh`) | 12 runs |
| Whole tool over randomly damaged links | 4 runs over 1,500 links |
| Whole tool on edge cases (links, empty files, bad paths and options) | 23 runs |
| Whole tool with `--cp`: 21 code pages, built-in and invalid ones included | 22 runs |
| Whole tool with `TZ=America/New_York` | 1 run, 557 files |
| Links randomly damaged, as read by the library | 6,000 |
| Shell items randomly damaged | 40,000 in the final run |
| Blocks and items generated to reach what the samples don't | 360,000 over 6 seeds |
| All 116 single and double byte code pages, against random bytes and every byte pair | 12,064 and 33,023 strings per page |

**Coverage, and why the generated data exists.** The clean samples reach only 35 of the 85 item classes and 9 of the 35 block classes, so a clean result on
them alone says little. The generated items put every block signature after a valid `0xbeef0004`, and build MTP, FindData and Nokia items, so that every
block class and every item class that can reach the output was compared (`ShellBagParseError` can't: it only exists inside `Beef0005`, which shows it as a
placeholder). This shows the code reads such data as the original does. It isn't real data, so what only real files contain, like the private corpus upstream
tests with, remains untested. It found one bug, an MTP folder failing with the wrong error, and a check of `--cp` found that pages `encoding_rs` lacks or reads
differently gave wrong text, so all single and double byte pages now come from tables generated from .NET.

Upstream's own test projects (`SpecComplianceTests`, `ShellItemTests`) weren't ported; their sample files were compared with the reference instead, and this
repository's tests build items and links in memory.

### Known differences

- **The machine's time zone.** The original shows local time in two places: `Beef0008`'s timestamp, and date properties of MTP items (which it also shifts
  by the offset). This port shows UTC, wherever it runs. None of the 1,002 samples has these, so with `TZ=America/New_York` all their output is identical. With
  `TZ=UTC` there is no difference at all.
- **XHTML folder name.** The original on Linux makes folders of the path's separators (`_for_/home/x/index.xhtml`); this port uses underscores as on Windows.
- **Unreadable folders** are named as on Windows, as in the other ports.
- **Dates in zip contents.** .NET's `TryParse` accepts forms such as `23:09:1z`, which this port doesn't. One string in 320,000 damaged items.
- **`--cp` with a stateful encoding:** ISO-2022 (`50220`, `50221`, `50222`, `50225`), HZ (`52936`), ISCII (`57002` to `57011`) and the 4-byte part of GB18030 (`54936`). None is a Windows
  ANSI code page. `50220` to `50222` and `54936` use `encoding_rs`, whose results differ from .NET's on many strings; the others read as 1252. The other 116 pages are exact.
- **The console log's name** has this port's version, not LECmd's, as in the other tools.

Windows and Linux differences: as in the other ports, Windows wins where it is more complete, as for the two names above.

`crates/shellitems-ez/data/dbcs.txt` is 1.4 MB, for the code page tables generated from .NET. `shellitems-ez` is now available for RECmd's 4 waiting
plugins, and for JLECmd and SBECmd.

## Open questions

Do real `.lnk` files from your cases exist that can be used as extra samples? They wouldn't be committed.
