# Plan: porting LECmd to Rust

Status: planned, not started. Line counts and samples are from the upstream clones of 2026-11-04.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| GuidMapping (14,469 GUID names, 2 prefixes) | 175 + data | `shellitems-ez::guids` |
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
- ExtensionBlocks: `6dd29c0318c15d16ac86755dba021f35913461d1`, **not confirmed**: the clone is shallow and has no tags, so check it
  is 2026.10.9.
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

## Open questions

None block the start. Do real `.lnk` files from your cases exist that can be used as extra samples? They wouldn't be committed.
