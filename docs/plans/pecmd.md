# Plan: porting PECmd to Rust

Status: done (2026-11-04), identical to PECmd 2026.10.3 in `tools/parity-pecmd.sh`. Upstream commits: `docs/upstream.md`.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| Prefetch (versions 17 to 31, XPRESS Huffman, hash) | ~1,200 | `prefetch-ez` |
| PECmd (`Program.cs`, `ExecutablePathResolver`) | ~2,100 | `pecmd`, `prefetch-ez::resolve` |

Options: `-f`, `-d`, `-k`, `-o`, `-q`, `--csv/--csvf`, `--json/--jsonf`, `--html`, `--dt`, `--mp`, `--dedupe`,
`--debug/--trace`, `--co`. `--vss` and `--ads` warn and are ignored, as the original does outside Windows.

## Checks

- `crates/prefetch-ez/tests/upstream.rs`: 214 assertions generated from the Prefetch library's own tests.
- `crates/prefetch-ez/tests/samples.rs`: its robustness and hash tests, over its 54 samples and files built in memory;
  every byte of a built file changed and every length tried, without a crash.
- These need `PREFETCH_TEST_FILES` set to `Prefetch.Test/TestFiles`; without it the sample checks do nothing.

## Parity

The reference is PECmd retargeted to net9.0 (with the Prefetch NuGet package 2026.10.1), run with LANG=en_US.UTF-8.
Console, exit code, CSV, time line, JSON, XHTML report and CSS compared; SourceAccessed left out (see the script).

- The 55 Prefetch.Test files one by one and as a folder, also with `--mp`, and with `-q --dt --dedupe -k`.
- 67 damaged files (truncated, bad offsets and counts, bad times, MAM errors, 40 with random bytes changed) and a folder
  named like a prefetch file, one by one and as a folder.
- By hand: `-o`, `--html`, `--csv`/`--json` on a file, `--csvf`/`--jsonf` forms, `--debug`, `--trace`, `--vss/--ads`,
  missing inputs, bad arguments, links to folders, and files whose last write time is before or after their change
  time (SourceCreated is the older of the two, not the birth time). The `--co` log file matches too (without the banner).

Not covered: real extractions (only the samples above), and the .NET 10 build the original ships.

## Differences from the original

- Banner and help are this port's. .NET stack traces after errors aren't printed.
- `directories.png` and `filesloaded.png` are written next to the report on every system (the original skips them
  outside Windows, though `style.css` uses them).
- An export stopped by an error leaves empty files; the original can leave whatever it had flushed.
- Messages of unusual OS errors are Rust's.
- With `-q`, a file shorter than its 84-byte header is listed under Failed files and skipped, as without `-q`. The
  original lets it through and the export then stops ("Object reference not set..."), leaving every output empty and
  exiting 1. Fixed on purpose, as it loses the results of all the other files. Worth reporting upstream.

## Original behaviour kept on purpose (worth reporting upstream)

- `-o name` without a folder fails: "The value cannot be an empty string".
- A relative `--html` fails: the report's path repeats the folder (`rel/rel/...`).
