# AmcacheParser port

`crates/amcache-ez` (library, no printing or exits) and `crates/amcacheparser` (CLI), from AmcacheParser 2026.10.1. Upstream
commit in `docs/upstream.md`.

## What it reads

- `AmcacheOld`: `Root\File` and `Root\Programs` (Windows 7 and 8).
- `AmcacheNew`: the `Root\Inventory*` keys (Windows 10 and 11). A hive upgraded from Windows 8 can have both, and then also
  gets `_OldFormat` CSVs.
- `AmcacheNew::from_databases`: the `Inventory*.db` SQLite databases of Windows 11 26H1 on (`rusqlite`, with SQLite built in),
  through the same code as the keys. Each database is copied with its `-wal` and `-journal` to a new folder in `--temp` (or
  `Temp` next to the program), and only the copy is opened, so nothing is written next to the evidence.

Options: `-f`, `-i`, `-w`, `-b`, `--csv`, `--csvf`, `--dt`, `--mp`, `--nl`, `--temp`, `--debug`, `--trace`, `--co`.

`RegistryKey.ToString()` moved from `recmd` to `registry_ez::details`, as this tool logs it for a key it can't parse.

## Parity

`tools/parity-amcache.sh` against AmcacheParser built with .NET 10, the only runtime upstream targets (CSV files byte for
byte, console and exit code; the console log too where the run has `--co`).

- 50 runs, 0 differences: both DFIR Artifact Museum hives (the upstream samples: a dirty Windows 10 hive with logs and a
  Windows Server 2012 R2 one), with `-i`, `--mp`, `--dt`, `--nl`, `-w`, `-b`, `--debug` and default names; databases made with
  upstream's Windows 11 26H2 schemas (bad dates, bad numbers, older copies of rows, a damaged page, rows only in a `-wal`,
  a garbage file, an empty file, BLOB and REAL columns, more than ten bad rows, unknown columns); a hive next to databases;
  a missing or unwritable output or temp folder.
- 124 damaged hives (flipped bytes, truncations, changed value lengths, offsets, types and names, and a hive with both
  formats): no panics; every CSV and exit code identical. 54 differ on the console only: see below.
- No real `Inventory*.db` samples are public, so databases from a real Windows 11 26H1 system have not been tried.

Upstream's `HiveTests` and the core of `DatabaseTests` are in `crates/amcache-ez/tests/upstream.rs` (the samples need
`AMCACHE_TEST_FILES`, upstream's `AmcacheParser.Test/TestFiles/DFIRArtifactMuseum`); `crates/amcacheparser/tests/cli.rs`
covers the program.

## Differences from the original

- Banner and help are this port's. .NET stack traces after errors aren't printed.
- `FileExtension` follows Windows, where these paths come from: on Linux the original gives `.d\noext` for `c:\x.d\noext`,
  and this port, like the Windows build, gives nothing.
- A date with `Z` or an offset in a value is given in UTC. The original converts it to the local time of the machine it
  runs on, so its output depends on that machine. Run with `TZ=UTC`, the two match.
- `DateTime.Parse` is reproduced for the forms in the parity cases (`M/d/yyyy`, `yyyy-M-d`, month names, a leading weekday,
  12 and 24 hour times, offsets). A form it doesn't cover, such as a time with no date, is left empty and counted in the
  invalid dates, where the original might read it. Windows writes the forms covered.
- Damaged hives: the low-level `Error getting ValueData` and `Error getting data block` lines can be repeated less often, or
  come at another point, as the original reads a value again each time, and the second line lacks the exception's type.
  CSVs are the same.
- A multi-line `Key data:` message in the console log has the `[time level]` prefix on every line, not just the first.
- `--temp`'s default is next to this program, as in the original, so its path differs.
- `.db` file names match in any case, as on Windows. The original on Linux only finds them written as `Inventory*.db`.
