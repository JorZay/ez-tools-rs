# Plan: porting WxTCmd to Rust

Status: done (2026-11-09), against WxTCmd `5677ea8a6e38e9d9f66970e90b5fb509bdfe06be`, version 2026.10.1. Crates `activitiescache-ez` and `wxtcmd`.

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| `Classes/` (`ActivitiesCache`, the three entry classes, `SqliteCopy`) | ~840 | `activitiescache-ez` |
| `Program.cs`, `ConsoleLog.cs`, `TempFolder.cs` | ~600 | `wxtcmd` (temporary folder: `ez_common::cli::prepare_temp`) |

Options: `-f`, `--csv`, `--dt`, `--temp`, `--debug`, `--trace`, `--co`. Outputs: `<time>_<user>_ActivityOperations.csv`,
`_Activity_PackageIDs.csv`, `_Activity.csv` (each only with rows), console log.

The only library from NuGet with output of its own is GuidMapping 2026.10.2, which is `guidmapping-ez`. SQLite is rusqlite's bundled
3.53.2; the original's Microsoft.Data.Sqlite 10.0.13 has 3.53.3. Every query is a `SELECT *` of a whole table, in rowid order, so the
row order doesn't depend on the version: no difference was seen, also on damaged databases.

## Kept from the original

- The database, its `-wal` and its `-journal` are copied to `WxTCmd-<id>` in the temporary folder and only the copy is opened, read-write
  (a WAL is read, a hot journal rolled back, in the copy). `PRAGMA writable_schema = ON` before the tables are read, so a truncated
  database still gives the rows before the damage. A table that fails part way keeps its rows; the error is listed, exit code 0.
- Columns by name in any case (OrdinalIgnoreCase), a missing one is null: every schema since 1803 works. Values by their SQLite storage
  class, as Microsoft.Data.Sqlite's `GetValue`: text and blobs as UTF-8 (U+FFFD for bad bytes), numbers as .NET writes them (`1E+20`,
  `-0`, `Infinity`), 16-byte blobs as .NET GUIDs, other blobs as hex.
- Numbers and times given as text are read as `int.TryParse`/`long.TryParse` with `NumberStyles.Integer`: white space around, a sign,
  and NUL characters at the end (`"1646000000\0"` is a time). Reals are truncated; a time of 0 (or 0.5) is no time.
- JSON is System.Text.Json's: strict, at most 64 levels, the first property of a name in any case (OrdinalIgnoreCase: the dotless i and
  the long s don't match), non-strings as their raw text (`{"a" : [1, 2]}` keeps its spaces). An escaped unpaired surrogate is an error
  only when that string, or a property name before the one looked for, is read: what was read before it stays (a payload's time zone
  but no display text).
- `Payload` is shown when it starts with `{` as `string.StartsWith` compares in the culture: characters without collation weight
  before it (a BOM, U+00AD, U+200B, NUL...) are skipped, so such a payload is shown as it is (and fails as JSON); a combining mark right
  after the `{` makes it `(Binary data)`. The same for ClipboardPayload's `[`, after `TrimStart` (U+00A0 is trimmed, then fails as JSON).
- ClipboardText: `Convert.FromBase64String` skips white space anywhere and doesn't check the unused bits (`aGVsbG9=` is `hello`);
  content of only white space is an empty text, which still adds a ` | `.
- ContentUri: `WebUtility.UrlDecode` (`+` is a space, `%XX` bytes with the ASCII around them as UTF-8), then a known folder GUID right
  after `file:` or `file:///` (not `file://`, not in upper case) is named.
- Executable: Win32 or `x_exe_path`, else `windows_universal`, else the first object; a known folder GUID before the first `\` is named.
  AdditionalInformation of Activity_PackageId only for names with `.exe` (case-sensitive). Platform names exactly as written
  (`packageId` → `Package`, but `PACKAGEID` stays).
- Duration: only with an end after 1970 that differs from the start; negative when the end is earlier (`-11.13:46:40`).
- `--dt` is `DateTimeOffset.ToString(format, InvariantCulture)`: the standard formats are the invariant culture's (`G` is
  `MM/dd/yyyy HH:mm:ss`, the empty format adds ` +00:00`) and the era is `A.D.`. A format .NET rejects stops at the first time written:
  that CSV has its header, whole rows and the row cut before that time; no later CSV; exit code 1. Rows without times pass.
- The user in the CSV names: the folder after the last `\Users\` or `/Users\` (ASCII case ignored, as the original's regular expression) in
  `-f` as given; `Users/<file>` gives the file's name.
- Exit codes: 1 for bad arguments, a missing file, a temporary folder or CSV folder that can't be written, a file that can't be copied;
  0 for a damaged database, not a SQLite database, or one without the timeline tables.
- Bad values are listed after the counts, at most 100 per table, then `<table>: N more errors`.

## Known differences

- Console: the banner, help and argument errors are this port's, and the JSON and SQLite error texts are close to the original's but not
  .NET's wording. The console log's name has this port's version. No administrator warning (as the original on Linux).
- A damaged schema can have column names that aren't UTF-8; they are read as .NET reads them (rusqlite would refuse them).

## Results

`tools/parity-wxtcmd.sh` (Linux original, files and exit codes) and `tools/gen-wxtcmd-dbs.py` (the databases). Inputs: the original
repository's three samples (Windows 11 with every row in the WAL, Windows 10 with Cyrillic text, plaso's 1803 schema), 8 databases of real
KAPE extractions (Windows 10 and 11, with WAL files, one with ActivityOperation rows), 26 made databases (a table of 323 activities, 191
operations and 74 package ids with every payload, AppId, clipboard, URI, time, number, GUID and string shape above; 1803-like and odd
schemas, lower case tables, views, missing columns, UTF-16, WAL only, hot journal, not a database, empty, truncated, bad header, bad
schema, user names in paths) and 40 randomly damaged copies of the Windows 10 sample.

- Linux: 79 runs over all inputs, 125 CSVs (10,497 lines) identical; 85 option runs (35 `--dt` values on two databases, `--co`, `--debug`,
  `--trace`, `--temp`, missing and repeated arguments) with 180 CSVs and all exit codes identical.
- Windows (the original built for win-x64 on the Windows 11 25H2 VM): 145 runs (every input above, the VM's own database from a shadow
  copy, 29 `--dt` values on two databases, options), 283 CSVs byte for byte identical, all exit codes the same.

Untested: a real ActivityOperation row with a clipboard payload (no sample has one; the format is the original's guess too), and
databases locked by a running system (the original's copy shares the file; this port reads it as a normal file).
