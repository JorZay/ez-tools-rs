# Plan: porting SQLECmd to Rust

Status: done (2026-11-05), against `c67634af503bd53777689998f1d9e3c0b4e2fdff`, version 2026.10.3. Crates `sqlmap-ez` and `sqlecmd`, the
unmodified maps in `maps-sqlecmd/`. Results and known differences are under "Results".

## What is ported

| Original (C#, EricZimmerman) | Lines | Rust |
|---|---|---|
| SQLMap (`MapFile`, `SqlMap.LoadMaps`, validation, header check) | ~340 | `sqlmap-ez` |
| SQLECmd (`Program.cs`, `DatabaseCopy`, `TempFolder`, `ConsoleLog`) | ~1,480 | `sqlecmd` |
| What System.Data.SQLite, Dapper, CsvHelper and ServiceStack do to a value | not in the repo | `sqlmap-ez::value` |
| `NativeSqlite.cs` | ~110 | Not needed: SQLite is built in |

About 1,900 lines. The tool is small, but its output depends on the libraries it calls, and that is where most of the work is.

Options: `-f`, `-d`, `--csv`, `--json`, `--blobdir`, `--noblob`, `--ifn`, `--dedupe`, `--hunt`, `--maps`, `--temp`, `--sync`,
`--debug`, `--trace`, `--co`. `--dedupe`, `--hunt` and `--co` default to true (`--hunt false` turns hunting off).

Outputs: one CSV per query, one JSON lines file per run, blob files, console log. Upstream's exit code rules are kept as they are.

## Requirement: the maps work without changes

Any `.smap` the original accepts must load here and give the same result, including users' own maps and those `--sync` brings in
later. There is no conversion step, no fork of the maps and no Rust-only field. Three parts make that true.

### 1. Reading the map

| Original's behaviour | What the port does |
|---|---|
| Every `*.smap` under `--maps`, recursively, in any case; default `Maps` next to the program | The same |
| Files sorted with `OrderBy(t => t)`, a culture-aware comparison, not byte order. This order decides which map wins on a duplicate `Id`, and the run order | Emulate that comparison for paths; check against the reference with all 93 maps |
| `IdentifyValue` is always text, so `05` stays `05` | Read YAML events and keep the raw text (see "Checked for this plan") |
| YamlDotNet rejects unknown fields, and field names match exactly. A map with an extra field is an error, and any map error gives exit code 1 | The same, with the same messages |
| `Version` is a double and can't be 0 | The same |
| `null`, `~` and empty values are null, so the validator rejects them | The same, using the scalar's style: a quoted `'null'` is text |
| FluentValidation messages, such as `'CSV Prefix' must not be empty.` (expected wording) | Take the wording from the reference, one bad map per rule |
| `BlobExtension` must match `^[a-zA-Z0-9_]+$` | The same |
| A byte order mark is accepted; aliases, duplicate keys and several documents go through YamlDotNet | Test each one against the reference and match it |

`!OS_Application_OptionalDescription.guide` and `.template` aren't `.smap`, so they aren't loaded. The guide says `FileName` is
case sensitive, but the code compares without case. The code is what gets ported.

### 2. Running the SQL

The SQL has to run on rusqlite's SQLite and do what it does in System.Data.SQLite:

- **Identifying a database:** `IdentifyQuery`'s first column of the first row, as text, compared with `IdentifyValue` ignoring case.
  With `--hunt` every map is tried on every SQLite file. Without it, only maps whose `FileName` equals the file's name.
- **Several statements in one query:** upstream's data reader accepts them; rusqlite's `prepare` refuses them. No shipped map
  has them, but a user's map may, so run the statements one at a time and take the rows of the first that returns columns (the
  exact rule comes from the System.Data.SQLite source).
- **Read-write copy:** only a copy is opened, read-write as upstream does, so a map can create a temporary table and a `-wal` is
  replayed. `amcache-ez` already has this copy; move it to `ez-common` rather than write it twice.
- **Extra SQL functions:** System.Data.SQLite's native library adds about 50 functions (`extension-functions.c`: math, `reverse`,
  `padl`, `charindex`, `stdev`, `median` and so on). No shipped map uses them, but a user's map could: `sqlmap-ez::functions` has them
  all, with their quirks. On Linux their math errors read as glibc's errno text; Windows' text isn't known here.
- **SQLite version:** the reference has 3.46.1 and this port 3.53.2. Two differences would change a map's results and are handled: reals become
  text with 15 digits (`SQLITE_DBCONFIG_FP_DIGITS`, the default became 17 in 3.52), and FTS5, which the reference doesn't have, is removed
  (`sqlite3_drop_modules`), so a query on such a table fails the same way. See Risks for what remains.

### 3. Turning the rows into output

Maps are written against the output the original gives, so a value must come out the same. This is the largest risk.

- **Types come from the declared column type, not only the stored value.** System.Data.SQLite maps the column's declared type (76 names)
  to a .NET type: `DATETIME` gives a `DateTime`, `BOOLEAN` a `bool`, `GUID` a `Guid`, and so on. A computed column, like `DATETIME(x)` in a
  map, has no declared type and stays as stored. So `SELECT *` on a `DATETIME` column and `SELECT datetime(col)` print differently. Text in
  an `INT` column reads as `0`, and 300 in an `INT8` as `44`. The table is `sqlmap-ez::value`, tested with all the names against 26 stored values.
- **A bad value can fail the whole query.** Anything in a `DATETIME` column that isn't one of its date formats throws, as does text in a `BOOLEAN` or a `GUID`
  that isn't one. The error is logged for that query and no file is written.
- **Formatting:** CsvHelper with the invariant culture writes doubles, dates, booleans and blobs not named in `BlobColumns`.
  ServiceStack writes the same values to JSON, dates as `yyyy-MM-ddTHH:mm:ss.fffffffZ`.
- **Connection setting:** `DateTimeKind=Utc`, so a value with a time zone is not moved to the local time.
- **Duplicate column names** (`SELECT a.id, b.id`): Dapper's handling decides the header and values. Test it, as joins are common.
- **`SourceFile` and `MapDescription`:** added to each row. A query column with the same name is overwritten, not duplicated.

Upstream behaviours that look like bugs and must stay:

- Blob columns are removed row by row, only where the value is a byte array. A row where the column is null keeps it, so its
  values may shift against the header, which comes from the first row. Confirm this with the reference, then keep it.
- With `--csv` and `--json` together, a query with no rows hits `continue` at the CSV step, so only one warning is logged.
- Two queries in one map with the same `BaseFileName` collide on `FileMode.CreateNew`: an export error and exit code 1.
- Without `--hunt`, a file matched by several maps is found once per map. Dedupe then skips the repeats with a warning.

## Checked for this plan

Using a scratch program with this workspace's `yaml-rust2` 0.13 and `rusqlite` 0.40.2:

| Check | Result | Consequence |
|---|---|---|
| Parse the 93 shipped maps | All parse | `yaml-rust2` stays, no new YAML crate |
| `IdentifyValue` through `YamlLoader` | Not text in any of the 93 | The usual loader can't be used: `05` or `0x10` would change. Use its event parser |
| Fields used in the shipped maps | The 10 map fields, 4 query fields and 3 blob fields of `MapFile.cs`, nothing else | The format is fully known |
| Bundled SQLite | 3.53.2 | The reference has 3.46.1 |
| Double-quoted strings | Accepted | `Windows_EdgeBrowser_Collections` needs them (`items.type == "website"`) |
| Several statements in `prepare` | Refused | Needs the statement loop above |
| `pi`, `sqrt`, `reverse`, `stdev` | Not in the bundled build | Registered. `regexp` isn't in the reference either |
| SQL functions in the 138 shipped queries | `datetime`, `strftime`, `json_extract`, `hex`, `substr`, `length`, `julianday`, `group_concat`, `coalesce`, plus `CAST`: all in the bundled build (only `json_extract` was run; the rest are core SQLite) | Shipped maps need nothing extra |
| Identify queries with `pragma_table_info` | 3 maps (`Windows_Firefox_History`, `Windows_Firefox_HistoryLegacy`, `TestFiles_BlobTest_Three`) | Both Firefox maps use it to tell schema versions apart, so test both with old and new schemas |
| `WITH` queries | 1 (`Windows_pCloud`) | Nothing special |

## Reference

SQLECmd targets `net10.0` and runs on Linux, so it can be built here with .NET 10, as for the other tools. It loads its native
library from `runtimes/linux-x64/native`. Build it with `dotnet publish SQLECmd -c Release -r linux-x64`, then copy `SQLMap/Maps` next to it.

Pin these and record them in `docs/upstream.md`: SQLECmd `c67634a`, System.Data.SQLite 1.0.119, ServiceStack.OrmLite.Sqlite 10.4.0 (its
copy of Dapper), CsvHelper 33.1.0, YamlDotNet 17.1.0, FluentValidation 11.12.0.

## Steps

1. **Reference and type table.** Build the reference. Get the System.Data.SQLite 1.0.119 source for the declared type table, the
   `GetValue` rules and its date formats. Run a test database with every declared type against every stored kind (null, integer,
   real, text, blob, bad values) through both CSV and JSON. This table specifies `sqlmap-ez::value`, so it comes first.
2. **`sqlmap-ez`, maps.** Event-based YAML, validation, sort order, messages. Test: all 93 shipped maps load, and each bad-map case
   matches the reference.
3. **`sqlmap-ez`, running.** Header check, statement loop, identify, value conversion, System.Data.SQLite's error text
   (`SQL logic error` and so on; `amcache-ez` has Microsoft.Data.Sqlite's, which differ).
4. **`sqlecmd`.** Options and help, file search in .NET's order, dedupe, CSV, JSON, blobs, unmatched list, console log, exit codes.
5. **`--sync`**, behind the `sync` feature, as in `recmd` and `evtxecmd`. It downloads the same folder of upstream's repository.
6. **Parity script** (`tools/parity-sqlecmd.sh`) and a database generator, then the docs as for the other tools.

Steps 2 and 3 are good commit points. Step 1 only writes results into this plan.

## Checks

- **The maps are unmodified.** Keep an untouched copy in `maps-sqlecmd/` (`maps/` is EvtxECmd's), recorded with its commit
  in `docs/upstream.md`. A test loads it and compares file hashes against a list taken from upstream, so an edit fails the test.
  Parity always runs both programs with `--maps` pointing at this same folder.
- **Every query is run.** Upstream ships only 5 test databases, for its `TestFiles_*` maps, so 88 maps have no database. A generator
  (`tools/gen-sqlecmd-dbs.py`) makes one per map: start from the tables in `IdentifyQuery`, then add each table or column SQLite
  reports missing until all of the map's queries run. Rows come from the type table's values. This proves each of the 138 queries
  runs and gives the same rows on both sides, but the declared types are partly guessed.
- **Real databases.** Fresh throwaway profiles of Firefox and Chromium on this machine give real schemas with no personal data.
  Mobile and app databases depend on samples being available.
- **User-style maps.** A set written for this: several statements, extra functions, comments, a byte order mark, quoted values, odd
  `IdentifyValue`s, duplicate `Id`s, nested folders.
- **Upstream's tests.** `MapTests`, `SqLiteFileTests` and `CliTests` (21 CLI tests) as a checklist: corrupt database, locked file, unreadable
  folder, evidence unchanged, temp folder rules.
- **Parity.** All of the above with `--hunt` on and off, `--dedupe` on and off, `--noblob`, `--blobdir`, `--ifn`, `--csv`, `--json` and both
  together. Every file, console and exit code, with time stamps, the elapsed time and stack traces masked.
- **Damage.** Generated databases with random bytes damaged, with a time limit: no panics, same files and exit codes.
- **Evidence.** Hash the input folder before and after, including `-wal` files.

## Results

Against the reference built from `c67634a` (2026-11-05), with `tools/parity-sqlecmd.sh`: every file, the console and the exit code.

| Test set | Runs | Result |
|---|---|---|
| Every declared type against every stored kind, CSV and JSON | 2 | Identical (2,184 queries) |
| All SQL functions with odd arguments, including the extra ones | 1 | Identical (1,892 queries) |
| Blob, duplicate column, several statement, identify and date cases | 4 | Identical, but for the SQLite version, compile option and function lists |
| The 93 shipped maps, unmodified, on generated databases, upstream's 5 and real Firefox and Chromium schemas, plus each map with identification forced | 199 | Identical (1,498 files) |
| Options, folders, links, WAL, damaged and non-SQLite files | 32 | Identical |
| Bad and unusual map files, each with and without `--debug` | 116 | Identical, but for one message |
| Generated and real databases with random damage | 220 | Identical (366 files), no panics |
| Non-ASCII paths, maps and columns, FTS4, FTS5, R-tree | 3 | Identical |

Coverage of the shipped maps: 85 of 93 maps and 118 of 138 queries gave rows. These 8 maps never did, because the guessed schema doesn't fit them (their
queries gave the same result on both sides, usually an error): `Windows_EventTranscriptDB_DataSampling`, `Windows_EventTranscriptDB_NoDataSampling`, `Windows_Firefox_Downloads-Places`,
`Windows_GoogleDrive_Changes`, `Windows_Ivanti_IvAppMon`, `Windows_YourPhone_NotificationsDB`, `iOS_Calls`, `iOS_HealthDb_Secure`.

Known differences:

- **File names of blobs:** `:` `*` `?` `"` `<` `>` `|` `\\` and control characters become `_`, as on Windows and in upstream's guide. On Linux the original only replaces `/`.
- **A folder that can't be read:** named in the message, and each counted, as on Windows. On Linux the original names the `-d` folder for all of them, as the handle is opened later there.
- **A YAML syntax error:** the same exit code and list of maps, but the parser's own text differs. For a tab that breaks indentation, the message and the "bad line" don't match YamlDotNet's.
- **`--trace`:** the original also dumps each map as text; that isn't ported. `--debug` lacks its line about loading `SQLite.Interop.dll`.
- **`SELECT sqlite_version()`, `pragma_compile_options`, `pragma_function_list`, `pragma_module_list`:** they report this build. `sqlite_stmt` isn't available.
- **Sorting of maps:** Latin-1 accents are handled as ICU does; other letters sort in code point order. This only matters for the run order and duplicate `Id`s.
- **Math errors on Windows:** the messages are glibc's, as the Linux reference has them.

## Risks

- **Sample gaps.** Generated databases and empty browser profiles show that the queries run and that values convert the same, not what a real, full database gives. Real
  databases from your cases would help, and the 8 maps above have no rows yet.
- **Other SQLite changes.** 3.47 to 3.53 can change results. On a real extraction (2026-11-05) `Windows_ChromiumBrowser_Favicons`, which joins three tables and sorts only by `favicons.id`, gives the same rows with ties in another order: 3.46 uses an automatic covering index on `icon_mapping`, 3.53 its existing index. SQLite 3.46.0 gives the reference's plan, but 3.53.2 is kept on purpose: these databases come from machines that may be compromised, and the order of ties means nothing. All other files were identical (123 files, 4 runs), and rows are never lost or changed. Newer functions (`if`, `unistr`) exist here and not in the reference, so a
  map that relies on those failing would differ.
- **Damaged databases.** Newer SQLite could read a damaged file differently. In 220 runs it didn't.

## Windows and Linux differences

Where the two differ, this port follows Windows if that build is more complete, as in the other ports: see the file names and unreadable folders above.

## Not ported

Exceptionless telemetry, as in the other tools.

## Open questions

None block the start. Are there real databases from your cases (Chrome, Firefox, Windows Timeline, `wpndatabase.db`, mobile) to use as extra samples?
