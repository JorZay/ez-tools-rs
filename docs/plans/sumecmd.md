# SumECmd port

Status: done (2026-11-09), against EricZimmerman/Sum `d2f5cb3c644654d17bb51c22acbc8e6289e52237`, SumECmd 2026.10.1. Crates `sum-ez` and `sumecmd`, on `ese-ez`
(extended for this port, below). The original reads with Windows' `esent.dll` and stops on anything else, so it was run on Windows 11 25H2 (a self-contained
`win-x64` build of the same commit, `reference-builds/windows/SumECmd`). Its CSVs are byte for byte identical to this port's on every input here but one kind:
a dirty database whose newest rows are only in its transaction logs (below). "Checks" says what was compared.

## What is ported

| Original (C#, EricZimmerman) | Rust |
|---|---|
| ManagedEsent and Windows' `esent.dll`, through `EseWorkspace` (copies, log replay, `esentutl /p`) | `ese-ez`, reading the files as they are |
| `SumData/Sum.cs`: the databases, tables, years and day dates | `sum-ez` |
| `SumECmd/Program.cs`, `ConsoleLog`, `TempFolder` | `sumecmd` |

Options: `-d` (required), `--csv` (required), `--wd` (on by default), `--dt`, `--temp`, `--debug/--trace`, `--co`. Seven CSVs, `<time>_SumECmd_SUMMARY_{SystemIdentInfo|RoleInfos|ChainedDbInfo}_Output.csv`
(always, a header at least) and `<time>_SumECmd_DETAIL_{Clients|ClientsDetailed|DnsInfo|RoleAccesses|VmInfo}_Output.csv` (each with its first row; `ClientsDetailed`
with the first client when `--wd`, even if no client has a day count), UTF-8 with a byte order mark, CRLF.

What the original does and this port too:

- `SystemIdentity.mdb`, then `Current.mdb`, then each `CHAINED_DATABASES` entry whose file is there (twice if listed twice), then every other `.mdb` of the folder
  (case ignored), in the order Windows lists the folder. Either first file may be missing; with neither, an error and exit code 0.
- Values read as ManagedEsent's `RetrieveColumnAs...` read them: text as UTF-16 (whatever the column's code page; an odd last byte left out) without NUL padding;
  a value shorter than its type is a row error, a longer one gives its first bytes; a missing column is null. `TotalAccesses` over `int.MaxValue` is clamped with
  an error; a FILETIME below 0 or past `DateTime.MaxValue` is `0001-01-01` with an error.
- A row that fails is reported and left out; a client row that fails in its day columns still reserves its role's place in the order of the CSV, as the original's
  dictionary does. Roles are in the order first met; role names are the first `ROLE_IDS` entry of the GUID, `(Unknown Role Guid)` if none.
- `Current.mdb`'s year: the latest client, role or DNS time in it (after 1601), else the newest chained year + 1, else the year its file was last written. A year
  `new DateTimeOffset` refuses (a chained year 0 or over 9999), or a day 366 of 9999, stops the original before any CSV with exit code 0; this port too.
- `IpAddress`: more than 10 bytes in hex, a colon after every 2; up to 10 as decimal numbers with dots.
- A database the original's ESE can't attach is "could not be opened" and the others are read. That includes databases with pages other than 4 KB: the original's
  ESE instance keeps `esent.dll`'s default page size and refuses them ("The database page size does not match the engine"), so this port does too, although
  `ese-ez` reads them. Real UAL databases have 4 KB pages.
- A bad `--dt`: each summary file stops at its first time (the header, and the row cut before that time, as CsvHelper leaves it), and the detail files stop at
  the first time of all, with exit code 1 (`docs/cli-options.md`).
- Exit codes: 1 for bad arguments, a missing `-d` folder or `--csv`, a database or log file that can't be read (the original fails in copying it), or an export
  that failed; 0 otherwise, also with damaged or missing databases.

## Differences from the original

- **No log replay and no repair.** The original copies the databases and the `Svc*` logs to a temporary folder, replays the logs into the copies, and repairs a
  copy that is still dirty with `esentutl /p`. This reads the files as they are, and warns when one isn't in Clean Shutdown (saying so when logs are next to it).
  - Without logs, the repair keeps what the file has: on the real extraction below (`Current.mdb` dirty, no logs, repaired by the original), 7,032 clients and
    1,425 DNS rows, identical CSVs. A dirty database whose logs were replayed (the Server 2016 sample) gave identical CSVs too.
  - With logs that hold rows the file doesn't have yet, those rows are missing here. The synthetic `dirty` case (ESE ended with `JET_bitTermDirty`, nothing
    flushed) has `Current.mdb`'s two clients, its DNS row and its role access only in the logs: the original shows them, this port doesn't. A live server's
    `Current.mdb` is usually dirty; how much is only in its logs depends on when ESE last flushed. Replaying ESE's logs would mean redoing its page operations
    (inserts, splits, merges), and the log format isn't documented: not done. On Windows, `esentutl /r svc /i` in a copy of the folder first gives the original's result.
- **`--temp` is accepted and ignored**: nothing is copied, and nothing is written next to the databases. The original stops with exit code 1 when that folder
  can't be written to; this port doesn't need it.
- **The console**: messages about copies, replays and repairs don't apply; this port's own wording for damage (the original has ESE's errors) and the dirty-state
  warning. Trace lines don't print each row. The administrator check is left out. The console log's name has this port's version, as in the other tools.
- **Damage**: what `esentutl /p` would make of a damaged database can't be known here; this port reads what it can and reports the rest per row or table.

## What `ese-ez` gained

Each of these was added for UAL and checked against `esent.dll` with databases built on Windows (below), following Microsoft's ESE source (MIT):

- **Long values** (`lv.hxx`, `rec.hxx`, `lv.cxx`): a tagged value flagged "separated" holds a long value id (4 or 8 bytes, little-endian); the table's long value
  tree (catalog type 4) has a root node per id (big-endian key; reference count and size) and chunk nodes (key: id and offset). Chunks shorter than their place
  in the value are compressed. Keys are rebuilt from the page's prefix (the external header, except on root pages; `node.cxx`).
- **Compression** (`compression.cxx`): 7-bit ASCII and UTF-16, Xpress (`_xpress`, CODING_DIRECT2) and LZ4, which Windows 11's `esent.dll` writes for long values.
  Xpress9, Xpress10 (Exchange) and encrypted values are errors. Windows 11 compressed the test values with 7-bit UTF-16 (916 values) and LZ4 (8 long
  values); 7-bit ASCII and Xpress are checked by unit tests only.
- **Multi-valued tagged columns** (`tagfld.hxx`): the first value, of both layouts (two values; several, with offsets), as `JetRetrieveColumn` gives it.
- **Null tags**: a tag flagged null (`0x2000` on pages under 16 KB, the header's `0x20` on larger ones) is null; it read as an empty value.
- **Pages of 16 and 32 KB**: every tagged value there has a header byte; `ese-ez` took the tag's `0x8000` bit (which means "derived column") for it, and read text
  one byte off. The 16 and 32 KB cases below now give the same rows as the 8 KB one.
- `Row::read` does all of this and gives owned bytes where it must; `Row::value` (what `srum-ez` uses) is unchanged for values in the record, and still reports long
  and compressed values as errors. SrumECmd's CSVs on the 5 real SRUM databases are identical before and after (1.55 million lines).

## Checks

| Check | Against | Size | Result |
|---|---|---|---|
| **Whole tool** | **The original, run on Windows 11 25H2** | **A real KAPE extraction of Server 2022 (`Current.mdb` dirty, its yearly database, `SystemIdentity.mdb`), the DFIR Artifact Museum's three samples (Server 2012 R2, 2016 with logs, 2019), and 21 folders built with `esent.dll`: 120 CSV files, 1,181,479 lines** | **Byte for byte identical** |
| The one that differs | The same | The synthetic `dirty` folder: rows only in the logs | 2 clients, 1 DNS row and 1 role access missing here (above) |
| Options | The original on Windows | 21 runs: `--wd`, `--dt` (standard, custom, empty, 6 bad ones), `--co false`, `--debug`, `--trace`, `--temp`, a folder without databases; 5 bad command lines | Identical files and exit codes |
| Damage | No panic, no hang | 300 runs of random bytes, page fields and truncation | None |
| SrumECmd after the `ese-ez` changes | Its CSVs before | 5 real SRUM databases | Identical |

The synthetic folders (`tools/gen-sumecmd-dbs`, run on Windows) use the column names, types and order of the real Server 2022 databases: every table, edge values
(times 0, negative, past the maximum; `TotalAccesses` over `int.MaxValue`; day 60 and 366 in leap and other years; IPv4, IPv6, 10, 11 and 0 address bytes; text with
commas, quotes, line breaks, spaces at the ends, odd byte counts, lone surrogates, NUL padding, empty values), roles listed twice or without a name, chained
databases listed twice, in another case, without a year or a name, missing or not listed, `.MDB` names, a database that isn't one, no `SystemIdentity.mdb`, a
year from each source, years that stop the original, 9,000 clients and 7,000 DNS rows (trees of several levels), primary indexes in descending order, long
values of up to 120 KB (several chunks, forced apart), compressed columns, a multi-valued column, and 8, 16 and 32 KB pages.

`crates/ese-ez/examples/dump_schema.rs` prints a database's state, tables, columns and row counts.

To rerun: build `tools/gen-sumecmd-dbs` for `win-x64`, make the folders on Windows, run the original on each (`--dt "yyyy-MM-dd HH:mm:ss.fffffff"` keeps whole
times), and compare with `tools/parity-sumecmd.sh <results> < cases`.

Not tested: real databases with long values, compressed values or virtual machines (none of the real ones has any; the synthetic ones do), Windows Server 2025, and
dirty databases from busy servers with their logs.
