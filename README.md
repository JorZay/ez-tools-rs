# ez-tools-rs

Rust ports of Eric Zimmerman's forensic tools (https://github.com/EricZimmerman), with the same output and no .NET.
Each tool is a library (which never prints or exits, so other programs can use it) and a thin command line client.

| Tool | Status |
|---|---|
| [EvtxECmd](https://github.com/EricZimmerman/evtx) → `evtxecmd` | Done |
| [MFTECmd](https://github.com/EricZimmerman/MFTECmd) → `mftecmd` | Done |
| [RECmd](https://github.com/EricZimmerman/RECmd) → `recmd` | Core and all 69 plugins done (`docs/plans/recmd.md`) |
| [rla](https://github.com/EricZimmerman/RECmd) → `rla` | Done (`docs/plans/recmd.md`) |
| [PECmd](https://github.com/EricZimmerman/PECmd) → `pecmd` | Done (`docs/plans/pecmd.md`) |
| [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser) → `amcacheparser` | Done (`docs/plans/amcache.md`) |
| [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) → `appcompatcacheparser` | Done (`docs/plans/appcompatcache.md`) |
| [SQLECmd](https://github.com/EricZimmerman/SQLECmd) → `sqlecmd` | Done, uses the original's maps unchanged (`docs/plans/sqlecmd.md`) |
| [LECmd](https://github.com/EricZimmerman/LECmd) → `lecmd` | Done (`docs/plans/lecmd.md`) |
| [JLECmd](https://github.com/EricZimmerman/JLECmd) → `jlecmd` | Done (`docs/plans/jlecmd.md`) |
| [RBCmd](https://github.com/EricZimmerman/RBCmd) → `rbcmd` | Done (`docs/plans/rbcmd.md`) |
| [SrumECmd](https://github.com/EricZimmerman/Srum) → `srumecmd` | Done, identical to the original run on Windows (`docs/plans/srumecmd.md`) |

The upstream commits each port was built from are in `docs/upstream.md`. How the ports compare with the originals running on Windows is in `docs/windows-checks.md`.

## pecmd

A port of PECmd: Windows Prefetch files, versions 17 (XP) to 31 (Windows 11, compressed), shown on the console or
exported to CSV (with a time line), JSON and XHTML, with PECmd's columns.

```
pecmd -d /cases/host1/Prefetch --csv out -q
pecmd -f /cases/host1/Prefetch/CMD.EXE-D269B812.pf
```

## recmd

A port of RECmd: registry hives searched (`--sa/--sk/--sv/--sd/--ss`), keys dumped (`--kn`, `--vn`, `--details`), and
batch files (`--bn`, RECmd's `.reb` files) to CSV or JSON, with RECmd's columns. Dirty hives get their transaction
logs (`.LOG1/.LOG2`, or the old `.LOG`) applied; deleted keys and values are recovered (`--recover`, on by default).
All 69 plugins are ported (list in `docs/plans/recmd.md`): each writes its own CSV or JSON next to the batch output.

```sh
recmd -d /cases/host1 --bn BatchExamples/DFIRBatch.reb --csv out
recmd -f /cases/host1/NTUSER.DAT --sk RunMRU
recmd -f /cases/host1/SYSTEM --kn 'ControlSet001\Services\bam' --details
```

Differences: dates and numbers inside values are en-US as .NET writes them, where the original follows the machine's
language; SID conversions give the SID as on Windows; `--vss` is ignored; as the original's Windows build, `-d` takes any file
whose name holds a hive's name and that has a hive's signature, and doesn't follow links to folders. `tools/parity-recmd.sh`
compares with the original.

## rla

A port of rla: replays the transaction logs of dirty hives (`.LOG`, `.LOG1`, `.LOG2` next to them) and saves the hives, under
their original path in `--out` or, with `--nop`, directly in it.

```sh
rla -f /cases/host1/SYSTEM --out out
rla -d /cases/host1 --out out --nop
```

Differences: as the original's Windows build, `-d` takes any file whose name holds a hive's name and that has a hive's
signature, and doesn't follow links to folders. `tools/parity-rla.sh` compares with the original.

## amcacheparser

Amcache.hve (Windows 7 to 11) and the `Inventory*.db` SQLite databases of Windows 11 26H1 on, to CSV:

```
amcacheparser -f /cases/host1/Amcache.hve --csv /tmp/out
amcacheparser -f /cases/host1/Programs -i --csv /tmp/out --csvf host1.csv
amcacheparser -f /cases/host1/Amcache.hve -b hashes.txt --csv /tmp/out
```

Transaction logs next to a dirty hive are applied, unless `--nl` is given. Databases are read from temporary copies
(`--temp`), so nothing is written next to the evidence. Differences from the original are in `docs/plans/amcache.md`;
`tools/parity-amcache.sh` compares with it.

## sqlecmd

A port of SQLECmd: finds SQLite databases (browsers, Windows Activities Cache, Dropbox, Android, iOS and many more) and runs the queries in its maps against them, to CSV,
JSON and blob files. The maps are the original's `.smap` files, unchanged: `maps-sqlecmd/` has a copy, and your own maps or those from upstream work as they are.

```bash
cargo build --release -p sqlecmd
sqlecmd -d /cases/host1 --maps maps-sqlecmd --csv /tmp/out          # every SQLite file, against every map
sqlecmd -d /cases/host1 --maps maps-sqlecmd --hunt false --csv /tmp/out   # only files with a map's file name
sqlecmd -f /cases/host1/History --maps maps-sqlecmd --json /tmp/out --blobdir /tmp/blobs
```

Without `--maps`, the maps are read from a `Maps` folder next to the program. Only copies of the databases are opened, in `--temp` or a `Temp` folder next to the program, so the evidence
isn't changed, and a `-wal` file is still read. `--sync` needs a build with `--features sync`. Values come out as in the original, which depends on the column's declared type: see `docs/plans/sqlecmd.md`.

## lecmd

A port of LECmd: Windows shortcut (`.lnk`) files, shown on the console or exported to CSV, JSON, XML and XHTML, with LECmd's columns. The shell items and extension
blocks they contain are read by `shellitems-ez`, which the other tools that need them can share.

```
lecmd -d /cases/host1/Recent --csv /tmp/out -q
lecmd -f /cases/host1/Recent/report.lnk
lecmd -d /cases/host1 --all --json /tmp/out --html /tmp/out --cp 932
```

Times are shown in UTC, on any machine: see `docs/plans/lecmd.md` for the few places where the original uses the local time zone.

## appcompatcacheparser

The AppCompatCache (ShimCache) of a SYSTEM hive, Windows XP to 11, to CSV:

```
appcompatcacheparser -f /cases/host1/SYSTEM --csv /tmp/out
appcompatcacheparser -f /cases/host1/SYSTEM --csv /tmp/out -t -c 2
```

Transaction logs next to a dirty hive are replayed, unless `--nl` is given. Entries still in the slack of the value are
recovered on Windows 8 to 11. `tools/parity-appcompatcache.sh` compares with the original.

## mftecmd

A port of MFTECmd: $MFT, $J, $LogFile, $Boot, $Secure:$SDS and $I30 to CSV, JSON and bodyfile, with MFTECmd's
options (`-f`, `-m`, `--csv/--csvf`, `--json/--jsonf`, `--body/--bodyf/--bdl/--blf`, `--de`, `--fls`, `--dd/--do`,
`--dr`, `--ds`, `--dt`, `--sn`, `--fl`, `--at`, `--rs`, `--ir/--re/--rm`, `--cutoff`, `--co`) and output names. The file
type is detected from the content.

```sh
mftecmd -f '/cases/C/$MFT' --csv out
mftecmd -f '/cases/C/$J' -m '/cases/C/$MFT' --csv out      # parent paths as they were when each record was written
mftecmd -f '/cases/C/$LogFile' -m '/cases/C/$MFT' --json out
mftecmd -f '/cases/C/$MFT' --body out --bdl c
mftecmd -f '/cases/C/$MFT' --de 0x270-5
```

The library (`ntfs-ez`) memory maps the $MFT and reads it in two parallel passes instead of holding every record in
memory: on a 1.6 GB $MFT, 4.5 s and 2 GB (mostly the mapped file) against MFTECmd's 36 s and 4.8 GB.

Differences: `--vss`, `--dedupe` and `--lowmem` are accepted and ignored (live systems, .NET); .NET stack traces
after some warnings are not printed. `tools/parity-mftecmd.sh` compares with the original.

## evtxecmd

A port of EvtxECmd: Windows event logs (EVTX) from forensic extractions into one CSV or JSON timeline, with
EvtxECmd's columns, value formats and maps.

It adds what working on many extractions at once needs: any number of files and folders, one timeline sorted by
time, and `--merge`, which collapses copies of the same log (an old and a new `Security.evtx`) into one row per event.

## Layout

| Path | What |
|---|---|
| `crates/ez-common` | What the tools share: .NET date and number formats, CSV and JSON as the EZ tools write them, the console log. |
| `crates/evtx-ez` | The library: parsing, maps, the timeline (sorting, merging), CSV/JSON writers. No printing, no exits: it can go into another program. |
| `crates/evtxecmd` | The command line tool, a thin client of the library. |
| `crates/ntfs-ez`, `crates/mftecmd` | MFTECmd's libraries (MFT, Usn, LogFile, Boot, Secure, I30) and its command line tool. |
| `crates/registry-ez`, `crates/recmd` | RECmd's hive library (the Registry package) and its command line tool. |
| `crates/prefetch-ez`, `crates/pecmd` | The Prefetch library and PECmd's command line tool. |
| `crates/amcache-ez`, `crates/amcacheparser` | The Amcache library and AmcacheParser's command line tool. |
| `crates/appcompatcache-ez`, `crates/appcompatcacheparser` | The ShimCache library and AppCompatCacheParser's command line tool. |
| `crates/rla` | rla's command line tool, on `registry-ez`. |
| `maps/` | EvtxECmd's maps (from its repository, MIT), built into the binary. |
| `tests/fixtures/rust-evtx` | Sample logs from [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (MIT/Apache-2.0). |
| `tools/parity.sh`, `tools/parity-mftecmd.sh`, `tools/parity-recmd.sh`, `tools/parity-pecmd.sh`, `tools/parity-amcache.sh`, `tools/parity-appcompatcache.sh`, `tools/parity-rla.sh` | Compare the tools' output with the originals'. |

## Use

```sh
cargo build --release            # target/release/evtxecmd
cargo build --release --features sync   # with --sync (downloads maps; adds an HTTP client)

# one timeline from several extractions
evtxecmd -d /cases/host1/Logs -d /cases/host1-old/Logs --csv out/
# copies of the same logs merged: each event once, SourceFile lists every copy that had it
evtxecmd -d extraction1 -d extraction2 --merge --csv timeline.csv
# single files (repeat -f), JSON lines, some event ids, a date range
evtxecmd -f Security.evtx -f old/Security.evtx --json out/ --inc 4624,4625,4688 --sd 2024-01-01 --ed 2024-02-01
# to standard output
evtxecmd -d Logs --csv - | head
```

`--csv` and `--json` take a file, a folder (for EvtxECmd's `<timestamp>_EvtxECmd_Output.csv` name), or `-`.
Messages go to standard error, and (unless `--no-log`) to `<timestamp>_EvtxECmd_<version>_ConsoleLog.txt` next to
the output. Run `evtxecmd --help` for every option.

### Order and merging

| Mode | Rows |
|---|---|
| default | Every event of every file, sorted by TimeCreated (ties in file order). |
| `--merge` | Sorted, and copies collapsed: files with the same bytes are read once (BLAKE3), chunks with the same bytes as one already read are not parsed again (xxh3), and rows for the same event are written once. |
| `--unsorted` | File by file, in file order, as EvtxECmd writes them; rows are written as they are parsed. Fastest. |

Files with the same bytes are read once in every mode (EvtxECmd's `--dedupe`); `--keep-identical` reads them all.

The same event means the same TimeCreated, computer, channel, record number and rendered content (a 128-bit hash of
the whole event). Where the record was is not part of it, so copies merge whatever their chunk layout (a log that
wrapped, or an old copy whose last chunk was only partly written). For a merged row:
- `SourceFile` is every file that had the event, joined with `|`, in the order the files were given.
- `HiddenRecord` is true if it was hidden in any copy.
- `ChunkNumber` and `ExtraDataOffset` are the first copy's.

Copies that really differ (a tampered or damaged record) stay separate rows. The summary shows how many chunks and
events were merged, per computer and channel.

Sorting uses `--mem` MB (default 256) of rows; past that, sorted runs go to compressed temporary files (in `--temp`
or the system's temporary folder) and are merged, so the size of a case is not limited by memory.

## Differences from EvtxECmd

- Output is the same as EvtxECmd's byte for byte (CSV, JSON, `--fj`) when rows are in file order (`--unsorted`);
  `tools/parity.sh` checks it. The default order is by time.
- JSON lines end with LF (as EvtxECmd on Linux writes them; on Windows it writes CRLF). CSV lines end with CRLF.
- `-f` and `-d` can be repeated and combined. `--csvf`/`--jsonf` are gone: `--csv`/`--json` take a file name.
- Not ported: `--vss` (Volume Shadow Copies) and reading locked files from a live system; this tool is for
  extractions. Mount shadow copies (e.g. with `vshadowmount`) and pass the folders with `-d`. `--xml` is not ported
  (the library has `EventRecord::to_xml`).
- Map values that are not found are counted in the summary, and listed with `--debug` (EvtxECmd lists each one as a
  warning).
- `--sync` takes the folder to save maps in, and is in builds with the `sync` feature.
- No telemetry.

## The library

```rust
use evtx_ez::{EvtxFile, MapSet, ParseOptions};

let (maps, _report) = MapSet::load_dir("maps")?;
let file = EvtxFile::open("Security.evtx")?;
for chunk in file.par_chunks(ParseOptions { maps: Some(&maps) }) {
    for r in chunk?.records {
        println!("{} {} {:?} {}", r.time_created, r.event_id, r.user_name, r.payload_json());
    }
}
```

`evtx_ez::timeline::run` builds a merged, sorted timeline from many files and hands each row to a `RowSink` (a
closure works); `evtx_ez::output::table` writes rows as EvtxECmd's CSV and JSON.

## Tests

`cargo test` runs the unit tests, the sample logs (record counts as EvtxECmd and the Rust evtx parser find them),
and merging tests (an older copy with a partly written last chunk, a byte-for-byte copy, a wrapped copy, sorting
through temporary files).

To compare with the original on your own logs, build EvtxECmd (`dotnet build EvtxECmd/EvtxECmd.csproj -c Release`
in its repository) and run `tools/parity.sh <EvtxECmd.dll> <Maps> <folder of logs>`.

## License

MIT. Ported from EvtxECmd and the evtx library, Copyright (c) Eric R. Zimmerman, MIT; see `LICENSE`.

## jlecmd

A port of JLECmd: jump lists (`*.automaticDestinations-ms`, `*.customDestinations-ms`) and the links inside them, to the console, CSV, JSON and XHTML, and the
links themselves with `--dumpTo`. `tools/parity-jlecmd.sh` compares with the original, whose quirks are kept; `docs/plans/jlecmd.md` lists them.

```
cargo build --release -p jlecmd
jlecmd -d /cases/host1 --csv /tmp/out --json /tmp/out -q
jlecmd -f /cases/host1/f01b4d95cf55d32a.automaticDestinations-ms --fd
jlecmd -d /cases/host1 --dumpTo /tmp/lnks -q
```

## rbcmd

A port of RBCmd: Recycle Bin files (`$I` from Vista on, `INFO2` from Windows 95 to XP/2003) to the console and CSV, with the files of deleted
folders listed from their `$R` folder. `tools/parity-rbcmd.sh` compares with the original; `docs/plans/rbcmd.md` lists the quirks kept and the differences.

```
cargo build --release -p rbcmd
rbcmd -d '/cases/host1/$Recycle.Bin' --csv /tmp/out -q
rbcmd -f '/cases/host1/$I3VPA17'
```

## srumecmd

A port of SrumECmd: the System Resource Usage Monitor database (`SRUDB.dat`) to CSV, with app run times, network use, and user and Wi-Fi profile names from an
optional SOFTWARE hive. The original needs Windows' `esent.dll`; this reads the database itself with `ese-ez`, in place and without writing.

```
cargo build --release -p srumecmd
srumecmd -f /cases/host1/SRUDB.dat -r /cases/host1/SOFTWARE --csv /tmp/out
srumecmd -d /cases/host1 --csv /tmp/out
```

Transaction logs aren't replayed: a database that wasn't shut down cleanly is read as it is, with a warning. The original only runs on Windows; it was compared there with
this port, with identical CSVs (`docs/plans/srumecmd.md`).
