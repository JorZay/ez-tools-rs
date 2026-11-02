# evtxecmd-rs

A Rust port of Eric Zimmerman's [EvtxECmd](https://github.com/EricZimmerman/evtx): Windows event logs (EVTX) from
forensic extractions into one CSV or JSON timeline, with EvtxECmd's columns, value formats and maps, and no .NET.

It adds what working on many extractions at once needs: any number of files and folders, one timeline sorted by
time, and `--merge`, which collapses copies of the same log (an old and a new `Security.evtx`) into one row per event.

## Layout

| Path | What |
|---|---|
| `crates/evtx-ez` | The library: parsing, maps, the timeline (sorting, merging), CSV/JSON writers. No printing, no exits: it can go into another program. |
| `crates/evtxecmd` | The command line tool, a thin client of the library. |
| `maps/` | EvtxECmd's maps (from its repository, MIT), built into the binary. |
| `tests/fixtures/rust-evtx` | Sample logs from [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (MIT/Apache-2.0). |
| `tools/parity.sh` | Compares this tool's output with the original EvtxECmd's on a folder of logs. |

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

Sorting uses `--mem` MB (default 1024) of rows; past that, sorted runs go to compressed temporary files (in `--temp`
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
