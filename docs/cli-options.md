# Command line options shared by the ports

How `--dt` and the command line itself behave in all the ports, compared with the originals by `tools/parity-options.py`.

## `--dt`

`Timestamp::format` in `ez-common` is .NET's `DateTimeOffset.ToString(format)` at offset 0 in en-US, as every original uses it:

- A custom format. `%x` is `x` alone, whatever follows it, and `g` is `AD`.
- A standard format of one letter, or an empty format: `G` is `1/2/2020 3:04:05 PM`, `D` is `Thursday, January 2, 2020`. ICU puts U+202F, not a space, before
  AM and PM in these, and only in these.
- `U` is an error, as for any `DateTimeOffset`, and so are other letters alone, more than seven `f` or `F`, an unmatched quote, and a `%` or `\` with
  nothing after it. `Timestamp::check_format` says so. The original fails while it writes, and what that leaves differs per tool:

| Tool | Files left | Exit code |
|---|---|---|
| RBCmd | CSV with only its header | 0 |
| AmcacheParser | Header of the first file, no later files | 0 |
| AppCompatCacheParser | CSV with only its header | 0 |
| EvtxECmd | CSV with only its header | 0 |
| PECmd | CSV, time line, JSON and XHTML `index.xhtml` empty | 1 |
| JLECmd | CSV and `index.xhtml` empty; JSON complete, as it comes first | 1 |
| LECmd | CSV with only its header, JSON empty, no XML, `<document />` in XHTML | 1 |
| RECmd | Batch CSV empty; plugin files complete, as they use no `--dt` | 1 |
| MFTECmd `$MFT` | CSV with only its header | 1 |
| MFTECmd `$J`, `$LogFile` | Header, whole rows, and the first row with a date cut before that date | 1 |
| SrumECmd | Each CSV: header, whole rows, and the first row with a date cut before that date | 1 |

The ports leave the same files. The original also loses every console and log line with a date, as Serilog swallows the error; the ports keep those lines.

## The command line

`ez_common::cli::parse_args` is what all the tools use, for the rules of the originals' parser:

- An option with a value can be given once: `-f a -f b` is refused.
- A flag can be repeated (`-q -q`), and takes `true` or `false` in any case (`--co False`), but only one value: `--co false --co false` is refused.
- Bad arguments exit with 1.

Messages are this port's. Options can be given as `--dt=x` and `--dt:x`, as in the originals.

## Compared

`tools/parity-options.py`, on one small real sample of each kind: 37 `--dt` values through every way a tool writes a date, and each option of each original (from
its `--help`) repeated and with values: 1,501 pairs of runs, comparing exit codes and output files, and the console for valid formats. 1,480 are identical.

The other 21 are known:

- `mftecmd --vss` (3): the Linux original stops with `COM is not supported`; the port ignores it and goes on.
- `evtxecmd` (18): the port's command line is its own by design. It takes several `-f` and `-d`, and has no `--met`, `--vss`, `--dedupe` or `--co`.

SrumECmd's original only runs on Windows: its 64 cases (the same 37 `--dt` values and each option repeated, on the SRUM database of a
Windows 11 25H2 machine) were compared with the original run there. 57 are identical. The other 7 are the standard formats with AM or PM
(`G`, `g`, `f`, `F`, `t`, `T` and empty): .NET on Windows takes its culture data from Windows and writes a space before AM and PM, where ICU, and
so the Linux originals and the ports, write U+202F.

Not compared, for lack of a sample: `$I30` and `$SDS` with MFTECmd (`$SDS` has no dates; `$I30` follows the same code as `$J`). Not compared with a bad `--dt`:
EvtxECmd's JSON, and files with rows that have no date before the first that has one (the ports keep such whole rows, by reading how `$LogFile` fails). The
comparison used one sample of each kind, not whole extractions.
