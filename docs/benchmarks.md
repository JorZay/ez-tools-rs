# Speed and memory against the originals

Measured 2026-11-04 on a 16-thread Linux machine with 30 GB of RAM: the Rust release builds against the originals at the
commits in `docs/upstream.md`, on .NET 9.0 and .NET 10.0. Median of 3 rounds, files already in the page cache, output to
tmpfs, console to /dev/null. Wall time and peak RSS from `/usr/bin/time`.

| Workload | .NET 9 | .NET 10 | Rust | Rust is faster by | .NET 9 RSS | .NET 10 RSS | Rust RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| PECmd, 1 file, console | 0.20 s | 0.16 s | < 0.01 s | at least 16x | 69 MB | 68 MB | 3 MB |
| PECmd, 10,800 files, CSV | 6.01 s | 6.09 s | 1.41 s | 4.3x | 2,330 MB | 2,334 MB | 992 MB |
| PECmd, 10,800 files, CSV + JSON | 7.07 s | 7.10 s | 1.78 s | 4.0x | 2,481 MB | 2,503 MB | 1,078 MB |
| MFTECmd, $MFT 1.6 GB, CSV | 16.81 s | 15.90 s | 1.61 s | 9.9x to 10.4x | 3,599 MB | 3,709 MB | 2,107 MB |
| MFTECmd, $LogFile 64 MB + $MFT, CSV | 19.96 s | 18.62 s | 4.86 s | 3.8x to 4.1x | 4,076 MB | 3,920 MB | 3,230 MB |
| MFTECmd, $SDS 12 MB, CSV | 0.34 s | 0.29 s | 0.03 s | about 10x | 98 MB | 99 MB | 24 MB |
| RECmd, SOFTWARE, DFIRBatch CSV | 1.92 s | 1.91 s | 1.09 s | 1.8x | 455 MB | 493 MB | 278 MB |
| RECmd, SOFTWARE, data search | 2.03 s | 2.10 s | 0.68 s | 3.0x | 425 MB | 463 MB | 295 MB |
| RECmd, 28 hives, DFIRBatch CSV | 3.00 s | 3.08 s | 2.51 s | 1.2x | 458 MB | 475 MB | 281 MB |
| EvtxECmd, 168 logs 2.4 GB, CSV | 76.00 s | 77.07 s | 11.72 s | 6.5x | 264 MB | 261 MB | 377 MB |
| EvtxECmd, the same sorted by time (port only) | | | 18.51 s | | | | 728 MB |

Reading these:

- Rust's RSS for $MFT includes the memory-mapped input file, so it isn't all allocated memory.
- EvtxECmd is the one case where the port uses more memory than the original. Its row uses `--unsorted --keep-identical`,
  the mode that matches the original's output.
- The small-input rows mostly measure .NET's startup (about 0.15 s).
- PECmd's sample corpus is 54 small files copied 200 times; its memory is mostly the parsed files, kept until the export,
  as the original does.
- RECmd ran without plugins on both sides (measured before any were ported), so a real run with plugins will differ.
- One sample set per tool and one machine: these show the size of the differences, not exact figures for other data.
