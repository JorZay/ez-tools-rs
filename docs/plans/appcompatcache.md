# AppCompatCacheParser port

`crates/appcompatcache-ez` (library, no printing or exits) and `crates/appcompatcacheparser` (CLI), from AppCompatCacheParser 2026.10.1.
Upstream commit in `docs/upstream.md`.

## What it reads

The AppCompatCache (ShimCache) value in each `ControlSet00x\Control\Session Manager` of a SYSTEM hive, through `registry-ez`,
with the transaction logs of a dirty hive replayed:

| Format | Signature | Entries |
|---|---|---|
| Windows XP | `0xDEADBEEF` | 96 slots, in LRU array order |
| Windows 2003, Vista, 2008 | `0xBADC0FFE` | fixed size table, 32 or 64 bit |
| Windows 7, 2008 R2 | `0xBADC0FEE` | fixed size table, 32 or 64 bit |
| Windows 8.0, 8.1 | `00ts`, `10ts` | one after the other, from each one's size |
| Windows 10, 11 | header size, then `10ts` | one after the other; executed is data tag 0x100 |

Entries in the slack of the value's cell are recovered for Windows 8 to 11, when they aren't still in the cache. Options:
`-f`, `--csv`, `--csvf`, `-c`, `-t`, `--dt`, `--nl`, `--debug`, `--trace`, `--co`.

## Parity

`tools/parity-appcompatcache.sh` against AppCompatCacheParser built with .NET 10 (CSV files byte for byte, console and exit
code; the console log too where the run has `--co`). 276 runs, 0 differences, 66,851 CSV rows:

- Upstream's 8 raw values (XP, 2008, 7 x86 and x64, 8.0, 8.1, 10, 10 Creators), each inside a minimal SYSTEM hive made for the
  test, as the program only takes hives: default names, `-c`, `-t`, `--dt`, `--debug`, and the wrong architecture in the hive.
- Several control sets (duplicates), a control set without the value or that isn't there, no `Select` key, values that aren't
  caches, entries in the slack of each format with signatures, and 5 truncations and 14 random damages of each value.
- The real hives: upstream's dirty Windows 11 SYSTEM with its logs (and without them, and with `--nl`), and the Registry
  repository's SYSTEM with its logs and SAM.
- That Windows 11 hive with bytes flipped (25) and truncated (5), and arguments and outputs that can't be used.

`crates/appcompatcache-ez/tests/upstream.rs` has upstream's sample and hive checks, and the core of its format checks
(the samples need `ACC_TEST_FILES`, upstream's `AppCompatCacheParserTest/TestFiles`).

## Differences from the original

- Banner and help are this port's. .NET stack traces after errors aren't printed.
- `--trace` doesn't print the original's `Dumping cache details` line, a dump of its objects, on each cache.
- The live Registry isn't available, as in the original on anything but Windows, so `-f` is needed.
- A hive in use can't be read raw (Windows only).
