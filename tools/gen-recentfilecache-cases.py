#!/usr/bin/env python3
"""Builds RecentFileCache.bcf files for tools/parity-recentfilecache.sh: valid ones, edge cases, and damaged copies.

    tools/gen-recentfilecache-cases.py <output folder> [seed] [sample ...]

Samples are real RecentFileCache.bcf files (upstream's RecentFileCache.Test/Files, say): each is also cut at every length
and, with a seed, damaged at random, the same for the same seed.
"""
import os
import random
import struct
import sys
import zlib

SIGNATURE = 0xFFEEFFFE


def crc(data):
    """CRC-32 of the file without the 4 bytes at 0x10"""
    return zlib.crc32(data[:0x10] + data[0x14:]) & 0xFFFFFFFF


def entry(name, length=None, terminator=0):
    data = name if isinstance(name, bytes) else name.encode("utf-16-le", "surrogatepass")
    return struct.pack("<i", len(data) // 2 if length is None else length) + data + struct.pack("<H", terminator)


def build(entries, checksum=None):
    data = bytearray(struct.pack("<IIIII", SIGNATURE, 0x2211, 3, 1, 0) + b"".join(entries))
    data[0x10:0x14] = struct.pack("<I", crc(bytes(data)) if checksum is None else checksum)
    return bytes(data)


NAMES = [
    "c:\\windows\\system32\\werfault.exe",
    "c:\\program files\\a,b\\comma.exe",
    'c:\\quote"d\\x.exe',
    "c:\\new\nline.exe",
    "c:\\carriage\rreturn.exe",
    " leading space.exe",
    "trailing space.exe ",
    "c:\\tab\there.exe",
    "c:\\{braces}\\[brackets].exe",
    "c:\\caf\u00e9\\\u4e2d\u6587.exe",
    "c:\\emoji\U0001F600.exe",
    "c:\\ctrl\x01\x1f\x7f.exe",
    "c:\\slash/and\\back\\\\.exe",
    "\u2028\u2029\u00a0\ufeff",
    "",
]


def cases():
    yield "header-only.bcf", build([])
    yield "one.bcf", build([entry("c:\\windows\\psexesvc.exe")])
    yield "names.bcf", build([entry(n) for n in NAMES])
    yield "empty-name.bcf", build([entry(""), entry("b.exe")])
    yield "only-empty-name.bcf", build([entry("")])
    yield "many.bcf", build([entry(f"c:\\windows\\file{i}.exe") for i in range(3000)])
    yield "long-name.bcf", build([entry("c:\\" + "x" * 40000 + ".exe")])
    yield "lone-surrogates.bcf", build([entry(b"a\x00\x00\xd8b\x00"), entry(b"\x00\xdc"), entry(b"\x3d\xd8\x00\xde"), entry(b"\x00\xdc\x3d\xd8")])
    yield "bad-crc.bcf", build([entry("a.exe")], 0x12345678)
    yield "zero-crc.bcf", build([entry("a.exe")], 0)
    for length in (-1, -2147483648, 2147483647, 1000, 6, 1073741824):
        yield f"bad-length-{length}.bcf", build([entry("good.exe"), entry("bad.exe", length), entry("never.exe")])
    good = build([entry("good.exe"), entry("cut.exe")])
    yield "cut-terminator.bcf", good[:-2]
    yield "cut-half-terminator.bcf", good[:-1]
    yield "cut-odd.bcf", good[:-3]
    yield "non-nul-terminator.bcf", build([entry("odd.exe", terminator=0x4141), entry("next.exe")])
    yield "non-nul-last.bcf", build([entry("odd.exe", terminator=0x0001)])
    for extra in (1, 2, 3):
        yield f"trailing-{extra}.bcf", build([entry("a.exe"), b"\x00" * extra])
    yield "trailing-ff.bcf", build([entry("a.exe"), b"\xff\xff\xff"])
    yield "empty.bcf", b""
    yield "one-byte.bcf", b"\xfe"
    yield "19-bytes.bcf", build([])[:19]
    yield "bad-signature.bcf", b"\x4c\x00\x00\x00" + build([entry("a.exe")])[4:]
    yield "zero-signature.bcf", bytes(40)
    yield "wrong-unknowns.bcf", build([entry("a.exe")])[:4] + b"\xff" * 12 + build([entry("a.exe")])[16:]
    # several problems at once
    yield "many-problems.bcf", build([entry("odd.exe", terminator=0x4141), entry("x", 5000)], 1)
    # file names that matter for the JSON's name
    yield "name with spaces, commas.bcf", build([entry("a.exe")])
    yield "noext", build([entry("a.exe")])


def main():
    out = sys.argv[1]
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None
    samples = sys.argv[3:]
    os.makedirs(out, exist_ok=True)

    def write(name, data):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)

    for name, data in cases():
        write(name, data)
    for sample in samples:
        data = open(sample, "rb").read()
        stem = os.path.basename(sample).replace(" ", "_")
        for size in range(0, len(data)):
            write(f"cut-{stem}-{size}.bcf", data[:size])
        if seed is not None:
            rng = random.Random(f"{seed}-{stem}")
            for i in range(200):
                d = bytearray(data[: rng.randint(20, len(data))])
                for _ in range(rng.randint(1, 8)):
                    at = rng.randrange(0x14, max(0x15, len(d)))
                    if at < len(d):
                        d[at] = rng.randrange(256)
                if rng.random() < 0.5:
                    d[0x10:0x14] = struct.pack("<I", crc(bytes(d)))
                write(f"damaged-{stem}-{i}.bcf", bytes(d))


if __name__ == "__main__":
    main()
