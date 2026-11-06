#!/usr/bin/env python3
"""Builds Recycle Bin files for tools/parity-rbcmd.sh: valid ones of every kind, edge cases, and damaged copies.

    tools/gen-rbcmd-cases.py <output folder> [seed] [sample folder ...]

Sample folders hold real $I and INFO2 files to damage (upstream's RecycleBin.Test/TestFiles, say). Without a seed only the
fixed cases are written; with one, damaged copies follow, the same for the same seed.
"""
import os
import random
import struct
import sys

TIME = 132223104000000000  # 2020-01-01
MAX_FILETIME = 0x24C85A5ED1C03FFF


def dollar_i1(name, size=1234, time=TIME, name_bytes=520):
    data = name.encode("utf-16-le", "surrogatepass").ljust(520, b"\0")[:520]
    return struct.pack("<qqq", 1, size, time) + data[:name_bytes]


def dollar_i2(name, size=1234, time=TIME, length=None):
    data = (name + "\0").encode("utf-16-le", "surrogatepass")
    return struct.pack("<qqqi", 2, size, time, len(data) // 2 if length is None else length) + data


def record(name, size, index=1, drive=2, time=TIME, file_size=4096, removed=False, unicode_name=None):
    data = bytearray(size)
    ansi = name if isinstance(name, bytes) else name.encode("ascii")
    data[0:len(ansi)] = ansi[:260]
    if removed:
        data[0] = 0
    data[260:280] = struct.pack("<iiqi", index, drive, time, file_size)
    if size >= 800:
        wide = (name.decode("latin-1") if isinstance(name, bytes) else name) if unicode_name is None else unicode_name
        data[280:800] = wide.encode("utf-16-le", "surrogatepass").ljust(520, b"\0")[:520]
    return bytes(data)


def info2(records, size=800, version=None):
    version = (4 if size == 280 else 5) if version is None else version
    return struct.pack("<iiiii", version, 0, 0, size, 0) + b"".join(records)


def write(folder, name, data):
    path = os.path.join(folder, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def fixed(out):
    d = os.path.join(out, "dollar")
    sizes = [0, 1, 1023, 1024, 1025, 1048, 1049, 1536, 1048576, 1073741824, 1099511627776, 1125899906842624, 1152921504606846976,
             2 ** 63 - 1, -1, -1024, -1536, -(2 ** 63) + 1, 999999, 1048524, 1048575, 123456789012]
    for i, size in enumerate(sizes):
        write(d, f"sizes/$IS{i:05}", dollar_i2("C:\\sizes\\file.txt", size=size))
    write(d, "minsize/$IMIN", dollar_i2("C:\\min.txt", size=-(2 ** 63)))
    write(d, "v1/$IA.txt", dollar_i1("C:\\Users\\me\\a.txt"))
    write(d, "v1/$IB", dollar_i1("C:\\" + "x" * 300))
    write(d, "v1/$ITRUNC", dollar_i1("C:\\short.txt", name_bytes=41))
    write(d, "v1/$IHEADER", dollar_i1("", name_bytes=0))
    write(d, "v2/$IA.txt", dollar_i2("C:\\Users\\me\\a.txt"))
    for name, value in [("comma", "C:\\a,b.txt"), ("quote", 'C:\\a"b.txt'), ("space", " C:\\a.txt "), ("nl", "C:\\a\r\nb.txt"), ("tab", "C:\\a\tb.txt"),
                        ("accent", "C:\\Users\\José\\ñandú 日本語 😀.txt"), ("lone", "C:\\bad\ud800x.txt"), ("empty", ""), ("embedded", "C:\\a\0b.txt"),
                        ("braces", "C:\\{Message}\\{0}.txt")]:
        write(d, f"names/$I{name}", dollar_i2(value))
    for name, value in [("neg", -1), ("min", -(2 ** 31)), ("max", 2 ** 31 - 1), ("big", 500), ("zero", 0), ("one", 1)]:
        write(d, f"lengths/$I{name}", dollar_i2("C:\\file.txt", length=value))
    write(d, "lengths/$Iodd", dollar_i2("C:\\file.txt") + b"\x41")
    write(d, "lengths/$Inolen", struct.pack("<qqq", 2, 1, TIME) + b"\1\0")
    for name, value in [("zero", 0), ("one", 1), ("neg", -1), ("min", -(2 ** 63)), ("max", 2 ** 63 - 1), ("top", MAX_FILETIME), ("over", MAX_FILETIME + 1)]:
        write(d, f"times/$I{name}", dollar_i2("C:\\t.txt", time=value))
        write(d, f"times/$Iv1{name}", dollar_i1("C:\\t.txt", time=value))
    for size in [0, 1, 3, 4, 7, 8, 23]:
        write(d, f"short/$I{size}", struct.pack("<qqq", 1, 2, TIME)[:size])
        write(d, f"short/$Iv2{size}", struct.pack("<qqq", 2, 2, TIME)[:size])
    write(d, "unknown/$Izero", bytes(32))
    write(d, "unknown/$Iff", b"\xff" * 32)
    write(d, "unknown/$I3", struct.pack("<qqq", 3, 2, TIME))
    write(d, "unknown/$Ihigh", struct.pack("<q", 0x100000001) + bytes(24))
    write(d, "unknown/$Ihigh4", struct.pack("<q", 0x100000004) + bytes(24))
    write(d, "unknown/not-picked-up.txt", b"not a recycle bin file")
    write(d, "unknown/$i-lower", dollar_i2("C:\\lower.txt"))
    write(d, "unknown/info2", info2([record("C:\\lower.txt", 800)]))
    write(d, "unknown/INFO2.bak", info2([record("C:\\bak.txt", 800)]))
    write(d, "unknown/$R123", b"content")

    # deleted folders, whose files come from the $R folder next to the $I file
    tree = os.path.join(d, "tree")
    write(tree, "$IDIR1", dollar_i2("C:\\Users\\me\\folder"))
    for name, size in [("a.txt", 10), ("b.bin", 2000), ("sub/c.txt", 3), ("sub/deep/d.txt", 0), ("other/e.txt", 7)]:
        write(tree, "$RDIR1/" + name, bytes(size))
    os.makedirs(os.path.join(tree, "$RDIR1", "empty"), exist_ok=True)
    write(tree, "$IDIR2.zip", dollar_i1("C:\\temp\\pack.zip"))
    write(tree, "$RDIR2.zip/in.txt", bytes(5))
    write(tree, "$IFILE", dollar_i2("C:\\temp\\file.txt"))
    write(tree, "$RFILE", bytes(9))
    write(tree, "$INODIR", dollar_i2("C:\\temp\\gone"))

    i = os.path.join(out, "info")
    many = [record(f"C:\\RECYCLER\\f{n}.txt", 800, index=n, drive=n % 26) for n in range(5)]
    many[2] = record("C:\\RECYCLER\\gone.txt", 800, index=2, removed=True)
    write(i, "unicode/INFO2", info2(many))
    write(i, "ansi/INFO2", info2([record("C:\\WINDOWS\\a.txt", 280), record("C:\\WINDOWS\\b.txt", 280, removed=True)], 280))
    write(i, "names/INFO2", info2([record(b"C:\\caf\xe9\\high.txt", 280, file_size=-5), record(b"C:\\" + b"y" * 260, 280, file_size=-(2 ** 31))], 280))
    write(i, "wide/INFO2", info2([record("C:\\wide.txt", 800, unicode_name="C:\\Usérs\\日本語.txt"), record("C:\\ansi.txt", 800, unicode_name=""),
                                 record("C:\\gone.txt", 800, unicode_name="C:\\kept 😀.txt", removed=True), record("", 800, unicode_name="")]))
    write(i, "empty/INFO2", info2([]))
    write(i, "sized/INFO2", info2([record("C:\\900a.txt", 900), record("C:\\900b.txt", 900)], 900))
    write(i, "small/INFO2", info2([record("C:\\300.txt", 300)], 300))
    write(i, "versions/a/INFO2", info2([record("C:\\v4.txt", 800)], 800, 4))
    write(i, "versions/b/INFO2", info2([record("C:\\v5.txt", 280)], 280, 5))
    write(i, "trailing/INFO2", info2([record("C:\\t.txt", 800)]) + bytes(799))
    for name, value in [("zero", 0), ("neg", -5), ("over", MAX_FILETIME + 1)]:
        write(i, f"times/{name}/INFO2", info2([record("C:\\t.txt", 800, time=value)]))
    for name, value in [("zero", 0), ("neg", -800), ("low", 279)]:
        data = bytearray(info2([record("C:\\t.txt", 800)]))
        data[12:16] = struct.pack("<i", value)
        write(i, f"badsize/{name}/INFO2", bytes(data))
    for size in [4, 8, 19, 20]:
        write(i, f"short/{size}/INFO2", struct.pack("<iiiii", 5, 0, 0, 800, 0)[:size])
    write(i, "unknown/INFO2", b"\x07" + bytes(40))
    write(i, "zero/INFO2", b"")


def damaged(out, seed, samples):
    rnd = random.Random(seed)
    goods = [dollar_i1("C:\\Users\\test\\file.txt"), dollar_i2("C:\\Users\\test\\file.txt"),
             info2([record("C:\\a.txt", 800), record("C:\\b.txt", 800, removed=True)]), info2([record("C:\\a.txt", 280)], 280)]
    for folder in samples:
        for root, _, names in os.walk(folder):
            for name in sorted(names):
                if name.startswith("$I") or name.startswith("INFO2"):
                    with open(os.path.join(root, name), "rb") as f:
                        goods.append(f.read())
    for n in range(600):
        good = rnd.choice(goods)
        data = bytearray(good[:rnd.randint(0, len(good))] if rnd.random() < 0.5 else good)
        for _ in range(rnd.randint(0, 6)):
            if data:
                # the fields that decide things are at the start
                at = rnd.randrange(min(len(data), 40)) if rnd.random() < 0.7 else rnd.randrange(len(data))
                data[at] = rnd.choice([0, 1, 2, 4, 5, 0x7f, 0x80, 0xff, rnd.randrange(256)])
        name = "INFO2" if n % 2 else f"$I{n:06}"
        write(os.path.join(out, "damaged"), f"{n % 40:02}/{n:04}/{name}", bytes(data))


def main():
    out = sys.argv[1]
    fixed(out)
    if len(sys.argv) > 2:
        damaged(out, int(sys.argv[2]), sys.argv[3:])


main()
