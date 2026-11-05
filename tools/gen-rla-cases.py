#!/usr/bin/env python3
"""Makes the hives and transaction logs tools/parity-rla.sh compares on, and prints its cases.

    tools/gen-rla-cases.py <Registry.Test/Hives> <DFIRArtifactMuseum/Win11/RathbunVM> <work folder> [random cases] > cases

Upstream's samples reach little of the replay (the new format, with both logs), so logs of both formats are also
built here, with valid checksums and hashes so that each check is reached, then with random values in their fields.
"""
import gzip
import os
import random
import shlex
import shutil
import struct
import sys

SEED = 0x82EF4D887A4E55C5
M32 = 0xFFFFFFFF


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def marvin(data):
    p0, p1 = SEED & M32, SEED >> 32

    def block():
        nonlocal p0, p1
        p1 ^= p0
        p0 = (rol(p0, 20) + p1) & M32
        p1 = rol(p1, 9) ^ p0
        p0 = (rol(p0, 27) + p1) & M32
        p1 = rol(p1, 19)

    n = len(data) // 4 * 4
    for i in range(0, n, 4):
        p0 = (p0 + struct.unpack_from("<I", data, i)[0]) & M32
        block()
    rest = data[n:]
    last = {0: 0x80, 1: 0x8000, 2: 0x800000, 3: 0x80000000}[len(rest)] | int.from_bytes(rest, "little")
    p0 = (p0 + last) & M32
    block()
    block()
    return (p1 << 32) | p0


def checksum(b):
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", b, i)[0]
    return {0: 1, M32: M32 - 1}.get(x, x)


def seal(block):
    b = bytearray(block)
    struct.pack_into("<I", b, 508, checksum(b))
    return bytes(b)


def dirty_hive(clean, primary, secondary, good_checksum=True):
    b = bytearray(clean)
    struct.pack_into("<II", b, 4, primary, secondary)
    struct.pack_into("<I", b, 508, checksum(b) if good_checksum else checksum(b) ^ 0x55)
    return bytes(b)


def log_base(clean, sequence, file_type, timestamp=None, bins=None, good_checksum=True):
    b = bytearray(clean[:512])
    struct.pack_into("<II", b, 4, sequence, sequence)
    struct.pack_into("<I", b, 28, file_type)
    if timestamp is not None:
        struct.pack_into("<q", b, 12, timestamp)
    if bins is not None:
        struct.pack_into("<I", b, 40, bins)
    struct.pack_into("<I", b, 508, checksum(b) if good_checksum else checksum(b) ^ 0x55)
    return bytes(b)


def entry(sequence, bins, pages, flags=0, count=None, size=None, good_hashes=True, signature=b"HvLE"):
    """pages: (offset from the first hive bin, bytes)"""
    refs = b"".join(struct.pack("<II", o, len(p)) for o, p in pages)
    body = refs + b"".join(p for _, p in pages)
    total = 40 + len(body)
    total = (total + 511) // 512 * 512
    size = total if size is None else size
    head = signature + struct.pack("<IIIII", size, flags, sequence, bins, len(pages) if count is None else count)
    rest = body.ljust(total - 40, b"\0")
    # the first hash covers everything after the header; the second one the header with the first hash
    hash1 = marvin(rest[: size - 40]) if size >= 40 else 0
    head1 = head + struct.pack("<Q", hash1)
    hash2 = marvin(head1)
    if not good_hashes:
        hash2 ^= 1
    return head1 + struct.pack("<Q", hash2) + rest


def dirt(base, bins, dirty):
    """An old format log: its base block, DIRT and a bitmap of 512 byte pages, then those pages (page number, 512 bytes)"""
    bitmap = bytearray(bins // 4096)
    pages = b""
    for number, page in sorted(dirty):
        bitmap[number // 8] |= 1 << (number % 8)
        pages += page
    head = base + b"DIRT" + bytes(bitmap)
    return head + b"\0" * (-len(head) % 512) + pages


def page(fill, length=4096):
    return bytes([fill]) * length


def main():
    hives, museum, work = sys.argv[1:4]
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 300
    work = os.path.abspath(work)
    shutil.rmtree(work, ignore_errors=True)
    cases = []

    def put(folder, files):
        path = os.path.join(work, folder)
        os.makedirs(path, exist_ok=True)
        for name, data in files.items():
            with open(os.path.join(path, name), "wb") as f:
                f.write(data)
        return path

    def case(*args, out="{out}/o"):
        cases.append(" ".join(shlex.quote(a) for a in args).replace("'{out}", "{out}") + " --out " + out)

    # ---- the samples ----
    samples = sorted(n for n in os.listdir(hives) if not n.upper().endswith((".LOG1", ".LOG2")))
    for name in samples:
        case("-f", os.path.join(hives, name))
        case("-f", os.path.join(hives, name), "--ca", "false")
        case("-f", os.path.join(hives, name), "--nop", "--debug")

    def read_museum(name):
        with gzip.open(os.path.join(museum, name + ".gz")) as f:
            return f.read()

    system, log1, log2 = read_museum("SYSTEM"), read_museum("SYSTEM.LOG1"), read_museum("SYSTEM.LOG2")
    both = put("museum/both", {"SYSTEM": system, "SYSTEM.LOG1": log1, "SYSTEM.LOG2": log2})
    for extra in ([], ["--nop"], ["--nop", "--cn", "false"], ["--ca", "false"], ["--co"], ["--debug"], ["--trace"]):
        case("-f", os.path.join(both, "SYSTEM"), *extra)
    for label, files in {
        "none": {},
        "only1": {"SYSTEM.LOG1": log1},
        "only2": {"SYSTEM.LOG2": log2},
        "swapped": {"SYSTEM.LOG1": log2, "SYSTEM.LOG2": log1},
        "lower": {"system.log1": log1, "system.log2": log2},
        "plainlog": {"SYSTEM.LOG": log2},
        "all3": {"SYSTEM.LOG": log1, "SYSTEM.LOG1": log1, "SYSTEM.LOG2": log2},
        "emptylog": {"SYSTEM.LOG1": b"", "SYSTEM.LOG2": log2},
        "allempty": {"SYSTEM.LOG1": b"", "SYSTEM.LOG2": b""},
        "otherext": {"SYSTEM.LOG3": log1, "SYSTEM.LOG1.bak": log1, "SYSTEM.LOG11": log1},
        "junklog": {"SYSTEM.LOG1": b"junk" * 2000},
        "shortjunk": {"SYSTEM.LOG1": b"junk"},
        "short512": {"SYSTEM.LOG1": log1[:512], "SYSTEM.LOG2": log2[:600]},
        "cut": {"SYSTEM.LOG1": log1[: len(log1) // 2], "SYSTEM.LOG2": log2[: len(log2) // 3 + 7]},
    }.items():
        folder = put("museum/" + label, {"SYSTEM": system, **files})
        case("-f", os.path.join(folder, "SYSTEM"))
        case("-f", os.path.join(folder, "SYSTEM"), "--ca", "false")
    links = put("museum/links", {})
    os.symlink(os.path.join(both, "SYSTEM"), os.path.join(links, "SYSTEM"))
    os.symlink(os.path.join(both, "SYSTEM.LOG1"), os.path.join(links, "SYSTEM.LOG1"))
    os.symlink(os.path.join(both, "SYSTEM.LOG2"), os.path.join(links, "SYSTEM.LOG2"))
    case("-f", os.path.join(links, "SYSTEM"))
    # logs of another hive
    with open(os.path.join(hives, "SAM"), "rb") as f:
        sam = f.read()
    other = put("museum/othertype", {"SAM": dirty_hive(sam, 9, 8), "SAM.LOG1": log1, "SAM.LOG2": log2})
    case("-f", os.path.join(other, "SAM"))

    # ---- files that aren't whole hives ----
    bad = put("bad", {"empty": b"", "three": b"reg", "notahive": b"not a hive at all", "justsig": b"regf", "header100": sam[:100], "header600": seal(sam[:512]) + sam[512:600], "header4095": sam[:4095], "header4096": sam[:4096], "dirty4096": dirty_hive(sam[:4096], 2, 1)})
    put("bad", {"header600.LOG1": log_base(sam, 1, 6) + entry(1, 4096, [(0, page(1))]), "dirty4096.LOG1": log_base(sam, 1, 6) + entry(1, 4096, [(0, sam[4096:8192])])})
    for name in ("empty", "three", "notahive", "justsig", "header100", "header600", "header4095", "header4096", "dirty4096", "missing"):
        case("-f", os.path.join(work, "bad", name))

    # ---- arguments and outputs ----
    afile = put("args", {"afile": b""})
    good = os.path.join(both, "SYSTEM")
    cases.append("")
    cases.append(f"-f {good}")
    cases.append(f"-d {both}")
    cases.append("--out {out}/o")
    cases.append(f"-f {good} --out {afile}/afile")
    cases.append(f"-f {good} --out {afile}/afile/below")
    cases.append(f"-d {work}/nothing --out {{out}}/o")
    cases.append(f"-f {good} --ca maybe --out {{out}}/o")
    cases.append(f"-f {good} -d {both} --out {{out}}/o")
    cases.append(f"-f '' -d {both} --out {{out}}/o")
    cases.append(f"-f {both} --out {{out}}/o")

    # ---- -d on names both builds look for (no links to folders: the Linux build follows them, the Windows one doesn't) ----
    triage = {
        "C/Users/eric/NTUSER.DAT": "NTUSER.DAT",
        "C/Users/bob/ntuser.dat": "NTUSER1.DAT",
        "C/Users/eric/AppData/Local/Microsoft/Windows/UsrClass.dat": "UsrClass 1.dat",
        "C/Windows/ServiceProfiles/LocalService/NTUSER.DAT": "NTUSER slack.DAT",
        "C/Windows/System32/config/SAM": "SAM",
        "C/Windows/System32/config/SECURITY": "SECURITY",
        "C/Windows/System32/config/SOFTWARE": "SOFTWARE",
        "C/Windows/System32/config/DRIVERS": "DRIVERS",
        "D/Windows/System32/config/SAM": "SAM_DUPENAME",
        "x/sam": "SAM_RootValue",
    }
    root = os.path.join(work, "triage")
    for target, source in triage.items():
        os.makedirs(os.path.dirname(os.path.join(root, target)), exist_ok=True)
        shutil.copy(os.path.join(hives, source), os.path.join(root, target))
    config = os.path.join(root, "C/Windows/System32/config")
    for name, data in (("SYSTEM", system), ("SYSTEM.LOG1", log1), ("SYSTEM.LOG2", log2), ("readme.txt", b"regf text"), ("DEFAULT", b"#!/bin/sh\necho a script named default\n"), ("COMPONENTS", b"reg")):
        with open(os.path.join(config, name), "wb") as f:
            f.write(data)
    os.symlink(os.path.join(config, "SAM"), os.path.join(root, "SAM"))
    for extra in ([], ["--nop"], ["--nop", "--cn", "false"], ["--ca", "false"], ["--nop", "--ca", "false"], ["--debug"]):
        case("-d", root, *extra)
    locked = os.path.join(root, "x", "locked")
    os.makedirs(locked)
    os.chmod(locked, 0)
    unreadable = put("unreadable", {"SAM": sam})
    os.chmod(os.path.join(unreadable, "SAM"), 0)
    case("-f", os.path.join(unreadable, "SAM"))
    case("-d", unreadable)

    # ---- built logs ----
    n = 100
    size = struct.unpack_from("<I", sam, 40)[0]
    first = sam[4096:8192]
    changed = bytearray(first)
    changed[100:110] = b"CHANGEDBIN"
    changed = bytes(changed)

    def base(seq=n, file_type=6, **kw):
        return log_base(sam, seq, file_type, **kw)

    good_entry = entry(n, size, [(0, changed)])
    built = {
        "one": (dirty_hive(sam, n + 1, n), {"LOG1": base() + good_entry}),
        "one_in_log2": (dirty_hive(sam, n + 1, n), {"LOG2": base() + good_entry}),
        "one_in_log": (dirty_hive(sam, n + 1, n), {"LOG": base() + good_entry}),
        "two": (dirty_hive(sam, n + 2, n), {"LOG1": base() + good_entry, "LOG2": base(n + 1) + entry(n + 1, size, [(4096, changed)])}),
        "two_reversed": (dirty_hive(sam, n + 2, n), {"LOG2": base() + good_entry, "LOG1": base(n + 1) + entry(n + 1, size, [(4096, changed)])}),
        "two_gap": (dirty_hive(sam, n + 2, n), {"LOG1": base() + good_entry, "LOG2": base(n + 5) + entry(n + 5, size, [(4096, changed)])}),
        "two_same": (dirty_hive(sam, n + 2, n), {"LOG1": base() + good_entry, "LOG2": base() + good_entry}),
        "older": (dirty_hive(sam, n + 1, n), {"LOG1": base(n - 5) + entry(n - 5, size, [(0, changed)])}),
        "older_and_good": (dirty_hive(sam, n + 1, n), {"LOG1": base(n - 5) + entry(n - 5, size, [(0, changed)]), "LOG2": base() + good_entry}),
        "several": (dirty_hive(sam, n + 3, n), {"LOG1": base() + good_entry + entry(n + 1, size, [(4096, changed)]) + entry(n + 2, size, [(8192, changed), (0, first)], flags=1)}),
        "wrong_sequence": (dirty_hive(sam, n + 3, n), {"LOG1": base() + good_entry + entry(n + 7, size, [(4096, changed)])}),
        "bad_hash": (dirty_hive(sam, n + 3, n), {"LOG1": base() + good_entry + entry(n + 1, size, [(4096, changed)], good_hashes=False)}),
        "first_bad_hash": (dirty_hive(sam, n + 3, n), {"LOG1": base() + entry(n, size, [(0, changed)], good_hashes=False)}),
        "no_entries": (dirty_hive(sam, n + 1, n), {"LOG1": base() + b"\0" * 1024}),
        "bad_size": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, size, [(0, changed)], size=700)}),
        "huge_size": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, size, [(0, changed)], size=512 * 1000000)}),
        "bad_count": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, size, [(0, changed)], count=0)}),
        "big_count": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, size, [(0, changed)], count=100000)}),
        "bad_bins": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, 4097, [(0, changed)])}),
        "grows": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, size + 8192 * 4, [(size + 8192, changed)])}),
        "shrinks": (dirty_hive(sam, n + 1, n), {"LOG1": base() + entry(n, 4096, [(0, changed)])}),
        "bad_log_base": (dirty_hive(sam, n + 1, n), {"LOG1": base(good_checksum=False) + good_entry}),
        "dirty_log_base": (dirty_hive(sam, n + 1, n), {"LOG1": seal(struct.pack("<4sII", b"regf", n, n + 1) + base()[12:]) + good_entry}),
        "bad_hive_checksum": (dirty_hive(sam, n + 1, n, False), {"LOG1": base() + good_entry}),
        "bad_checksum_only": (dirty_hive(sam, n, n, False), {"LOG1": base() + good_entry}),
        "bad_checksum_no_logs": (dirty_hive(sam, n, n, False), {}),
        "clean_with_logs": (dirty_hive(sam, n, n), {"LOG1": base() + good_entry}),
        "old": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1), size, [(0, changed[:512]), (9, changed[512:1024])])}),
        "old_type2": (dirty_hive(sam, n + 1, n), {"LOG": dirt(base(n, 2), size, [(0, changed[:512])])}),
        "old_two_new_first": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1, timestamp=2**62), size, [(0, changed[:512])]), "LOG2": dirt(base(n, 1), size, [(1, changed[:512])])}),
        "old_two_new_second": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1), size, [(0, changed[:512])]), "LOG2": dirt(base(n, 1, timestamp=2**62), size, [(1, changed[:512])])}),
        "old_older": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1, timestamp=1), size, [(0, changed[:512])])}),
        "old_no_pages": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1), size, []) + b"\0" * 512}),
        "old_cut": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1), size, [(0, changed[:512]), (9, changed[:512])])[:-512]}),
        "old_grows": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1, bins=size + 8192), size + 8192, [(size // 512 + 3, changed[:512])])}),
        "old_no_dirt": (dirty_hive(sam, n + 1, n), {"LOG1": base(n, 1) + b"NOPE" + b"\0" * 2000}),
        "old_and_new": (dirty_hive(sam, n + 1, n), {"LOG1": dirt(base(n, 1), size, [(0, changed[:512])]), "LOG2": base() + good_entry}),
        "old_bad_hive_checksum": (dirty_hive(sam, n + 1, n, False), {"LOG1": dirt(base(n, 1), size, [(0, changed[:512])])}),
        "unknown_type": (dirty_hive(sam, n + 1, n), {"LOG1": base(n, 3) + good_entry}),
    }
    for label, (hive, logs) in built.items():
        folder = put("built/" + label, {"SAM": hive, **{"SAM." + ext: data for ext, data in logs.items()}})
        case("-f", os.path.join(folder, "SAM"))

    # ---- random values in those logs, then random bytes ----
    rng = random.Random(54756)
    interesting = [0, 1, 2, 511, 512, 513, 4095, 4096, 4097, 8192, size, size - 4096, size + 4096, 0x7FFFFFFF, 0x80000000, M32, n - 1, n, n + 1, n + 2]
    templates = [(label, v) for label, v in built.items() if v[1]]
    for i in range(count):
        label, (hive, logs) = rng.choice(templates)
        hive = bytearray(hive)
        logs = {ext: bytearray(data) for ext, data in logs.items()}
        kind = i % 4
        for _ in range(rng.randint(1, 4)):
            ext = rng.choice(list(logs))
            data = logs[ext]
            if kind == 0:  # a field of the log's base block, with its checksum right
                offset = rng.choice([4, 8, 12, 16, 28, 40, 144])
                struct.pack_into("<I", data, offset, rng.choice(interesting))
                struct.pack_into("<I", data, 508, checksum(data))
            elif kind == 1 and len(data) >= 552 and data[512:516] == b"HvLE":  # a field of the first entry, with its hashes right
                offset = rng.choice([516, 520, 524, 528, 532, 552, 556])
                struct.pack_into("<I", data, offset, rng.choice(interesting))
                entry_size = struct.unpack_from("<I", data, 516)[0]
                if 40 <= entry_size and 512 + entry_size <= len(data):
                    struct.pack_into("<Q", data, 536, marvin(bytes(data[552:512 + entry_size])))
                struct.pack_into("<Q", data, 544, marvin(bytes(data[512:544])))
            elif kind == 2:  # any bytes of a log, or its end
                if rng.random() < 0.3:
                    del data[rng.randrange(len(data)) :]
                else:
                    for _ in range(rng.randint(1, 20)):
                        data[rng.randrange(len(data))] = rng.randrange(256)
            else:  # the hive's base block
                offset = rng.choice([4, 8, 28, 36, 40, 144])
                struct.pack_into("<I", hive, offset, rng.choice(interesting))
                if rng.random() < 0.8:
                    struct.pack_into("<I", hive, 508, checksum(hive))
        folder = put(f"random/{i}", {"SAM": bytes(hive), **{"SAM." + ext: bytes(data) for ext, data in logs.items()}})
        case("-f", os.path.join(folder, "SAM"))

    print("\n".join(c for c in cases))


main()
