#!/usr/bin/env python3
"""Makes jump lists for tools/parity-jlecmd.sh: the upstream samples and real files don't reach every shell item or error path.

    tools/gen-jlecmd-cases.py <file of "name<TAB>base64 shell item" lines> <output folder> [count] [seed]

Writes automatic destinations files (a compound file with a DestList and LNK streams, in the mini stream or in sectors), custom
destinations files, and a randomly damaged copy of some of each. Nothing here comes from real cases.
"""
import base64, random, struct, sys, uuid, os

items = []
for line in open(sys.argv[1], errors='replace'):
    parts = line.rstrip('\n').split('\t')
    if len(parts) >= 2 and not line.startswith('#'):
        try:
            raw = base64.b64decode(parts[1])
        except Exception:
            continue
        if 3 <= len(raw) < 0x8000:
            items.append(raw)
out = sys.argv[2]
count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
R = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
os.makedirs(out, exist_ok=True)
CLSID = uuid.UUID('00021401-0000-0000-c000-000000000046').bytes_le


def u16s(text):
    return struct.pack('<H', len(text)) + text.encode('utf-16le')


def tracker():
    droid = uuid.UUID(int=R.getrandbits(128)).bytes_le
    if R.random() < .7:
        droid = droid[:7] + bytes([0x10 | (droid[7] & 15)]) + droid[8:]
    body = struct.pack('<IIII', 0x60, 0xa0000003, 0x58, 0) + b'host'.ljust(16, b'\0') + uuid.uuid4().bytes_le + droid + uuid.uuid4().bytes_le + droid
    return body


def console():
    body = bytearray(0xcc)
    struct.pack_into('<II', body, 0, 0xcc, 0xa0000002)
    for at in range(8, 0xcc, 4):
        struct.pack_into('<I', body, at, R.choice([0, 1, 7, 0x20, 400, 700, 0x00190050]))
    body[44:60] = 'Consolas'.encode('utf-16le').ljust(16, b'\0')
    return bytes(body)


def text_block(signature):
    body = bytearray(0x314)
    struct.pack_into('<II', body, 0, 0x314, signature)
    body[8:12] = b'%a%\0'
    body[268:276] = '%b%'.encode('utf-16le') + b'\0\0'
    return bytes(body)


def lnk():
    flags = 0x80 | 0x1
    ids = b''.join(struct.pack('<H', 0) * 0 + item for item in R.sample(items, R.randint(1, 3)))
    # items carry their own size
    id_list = ids + b'\0\0'
    body = b''
    if R.random() < .4:
        flags |= 0x2
        volume = struct.pack('<IIII', 0x18, R.choice([2, 3, 4, 5, 3, 3, 99]), R.getrandbits(32), 0x10) + b'LABEL\0\0\0'
        local = b'C:\\x\\y.txt\0'
        common = b'\0'
        size = 0x1c + len(volume) + len(local) + len(common)
        body += struct.pack('<IIIIIII', size, 0x1c, 1, 0x1c, 0x1c + len(volume), 0, 0x1c + len(volume) + len(local)) + volume + local + common
    elif R.random() < .3:
        flags |= 0x2
        share = struct.pack('<IIIII', 0x14 + 8 + 3, R.choice([1, 2, 3]), 0x14, 0x14 + 8, 0x20000) + b'\\\\s\\sh\0\0' + b'Z:\0'
        common = b'a.txt\0'
        size = 0x1c + len(share) + len(common)
        body += struct.pack('<IIIIIII', size, 0x1c, 2, 0, 0, 0x1c, 0x1c + len(share)) + share + common
    for flag, text in [(0x4, 'A name'), (0x8, '..\\rel'), (0x10, 'C:\\work'), (0x20, '/c calc "x"'), (0x40, 'icon.ico')]:
        if R.random() < .3:
            flags |= flag
            body += u16s(text)
    if R.random() < .1:
        body += u16s('')
    extra = b''
    if R.random() < .5:
        extra += tracker()
    if R.random() < .03:
        extra += tracker()
    if R.random() < .1:
        extra += console()
    if R.random() < .1:
        extra += text_block(R.choice([0xa0000001, 0xa0000007, 0xa0000006]))
    if R.random() < .1:
        extra += struct.pack('<IIII', 0x10, 0xa0000005, 0x24, 0x10)
    if R.random() < .1:
        extra += struct.pack('<II', 0x1c, 0xa000000b) + uuid.UUID('fdd39ad0-238f-46af-adb4-6c85480369c7').bytes_le + struct.pack('<I', 0)
    if R.random() < .1:
        extra += struct.pack('<IIIxxxx', 0x10, 0xa0000004, 0x4e4)
    if R.random() < .05:
        extra += struct.pack('<II', 12, 0xa00000ff) + b'\0\0\0\0'
    header = struct.pack('<I', 0x4c) + CLSID + struct.pack('<II', flags, R.choice([0x20, 0x10, 0x80])) + struct.pack('<qqq', *[R.choice([0, 130000000000000000, 131000000000000000, -1]) for _ in range(3)]) \
        + struct.pack('<IiI', R.getrandbits(16), 0, R.choice([1, 3, 7, 1, 1, 42])) + bytes([R.choice([0, 0x41]), R.choice([0, 2])]) + bytes(10)
    trailer = struct.pack('<I', 0) if R.random() < .95 else b''
    return header + struct.pack('<H', len(id_list)) + id_list + body + extra + trailer


def custom():
    categories = R.randint(1, 3)
    data = struct.pack('<III', 2, categories, 0)
    for c in range(categories):
        kind = R.choice([0, 0, 1, 2])
        data += struct.pack('<I', kind)
        n = R.randint(0, 4)
        if kind == 0:
            data += u16s(R.choice(['Tasks', 'Recent', 'Déjà vu', ''])) + struct.pack('<I', n)
        elif kind == 1:
            data += struct.pack('<I', R.choice([1, 2]))
        else:
            data += struct.pack('<I', n)
        for _ in range(n):
            data += CLSID + lnk()
        data += b'\xab\xfb\xbf\xba'
    return data


def sps():
    value = struct.pack('<IIB', 8 + 1 + 4 + 8, 5, 0) + struct.pack('<HH', 0x13, 0) + struct.pack('<I', 7)
    return struct.pack('<I', 28 + len(value) + 4) + b'1SPS' + uuid.uuid4().bytes_le + value + struct.pack('<I', 0)


def dest_list(version, numbers):
    entries = b''
    for number in numbers:
        droid = uuid.uuid4().bytes_le
        if R.random() < .7:
            droid = droid[:7] + bytes([0x10 | (droid[7] & 15)]) + droid[8:]
        elif R.random() < .3:
            droid = bytes(16)
        path = R.choice(['C:\\Users\\x\\a.txt', 'knownfolder:{fdd39ad0-238f-46af-adb4-6c85480369c7}', '::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\x', 'Déjà\\日本語', '', 'knownfolder:{00000000-0000-0000-0000-000000000000}'])
        host = R.choice([b'host'.ljust(16, b'\0'), 'pc'.encode('utf-16le').ljust(16, b'\0'), b'caf\xe9'.ljust(16, b'\0')])
        e = struct.pack('<q', R.getrandbits(62)) + uuid.uuid4().bytes_le + droid + uuid.uuid4().bytes_le + droid + host + struct.pack('<iif', number, 0, 1.5) \
            + struct.pack('<q', R.choice([131000000000000000, 0, -1, 130000000000000000])) + struct.pack('<i', R.choice([-1, -1, 0, 3]))
        if version > 1:
            e += struct.pack('<iiii', 0, R.randint(0, 2000), 0, 0)
        else:
            e += struct.pack('<i', 0)
        e += u16s(path)
        if version > 1:
            store = sps() if R.random() < .2 else b''
            e += struct.pack('<i', len(store)) + store
        entries += e
    return struct.pack('<iiifiiii', version, len(numbers), 0, 1.0, max(numbers, default=0), 0, 1, 0) + entries


def compound(streams, mini_limit, sector_shift=9):
    """A compound file with these (name, bytes) streams in one flat directory"""
    size = 1 << sector_shift
    sectors = []
    fat_chain = {}

    def add_chain(data):
        first = len(sectors)
        chunks = [data[i:i + size].ljust(size, b'\0') for i in range(0, len(data), size)] or []
        for i, chunk in enumerate(chunks):
            sectors.append(chunk)
            fat_chain[first + i] = first + i + 1 if i + 1 < len(chunks) else -2
        return first if chunks else -2

    mini, ssat, entries = b'', [], []
    for name, data in streams:
        if 0 < len(data) < mini_limit:
            first = len(mini) // 64
            count = (len(data) + 63) // 64
            mini += data.ljust(count * 64, b'\0')
            ssat += [first + i + 1 if i + 1 < count else -2 for i in range(count)]
            entries.append((name, first, len(data)))
        else:
            entries.append((name, add_chain(data), len(data)))
    mini_first = add_chain(mini)
    ssat_first = add_chain(b''.join(struct.pack('<i', v) for v in ssat)) if ssat else -2

    def entry(name, kind, first, length, nxt=-1, child=-1):
        encoded = name.encode('utf-16le')
        times = struct.pack('<qq', 0, R.choice([0, 131000000000000000]))
        return encoded.ljust(64, b'\0') + struct.pack('<HBB', len(encoded) + 2, kind, 1) + struct.pack('<iii', -1, nxt, child) + bytes(16) + struct.pack('<I', 0) + times + struct.pack('<iiI', first, length, 0)

    directory = entry('Root Entry', 5, mini_first, len(mini), child=1 if entries else -1)
    for i, (name, first, length) in enumerate(entries):
        directory += entry(name, 2, first, length, nxt=i + 2 if i + 1 < len(entries) else -1)
    directory = directory.ljust((len(directory) + size - 1) // size * size, b'\0')
    directory_first = add_chain(directory)
    per = size // 4
    fat_sectors = 1
    while (len(sectors) + fat_sectors) > fat_sectors * per:
        fat_sectors += 1
    fat_ids = list(range(len(sectors), len(sectors) + fat_sectors))
    table = [fat_chain.get(i, -1) for i in range(len(sectors))] + [-3] * fat_sectors
    table += [-1] * (fat_sectors * per - len(table))
    fat = b''.join(struct.pack('<i', v) for v in table)
    header = bytes.fromhex('d0cf11e0a1b11ae1') + bytes(16) + struct.pack('<HHHHH', 0x3e, 3 if sector_shift == 9 else 4, 0xfffe, sector_shift, 6) + bytes(6) \
        + struct.pack('<iii', 0, fat_sectors, directory_first) + bytes(4) + struct.pack('<Ii', mini_limit, ssat_first) + struct.pack('<I', (len(ssat) * 4 + size - 1) // size) + struct.pack('<ii', -2, 0)
    ids = fat_ids + [-1] * (109 - len(fat_ids))
    header += b''.join(struct.pack('<i', v) for v in ids[:109])
    body = b''.join(sectors) + fat
    if sector_shift == 12:
        header = header.ljust(4096, b'\0')
    return header + body


def automatic():
    version = R.choice([1, 3, 4, 4, 2])
    numbers = R.sample(range(1, 300), R.randint(0, 5))
    streams = [('DestList', dest_list(version, numbers))]
    for number in numbers:
        if R.random() < .9:
            streams.append((f'{number:x}' if R.random() < .5 else f'{number:X}', lnk()))
    if R.random() < .3:
        streams.append((f'{R.randint(400, 500):x}', lnk()))
    if R.random() < .3:
        streams.append(('DestListPropertyStore', R.choice([struct.pack('<i', 0), struct.pack('<i', 1) + sps(), b'\1\0\0\0garbage', b''])))
    return compound(streams, R.choice([4096, 4096, 0, 256]), R.choice([9, 9, 12]))


def damage(data):
    data = bytearray(data)
    for _ in range(R.randint(1, 12)):
        kind = R.random()
        at = R.randrange(len(data)) if data else 0
        if kind < .7 and data:
            data[at] = R.randrange(256)
        elif kind < .85 and data and at + 4 <= len(data):
            data[at:at + 4] = struct.pack('<i', R.choice([-1, -2, 0, 1, 0x7fffffff, 512]))
        else:
            del data[at:]
    return bytes(data)


APP = ['1b4dd67f29cb1962', 'f01b4d95cf55d32a', 'abcdef0123456789', '5f7b5f1e01b83767']
for i in range(count):
    a, c = automatic(), custom()
    name = f'{R.choice(APP)}{i:04x}'
    open(f'{out}/{name}.automaticDestinations-ms', 'wb').write(a)
    open(f'{out}/{name}.customDestinations-ms', 'wb').write(c)
    if i % 2 == 0:
        os.makedirs(f'{out}/damaged', exist_ok=True)
        open(f'{out}/damaged/{name}d.automaticDestinations-ms', 'wb').write(damage(a))
        open(f'{out}/damaged/{name}d.customDestinations-ms', 'wb').write(damage(c))
