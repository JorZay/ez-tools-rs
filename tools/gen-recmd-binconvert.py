"""A hive and a batch file for RECmd's BinaryConvert (2026.11, issue #117): every conversion on values of every type,
fitting and not.
#   python3 tools/gen-recmd-binconvert.py <work folder>
# writes <work folder>/SOFTWARE, binconvert.reb and cases, for tools/parity-recmd.sh"""
import os, random, struct, sys

A = sys.argv[1]
FT = 132900000000000000
S = lambda t: (1, t.encode('utf-16-le') + b'\0\0')
X = lambda t: (2, t.encode('utf-16-le') + b'\0\0')
M = lambda *t: (7, ('\0'.join(t) + '\0\0').encode('utf-16-le'))
D = lambda n: (4, struct.pack('<I', n))
DB = lambda n: (5, struct.pack('>I', n))
Q = lambda n: (11, struct.pack('<Q', n & 0xFFFFFFFFFFFFFFFF))
B = lambda b: (3, b)
U = lambda t: t.encode('utf-16-le')


class H:
    def __init__(s): s.b = bytearray(); s.n = 0
    def cell(s, data):
        size = 4 + len(data)
        size += (8 - size % 8) % 8
        at = len(s.b)
        s.b += struct.pack('<i', -size) + data + b'\0' * (size - 4 - len(data))
        return at + 32
    def value(s, name, typ, data):
        n = name.encode('ascii')
        if 0 < len(data) <= 4:
            off = int.from_bytes(data.ljust(4, b'\0'), 'little'); ln = len(data) | 0x80000000
        elif not data:
            off, ln = 0xFFFFFFFF, 0
        else:
            off = s.cell(data); ln = len(data)
        return s.cell(b'vk' + struct.pack('<HIIIHH', len(n), ln, off, typ, 1, 0) + n)
    def key(s, name, spec, root=False):
        subs = [s.key(k, v) for k, v in spec.items() if not k.startswith('=')]
        vals = [s.value(k[1:], v[0], v[1]) for k, v in spec.items() if k.startswith('=')]
        so = 0xFFFFFFFF
        if subs: so = s.cell(b'lf' + struct.pack('<H', len(subs)) + b''.join(struct.pack('<I', x) + b'\0\0\0\0' for x in subs))
        vo = 0xFFFFFFFF
        if vals: vo = s.cell(b''.join(struct.pack('<I', v) for v in vals))
        n = name.encode('ascii')
        s.n += 1
        nk = b'nk' + struct.pack('<H', 0x20 | (0x0C if root else 0)) + struct.pack('<Q', FT + s.n * 864000000000 + 1234567) + struct.pack('<I', 0)
        nk += struct.pack('<IIIII', 0, len(subs), 0, so, 0xFFFFFFFF) + struct.pack('<II', len(vals), vo) + struct.pack('<II', 0xFFFFFFFF, 0xFFFFFFFF)
        nk += struct.pack('<IIIII', 0, 0, 0, 0, 0) + struct.pack('<HH', len(n), 0) + n
        at = s.cell(nk)
        for x in subs: struct.pack_into('<I', s.b, x - 32 + 4 + 16, at)
        return at


def write(path, internal, spec):
    h = H(); root = h.key('ROOT', spec, True)
    end = len(h.b) + 32
    size = (end + 4095) // 4096 * 4096
    if size - end < 8 and size != end: size += 4096
    tail = size - end
    body = b'hbin' + struct.pack('<III', 0, size, 0) + b'\0' * 16 + bytes(h.b)
    if tail: body += struct.pack('<i', tail) + b'\0' * (tail - 4)
    r = bytearray(4096); r[0:4] = b'regf'
    struct.pack_into('<IIQIIIII', r, 4, 1, 1, FT, 1, 3, 0, 1, root)
    struct.pack_into('<I', r, 40, size); struct.pack_into('<I', r, 44, 1)
    nm = internal.encode('utf-16-le')[:64]; r[48:48 + len(nm)] = nm
    c = 0
    for i in range(0, 508, 4): c ^= struct.unpack_from('<I', r, i)[0]
    struct.pack_into('<I', r, 508, c)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').write(bytes(r) + body)


def v6(*g): return b''.join(struct.pack('>H', x) for x in g)
def dos(y, mo, d, h, mi, s): return struct.pack('<HH', (h << 11) | (mi << 5) | (s // 2), ((y - 1980) << 9) | (mo << 5) | d)
def sid(auth, *subs): return bytes([1, len(subs)]) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in subs)


rnd = random.Random(117)
VALUES = [
    ('b0', B(b'')), ('b2', B(b'\x01\x02')), ('b3', B(b'\x01\x02\x03')), ('b4', B(b'\x7f\0\0\x01')), ('b6', B(bytes(range(0xA0, 0xA6)))),
    ('bft', B(struct.pack('<Q', FT))), ('bftneg', B(struct.pack('<q', -1))), ('bzero8', B(bytes(8))),
    ('bdouble', B(struct.pack('<d', 45000.75))), ('bmac', B(struct.pack('<d', 700000000.123456789))), ('bnan', B(struct.pack('<d', float('nan')))),
    ('bticks', B(struct.pack('<q', 638000000000000000))), ('bwebkit', B(struct.pack('<q', 13300000000000000))),
    ('bms', B(struct.pack('<q', 1700000000123))), ('bmsbad', B(struct.pack('<q', 2**62))),
    ('bst', B(struct.pack('<8h', 2024, 5, 3, 17, 13, 45, 7, 999))), ('bstbad', B(struct.pack('<8h', 2024, 13, 3, 17, 13, 45, 7, 999))),
    ('bguid', B(bytes.fromhex('90e24d373f126545916439c4925e467b'))), ('bguid2', B(bytes(range(16)))),
    ('bv6a', B(v6(0x2001, 0xdb8, 0, 0, 1, 0, 0, 1))), ('bv6b', B(v6(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304))), ('bv6c', B(v6(0, 0, 0, 0, 0, 0, 0x0102, 0x0304))),
    ('bv6d', B(v6(0, 0, 0, 0, 0xffff, 0, 0x0a00, 1))), ('bv6e', B(v6(0xfe80, 0, 0, 0, 0, 0x5efe, 0xc0a8, 1))), ('bv6f', B(v6(0, 0, 0, 0, 0, 0, 0, 1))),
    ('bv6g', B(bytes(16))), ('bv6h', B(v6(1, 0, 0, 2, 0, 0, 0, 3))), ('bv6i', B(v6(0xfe80, 0, 0, 0, 0x1ff, 0xfe23, 0x4567, 0x890a))),
    ('bsid', B(sid(5, 21, 1004336348, 1177238915, 682003330, 1001))), ('bsidhi', B(sid(0x123456789ABC, 1, 2))), ('bsidbad', B(bytes([2, 1]) + bytes(10))),
    ('bdos', B(dos(2021, 7, 14, 9, 30, 44))), ('bdosbad', B(b'\0\0\0\0')),
    ('btext16', B(U('Hello, wörld\0'))), ('bb64', B(U('SGVsbG8gd29ybGQ='))), ('bb64u', B(U('SABpAA=='))), ('bb64bin', B(U('AAEC/w=='))),
    ('basc', B(b'plain \x80\x99 text\0\0')), ('brot', B(U('HRZR_EHACNGU:P:\\Jvaqbjf\0'))),
    ('bpid', B(bytes(rnd.randrange(256) for _ in range(164)))), ('bpid2', B(bytes(rnd.randrange(256) for _ in range(67)))),
    ('d0', D(0)), ('dip', D(0x0100007F)), ('dmax', D(0xFFFFFFFF)), ('depoch', D(1600000000)), ('dbe', DB(0x01020304)),
    ('qft', Q(FT)), ('qticks', Q(638000000000000000)), ('qms', Q(1700000000123)), ('qwebkit', Q(13300000000000000)), ('qneg', Q(-5)),
    ('shex', S('0x1A2B3C4D')), ('shexbig', S('0x1FFFFFFFFFFFFFFFF')), ('shexbad', S('0xZZ')), ('shex0', S('0x')),
    ('snum', S('1600000000')), ('sneg', S('-5')), ('sspace', S('  42  ')), ('sdouble', S('45000.5')), ('sexp', S('1e3')),
    ('sinf', S('Infinity')), ('sinf2', S('inf')), ('sbig', S('1e400')), ('stext', S('abc')), ('sempty', S('')),
    ('sb64', S('SGVsbG8=')), ('sb64bad', S('SGk')), ('sb64ws', S(' SG Vs\nbG8= ')), ('srot', S('Uryyb, Jbeyq!')),
    ('sft', S('132900000000000000')), ('smac', S('700000000.5')), ('sguid', S('{374DE290-123F-4565-9164-39C4925E467B}')),
    ('xnum', X('0x10')), ('mnum', M('5', '6')), ('mtext', M('a', 'b')),
    ('none', (0, b'\x01\x02\x03\x04\x05\x06\x07\x08')),
]
CONVERSIONS = ['FILETIME', 'IP', 'EPOCH', 'SID', 'SYSTEMTIME', 'DateTimeTicks', 'OLE', 'EpochMilliseconds', 'Ascii', 'Unicode',
               'ToBase64', 'FromBase64', 'Guid', 'DosTimeDate', 'DosDateTime', 'Ipv6', 'MacAddress', 'Rot13', 'WebKit',
               'MacAbsolute', 'BigEndian', 'ProductKey', 'ProductKeyOld']

spec = {'Conv': {c: {'=' + n: v for n, v in VALUES} for c in CONVERSIONS}}
spec['Conv']['Empty'] = {}
write(os.path.join(A, 'SOFTWARE'), 'SOFTWARE', spec)

entry = lambda desc, path, conv, binary='true', value=None: (
    f"    -\n        Description: {desc}\n        HiveType: SOFTWARE\n        Category: Conv\n        KeyPath: {path}\n"
    + (f"        ValueName: {value}\n" if value else '')
    + f"        Recursive: false\n        IncludeBinary: {binary}\n        BinaryConvert: {conv}\n")
reb = 'Description: BinaryConvert\nAuthor: test\nVersion: 1\nId: 0b1e3a53-0000-4000-8000-000000000117\nKeys:\n'
reb += ''.join(entry(c, f'Conv\\{c}', c) for c in CONVERSIONS)
reb += entry('names in lower case', 'Conv\\Ascii', 'unicode')
reb += entry('a number', 'Conv\\IP', '2')
reb += entry('binary not included', 'Conv\\FILETIME', 'FILETIME', 'false')
reb += entry('one value', 'Conv\\EPOCH', 'EPOCH', 'true', 'snum')
reb += entry('no value', 'Conv\\Empty', 'Guid')
open(os.path.join(A, 'binconvert.reb'), 'w').write(reb)
open(os.path.join(A, 'cases'), 'w').write(
    f'-f "{A}/SOFTWARE" --bn "{A}/binconvert.reb" --csv {{out}} --csvf out.csv --nl\n'
    f'-f "{A}/SOFTWARE" --bn "{A}/binconvert.reb" --json {{out}} --nl\n'
    f'-f "{A}/SOFTWARE" --bn "{A}/binconvert.reb" --csv {{out}} --csvf out.csv --nl --dt "dd/MM/yyyy HH:mm:ss.fff"\n')
