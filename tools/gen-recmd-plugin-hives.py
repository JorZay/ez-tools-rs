"""Hives for the RECmd plugins: every plugin's key, with normal, missing, odd and damaged values, and a batch file for them."""
#   python3 tools/gen-recmd-plugin-hives.py <work folder> <a raw AppCompatCache value, e.g. upstream's Win10Creators.bin> [shell items]
# [shell items]: a file of base64 shell items, one per line after a tab (ExtensionBlocks' samples): adds hives with them in the shell item
# plugins' values, as they are and randomly damaged.
# writes <work folder>/h (the hives), plugins.reb and cases, for tools/parity-recmd.sh
import base64, os, random, struct, sys
A, ACC = sys.argv[1], sys.argv[2]
SAMPLES = sys.argv[3] if len(sys.argv) > 3 else None
FT = 132900000000000000
S = lambda t: (1, t.encode('utf-16-le') + b'\0\0')
D = lambda n: (4, struct.pack('<I', n))
Q = lambda n: (11, struct.pack('<Q', n))
B = lambda b: (3, b)
M = lambda *t: (7, ('\0'.join(t) + '\0\0').encode('utf-16-le'))

class H:
    def __init__(s): s.b = bytearray(); s.n = 0
    def cell(s, data, sl=0):
        size = 4 + len(data) + sl
        size += (8 - size % 8) % 8
        at = len(s.b)
        s.b += struct.pack('<i', -size) + data + b'\0' * (size - 4 - len(data))
        return at + 32
    def value(s, name, typ, data, sl=b''):
        try: n = name.encode('ascii'); fl = 1
        except UnicodeError: n = name.encode('utf-16-le'); fl = 0
        if 0 < len(data) <= 4:
            off = int.from_bytes(data.ljust(4, b'\0'), 'little'); ln = len(data) | 0x80000000
        elif not data:
            off, ln = 0xFFFFFFFF, 0
        else:
            off = s.cell(data, len(sl))
            st = off - 32 + 4 + len(data); s.b[st:st + len(sl)] = sl; ln = len(data)
        return s.cell(b'vk' + struct.pack('<HIIIHH', len(n), ln, off, typ, fl, 0) + n)
    def key(s, name, spec, root=False):
        subs = [s.key(k, v) for k, v in spec.items() if not k.startswith('=')]
        vals = []
        for k, v in spec.items():
            if k.startswith('='):
                vals.append(s.value(k[1:], v[0], v[1], v[2] if len(v) > 2 else b''))
        so = 0xFFFFFFFF
        if subs: so = s.cell(b'lf' + struct.pack('<H', len(subs)) + b''.join(struct.pack('<I', x) + b'\0\0\0\0' for x in subs))
        vo = 0xFFFFFFFF
        if vals: vo = s.cell(b''.join(struct.pack('<I', v) for v in vals))
        try: n = name.encode('ascii'); fl = 0x20
        except UnicodeError: n = name.encode('utf-16-le'); fl = 0
        s.n += 1
        nk = b'nk' + struct.pack('<H', fl | (0x0C if root else 0)) + struct.pack('<Q', FT + s.n * 864000000000 + 1234567) + struct.pack('<I', 0)
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

def nest(path, spec):
    for p in reversed(path.split('\\')): spec = {p: spec}
    return spec
def merge(a, b):
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict): merge(a[k], v)
        else: a[k] = v
    return a
def tree(*pairs):
    t = {}
    for p, s in pairs: merge(t, nest(p, s))
    return t
ft = struct.pack('<Q', FT)
NASTY = 'a,"b"\nc\u00e9\u4e2d\U0001F600'

amc = lambda **k: {'=' + n: S(v) for n, v in k.items()}
AMCACHE = tree(
 ('Root\\InventoryApplication', {'one': amc(Name='App', Version='1.0', Publisher='Pub,lisher', Source='s', RootDirPath='C:\\x', UninstallString=NASTY), 'empty': {}}),
 ('Root\\InventoryApplicationFile', {'f': {**amc(LowerCaseLongPath='c:\\a.exe', Name='a', ProductName='p', Publisher='q', Version='2'), '=FileId': S('0000abcdef0000123400005678')}, 'g': {'=FileId': D(5)}, 'h': {}}),
 ('Root\\InventoryApplicationShortcut', {'s': amc(ShortcutPath='c:\\a.lnk'), 't': {}}),
 ('Root\\InventoryDeviceContainer', {'d': amc(ModelName='m', FriendlyName='f', ModelNumber='n', Manufacturer='x', PrimaryCategory='c', ModelId='i'), 'e': {}}),
 ('Root\\InventoryDevicePnp', {'d': amc(Model='m', Manufacturer='x', Description='d', InstallDate='01/02/2020', ParentId='p', MatchingID='z'), 'e': {}}),
 ('Root\\InventoryDriverBinary', {'c:/d.sys': {**amc(DriverLastWriteTime='1/2/2020', DriverCompany='co', DriverName='n', DriverVersion='v', Product='p', ProductVersion='pv'), '=DriverId': S('00001111')}, 'e': {}}),
 ('Root\\Mare', {'a': amc(restore='x|y|z'), 'b': amc(restore='nopipe'), 'c': {}, 'd': amc(restore='|')}),
)
def rv(*args): return {'=' + n: v for n, v in args}
NTUSER = tree(
 ('Software\\7-Zip\\Compression', {'=ArcHistory': (3, ('c:\\a.7z\0  \0\0' + NASTY + '\0').encode('utf-16-le')), '=Other': D(1)}),
 ('Software\\7-Zip\\FM', {'=CopyHistory': M('c:\\copy1', 'c:\\copy2'), '=FolderHistory': M('c:\\f1'), }),
 ('Software\\7-Zip\\Extraction', {'=PathHistory': (3, 'c:\\ex'.encode('utf-16-le') + b'\x41')}),
 ('Software\\Adobe', {'Acrobat': {'11.0': {'TrustManager': {'cDefaultLaunchURLPerms': {'=tHostPerms': S('version:1|http://a.com:2|http://b.com:3|http://c.com:9|ok:2')}}}, '10.0': {}, '9.0': {'TrustManager': {}}}, 'Reader': {'1': {'TrustManager': {'cDefaultLaunchURLPerms': {'=tHostPerms': S('good:2|x|after:3')}}}, '2': {'TrustManager': {'cDefaultLaunchURLPerms': {}}}}}),
 ('Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags', {'Layers': rv(('c:\\a.exe', S('~ RUNASADMIN')), ('c:\\b.exe', S('x'))), 'Compatibility Assistant': {'Persisted': rv(('c:\\p.exe', D(1))), 'Store': rv(('c:\\s.exe', B(b'\1' * 20)))}, 'Other': rv(('x', D(1)))}),
 ('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths', {'a.exe': rv(('(default)', S('c:\\a.exe')), ('Path', S('c:\\'))), 'b.exe': {}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage', {'AppBadgeUpdated': rv(('Microsoft.App', D(7)), ('Other', S('t'))), 'AppSwitched': rv(('x', Q(9))), 'Empty': {}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData', rv(('App.One', B(ft)), ('Short', B(b'\1\2')), ('Empty', B(b'')))),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', rv(('MRUList', S('cab')), ('a', S('cmd\\1')), ('b', S('notepad')), ('c', S('calc\\1\\1')), ('z', S('not in list')), ('yy', S('two chars')))),
 ('Software\\Microsoft\\Terminal Server Client', {'Default': rv(('MRU0', S('host1')), ('MRU1', S('host2'))), 'Servers': {'host1': rv(('UsernameHint', S('dom\\user'))), 'host2': {}, 'host3': rv(('UsernameHint', S('')))}}),
 ('Software\\Microsoft\\Internet Explorer\\TypedURLs', {'=url1': S('http://one') + ('p\0a\0s\0t\0'.encode(),), '=url2': S('http://two'), '=url3': S('http://three'), '=url4': S('http://four'), '=url5': S('http://five'), '=url6': S('http://six')}),
 ('Software\\Microsoft\\Internet Explorer\\TypedURLsTime', rv(('url1', B(ft)), ('url2', B(b'\1\2')), ('url3', B(struct.pack('<q', -1))), ('url4', B(struct.pack('<q', 100))), ('url5', B(struct.pack('<q', 2650467744000000000))))),
 ('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', {'App': {'=DisplayName': S('N'), '=DisplayVersion': S('1'), '=Publisher': S('P'), '=InstallDate': S('2020'), '=InstallSource': S('s'), '=InstallLocation': S('l'), '=UninstallString': S('u')}, 'Bare': {}}),
 ('Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository', {'Families': {'Fam': {'App_1': rv(('InstallTime', Q(FT))), 'App_2': rv(('InstallTime', S('notnum'))), 'App_3': {}, 'App_4': rv(('InstallTime', S(' 123 ')))}}, 'Packages': {'App_1': rv(('DisplayName', S('Dn')), ('PackageRootFolder', S('c:\\r')))}}),
 ('Software\\WinRAR', {'ArcHistory': rv(('0', S('c:\\a.rar')), ('1', D(4))), 'DialogEditHistory': {'ArcName': rv(('0', S('x.rar'))), 'ExtrPath': rv(('0', S('c:\\out')))}, 'Other': rv(('0', S('skip')))}),
)
NTUSER_BAD = tree(
 ('Software\\Microsoft\\Terminal Server Client', {'Default': rv(('MRU0', S('h')), ('MRUx', S('i'))), 'Servers': {'h': {}}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData', rv(('good', B(ft)), ('neg', B(struct.pack('<q', -5))), ('after', B(ft)))),
 ('Software\\Adobe', {'A': {'1': {'TrustManager': {'cDefaultLaunchURLPerms': {'=tHostPerms': S('fine:2|y')}}}}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', rv(('a', S('no list'))),),
)
NTUSER_BAD2 = tree(
 ('Software\\Microsoft\\Terminal Server Client', {'Default': rv(('AB', S('h'))), 'Servers': {'h': {}}}),
 ('Software\\Adobe', {'A': {'1': {'TrustManager': {'cDefaultLaunchURLPerms': {}}}}}),
)
NTUSER_BAD3 = tree(
 ('Software\\Microsoft\\Terminal Server Client', {'Default': rv(('MRU0', S('h')), ('MRU1', S('h'))), 'Servers': {'h': {}}}),
)
NTUSER_BAD4 = tree(
 ('Software\\Microsoft\\Terminal Server Client', {'Default': rv(('MRU99999999999', S('h'))), 'Servers': {'h': {}}}),
)
NTUSER_BAD5 = tree(
 ('Software\\Microsoft\\Terminal Server Client', {'Servers': {'h': {}}}),
 ('Software\\Adobe', {'A': {'1': {'TrustManager': {'cDefaultLaunchURLPerms': {'=tHostPerms': S('')}}}}}),
)
acc = open(ACC, 'rb').read()
CS = {
 'Control': {
  'Session Manager': {'AppCompatCache': {'=AppCompatCache': B(acc)}, 'Environment': {'=PROCESSOR_ARCHITECTURE': S('AMD64')}},
  'DeviceClasses': {'{53f56307-b6bf-11d0-94f2-00a0c91efb8b}': {'##?#USBSTOR#Disk&Ven_A#123&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}': {}, '##?#STORAGE#Volume#_??_USBSTOR#Disk&Ven_B#456&0#{x}': {}, 'x#y#z': {}, 'a##b#c#d': {}}, '{00000000-0000-0000-0000-000000000000}': {'skip#me#now': {}}, '{A5DCBF10-6530-11D2-901F-00C04FB951ED}': {'one#two': {}, 'never#read#this': {}}, '{6AC27878-A6FA-4155-BA85-F98F491D4F33}': {'p#q#r': {}}},
  'Lsa': {'=DsrmAdminLogonBehavior': D(2), '=Other': D(1)},
  'Class': {'{4d36e972-e325-11ce-bfc1-08002be10318}': {'0000': {'=DriverDesc': S('Nic'), '=DriverDate': S('1-1-2020'), '=DriverVersion': S('1'), '=DeviceInstanceID': S('PCI\\x'), '=ProviderName': S('Prov')}, '0001': {}, 'Properties': {'=x': D(1)}, '00123': {}}},
  'NetworkSetup2': {'Interfaces': {'{a}': {'Kernel': {'=ProtocolList': M('a', 'b'), '=IfAlias': S('Eth'), '=IfDescr': S('Desc'), '=IfType': D(6), '=PermanentAddress': B(b'\0\1\2\3\4\5'), '=CurrentAddress': B(b'\6\7\x08\x09\x0a\x0b')}}, '{b}': {}}, 'Other': {}},
  'WMI': {'Autologger': {'EventLog-Application': {'{cafeefac-0015-0000-0007-abcdeffedcbc}': {'=Enabled': D(1), '=EnableProperty': D(0)}, '{00000000-0000-0000-0000-000000000123}': {'=enabled': S('x')}, 'not a guid': {}, '{04271989-0000-0000-0000-000000000000}': {}}, 'EventLog-System': {'{91cf45d0-9550-4bac-8d54-2f764ac27f70}': {}}}},
 },
 'Services': {
  'bam': {'State': {'UserSettings': {'S-1-5-18': {'=\\Device\\a.exe': B(ft + b'\0' * 16), '=Version': D(1), '=SequenceNumber': D(1), '=\\Device\\short': B(b'\1\2'), '=\\Device\\neg': B(struct.pack('<q', -5)), '=\\Device\\big': B(struct.pack('<q', 2650467744000000000))}}}, 'UserSettings': {'S-1-5-19': {'=\\Device\\b.exe': B(ft)}}},
  'dam': {'UserSettings': {'S-1-5-20': {'=\\Device\\c.exe': B(ft)}}},
  'BTHPORT': {'Parameters': {'Devices': {'001122334455': {'=Name': B(b'Phone \xe9\x80\x00'), '=LastSeen': B(ft), 'CachedServices': {}, 'Sub': {'=Name': B(b'Inner'), 'x': {}}, 'Sub2': {'=Name': B(b'NoSubs')}}, '66': {'=Name': B(b'NoSubkeys')}, '77': {'x': {}}, '88': {'=Name': B(b'NoSeen'), 'x': {}}}}},
  'Tcpip': {'Parameters': {'Interfaces': {'{i}': {'=IPAddress': M('10.0.0.1'), '=SubnetMask': M('255.0.0.0'), '=DhcpSubnetMask': S('m'), '=DhcpServer': S('s'), '=DhcpNameServer': S('n'), '=DhcpIPAddress': S('i'), '=DhcpDefaultGateway': M('g'), '=LeaseObtainedTime': D(1600000000), '=LeaseTerminatesTime': D(4294967295), '=EnableDHCP': D(1)}, '{j}': {'=EnableDHCP': D(0)}, '{k}': {}, '{bad}': {'=LeaseObtainedTime': B(b'\1')}, '{bad2}': {'=LeaseTerminatesTime': B(b'')}}}},
 },
}
SYSTEM = {'ControlSet001': CS, 'ControlSet002': {'Control': {'Session Manager': {'AppCompatCache': {'=AppCompatCache': B(b'bogus-cache-value')}}, 'Lsa': {'=dsrmadminlogonbehaviour': S('abc'), '=DSRMADMINLOGONBEHAVIOR': D(1)}, 'WMI': {'Autologger': {'EventLog-Application': {'{cafeefac-0015-0000-0007-abcdeffedcbc}': {}}}}}}}
SYSTEM_BAD = {'ControlSet001': {'Control': {'Session Manager': {'AppCompatCache': {'=Other': D(1)}}, 'Lsa': {'=DsrmAdminLogonBehavior': D(0)}}, 'Services': {'BTHPORT': {'Parameters': {'Devices': {'a': {'=Name': B(b'First'), 'x': {}}, 'b': {'=Name': B(b'Bad'), '=LastSeen': B(b'\1'), 'x': {}}, 'c': {'=Name': B(b'Never'), 'x': {}}}}}}}}
SOFTWARE = tree(
 ('Microsoft\\Windows\\CurrentVersion\\App Paths', {'c.exe': rv(('(default)', S('c:\\c.exe')))}),
 ('Microsoft\\Windows\\CurrentVersion\\Uninstall', {'U1': {'=DisplayName': S('One')}, 'U2': {}}),
 ('WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', {'W1': {'=Publisher': S('Wow')}}),
 ('Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products', {'P1': {'InstallProperties': {'=DisplayName': S('Prod'), '=DisplayVersion': S('1.2'), '=InstallDate': S('20200101'), '=Publisher': S('Pb'), '=Language': D(1033), '=InstallLocation': S('il'), '=InstallSource': S('is'), '=Comments': S('cm')}}, 'P2': {}}),
 ('Classes\\Installer\\Products', {'C1': {'=ProductName': S('CP'), '=Language': D(1033), 'SourceList': {'=PackageName': S('a.msi'), '=LastUsedSource': S('n;1;c:\\')}}, 'C2': {}}),
 ('Microsoft\\Windows NT\\CurrentVersion\\ProfileList', {
   'S-1-5-18': {'=ProfileImagePath': S('c:\\sys'), '=LocalProfileLoadTimeHigh': D(30000000), '=LocalProfileLoadTimeLow': D(1234), '=LocalProfileUnloadTimeHigh': D(30000000), '=LocalProfileUnloadTimeLow': D(0xABCDEF01)},
   'OnlyHigh': {'=LocalProfileLoadTimeHigh': D(1)}, 'Bare': {}, 'BadText': {'=LocalProfileLoadTimeHigh': S('abc'), '=LocalProfileLoadTimeLow': D(1)},
   'Empty': {'=LocalProfileLoadTimeHigh': S(''), '=LocalProfileLoadTimeLow': D(1)}, 'Over': {'=LocalProfileLoadTimeHigh': S('99999999999999999999'), '=LocalProfileLoadTimeLow': D(1)},
   'Long': {'=LocalProfileLoadTimeHigh': S('9223372036854775807'), '=LocalProfileLoadTimeLow': S('9223372036854775807')}, 'Neg': {'=LocalProfileLoadTimeHigh': D(0xFFFFFFFF), '=LocalProfileLoadTimeLow': D(0xFFFFFFFF)},
   'Minus': {'=LocalProfileLoadTimeHigh': S('-1'), '=LocalProfileLoadTimeLow': D(1)}, 'Space': {'=LocalProfileLoadTimeHigh': S(' 1 '), '=LocalProfileLoadTimeLow': S('+2\0')},
 }),
 ('Microsoft\\RADAR\\HeapLeakDetection', {'DiagnosedApplications': {'a.exe': rv(('LastDetectionTime', Q(FT))), 'b.exe': {}, 'c.exe': rv(('LastDetectionTime', S('x'))), 'd.exe': rv(('LastDetectionTime', Q(0x8000000000000001)))}, 'ReflectionApplications': {'e.exe': {}}}),
 ('Microsoft\\Windows Search\\VolumeInfoCache', {'C:': rv(('VolumeLabel', S('Sys')), ('DriveType', D(3))), 'D:': rv(('DriveType', D(9))), 'E:': {}, 'F:': rv(('DriveType', S('2')))}),
 ('Microsoft\\Windows Portable Devices', {'Devices': {'WPD#x##USBSTOR#Disk#SER1#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}': rv(('FriendlyName', S('Stick'))), 'SWD#WPD??a#b#c': {}, 'plain': {}, 'x##one#two': {}, 'guid-{12345678-1234-1234-1234-1234567890ab}': {}, 'y##a#b#c??d#e': {}}}),
)
SOFTWARE_BAD = tree(('WOW6432Node\\Microsoft\\RADAR\\HeapLeakDetection', {'DiagnosedApplications': {'a.exe': {}}}), ('Microsoft\\Windows\\CurrentVersion\\Uninstall', {'U1': {}}))
SOFTWARE_BAD2 = tree(('Microsoft\\RADAR\\HeapLeakDetection', {'ReflectionApplications': {'a.exe': {}}}))
USRCLASS = tree(('Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository', {'Families': {'F': {'A': rv(('InstallTime', Q(FT)))}}, 'Packages': {'A': rv(('DisplayName', S('Name')))}}))
USRCLASS2 = tree(('Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository', {'Families': {'F': {}}}))
# Shell items for LastVisitedPidlMRU, OpenSavePidlMRU, Taskband and RecentDocs
EXPLORER = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer'
U = lambda t: t.encode('utf-16-le') + b'\0\0'
def sized(b): return struct.pack('<H', len(b) + 2) + b
def be4(name): return sized(struct.pack('<HI', 9, 0xbeef0004) + b'\x21\x48\0\0\x21\x48\0\0' + struct.pack('<H', 0x2e) + b'\0\0' + struct.pack('<IHH', 5, 0, 3) + b'\0' * 18 + U(name) + b'\0\0\x14\0')
def be_text(sig, text): return sized(struct.pack('<HI', 0, sig) + b'\0\0' + U(text) + b'\x14\0')
def fileitem(kind, short, long, *blocks): 
    b = bytes([kind, 0]) + struct.pack('<I', 1234) + b'\x21\x48\0\x60\x20\0' + short.encode() + b'\0'
    if len(b) % 2: b += b'\0'
    return sized(b + be4(long) + b''.join(blocks) + b'\0\0')
ROOT = sized(bytes([0x1f, 0x50]) + bytes.fromhex('e04fd020ea3a6910a2d808002b30309d'))
DRIVE = sized(bytes([0x2f]) + b'C:\\'.ljust(22, b'\0'))
PATHITEM = ROOT + DRIVE + fileitem(0x31, 'USERS', 'Users') + fileitem(0x32, 'LONGFI~1.PDF', 'long file, "x".pdf')
UNKNOWN = sized(bytes([0xfe, 1, 2]))
def mru(*n): return B(b''.join(struct.pack('<i', x) for x in n) + b'\xff\xff\xff\xff')
def recent(target, item, end=b'\0\0'): return B(U(target) + item + end)
def nameditem(kind, text, tail=b''):
    name = text.encode('utf-16-le') if kind == 36 else text.encode('latin-1')
    return sized(bytes([kind]) + b'\0' * 11 + name + b'\0\0' + tail)
def favorites(*chunks, first=b'\0', marker=b'\0\0\0\0\xff'):
    b = first
    for c in chunks: b += struct.pack('<i', len(c) + 4) + c + marker
    return B(b)
PIN1 = fileitem(0x32, 'A.LNK', 'App One.lnk', be_text(0xbeef001d, 'C:\\apps\\one.exe'), be_text(0xbeef001e, 'User pinned'))
PIN2 = fileitem(0x32, 'B.LNK', 'Bare.lnk')
SHELL = tree(
 (EXPLORER + '\\ComDlg32\\LastVisitedPidlMRU', rv(('MRUListEx', mru(1, 0, 3)), ('0', B(U('notepad.exe') + PATHITEM + b'\0\0')), ('1', B(U('first.exe') + ROOT + DRIVE + b'\0\0')), ('2', B(U('notinlist.exe') + ROOT)),
   ('3', B(U('noitems.exe'))), ('name', B(U('name.exe') + ROOT)), ('4', B(U('past.exe') + ROOT + b'\xff\xff\0\0')), ('5', B(U('small.exe') + ROOT + b'\x02\0\0\0')), ('6', B(U('unknown.exe') + UNKNOWN + ROOT)), ('7', B(U('cut.exe') + sized(bytes([0x32, 0])) + ROOT)), ('8', B('noend'.encode('utf-16-le'))), ('9', B(b'')), ('10', S('text')))),
 (EXPLORER + '\\ComDlg32\\LastVisitedPidlMRULegacy', rv(('MRUListEx', B(b'\1\0\0\0\xff')), ('0', B(U('never.exe') + ROOT)))),
 (EXPLORER + '\\ComDlg32\\OpenSavePidlMRU', {'*': rv(('MRUListEx', mru(1, 0)), ('0', B(PATHITEM + b'\0\0')), ('1', B(ROOT + b'\0\0')), ('2', B(ROOT + DRIVE)), ('x', B(UNKNOWN))), 'pdf': rv(('0', B(ROOT + b'\xff\xff'))), 'odd': rv(('MRUListEx', B(b'\xff\xff\xff\xff'))), 'empty': {}}),
 (EXPLORER + '\\Taskband', rv(('Favorites', favorites(PIN1 + PIN2 + fileitem(0x31, 'DIR', 'A folder', be_text(0xbeef001d, 'x'), be_text(0xbeef001e, 'y')), ROOT + UNKNOWN + sized(bytes([0x32, 0])) + b'\0\0')), ('Other', D(1)))),
 (EXPLORER + '\\RecentDocs', {**rv(('MRUListEx', mru(2, 0, 2, 9)), ('0', recent('report.pdf', nameditem(36, 'report.lnk', be4('report long.lnk')))), ('1', recent('a folder', nameditem(36, 'folder.lnk'))), ('2', recent('sheet.XLSX', nameditem(0x32, 'sh\xe9et.lnk'), b'')),
     ('3', recent('noitem.txt', b'')), ('4', recent('zero.txt', b'\0\0')), ('5', recent('short.txt', sized(b'\0'))), ('6', recent('bad.txt', nameditem(36, 'bad', struct.pack('<HHI', 12, 9, 0xbeef0004) + b'\1\2\3\4'))), ('ViewStream', B(b'\1\2')), ('CachePrefix', S('x')), ('-0', recent('minus.txt', nameditem(36, 'minus.lnk'))), (' 7 ', recent('space.tar.gz', nameditem(0x32, 'space.lnk'))), ('8', recent('dot.', nameditem(36, 'dot.lnk')))),
   '.pdf': {**rv(('MRUListEx', mru(0)), ('0', recent('report.pdf', nameditem(36, 'report.lnk', be4('report long.lnk'))))), },
   '.XLSX': rv(('MRUListEx', mru(4)), ('4', recent('other.xlsx', nameditem(36, 'o.lnk')))),
   '.txt': rv(('0', recent('t.txt', nameditem(36, 't.lnk')))),
   'Folder': rv(('MRUListEx', mru(0)), ('0', recent('a folder', nameditem(36, 'folder.lnk')))),
   '.short': rv(('MRUListEx', B(b'\0\0')))}),
)
BAD_FAVORITES = [b'', b'\0', b'\0\1\2', struct.pack('<bi', 0, -1), struct.pack('<bi', 0, 0), struct.pack('<bi', 0, 2), struct.pack('<bi', 0, 0x7fffffff), favorites(ROOT, marker=b'')[1], favorites(ROOT + b'\1')[1], favorites(ROOT[:-2] + b'\xff\xff')[1], favorites(b'\xff\xff' + ROOT)[1]]
EXTRA_HIVES = {f'ntuser_taskband{i}/NTUSER.DAT': ('ntuser.dat', tree((EXPLORER + '\\Taskband', rv(('Favorites', B(b)))))) for i, b in enumerate(BAD_FAVORITES)}
EXTRA_HIVES['ntuser_shell/NTUSER.DAT'] = ('ntuser.dat', SHELL)
EXTRA_HIVES['ntuser_shell_oddmru/NTUSER.DAT'] = ('ntuser.dat', tree((EXPLORER + '\\ComDlg32\\OpenSavePidlMRU', {'a': rv(('0', B(ROOT))), 'b': rv(('MRUListEx', B(b'\1\0')), ('0', B(ROOT))), 'c': rv(('0', B(DRIVE)))})))
if SAMPLES:
    items = [base64.b64decode(l.split('\t')[1]) for l in open(SAMPLES) if '\t' in l and not l.startswith('#')]
    def damage(b, r):
        b = bytearray(b)
        m = r.randrange(5)
        if m == 0:
            for _ in range(r.randint(1, 4)): b[r.randrange(len(b))] = r.randrange(256)
        elif m == 1: b = b[:r.randrange(len(b) + 1)]
        elif m == 2:
            i = r.randrange(len(b)); b[i:i + 2] = r.choice([b'\0\0', b'\xff\xff', b'\xff\x7f', b'\2\0', b'\1\0'])
        elif m == 3: b += bytes(r.randrange(256) for _ in range(r.randint(1, 30)))
        else:
            i = r.randrange(len(b)); b[i:i + 4] = bytes(r.randrange(256) for _ in range(4))
        return bytes(b)
    def sample_hive(values, r):
        lv = {'=MRUListEx': mru(*range(0, len(values), 2))}; os_ = dict(lv); rd = dict(lv)
        for n, it in enumerate(values):
            lv[f'={n}'] = B(U('app.exe') + it + b'\0\0'); os_[f'={n}'] = B(it + b'\0\0')
            rd[f'={n}'] = B(U(f'doc{n % 7}.txt') + nameditem(36, 'n', it) + b'\0\0')
        spec = tree((EXPLORER + '\\ComDlg32\\LastVisitedPidlMRU', lv), (EXPLORER + '\\ComDlg32\\OpenSavePidlMRU', {'*': os_}), (EXPLORER + '\\RecentDocs', rd), (EXPLORER + '\\Taskband', rv(('Favorites', favorites(*[v[:2000] for v in values[:40]])))))
        return ('ntuser.dat', spec)
    good = [i for i in items if len(i) >= 3]
    EXTRA_HIVES['ntuser_samples/NTUSER.DAT'] = sample_hive(good, None)
    for seed in range(1, 6):
        r = random.Random(seed)
        EXTRA_HIVES[f'ntuser_damaged{seed}/NTUSER.DAT'] = sample_hive([damage(r.choice(good), r) for _ in range(1500)], r)
    # Taskband reads until something stops it, so a hive for each
    r = random.Random(99)
    for n in range(300):
        vals = [damage(r.choice(good), r) for _ in range(r.randint(1, 3))]
        EXTRA_HIVES[f'tb/{n}/NTUSER.DAT'] = ('ntuser.dat', tree((EXPLORER + '\\Taskband', rv(('Favorites', B(damage(favorites(*vals)[1], r)))))))
# The medium plugins
def ftb(n=0): return struct.pack('<q', FT + n)
def hexa(t): return t.encode('latin-1').hex().upper()
def adobe_item(date, **kw):
    v = {'=tDIText': S('/C/a.pdf'), '=tFileName': S('a.pdf'), '=uFileSize': D(1234), '=tFileSource': S('src'), '=uPageCount': D(7)}
    if date is not None: v['=sDate'] = S(date)
    v.update(kw); return v
DATES = ["D:20200102030405+01'00'", "D:20200102030405-05'30'", "D:20200102030405Z", "D:20200102030405Z00'00'", "D:20200102030405+0'00'", "D:20200102030405+0100", "D:20200102030405+100", "D:20200102030405+01", "D:20200102030405+1", "D:20200102030405+14'00'", "D:20200102030405+14'01'", "D:20200102030405+15'00'", "D:20200102030405+01'60'", "D:20201302030405+01'00'", "D:20200230030405+01'00'", "D:20200102250405+01'00'", "D:00010101000000+01'00'", "D:99991231235959-01'00'", "D:00000101000000+01'00'", "D:2020010203040", "short", "XXabcd0102030405+01'00'", "D:20200102030405", "D:20200102030405 +01'00'"]
ARES_AWAY = '5468697320697320616E206175746F6D617469632061776179206D6573736167652067656E65726174656420627920417265732070726F6772616D2C20757365722069736E27742068657265206E6F772E'
HINT = 'Home Wifi'.encode('latin-1').hex()[::-1]
SYSTIME = struct.pack('<8h', 2020, 2, 3, 4, 5, 6, 7, 8)
USERASSIST = {'{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}': {'Count': rv(
   ('{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\\abc.rkr', B(b'\0' * 4 + struct.pack('<ii', 12, 3) + struct.pack('<i', 123456789) + b'\0' * 44 + ftb() + b'\0' * 4)),
   ('HRZR_PGYFRFFVBA', B(b'\0' * 4 + struct.pack('<i', 2) + ftb())), ('short', B(b'\1\2\3')), ('{ABCDEF01-0000-0000-0000-000000000000}\\x', B(b'\0' * 4 + struct.pack('<i', 1234567) + struct.pack('<q', 100))),
   ('C:\\Znva.rkr', B(b'\0' * 4 + struct.pack('<ii', -5, -1) + struct.pack('<i', -90061000) + b'\0' * 44 + ftb(5) + b'\0' * 4)), ('neg', B(b'\0' * 8 + struct.pack('<q', -1))))}, 'Empty': {}}
def office(path_, ft_='01D005C5B44B6300'): return S(f'[F00000000][T{ft_}][O00000000]*{path_}')
OFFICE_VALUES = rv(('Item 1', office('C:\\a\\doc.docx')), ('Item 2', office('C:\\read.docx', '1D005C5B44B6300')), ('Max Display', D(25)), ('Item Metadata 1', S('<x/>')), ('FOLDER1', S('C:\\folder')), ('Item 3', S('notentry')), ('Item 4', S('[T00]')), ('Item 5', S('[F0]*noT')), ('Item 6', S('[TZZ]*bad')), ('Item 7', office('C:\\late.docx', 'FFFFFFFFFFFFFFFF')))
def taskflow(*rows):
    b = b'\0' * 4 + ftb() + b'\0' * 0xd
    for full, exe, title in rows:
        b += b'\x12\x34' + bytes([len(full)]) + full.encode('utf-16-le') + b'\0' * 5 + b'\xd2\0' + bytes([len(exe)]) + exe.encode('utf-16-le')
        if title is None: b += struct.pack('<h', 0x32c6) + b'\0' * 0x18
        else: b += b'\1\0' + bytes([len(title)]) + title.encode('utf-16-le') + b'\0' * 0x1a
    return B(b)
def icons(*names, count=None):
    b = b'\0' * 0x18 + struct.pack('<h', len(names) if count is None else count) + b'\0' * 6
    for n in names: b += struct.pack('<h', len(n)) + b'\0' * 6 + n.encode('utf-16-le')
    return B(b)
RECENT_APP = {'=AppId': S('app.one'), '=AppPath': S('C:\\one.exe'), '=LastAccessedTime': Q(FT), '=LaunchCount': D(4), 'RecentItems': {'{i}': {'=DisplayName': S('doc'), '=LastAccessedTime': Q(FT + 1), '=Path': S('C:\\doc.txt')}, '{j}': {'=LastAccessedTime': Q(FT + 2)}}}
TR = '-'.join(f'{x:02X}' for x in ftb()) + '-00-00-00-00-'
def trust(tail): return B(bytes.fromhex(TR.replace('-', '')) + bytes.fromhex(tail))
M_NTUSER = tree(
 ('Software\\Adobe', {'Acrobat Reader': {'11.0': {'AVGeneral': {'cRecentFiles': {**{f'c{i}': adobe_item(d) for i, d in enumerate(DATES)}, 'nodate': adobe_item(None), 'bin': {'=tDIText': B(b'/C/b\xe9n.pdf\0'), '=sDate': B(b"D:20200102030405+01'00'\0"), '=uFileSize': B(b'\1\0')}, 'bare': {}}}}, 'noav': {}}, 'noversion': {}}),
 ('Software\\Ares', {'=Network.DHTID': S('AB-CD'), '=Download.Folder': S(hexa('C:\\dl')), '=Personal.CustomMessage': S('hi'), '=Personal.Nickname': S(hexa('nick\xe9')), '=PrivateMessage.AwayMessage': S(hexa('gone')), '=Stats.LstConnect': D(1600000000), '=Transfer.ServerPort': D(1234), '=Personal.GUID': S('{g}'),
   'Search.History': {'genHist': {'=' + hexa('term one'): S(''), '=' + hexa('two'): S(''), '=zz': S('')}, 'audio1234': {'=' + hexa('song'): S('')}, 'none': {}}}),
 (EXPLORER + '\\ComDlg32\\CIDSizeMRU', rv(('MRUListEx', mru(1, 0, 1)), ('0', B(U('b.exe'))), ('1', B(U('a.exe') + U('more'))), ('5', B(U('notlisted.exe'))), ('name', B(U('x'))), ('Oddity', S('t')))),
 (EXPLORER + '\\ComDlg32\\FirstFolder', rv(('MRUListEx', mru(1, 0)), ('0', B(U('b.exe'))), ('1', B(U('a.exe') + U('C:\\f'))))),
 (EXPLORER + '\\ComDlg32\\LastVisitedMRU', rv(('MRUList', S('ba')), ('a', B(U('a.exe') + U('C:\\a'))), ('b', B(U('b.exe') + U('C:\\b'))), ('c', B(U('c.exe') + U('C:\\c'))))),
 (EXPLORER + '\\ComDlg32\\OpenSaveMRU', {**rv(('MRUList', S('ba')), ('a', S('C:\\a.txt')), ('b', S('C:\\b.txt'))), '*': rv(('MRUList', S('a')), ('a', S('C:\\s.txt'))), 'pdf': rv(('z', S('C:\\z.pdf'))), 'none': {}}),
 (EXPLORER + '\\FileExts', {'.txt': {'OpenWithList': rv(('MRUList', S('bca')), ('a', S('a.exe')), ('b', S('b.exe'))), 'OpenWithProgids': rv(('txtfile', B(b'')), ('other', B(b''))), 'UserChoice': rv(('ProgId', S('Applications\\a.exe'))), 'Skip': {}}, '.bare': {'=Progid': S('p')}, '.empty': {}, '.nolist': {'OpenWithList': {}}}),
 ('Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop', rv(('IconLayouts', icons('This PC', 'Recycle Bin', 'd\u00e9j\u00e0')))),
 ('Software\\Microsoft\\Office\\16.0\\Word\\File MRU', OFFICE_VALUES),
 ('Software\\Microsoft\\Office\\16.0\\Word\\User MRU\\ADAL_1\\File MRU', rv(('Item 1', office('C:\\read.docx')))),
 ('Software\\Microsoft\\Office\\16.0\\Word\\User MRU\\ADAL_1\\Place MRU', rv(('Item 1', office('C:\\place')))),
 ('Software\\Microsoft\\Office\\16.0\\Word\\Reading Locations', {'Document 0': rv(('File Path', S('C:\\read.docx'))), 'Document 1': {}}),
 ('Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\t1.docx', trust('0000000001000000')), ('C:\\t2.docm', trust('00000000FFFFFF7F')), ('C:\\t3.docx', trust('0000000002000000')))),
 ('Software\\Microsoft\\Office\\15.0\\Excel\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\e.xlsx', trust('0000000001000000')))),
 ('Software\\Microsoft\\Internet Explorer', {'Suggested Sites': rv(('LogFileFolder', S('C:\\Users\\bob\\AppData')), ('Other', D(1))), 'Main': {}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps', {'{a}': RECENT_APP, '{b}': {**RECENT_APP, 'RecentItems': {}}}),
 ('Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.taskflow.shellactivities\\Current', rv(('Data', taskflow(('C:\\a\\x.txt', 'notepad.exe', ' Title '), ('C:\\b', 'b.exe', None))))),
 (EXPLORER + '\\UserAssist', USERASSIST),
 (EXPLORER + '\\WordWheelQuery', {**rv(('MRUListEx', mru(1, 0)), ('0', B(U('second'))), ('1', B(U('first')))), '{sub}': rv(('MRUListEx', mru(0)), ('0', B(U('subterm')))), 'nomru': rv(('0', B(U('x')))), 'dup': rv(('MRUListEx', mru(1, 1)), ('1', B(U('y')))), 'odd': rv(('MRUListEx', mru(0)), ('name', B(U('y'))), ('0', B(U('z'))))}),
)
BAD_NTUSER = {
 'ares1': tree(('Software\\Ares', rv(('Network.DHTID', S('x')), ('Stats.LstConnect', S('abc')), ('Personal.GUID', S('never'))))),
 'ares2': tree(('Software\\Ares', {'=Personal.GUID': S('g'), 'Search.History': {'abc': {'=' + hexa('t'): S('')}, 'zzzz1': {'=' + hexa('t'): S('')}}})),
 'ares3': tree(('Software\\Ares', rv(('Download.Folder', S('zz')), ('PrivateMessage.AwayMessage', S(ARES_AWAY))))),
 'ares4': tree(('Software\\Ares', rv(('PrivateMessage.AwayMessage', S(ARES_AWAY)), ('Transfer.ServerPort', D(0))))),
 'first1': tree((EXPLORER + '\\ComDlg32\\FirstFolder', rv(('0', B(U('nolist'))))), (EXPLORER + '\\ComDlg32\\LastVisitedMRU', rv(('a', B('nonul'.encode('utf-16-le'))), ('b', B(U('b') + U('c')))))),
 'first2': tree((EXPLORER + '\\ComDlg32\\FirstFolder', rv(('MRUListEx', mru(0)), ('0', B(U('a'))), ('7', B(U('b'))), ('8', B(U('c')))))),
 'first3': tree((EXPLORER + '\\ComDlg32\\FirstFolder', rv(('MRUListEx', B(struct.pack('<i', 0))), ('0', B(U('a')))))),
 'first4': tree((EXPLORER + '\\ComDlg32\\FirstFolder', rv(('MRUListEx', mru(0)), ('0', B(U('a'))), ('nan', B(U('b')))))),
 'icons1': tree(('Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop', rv(('IconLayouts', B(b'\1\2'))))),
 'icons2': tree(('Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop', rv(('IconLayouts', icons('one', count=3))))),
 'icons3': tree(('Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop', rv(('IconLayouts', B(b'\0' * 0x18 + struct.pack('<h', 1) + b'\0' * 6 + struct.pack('<h', 500) + b'\0' * 6))))),
 'apps1': tree(('Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps', {'{a}': RECENT_APP, '{b}': {'=AppId': S('x')}, '{c}': RECENT_APP})),
 'apps2': tree(('Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps', {'{a}': {**RECENT_APP, 'RecentItems': {'bad': {'=DisplayName': S('d')}}}})),
 'task1': tree(('Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.taskflow.shellactivities\\Current', rv(('Data', B(b'\0\1'))))),
 'task2': tree(('Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.taskflow.shellactivities\\Current', rv(('Data', B(taskflow(('C:\\a', 'b', None))[1][:40]))))),
 'trust1': tree(('Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\t.docx', trust('0000000001000000'))))),
 'trust2': tree(('Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\t.docx', trust('0000000001000000')), ('C:\\s', S('zz')))), ('Software\\Microsoft\\Internet Explorer', {'Main': {}})),
 'trust3': tree(('Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\t.docx', trust('0000000001000000')))), ('Software\\Microsoft\\Internet Explorer', {'Suggested Sites': rv(('LogFileFolder', S('nobackslash')))})),
 'trust4': tree(('Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', rv(('C:\\t.docx', B(b'\1\2')))), ('Software\\Microsoft\\Internet Explorer', {})),
}
def props(name=None, times=True):
    p = {}
    if name is not None: p['{540b947e-8b40-45bc-a8a2-6a0b894cbda2}'] = {'0004': rv(('(default)', B(name.encode('utf-16-le'))))}
    if times: p['{83da6326-97a6-4088-9453-a1923f573b29}'] = {'0064': rv(('(default)', B(ftb(1)))), '0065': rv(('(default)', B(ftb(2)))), '0066': rv(('(default)', B(ftb(3)))), '0067': rv(('(default)', B(b'\1\2')))}
    return {'Properties': p}
SYS_MEDIUM = {'ControlSet001': {
 'Control': {'TimeZoneInformation': rv(('TimeZoneKeyName', S('Pacific Standard Time')), ('Bias', D(480)), ('StandardName', S('@tzres.dll,-212')), ('StandardBias', D(0)), ('StandardStart', B(bytes.fromhex('00000A00020017003B003B00E7030600'))), ('DaylightName', S('d')), ('DaylightBias', D(0xFFFFFFC4)), ('DaylightStart', B(bytes.fromhex('00000300020002000000000000000000'))), ('ActiveTimeBias', D(420)), ('Other', D(1)))},
 'Enum': {
  'USB': {'VID_1&PID_2': {'SER1': {**rv(('ParentIdPrefix', S('7&abc')), ('Service', S('USBSTOR')), ('DeviceDesc', S('@usb.inf,%desc%;USB Device')), ('FriendlyName', S('Stick;Friendly')), ('LocationInformation', S('Port_#0001'))), **props('Name')}, 'SER2': {}}, 'empty': {}},
  'USBSTOR': {'Disk&Ven_A&Prod_B&Rev_1': {'SER1&0': {**props('Disk name'), 'Device Parameters': {'Partmgr': rv(('DiskId', S('{d}')))}}, 'SER2&0': {}}, 'Disk&Ven_A': {'x': {}}, 'Disk&Ven_A&Prod_C&Rev_2': {}},
  'SCSI': {'Disk&Ven_V&Prod_P': {'4&1': {**props('Scsi name'), 'Device Parameters': {'Partmgr': rv(('DiskId', S('{s}'))), 'Storport': rv(('InitialTimestamp', B(ftb(9))))}}, '4&2': {}}, 'CdRom&Ven_X&Prod_Y&Rev_1': {'z': {}}},
  'SWD': {'WPDBUSENUM': {'_??_x': {**rv(('Service', S('WUDFWpdFs')), ('DeviceDesc', S('a;b;c')), ('FriendlyName', S('nosemi'))), **props()}, 'bare': {}}, 'empty': {}},
 },
 'Services': {
  'one': {**rv(('Description', S('desc')), ('DisplayName', S('Disp')), ('ServiceDll', S('a.dll')), ('Group', S('g')), ('ImagePath', S('C:\\one.exe')), ('RequiredPrivileges', M('SeA', 'SeB')), ('Type', D(0x110)), ('Start', D(2))), 'parameters': rv(('servicedll', S('b.dll')))},
  'two': rv(('TYPE', D(1)), ('START', D(9)), ('group', S('notexact'))), 'bits': rv(('Type', D(0x200)), ('Start', D(0))), 'combo': rv(('Type', D(0x213))), 'zero': rv(('Type', D(0)), ('Start', D(1))), 'bare': {},
  'Tcpip': {'Parameters': {'Interfaces': {
    '{i1}': {**rv(('DhcpNetworkHint', S(HINT)), ('DhcpDefaultGateway', M('10.0.0.1')), ('DhcpIPAddress', S('10.0.0.5')), ('DhcpServer', S('10.0.0.2')), ('LeaseObtainedTime', D(1600000000)), ('LeaseTerminatesTime', D(1600003600)), ('DhcpDomain', S('corp'))), 'sub1': rv(('DhcpNetworkHint', S(HINT)), ('LeaseObtainedTime', D(1)), ('LeaseTerminatesTime', D(2))), 'sub2': {}},
    '{i2}': rv(('DhcpNetworkHint', S('zz'))), '{i3}': {'a': rv(('DhcpNetworkHint', S(HINT + 'A')), ('LeaseObtainedTime', D(1)), ('LeaseTerminatesTime', D(2)))}}}},
  'SharedAccess': {'Parameters': {'FirewallPolicy': {
    'FirewallRules': rv(('r1', S('v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|Name=Web,Thing|Desc=d=e|App=C:\\a.exe|')), ('r2', S('Action=Block|Protocol=99|RPort=1|RPort=2|XName=odd|EmbedCtxt=x')), ('r3', S('')), ('r4', D(1))),
    'RestrictedServices': {'AppIso': {'FirewallRules': rv(('a', S('Action=Allow|Protocol=17')))}}, 'Mdm': {'FirewallRules': rv(('m', S('Protocol=1')))}}}},
 }}}
SYS_BAD = {'ControlSet001': {
 'Control': {'TimeZoneInformation': rv(('TimeZoneKeyName', S('a')), ('StandardStart', B(b'\1\2\3')), ('Bias', D(5)))},
 'Enum': {'USB': {'a': {'b': props('n') | {'Properties': {'{83da6326-97a6-4088-9453-a1923f573b29}': {'0064': rv(('(default)', B(struct.pack('<q', -1))))}}}}, 'c': {'d': {}}}, 'USBSTOR': {'Disk&A&B&C': {'s': {'Properties': {'{83da6326-97a6-4088-9453-a1923f573b29}': {'0066': rv(('(default)', B(struct.pack('<q', -1))))}}}}}},
 'Services': {'a': rv(('Type', S('x'))), 'b': rv(('Type', D(1))), 'Tcpip': {'Parameters': {'Interfaces': {'{i}': {'a': rv(('DhcpNetworkHint', S('zz')))}}}}}}}
SW_MEDIUM = tree(('Microsoft\\Windows NT\\CurrentVersion\\NetworkList', {
  'Profiles': {'{p1}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('Home')), ('NameType', D(71))), '{p2}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('Lan')), ('NameType', D(6))), '{p3}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('Odd')), ('NameType', D(5))), '{p4}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('None')), ('NameType', D(0))), '{p5}': rv(('DateCreated', B(b'\1\2')), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('x')), ('NameType', D(6))), '{p6}': rv(('DateCreated', B(SYSTIME))), '{p7}': rv(('DateCreated', B(struct.pack('<8h', 2020, 13, 1, 1, 1, 1, 1, 1))), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('x')), ('NameType', D(6)))},
  'Signatures': {'Unmanaged': {'s1': rv(('DefaultGatewayMac', B(b'\0\1\2\3\4\5')), ('DnsSuffix', S('home')), ('ProfileGuid', S('{p1}')), ('FirstNetwork', S('Wifi'))), 's2': rv(('DnsSuffix', S('x')))}, 'Managed': {'s3': rv(('DefaultGatewayMac', B(b'\6\7\x08\x09\x0a\x0b')), ('DnsSuffix', S('corp')), ('ProfileGuid', S('{p2}')), ('FirstNetwork', S('Lan')))}}}))
SW_BAD = {'p1': tree(('Microsoft\\Windows NT\\CurrentVersion\\NetworkList', {'Other': {}})), 'p2': tree(('Microsoft\\Windows NT\\CurrentVersion\\NetworkList', {'Profiles': {'{p}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('H')), ('NameType', D(71)))}})), 'p3': tree(('Microsoft\\Windows NT\\CurrentVersion\\NetworkList', {'Profiles': {'{p}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('H')), ('NameType', D(71)))}, 'Signatures': {}})), 'p4': tree(('Microsoft\\Windows NT\\CurrentVersion\\NetworkList', {'Profiles': {'{p}': rv(('DateCreated', B(SYSTIME)), ('DateLastConnected', B(SYSTIME)), ('ProfileName', S('H')), ('NameType', D(71)))}, 'Signatures': {'Unmanaged': {'s': rv(('DefaultGatewayMac', B(b'\0')), ('DnsSuffix', S('d')), ('ProfileGuid', S('{p}')), ('FirstNetwork', S('F')))}}}))}
def alias(name, comment, *sids):
    body = name.encode('utf-16-le') + comment.encode('utf-16-le')
    members = b''.join(sids)
    h = bytearray(0x34)
    struct.pack_into('<i', h, 0x10, 0); struct.pack_into('<i', h, 0x14, len(name) * 2)
    struct.pack_into('<i', h, 0x1c, len(name) * 2); struct.pack_into('<i', h, 0x20, len(comment) * 2)
    struct.pack_into('<i', h, 0x28, len(body)); struct.pack_into('<i', h, 0x30, len(sids))
    return B(bytes(h) + body + members)
SID1 = bytes.fromhex('01010000000000050b000000'); SID5 = bytes.fromhex('010500000000000515000000') + struct.pack('<4I', 1, 2, 3, 1001)
SAM = tree(('SAM\\Domains\\Builtin\\Aliases', {'00000220': rv(('C', alias('Administrators', 'Admins', SID1, SID5))), '00000221': rv(('C', alias('Users', ''))), 'Names': {'Administrators': {}}, '00000222': rv(('C', B(b'\1\2'))), '00000223': rv(('C', alias('Odd', 'x', b'\2\0\0\0' + b'\0' * 8))), '00000224': rv(('C', alias('Cut', 'x', SID5[:10])))}))
SYSCACHE = tree(('DefaultObjectStore\\ObjectTable', {'1': rv(('_ObjectId_', Q(5)), ('_ObjectLru_', D(6)), ('_FileId_', Q(0x0002000300000007)), ('_Usn_', Q(8)), ('_UsnJournalId_', Q(9)), ('AeFileID', B(U('0000ABCDEF'))), ('AeProgramID', B(U('prog')))), '2': {}, '3': rv(('_FileId_', B(b'\1\2'))), '4': rv(('_ObjectId_', S('x')))}))
EXTRA_HIVES.update({'m_ntuser/NTUSER.DAT': ('ntuser.dat', M_NTUSER), 'm_system/SYSTEM': ('SYSTEM', SYS_MEDIUM), 'm_system_bad/SYSTEM': ('SYSTEM', SYS_BAD), 'm_software/SOFTWARE': ('SOFTWARE', SW_MEDIUM), 'm_sam/SAM': ('SAM', SAM), 'm_syscache/Syscache.hve': ('Syscache.hve', SYSCACHE)})
for k_, v_ in BAD_NTUSER.items(): EXTRA_HIVES[f'm_{k_}/NTUSER.DAT'] = ('ntuser.dat', v_)
for k_, v_ in SW_BAD.items(): EXTRA_HIVES[f'm_sw_{k_}/SOFTWARE'] = ('SOFTWARE', v_)
if SAMPLES:
    def mutated(spec, r):
        out = {}
        for k, v in spec.items():
            if isinstance(v, dict):
                out[k] = mutated(v, r)
            elif k.startswith('=') and r.random() < 0.35:
                kind = r.randrange(5)
                if kind == 0: out[k] = B(bytes(r.randrange(256) for _ in range(r.randint(0, 40))))
                elif kind == 1: out[k] = S(r.choice(['', 'x', '-1', '99999999999', '12', 'zz', 'a;b', 'A|B=C', '[T01D0]*p', 'D:2020']))
                elif kind == 2: out[k] = D(r.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 71, 1 << 20]))
                elif kind == 3 and v[1]: out[k] = (v[0], v[1][:r.randrange(len(v[1]))])
                elif v[1]:
                    b = bytearray(v[1]); b[r.randrange(len(b))] = r.randrange(256); out[k] = (v[0], bytes(b))
                else: out[k] = v
            else:
                out[k] = v
        return out
    for seed in range(1, 41):
        r = random.Random(1000 + seed)
        for name, (internal, spec) in {'nt/NTUSER.DAT': ('ntuser.dat', M_NTUSER), 'sy/SYSTEM': ('SYSTEM', SYS_MEDIUM), 'sw/SOFTWARE': ('SOFTWARE', SW_MEDIUM), 'sa/SAM': ('SAM', SAM), 'sc/Syscache.hve': ('Syscache.hve', SYSCACHE)}.items():
            EXTRA_HIVES[f'md{seed}/{name}'] = (internal, mutated(spec, r))
H_ = {
 'amcache/Amcache.hve': ('Amcache.hve', AMCACHE), 'ntuser/NTUSER.DAT': ('ntuser.dat', NTUSER), 'ntuser_bad/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD),
 'ntuser_bad2/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD2), 'ntuser_bad3/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD3), 'ntuser_bad4/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD4), 'ntuser_bad5/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD5),
 'system/SYSTEM': ('SYSTEM', SYSTEM), 'system_bad/SYSTEM': ('SYSTEM', SYSTEM_BAD), 'software/SOFTWARE': ('SOFTWARE', SOFTWARE), 'software_bad/SOFTWARE': ('SOFTWARE', SOFTWARE_BAD), 'software_bad2/SOFTWARE': ('SOFTWARE', SOFTWARE_BAD2),
 'usrclass/UsrClass.dat': ('UsrClass.dat', USRCLASS), 'usrclass2/UsrClass.dat': ('UsrClass.dat', USRCLASS2),
}
H_.update(EXTRA_HIVES)
for p, (n, s) in H_.items(): write(f'{A}/h/{p}', n, s)
PATHS = [
 ('Amcache', ['Root\\InventoryApplication', 'Root\\InventoryApplicationFile', 'Root\\InventoryApplicationShortcut', 'Root\\InventoryDeviceContainer', 'Root\\InventoryDevicePnp', 'Root\\InventoryDriverBinary', 'Root\\Mare']),
 ('NtUser', [EXPLORER + '\\ComDlg32\\LastVisitedPidlMRU', EXPLORER + '\\ComDlg32\\LastVisitedPidlMRULegacy', EXPLORER + '\\ComDlg32\\OpenSavePidlMRU', (EXPLORER + '\\Taskband', 'Favorites'), EXPLORER + '\\Taskband', EXPLORER + '\\RecentDocs', EXPLORER + '\\RecentDocs\\*', ('Software\\7-Zip\\Compression', 'ArcHistory'), ('Software\\7-Zip\\FM', 'CopyHistory'), ('Software\\7-Zip\\FM', 'FolderHistory'), ('Software\\7-Zip\\Extraction', 'PathHistory'), ('Software\\7-Zip', 'ArcHistory'), 'Software\\7-Zip\\FM', 'Software\\Adobe', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths', 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage', 'Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData', 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', 'Software\\Microsoft\\Terminal Server Client', 'Software\\Microsoft\\Internet Explorer\\TypedURLs', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository', 'Software\\WinRAR']),
 ('System', [('ControlSet00*\\Control\\Session Manager\\AppCompatCache', 'AppCompatCache'), 'ControlSet00*\\Control\\Session Manager\\AppCompatCache', 'ControlSet00*\\Services\\bam\\State\\UserSettings\\*', 'ControlSet00*\\Services\\bam\\UserSettings\\*', 'ControlSet00*\\Services\\dam\\UserSettings\\*', 'ControlSet00*\\Services\\BTHPORT\\Parameters\\Devices', 'ControlSet00*\\Control\\DeviceClasses', ('ControlSet00*\\Control\\Lsa', 'DsrmAdminLogonBehavior'), 'ControlSet00*\\Control\\Lsa', 'ControlSet001\\Control\\WMI\\Autologger\\EventLog-Application', 'ControlSet001\\Control\\WMI\\Autologger\\EventLog-System', 'ControlSet002\\Control\\WMI\\Autologger\\EventLog-Application', 'ControlSet00*\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}', 'ControlSet00*\\Services\\Tcpip\\Parameters\\Interfaces', 'ControlSet00*\\Control\\NetworkSetup2']),
 ('Software', ['Microsoft\\Windows\\CurrentVersion\\App Paths', 'Microsoft\\Windows\\CurrentVersion\\Uninstall', 'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\*\\Products', 'Classes\\Installer\\Products', 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList', 'Microsoft\\RADAR\\HeapLeakDetection', 'WOW6432Node\\Microsoft\\RADAR\\HeapLeakDetection', 'Microsoft\\Windows Search\\VolumeInfoCache', 'Microsoft\\Windows Portable Devices']),
 ('NtUser', ['Software\\Adobe', 'Software\\Ares', EXPLORER + '\\ComDlg32\\CIDSizeMRU', EXPLORER + '\\ComDlg32\\FirstFolder', EXPLORER + '\\ComDlg32\\LastVisitedMRU', EXPLORER + '\\ComDlg32\\OpenSaveMRU', EXPLORER + '\\FileExts', 'Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop', 'Software\\Microsoft\\Office\\*\\*\\File MRU', 'Software\\Microsoft\\Office\\*\\*\\User MRU\\*\\File MRU', 'Software\\Microsoft\\Office\\*\\*\\User MRU\\*\\Place MRU', 'Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords', 'Software\\Microsoft\\Office\\15.0\\Excel\\Security\\Trusted Documents\\TrustRecords', 'Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps', 'Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\Store\\Cache\\DefaultAccount\\$$windows.data.taskflow.shellactivities\\Current', EXPLORER + '\\UserAssist', EXPLORER + '\\UserAssist\\*\\Count', EXPLORER + '\\WordWheelQuery']),
 ('System', ['ControlSet00*\\Control\\TimeZoneInformation', 'ControlSet00*\\Enum\\USB', 'ControlSet00*\\Enum\\USBSTOR', 'ControlSet00*\\Enum\\SCSI', 'ControlSet00*\\Enum\\SWD', 'ControlSet00*\\Services', 'ControlSet00*\\Services\\Tcpip\\Parameters\\Interfaces', 'ControlSet00*\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules', 'ControlSet00*\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules', 'ControlSet00*\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Mdm\\FirewallRules']),
 ('Software', ['Microsoft\\Windows NT\\CurrentVersion\\NetworkList']),
 ('Sam', ['SAM\\Domains\\Builtin\\Aliases']),
 ('Syscache', ['DefaultObjectStore\\ObjectTable']),
 ('UsrClass', ['Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository']),
]
def q(s): return '"' + s.replace('\\', '\\\\') + '"'
with open(f'{A}/plugins.reb', 'w') as f:
    f.write('Description: plugin test\nAuthor: t\nVersion: 1\nId: 11111111-1111-1111-1111-111111111111\nKeys:\n')
    for t, ps in PATHS:
        for p in ps:
            vn = None
            if isinstance(p, tuple): p, vn = p
            f.write(f'    -\n        Description: {t} {q(p)[1:-1].replace(chr(92)*2,"/").replace("{","").replace("}","").replace("*","_")}\n        HiveType: {t}\n        Category: Test\n        KeyPath: {q(p)}\n        Recursive: false\n        Comment: "c"\n')
            if vn: f.write(f'        ValueName: {vn}\n')
    f.write('    -\n        Description: disabled\n        HiveType: NtUser\n        Category: Test\n        KeyPath: Software\\WinRAR\n        DisablePlugin: true\n        Recursive: true\n        Comment: "off"\n')
cases = []
for p in H_:
    full = f'{A}/h/{p}'
    cases.append(f'-f "{full}" --bn {A}/plugins.reb --csv {{out}} --csvf o.csv')
    cases.append(f'-f "{full}" --bn {A}/plugins.reb --json {{out}} --jsonf o.json')
cases.append(f'-f "{A}/h/system/SYSTEM" --bn {A}/plugins.reb --csv {{out}} --csvf o.csv --dt "dd/MM/yyyy HH:mm"')
cases.append(f'-d "{A}/h" --bn {A}/plugins.reb --csv {{out}} --csvf all.csv')
cases.append(f'-d "{A}/h" --bn {A}/plugins.reb --json {{out}} --jsonf all.json')
cases.append(f'-f "{A}/h/system/SYSTEM" --bn {A}/plugins.reb --csv {{out}}')
cases.append(f'-f "{A}/h/ntuser/NTUSER.DAT" --bn {A}/plugins.reb --json {{out}}')
cases.append(f'-f "{A}/h/ntuser/NTUSER.DAT" --bn {A}/plugins.reb --csv {{out}}/new/dir --csvf o.csv')
open(f'{A}/cases', 'w').write('\n'.join(cases) + '\n')
