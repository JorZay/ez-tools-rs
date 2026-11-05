"""Hives for the RECmd plugins: every plugin's key, with normal, missing, odd and damaged values, and a batch file for them."""
#   python3 tools/gen-recmd-plugin-hives.py <work folder> <a raw AppCompatCache value, e.g. upstream's Win10Creators.bin>
# writes <work folder>/h (the hives), plugins.reb and cases, for tools/parity-recmd.sh
import os, struct, sys
A, ACC = sys.argv[1], sys.argv[2]
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
H_ = {
 'amcache/Amcache.hve': ('Amcache.hve', AMCACHE), 'ntuser/NTUSER.DAT': ('ntuser.dat', NTUSER), 'ntuser_bad/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD),
 'ntuser_bad2/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD2), 'ntuser_bad3/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD3), 'ntuser_bad4/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD4), 'ntuser_bad5/NTUSER.DAT': ('ntuser.dat', NTUSER_BAD5),
 'system/SYSTEM': ('SYSTEM', SYSTEM), 'system_bad/SYSTEM': ('SYSTEM', SYSTEM_BAD), 'software/SOFTWARE': ('SOFTWARE', SOFTWARE), 'software_bad/SOFTWARE': ('SOFTWARE', SOFTWARE_BAD), 'software_bad2/SOFTWARE': ('SOFTWARE', SOFTWARE_BAD2),
 'usrclass/UsrClass.dat': ('UsrClass.dat', USRCLASS), 'usrclass2/UsrClass.dat': ('UsrClass.dat', USRCLASS2),
}
for p, (n, s) in H_.items(): write(f'{A}/h/{p}', n, s)
PATHS = [
 ('Amcache', ['Root\\InventoryApplication', 'Root\\InventoryApplicationFile', 'Root\\InventoryApplicationShortcut', 'Root\\InventoryDeviceContainer', 'Root\\InventoryDevicePnp', 'Root\\InventoryDriverBinary', 'Root\\Mare']),
 ('NtUser', [('Software\\7-Zip\\Compression', 'ArcHistory'), ('Software\\7-Zip\\FM', 'CopyHistory'), ('Software\\7-Zip\\FM', 'FolderHistory'), ('Software\\7-Zip\\Extraction', 'PathHistory'), ('Software\\7-Zip', 'ArcHistory'), 'Software\\7-Zip\\FM', 'Software\\Adobe', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths', 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage', 'Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData', 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', 'Software\\Microsoft\\Terminal Server Client', 'Software\\Microsoft\\Internet Explorer\\TypedURLs', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository', 'Software\\WinRAR']),
 ('System', [('ControlSet00*\\Control\\Session Manager\\AppCompatCache', 'AppCompatCache'), 'ControlSet00*\\Control\\Session Manager\\AppCompatCache', 'ControlSet00*\\Services\\bam\\State\\UserSettings\\*', 'ControlSet00*\\Services\\bam\\UserSettings\\*', 'ControlSet00*\\Services\\dam\\UserSettings\\*', 'ControlSet00*\\Services\\BTHPORT\\Parameters\\Devices', 'ControlSet00*\\Control\\DeviceClasses', ('ControlSet00*\\Control\\Lsa', 'DsrmAdminLogonBehavior'), 'ControlSet00*\\Control\\Lsa', 'ControlSet001\\Control\\WMI\\Autologger\\EventLog-Application', 'ControlSet001\\Control\\WMI\\Autologger\\EventLog-System', 'ControlSet002\\Control\\WMI\\Autologger\\EventLog-Application', 'ControlSet00*\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}', 'ControlSet00*\\Services\\Tcpip\\Parameters\\Interfaces', 'ControlSet00*\\Control\\NetworkSetup2']),
 ('Software', ['Microsoft\\Windows\\CurrentVersion\\App Paths', 'Microsoft\\Windows\\CurrentVersion\\Uninstall', 'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\*\\Products', 'Classes\\Installer\\Products', 'Microsoft\\Windows NT\\CurrentVersion\\ProfileList', 'Microsoft\\RADAR\\HeapLeakDetection', 'WOW6432Node\\Microsoft\\RADAR\\HeapLeakDetection', 'Microsoft\\Windows Search\\VolumeInfoCache', 'Microsoft\\Windows Portable Devices']),
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
