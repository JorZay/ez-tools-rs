#!/usr/bin/env python3
"""Makes ActivitiesCache.db files for comparing WxTCmd ports with the original: every value shape the original reads (payload
JSON, AppId JSON, clipboard payloads, content URIs, times, numbers and GUIDs of each SQLite type, NULLs, damaged JSON) and
databases of other shapes (old and odd schemas, missing tables, WAL and journal files, damage, not a database).

    tools/gen-wxtcmd-dbs.py <output folder> [sample database for the damaged copies]

Each database is in its own folder, <output>/<case>/Users/user/L.user/ActivitiesCache.db (so the CSV names get _user), except
the cases about the user name in the path.
"""
import os
import random
import shutil
import sqlite3
import struct
import sys
import uuid

SCHEMA = (
    "CREATE TABLE [Activity]([Id] GUID PRIMARY KEY NOT NULL, [AppId] TEXT NOT NULL, [PackageIdHash] TEXT, [AppActivityId] TEXT, [ActivityType] INT NOT NULL, [ActivityStatus] INT NOT NULL, [ParentActivityId] GUID, [Tag] TEXT, [Group] TEXT, [MatchId] TEXT, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME, [Payload] BLOB, [Priority] INT, [IsLocalOnly] INT, [PlatformDeviceId] TEXT, [DdsDeviceId] TEXT, [CreatedInCloud] DATETIME, [StartTime] DATETIME, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME, [GroupAppActivityId] TEXT, [ClipboardPayload] BLOB, [EnterpriseId] TEXT, [OriginalPayload] BLOB, [UserActionState] INT,[IsRead] INT,[OriginalLastModifiedOnClient] DATETIME, [GroupItems] TEXT, [LocalExpirationTime] DATETIME, [ETag] INT NOT NULL);"
    "CREATE TABLE [ActivityOperation]([OperationOrder] INTEGER PRIMARY KEY ASC NOT NULL, [Id] GUID NOT NULL, [OperationType] INT NOT NULL, [AppId] TEXT NOT NULL, [PackageIdHash] TEXT, [AppActivityId] TEXT, [ActivityType] INT NOT NULL, [ParentActivityId] GUID, [Tag] TEXT, [Group] TEXT, [MatchId] TEXT, [LastModifiedTime] DATETIME NOT NULL, [ExpirationTime] DATETIME, [Payload] BLOB, [Priority] INT, [CreatedTime] DATETIME, [OperationExpirationTime] DATETIME,[PlatformDeviceId] TEXT, [DdsDeviceId] TEXT, [CreatedInCloud] DATETIME, [StartTime] DATETIME NOT NULL, [EndTime] DATETIME, [LastModifiedOnClient] DATETIME NOT NULL, [CorrelationVector] TEXT, [GroupAppActivityId] TEXT, [ClipboardPayload] BLOB, [EnterpriseId] TEXT, [UserActionState] INT,[IsRead] INT,[OriginalPayload] BLOB, [OriginalLastModifiedOnClient] DATETIME, [UploadAllowedByPolicy] INT NOT NULL DEFAULT 1, [PatchFields] BLOB, [GroupItems] TEXT, [ThrottleReleaseTime] DATETIME, [ETag] INT NOT NULL);"
    "CREATE TABLE [Activity_PackageId]([ActivityId] GUID NOT NULL, [Platform] TEXT NOT NULL COLLATE NOCASE, [PackageName] TEXT NOT NULL COLLATE NOCASE, [ExpirationTime] DATETIME NOT NULL);"
)

# the same tables with no declared types and no constraints: any value of any type goes in as it is
LOOSE = (
    "CREATE TABLE Activity(Id, AppId, PackageIdHash, AppActivityId, ActivityType, ActivityStatus, LastModifiedTime, ExpirationTime, Payload, IsLocalOnly, PlatformDeviceId, CreatedInCloud, StartTime, EndTime, LastModifiedOnClient, ClipboardPayload, OriginalLastModifiedOnClient, ETag);"
    "CREATE TABLE ActivityOperation(OperationOrder, Id, OperationType, AppId, PackageIdHash, AppActivityId, ActivityType, LastModifiedTime, ExpirationTime, Payload, CreatedTime, OperationExpirationTime, PlatformDeviceId, StartTime, EndTime, LastModifiedOnClient, ClipboardPayload, ETag);"
    "CREATE TABLE Activity_PackageId(ActivityId, Platform, PackageName, ExpirationTime);"
)

APP_ID = '[{"application":"{6D809377-6AF0-444B-8957-A3773F02200E}\\\\Notepad++\\\\notepad++.exe","platform":"windows_win32"},{"application":"","platform":"packageId"}]'
PAYLOAD = b'{"displayText":"notepad++.exe","activationUri":"ms-shellactivity:","appDisplayName":"Notepad++","backgroundColor":"black"}'

counter = 0


def gid():
    global counter
    counter += 1
    return uuid.UUID(int=0x1234_5678_9ABC_DEF0_0000_0000_0000_0000 + counter).bytes_le


def activity(**values):
    row = {"Id": gid(), "AppId": APP_ID, "ActivityType": 5, "ActivityStatus": 1, "LastModifiedTime": 1646000000, "StartTime": 1646000000,
           "EndTime": 0, "ExpirationTime": 1648592000, "ETag": 1, "AppActivityId": "ECB32AF3-1440-4086-94E3-5311F97F89C4", "Payload": PAYLOAD}
    row.update(values)
    return row


def operation(order, **values):
    row = activity(**values)
    del row["ActivityStatus"]
    row.setdefault("OperationOrder", order)
    row.setdefault("OperationType", 1)
    row.setdefault("LastModifiedOnClient", 1646000000)
    row.setdefault("CreatedTime", 1646000100)
    return row


def package(**values):
    row = {"ActivityId": gid(), "Platform": "windows_win32", "PackageName": "notepad.exe", "ExpirationTime": 1648592000}
    row.update(values)
    return row


def insert(db, table, rows):
    for row in rows:
        cols = list(row)
        db.execute(f"INSERT INTO [{table}] ({','.join('[' + c + ']' for c in cols)}) VALUES ({','.join('?' * len(cols))})", [row[c] for c in cols])


def make(path, activities=(), operations=(), packages=(), schema=SCHEMA, journal=None, pragmas=()):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path)
    for p in pragmas:
        db.execute(p)
    if journal:
        db.execute(f"PRAGMA journal_mode={journal}")
    db.executescript(schema)
    insert(db, "Activity", activities)
    insert(db, "ActivityOperation", operations)
    insert(db, "Activity_PackageId", packages)
    db.commit()
    db.close()


def b64(data):
    import base64
    return base64.b64encode(data).decode()


def clip(*pairs):
    """A clipboard payload of one entry with these properties"""
    import json
    return json.dumps([dict(pairs)]).encode()


# Payloads: JSON shapes, odd JSON, and what isn't JSON
PAYLOADS = [
    None, b"", b"binary\x00\x01", "text payload", b"{", b"{}", b"[]", b" {}", b"\t{}", b"{ }  ", b'{"displayText":"a"} x', b'{"displayText":"a"}\n',
    b'{"displayText":"plain"}', b'{"DISPLAYTEXT":"upper","APPDISPLAYNAME":"App","DESCRIPTION":"d"}',
    b'{"displayText":"first","displayText":"second"}', b'{"displayText":5,"description":true,"contentUri":null}',
    b'{"displayText":{"a" : [1, 2]},"description":[ 1 ,2 ]}', b'{"displayText":null,"description":"d"}', b'{"displayText":"x","description":null,"contentUri":"file:///C:/a"}',
    b'{"displayText":"t","appDisplayName":"","description":"d"}', b'{"appDisplayName":"App","contentUri":"c"}',
    b'{"displayText":"t","appDisplayName":"App"}', b'{"description":"only"}', b'{"contentUri":""}', b'{"contentUri":"","description":""}',
    b'{"displayText":"esc \\" \\\\ \\/ \\b \\f \\n \\r \\t \\u00e9 \\u20ac \\ud83d\\ude00 end"}',
    b'{"displayText":"lone \\ud800 surrogate"}', b'{"displayText":"lone \\udc00 low"}', b'{"userTimezone":"tz","displayText":"\\ud800","devicePlatform":"p"}',
    b'{"x\\ud800":1,"displayText":"after bad name"}', b'{"displayText":"before bad name","x\\ud800":1}',
    b'{"displayText":"trailing comma",}', b'{"displayText":"comment"/* c */}', b'{"displayText":\'single\'}', b'{displayText:"unquoted"}',
    b'{"displayText":01}', b'{"displayText":1.}', b'{"displayText":-}', b'{"displayText":1e5,"description":-0.5E-3}', b'{"displayText":NaN}',
    b'{"displayText":tru}', b'{"displayText":"ctl \x01 char"}', b'{"displayText":"tab \t char"}', b'{"displayText":"del \x7f char"}',
    b'{"displayText":"bad \\x escape"}', b'{"displayText":"short \\u12 escape"}', b'{"displayText":"upper \\U0041"}',
    b'{"displayText":"\xc3\xa9 utf8 \xe2\x82\xac"}', b'{"displayText":"bad utf8 \xff\xfe \xc3 end"}', b'{"displayText":"\xed\xa0\x80 cesu"}',
    b'\xef\xbb\xbf{"displayText":"bom"}', '\u00ad{"displayText":"soft hyphen"}'.encode(), b'\x00{"displayText":"nul"}', '\u200b{"displayText":"zwsp"}'.encode(),
    '\u200d{"displayText":"zwj"}'.encode(), '{\u0301"displayText":"acute"}'.encode(), b'{\x00"displayText":"nul after"}', '\uff5b"displayText":"fullwidth"}'.encode(),
    b'{"a":' + b'[' * 63 + b']' * 63 + b',"displayText":"depth 64"}', b'{"a":' + b'[' * 64 + b']' * 64 + b',"displayText":"depth 65"}',
    b'{"displayText":"commas, and \\"quotes\\"","description":" lead space","contentUri":"trail space "}',
    b'{"displayText":"line\\r\\nbreak","description":"d\\nx"}', b'{"displayText":"\\u0000nul"}',
    b'{"userTimezone":"America/Los_Angeles","devicePlatform":"Windows","displayText":"all","appDisplayName":"App","description":"desc","contentUri":"file:///C:/x"}',
    b'{"userTimezone":7,"devicePlatform":false}', b'{"d\xc4\xb1splayText":"dotless i"}', b'{"di\xc5\xbfplayText":"long s"}', b'{"\\u0064isplayText":"escaped name"}',
    b'{"displayText":"x"} {"y":1}', b'{"displayText":"\\ud83d\\ude00 pair"}', b'  ', b'{"displayText":"' + b'x' * 5000 + b'"}',
]

URIS = [
    "file:///C:/temp/a%20b.txt?VolumeId={A78E0A99-2928-4625-90CF-E0B88E88439B}&ObjectId={1147D6EA-BCAE-41CB-A7E1-5A41C07250FE}",
    "file:{374DE290-123F-4565-9164-39C4925E467B}\\a.zip", "file:///{374DE290-123F-4565-9164-39C4925E467B}\\a.zip", "file://{374DE290-123F-4565-9164-39C4925E467B}\\a.zip",
    "file:{374de290-123f-4565-9164-39c4925e467b}\\lower.zip", "FILE:{374DE290-123F-4565-9164-39C4925E467B}\\upper", "file:{00000000-0000-0000-0000-00000000ABCD}\\a.zip",
    "file:{------------------------------------}", "file:{374DE290-123F-4565-9164-39C4925E467B}", "file:{374DE290-123F-4565-9164-39C4925E467B}x\ny\n",
    "file:%7B374DE290-123F-4565-9164-39C4925E467B%7D\\enc.zip", "a+b%2Bc", "%", "%4", "%41", "%zz%41", "%C3%A9 %E2%82%AC", "%C3 bad %FF", "%E2%82", "\u00e9%41\u00e9", "%F0%9F%98%80",
    "{", "", "x%2", "100%", "%%41", "https://example.com/a?b=c&d=%20e", "file:{374DE290-123F-4565-9164-39C4925E467B\\no close",
]

APP_IDS = [
    APP_ID, '[{"application":"Microsoft.Windows.Explorer","platform":"windows_universal"},{"application":"x","platform":"host"}]', '[{"application":"a","platform":"host"}]',
    '[{"application":"{00000000-0000-0000-0000-00000000ABCD}\\\\a.exe","platform":"x_exe_path"}]', "[]", "{}", "not json", "", '"string"', "5", "[1,2,null]",
    '[{"platform":"windows_win32"},{"application":"b","platform":"windows_universal"}]', '[{"application":"u","platform":"windows_universal"},{"application":"w","platform":"WINDOWS_WIN32"}]',
    '[{"application":5,"platform":"windows_win32"}]', '[{"application":{"x":1},"platform":"x"}]', '[{"application":null,"platform":"windows_win32"},{"application":"z","platform":"windows_win32"}]',
    '[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\\\notepad.exe","platform":"x_exe_path"},{"application":"y","platform":"windows_win32"}]',
    '[{"application":"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}\\\\lower.exe","platform":"windows_win32"}]', '[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}","platform":"windows_win32"}]',
    '[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}/fwd/slash.exe","platform":"windows_win32"}]', '[{"application":"1AC14E77-02E7-4E5D-B744-2EB1AE5198B7\\\\nobrace.exe","platform":"windows_win32"}]',
    '[{"application":"{ 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\\\sp.exe","platform":"windows_win32"}]', '[{"application":"{1AC14E7702E74E5DB7442EB1AE5198B7}\\\\n.exe","platform":"windows_win32"}]',
    '[{"application":"\\ud800","platform":"windows_win32"}]', '[{"platform":"\\ud800","application":"bad platform"}]', '[{"application":"a","platform":"host"}', '  [ {"application" : "spaced", "platform":"host"} ]  ',
    '[{"APPLICATION":"upper keys","PLATFORM":"Windows_Win32"}]', '[[{"application":"nested"}], {"application":"second","platform":"x"}]', '[{"application":"{CF4B8A6A-1F4E-4C5C-BE87-6F6D1F2B6E6D}\\\\fam.exe","platform":"x_exe_path"}]',
]

CLIPS = [
    clip(("content", b64(b"hello")), ("formatName", "Text")), clip(("content", b64(b"hello"))), clip(("content", b64(b"hello")), ("formatName", "Text")),
    clip(("content", b64(b"hello")), ("formatName", "Text")) [:-1] + b',{"content":"d29ybGQ=","formatName":"UnicodeText"}]', clip(("content", "/9j/4AAQ"), ("formatName", "Bitmap")),
    clip(("content", "/9j/4AAQ"), ("formatName", "Text")), clip(("content", "not base64!"), ("formatName", "Text")), b'[1, "x", null]', b"", b"binary", b"[",
    b'[{"content": 5', b'[{"content":5,"formatName":"Text"}]', b'[{"content":"aGVsbG8=","formatName":5}]', b'[{"content":"aGVsbG8=","formatName":null}]',
    b'[{"content":"aGVsbG8=","formatName":"text/plain"}]', b'[{"content":"aGVsbG8=","formatName":"TEXT"}]', b'[{"content":"aGVsbG8=","formatName":""}]',
    b'[{"content":"aGVsbG9=","formatName":"Text"}]', b'[{"content":"aGVsbG8","formatName":"Text"}]', b'[{"content":"aGVs bG8=","formatName":"Text"}]',
    b'[{"content":" aGVs\\r\\nbG8=\\t","formatName":"Text"}]', b'[{"content":"   ","formatName":"Text"}]', b'[{"content":"","formatName":"Text"}]', b'[{"content":"aGk=","formatName":"Text"},{"content":" ","formatName":"Text"}]',
    b'[{"content":"aGVsbG8==","formatName":"Text"}]', b'[{"content":"aGVsbA==","formatName":"Text"}]', b'[{"content":"aGVsbB==","formatName":"Text"}]', b'[{"content":"aG=sbG8=","formatName":"Text"}]',
    b'[{"content":"aGVsbG8=aGk=","formatName":"Text"}]', b'[{"content":"aGVsbG8-","formatName":"Text"}]', b'[{"content":"aGVsbG8_","formatName":"Text"}]', b'[{"content":"YQ","formatName":"Text"}]',
    b'[{"content":"YQ=","formatName":"Text"}]', b'[{"content":"Y===","formatName":"Text"}]', b'[{"content":"====","formatName":"Text"}]', b'[{"content":"\\u0061GVsbG8=","formatName":"Text"}]',
    clip(("content", b64("t\u00e9xt \u20ac".encode())), ("formatName", "Text")), clip(("content", b64(b"nul\x00\x00\x00")), ("formatName", "Text")), clip(("content", b64(b"\x00\x00")), ("formatName", "Text")),
    clip(("content", b64(b"\xef\xbb\xbfbom")), ("formatName", "Text")), clip(("content", b64(b"\xed\xa0\x80")), ("formatName", "Text")), clip(("content", b64(b"a\x00b\x00")), ("formatName", "Text")),
    clip(("content", b64(b"line,\r\n\"q\"")), ("formatName", "Text")), b'  [{"content":"aGk=","formatName":"Text"}]', '\u00a0[{"content":"aGk=","formatName":"Text"}]'.encode(),
    '\u00ad[{"content":"aGk=","formatName":"Text"}]'.encode(), b'{"content":"aGk="}', b'[{"content":"aGk=","formatName":"Text"}] x', b'[{"CONTENT":"aGk=","FORMATNAME":"text"}]',
    b'[{"content":"\\ud800","formatName":"Text"}]', b'[{"formatName":"\\ud800","content":"aGk="}]', b'[{"content":"aGk=","formatName":"Text"},{"content":"\\ud800","formatName":"Text"}]',
    "[" + ",".join('{"content":"aGk=","formatName":"Text"}' for _ in range(3)) + "]", '[{"content":"aGk="}]',
]

TIMES = [None, 0, 1, -1, 1646000000, -62135596800, -62135596801, 253402300799, 253402300800, 9223372036854775807, -9223372036854775808, 1.6e9, 0.5, -0.5, 1646000000.9,
         1e300, -1e300, 9.3e18, "1646000000", " 1646000000 ", "+1646000000", "-5", "1646000000\x00", "1646000000\x00x", "abc", "", "1.5", "0x10", "\u0661\u0662", b"\x01\x02", b"",
         "\t1646000000\n", "1646000000 \x00"]

INTS = [None, 0, 2, 5, 6, 10, 16, 11, -1, 2147483647, 2147483648, -2147483649, "5", " 6 ", "+10", "x", 5.0, 5.5, b"\x05", "", "16\x00"]

GUIDS = [uuid.UUID("9d499512-8396-4125-f391-d0bb75ee3be4").bytes_le, b"\x01\x02\x03", b"", b"\x00" * 15, b"\xff" * 17, "text-id", 12345, -1.5, 1e20, 0.1, None, "\u00e9,\"x\"", b"\x00" * 16]

STRINGS = [None, "", "plain", "with,comma", 'with "quote"', "line\nbreak", "cr\rret", " lead", "trail ", "\ttab", "nul\x00inside", "\u00e9\u20ac\U0001F600", b"blob utf8 \xc3\xa9", b"\xff\xfe bad",
           42, -7, 1.5, 1e20, 1e15, 1e-5, 0.0001, -0.0, 123456789012345680.0, 3.4e-300, float("inf"), float("-inf")]


def value_rows():
    rows = []
    for p in PAYLOADS:
        rows.append(activity(Payload=p))
    for u in URIS:
        import json
        rows.append(activity(Payload=json.dumps({"displayText": "uri", "description": "desc", "contentUri": u}).encode()))
    for a in APP_IDS:
        rows.append(activity(AppId=a))
    for c in CLIPS:
        rows.append(activity(ClipboardPayload=c, ActivityType=10))
    for i, t in enumerate(TIMES):
        rows.append(activity(StartTime=t, EndTime=t, LastModifiedTime=t))
        rows.append(activity(ExpirationTime=t, CreatedInCloud=t, LastModifiedOnClient=t, OriginalLastModifiedOnClient=t))
    for n in INTS:
        rows.append(activity(ActivityType=n, ETag=n, IsLocalOnly=n))
    for g in GUIDS:
        rows.append(activity(Id=g))
    for s in STRINGS:
        rows.append(activity(PackageIdHash=s, PlatformDeviceId=s, AppActivityId=s, ClipboardPayload=s, AppId=s))
    # durations
    for start, end in [(1646000000, 1646000065), (1646000000, 1646000000), (1646000000, 1645000000), (1646000000, 1646200000), (1646000000, 86400), (1646000000, 31536000),
                       (1646000000, 31536001 + 86400 * 365), (None, 1646000000), (1646000000, None), (0, 1646000000), (-62135596800, 253402300799), (253402300799, -62135596800)]:
        rows.append(activity(StartTime=start, EndTime=end))
    return rows


def operation_rows():
    rows = []
    import json
    order = 0
    for p in PAYLOADS[:40] + [json.dumps({"description": "d", "contentUri": u}).encode() for u in URIS[:8]]:
        order += 1
        rows.append(operation(order, Payload=p))
    for a in APP_IDS:
        order += 1
        rows.append(operation(order, AppId=a))
    for c in CLIPS[:20]:
        order += 1
        rows.append(operation(order, ClipboardPayload=c))
    for t in TIMES:
        order += 1
        rows.append(operation(order, StartTime=t, EndTime=t, CreatedTime=t, OperationExpirationTime=t, LastModifiedOnClient=t))
    for n in INTS:
        order += 1
        rows.append(operation(order, OperationType=n, ActivityType=n, ETag=n))
    for g in GUIDS:
        order += 1
        rows.append(operation(order, Id=g))
    for s in STRINGS:
        order += 1
        rows.append(operation(order, PlatformDeviceId=s, AppActivityId=s, AppId=s))
    return rows


def package_rows():
    rows = []
    for platform in ["windows_win32", "x_exe_path", "packageId", "PACKAGEID", "Windows_Win32", "windows_universal", "host", "", None, 5, b"x_exe_path", "x_exe_path "]:
        rows.append(package(Platform=platform))
    for name in ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe", "{6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe", "{00000000-0000-0000-0000-00000000ABCD}\\x.exe",
                 "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\NOTEPAD.EXE", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\a.exe.txt", "C:\\Windows\\x.exe", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}.exe",
                 "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}\\lower.exe", "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "Microsoft.Windows.Explorer", "", None, 7, b"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\blob.exe",
                 "{CF4B8A6A-1F4E-4C5C-BE87-6F6D1F2B6E6D}\\fam.exe", "x.exe,\"q\""]:
        rows.append(package(PackageName=name))
    for t in TIMES:
        rows.append(package(ExpirationTime=t))
    for g in GUIDS:
        rows.append(package(ActivityId=g))
    return rows


def main():
    out = sys.argv[1]
    sample = sys.argv[2] if len(sys.argv) > 2 else None
    def path(case, user="user", folder=None):
        return os.path.join(out, case, "Users", user, folder or f"L.{user}", "ActivitiesCache.db")

    make(path("values"), value_rows(), operation_rows(), package_rows(), schema=LOOSE)
    make(path("typed"), [activity(), activity(EndTime=1646000065), activity(StartTime="1646000000", Payload="text payload")], [operation(1), operation(2, EndTime=1646000065)], [package(), package(Platform="x_exe_path")])
    make(path("activity-only"), [activity()], schema=SCHEMA.split(";")[0])
    make(path("operations-only"), (), [operation(1)], schema=SCHEMA.split(";")[1])
    make(path("packages-only"), (), (), [package()], schema=SCHEMA.split(";")[2])
    make(path("empty-tables"))
    make(path("other-db"), schema="CREATE TABLE t(a);")
    make(path("lower-names"), [activity()], [operation(1)], [package()], schema=LOOSE.replace("TABLE Activity(", "TABLE activity(").replace("TABLE ActivityOperation(", "TABLE ACTIVITYOPERATION(").replace("Activity_PackageId(", "activity_packageid("))
    # columns missing, in other cases, and extra
    make(path("few-columns"), schema="CREATE TABLE Activity(ID, appid, PAYLOAD, Extra); CREATE TABLE ActivityOperation(Id); CREATE TABLE Activity_PackageId(Other);")
    db = sqlite3.connect(path("few-columns"))
    db.execute("INSERT INTO Activity VALUES (?, ?, ?, ?)", (gid(), APP_ID, PAYLOAD, "x"))
    db.execute("INSERT INTO ActivityOperation VALUES (?)", (gid(),))
    db.execute("INSERT INTO Activity_PackageId VALUES (1)")
    db.commit()
    db.close()
    make(path("views"), [activity()], schema=SCHEMA + "CREATE VIEW v AS SELECT * FROM Activity;", pragmas=())
    db = sqlite3.connect(path("views"))
    db.executescript("ALTER TABLE ActivityOperation RENAME TO ActivityOperationOld; CREATE VIEW ActivityOperation AS SELECT * FROM ActivityOperationOld;")
    db.close()
    # rows in rowid order, not in insertion order
    make(path("rowid-order"), schema=SCHEMA)
    db = sqlite3.connect(path("rowid-order"))
    for rowid in [5, 1, 3]:
        db.execute("INSERT INTO Activity (rowid, Id, AppId, ActivityType, ActivityStatus, LastModifiedTime, ETag, Payload) VALUES (?, ?, ?, 5, 1, ?, 1, ?)", (rowid, gid(), APP_ID, 1646000000 + rowid, PAYLOAD))
    db.commit()
    db.close()
    make(path("utf16"), [activity(Payload='{"displayText":"\u00e9 utf16"}', AppId='[{"application":"\u00e9","platform":"host"}]')], pragmas=("PRAGMA encoding='UTF-16le'",))
    make(path("utf16be"), [activity(PackageIdHash="be \u20ac")], pragmas=("PRAGMA encoding='UTF-16be'",))
    # every row only in the WAL, as some Windows 11 databases have it
    wal = path("wal-only")
    os.makedirs(os.path.dirname(wal), exist_ok=True)
    db = sqlite3.connect(wal)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.executescript(SCHEMA)
    insert(db, "Activity", [activity(), activity()])
    insert(db, "Activity_PackageId", [package()])
    db.commit()
    shutil.copy(wal, wal + ".keep")
    shutil.copy(wal + "-wal", wal + "-wal.keep")
    db.close()
    os.replace(wal + ".keep", wal)
    os.replace(wal + "-wal.keep", wal + "-wal")
    # a hot journal: the copy is rolled back to before the last transaction
    hot = path("hot-journal")
    make(hot, [activity()])
    db = sqlite3.connect(hot)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("BEGIN")
    db.execute("PRAGMA cache_size=1")
    insert(db, "Activity", [activity(Payload=b'{"displayText":"x' + b"y" * 3000 + b'"}') for _ in range(30)])
    shutil.copy(hot, hot + ".keep")
    shutil.copy(hot + "-journal", hot + "-journal.keep")
    db.rollback()
    db.close()
    os.replace(hot + ".keep", hot)
    os.replace(hot + "-journal.keep", hot + "-journal")
    # not a database, empty, truncated
    os.makedirs(os.path.dirname(path("not-db")), exist_ok=True)
    with open(path("not-db"), "wb") as f:
        f.write(bytes(i % 256 for i in range(8192)))
    os.makedirs(os.path.dirname(path("empty-file")), exist_ok=True)
    open(path("empty-file"), "wb").close()
    os.makedirs(os.path.dirname(path("short-file")), exist_ok=True)
    with open(path("short-file"), "wb") as f:
        f.write(b"SQLite format 3\x00")
    big = path("truncated")
    make(big, [activity(Payload=b'{"displayText":"' + b"x" * 900 + b'"}') for _ in range(400)])
    with open(big, "rb") as f:
        data = f.read()
    with open(big, "wb") as f:
        f.write(data[: len(data) // 2])
    make(path("bad-header"), [activity()])
    with open(path("bad-header"), "r+b") as f:
        f.seek(16)
        f.write(struct.pack(">H", 3))  # a page size that isn't a power of two
    make(path("bad-schema"), [activity()])
    db = sqlite3.connect(path("bad-schema"))
    db.execute("PRAGMA writable_schema=ON")
    db.execute("UPDATE sqlite_master SET sql = 'CREATE TABLE Activity_PackageId(x' WHERE name = 'Activity_PackageId'")
    db.commit()
    db.close()
    # the user name in the path
    make(path("user-plain", "jane.doe", "L.jane.doe"), [activity()])
    make(os.path.join(out, "user-twice", "Users", "first", "x", "Users", "second", "ActivitiesCache.db"), [activity()])
    make(os.path.join(out, "user-lower", "users", "lower", "ActivitiesCache.db"), [activity()])
    make(os.path.join(out, "user-none", "nobody", "ActivitiesCache.db"), [activity()])
    make(os.path.join(out, "user-long-s", "U\u017fers", "longs", "ActivitiesCache.db"), [activity()])
    make(os.path.join(out, "user-comma", "Users", "a,b c", "ActivitiesCache.db"), [activity()])
    make(os.path.join(out, "user-end", "Users", "ActivitiesCache.db"), [activity()])
    # damaged copies of a sample
    if sample:
        with open(sample, "rb") as f:
            original = f.read()
        rnd = random.Random(1234)
        for n in range(40):
            data = bytearray(original)
            for i in range(rnd.randint(1, 200)):
                data[rnd.randrange(0 if i % 10 == 0 else 100, len(data))] = rnd.randrange(256)
            p = path(f"damaged{n:02}")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)


if __name__ == "__main__":
    main()
