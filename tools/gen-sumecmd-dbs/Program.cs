// Builds User Access Logging databases with ManagedEsent (esent.dll), with the schema of a real Server 2022 UAL folder, for comparing
// SumECmd with its port. Usage: UalGen <out folder> <case> [page size]. Each case is a folder <out>\<case>[page size]. Windows only:
// dotnet publish -c Release -r win-x64 --self-contained, then run it on Windows. The cases are in Main.
using System.Text;
using Microsoft.Isam.Esent.Interop;
using Microsoft.Isam.Esent.Interop.Windows7;

record Col(string Name, JET_coltyp Type, bool Tagged = false, bool Compressed = false, bool Multi = false);

static class B
{
    public const JET_coltyp Guid16 = (JET_coltyp)16;
    public const JET_coltyp UInt32 = (JET_coltyp)14;
    public const JET_coltyp UInt16 = (JET_coltyp)17;
    public const JET_coltyp Int64 = (JET_coltyp)15;

    public static long FT(int y, int m, int d, int h = 12, int min = 0, int s = 0, int ms = 0) =>
        new DateTime(y, m, d, h, min, s, ms, DateTimeKind.Utc).ToFileTimeUtc() + 1234;

    public static bool Compress;
    public static List<(string Table, string[] Key)> Indexes = new();

    public static void Create(string path, Action<JET_SESID, JET_DBID> fill, bool dirty = false)
    {
        var folder = Path.GetDirectoryName(path);
        var logs = dirty ? folder : Path.Combine(Path.GetTempPath(), $"ualgen-{Guid.NewGuid():N}");
        Directory.CreateDirectory(logs);
        Api.JetCreateInstance(out var instance, $"ualgen-{Guid.NewGuid():N}");
        var p = new InstanceParameters(instance)
        {
            BaseName = "Svc", LogFileDirectory = logs, SystemDirectory = logs, TempDirectory = logs, CreatePathIfNotExist = true,
            NoInformationEvent = true, CircularLog = false
        };
        Api.JetInit(ref instance);
        Api.JetBeginSession(instance, out var sesid, null, null);
        Api.JetCreateDatabase(sesid, path, null, out var dbid, CreateDatabaseGrbit.OverwriteExisting);
        fill(sesid, dbid);
        if (dirty)
        {
            try { Api.JetTerm2(instance, (TermGrbit)0x8); } catch (EsentDirtyShutdownException) { }
            return;
        }
        Api.JetCloseDatabase(sesid, dbid, CloseDatabaseGrbit.None);
        Api.JetDetachDatabase(sesid, path);
        Api.JetEndSession(sesid, EndSessionGrbit.None);
        Api.JetTerm(instance);
        try { Directory.Delete(logs, true); } catch (IOException) { }
    }

    public static void Table(JET_SESID s, JET_DBID db, string name, params Col[] cols)
    {
        Api.JetBeginTransaction(s);
        Api.JetCreateTable(s, db, name, 1, 100, out var table);
        foreach (var c in cols)
        {
            var g = c.Tagged ? ColumndefGrbit.ColumnTagged : ColumndefGrbit.None;
            if (c.Multi) g |= ColumndefGrbit.ColumnMultiValued | ColumndefGrbit.ColumnTagged;
            if (c.Compressed || (Compress && (c.Type == JET_coltyp.LongText || c.Type == JET_coltyp.LongBinary))) g |= Windows7Grbits.ColumnCompressed;
            var def = new JET_COLUMNDEF
            {
                coltyp = c.Type, cp = c.Type == JET_coltyp.LongText || c.Type == JET_coltyp.Text ? JET_CP.Unicode : JET_CP.None, grbit = g
            };
            Api.JetAddColumn(s, table, c.Name, def, null, 0, out _);
        }
        foreach (var (t, key) in Indexes)
        {
            if (t != name) continue;
            var k = string.Join("", key.Select(x => x + "\0")) + "\0";
            Api.JetCreateIndex(s, table, "primary", CreateIndexGrbit.IndexPrimary, k, k.Length, 100);
        }
        Api.JetCloseTable(s, table);
        Api.JetCommitTransaction(s, CommitTransactionGrbit.None);
    }

    /// One row: values by column name; a string is UTF-16, a byte[] is stored as it is, a List is a multi-valued column
    public static void Insert(JET_SESID s, JET_DBID db, string tableName, Dictionary<string, object> values, SetColumnGrbit extra = SetColumnGrbit.None)
    {
        using var table = new Table(s, db, tableName, OpenTableGrbit.None);
        var cols = Api.GetColumnDictionary(s, table);
        Api.JetBeginTransaction(s);
        using (var update = new Update(s, table, JET_prep.Insert))
        {
            foreach (var (name, v) in values)
            {
                if (v == null) continue;
                var col = cols[name];
                if (v is System.Collections.IList list && v is not byte[])
                {
                    var i = 1;
                    foreach (var item in list)
                    {
                        var b = Bytes(item);
                        var sv = new JET_SETINFO { itagSequence = i++ };
                        Api.JetSetColumn(s, table, col, b, b.Length, SetColumnGrbit.None, sv);
                    }
                    continue;
                }
                var bytes = Bytes(v);
                var g = extra;
                if (bytes.Length == 0) g |= SetColumnGrbit.ZeroLength;
                Api.JetSetColumn(s, table, col, bytes, bytes.Length, g, null);
            }
            update.Save();
        }
        Api.JetCommitTransaction(s, CommitTransactionGrbit.None);
    }

    static byte[] Bytes(object v) => v switch
    {
        byte[] b => b,
        string str => Encoding.Unicode.GetBytes(str),
        Guid g => g.ToByteArray(),
        long l => BitConverter.GetBytes(l),
        int i => BitConverter.GetBytes(i),
        uint u => BitConverter.GetBytes(u),
        ushort u => BitConverter.GetBytes(u),
        short sh => BitConverter.GetBytes(sh),
        byte by => new[] { by },
        bool bo => new[] { (byte)(bo ? 1 : 0) },
        _ => throw new ArgumentException(v.GetType().Name)
    };

    public static readonly Col[] SystemIdentityCols =
    {
        new("CreationTime", JET_coltyp.DateTime), new("PhysicalProcessorCount", JET_coltyp.UnsignedByte),
        new("CoresPerPhysicalProcessor", JET_coltyp.UnsignedByte), new("LogicalProcessorsPerPhysicalProcessor", JET_coltyp.UnsignedByte),
        new("MaximumMemory", Int64), new("OSMajor", JET_coltyp.UnsignedByte), new("OSMinor", JET_coltyp.UnsignedByte),
        new("OSBuildNumber", UInt16), new("OSPlatformId", UInt16), new("ServicePackMajor", JET_coltyp.UnsignedByte),
        new("ServicePackMinor", JET_coltyp.UnsignedByte), new("OSSuiteMask", UInt16), new("OSProductType", JET_coltyp.UnsignedByte),
        new("OSCurrentTimeZone", UInt16), new("OSDaylightInEffect", JET_coltyp.Bit),
        new("SystemManufacturer", JET_coltyp.LongText, true), new("SystemProductName", JET_coltyp.LongText, true),
        new("SystemSMBIOSUUID", JET_coltyp.LongText, true), new("SystemSerialNumber", JET_coltyp.LongText, true),
        new("SystemDNSHostName", JET_coltyp.LongText, true), new("SystemDomainName", JET_coltyp.LongText, true),
        new("OSSerialNumber", JET_coltyp.LongText, true), new("OSCountryCode", JET_coltyp.LongText, true),
        new("OSLastBootUpTime", JET_coltyp.LongText, true)
    };

    public static Col[] ClientCols(bool multiDays = false)
    {
        var c = new List<Col>
        {
            new("RoleGuid", Guid16), new("TenantId", Guid16), new("TotalAccesses", UInt32), new("InsertDate", JET_coltyp.DateTime),
            new("LastAccess", JET_coltyp.DateTime), new("Address", JET_coltyp.Binary), new("AuthenticatedUserName", JET_coltyp.LongText, true),
            new("ClientName", JET_coltyp.LongText, true)
        };
        for (var i = 1; i <= 366; i++) c.Add(new($"Day{i}", UInt16, true, false, multiDays && i == 2));
        return c.ToArray();
    }

    public static void SystemIdentity(string path, IEnumerable<(Guid, string)> roles, IEnumerable<(object Year, object File)> chained,
        IEnumerable<Dictionary<string, object>> idents = null, bool dirty = false)
    {
        Create(path, (s, db) =>
        {
            Table(s, db, "SYSTEM_IDENTITY", SystemIdentityCols);
            Table(s, db, "CHAINED_DATABASES", new("Year", UInt16), new("FileName", JET_coltyp.Text));
            Table(s, db, "ROLE_IDS", new("RoleGuid", Guid16), new("ProductName", JET_coltyp.LongText, true), new("RoleName", JET_coltyp.LongText, true));
            foreach (var row in idents ?? new[] { Ident("HOST1") }) Insert(s, db, "SYSTEM_IDENTITY", row);
            foreach (var (g, name) in roles)
                Insert(s, db, "ROLE_IDS", new() { ["RoleGuid"] = g, ["ProductName"] = "0997dbd9-4db4-49aa-8ec5-8f5c6ae1c870\0", ["RoleName"] = name == null ? null : name + "\0" });
            foreach (var (year, file) in chained)
                Insert(s, db, "CHAINED_DATABASES", new() { ["Year"] = year, ["FileName"] = file });
        }, dirty);
    }

    public static Dictionary<string, object> Ident(string host) => new()
    {
        ["CreationTime"] = FT(2020, 9, 17), ["PhysicalProcessorCount"] = (byte)2, ["CoresPerPhysicalProcessor"] = (byte)4,
        ["LogicalProcessorsPerPhysicalProcessor"] = (byte)8, ["MaximumMemory"] = 2147483648L, ["OSMajor"] = (byte)10, ["OSMinor"] = (byte)0,
        ["OSBuildNumber"] = (ushort)40000, ["OSPlatformId"] = (ushort)2, ["ServicePackMajor"] = (byte)0, ["ServicePackMinor"] = (byte)1,
        ["OSSuiteMask"] = (ushort)272, ["OSProductType"] = (byte)3, ["OSCurrentTimeZone"] = unchecked((ushort)(short)-420),
        ["OSDaylightInEffect"] = true, ["SystemManufacturer"] = "VMware, Inc.\0", ["SystemProductName"] = "VMware7,1\0",
        ["SystemSMBIOSUUID"] = "12345678-ABCD-1234-ABCD-123456789ABC\0", ["SystemSerialNumber"] = "VMware-00 11 22\0",
        ["SystemDNSHostName"] = host + "\0\0", ["SystemDomainName"] = "corp.example\0", ["OSSerialNumber"] = "00000-00000-00000-AA000\0",
        ["OSCountryCode"] = "1\0", ["OSLastBootUpTime"] = "20200101000000.500000+060\0"
    };

    public static Dictionary<string, object> Client(Guid role, string user, int year, Dictionary<int, ushort> days = null, uint total = 5,
        object address = null, string clientName = null, long? insert = null, long? last = null, Guid? tenant = null)
    {
        var d = new Dictionary<string, object>
        {
            ["RoleGuid"] = role, ["TenantId"] = tenant ?? Guid.Empty, ["TotalAccesses"] = total, ["InsertDate"] = insert ?? FT(year, 1, 2),
            ["LastAccess"] = last ?? FT(year, 3, 4), ["Address"] = address ?? new byte[] { 10, 0, 0, 5 }, ["AuthenticatedUserName"] = user,
            ["ClientName"] = clientName
        };
        foreach (var (k, v) in days ?? new()) d[$"Day{k}"] = v;
        return d;
    }

    public static void Ual(string path, IEnumerable<Dictionary<string, object>> clients, IEnumerable<Dictionary<string, object>> dns = null,
        IEnumerable<Dictionary<string, object>> roles = null, IEnumerable<Dictionary<string, object>> vms = null, bool dirty = false,
        bool multiDays = false, SetColumnGrbit extra = SetColumnGrbit.None)
    {
        Create(path, (s, db) =>
        {
            Table(s, db, "ROLE_ACCESS", new("RoleGuid", Guid16), new("FirstSeen", JET_coltyp.DateTime), new("LastSeen", JET_coltyp.DateTime));
            Table(s, db, "CLIENTS", ClientCols(multiDays));
            Table(s, db, "DNS", new("LastSeen", JET_coltyp.DateTime), new("Address", JET_coltyp.LongText, true), new("HostName", JET_coltyp.LongText, true));
            Table(s, db, "VIRTUALMACHINES", new("VmGuid", Guid16), new("BIOSGuid", Guid16), new("CreationTime", JET_coltyp.DateTime),
                new("LastSeenActive", JET_coltyp.DateTime), new("SerialNumber", JET_coltyp.LongText, true));
            foreach (var c in clients) Insert(s, db, "CLIENTS", c, extra);
            foreach (var c in dns ?? Array.Empty<Dictionary<string, object>>()) Insert(s, db, "DNS", c, extra);
            foreach (var c in roles ?? Array.Empty<Dictionary<string, object>>()) Insert(s, db, "ROLE_ACCESS", c);
            foreach (var c in vms ?? Array.Empty<Dictionary<string, object>>()) Insert(s, db, "VIRTUALMACHINES", c, extra);
        }, dirty);
    }

    public static Dictionary<string, object> Dns(string address, string host, long seen) => new() { ["Address"] = address, ["HostName"] = host, ["LastSeen"] = seen };
    public static Dictionary<string, object> Role(Guid g, long first, long last) => new() { ["RoleGuid"] = g, ["FirstSeen"] = first, ["LastSeen"] = last };
    public static Dictionary<string, object> Vm(Guid vm, Guid bios, long created, long seen, string serial) =>
        new() { ["VmGuid"] = vm, ["BIOSGuid"] = bios, ["CreationTime"] = created, ["LastSeenActive"] = seen, ["SerialNumber"] = serial };
}

static class Program
{
    static readonly Guid FileServer = Guid.Parse("10a9226f-50ee-49d8-a393-9a501d47ce04");
    static readonly Guid WebServer = Guid.Parse("d6256cf7-98fb-4eb4-aa18-303f1da1f770");
    static readonly Guid Unknown = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    const string Chained = "{9D2CCF2E-F5C3-47F3-9BFA-49937CC468C0}.mdb";
    const string Chained2 = "{66766B00-E4FD-4C31-90F0-5F3EEFEAEA20}.mdb";

    static string _dir;
    static string P(string n) => Path.Combine(_dir, n);

    static void Standard(bool dirtyCurrent = false)
    {
        B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server"), (WebServer, "Web Server") }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
        B.Ual(P("Current.mdb"), new[]
        {
            B.Client(FileServer, "CORP\\alice", 2020, new() { [1] = 3, [60] = 40000, [366] = 1 }),
            B.Client(WebServer, "CORP\\bob", 2020, address: Enumerable.Range(1, 16).Select(i => (byte)i).ToArray())
        }, new[] { B.Dns("10.0.0.5", "pc1.corp.example", B.FT(2020, 3, 1)) }, new[] { B.Role(FileServer, B.FT(2020, 1, 1), B.FT(2020, 3, 4)) }, dirty: dirtyCurrent);
        B.Ual(P(Chained), new[] { B.Client(FileServer, "CORP\\carol", 2019, new() { [32] = 7 }) });
    }

    static IEnumerable<Dictionary<string, object>> Many(int n, int year, int seed)
    {
        var r = new Random(seed);
        var roles = new[] { FileServer, WebServer, Unknown };
        for (var i = 0; i < n; i++)
        {
            var days = new Dictionary<int, ushort>();
            var count = r.Next(0, 3) == 0 ? 366 : r.Next(0, 40);
            for (var k = 0; k < count; k++) days[r.Next(1, 367)] = (ushort)r.Next(0, 65536);
            object addr = r.Next(0, 2) == 0 ? new[] { (byte)10, (byte)r.Next(256), (byte)r.Next(256), (byte)r.Next(256) } : Enumerable.Range(0, 16).Select(_ => (byte)r.Next(256)).ToArray();
            yield return B.Client(roles[r.Next(3)], $"DOM\\user{r.Next(100000)}{(r.Next(5) == 0 ? "$" : "")}", year, days, (uint)r.Next(), addr,
                r.Next(3) == 0 ? $"pc-{i}" : null, B.FT(year, 1, 1, r.Next(24), r.Next(60), r.Next(60), r.Next(1000)), B.FT(year, r.Next(1, 13), r.Next(1, 29), r.Next(24), r.Next(60)),
                r.Next(2) == 0 ? Guid.Empty : new Guid(r.Next(), (short)r.Next(), (short)r.Next(), 1, 2, 3, 4, 5, 6, 7, 8));
        }
    }

    static IEnumerable<Dictionary<string, object>> ManyDns(int n, int year, int seed)
    {
        var r = new Random(seed);
        for (var i = 0; i < n; i++)
            yield return B.Dns($"10.{r.Next(256)}.{r.Next(256)}.{r.Next(256)}", $"host{r.Next(100000)}.corp.example", B.FT(year, r.Next(1, 13), r.Next(1, 29), r.Next(24), r.Next(60), r.Next(60), r.Next(1000)));
    }

    static void Main(string[] args)
    {
        var root = args[0];
        var name = args[1];
        if (args.Length > 2) SystemParameters.DatabasePageSize = int.Parse(args[2]);
        _dir = Path.Combine(root, name + (args.Length > 2 ? args[2] : ""));
        if (Directory.Exists(_dir)) Directory.Delete(_dir, true);
        Directory.CreateDirectory(_dir);
        switch (name)
        {
            case "clean":
                Standard();
                break;
            case "dirty":
                Standard(true);
                break;
            case "dirtynologs":
                Standard(true);
                foreach (var f in Directory.GetFiles(_dir).Where(f => !f.EndsWith(".mdb", StringComparison.OrdinalIgnoreCase))) File.Delete(f);
                break;
            case "nosysident":
                Standard();
                File.Delete(P("SystemIdentity.mdb"));
                break;
            case "badcurrent":
                Standard();
                File.WriteAllBytes(P("Current.mdb"), Enumerable.Repeat((byte)0x41, 64 * 1024).ToArray());
                break;
            case "badvalues":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, Array.Empty<(object, object)>());
                B.Ual(P("Current.mdb"), new[]
                {
                    B.Client(FileServer, "CORP\\bad", 2021, total: 3_000_000_000, insert: -5, last: long.MaxValue),
                    B.Client(FileServer, "CORP\\good", 2021),
                    // a FILETIME of 0 (1601) and the largest a DateTime holds
                    B.Client(WebServer, "CORP\\edge", 2021, insert: 0, last: DateTime.MaxValue.ToFileTimeUtc()),
                    B.Client(WebServer, "CORP\\toolarge", 2021, insert: DateTime.MaxValue.ToFileTimeUtc() + 1, last: B.FT(2021, 5, 5))
                }, new[] { B.Dns("x", "bad.time", -1), B.Dns(null, null, 0) }, new[] { B.Role(WebServer, long.MinValue, 0) },
                    new[] { B.Vm(Guid.NewGuid(), Guid.Empty, long.MaxValue, B.FT(2021, 1, 1), null) });
                break;
            case "edge":
            {
                var roles = new[] { (FileServer, "File Server"), (WebServer, "Web, \"Server\""), (FileServer, "File Server again"), (Unknown, (string)null) };
                var idents = new[]
                {
                    B.Ident("HOST1"),
                    new Dictionary<string, object> { ["CreationTime"] = B.FT(2021, 2, 3) },
                    new Dictionary<string, object> { ["OSMajor"] = (byte)255, ["OSBuildNumber"] = (ushort)65535, ["OSCurrentTimeZone"] = (ushort)32768, ["OSDaylightInEffect"] = false,
                        ["MaximumMemory"] = long.MinValue, ["SystemDNSHostName"] = " spaced ", ["SystemDomainName"] = "line\r\nbreak", ["SystemManufacturer"] = "",
                        ["OSCountryCode"] = new byte[] { 0x41, 0, 0x42 }, ["SystemSerialNumber"] = new byte[] { 0x00, 0xD8, 0x41, 0x00 }, ["OSSerialNumber"] = "\0\0" }
                };
                B.SystemIdentity(P("SystemIdentity.mdb"), roles, new (object, object)[]
                {
                    ((ushort)2016, Chained.ToLowerInvariant() + "\0"), ((ushort)2016, Chained + "\0"), (null, "{11111111-1111-1111-1111-111111111111}.mdb\0"),
                    ((ushort)2017, null), ((ushort)2018, "\0"), ((ushort)2017, "{22222222-2222-2222-2222-222222222222}.mdb\0")
                }, idents);
                B.Ual(P("Current.mdb"), new[]
                {
                    B.Client(FileServer, "CORP\\alice", 2020, new() { [1] = 3, [59] = 1, [60] = 40000, [365] = 2, [366] = 1 }, clientName: "pc,1"),
                    B.Client(Unknown, "quote\"d", 2020, address: new byte[11], clientName: "\0"),
                    B.Client(WebServer, " lead", 2020, address: new byte[0], clientName: "é ü 日本"),
                    B.Client(Guid.Empty, null, 2020, address: new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }),
                    B.Client(FileServer, "CORP\\second", 2020, new() { [100] = 0 }, address: new byte[] { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
                    B.Client(WebServer, "multi\nline", 2020),
                }, new[] { B.Dns("10.0.0.5", "pc1.corp.example", B.FT(2020, 3, 1)), B.Dns("fe80::1", "", B.FT(2020, 12, 31, 23, 59, 59, 999)) },
                    new[] { B.Role(FileServer, B.FT(2020, 1, 1), B.FT(2020, 3, 4)), B.Role(Guid.Empty, 0, 0), B.Role(Unknown, B.FT(2020, 1, 1), B.FT(2020, 1, 2)) },
                    new[] { B.Vm(Guid.Parse("11111111-2222-3333-4444-555555555555"), Guid.Parse("66666666-7777-8888-9999-000000000000"), B.FT(2019, 5, 5), B.FT(2020, 6, 6), "VM serial, 1") });
                // 2016 is a leap year: day 60 is February 29th, day 366 December 31st
                B.Ual(P(Chained), new[] { B.Client(FileServer, "CORP\\carol", 2016, new() { [60] = 7, [366] = 9 }) },
                    roles: new[] { B.Role(WebServer, B.FT(2016, 1, 1), B.FT(2016, 12, 31)) });
                // not listed, and listed under another name
                B.Ual(P("{33333333-3333-3333-3333-333333333333}.mdb"), new[] { B.Client(WebServer, "CORP\\dave", 2015, new() { [365] = 1, [366] = 2 }) });
                B.Ual(P("other.MDB"), Array.Empty<Dictionary<string, object>>(), ManyDns(3, 2014, 1));
                File.WriteAllText(P("notes.txt"), "x");
                break;
            }
            case "big":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server"), (WebServer, "Web Server") }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
                B.Ual(P("Current.mdb"), Many(6000, 2020, 1), ManyDns(5000, 2020, 2), new[] { B.Role(FileServer, B.FT(2020, 1, 1), B.FT(2020, 3, 4)) });
                B.Ual(P(Chained), Many(3000, 2019, 3), ManyDns(2000, 2019, 4));
                break;
            case "pk":
                B.Indexes.Add(("CLIENTS", new[] { "-AuthenticatedUserName", "+RoleGuid" }));
                B.Indexes.Add(("DNS", new[] { "+HostName", "-LastSeen" }));
                B.Indexes.Add(("ROLE_IDS", new[] { "+RoleGuid" }));
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (WebServer, "Web Server"), (FileServer, "File Server") }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
                B.Ual(P("Current.mdb"), Many(800, 2020, 5), ManyDns(700, 2020, 6));
                break;
            case "lv":
            {
                var longName = string.Concat(Enumerable.Range(0, 3000).Select(i => (char)('a' + i % 26)));
                var huge = string.Concat(Enumerable.Range(0, 60000).Select(i => (char)(0x4e00 + i % 500)));
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, longName) }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
                B.Ual(P("Current.mdb"), new[]
                {
                    B.Client(FileServer, longName, 2020, new() { [1] = 1 }, clientName: huge),
                    B.Client(FileServer, "short", 2020, clientName: "x"),
                    B.Client(WebServer, "DOM\\" + longName.Substring(0, 300), 2020, clientName: longName.Substring(0, 1100) + "\0"),
                }, new[] { B.Dns("10.0.0.1", huge.Substring(0, 9000), B.FT(2020, 1, 1)) },
                    vms: new[] { B.Vm(Guid.NewGuid(), Guid.NewGuid(), B.FT(2020, 1, 1), B.FT(2020, 1, 1), longName) });
                // every long text value stored apart from its record
                B.Ual(P(Chained), Many(50, 2019, 7), ManyDns(30, 2019, 8), extra: SetColumnGrbit.SeparateLV);
                break;
            }
            case "comp":
            {
                B.Compress = true;
                var ascii = string.Concat(Enumerable.Range(0, 200).Select(i => (char)('a' + i % 26)));
                var text = string.Concat(Enumerable.Range(0, 5000).Select(i => "lorem ipsum dolor "[i % 18]));
                var uni = string.Concat(Enumerable.Range(0, 3000).Select(i => (char)(0x4e00 + i % 7)));
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server Role Name " + ascii) }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
                B.Ual(P("Current.mdb"), new[]
                {
                    B.Client(FileServer, "DOM\\" + ascii, 2020, clientName: text),
                    B.Client(FileServer, "DOM\\é" + ascii, 2020, clientName: uni),
                    B.Client(WebServer, "DOM\\abcdefghij", 2020, clientName: "abcdefghijklmnopqrstuvwxyz0123456789"),
                    B.Client(WebServer, "DOM\\x", 2020, clientName: text.Substring(0, 900)),
                }, new[] { B.Dns("10.0.0.1", text.Substring(0, 3000), B.FT(2020, 1, 1)), B.Dns("10.0.0.2", ascii, B.FT(2020, 1, 2)) });
                B.Ual(P(Chained), Many(300, 2019, 9), ManyDns(300, 2019, 10));
                break;
            }
            case "multi":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, Array.Empty<(object, object)>());
                B.Ual(P("Current.mdb"), new[]
                {
                    new Dictionary<string, object>(B.Client(FileServer, "two days", 2020, new() { [1] = 5 })) { ["Day2"] = new List<ushort> { 7, 8 } },
                    B.Client(FileServer, "one", 2020, new() { [2] = 4 })
                }, multiDays: true);
                break;
            case "badyear0":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, new (object, object)[] { ((ushort)0, Chained + "\0") });
                B.Ual(P("Current.mdb"), new[] { B.Client(FileServer, "a", 2020) });
                B.Ual(P(Chained), new[] { B.Client(FileServer, "b", 2019) });
                break;
            case "badyear":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, new (object, object)[] { ((ushort)10000, Chained + "\0") });
                B.Ual(P("Current.mdb"), new[] { B.Client(FileServer, "a", 2020) });
                B.Ual(P(Chained), new[] { B.Client(FileServer, "b", 2019) });
                break;
            case "year9999":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, Array.Empty<(object, object)>());
                B.Ual(P("Current.mdb"), new[] { B.Client(FileServer, "a", 9999, new() { [366] = 1 }, last: B.FT(9999, 12, 31)) });
                break;
            case "nextyear":
                // no times in Current.mdb: the year after the newest chained database
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server") }, new (object, object)[] { ((ushort)2019, Chained + "\0"), ((ushort)2021, Chained2 + "\0") });
                B.Ual(P("Current.mdb"), new[] { B.Client(FileServer, "a", 2020, new() { [3] = 3 }, insert: 0, last: 0) });
                B.Ual(P(Chained2), new[] { B.Client(FileServer, "b", 2021, new() { [366] = 1 }) });
                break;
            case "empty":
                B.SystemIdentity(P("SystemIdentity.mdb"), Array.Empty<(Guid, string)>(), Array.Empty<(object, object)>(), Array.Empty<Dictionary<string, object>>());
                B.Create(P("Current.mdb"), (s, db) => B.Table(s, db, "OTHER", new Col("x", B.UInt16)));
                break;
            case "casing":
                Standard();
                File.Move(P("Current.mdb"), P("current.MDB"));
                File.Move(P("SystemIdentity.mdb"), P("SYSTEMIDENTITY.mdb"));
                File.Move(P(Chained), P(Chained.ToLowerInvariant().Replace(".mdb", ".Mdb")));
                break;
            case "onlycurrent":
                B.Ual(P("Current.mdb"), new[] { B.Client(FileServer, "a", 2020, new() { [3] = 3 }, insert: 0, last: 0) });
                break;
            case "page":
                B.SystemIdentity(P("SystemIdentity.mdb"), new[] { (FileServer, "File Server"), (WebServer, "Web Server") }, new (object, object)[] { ((ushort)2019, Chained + "\0") });
                B.Ual(P("Current.mdb"), Many(1500, 2020, 11), ManyDns(1000, 2020, 12), new[] { B.Role(FileServer, B.FT(2020, 1, 1), B.FT(2020, 3, 4)) });
                B.Ual(P(Chained), Many(200, 2019, 13), ManyDns(100, 2019, 14), extra: SetColumnGrbit.SeparateLV);
                break;
            default:
                throw new ArgumentException(name);
        }
    }
}
