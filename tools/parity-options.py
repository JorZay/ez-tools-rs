#!/usr/bin/env python3
"""Compares how the original tools and the ports take --dt values and repeated options.

    tools/parity-options.py <reference builds> <inputs> <work folder> [dt|repeat|both] [run ...]

<reference builds> has <Tool>/<Tool>.dll. <inputs> has one small sample of each kind, under the names in RUNS. The work folder is
emptied of each run's output as it goes. Needs dotnet on PATH. What's compared: exit code and output files (with the time and version
in file names masked, and each run's folder name in the contents); for --dt, also the console after the command line.
"""
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# run name: (tool, original's name, the original's arguments, the port's where they differ). {in}, {out} are replaced.
RUNS = {
    "amcacheparser": ("amcacheparser", "AmcacheParser", ["-f", "{in}/Amcache.hve", "-i", "--csv", "{out}/o"]),
    "appcompatcacheparser": ("appcompatcacheparser", "AppCompatCacheParser", ["-f", "{in}/SYSTEM", "--csv", "{out}/o"]),
    "evtxecmd": ("evtxecmd", "EvtxECmd", ["-f", "{in}/small.evtx", "--csv", "{out}/o", "--csvf", "o.csv", "--maps", HERE + "/maps", "--co", "false"],
                 ["-f", "{in}/small.evtx", "--csv", "{out}/o/o.csv", "--maps", HERE + "/maps", "--unsorted", "--keep-identical", "--no-log", "-q"]),
    "jlecmd": ("jlecmd", "JLECmd", ["-f", "{in}/f.automaticDestinations-ms", "--csv", "{out}/o", "--fd"]),
    "lecmd": ("lecmd", "LECmd", ["-f", "{in}/f.lnk", "--csv", "{out}/o"]),
    "mftecmd": ("mftecmd", "MFTECmd", ["-f", "{in}/$MFT", "--csv", "{out}/o"]),
    "mftecmd-usn": ("mftecmd", "MFTECmd", ["-f", "{in}/$J", "--csv", "{out}/o"]),
    "pecmd": ("pecmd", "PECmd", ["-f", "{in}/f.pf", "--csv", "{out}/o"]),
    "rbcmd": ("rbcmd", "RBCmd", ["-d", "{in}/recycle", "--csv", "{out}/o"]),
    "recmd": ("recmd", "RECmd", ["-f", "{in}/NTUSER.DAT", "--bn", "{in}/run.reb", "--csv", "{out}/o", "--nl"]),
    "recmd-search": ("recmd", "RECmd", ["-f", "{in}/NTUSER.DAT", "--sk", "Run", "--nl"]),
    "recmd-key": ("recmd", "RECmd", ["-f", "{in}/NTUSER.DAT", "--kn", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "--details", "--nl"]),
    "jlecmd-custom": ("jlecmd", "JLECmd", ["-f", "{in}/f.customDestinations-ms", "--csv", "{out}/o"]),
    "jlecmd-all": ("jlecmd", "JLECmd", ["-f", "{in}/f.automaticDestinations-ms", "--csv", "{out}/c", "--json", "{out}/j", "--html", "{out}/h", "-q"]),
    "lecmd-all": ("lecmd", "LECmd", ["-f", "{in}/f.lnk", "--csv", "{out}/c", "--json", "{out}/j", "--xml", "{out}/x", "--html", "{out}/h", "-q"]),
    "pecmd-all": ("pecmd", "PECmd", ["-f", "{in}/f.pf", "--csv", "{out}/c", "--json", "{out}/j", "--html", "{out}/h", "-q"]),
    "mftecmd-boot": ("mftecmd", "MFTECmd", ["-f", "{in}/$Boot", "--csv", "{out}/o"]),
    "mftecmd-logfile": ("mftecmd", "MFTECmd", ["-f", "{in}/$LogFile", "--csv", "{out}/o"]),
    "mftecmd-body": ("mftecmd", "MFTECmd", ["-f", "{in}/$MFT", "--body", "{out}/o", "--bdl", "c"]),
    "mftecmd-json": ("mftecmd", "MFTECmd", ["-f", "{in}/$MFT", "--json", "{out}/o"]),
    "mftecmd-record": ("mftecmd", "MFTECmd", ["-f", "{in}/$MFT", "--de", "5"]),
    "rla": ("rla", "rla", ["-f", "{in}/NTUSER.DAT", "--out", "{out}/o"]),
    "sqlecmd": ("sqlecmd", "SQLECmd", ["-f", "{in}/none.db", "--csv", "{out}/o", "--maps", HERE + "/maps-sqlecmd"]),
}
NO_DT = {"rla", "sqlecmd"}
# would download over the reference build's maps
SKIP_OPTIONS = {"--sync", "--help", "-h", "-?", "--version"}

FORMATS = ["", "G", "g", "d", "D", "f", "F", "t", "T", "s", "u", "o", "O", "r", "R", "m", "M", "y", "Y", "U", "x", "%", "%d", "%dd", "ffffffff",
           "yyyy'", "\\", "yyyy\\", "yyyy-MM-dd HH:mm:ss.fffffff", "yyyyy MMMMM dddd HHH tt K zzz g gg", "h:m:s t", "%%", "FFFFFFF",
           "ddd yyyy MM dd", "'lit' yyyy", "FF.FF ff", "dd/MM/yy z zz"]


# The original's log drops each line with such a date, which isn't reproduced: output files and exit codes are compared
BAD_FORMATS = {"U", "x", "%", "ffffffff", "yyyy'", "\\", "yyyy\\", "%%"}


def env():
    e = dict(os.environ, LANG="en_US.UTF-8", TZ="UTC")
    return e


def run(command, cwd):
    os.makedirs(cwd, exist_ok=True)
    try:
        done = subprocess.run(command, cwd=cwd, env=env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    except subprocess.TimeoutExpired:
        return -999, b""
    return done.returncode, done.stdout


def mask_name(path):
    path = re.sub(r"\d{14}", "{time}", path)
    # the XHTML folder: on Linux the original makes folders of the path's separators, the ports underscores as on Windows
    path = re.sub(r"_for_.*/", "_for_/", path)
    path = re.sub(r"_(\d+\.\d+\.\d+)_ConsoleLog", "_{version}_ConsoleLog", path)
    # the same for RECmd's plugin files
    return re.sub(r"_+", "_", path.replace("/", "_"))


def outputs(folder):
    found = {}
    for root, _, names in os.walk(folder):
        for name in names:
            # PECmd's two pictures are written on every system, where the original only writes them on Windows
            if name.endswith(".png"):
                continue
            full = os.path.join(root, name)
            found[mask_name(os.path.relpath(full, folder))] = full
    return found


def mask(data, *folders):
    for folder in folders:
        data = data.replace(folder.encode(), b"{out}")
    return data


def console(data, folder):
    data = mask(data, folder)
    at = data.find(b"Command line:")
    data = data[at:] if at >= 0 else data
    lines = []
    for line in data.split(b"\n")[1:]:
        if re.match(rb"^(   at |--- End of|   --- End of| ---> |[A-Za-z.]*Exception: )", line):
            continue
        line = re.sub(rb"[0-9.,]+ seconds", b"{time} seconds", line)
        line = re.sub(rb"\d{14}", b"{time}", line)
        line = re.sub(rb"_for_\S*?/?index", b"_for_/index", line)
        line = re.sub(rb"_\d+\.\d+\.\d+_ConsoleLog", b"_{version}_ConsoleLog", line)
        lines.append(line.rstrip(b"\r"))
    return lines


def compare(run_name, tool, dll, label, ref_args, our_args, inputs, work, compare_console):
    results = []
    sides = {}
    for side in ("ref", "ours"):
        out = os.path.join(work, f"{run_name}-{abs(hash(label)) % 10 ** 12}-{side}")
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out)
        args = ref_args if side == "ref" else our_args
        final = [a.replace("{in}", inputs).replace("{out}", out) for a in args]
        command = ["dotnet", dll] + final if side == "ref" else [os.path.join(HERE, "target/release", tool)] + final
        code, data = run(command, out)
        sides[side] = (out, code, data)
    (ro, rc, rd), (oo, oc, od) = sides["ref"], sides["ours"]
    if rc != oc:
        results.append(f"exit {rc} vs {oc}")
    rf, of = outputs(ro), outputs(oo)
    if sorted(rf) != sorted(of):
        results.append(f"files {sorted(set(rf) ^ set(of))[:4]}")
    for name in sorted(set(rf) & set(of)):
        if name.endswith("_ConsoleLog.txt"):
            continue
        with open(rf[name], "rb") as a, open(of[name], "rb") as b:
            # InternalId is random in each run of the original
            def clean(data, folder):
                data = re.sub(rb'"?InternalId"?:\s*"?[0-9a-f-]+"?', b"", mask(data, folder))
                # RECmd's batch CSV names its plugins' files
                data = re.sub(rb"(\{time\}_[A-Za-z0-9]+_)/", rb"\1_", re.sub(rb"\d{14}", b"{time}", data))
                # the Linux originals' .NET platform rules, which the ports don't follow (tools/platform.sh)
                return data.replace("\u202f".encode(), b" ").replace(b"\r\n", b"\n")
            if clean(a.read(), ro) != clean(b.read(), oo):
                results.append(f"content {name}")
    if compare_console and not results and console(rd, ro) != console(od, oo):
        results.append("console")
    if results:
        keep = os.path.join(work, "kept", f"{run_name}-{abs(hash(label)) % 10 ** 12}")
        shutil.rmtree(keep, ignore_errors=True)
        os.makedirs(keep)
        for side, (folder, _, data) in sides.items():
            shutil.move(folder, os.path.join(keep, side))
            with open(os.path.join(keep, side + ".log"), "wb") as f:
                f.write(data)
        results.append(f"kept {keep}")
    else:
        for folder, _, _ in sides.values():
            shutil.rmtree(folder, ignore_errors=True)
    return run_name, label, rc, oc, results


def options_of(dll):
    """The original's options, from its help: (name, takes no value)"""
    done = subprocess.run(["dotnet", dll, "--help"], env=env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    found = []
    for line in done.stdout.splitlines():
        m = re.match(r"^  (-[-\w?]+)(, [-\w?, ]+)?( <[^>]+>)?", line)
        if m and m.group(1) not in SKIP_OPTIONS:
            found.append((m.group(1), m.group(3) is None))
    return found


def main():
    refs, inputs, work = [os.path.abspath(a) for a in sys.argv[1:4]]
    mode = sys.argv[4] if len(sys.argv) > 4 else "both"
    only = sys.argv[5:] or list(RUNS)
    jobs = []
    seen = set()
    for run_name in only:
        spec = RUNS[run_name]
        tool, name, ref_base = spec[:3]
        our_base = spec[3] if len(spec) > 3 else ref_base
        dll = os.path.join(refs, name, name + ".dll")
        if mode in ("dt", "both") and tool not in NO_DT:
            for fmt in FORMATS:
                jobs.append((run_name, tool, dll, f"--dt {fmt!r}", ref_base + ["--dt", fmt], our_base + ["--dt", fmt], inputs, work, tool != "evtxecmd" and fmt not in BAD_FORMATS))
        if mode in ("repeat", "both") and tool not in seen:
            seen.add(tool)
            for flag, is_flag in options_of(dll):
                extra = [[flag, flag], [flag, "false"], [flag, "true"], [flag, "False"], [flag, "maybe"], [flag, "false", flag, "false"], [flag, "true", flag]] if is_flag else [[flag, "v", flag, "v"]]
                for e in extra:
                    jobs.append((run_name, tool, dll, " ".join(e), ref_base + e, our_base + e, inputs, work, False))
    same = {}
    bad = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for run_name, label, rc, oc, results in pool.map(lambda j: compare(*j), jobs):
            if results:
                bad.setdefault(run_name, []).append(label)
                print(f"{run_name}: {label}: {'; '.join(results)}", flush=True)
            else:
                same[run_name] = same.get(run_name, 0) + 1
    for run_name in only:
        print(f"== {run_name}: same {same.get(run_name, 0)}, different {len(bad.get(run_name, []))}")


main()
