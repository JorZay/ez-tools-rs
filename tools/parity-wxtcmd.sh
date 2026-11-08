#!/usr/bin/env bash
# Compares this port's output with the original WxTCmd's: the exit code and every file each one writes must be the same (the
# CSVs byte for byte, after tools/platform.sh; the console log only by its name).
#
#   tools/parity-wxtcmd.sh <WxTCmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f /evidence/C/Users/x/AppData/Local/ConnectedDevicesPlatform/L.x/ActivitiesCache.db --csv {out}
# (quoted as in a shell). {out} is replaced by the run's output folder. The original runs with LANG=en_US.UTF-8 and TZ=UTC.
# Databases for the edge cases: tools/gen-wxtcmd-dbs.py. Build the release binary first (cargo build --release -p wxtcmd).
set -uo pipefail
. "$(dirname "$0")/platform.sh"

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/wxtcmd"
same=0 diff=0 n=0
mkdir -p "$work"

# Each file: its name without the time stamp and version (the two runs start at different times), a tab, its own name
names() {
    (cd "$1" && find . -type f | while IFS= read -r f; do
        printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{14}_/{time}_/; s/_WxTCmd_[0-9.]+_ConsoleLog/_WxTCmd_{version}_ConsoleLog/')" "$f"
    done | LC_ALL=C sort)
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        rm -rf "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        if [ $side = ref ]; then
            LANG=en_US.UTF-8 TZ=UTC dotnet "$dll" "${args[@]}" > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" > "$out.log" 2>&1
        fi
        echo $? > "$out.exit"
        mkdir -p "$out"
        names "$out" > "$out.names"
    done
    if ! cmp -s "$work/$n-ref.exit" "$work/$n-ours.exit"; then
        diff=$((diff + 1))
        echo "DIFF exit code: $line ($(cat "$work/$n-ref.exit") vs $(cat "$work/$n-ours.exit"))"
    fi
    if ! cmp -s <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names"); then
        diff=$((diff + 1))
        echo "DIFF file names: $line"
        diff <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names") | head -10
        continue
    fi
    while IFS=$'\t' read -r name r o; do
        case "$name" in *_ConsoleLog.txt) continue ;; esac
        if cmp -s <(platform "$work/$n-ref/$r") <(platform "$work/$n-ours/$o"); then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $line: $name"
        fi
    done < <(paste "$work/$n-ref.names" <(cut -f2 "$work/$n-ours.names"))
done

echo "runs: $n, identical files: $same, differences: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
