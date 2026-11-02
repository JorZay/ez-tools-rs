#!/usr/bin/env bash
# Compares this port's output with the original EvtxECmd's, file by file: CSV, JSON and --fj JSON must be identical.
#
#   tools/parity.sh <EvtxECmd.dll> <Maps folder> <folder of .evtx files> [work folder]
#
# The rows are compared in file order (--unsorted), as EvtxECmd writes them. Build the release binary first
# (cargo build --release). EvtxECmd runs with `dotnet`; its own Maps and these must be the same.
set -euo pipefail

dll=$1 maps=$2 logs=$3
work=${4:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/evtxecmd"
mkdir -p "$work/ref" "$work/ours"

same=0 diff=0
while IFS= read -r -d '' f; do
    n=$(basename "$f" .evtx)
    dotnet "$dll" -f "$f" --csv "$work/ref" --csvf "$n.csv" --json "$work/ref" --jsonf "$n.json" --maps "$maps" --co false >/dev/null 2>&1 || true
    dotnet "$dll" -f "$f" --json "$work/ref" --jsonf "$n.fj.json" --fj --maps "$maps" --co false >/dev/null 2>&1 || true
    "$ours" -f "$f" --csv "$work/ours/$n.csv" --json "$work/ours/$n.json" --maps "$maps" --unsorted --keep-identical --no-log -q 2>/dev/null || true
    "$ours" -f "$f" --json "$work/ours/$n.fj.json" --fj --maps "$maps" --unsorted --keep-identical --no-log -q 2>/dev/null || true
    for ext in csv json fj.json; do
        if [ ! -e "$work/ref/$n.$ext" ] && [ ! -e "$work/ours/$n.$ext" ]; then
            continue
        fi
        if cmp -s "$work/ref/$n.$ext" "$work/ours/$n.$ext"; then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $f ($ext): $work/ref/$n.$ext $work/ours/$n.$ext"
        fi
    done
done < <(find "$logs" -type f -iname '*.evtx' -print0 | sort -z)

echo "identical: $same, different: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
