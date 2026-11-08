#!/usr/bin/env bash
# Compares this port's output with the original SumECmd's, run on Windows (it reads with esent.dll and stops on anything else).
# Every CSV each one writes must be identical (file names compared without their time stamp), and so must the exit code.
#
#   tools/parity-sumecmd.sh <results> [work folder] < cases
#
# Each line of `cases` is `name|input folder|arguments`, e.g. `edge|/samples/edge|--wd false` (arguments quoted as in a shell).
# <results>/<name> is the --csv folder of the original's run of that case on Windows, on a copy of the same input folder, and
# <results>/codes.txt has a line `name exit-code` for each. tools/gen-sumecmd-dbs builds test databases on Windows.
set -uo pipefail
. "$(dirname "$0")/platform.sh"

results=$1
work=${2:-$(mktemp -d)}
mkdir -p "$work"
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/sumecmd"
same=0 diff=0

names() { [ -d "$1" ] && (cd "$1" && find . -type f ! -name '*_ConsoleLog.txt' | sed -E 's/[0-9]{14}_//' | LC_ALL=C sort); }
file_of() { find "$1" -type f -name "*_${2#./}" | head -1; }

while IFS='|' read -r name input args; do
    [ -z "$name" ] && continue
    out="$work/$name"
    rm -rf "$out"
    eval "extra=($args)"
    LANG=en_US.UTF-8 TZ=UTC "$ours" -d "$input" --csv "$out" "${extra[@]}" > "$out.log" 2>&1
    code=$?
    ref=$(awk -v n="$name" '$1 == n { print $2 }' "$results/codes.txt" | tr -d '\r')
    ok=1
    if [ "$code" != "$ref" ]; then
        echo "DIFF exit code: $name ($ref vs $code)"
        ok=0
    fi
    if ! cmp -s <(names "$results/$name") <(names "$out"); then
        echo "DIFF file names: $name"
        diff <(names "$results/$name") <(names "$out") | head -10
        ok=0
    else
        while IFS= read -r f; do
            if ! cmp -s "$(file_of "$results/$name" "$f")" "$(file_of "$out" "$f")"; then
                echo "DIFF $name: $f"
                ok=0
            fi
        done < <(names "$out")
    fi
    if [ $ok = 1 ]; then same=$((same + 1)); else diff=$((diff + 1)); fi
done

echo "same: $same, different: $diff (work folder: $work)"
[ $diff = 0 ]
