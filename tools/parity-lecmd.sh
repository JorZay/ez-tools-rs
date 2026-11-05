#!/usr/bin/env bash
# Compares this port's output with the original LECmd's: every file each one writes must be identical, and so must the console
# output after the banner and the exit code (minus timings, stack traces, the output folder's name and time stamps).
#
#   tools/parity-lecmd.sh <LECmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -d /samples --csv {out}/c --json {out}/j --xml {out}/x --html {out}/h
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added. The original runs with
# LANG=en_US.UTF-8. Read the samples once before running, as a read can change their access time (SourceAccessed).
# The XHTML folder's name: on Linux the original makes folders of the path's separators, this port underscores as on Windows.
set -uo pipefail

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/lecmd"
same=0 diff=0 n=0

console() {
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^--- End of' -e '^   --- End of' -e '^ ---> ' -e '^[A-Za-z.]*Exception: ' |
        sed -E "s#$2#{out}#g; s/\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{14}/{time}/g; s/ in [0-9.,]+ seconds/ in {time} seconds/; s#_for_[^ ]*#_for_#"
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        if [ $side = ref ]; then
            LANG=en_US.UTF-8 dotnet "$dll" "${args[@]}" --co false > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" --co false > "$out.log" 2>&1
        fi
        echo $? > "$out.exit"
    done
    if ! cmp -s "$work/$n-ref.exit" "$work/$n-ours.exit"; then
        diff=$((diff + 1))
        echo "DIFF exit code: $line ($(cat "$work/$n-ref.exit") vs $(cat "$work/$n-ours.exit"))"
    fi
    if ! cmp -s <(console "$work/$n-ref.log" "$work/$n-ref") <(console "$work/$n-ours.log" "$work/$n-ours"); then
        diff=$((diff + 1))
        echo "DIFF console: $line"
    fi
    names() { (cd "$1" && find . -type f | while IFS= read -r f; do printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{14}/{time}/g; s#_for_.*/#_for_/#')" "$f"; done | LC_ALL=C sort); }
    names "$work/$n-ref" > "$work/$n-ref.names"
    names "$work/$n-ours" > "$work/$n-ours.names"
    if ! cmp -s <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names"); then
        diff=$((diff + 1))
        echo "DIFF file names: $line"
        diff <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names") | head -20
    else
        while IFS=$'\t' read -r name f o; do
            if cmp -s "$work/$n-ref/$f" "$work/$n-ours/$o"; then
                same=$((same + 1))
            else
                diff=$((diff + 1))
                echo "DIFF $line: $name"
            fi
        done < <(paste "$work/$n-ref.names" <(cut -f2 "$work/$n-ours.names"))
    fi
done

echo "runs: $n, identical files: $same, differences: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
