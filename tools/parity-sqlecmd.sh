#!/usr/bin/env bash
# Compares this port's output with the original SQLECmd's: every file each one writes must be identical, and so must the
# console output after the banner and the exit code (minus timings, stack traces, the output folder's name and time stamps).
#
#   tools/parity-sqlecmd.sh <SQLECmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -d /evidence --maps /maps --csv {out} --json {out}
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added. The original runs with
# LANG=en_US.UTF-8. Blob names only differ in the characters Windows doesn't allow in a file name, which this port replaces as
# Windows does: those are replaced on both sides before comparing. Build the release binary first (cargo build --release -p sqlecmd).
set -uo pipefail
. "$(dirname "$0")/platform.sh"

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/sqlecmd"
same=0 diff=0 n=0

# the file name characters only differ in names of blob files
blob_names() {
    sed -E '/^\tDumping blob from column/{s/[:*?"<>|\\]/_/g; s/_(\/|$)/\1/}; s/\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{20}/{time}/g; s/[0-9]{14}_SQLECmd_/{time}_SQLECmd_/g'
}

console() {
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^System\.' -e '^--- End of' -e 'Loaded SQLite.Interop.dll' -e 'SQLECmd-[0-9a-f]*' |
        sed -E "s#$2#{out}#g; s/^(Processed [0-9,]+ files? in) [0-9.,]+ seconds/\1 {time} seconds/" | blob_names
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
            "$ours" "${args[@]}" --co false --temp "$work/ours-temp" > "$out.log" 2>&1
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
    # files by their names without the time stamp, as the two runs start at different times. Several databases can give the
    # same name: those pair up in the order they were written, which their time stamps give
    names() { (cd "$1" && find . -type f | while IFS= read -r f; do printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{20}/{time}/g; s/[:*?"<>|\\]/_/g')" "$f"; done | LC_ALL=C sort); }
    names "$work/$n-ref" > "$work/$n-ref.names"
    names "$work/$n-ours" > "$work/$n-ours.names"
    if ! cmp -s <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names"); then
        diff=$((diff + 1))
        echo "DIFF file names: $line"
        diff <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names") | head -20
    else
        while IFS=$'\t' read -r name f o; do
            if cmp -s <(sed -E "s#$work/$n-ref#{out}#g" "$work/$n-ref/$f" | platform) <(sed -E "s#$work/$n-ours#{out}#g" "$work/$n-ours/$o" | platform); then
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
