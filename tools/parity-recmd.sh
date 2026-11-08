#!/usr/bin/env bash
# Compares this port's output with the original RECmd's: every file each one writes must be identical, and so must
# the console output after the banner (minus timings, exception stack traces, the output folder's name and the run's time stamp).
#
#   tools/parity-recmd.sh <RECmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f "/hives/UsrClass 1.dat" --bn DFIRBatch.reb --csv {out} --csvf out.csv
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added. A -d folder should only hold
# hives with names ending in a hive's name, and no links to folders: elsewhere this port finds what the original's Windows build
# finds, not what its Linux one does. The original runs with LANG=en_US.UTF-8 (the
# culture this port writes dates and numbers in). Give the original a Plugins folder created in NTFS order (docs/plans/recmd.md): it runs plugins in folder order. Build the release binary first (cargo build --release).
set -uo pipefail
. "$(dirname "$0")/platform.sh"

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/recmd"
same=0 diff=0 n=0

console() {
    # after the banner and the command line; without timings, stack traces, the folder name and the run's time stamp
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 | grep -a -v -e '^Total search time' -e '^   at ' -e '^System\.' -e '^--- End of' -e '^Searching .* for hives' |
        sed -E "s#$2#{out}#g; s/[0-9]{14}/{time}/g"
}

# An output file without the folder's name and the run's time stamp (plugin rows name their detail file). Plugin files
# on Linux: the original makes a folder of the hive's path separator, this port an underscore as on Windows
masked() {
    sed -E "s#$2#{out}#g; s/[0-9]{14}/{time}/g; s#(\{time\}_[A-Za-z0-9]+_)/#\1_#g" "$1"
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
    # files by their names without the time stamp, as the two runs start at different times
    names() { (cd "$1" && find . -type f | while IFS= read -r f; do printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{14}/{time}/g; s#_/#__#')" "$f"; done | sort); }
    names "$work/$n-ref" > "$work/$n-ref.names"
    names "$work/$n-ours" > "$work/$n-ours.names"
    while IFS=$'\t' read -r name f; do
        o=$(awk -F'\t' -v n="$name" '$1 == n { print $2 }' "$work/$n-ours.names")
        if [ -z "$o" ]; then
            diff=$((diff + 1))
            echo "MISSING from this port for $line: $name"
        elif cmp -s <(masked "$work/$n-ref/$f" "$work/$n-ref" | platform) <(masked "$work/$n-ours/$o" "$work/$n-ours" | platform); then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $line: $name"
        fi
    done < "$work/$n-ref.names"
    extra=$(cut -f1 "$work/$n-ours.names" | while IFS= read -r name; do grep -qF -- "$name	" "$work/$n-ref.names" || echo "$name"; done)
    [ -n "$extra" ] && { diff=$((diff + 1)); echo "EXTRA files from this port for $line: $extra"; }
done

echo "runs: $n, identical files: $same, differences: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
