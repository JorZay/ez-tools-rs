#!/usr/bin/env bash
# Compares this port's output with the original RECmd's: every file each one writes must be identical, and so must
# the console output after the banner (minus timings, exception stack traces and the output folder's name).
#
#   tools/parity-recmd.sh <RECmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f "/hives/UsrClass 1.dat" --bn DFIRBatch.reb --csv {out} --csvf out.csv
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added. The original runs with LANG=en_GB.UTF-8, this
# port's default; PARITY_EN_US=1 compares en-US instead, with --en-us on this port's side. Build the release binary first (cargo build --release).
set -uo pipefail

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/recmd"
same=0 diff=0 n=0
ref_lang=en_GB.UTF-8 ours_flags=()
if [ "${PARITY_EN_US:-}" = 1 ]; then
    ref_lang=en_US.UTF-8 ours_flags=(--en-us)
fi

console() {
    # after the banner and the command line; without timings, stack traces and the folder name
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 | grep -a -v -e '^Total search time' -e '^   at ' -e '^System\.' -e '^--- End of' |
        sed "s#$2#{out}#g"
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        if [ $side = ref ]; then
            LANG=$ref_lang dotnet "$dll" "${args[@]}" --co false > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" "${ours_flags[@]}" --co false > "$out.log" 2>&1
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
    for f in $(cd "$work/$n-ref" && find . -type f | sort); do
        if cmp -s "$work/$n-ref/$f" "$work/$n-ours/$f"; then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $line: $f"
        fi
    done
    extra=$(cd "$work/$n-ours" && find . -type f | sort | while read -r f; do [ -e "$work/$n-ref/$f" ] || echo "$f"; done)
    [ -n "$extra" ] && { diff=$((diff + 1)); echo "EXTRA files from this port for $line: $extra"; }
done

echo "runs: $n, identical files: $same, differences: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
