#!/usr/bin/env bash
# Compares this port's output with the original MFTECmd's: every file each one writes must be identical.
#
#   tools/parity-mftecmd.sh <MFTECmd.dll> [work folder] < cases
#
# Each line of `cases` is a file, a tab, and extra arguments, e.g.
#   /cases/C/$MFT<TAB>--fl --sn --body {out} --bdl c
# {out} is replaced by the output folder. --csv/--csvf (and --json/--jsonf for $MFT, $J and $LogFile) are added.
# .gz files are decompressed first. Build the release binary first (cargo build --release).
set -uo pipefail

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/mftecmd"
same=0 diff=0 n=0

while IFS=$'\t' read -r file extra; do
    [ -z "$file" ] && continue
    n=$((n + 1))
    if [[ "$file" == *.gz ]]; then
        mkdir -p "$work/gz$n"
        plain="$work/gz$n/$(basename "${file%.gz}")"
        gunzip -c "$file" > "$plain"
        file=$plain
    fi
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        args=(-f "$file" --csv "$out" --csvf out.csv --json "$out" --jsonf out.json --co false)
        read -r -a more <<< "${extra//\{out\}/$out}"
        if [ $side = ref ]; then
            dotnet "$dll" "${args[@]}" "${more[@]}" > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" "${more[@]}" > "$out.log" 2>&1
        fi
        echo $? > "$out.exit"
    done
    if ! cmp -s "$work/$n-ref.exit" "$work/$n-ours.exit"; then
        diff=$((diff + 1))
        echo "DIFF exit code: $file $extra ($(cat "$work/$n-ref.exit") vs $(cat "$work/$n-ours.exit"))"
    fi
    for f in $(cd "$work/$n-ref" && find . -type f | sort); do
        if cmp -s "$work/$n-ref/$f" "$work/$n-ours/$f"; then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $file $extra: $f"
        fi
    done
    extra_files=$(cd "$work/$n-ours" && find . -type f | sort | while read -r f; do [ -e "$work/$n-ref/$f" ] || echo "$f"; done)
    [ -n "$extra_files" ] && { diff=$((diff + 1)); echo "EXTRA files from this port for $file: $extra_files"; }
done

echo "identical: $same, different: $diff (outputs in $work)"
[ "$diff" -eq 0 ]
