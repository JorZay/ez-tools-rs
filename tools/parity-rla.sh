#!/usr/bin/env bash
# Compares this port's output with the original rla's: every file each one writes must be identical (names under --out
# and bytes), and so must the exit code and the console after the banner (minus the time taken, exception stack traces and the
# output folder's name; console differences are shown but counted apart, as only the relevant information has to match).
#
#   tools/parity-rla.sh <rla.dll> < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f "/hives/SYSTEM" --out {out}/o --nop
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added unless the line has --co.
# A console log's name and time stamps are masked. Lines with -d differ on purpose where a file's name only holds a
# hive's name (docs/plans/recmd.md). Build the release binary first (cargo build --release). The outputs are deleted at the end, as
# they hold copies of the data; PARITY_KEEP=1 keeps them, to look at a difference.
set -uo pipefail

dll=$1
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/rla"
work=$(mktemp -d)
[ -n "${PARITY_KEEP:-}" ] && echo "outputs in $work" || trap 'rm -rf "$work"' EXIT
same=0 diff=0 console_diff=0 n=0 replayed=0

console() {
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^System\.' -e '^--- End of' -e '^Total processing time' -e '^Console log: ' \
            -e '^Creating --out directory' -e 'contains files! This may cause --cn' -e '^Searching .* for hives' -e 'does not have a hive' |
        sed -e "s#$2#{out}#g"
}

# the saved files: name under the run's folder and hash; console logs by their masked contents
tree() {
    (cd "$1" && find . -type f ! -name '*_ConsoleLog.txt' -print0 | sort -z | xargs -0 -r sha256sum)
    (cd "$1" && find . -type f -name '*_ConsoleLog.txt' | sed -E 's/[0-9]{14}_rla_[0-9.]+_/{stamp}_rla_/' | sort)
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        case "$line" in *--co*) ;; *) args+=(--co false) ;; esac
        if [ $side = ref ]; then
            LANG=en_US.UTF-8 dotnet "$dll" "${args[@]}" > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" > "$out.log" 2>&1
        fi
        echo $? > "$out.code"
        tree "$out" | sed -e "s#$n-$side#{run}#g" > "$out.tree"
    done
    if cmp -s "$work/$n-ref.tree" "$work/$n-ours.tree" && cmp -s "$work/$n-ref.code" "$work/$n-ours.code"; then
        same=$((same + 1))
        if ! diff -a <(console "$work/$n-ref.log" "$work/$n-ref") <(console "$work/$n-ours.log" "$work/$n-ours") > "$work/$n.console"; then
            console_diff=$((console_diff + 1))
            echo "CONSOLE: $line"
            head -8 "$work/$n.console"
        fi
    else
        diff=$((diff + 1))
        echo "DIFFERENT: $line (exit codes $(cat "$work/$n-ref.code") and $(cat "$work/$n-ours.code"))"
        diff -a "$work/$n-ref.tree" "$work/$n-ours.tree" | head -8
    fi
    grep -a -q 'Transaction logs applied' "$work/$n-ref.log" && replayed=$((replayed + 1))
    rm -rf "${work:?}/$n-ref" "${work:?}/$n-ours"
done

echo "$n runs: $same with the same files and exit code, $diff different, $console_diff with another console; the original replayed logs in $replayed"
[ "$diff" -eq 0 ]
