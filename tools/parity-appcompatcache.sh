#!/usr/bin/env bash
# Compares this port's output with the original AppCompatCacheParser's: every file each one writes must be identical, and so must
# the console output after the banner (minus exception stack traces and the output folder's name).
#
#   tools/parity-appcompatcache.sh <AppCompatCacheParser.dll> < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f "/hives/SYSTEM" -t --csv {out}/o --csvf o.csv
# (quoted as in a shell). {out} is replaced by the run's output folder; --co false is added unless the line has --co.
# The time at the start of default file names is removed before comparing. The original runs with LANG=en_GB.UTF-8. Build the release binary first
# (cargo build --release). The outputs are deleted at the end, as they hold copies of the data; PARITY_KEEP=1 keeps them,
# to look at a difference.
set -uo pipefail

dll=$1
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/appcompatcacheparser"
work=$(mktemp -d)
[ -n "${PARITY_KEEP:-}" ] && echo "outputs in $work" || trap 'rm -rf "$work"' EXIT
same=0 diff=0 n=0

console() {
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^System\.' -e '^Microsoft\.' -e '^--- End of' -e '^ ---> ' -e '^   --- End of' -e '^Console log: ' |
        sed -e "s#$2#{out}#g" -e 's/[0-9]\{14\}_/{stamp}_/g'
}

# the log file: its time stamps and name go
logfile() {
    grep -a -v -e '^   at ' -e '^System\.' -e '^Microsoft\.' -e '^--- End of' -e '^ ---> ' -e '^   --- End of' -e 'Console log: ' -e 'Command line: ' -e 'version ' -e 'Author: ' -e 'github.com' "$1" | sed -e 's/\r$//' | grep -a -v '^$' |
        sed -E -e 's/^\[[0-9:.]+ ([A-Z]+)\]/[\1]/' -e "s#$2#{out}#g" -e 's/[0-9]{14}_/{stamp}_/g'
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        case "$line" in *--co*) co=() ;; *) co=(--co false) ;; esac
        if [ $side = ref ]; then
            LANG=en_GB.UTF-8 dotnet "$dll" "${args[@]}" "${co[@]}" > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" "${co[@]}" > "$out.log" 2>&1
        fi
        echo $? > "$out.exit"
        # default names start with the time; the log file has the version in its name
        find "$out" -type f | while read -r f; do
            b=$(basename "$f")
            c=$(echo "$b" | sed -E -e 's/^[0-9]{14}_//' -e 's/^AppCompatCacheParser_[^_]*_ConsoleLog/ConsoleLog/')
            [ "$b" = "$c" ] || mv "$f" "$(dirname "$f")/$c"
        done
    done
    if ! cmp -s "$work/$n-ref.exit" "$work/$n-ours.exit"; then
        diff=$((diff + 1))
        echo "DIFF exit code ($(cat "$work/$n-ref.exit") vs $(cat "$work/$n-ours.exit")): $line"
    fi
    if ! cmp -s <(console "$work/$n-ref.log" "$work/$n-ref") <(console "$work/$n-ours.log" "$work/$n-ours"); then
        diff=$((diff + 1))
        echo "DIFF console: $line"
    fi
    while read -r f; do
        if [ "$(basename "$f")" = "ConsoleLog.txt" ]; then
            if cmp -s <(logfile "$work/$n-ref/$f" "$work/$n-ref") <(logfile "$work/$n-ours/$f" "$work/$n-ours"); then same=$((same + 1)); else diff=$((diff + 1)); echo "DIFF $line: $f"; fi
        elif cmp -s "$work/$n-ref/$f" "$work/$n-ours/$f"; then
            same=$((same + 1))
        else
            diff=$((diff + 1))
            echo "DIFF $line: $f"
        fi
    done < <(cd "$work/$n-ref" && find . -type f | sort)
    extra=$(cd "$work/$n-ours" && find . -type f | sort | while read -r f; do [ -e "$work/$n-ref/$f" ] || echo "$f"; done)
    [ -n "$extra" ] && { diff=$((diff + 1)); echo "EXTRA files from this port for $line: $extra"; }
done

echo "runs: $n, identical files: $same, differences: $diff"
[ "$diff" -eq 0 ]
