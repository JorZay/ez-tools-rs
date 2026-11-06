#!/usr/bin/env bash
# Compares this port's output with the original RBCmd's: every file each one writes must be identical, and so must the console
# output after the banner and the exit code (minus timings, stack traces, the output folder's name and time stamps). Console
# logs (--co) are compared without the time of each line and the version in the file's name.
#
#   tools/parity-rbcmd.sh <RBCmd.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -d /samples --csv {out}/c
# (quoted as in a shell). {out} is replaced by the run's output folder, which is also where relative paths start. The original
# runs with LANG=en_US.UTF-8 and TZ=UTC. tools/gen-rbcmd-cases.py builds samples.
set -uo pipefail

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/rbcmd"
same=0 diff=0 n=0

console() {
    sed -n '/^\(\[[0-9:.]* [A-Z]*\] \)\?Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^--- End of' -e '^   --- End of' -e '^ ---> ' -e '^[A-Za-z.]*Exception: ' -e "^File name: '" |
        sed -E "s#$2#{out}#g; s/^\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{14}/{time}/g; s/ in [0-9.,]+ seconds/ in {time} seconds/; s/_RBCmd_[0-9.]+_ConsoleLog/_RBCmd_{version}_ConsoleLog/"
}

log_file() {
    grep -a -v -e '^   at ' -e '^--- End of' -e '^   --- End of' -e '^ ---> ' -e '^[A-Za-z.]*Exception: ' -e "^File name: '" "$1" |
        sed -E "s#$2#{out}#g; s/^\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{14}/{time}/g; s/ in [0-9.,]+ seconds/ in {time} seconds/; s/_RBCmd_[0-9.]+_ConsoleLog/_RBCmd_{version}_ConsoleLog/; /RBCmd .*version/d; /^Author: /d; /^https:/d; /^\r?$/d"
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        eval "args=(${line//\{out\}/\"$out\"})"
        if [ $side = ref ]; then
            (cd "$out" && LANG=en_US.UTF-8 TZ=UTC dotnet "$dll" "${args[@]}") > "$out.log" 2>&1
        else
            (cd "$out" && LANG=en_US.UTF-8 TZ=UTC "$ours" "${args[@]}") > "$out.log" 2>&1
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
    names() { (cd "$1" && find . -type f | while IFS= read -r f; do printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{14}/{time}/g; s/_RBCmd_[0-9.]+_ConsoleLog/_RBCmd_{version}_ConsoleLog/')" "$f"; done | LC_ALL=C sort); }
    names "$work/$n-ref" > "$work/$n-ref.names"
    names "$work/$n-ours" > "$work/$n-ours.names"
    if ! cmp -s <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names"); then
        diff=$((diff + 1))
        echo "DIFF file names: $line"
        diff <(cut -f1 "$work/$n-ref.names") <(cut -f1 "$work/$n-ours.names") | head -20
    else
        while IFS=$'\t' read -r name f o; do
            case "$name" in
                *_ConsoleLog.txt)
                    same_file() { cmp -s <(log_file "$work/$n-ref/$f" "$work/$n-ref") <(log_file "$work/$n-ours/$o" "$work/$n-ours"); } ;;
                *)
                    same_file() { sed "s#$work/$n-ref#{out}#g" "$work/$n-ref/$f" | cmp -s - <(sed "s#$work/$n-ours#{out}#g" "$work/$n-ours/$o"); } ;;
            esac
            if same_file; then
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
