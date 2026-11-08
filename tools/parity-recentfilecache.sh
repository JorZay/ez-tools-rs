#!/usr/bin/env bash
# Compares this port's output with the original RecentFileCacheParser's: every file each one writes must be identical, and so must the console
# output after the banner and the exit code (minus timings, stack traces, the output folder's name and time stamps). Console
# logs (--co) are compared without the time of each line and the version in the file's name.
#
#   tools/parity-recentfilecache.sh <RecentFileCacheParser.dll> [work folder] < cases
#
# Each line of `cases` is the arguments of one run, e.g.
#   -f /samples/RecentFileCache.bcf --csv {out}/c --json {out}/j
# (quoted as in a shell). {out} is replaced by the run's output folder, which is also where relative paths start. The original
# runs with LANG=en_US.UTF-8 and TZ=UTC. tools/gen-recentfilecache-cases.py builds samples.
#
# The outputs hold the source file's times, its access time too: keep the inputs on a file system mounted relatime (not tmpfs,
# which updates the access time at every read), so that the read before each pair of runs is the last to change it.
set -uo pipefail
. "$(dirname "$0")/platform.sh"

dll=$1
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/recentfilecacheparser"
same=0 diff=0 n=0

console() {
    sed -n '/^\(\[[0-9:.]* [A-Z]*\] \)\?Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^   at ' -e '^--- End of' -e '^   --- End of' -e '^ ---> ' -e '^[A-Za-z.]*Exception: ' -e "^File name: '" |
        sed -E "s#$2#{out}#g; s/^\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{14}/{time}/g; s/ in [0-9.,]+ seconds/ in {time} seconds/; s/_RecentFileCacheParser_[0-9.]+_ConsoleLog/_RecentFileCacheParser_{version}_ConsoleLog/"
}

log_file() {
    grep -a -v -e '^   at ' -e '^--- End of' -e '^   --- End of' -e '^ ---> ' -e '^[A-Za-z.]*Exception: ' -e "^File name: '" "$1" |
        sed -E "s#$2#{out}#g; s/^\[[0-9:.]{12} ([A-Z]{3})\]/[\1]/; s/[0-9]{14}/{time}/g; s/ in [0-9.,]+ seconds/ in {time} seconds/; s/_RecentFileCacheParser_[0-9.]+_ConsoleLog/_RecentFileCacheParser_{version}_ConsoleLog/; /RecentFileCacheParser .*version/d; /^Author: /d; /^https:/d; /^\r?$/d"
}

while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    # the source file's times are in the output: read it once first, so that neither run changes its access time
    eval "first=(${line//\{out\}/x})"
    for i in "${!first[@]}"; do
        [ "${first[$i]}" = -f ] && cat -- "${first[$((i + 1))]:-}" > /dev/null 2>&1
    done
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
    names() { (cd "$1" && find . -type f | while IFS= read -r f; do printf '%s\t%s\n' "$(printf '%s' "$f" | sed -E 's/[0-9]{14}/{time}/g; s/_RecentFileCacheParser_[0-9.]+_ConsoleLog/_RecentFileCacheParser_{version}_ConsoleLog/')" "$f"; done | LC_ALL=C sort); }
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
                    same_file() { cmp -s <(log_file "$work/$n-ref/$f" "$work/$n-ref" | platform) <(log_file "$work/$n-ours/$o" "$work/$n-ours" | platform); } ;;
                *)
                    same_file() { sed "s#$work/$n-ref#{out}#g" "$work/$n-ref/$f" | platform | cmp -s - <(sed "s#$work/$n-ours#{out}#g" "$work/$n-ours/$o" | platform); } ;;
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
