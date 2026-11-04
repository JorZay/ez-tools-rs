#!/usr/bin/env bash
# Compares this port's output with the original PECmd's: the CSV, time line, JSON, XHTML report and console output (minus
# the banner, timings, stack traces and the output folder's name) must be identical.
#
#   tools/parity-pecmd.sh <PECmd.dll> <prefetch file or folder>... [-- extra arguments]
#
# The original runs with LANG=en_US.UTF-8. Build the release binary first (cargo build --release). SourceAccessed is left
# out of the comparison: each read can update a file's access time, so the two tools see different ones. The outputs are
# deleted at the end, as they hold copies of the data.
set -uo pipefail

dll=$1
shift
inputs=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
    inputs+=("$1")
    shift
done
[ "${1:-}" = "--" ] && shift
extra=("$@")

here=$(cd "$(dirname "$0")/.." && pwd)
ours="$here/target/release/pecmd"
work=$(mktemp -d)
# PARITY_KEEP=1 keeps them, to look at a difference
[ -n "${PARITY_KEEP:-}" ] && echo "outputs in $work" || trap 'rm -rf "$work"' EXIT
same=0 diff=0

console() {
    sed -n '/^Command line:/,$p' "$1" | tail -n +2 |
        grep -a -v -e '^---------- Processed' -e '^Processed ' -e '^Last accessed on: ' -e '^   at ' -e '^Prefetch\.' -e '^System\.' -e '^--- End of' -e '^ ---> ' -e '^   --- End of' |
        sed -e "s#$2#{out}#g" -e 's/_PECmd_Output_for_[^/]*/_PECmd_Output_for_X/' -e 's/[0-9]\{14\}_PECmd_Output/{stamp}_PECmd_Output/g' -e 's/\r$//'
}

# without the access time
masked() {
    sed -E -e 's/"SourceAccessed":"[^"]*"/"SourceAccessed":""/' -e 's#<SourceAccessed>[^<]*#<SourceAccessed>#' \
        -e 's/^([^,]*,[^,]*,[^,]*,[^,]*,)[0-9][^,]*/\1/' "$1"
}

check() {
    if cmp -s <(masked "$1") <(masked "$2"); then
        same=$((same + 1))
    else
        diff=$((diff + 1))
        echo "DIFF $3"
    fi
}

n=0
for input in "${inputs[@]}"; do
    n=$((n + 1))
    if [ -d "$input" ]; then source=(-d "$input"); else source=(-f "$input"); fi
    for side in ref ours; do
        out="$work/$n-$side"
        mkdir -p "$out"
        args=("${source[@]}" --csv "$out" --csvf out.csv --json "$out" --jsonf out.json --html "$out" --co false "${extra[@]}")
        if [ $side = ref ]; then
            LANG=en_US.UTF-8 dotnet "$dll" "${args[@]}" > "$out.log" 2>&1
        else
            "$ours" "${args[@]}" > "$out.log" 2>&1
        fi
        echo $? > "$out.exit"
        # the report's folder has the time and the output folder in its name
        report=$(find "$out" -name index.xhtml | head -1)
        [ -n "$report" ] && mv "$(dirname "$report")" "$out/report"
    done
    check "$work/$n-ref.exit" "$work/$n-ours.exit" "exit code: $input"
    console "$work/$n-ref.log" "$work/$n-ref" > "$work/$n-ref.console"
    console "$work/$n-ours.log" "$work/$n-ours" > "$work/$n-ours.console"
    check "$work/$n-ref.console" "$work/$n-ours.console" "console: $input"
    for f in out.csv out_Timeline.csv out.json report/styles/normalize.css report/styles/style.css; do
        [ -e "$work/$n-ref/$f" ] || [ -e "$work/$n-ours/$f" ] || continue
        check "$work/$n-ref/$f" "$work/$n-ours/$f" "$f: $input"
    done
    # the report names the output folder only through the sources, which are the same on both sides
    [ -e "$work/$n-ref/report/index.xhtml" ] && check "$work/$n-ref/report/index.xhtml" "$work/$n-ours/report/index.xhtml" "index.xhtml: $input"
done

echo "inputs: $n, identical: $same, differences: $diff"
[ "$diff" -eq 0 ]
