# Sourced by the parity scripts. The ports write what the originals write on Windows; the Linux builds of the originals differ
# from that in two .NET platform rules: U+202F, not a space, before AM and PM in standard date formats, and LF, not CRLF, for
# Environment.NewLine (docs/windows-checks.md). Output files are compared after making both sides the same in these.
platform() { perl -pe 's/\xe2\x80\xaf/ /g; s/\r\n/\n/g' "$@"; }
