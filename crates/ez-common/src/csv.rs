//! CSV as CsvHelper writes it (EZ tools' --csv output).

/// CsvHelper's line ending
pub const NEW_LINE: &str = "\r\n";

/// A field as CsvHelper writes it: quoted when it has a quote, a comma or a line break, or starts or ends with a
/// space; quotes doubled
pub fn field(out: &mut String, s: &str) {
    let quote = s.contains(['"', ',', '\r', '\n']) || s.starts_with(' ') || s.ends_with(' ');
    if !quote {
        out.push_str(s);
        return;
    }
    out.push('"');
    for c in s.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}
