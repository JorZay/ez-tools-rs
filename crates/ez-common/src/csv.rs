//! CSV as CsvHelper writes it (EZ tools' --csv output).

/// CsvHelper's line ending
pub const NEW_LINE: &str = "\r\n";

/// What CsvHelper reports when a value can't be written, as a date with a bad --dt
pub const WRITER_ERROR: &str = "An unexpected error occurred. See inner exception for details.";

/// Used as the date format where the real one is bad: dates come out as this, for [`cut_at_bad_date`]
pub const BAD_DATE: &str = "\u{1}";

/// CSV text as CsvHelper leaves it when it fails on the first date: what it had written up to that field
pub fn cut_at_bad_date(out: &mut String) {
    if let Some(at) = out.find(BAD_DATE) {
        out.truncate(at);
        if out.ends_with(',') {
            out.pop();
        }
    }
}

/// A field as CsvHelper writes it: quoted when it has a quote, a comma or a line break, or starts or ends with a
/// space; quotes doubled
pub fn field(out: &mut String, s: &str) {
    field_with(out, s, ',');
}

/// A field as CsvHelper writes it with another delimiter
pub fn field_with(out: &mut String, s: &str, delimiter: char) {
    let quote = s.contains(['"', delimiter, '\r', '\n']) || s.starts_with(' ') || s.ends_with(' ');
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
