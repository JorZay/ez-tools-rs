//! Every line of a file of base64 byte strings decoded with each code page, for comparing with .NET:
//! `dump_codepages <file> <pages...>`, printing `page, line, UTF-16 as hex`.

use std::io::Write;

fn value(c: u8) -> u32 {
    match c {
        b'A'..=b'Z' => u32::from(c - b'A'),
        b'a'..=b'z' => u32::from(c - b'a') + 26,
        b'0'..=b'9' => u32::from(c - b'0') + 52,
        b'+' => 62,
        _ => 63,
    }
}

fn base64(line: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in line.as_bytes().chunks(4) {
        let n = chunk.iter().filter(|c| **c != b'=').fold(0, |n, c| (n << 6) | value(*c)) << (6 * (4 - chunk.iter().filter(|c| **c != b'=').count()));
        let have = chunk.iter().filter(|c| **c != b'=').count();
        out.extend_from_slice(&n.to_be_bytes()[1..have.max(1)]);
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[1]).unwrap();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for page in &args[2..] {
        let number: i32 = page.parse().unwrap();
        for (n, line) in text.lines().enumerate() {
            let decoded = shellitems_ez::utils::provider_decode(number, &base64(line)).unwrap_or_default();
            let hex: String = decoded.encode_utf16().flat_map(u16::to_le_bytes).map(|b| format!("{b:02X}")).collect();
            writeln!(out, "{page}\t{}\t{hex}", n + 1).unwrap();
        }
    }
}
