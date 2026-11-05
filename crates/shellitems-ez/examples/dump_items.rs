//! Dumps shell items as the .NET dump in ez-tools-oracle does, to compare the two: dump_items <samples file>
use shellitems_ez::create_with_code_page;

fn line(s: &str) -> String {
    s.replace("\r\n", "\\n").replace('\n', "\\n").replace('\r', "\\r")
}

fn base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut bits, mut n) = (0u32, 0);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        bits = (bits << 6) | u32::from(v);
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn main() {
    let path = std::env::args().nth(1).expect("samples file");
    // `dump_items <file> nulls`: which items leave Value null
    let nulls = std::env::args().nth(2).is_some();
    let mut number = 0;
    for l in std::fs::read_to_string(path).unwrap().lines() {
        number += 1;
        if l.starts_with('#') || !l.contains('\t') {
            continue;
        }
        let raw = base64(l.split('\t').nth(1).unwrap());
        match create_with_code_page(&raw, 1252) {
            Ok(b) if nulls => println!("{number}\t{}\t{}", b.class, if b.value_is_null { "null" } else if b.value.is_empty() { "empty" } else { "text" }),
            Err(_) if nulls => println!("{number}\tERROR"),
            Ok(b) => {
                println!("{number}\t{}\t{}\t{}", b.class, line(&b.friendly_name), line(&b.value));
                println!("  text\t{}", line(&b.to_text()));
                for e in &b.extension_blocks {
                    println!("  block\t{}\t{}", e.class, line(&e.to_text()));
                }
            }
            Err(e) => println!("{number}\tERROR\t{}", line(&e)),
        }
    }
}
