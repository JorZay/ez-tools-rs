//! Dumps links as target/oracle's .NET dump does, to compare the two: dump_lnk <folder>
use std::path::{Path, PathBuf};

fn line(s: &str) -> String {
    s.replace("\r\n", "\\n").replace('\n', "\\n").replace('\r', "\\r")
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        if e.path().is_dir() { files(&e.path(), out) } else { out.push(e.path()) }
    }
}

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("folder"));
    let mut all = Vec::new();
    files(&root, &mut all);
    let mut names: Vec<(String, PathBuf)> = all.into_iter().map(|p| (p.to_string_lossy().into_owned(), p)).collect();
    names.sort_by(|a, b| {
        let (x, y): (Vec<u16>, Vec<u16>) = (a.0.encode_utf16().collect(), b.0.encode_utf16().collect());
        x.cmp(&y)
    });
    for (name, path) in names {
        println!("FILE\t{}", path.strip_prefix(&root).unwrap().display());
        match lnk_ez::load_file(&name, 1252) {
            Ok(l) => {
                for e in &l.parse_errors {
                    println!(" parse\t{}", line(e));
                }
                for (i, b) in l.target_ids.iter().enumerate() {
                    println!("id{i}\t{}\t{}\t{}", b.class, line(&b.friendly_name), line(&b.value));
                    println!("  text\t{}", line(&b.to_text()));
                    for e in &b.extension_blocks {
                        println!("  block\t{}\t{}", e.class, line(&e.to_text()));
                    }
                }
                for x in &l.extra_blocks {
                    println!(" extra\t{}\t{}", x.class_name(), line(&x.to_text()));
                }
            }
            Err(e) => println!(" ERROR\tLnkParseException\t{}", line(&e.message)),
        }
    }
}
