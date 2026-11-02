//! Embeds the maps in ../../maps, so the binary works without a Maps folder.

use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../maps");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("maps folder")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_lowercase().ends_with(".map"))
        .collect();
    names.sort();
    let mut out = String::from("/// The maps from the repository's maps folder: file name and text\npub static EMBEDDED_MAPS: &[(&str, &str)] = &[\n");
    for n in &names {
        let path = dir.join(n).canonicalize().unwrap();
        out.push_str(&format!("    ({n:?}, include_str!({:?})),\n", path.display().to_string()));
    }
    out.push_str("];\n");
    let dest = Path::new(&std::env::var("OUT_DIR").unwrap()).join("maps.rs");
    std::fs::write(dest, out).unwrap();
}
