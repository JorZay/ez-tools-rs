//! Prints an ESE database's state, its tables and columns (id, JET_coltyp, size), and each table's number of rows and the first
//! errors in reading their values
fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).expect("read");
        let db = match ese_ez::Database::new(data) {
            Ok(db) => db,
            Err(e) => {
                println!("{path}: {e}");
                continue;
            }
        };
        println!("{path}: {} (format 0x{:x},{})", db.state(), db.format_version, db.format_revision);
        for t in db.tables() {
            let (mut rows, mut errors) = (0, Vec::new());
            let walk = db.for_each_row(t, &mut |row| {
                rows += 1;
                for c in &t.columns {
                    if let Err(e) = row.value(c) {
                        errors.push(e);
                    }
                }
                Ok(())
            });
            println!("TABLE {} (root {}): {rows} rows{}", t.name, t.root_page, walk.err().map(|e| format!(", stopped: {e}")).unwrap_or_default());
            for e in errors.iter().take(5) {
                println!("  error: {e}");
            }
            for c in &t.columns {
                println!("  {} {} type {} space {}", c.id, c.name, c.coltyp, c.space);
            }
        }
    }
}
