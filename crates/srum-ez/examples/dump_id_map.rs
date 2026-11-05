//! For comparing with the original's classes: `dump_id_map map <SRUDB.dat>` has each entry's raw bytes and how it reads, and
//! `dump_id_map hive <SOFTWARE>` the names a hive gives.
use ese_ez::Database;
use ez_common::json::base64;
use srum_ez::names::sid_type_name;
use srum_ez::{AppInfo, SoftwareNames, Srum, sid_from_bytes};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "hive" {
        match SoftwareNames::read(&args[2]) {
            Ok(names) => {
                let mut users: Vec<_> = names.sid_to_user.iter().collect();
                users.sort();
                for (sid, user) in users {
                    println!("U\t{sid}\t{user}");
                }
                let mut ssids: Vec<_> = names.ssids.iter().collect();
                ssids.sort();
                for (index, name) in ssids {
                    println!("W\t{index}\t{name}");
                }
            }
            Err((message, _)) => println!("ERROR\t{message}"),
        }
        return;
    }
    let db = Database::new(std::fs::read(&args[2]).unwrap()).unwrap_or_else(|e| panic!("{e}"));
    for (index, kind, blob) in Srum::raw_id_map(&db) {
        let raw = blob.as_deref();
        let encoded = raw.map_or_else(|| "-".to_string(), base64);
        if kind == Some(3) {
            let sid = sid_from_bytes(raw);
            println!("{index}\t3\t{encoded}\t{sid}\t{}", sid_type_name(&sid));
        } else {
            let text = raw.map(|b| ez_common::net::unicode_string(b, 0, b.len() as i64).unwrap_or_default()).unwrap_or_default();
            let info = AppInfo::new(text.trim_matches('\0'));
            let time = info.timestamp.map_or_else(String::new, |t| t.format("yyyy-MM-dd HH:mm:ss"));
            println!("{index}\t{}\t{encoded}\t{}\t{}\t{time}\t{}", kind.map_or(-1, i32::from), info.exe_info.replace(['\t', '\n', '\r'], "~"), info.description.unwrap_or_default().replace(['\t', '\n', '\r'], "~"), info.unknown.unwrap_or_default().replace(['\t', '\n', '\r'], "~"));
        }
    }
}
