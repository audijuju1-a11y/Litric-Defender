//! litric-clamav-import --serial N --source-note "how obtained/verified" --out db.lsdb
//!                      [--created UNIX_SECONDS] [--report file] [--binary] <dir-or-files...>
//! Output is UNSIGNED; sign it with `sigtool sign` before installing.
use clamav_import::*;
use std::path::PathBuf;

fn main() {
    let mut a = std::env::args().skip(1);
    let (mut serial, mut created, mut note, mut out, mut rep) = (None::<u64>, None::<u64>, None, None, None);
    let mut binary = false;
    let mut inputs: Vec<PathBuf> = vec![];
    while let Some(x) = a.next() {
        match x.as_str() {
            "--serial" => serial = a.next().and_then(|v| v.parse().ok()),
            "--created" => created = a.next().and_then(|v| v.parse().ok()),
            "--source-note" => note = a.next(),
            "--out" => out = a.next(),
            "--report" => rep = a.next(),
            "--binary" => binary = true,
            _ => inputs.push(PathBuf::from(x)),
        }
    }
    let (Some(serial), Some(note), Some(out)) = (serial, note, out) else {
        eprintln!("usage: litric-clamav-import --serial N --source-note TEXT --out FILE [--created SECS] [--report FILE] <dir|files>...");
        std::process::exit(2);
    };
    let created = created.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    let opts = Options { serial, created, source_note: note };
    let mut files: Vec<PathBuf> = vec![];
    for p in &inputs {
        if p.is_dir() {
            match std::fs::read_dir(p) {
                Ok(rd) => files.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_file())),
                Err(e) => {
                    eprintln!("cannot read {}: {e}", p.display());
                    std::process::exit(1);
                }
            }
        } else {
            files.push(p.clone());
        }
    }
    match import(&files, &opts) {
        Ok(o) => {
            let text = o.report.render();
            print!("{text}");
            if let Some(r) = rep {
                let _ = std::fs::write(r, &text);
            }
            let bytes = if binary {
                match sigdb::Database::parse(&o.db) {
                    Ok(db) => sigdb::binary::encode(&db),
                    Err(e) => {
                        eprintln!("internal error converting to binary: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                o.db.clone()
            };
            if let Err(e) = std::fs::write(&out, &bytes) {
                eprintln!("cannot write {out}: {e}");
                std::process::exit(1);
            }
            println!("wrote {out} ({}, UNSIGNED; sign with `sigtool sign` before installing)", if binary { "binary" } else { "text" });
        }
        Err(e) => {
            eprintln!("import failed: {e}");
            std::process::exit(1);
        }
    }
}
