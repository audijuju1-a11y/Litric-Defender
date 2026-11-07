//! Decoy files. Content is synthetic and contains no personal data.
//! Legitimate software has no reason to modify them, so changes are
//! high-signal evidence (the engine weighs it with other signals).

use recovery::sha256_hex;
use std::{fs, io, path::{Path, PathBuf}};

const NAMES: &[&str] = &[
    "_Documents_Backup.docx",
    "_Budget_Summary.xlsx",
    "_Family_Photos.jpg",
    "_Contacts_Export.txt",
    "_Records.db",
];

#[derive(Debug, Clone)]
pub struct Decoy {
    pub path: PathBuf,
    pub hash: String,
}

#[derive(Debug, PartialEq)]
pub enum Tamper {
    Missing(PathBuf),
    Modified(PathBuf),
}

fn content(name: &str) -> Vec<u8> {
    format!("LITRIC HONEYVAULT DECOY FILE\nSynthetic; contains no real data. Do not edit.\n{name}\n")
        .repeat(40)
        .into_bytes()
}

/// Create any missing decoys in `dir`. Never overwrites an existing file;
/// an existing-but-different file is reported by `check`.
pub fn deploy(dir: &Path) -> io::Result<Vec<Decoy>> {
    let mut out = vec![];
    for name in NAMES {
        let path = dir.join(name);
        let data = content(name);
        if !path.exists() {
            fs::write(&path, &data)?;
        }
        out.push(Decoy { path, hash: sha256_hex(&data) });
    }
    Ok(out)
}

pub fn check(decoys: &[Decoy]) -> Vec<Tamper> {
    decoys
        .iter()
        .filter_map(|d| match fs::read(&d.path) {
            Err(_) => Some(Tamper::Missing(d.path.clone())),
            Ok(b) if sha256_hex(&b) != d.hash => Some(Tamper::Modified(d.path.clone())),
            Ok(_) => None,
        })
        .collect()
}
