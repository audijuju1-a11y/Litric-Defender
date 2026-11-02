//! Hashing primitives used for file identity and reputation keys.
//!
//! We never implement cryptography ourselves: SHA-256 comes from the audited
//! `sha2` crate. The import fingerprint is a Litric-defined construction and is
//! explicitly *not* the Microsoft "imphash" (which is MD5-based); it is
//! documented as such so threat-intel consumers are not misled.

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// A 32-byte SHA-256 digest with hex presentation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(nibble(b >> 4));
            s.push(nibble(b & 0x0f));
        }
        s
    }

    /// Parses a 64-character lowercase/uppercase hex string.
    pub fn from_hex(s: &str) -> Option<Digest32> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = hex_val(*bytes.get(i * 2)?)?;
            let lo = hex_val(*bytes.get(i * 2 + 1)?)?;
            out[i] = (hi << 4) | lo;
        }
        Some(Digest32(out))
    }
}

fn nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'a' + v - 10) as char,
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// SHA-256 over an in-memory buffer.
pub fn sha256_bytes(data: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    Digest32(d)
}

/// Streaming SHA-256 over a file, with a hard byte cap so a giant or endless
/// file (device node, sparse monster) cannot stall the scanner indefinitely.
///
/// Returns `(digest, bytes_hashed, truncated)`.
pub fn sha256_file(path: &Path, max_bytes: u64) -> io::Result<(Digest32, u64, bool)> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    let mut truncated = false;
    loop {
        let want = if total >= max_bytes {
            truncated = true;
            break;
        } else {
            (max_bytes - total).min(buf.len() as u64) as usize
        };
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    let out = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    Ok((Digest32(d), total, truncated))
}

/// Computes a stable fingerprint of a PE import table.
///
/// Format: `sha256(dll1.func1,dll1.func2,dll2.func3,...)` with names lowercased
/// and the `.dll`/`.ocx`/`.sys` extension stripped, imports in on-disk order.
/// Ordinal imports are encoded as `dll.#123`.
pub fn import_fingerprint(entries: &[(String, String)]) -> Digest32 {
    let mut s = String::new();
    for (i, (dll, func)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let d = strip_module_ext(&dll.to_ascii_lowercase());
        s.push_str(&d);
        s.push('.');
        s.push_str(&func.to_ascii_lowercase());
    }
    sha256_bytes(s.as_bytes())
}

fn strip_module_ext(name: &str) -> String {
    for ext in [".dll", ".ocx", ".sys", ".drv", ".exe", ".cpl"] {
        if let Some(stripped) = name.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vector() {
        // FIPS 180-2 test vector: SHA-256("abc").
        let d = sha256_bytes(b"abc");
        assert_eq!(
            d.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_sha256_vector() {
        assert_eq!(
            sha256_bytes(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = sha256_bytes(b"litric");
        assert_eq!(Digest32::from_hex(&d.to_hex()), Some(d));
        assert_eq!(Digest32::from_hex("zz"), None);
        assert_eq!(Digest32::from_hex(&"0".repeat(64)), Some(Digest32([0u8; 32])));
    }

    #[test]
    fn import_fingerprint_is_order_sensitive() {
        let a = import_fingerprint(&[
            ("KERNEL32.dll".into(), "CreateFileW".into()),
            ("USER32.dll".into(), "MessageBoxA".into()),
        ]);
        let b = import_fingerprint(&[
            ("USER32.dll".into(), "MessageBoxA".into()),
            ("KERNEL32.dll".into(), "CreateFileW".into()),
        ]);
        assert_ne!(a, b);
        // Case and extension folding must not change the fingerprint.
        let c = import_fingerprint(&[
            ("kernel32".into(), "createfilew".into()),
            ("user32".into(), "messageboxa".into()),
        ]);
        assert_eq!(a, c);
    }
}
