//! Developer/release tool. The signing seed is a 64-hex-char secret in a file
//! you keep OFFLINE (generate it with a trustworthy RNG, e.g. `openssl rand -hex 32`).
//!   sigtool pubkey <seedfile>
//!   sigtool sign   <seedfile> <db> <out.sig>
//!   sigtool compile <db.txt> <out.bin>          (text database -> binary LSDBBIN1, UNSIGNED)
//!   sigtool check  <db> <sig> <pubkey-hex>     (verify + strict parse; text or binary)
use sigdb::*;
use std::fs;

fn seed(path: &str) -> [u8; 32] {
    let t = fs::read_to_string(path).expect("cannot read seed file");
    hex_decode(t.trim()).filter(|b| b.len() == 32).expect("seed must be 64 hex chars").try_into().unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        ["pubkey", s] => {
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed(s));
            let vk = sk.verifying_key();
            println!("{} key-id {}", hex_encode(vk.as_bytes()), key_id(&vk));
        }
        ["sign", s, db, out] => {
            let bytes = fs::read(db).expect("cannot read db");
            let valid = if binary::is_binary(&bytes) { binary::load_bytes(&bytes, None).map(|_| ()) } else { Database::parse(&bytes).map(|_| ()) };
            valid.unwrap_or_else(|e| { eprintln!("refusing to sign an invalid database: {e}"); std::process::exit(1) });
            fs::write(out, format!("{}\n", sign_bundle(&seed(s), &bytes))).expect("cannot write sig");
        }
        ["compile", src, out] => {
            let text = fs::read(src).expect("cannot read source database");
            let db = Database::parse(&text).unwrap_or_else(|e| { eprintln!("invalid text database: {e}"); std::process::exit(1) });
            let bin = binary::encode(&db);
            fs::write(out, &bin).expect("cannot write output");
            println!("compiled {} rules: {} bytes text -> {} bytes binary (UNSIGNED; sign it)", db.rule_count(), text.len(), bin.len());
        }
        ["check", db, sig, pubhex] => {
            let (bytes, sigline) = (fs::read(db).unwrap(), fs::read_to_string(sig).unwrap());
            let mut k = TrustedKeys::new();
            k.add_hex(pubhex).unwrap();
            match load_verified_bytes(&bytes, &sigline, &k) {
                Ok(d) => println!("OK {} serial {} rules {}", if binary::is_binary(&bytes) { "binary" } else { "text" }, d.serial, d.rule_count()),
                Err(e) => { eprintln!("FAIL: {e}"); std::process::exit(1) }
            }
        }
        _ => { eprintln!("usage: sigtool pubkey|sign|compile|check ..."); std::process::exit(2) }
    }
}
