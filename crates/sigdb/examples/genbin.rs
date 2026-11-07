//! Synthetic binary database generator (NOT real signatures): genbin <rules> <out>
//! Writes sorted random MD5 file-hash rules straight into the binary container.
use sigdb::binary::assemble;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|v| v.parse().ok()).expect("rule count");
    let out = std::env::args().nth(2).expect("out path");
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut rows: Vec<([u8; 16], u32)> = (0..n).map(|i| {
        let (a, b) = (rnd(), rnd());
        let mut k = [0u8; 16];
        k[..8].copy_from_slice(&a.to_be_bytes());
        k[8..].copy_from_slice(&b.to_be_bytes());
        (k, (i % 100_000) as u32)
    }).collect();
    rows.sort();
    rows.dedup();
    let n = rows.len();
    let nfam = 500u32;
    let mut fam = nfam.to_le_bytes().to_vec();
    for f in 0..nfam {
        let name = format!("Win.Trojan.Family{f}");
        fam.push(name.len() as u8);
        fam.extend_from_slice(name.as_bytes());
    }
    let (mut arena, mut keys, mut sizes, mut meta) = (String::new(), Vec::with_capacity(n * 16), Vec::with_capacity(n * 4), Vec::with_capacity(n * 12));
    for (i, (k, s)) in rows.iter().enumerate() {
        let id = format!("clam.h.{i}");
        let off = arena.len() as u32;
        arena.push_str(&id);
        keys.extend_from_slice(k);
        sizes.extend_from_slice(&s.to_le_bytes());
        meta.extend_from_slice(&((i as u32) % nfam).to_le_bytes());
        meta.extend_from_slice(&off.to_le_bytes());
        meta.extend_from_slice(&[id.len() as u8, 2, 90, 0]);
    }
    let mut table = (n as u64).to_le_bytes().to_vec();
    table.extend_from_slice(&keys);
    table.extend_from_slice(&sizes);
    table.extend_from_slice(&meta);
    let bin = assemble(1, 1, 2, n as u64, &[(2, fam), (3, arena.into_bytes()), (0x100, table)]);
    std::fs::write(&out, &bin).unwrap();
    println!("wrote {out}: {n} rules, {} MiB", bin.len() / 1048576);
}
