//! Litric binary database container `LSDBBIN1`.
//!
//! Layout (little endian):
//! ```text
//! header (signed):  magic[8] header_len:u32 format:u32 serial:u64 created:u64
//!                   min_engine:u32 n_sections:u32 rule_count:u64
//!                   n x { type:u32 reserved:u32=0 offset:u64 length:u64 sha256[32] }
//! sections:         contiguous, in table order, no gaps, no trailing bytes
//! ```
//! The Ed25519 signature covers ONLY the header. The header carries the SHA-256
//! of every section, so a loader can verify authenticity first and then verify
//! and decode one section at a time without holding the whole file in memory.
//!
//! The reader trusts NOTHING in a validly signed file: every length, index,
//! range, ordering and bytecode instruction is checked, because a signed file
//! can still be malformed (tooling bug) and must never cause a panic or a
//! silently wrong table.

use super::*;
use std::io::{Read, Seek, SeekFrom};

pub const MAGIC: &[u8; 8] = b"LSDBBIN1";
const FORMAT_VERSION: u32 = 1;
const MAX_SECTIONS: usize = 64;
const MAX_BIN_RULES: u64 = 64_000_000;
const MAX_SECTION_BYTES: u64 = 4 << 30;
const FIXED: usize = 48;
const ENTRY: usize = 56;
const MAX_FAMILIES: u32 = 4_000_000;

const T_SOURCES: u32 = 1;
const T_FAMILIES: u32 = 2;
const T_ARENA: u32 = 3;
const T_LEGACY: u32 = 4;
const T_NDB: u32 = 0x200;
const T_LDB: u32 = 0x201;
/// kind: 0 file hashes, 1 PE-section hashes, 2 allowlist
fn t_table(kind: u32, algo: u32) -> u32 {
    0x100 + kind * 3 + algo
}

pub fn is_binary(prefix: &[u8]) -> bool {
    prefix.starts_with(MAGIC)
}

fn corrupt<T>(m: impl Into<String>) -> Result<T, Error> {
    Err(Error::Corrupt(m.into()))
}
fn io_err(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Corrupt("database file is truncated".into())
    } else {
        Error::Io(e)
    }
}

struct Entry {
    ty: u32,
    offset: u64,
    length: u64,
    sha: [u8; 32],
}
struct Header {
    serial: u64,
    created: u64,
    min_engine: u32,
    rule_count: u64,
    entries: Vec<Entry>,
}

// ---------------------------------------------------------------- writing

/// Build a container from raw sections (used by `encode`; public so tests can
/// forge signed-but-malformed files).
pub fn assemble(serial: u64, created: u64, min_engine: u32, rule_count: u64, sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let n = sections.len();
    let hl = FIXED + ENTRY * n;
    let mut out = Vec::with_capacity(hl + sections.iter().map(|s| s.1.len()).sum::<usize>());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(hl as u32).to_le_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&created.to_le_bytes());
    out.extend_from_slice(&min_engine.to_le_bytes());
    out.extend_from_slice(&(n as u32).to_le_bytes());
    out.extend_from_slice(&rule_count.to_le_bytes());
    let mut off = hl as u64;
    for (ty, data) in sections {
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&sha256(data));
        off += data.len() as u64;
    }
    for (_, data) in sections {
        out.extend_from_slice(data);
    }
    out
}

/// The region covered by the signature, if `bytes` starts with a plausible header.
pub fn signed_region(bytes: &[u8]) -> Option<&[u8]> {
    if !is_binary(bytes) || bytes.len() < FIXED {
        return None;
    }
    let hl = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    bytes.get(..hl).filter(|_| hl >= FIXED)
}

fn sev_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
fn target_name(t: Target) -> &'static str {
    match t {
        Target::Any => "any",
        Target::Pe => "pe",
        Target::Elf => "elf",
        Target::Zip => "zip",
        Target::Pdf => "pdf",
        Target::Script => "script",
    }
}
fn target_code(t: Target) -> u8 {
    match t {
        Target::Any => 0,
        Target::Pe => 1,
        Target::Elf => 2,
        Target::Pdf => 3,
        Target::Zip => 4,
        Target::Script => 5,
    }
}
fn target_from(c: u8) -> Option<Target> {
    Some(match c {
        0 => Target::Any,
        1 => Target::Pe,
        2 => Target::Elf,
        3 => Target::Pdf,
        _ => return None,
    })
}

fn put_meta(out: &mut Vec<u8>, m: &Meta) {
    out.extend_from_slice(&m.family.to_le_bytes());
    out.extend_from_slice(&m.id_off.to_le_bytes());
    out.extend_from_slice(&[m.id_len, m.sev, m.conf, 0]);
}

fn table_payload(t: &HashTable, with_meta: bool) -> Vec<u8> {
    let n = t.len();
    let mut out = Vec::with_capacity(8 + n * (t.klen + 4 + if with_meta { 12 } else { 0 }));
    out.extend_from_slice(&(n as u64).to_le_bytes());
    out.extend_from_slice(&t.keys);
    for s in &t.sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
    if with_meta {
        for m in &t.meta {
            put_meta(&mut out, m);
        }
    }
    out
}

fn legacy_text(db: &Database) -> String {
    let mut lines: Vec<String> = vec![];
    let mut hr: Vec<(&[u8; 32], &Rule)> = db.hash_rules.iter().collect();
    hr.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    for (h, r) in hr {
        lines.push(format!("H {} {} {} {} {}", r.id, r.family, sev_name(r.severity), r.confidence, hex_encode(h)));
    }
    for p in &db.patterns {
        lines.push(format!("P {} {} {} {} {} {}", p.rule.id, p.rule.family, sev_name(p.rule.severity), p.rule.confidence, target_name(p.target), hex_encode(&p.pattern)));
    }
    let mut al: Vec<&[u8; 32]> = db.allow.iter().collect();
    al.sort();
    for h in al {
        lines.push(format!("A {}", hex_encode(h)));
    }
    let mut rv: Vec<&String> = db.revoked.iter().collect();
    rv.sort();
    for r in rv {
        lines.push(format!("R {r}"));
    }
    lines.join("\n")
}

fn encode_offset(o: &ndb::Offset) -> (u8, u64, u32) {
    match &o.base {
        ndb::Base::Anywhere => (0, 0, 0),
        ndb::Base::Abs(n) => (1, *n, 0),
        ndb::Base::Ep(d) => (2, *d as u64, 0),
        ndb::Base::Section(k, n) => (3, *n, *k),
        ndb::Base::LastSection(n) => (4, *n, 0),
        ndb::Base::Eof(n) => (5, *n, 0),
    }
}

fn decode_offset(tag: u8, val: u64, aux: u32, maxshift: u32, target: Target) -> Result<ndb::Offset, Error> {
    if maxshift as u64 > 1 << 20 {
        return corrupt("maxshift out of range");
    }
    let base = match tag {
        0 if val == 0 && aux == 0 && maxshift == 0 => ndb::Base::Anywhere,
        1 if aux == 0 => ndb::Base::Abs(val),
        2 if aux == 0 => ndb::Base::Ep(val as i64),
        3 => ndb::Base::Section(aux, val),
        4 if aux == 0 => ndb::Base::LastSection(val),
        5 if aux == 0 && maxshift == 0 => ndb::Base::Eof(val),
        _ => return corrupt("invalid offset"),
    };
    let offset = ndb::Offset { base, maxshift };
    if offset.needs_pe() && target != Target::Pe {
        return corrupt("EP/section offset on a non-PE target");
    }
    Ok(offset)
}

/// Bounds-checked cursor over untrusted bytes.
struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let e = self.p.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| Error::Corrupt("record truncated".into()))?;
        let s = &self.b[self.p..e];
        self.p = e;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// Canonical raw sections of a database (deterministic).
pub fn sections_of(db: &Database) -> Vec<(u32, Vec<u8>)> {
    let mut s: Vec<(u32, Vec<u8>)> = vec![];
    if !db.sources.is_empty() {
        s.push((T_SOURCES, db.sources.join("\n").into_bytes()));
    }
    if !db.families.is_empty() {
        let mut f = (db.families.len() as u32).to_le_bytes().to_vec();
        for n in &db.families {
            f.push(n.len() as u8);
            f.extend_from_slice(n.as_bytes());
        }
        s.push((T_FAMILIES, f));
    }
    if !db.id_arena.is_empty() {
        s.push((T_ARENA, db.id_arena.clone().into_bytes()));
    }
    let legacy = legacy_text(db);
    if !legacy.is_empty() {
        s.push((T_LEGACY, legacy.into_bytes()));
    }
    for (kind, tables, with_meta) in [(0u32, &db.file_tables, true), (1, &db.section_tables, true), (2, &db.allow_tables, false)] {
        for a in ALGOS {
            let t = &tables[a.idx()];
            if t.len() > 0 {
                s.push((t_table(kind, a.idx() as u32), table_payload(t, with_meta)));
            }
        }
    }
    if !db.ndb.is_empty() {
        let mut o = (db.ndb.len() as u64).to_le_bytes().to_vec();
        for r in &db.ndb {
            put_meta(&mut o, &r.meta);
            o.push(target_code(r.target));
            let (tag, val, aux) = encode_offset(&r.offset);
            o.push(tag);
            o.extend_from_slice(&val.to_le_bytes());
            o.extend_from_slice(&aux.to_le_bytes());
            o.extend_from_slice(&r.offset.maxshift.to_le_bytes());
            o.extend_from_slice(&(r.code.len() as u32).to_le_bytes());
            o.extend_from_slice(&r.code);
        }
        s.push((T_NDB, o));
    }
    if !db.ldb.is_empty() {
        let mut o = (db.ldb.len() as u64).to_le_bytes().to_vec();
        for r in &db.ldb {
            put_meta(&mut o, &r.meta);
            o.push(target_code(r.target));
            let flags = r.constraints.filesize.is_some() as u8 | (r.constraints.sections.is_some() as u8) << 1;
            o.push(flags);
            for (a, b) in [r.constraints.filesize, r.constraints.sections].into_iter().flatten() {
                o.extend_from_slice(&a.to_le_bytes());
                o.extend_from_slice(&b.to_le_bytes());
            }
            o.extend_from_slice(&(r.expr_text.len() as u16).to_le_bytes());
            o.extend_from_slice(r.expr_text.as_bytes());
            o.push(r.subs.len() as u8);
            for sub in &r.subs {
                let (tag, val, aux) = encode_offset(&sub.offset);
                o.push(tag);
                o.extend_from_slice(&val.to_le_bytes());
                o.extend_from_slice(&aux.to_le_bytes());
                o.extend_from_slice(&sub.offset.maxshift.to_le_bytes());
                o.extend_from_slice(&(sub.code.len() as u32).to_le_bytes());
                o.extend_from_slice(&sub.code);
            }
        }
        s.push((T_LDB, o));
    }
    s
}

/// Serialize a database to the binary container (UNSIGNED; sign the header with `sign_bundle`).
pub fn encode(db: &Database) -> Vec<u8> {
    assemble(db.serial, db.created, db.min_engine.max(2), db.rule_count() as u64, &sections_of(db))
}

/// SHA-256 over the canonical content. Equal digests mean equal databases.
pub fn content_digest(db: &Database) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(db.serial.to_le_bytes());
    h.update(db.created.to_le_bytes());
    h.update((db.min_engine.max(2) as u64).to_le_bytes());
    for (ty, data) in sections_of(db) {
        h.update(ty.to_le_bytes());
        h.update((data.len() as u64).to_le_bytes());
        h.update(&data);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------- reading

fn parse_header(hdr: &[u8], total: u64) -> Result<Header, Error> {
    let u32at = |o: usize| u32::from_le_bytes([hdr[o], hdr[o + 1], hdr[o + 2], hdr[o + 3]]);
    let u64at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&hdr[o..o + 8]);
        u64::from_le_bytes(b)
    };
    if hdr.len() < FIXED || &hdr[..8] != MAGIC {
        return corrupt("bad magic");
    }
    if u32at(8) as usize != hdr.len() {
        return corrupt("header length mismatch");
    }
    if u32at(12) != FORMAT_VERSION {
        return corrupt("unsupported binary format version");
    }
    let n = u32at(36) as usize;
    if n > MAX_SECTIONS || hdr.len() != FIXED + ENTRY * n {
        return corrupt("section table size is inconsistent");
    }
    let rule_count = u64at(40);
    if rule_count > MAX_BIN_RULES {
        return corrupt("rule count exceeds limit");
    }
    let mut entries = Vec::with_capacity(n);
    let mut expected = hdr.len() as u64;
    let mut seen: HashSet<u32> = HashSet::new();
    for i in 0..n {
        let b = FIXED + ENTRY * i;
        let ty = u32at(b);
        if u32at(b + 4) != 0 {
            return corrupt("reserved field is not zero");
        }
        let (offset, length) = (u64at(b + 8), u64at(b + 16));
        let known = matches!(ty, T_SOURCES | T_FAMILIES | T_ARENA | T_LEGACY | T_NDB | T_LDB) || (0x100..=0x108).contains(&ty);
        if !known {
            return corrupt(format!("unknown section type {ty:#x}"));
        }
        if !seen.insert(ty) {
            return corrupt("duplicate section type");
        }
        if length > MAX_SECTION_BYTES || offset != expected {
            return corrupt("sections are not contiguous or are too large");
        }
        expected = expected.checked_add(length).ok_or_else(|| Error::Corrupt("section overflow".into()))?;
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&hdr[b + 24..b + 56]);
        entries.push(Entry { ty, offset, length, sha });
    }
    if expected != total {
        return corrupt("file length does not match the section table (truncated or trailing data)");
    }
    Ok(Header { serial: u64at(16), created: u64at(24), min_engine: u32at(32), rule_count, entries })
}

fn read_section<R: Read + Seek>(r: &mut R, base: u64, e: &Entry) -> Result<Vec<u8>, Error> {
    r.seek(SeekFrom::Start(base + e.offset))?;
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(e.length as usize).map_err(|_| Error::Corrupt("cannot allocate memory for a database section".into()))?;
    let mut h = Sha256::new();
    let mut chunk = vec![0u8; 1 << 20];
    let mut left = e.length;
    while left > 0 {
        let n = (left as usize).min(chunk.len());
        r.read_exact(&mut chunk[..n]).map_err(io_err)?;
        h.update(&chunk[..n]);
        v.extend_from_slice(&chunk[..n]);
        left -= n as u64;
    }
    let got: [u8; 32] = h.finalize().into();
    if got != e.sha {
        return corrupt("section hash mismatch: database is damaged or was modified");
    }
    Ok(v)
}

fn read_header_bytes<R: Read + Seek>(r: &mut R, base: u64) -> Result<(Vec<u8>, u64), Error> {
    let end = r.seek(SeekFrom::End(0))?;
    let total = end.checked_sub(base).ok_or_else(|| Error::Corrupt("bundle shorter than its signature line".into()))?;
    if total < FIXED as u64 {
        return corrupt("database file is truncated");
    }
    r.seek(SeekFrom::Start(base))?;
    let mut pre = [0u8; 16];
    r.read_exact(&mut pre).map_err(io_err)?;
    if &pre[..8] != MAGIC {
        return corrupt("not a binary Litric database");
    }
    let hl = u32::from_le_bytes([pre[8], pre[9], pre[10], pre[11]]) as usize;
    if !(FIXED..=FIXED + ENTRY * MAX_SECTIONS).contains(&hl) || hl as u64 > total {
        return corrupt("header length out of range");
    }
    let mut hdr = vec![0u8; hl];
    hdr[..16].copy_from_slice(&pre);
    r.read_exact(&mut hdr[16..]).map_err(io_err)?;
    Ok((hdr, total))
}

/// Verify authenticity and integrity only (no decoding): signature over the
/// header, then every section hash, streaming.
pub fn verify_only<R: Read + Seek>(r: &mut R, base: u64, sig_line: &str, keys: &TrustedKeys) -> Result<(u64, u32), Error> {
    let (hdr, total) = read_header_bytes(r, base)?;
    verify_signature(&hdr, sig_line, keys)?;
    let h = parse_header(&hdr, total)?;
    for e in &h.entries {
        read_section(r, base, e)?;
    }
    Ok((h.serial, h.min_engine))
}

/// Load a binary database. `verify = Some((signature line, keys))` checks the
/// signature BEFORE any field of the header is trusted; `None` skips it (tests,
/// or callers that verified separately).
pub fn load<R: Read + Seek>(r: &mut R, base: u64, verify: Option<(&str, &TrustedKeys)>) -> Result<Database, Error> {
    let (hdr, total) = read_header_bytes(r, base)?;
    if let Some((sig, keys)) = verify {
        verify_signature(&hdr, sig, keys)?;
    }
    let h = parse_header(&hdr, total)?;
    decode(r, base, &h)
}

pub fn load_bytes(bytes: &[u8], verify: Option<(&str, &TrustedKeys)>) -> Result<Database, Error> {
    load(&mut std::io::Cursor::new(bytes), 0, verify)
}

fn find<'a>(h: &'a Header, ty: u32) -> Option<&'a Entry> {
    h.entries.iter().find(|e| e.ty == ty)
}

fn read_meta(b: &[u8], nfam: usize, arena_len: usize) -> Result<Meta, Error> {
    let family = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let id_off = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let (id_len, sev, conf, pad) = (b[8], b[9], b[10], b[11]);
    if family as usize >= nfam || pad != 0 || sev > 3 || conf > 100 || id_len == 0 || id_len > 64 {
        return corrupt("rule metadata out of range");
    }
    if (id_off as usize).checked_add(id_len as usize).map_or(true, |e| e > arena_len) {
        return corrupt("rule id range lies outside the id arena");
    }
    Ok(Meta { family, id_off, id_len, sev, conf })
}

fn decode_table(raw: &[u8], klen: usize, with_meta: bool, nfam: usize, arena_len: usize) -> Result<HashTable, Error> {
    if raw.len() < 8 {
        return corrupt("table section too short");
    }
    let count = u64::from_le_bytes(raw[..8].try_into().unwrap());
    if count > MAX_BIN_RULES {
        return corrupt("table count exceeds limit");
    }
    let per = klen as u64 + 4 + if with_meta { 12 } else { 0 };
    let expect = count.checked_mul(per).and_then(|v| v.checked_add(8));
    if expect != Some(raw.len() as u64) {
        return corrupt("table length does not match its entry count");
    }
    let n = count as usize;
    let mut t = HashTable::with_klen(klen);
    t.keys = raw[8..8 + n * klen].to_vec();
    let sz = &raw[8 + n * klen..8 + n * (klen + 4)];
    t.sizes = sz.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    if with_meta {
        let mb = &raw[8 + n * (klen + 4)..];
        t.meta.reserve_exact(n);
        for c in mb.chunks_exact(12) {
            t.meta.push(read_meta(c, nfam, arena_len)?);
        }
    } else {
        t.meta = vec![Meta::default(); n];
    }
    for i in 1..n {
        let ord = t.key(i - 1).cmp(t.key(i)).then(t.sizes[i - 1].cmp(&t.sizes[i]));
        if ord != std::cmp::Ordering::Less {
            return corrupt("hash table is not strictly sorted (or has duplicates)");
        }
    }
    Ok(t)
}

fn decode_ndb(raw: &[u8], nfam: usize, arena_len: usize) -> Result<Vec<NdbRule>, Error> {
    if raw.len() < 8 {
        return corrupt("extended-signature section too short");
    }
    let count = u64::from_le_bytes(raw[..8].try_into().unwrap());
    if count > MAX_BIN_RULES {
        return corrupt("extended-signature count exceeds limit");
    }
    let mut out: Vec<NdbRule> = Vec::new();
    out.try_reserve_exact((count as usize).min(raw.len() / 33)).map_err(|_| Error::Corrupt("allocation".into()))?;
    let mut p = 8usize;
    for _ in 0..count {
        // meta(12) target(1) tag(1) value(8) aux(4) maxshift(4) code_len(4) = 34
        let rec = raw.get(p..p + 34).ok_or_else(|| Error::Corrupt("extended-signature record truncated".into()))?;
        let meta = read_meta(&rec[..12], nfam, arena_len)?;
        let target = target_from(rec[12]).ok_or_else(|| Error::Corrupt("invalid extended-signature target".into()))?;
        let tag = rec[13];
        let val = u64::from_le_bytes(rec[14..22].try_into().unwrap());
        let aux = u32::from_le_bytes(rec[22..26].try_into().unwrap());
        let maxshift = u32::from_le_bytes(rec[26..30].try_into().unwrap());
        let code_len = u32::from_le_bytes(rec[30..34].try_into().unwrap()) as usize;
        let code = raw.get(p + 34..p + 34 + code_len).ok_or_else(|| Error::Corrupt("extended-signature bytecode truncated".into()))?;
        p += 34 + code_len;
        let offset = decode_offset(tag, val, aux, maxshift, target)?;
        ndb::validate_code(code).map_err(|e| Error::Corrupt(format!("extended-signature bytecode: {e}")))?;
        if ndb::anchor_of_code(code).is_none() && !offset.is_positional() {
            return corrupt("extended signature cannot be located (no anchor and no exact offset)");
        }
        out.push(NdbRule { meta, target, offset, code: code.to_vec().into_boxed_slice() });
    }
    if p != raw.len() {
        return corrupt("trailing bytes in extended-signature section");
    }
    Ok(out)
}

fn decode_ldb(raw: &[u8], nfam: usize, arena_len: usize) -> Result<Vec<LdbRule>, Error> {
    let mut rd = Rd { b: raw, p: 0 };
    let count = rd.u64()?;
    if count > MAX_BIN_RULES {
        return corrupt("logical-signature count exceeds limit");
    }
    let mut out: Vec<LdbRule> = Vec::new();
    out.try_reserve_exact((count as usize).min(raw.len() / 20)).map_err(|_| Error::Corrupt("allocation".into()))?;
    for _ in 0..count {
        let meta = read_meta(rd.take(12)?, nfam, arena_len)?;
        let target = target_from(rd.u8()?).ok_or_else(|| Error::Corrupt("invalid logical-signature target".into()))?;
        let flags = rd.u8()?;
        if flags & !0b11 != 0 {
            return corrupt("invalid constraint flags");
        }
        let mut c = ldb::Constraints::default();
        for (bit, slot) in [(1u8, &mut c.filesize), (2u8, &mut c.sections)] {
            if flags & bit != 0 {
                let (a, b) = (rd.u64()?, rd.u64()?);
                if a > b {
                    return corrupt("constraint range min exceeds max");
                }
                *slot = Some((a, b));
            }
        }
        let el = rd.u16()? as usize;
        if el == 0 || el > ldb::MAX_EXPR_CHARS {
            return corrupt("expression length out of range");
        }
        let expr_text = std::str::from_utf8(rd.take(el)?).map_err(|_| Error::Corrupt("expression is not UTF-8".into()))?.to_string();
        let expr = ldb::parse_expr(&expr_text).map_err(|e| Error::Corrupt(format!("logical expression: {e}")))?;
        let nsub = rd.u8()? as usize;
        if nsub == 0 || nsub > ldb::MAX_SUBSIGS || expr.max_index() as usize >= nsub {
            return corrupt("subsignature count out of range or expression refers past it");
        }
        let mut subs = Vec::with_capacity(nsub);
        for _ in 0..nsub {
            let (tag, val, aux, maxshift, cl) = (rd.u8()?, rd.u64()?, rd.u32()?, rd.u32()?, rd.u32()? as usize);
            let code = rd.take(cl)?;
            let offset = decode_offset(tag, val, aux, maxshift, target)?;
            ndb::validate_code(code).map_err(|e| Error::Corrupt(format!("subsignature bytecode: {e}")))?;
            if ndb::anchor_of_code(code).is_none() && !offset.is_positional() {
                return corrupt("subsignature cannot be located (no anchor and no exact offset)");
            }
            subs.push(LdbSub { offset, code: code.to_vec().into_boxed_slice() });
        }
        out.push(LdbRule { meta, target, constraints: c, expr_text, expr, subs });
    }
    if rd.p != raw.len() {
        return corrupt("trailing bytes in logical-signature section");
    }
    Ok(out)
}

fn decode<R: Read + Seek>(r: &mut R, base: u64, h: &Header) -> Result<Database, Error> {
    if h.min_engine > ENGINE_VERSION {
        return Err(Error::EngineTooOld { need: h.min_engine });
    }
    let mut db = Database { version: 3, serial: h.serial, created: h.created, min_engine: h.min_engine, ..Default::default() };
    // families
    if let Some(e) = find(h, T_FAMILIES) {
        let raw = read_section(r, base, e)?;
        if raw.len() < 4 {
            return corrupt("family table too short");
        }
        let n = u32::from_le_bytes(raw[..4].try_into().unwrap());
        if n > MAX_FAMILIES {
            return corrupt("too many families");
        }
        let mut p = 4usize;
        for _ in 0..n {
            let l = *raw.get(p).ok_or_else(|| Error::Corrupt("family table truncated".into()))? as usize;
            let b = raw.get(p + 1..p + 1 + l).ok_or_else(|| Error::Corrupt("family table truncated".into()))?;
            let s = std::str::from_utf8(b).map_err(|_| Error::Corrupt("family name is not UTF-8".into()))?;
            if !valid_name(s) {
                return corrupt("invalid family name");
            }
            db.families.push(s.to_string());
            p += 1 + l;
        }
        if p != raw.len() {
            return corrupt("trailing bytes in family table");
        }
    }
    // id arena (every byte must be an identifier character, so any slice is a valid id)
    if let Some(e) = find(h, T_ARENA) {
        let raw = read_section(r, base, e)?;
        if raw.len() > u32::MAX as usize || !raw.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) {
            return corrupt("id arena contains invalid bytes");
        }
        db.id_arena = String::from_utf8(raw).map_err(|_| Error::Corrupt("id arena".into()))?;
    }
    let (nfam, alen) = (db.families.len(), db.id_arena.len());
    if let Some(e) = find(h, T_SOURCES) {
        let raw = read_section(r, base, e)?;
        let text = String::from_utf8(raw).map_err(|_| Error::Corrupt("sources are not UTF-8".into()))?;
        for l in text.split('\n') {
            if l.is_empty() || l.len() > 200 || l.chars().any(|c| c.is_control()) || db.sources.len() >= MAX_SOURCES {
                return corrupt("invalid source line");
            }
            db.sources.push(l.to_string());
        }
    }
    if let Some(e) = find(h, T_LEGACY) {
        let raw = read_section(r, base, e)?;
        if raw.len() > 64 << 20 {
            return corrupt("legacy section too large");
        }
        let text = String::from_utf8(raw).map_err(|_| Error::Corrupt("legacy records are not UTF-8".into()))?;
        let mut n_rules = 0usize;
        for l in text.split('\n') {
            match l.split(' ').next() {
                Some("H" | "P") => n_rules += 1,
                Some("A" | "R") => {}
                _ => return corrupt("unexpected record in legacy section"),
            }
        }
        let wrapped = format!("LITRIC-SIGDB 2\nserial 0\ncreated 0\nmin-engine 1\nrule-count {n_rules}\n{text}\nEND\n");
        let legacy = Database::parse(wrapped.as_bytes())?;
        db.hash_rules = legacy.hash_rules;
        db.patterns = legacy.patterns;
        db.allow = legacy.allow;
        db.revoked = legacy.revoked;
    }
    for (kind, with_meta) in [(0u32, true), (1, true), (2, false)] {
        for a in ALGOS {
            if let Some(e) = find(h, t_table(kind, a.idx() as u32)) {
                let raw = read_section(r, base, e)?;
                let t = decode_table(&raw, a.len(), with_meta, nfam, alen)?;
                match kind {
                    0 => db.file_tables[a.idx()] = t,
                    1 => db.section_tables[a.idx()] = t,
                    _ => db.allow_tables[a.idx()] = t,
                }
            }
        }
    }
    if let Some(e) = find(h, T_NDB) {
        let raw = read_section(r, base, e)?;
        db.ndb = decode_ndb(&raw, nfam, alen)?;
    }
    if let Some(e) = find(h, T_LDB) {
        let raw = read_section(r, base, e)?;
        db.ldb = decode_ldb(&raw, nfam, alen)?;
    }
    // Every known section type is read (and therefore hash-verified) above.
    if db.rule_count() as u64 != h.rule_count {
        return corrupt("header rule count does not match the decoded rules");
    }
    Ok(db)
}
