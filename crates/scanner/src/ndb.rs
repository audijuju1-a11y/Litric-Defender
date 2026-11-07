//! Matching engine for ClamAV-style extended (NDB) signatures.
//! OWNERSHIP: Litric implementation of the documented syntax subset
//! (see `sigdb::ndb`). Not libclamav, and not verified against it.
//!
//! Strategy: hashed 2/3/4-byte key tables over each signature's exact-byte
//! anchor, then a bounded backtracking verifier for wildcards/gaps/alternatives.
//! Every verification step is charged to a per-file budget; when it runs out
//! the caller must report the file as incompletely scanned.

use sigdb::ndb::{anchor_of_code, op_len, rd_u32, Base, Offset, OP_ALT, OP_ANY, OP_BYTE, OP_GAP, OP_MASK};
use sigdb::{LdbRule, NdbRule, Target};
use std::collections::{HashMap, HashSet};

pub struct Exceeded;

/// PE facts needed to resolve EP / section offsets.
pub struct PeCtx {
    pub entry_offset: Option<u64>,
    pub section_starts: Vec<u64>,
}

/// Allowed signature start positions [lo, hi] (inclusive), or None if the
/// offset cannot be resolved for this file (then the signature cannot match).
pub fn window(off: &Offset, len: u64, pe: Option<&PeCtx>) -> Option<(u64, u64)> {
    let base: u64 = match &off.base {
        Base::Anywhere => return Some((0, len)),
        Base::Abs(n) => *n,
        Base::Eof(n) => len.checked_sub(*n)?,
        Base::Ep(d) => {
            let e = i64::try_from(pe?.entry_offset?).ok()?;
            let v = e.checked_add(*d)?;
            u64::try_from(v).ok()?
        }
        Base::Section(k, n) => pe?.section_starts.get(*k as usize)?.checked_add(*n)?,
        Base::LastSection(n) => pe?.section_starts.last()?.checked_add(*n)?,
    };
    Some((base, base.saturating_add(off.maxshift as u64)))
}

fn tick(b: &mut i64, n: i64) -> Result<(), Exceeded> {
    *b -= n;
    if *b < 0 {
        Err(Exceeded)
    } else {
        Ok(())
    }
}

/// Does the signature bytecode match with its first byte exactly at `start`?
pub fn match_at(code: &[u8], data: &[u8], start: usize, budget: &mut i64) -> Result<bool, Exceeded> {
    go(code, data, start, budget)
}

fn go(code: &[u8], data: &[u8], mut pos: usize, budget: &mut i64) -> Result<bool, Exceeded> {
    let mut i = 0usize;
    while i < code.len() {
        // Bytecode is validated at load time; a malformed instruction simply cannot match.
        let Some(l) = op_len(code, i) else { return Ok(false) };
        match code[i] {
            OP_BYTE => {
                if data.get(pos) != code.get(i + 1) {
                    return Ok(false);
                }
                pos += 1;
            }
            OP_MASK => match (data.get(pos), code.get(i + 1), code.get(i + 2)) {
                (Some(d), Some(v), Some(m)) if d & m == *v => pos += 1,
                _ => return Ok(false),
            },
            OP_ALT => {
                let rest = &code[i + l..];
                let n = u16::from_le_bytes([code[i + 1], code[i + 2]]) as usize;
                let mut p = i + 3;
                for _ in 0..n {
                    let al = u16::from_le_bytes([code[p], code[p + 1]]) as usize;
                    let alt = &code[p + 2..p + 2 + al];
                    p += 2 + al;
                    tick(budget, 1)?;
                    if data.get(pos..).map_or(false, |d| d.starts_with(alt)) && go(rest, data, pos + al, budget)? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            OP_ANY => {
                let rest = &code[i + 1..];
                let next_byte = if rest.first() == Some(&OP_BYTE) { rest.get(1).copied() } else { None };
                let mut s = pos;
                while s <= data.len() {
                    if let Some(b) = next_byte {
                        match data[s..].iter().position(|x| *x == b) {
                            Some(o) => {
                                tick(budget, (o / 16) as i64)?;
                                s += o;
                            }
                            None => return Ok(false),
                        }
                    }
                    tick(budget, 1)?;
                    if go(rest, data, s, budget)? {
                        return Ok(true);
                    }
                    s += 1;
                }
                return Ok(false);
            }
            OP_GAP => {
                let (Some(min), Some(maxraw)) = (rd_u32(code, i + 1), rd_u32(code, i + 5)) else { return Ok(false) };
                let rest = &code[i + 9..];
                let remaining = data.len().saturating_sub(pos);
                let hi = if maxraw == u32::MAX { remaining } else { (maxraw as usize).min(remaining) };
                let mut sh = min as usize;
                while sh <= hi {
                    tick(budget, 1)?;
                    if go(rest, data, pos + sh, budget)? {
                        return Ok(true);
                    }
                    sh += 1;
                }
                return Ok(false);
            }
            _ => return Ok(false),
        }
        i += l;
    }
    Ok(true)
}

/// Prefilter tables keyed by the first 2, 3 or 4 bytes of each signature's anchor.
/// A rolling window is tested against a bitset per table (cheap, cache-friendly);
/// only bitset hits touch the hash map. Candidates are always verified in full by
/// `match_at`, so sharing a key between many signatures costs time, never correctness.
#[derive(Default)]
struct KeyTable {
    bits: Vec<u64>,
    shift: u32,
    /// key -> [(rule index, anchor offset from signature start)]
    map: HashMap<u32, Vec<(u32, u32)>>,
}

impl KeyTable {
    fn with_bits(log2_bits: u32) -> Self {
        Self { bits: vec![0u64; 1usize << (log2_bits.saturating_sub(6))], shift: 32 - log2_bits, map: HashMap::new() }
    }
    #[inline]
    fn slot(&self, key: u32) -> (usize, u64) {
        let h = if self.shift == 0 { key } else { key.wrapping_mul(0x9E37_79B1) >> self.shift };
        ((h >> 6) as usize, 1u64 << (h & 63))
    }
    fn insert(&mut self, key: u32, v: (u32, u32)) {
        let (w, b) = self.slot(key);
        self.bits[w] |= b;
        self.map.entry(key).or_default().push(v);
    }
    #[inline]
    fn maybe(&self, key: u32) -> bool {
        let (w, b) = self.slot(key);
        self.bits[w] & b != 0
    }
}

/// Table value: rule index, or (LDB_BIT | sub-entry index) for logical subsignatures.
const LDB_BIT: u32 = 0x8000_0000;
const MAX_COUNT: u32 = 1 << 20;

/// Results of one scan over the extended and logical rules.
#[derive(Default)]
pub struct ScanOut {
    /// Indices of matching extended (NDB) rules.
    pub ndb_hits: Vec<u32>,
    /// Logical rule index -> match count per subsignature (only rules with at least one match).
    pub ldb_counts: HashMap<u32, Vec<u32>>,
}

pub struct NdbIndex {
    t2: Option<KeyTable>,
    t3: Option<KeyTable>,
    t4: Option<KeyTable>,
    /// extended rules without an anchor (exact-offset only)
    positional: Vec<u32>,
    /// logical subsignatures: (rule index, subsignature index)
    sub_entries: Vec<(u32, u8)>,
    /// sub-entry indices without an anchor (exact-offset only)
    positional_subs: Vec<u32>,
}

fn insert_by_anchor(t: &mut [Option<KeyTable>; 3], bytes: &[u8], off: usize, id: u32) {
    let v = (id, off as u32);
    match bytes.len() {
        2 => t[0].get_or_insert_with(|| KeyTable::with_bits(16)).insert(u32::from(bytes[0]) << 8 | u32::from(bytes[1]), v),
        3 => t[1].get_or_insert_with(|| KeyTable::with_bits(24)).insert(u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]), v),
        _ => t[2].get_or_insert_with(|| KeyTable::with_bits(22)).insert(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), v),
    }
}

impl NdbIndex {
    pub fn build(rules: &[NdbRule], logical: &[LdbRule]) -> (Self, Option<String>) {
        let mut tables: [Option<KeyTable>; 3] = [None, None, None];
        let (mut positional, mut sub_entries, mut positional_subs) = (vec![], vec![], vec![]);
        for (i, r) in rules.iter().enumerate() {
            match anchor_of_code(&r.code) {
                Some((off, bytes)) => insert_by_anchor(&mut tables, &bytes, off, i as u32),
                None => positional.push(i as u32),
            }
        }
        for (ri, rule) in logical.iter().enumerate() {
            for (si, sub) in rule.subs.iter().enumerate() {
                let entry = sub_entries.len() as u32;
                sub_entries.push((ri as u32, si as u8));
                match anchor_of_code(&sub.code) {
                    Some((off, bytes)) => insert_by_anchor(&mut tables, &bytes, off, LDB_BIT | entry),
                    None => positional_subs.push(entry),
                }
            }
        }
        let [t2, t3, t4] = tables;
        (Self { t2, t3, t4, positional, sub_entries, positional_subs }, None)
    }

    /// Err(Exceeded) = the work budget ran out; `out` holds what was found so far.
    #[allow(clippy::too_many_arguments)]
    pub fn scan(&self, rules: &[NdbRule], logical: &[LdbRule], data: &[u8], kind: Target, pe: Option<&PeCtx>, budget: &mut i64, out: &mut ScanOut) -> Result<(), Exceeded> {
        let len = data.len() as u64;
        let sections = pe.map(|p| p.section_starts.len() as u64);
        let applies = |t: Target| t == Target::Any || t == kind;
        let mut done: HashSet<u32> = HashSet::new();
        let mut candidate = |id: u32, off: u32, anchor_start: usize, budget: &mut i64, out: &mut ScanOut| -> Result<(), Exceeded> {
            tick(budget, 1)?;
            let Some(start) = anchor_start.checked_sub(off as usize) else { return Ok(()) };
            if id & LDB_BIT == 0 {
                if done.contains(&id) {
                    return Ok(());
                }
                let r = &rules[id as usize];
                if !applies(r.target) {
                    return Ok(());
                }
                let Some((lo, hi)) = window(&r.offset, len, pe) else { return Ok(()) };
                if (start as u64) < lo || (start as u64) > hi {
                    return Ok(());
                }
                if match_at(&r.code, data, start, budget)? {
                    done.insert(id);
                    out.ndb_hits.push(id);
                }
            } else {
                let (ri, si) = self.sub_entries[(id & !LDB_BIT) as usize];
                let rule = &logical[ri as usize];
                if !applies(rule.target) || !rule.constraints.check(len, sections) {
                    return Ok(());
                }
                let sub = &rule.subs[si as usize];
                let Some((lo, hi)) = window(&sub.offset, len, pe) else { return Ok(()) };
                if (start as u64) < lo || (start as u64) > hi {
                    return Ok(());
                }
                if match_at(&sub.code, data, start, budget)? {
                    let counts = out.ldb_counts.entry(ri).or_insert_with(|| vec![0; rule.subs.len()]);
                    counts[si as usize] = (counts[si as usize] + 1).min(MAX_COUNT);
                }
            }
            Ok(())
        };
        if self.t2.is_some() || self.t3.is_some() || self.t4.is_some() {
            let mut w: u32 = 0;
            for (j, &byte) in data.iter().enumerate() {
                w = (w << 8) | u32::from(byte);
                if let Some(t) = &self.t2 {
                    if j >= 1 && t.maybe(w & 0xFFFF) {
                        if let Some(v) = t.map.get(&(w & 0xFFFF)) {
                            for &(id, off) in v {
                                candidate(id, off, j - 1, budget, out)?;
                            }
                        }
                    }
                }
                if let Some(t) = &self.t3 {
                    if j >= 2 && t.maybe(w & 0xFF_FFFF) {
                        if let Some(v) = t.map.get(&(w & 0xFF_FFFF)) {
                            for &(id, off) in v {
                                candidate(id, off, j - 2, budget, out)?;
                            }
                        }
                    }
                }
                if let Some(t) = &self.t4 {
                    if j >= 3 && t.maybe(w) {
                        if let Some(v) = t.map.get(&w) {
                            for &(id, off) in v {
                                candidate(id, off, j - 3, budget, out)?;
                            }
                        }
                    }
                }
            }
        }
        for &ri in &self.positional {
            tick(budget, 1)?;
            let r = &rules[ri as usize];
            if !applies(r.target) {
                continue;
            }
            let Some((lo, _)) = window(&r.offset, len, pe) else { continue };
            if lo <= len && match_at(&r.code, data, lo as usize, budget)? {
                out.ndb_hits.push(ri);
            }
        }
        for &entry in &self.positional_subs {
            tick(budget, 1)?;
            let (ri, si) = self.sub_entries[entry as usize];
            let rule = &logical[ri as usize];
            if !applies(rule.target) || !rule.constraints.check(len, sections) {
                continue;
            }
            let sub = &rule.subs[si as usize];
            let Some((lo, _)) = window(&sub.offset, len, pe) else { continue };
            if lo <= len && match_at(&sub.code, data, lo as usize, budget)? {
                let counts = out.ldb_counts.entry(ri).or_insert_with(|| vec![0; rule.subs.len()]);
                counts[si as usize] = (counts[si as usize] + 1).min(MAX_COUNT);
            }
        }
        Ok(())
    }
}
