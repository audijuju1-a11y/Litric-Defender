//! ClamAV-style extended (NDB) signature syntax: parser and data model.
//! OWNERSHIP: Litric implementation of the publicly documented text syntax.
//! Only the subset below is accepted; everything else is rejected with an
//! explicit `Unsupported` reason so importers can report it.
//!
//! Supported hex syntax: `aa` exact byte, `??` any byte, `a?`/`?a` nibble,
//! `*` any run of bytes, `{n}` `{n-m}` `{-m}` `{n-}` gaps, `(aa|bbcc)` alternatives
//! (exact bytes only). Unsupported: `!(..)`, `(B)`, `(L)`, `[n-m]`.
//! Offsets: `*`, `N`, `EOF-N`, `EP+N`, `EP-N`, `S<k>+N`, `SL+N`, each with optional `,maxshift`.

use std::fmt;

pub const MAX_SIG_CHARS: usize = 8192;
pub const MAX_WILDCARD_SEGMENTS: usize = 64;
const MAX_GAP: u64 = 1 << 24;
const MAX_ALTS: usize = 256;
const MAX_SHIFT: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Byte(u8),
    Masked { val: u8, mask: u8 },
    /// Alternatives of exact byte strings.
    Alt(Vec<Vec<u8>>),
    /// `*`: any number of bytes (including zero).
    Any,
    Gap { min: u32, max: Option<u32> },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Base {
    Anywhere,
    Abs(u64),
    /// Entry point (file offset) plus a signed delta. PE only.
    Ep(i64),
    /// Start of section k (0-based) plus n. PE only.
    Section(u32, u64),
    /// Start of the last section plus n. PE only.
    LastSection(u64),
    /// n bytes before end of file.
    Eof(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Offset {
    pub base: Base,
    /// The signature may start anywhere in [base, base + maxshift].
    pub maxshift: u32,
}

impl Offset {
    pub fn needs_pe(&self) -> bool {
        matches!(self.base, Base::Ep(_) | Base::Section(..) | Base::LastSection(_))
    }
    /// Exactly one possible start position (no anchor search needed).
    pub fn is_positional(&self) -> bool {
        !matches!(self.base, Base::Anywhere) && self.maxshift == 0
    }
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub toks: Vec<Tok>,
    /// (byte offset from signature start, exact bytes >= 2) inside the fixed-width
    /// prefix; used as the search prefilter.
    pub anchor: Option<(usize, Vec<u8>)>,
}

#[derive(Debug)]
pub enum SigError {
    Malformed(String),
    Unsupported(String),
}
impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigError::Malformed(m) => write!(f, "malformed: {m}"),
            SigError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}
fn mal<T>(m: impl Into<String>) -> Result<T, SigError> {
    Err(SigError::Malformed(m.into()))
}
fn uns<T>(m: impl Into<String>) -> Result<T, SigError> {
    Err(SigError::Unsupported(m.into()))
}

pub fn parse_offset(s: &str) -> Result<Offset, SigError> {
    let (main, shift) = match s.split_once(',') {
        Some((m, sh)) => {
            let v: u64 = sh.parse().or_else(|_| mal("maxshift is not a number"))?;
            if v > MAX_SHIFT {
                return mal("maxshift too large");
            }
            (m, v as u32)
        }
        None => (s, 0),
    };
    let num = |t: &str| -> Result<u64, SigError> { t.parse().or_else(|_| mal("offset is not a number")) };
    let base = if main == "*" {
        if shift != 0 {
            return mal("`*` offset cannot have a maxshift");
        }
        Base::Anywhere
    } else if main.starts_with("VI") {
        return uns("version-info (VI) offset");
    } else if let Some(r) = main.strip_prefix("EOF-") {
        Base::Eof(num(r)?)
    } else if let Some(r) = main.strip_prefix("EP+") {
        Base::Ep(num(r)? as i64)
    } else if let Some(r) = main.strip_prefix("EP-") {
        Base::Ep(-(num(r)? as i64))
    } else if let Some(r) = main.strip_prefix("SL+") {
        Base::LastSection(num(r)?)
    } else if main.starts_with('S') && main[1..].chars().next().map_or(false, |c| c.is_ascii_digit()) {
        let rest = &main[1..];
        match rest.split_once('+') {
            Some((k, n)) => Base::Section(num(k)?.try_into().or_else(|_| mal("section index too large"))?, num(n)?),
            None => return uns("section offset without `+n` form"),
        }
    } else if main.starts_with("SE") || main.starts_with("SL-") || main.contains("-") && main.starts_with('S') {
        return uns("section-end / negative section offsets");
    } else if main.bytes().all(|b| b.is_ascii_digit()) && !main.is_empty() {
        Base::Abs(num(main)?)
    } else {
        return mal("unrecognised offset");
    };
    if matches!(base, Base::Eof(_)) && shift != 0 {
        return uns("EOF offset with maxshift");
    }
    Ok(Offset { base, maxshift: shift })
}

fn nib(c: u8) -> Option<(u8, u8)> {
    match c {
        b'?' => Some((0, 0)),
        _ => (c as char).to_digit(16).map(|d| (d as u8, 0xF)),
    }
}

pub fn parse_sig(s: &str) -> Result<Sig, SigError> {
    if s.is_empty() || s.len() > MAX_SIG_CHARS {
        return mal(format!("signature must be 1..={MAX_SIG_CHARS} characters"));
    }
    let b = s.as_bytes();
    let mut toks: Vec<Tok> = vec![];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'*' => {
                toks.push(Tok::Any);
                i += 1;
            }
            b'{' => {
                let Some(end) = s[i..].find('}').map(|e| i + e) else { return mal("unterminated `{`") };
                let inner = &s[i + 1..end];
                let num = |t: &str| -> Result<u64, SigError> {
                    let v: u64 = t.parse().or_else(|_| mal("gap bound is not a number"))?;
                    if v > MAX_GAP { return mal("gap bound too large"); }
                    Ok(v)
                };
                let (min, max) = match inner.split_once('-') {
                    None => {
                        let n = num(inner)?;
                        (n, Some(n))
                    }
                    Some(("", "")) => return mal("empty gap `{-}`"),
                    Some((a, "")) => (num(a)?, None),
                    Some(("", m)) => (0, Some(num(m)?)),
                    Some((a, m)) => {
                        let (a, m) = (num(a)?, num(m)?);
                        if a > m { return mal("gap min exceeds max"); }
                        (a, Some(m))
                    }
                };
                toks.push(Tok::Gap { min: min as u32, max: max.map(|m| m as u32) });
                i = end + 1;
            }
            b'(' => {
                let Some(end) = s[i..].find(')').map(|e| i + e) else { return mal("unterminated `(`") };
                let inner = &s[i + 1..end];
                if inner == "B" || inner == "L" {
                    return uns("word-boundary markers (B)/(L)");
                }
                if !inner.bytes().all(|c| c == b'|' || c.is_ascii_hexdigit()) {
                    return uns("alternatives containing wildcards or other syntax");
                }
                let mut alts = vec![];
                for part in inner.split('|') {
                    if part.is_empty() || part.len() % 2 != 0 {
                        return mal("alternative must be a non-empty even-length hex string");
                    }
                    alts.push(crate::hex_decode(part).ok_or_else(|| SigError::Malformed("bad hex in alternative".into()))?);
                }
                if alts.len() > MAX_ALTS {
                    return mal("too many alternatives");
                }
                toks.push(Tok::Alt(alts));
                i = end + 1;
            }
            b'!' => return if b.get(i + 1) == Some(&b'(') { uns("negated alternatives !(..)") } else { mal("stray `!`") },
            b'[' => return uns("anchored byte range [n-m]"),
            c => {
                let (Some((v1, m1)), Some((v2, m2))) = (nib(c), b.get(i + 1).copied().and_then(nib)) else {
                    return mal("invalid character or odd number of hex digits");
                };
                let (val, mask) = ((v1 << 4) | v2, (m1 << 4) | m2);
                toks.push(if mask == 0xFF { Tok::Byte(val) } else { Tok::Masked { val, mask } });
                i += 2;
            }
        }
    }
    if matches!(toks.first(), Some(Tok::Any | Tok::Gap { .. })) || matches!(toks.last(), Some(Tok::Any | Tok::Gap { .. })) {
        return mal("signature may not start or end with a wildcard gap");
    }
    let wild = toks.iter().filter(|t| matches!(t, Tok::Any | Tok::Gap { .. } | Tok::Alt(_))).count();
    if wild > MAX_WILDCARD_SEGMENTS {
        return uns(format!("more than {MAX_WILDCARD_SEGMENTS} gap/alternative segments"));
    }
    // anchor: longest run (>=2) of exact bytes inside the fixed-width prefix
    let (mut pos, mut best, mut run, mut run_start): (usize, Option<(usize, Vec<u8>)>, Vec<u8>, usize) = (0, None, vec![], 0);
    let flush = |run: &mut Vec<u8>, start: usize, best: &mut Option<(usize, Vec<u8>)>| {
        if run.len() >= 2 && best.as_ref().map_or(true, |b| run.len() > b.1.len()) {
            *best = Some((start, run.clone()));
        }
        run.clear();
    };
    for t in &toks {
        match t {
            Tok::Byte(x) => {
                if run.is_empty() {
                    run_start = pos;
                }
                run.push(*x);
                pos += 1;
            }
            Tok::Masked { .. } => {
                flush(&mut run, run_start, &mut best);
                pos += 1;
            }
            Tok::Alt(a) if a.iter().all(|x| x.len() == a[0].len()) => {
                flush(&mut run, run_start, &mut best);
                pos += a[0].len();
            }
            _ => break,
        }
    }
    flush(&mut run, run_start, &mut best);
    Ok(Sig { toks, anchor: best })
}

/// A signature is usable only if it can be located: an anchor to search for,
/// or a single exact start position.
pub fn locatable(sig: &Sig, off: &Offset) -> Result<(), SigError> {
    if sig.anchor.is_none() && !off.is_positional() {
        return uns("no exact-byte anchor (>= 2 bytes) in the fixed prefix and no exact offset");
    }
    Ok(())
}

// ------------------------------------------------------------------ bytecode
// Compact in-memory / on-disk encoding of a parsed signature:
//   0x01 b            exact byte
//   0x02 val mask     masked byte
//   0x03              any run of bytes (`*`)
//   0x04 min:u32 max:u32   gap; max == u32::MAX means unbounded
//   0x05 n:u16 { len:u16 bytes }*n   alternatives

pub const OP_BYTE: u8 = 1;
pub const OP_MASK: u8 = 2;
pub const OP_ANY: u8 = 3;
pub const OP_GAP: u8 = 4;
pub const OP_ALT: u8 = 5;

pub fn compile(toks: &[Tok]) -> Vec<u8> {
    let mut c = Vec::with_capacity(toks.len() * 2);
    for t in toks {
        match t {
            Tok::Byte(b) => c.extend_from_slice(&[OP_BYTE, *b]),
            Tok::Masked { val, mask } => c.extend_from_slice(&[OP_MASK, *val, *mask]),
            Tok::Any => c.push(OP_ANY),
            Tok::Gap { min, max } => {
                c.push(OP_GAP);
                c.extend_from_slice(&min.to_le_bytes());
                c.extend_from_slice(&max.unwrap_or(u32::MAX).to_le_bytes());
            }
            Tok::Alt(alts) => {
                c.push(OP_ALT);
                c.extend_from_slice(&(alts.len() as u16).to_le_bytes());
                for a in alts {
                    c.extend_from_slice(&(a.len() as u16).to_le_bytes());
                    c.extend_from_slice(a);
                }
            }
        }
    }
    c
}

fn rd_u16(c: &[u8], i: usize) -> Option<u16> {
    let b = c.get(i..i.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
pub fn rd_u32(c: &[u8], i: usize) -> Option<u32> {
    let b = c.get(i..i.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Length in bytes of the instruction at `i`, or None if it is malformed/truncated.
pub fn op_len(c: &[u8], i: usize) -> Option<usize> {
    match *c.get(i)? {
        OP_BYTE => (i + 2 <= c.len()).then_some(2),
        OP_MASK => (i + 3 <= c.len()).then_some(3),
        OP_ANY => Some(1),
        OP_GAP => (i + 9 <= c.len()).then_some(9),
        OP_ALT => {
            let n = rd_u16(c, i + 1)? as usize;
            let mut p = i + 3;
            for _ in 0..n {
                let l = rd_u16(c, p)? as usize;
                p = p.checked_add(2)?.checked_add(l)?;
                if p > c.len() {
                    return None;
                }
            }
            Some(p - i)
        }
        _ => None,
    }
}

/// Full structural validation of untrusted bytecode (used on binary load).
pub fn validate_code(c: &[u8]) -> Result<(), String> {
    if c.is_empty() || c.len() > 4 * MAX_SIG_CHARS {
        return Err("bytecode length out of range".into());
    }
    let (mut i, mut wild, mut first, mut last) = (0usize, 0usize, None, None);
    while i < c.len() {
        let l = op_len(c, i).ok_or("malformed instruction")?;
        let op = c[i];
        if first.is_none() {
            first = Some(op);
        }
        last = Some(op);
        match op {
            OP_GAP => {
                let (min, max) = (rd_u32(c, i + 1).ok_or("gap")?, rd_u32(c, i + 5).ok_or("gap")?);
                if max != u32::MAX && min > max {
                    return Err("gap min exceeds max".into());
                }
                if min as u64 > MAX_GAP || (max != u32::MAX && max as u64 > MAX_GAP) {
                    return Err("gap bound too large".into());
                }
                wild += 1;
            }
            OP_ANY => wild += 1,
            OP_ALT => {
                let n = rd_u16(c, i + 1).ok_or("alt")? as usize;
                if n == 0 || n > MAX_ALTS {
                    return Err("alternative count out of range".into());
                }
                let mut p = i + 3;
                for _ in 0..n {
                    let al = rd_u16(c, p).ok_or("alt")? as usize;
                    if al == 0 {
                        return Err("empty alternative".into());
                    }
                    p += 2 + al;
                }
                wild += 1;
            }
            _ => {}
        }
        i += l;
    }
    if matches!(first, Some(OP_ANY | OP_GAP)) || matches!(last, Some(OP_ANY | OP_GAP)) {
        return Err("signature starts or ends with a wildcard gap".into());
    }
    if wild > MAX_WILDCARD_SEGMENTS {
        return Err("too many wildcard segments".into());
    }
    Ok(())
}

/// Same anchor rule as `parse_sig`, computed from bytecode.
pub fn anchor_of_code(c: &[u8]) -> Option<(usize, Vec<u8>)> {
    let (mut pos, mut best, mut run, mut run_start): (usize, Option<(usize, Vec<u8>)>, Vec<u8>, usize) = (0, None, vec![], 0);
    let flush = |run: &mut Vec<u8>, start: usize, best: &mut Option<(usize, Vec<u8>)>| {
        if run.len() >= 2 && best.as_ref().map_or(true, |b| run.len() > b.1.len()) {
            *best = Some((start, run.clone()));
        }
        run.clear();
    };
    let mut i = 0;
    while i < c.len() {
        let Some(l) = op_len(c, i) else { break };
        match c[i] {
            OP_BYTE => {
                if run.is_empty() {
                    run_start = pos;
                }
                run.push(c[i + 1]);
                pos += 1;
            }
            OP_MASK => {
                flush(&mut run, run_start, &mut best);
                pos += 1;
            }
            OP_ALT => {
                // fixed width only if all alternatives have the same length
                let n = rd_u16(c, i + 1).unwrap_or(0) as usize;
                let (mut p, mut width, mut same) = (i + 3, None::<usize>, true);
                for _ in 0..n {
                    let al = rd_u16(c, p).unwrap_or(0) as usize;
                    if *width.get_or_insert(al) != al {
                        same = false;
                    }
                    p += 2 + al;
                }
                if same {
                    flush(&mut run, run_start, &mut best);
                    pos += width.unwrap_or(0);
                } else {
                    break;
                }
            }
            _ => break,
        }
        i += l;
    }
    flush(&mut run, run_start, &mut best);
    best
}
