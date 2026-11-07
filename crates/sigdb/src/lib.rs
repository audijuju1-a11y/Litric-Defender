//! Litric signature database (LSDB).
//!
//! Three distinct trust systems are never mixed here:
//!  1. detection signatures  -> the rules inside the database
//!  2. database signing      -> Ed25519 over the exact database bytes
//!  3. code signing          -> not handled here (Authenticode is separate)
//!
//! Loading is all-or-nothing: any malformed line rejects the whole file,
//! so a half-parsed database can never become active.
//!
//! Text format (one record per line, single spaces, final `END`):
//! ```text
//! LITRIC-SIGDB 1
//! serial 42
//! created 1730000000
//! min-engine 1
//! rule-count 2
//! H <id> <family> <severity> <confidence> <sha256-hex>
//! P <id> <family> <severity> <confidence> <target> <pattern-hex>
//! A <sha256-hex>            known-good (suppresses detection)
//! R <id>                    revoked rule id (removed from this bundle)
//! END
//! ```

pub mod binary;
pub mod ldb;
pub mod ndb;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::{fmt, fs, io, path::{Path, PathBuf}};

pub const ENGINE_VERSION: u32 = 2;
pub const MAX_DB_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_RULES: usize = 10_000_000;
pub const MAX_SOURCES: usize = 16;
pub const MIN_PATTERN: usize = 4;
pub const MAX_PATTERN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Any,
    Pe,
    Elf,
    Zip,
    Pdf,
    Script,
}

impl Target {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "any" => Self::Any,
            "pe" => Self::Pe,
            "elf" => Self::Elf,
            "zip" => Self::Zip,
            "pdf" => Self::Pdf,
            "script" => Self::Script,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub family: String,
    pub severity: Severity,
    /// 0..=100 quality score assigned by the rule author.
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub rule: Rule,
    pub target: Target,
    pub pattern: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algo {
    Md5,
    Sha1,
    Sha256,
}
pub const ALGOS: [Algo; 3] = [Algo::Md5, Algo::Sha1, Algo::Sha256];
impl Algo {
    pub fn len(self) -> usize {
        match self {
            Algo::Md5 => 16,
            Algo::Sha1 => 20,
            Algo::Sha256 => 32,
        }
    }
    pub fn idx(self) -> usize {
        self as usize
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            _ => return None,
        })
    }
}

/// Compact per-rule metadata for the large hash tables (12 bytes).
#[derive(Debug, Clone, Copy, Default)]
struct Meta {
    family: u32,
    id_off: u32,
    id_len: u8,
    sev: u8,
    conf: u8,
}

/// Sorted (hash,size) -> Meta table. Memory per rule is roughly
/// hash(16..32) + size(4) + meta(12) + id text, instead of several heap allocations.
#[derive(Debug, Default)]
struct HashTable {
    klen: usize,
    keys: Vec<u8>,
    sizes: Vec<u32>,
    meta: Vec<Meta>,
}

impl HashTable {
    fn with_klen(klen: usize) -> Self {
        Self { klen, ..Default::default() }
    }
    fn len(&self) -> usize {
        self.sizes.len()
    }
    fn key(&self, i: usize) -> &[u8] {
        &self.keys[i * self.klen..(i + 1) * self.klen]
    }
    fn push(&mut self, key: &[u8], size: u32, m: Meta) {
        self.keys.extend_from_slice(key);
        self.sizes.push(size);
        self.meta.push(m);
    }
    fn finalize(&mut self, revoked: &HashSet<String>, arena: &str) -> Result<(), String> {
        if !revoked.is_empty() {
            let keep: Vec<usize> = (0..self.len())
                .filter(|&i| {
                    let m = &self.meta[i];
                    m.id_len == 0 || !revoked.contains(&arena[m.id_off as usize..m.id_off as usize + m.id_len as usize])
                })
                .collect();
            if keep.len() != self.len() {
                let (mut k, mut s, mut mm) = (Vec::new(), Vec::new(), Vec::new());
                for i in keep {
                    k.extend_from_slice(self.key(i));
                    s.push(self.sizes[i]);
                    mm.push(self.meta[i]);
                }
                self.keys = k;
                self.sizes = s;
                self.meta = mm;
            }
        }
        let n = self.len();
        let mut idx: Vec<u32> = (0..n as u32).collect();
        idx.sort_unstable_by(|&a, &b| {
            self.key(a as usize).cmp(self.key(b as usize)).then(self.sizes[a as usize].cmp(&self.sizes[b as usize]))
        });
        for w in idx.windows(2) {
            let (a, b) = (w[0] as usize, w[1] as usize);
            if self.key(a) == self.key(b) && self.sizes[a] == self.sizes[b] {
                return Err("duplicate hash rule (same algorithm, hash and size)".into());
            }
        }
        let (mut k, mut s, mut mm) = (Vec::with_capacity(self.keys.len()), Vec::with_capacity(n), Vec::with_capacity(n));
        for &i in &idx {
            let i = i as usize;
            k.extend_from_slice(self.key(i));
            s.push(self.sizes[i]);
            mm.push(self.meta[i]);
        }
        self.keys = k;
        self.sizes = s;
        self.meta = mm;
        Ok(())
    }
    fn lookup(&self, key: &[u8], size: u32) -> Option<&Meta> {
        if key.len() != self.klen || self.klen == 0 {
            return None;
        }
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.key(mid).cmp(key).then(self.sizes[mid].cmp(&size)) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(&self.meta[mid]),
            }
        }
        None
    }
}

/// Compact extended-signature rule. Identity/family/severity live in the shared
/// tables (see `Database::ndb_rule`); the signature is stored as bytecode.
#[derive(Debug, Clone)]
pub struct NdbRule {
    meta: Meta,
    pub target: Target,
    pub offset: ndb::Offset,
    pub code: Box<[u8]>,
}

/// One subsignature of a logical signature: its own offset and bytecode.
#[derive(Debug, Clone)]
pub struct LdbSub {
    pub offset: ndb::Offset,
    pub code: Box<[u8]>,
}

/// Logical (LDB) rule: several subsignatures combined by a boolean expression
/// with optional per-subsignature match-count conditions.
#[derive(Debug, Clone)]
pub struct LdbRule {
    meta: Meta,
    pub target: Target,
    pub constraints: ldb::Constraints,
    /// Canonical expression text (what is stored on disk) and its parse.
    pub expr_text: String,
    pub expr: ldb::Expr,
    pub subs: Vec<LdbSub>,
}

#[derive(Debug, Default)]
pub struct Database {
    pub version: u32,
    /// ClamAV-style logical signatures (v2 `LDB` records).
    pub ldb: Vec<LdbRule>,
    /// ClamAV-style extended signatures (v2 `NDB` records).
    pub ndb: Vec<NdbRule>,
    /// Free-text provenance lines (v2): where the content came from.
    pub sources: Vec<String>,
    families: Vec<String>,
    id_arena: String,
    file_tables: [HashTable; 3],
    section_tables: [HashTable; 3],
    allow_tables: [HashTable; 3],
    pub serial: u64,
    pub created: u64,
    pub min_engine: u32,
    pub hash_rules: HashMap<[u8; 32], Rule>,
    pub patterns: Vec<PatternRule>,
    pub allow: HashSet<[u8; 32]>,
    pub revoked: HashSet<String>,
}

#[derive(Debug)]
pub enum Error {
    Parse { line: usize, msg: String },
    BadSignature(String),
    UnknownKey(String),
    KeyRevoked(String),
    Rollback { current: u64, offered: u64 },
    SerialReuse(u64),
    EngineTooOld { need: u32 },
    Corrupt(String),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse { line, msg } => write!(f, "database parse error at line {line}: {msg}"),
            Error::BadSignature(m) => write!(f, "signature verification failed: {m}"),
            Error::UnknownKey(k) => write!(f, "database signed by unknown key {k}"),
            Error::KeyRevoked(k) => write!(f, "signing key {k} has been revoked"),
            Error::Rollback { current, offered } => write!(f, "rollback refused: offered serial {offered} < current {current}"),
            Error::SerialReuse(s) => write!(f, "serial {s} already installed with different content"),
            Error::EngineTooOld { need } => write!(f, "database needs engine version >= {need}"),
            Error::Corrupt(m) => write!(f, "corrupt store: {m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn perr<T>(line: usize, msg: impl Into<String>) -> Result<T, Error> {
    Err(Error::Parse { line, msg: msg.into() })
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

impl Database {
    /// Identity, family, severity and confidence of the i-th extended rule.
    pub fn ndb_rule(&self, i: usize) -> Rule {
        self.rule_from(&self.ndb[i].meta)
    }

    /// Identity, family, severity and confidence of the i-th logical rule.
    pub fn ldb_rule(&self, i: usize) -> Rule {
        self.rule_from(&self.ldb[i].meta)
    }

    pub fn rule_count(&self) -> usize {
        self.hash_rules.len()
            + self.patterns.len()
            + self.ndb.len()
            + self.ldb.len()
            + self.file_tables.iter().map(|t| t.len()).sum::<usize>()
            + self.section_tables.iter().map(|t| t.len()).sum::<usize>()
    }

    fn rule_from(&self, m: &Meta) -> Rule {
        let o = m.id_off as usize;
        Rule {
            id: self.id_arena[o..o + m.id_len as usize].to_string(),
            family: self.families[m.family as usize].clone(),
            severity: match m.sev {
                0 => Severity::Low,
                1 => Severity::Medium,
                2 => Severity::High,
                _ => Severity::Critical,
            },
            confidence: m.conf,
        }
    }

    /// Whole-file hash rule keyed by (algorithm, digest, exact file size).
    pub fn lookup_file(&self, algo: Algo, digest: &[u8], size: u64) -> Option<Rule> {
        let size = u32::try_from(size).ok()?;
        self.file_tables[algo.idx()].lookup(digest, size).map(|m| self.rule_from(m))
    }
    /// PE section hash rule keyed by (algorithm, digest, bytes hashed).
    pub fn lookup_section(&self, algo: Algo, digest: &[u8], size: u64) -> Option<Rule> {
        let size = u32::try_from(size).ok()?;
        self.section_tables[algo.idx()].lookup(digest, size).map(|m| self.rule_from(m))
    }
    pub fn is_allowed(&self, algo: Algo, digest: &[u8], size: u64) -> bool {
        u32::try_from(size).ok().map_or(false, |s| self.allow_tables[algo.idx()].lookup(digest, s).is_some())
    }
    /// True if this algorithm must be computed while scanning.
    pub fn needs(&self, algo: Algo) -> bool {
        let i = algo.idx();
        self.file_tables[i].len() + self.allow_tables[i].len() + self.section_tables[i].len() > 0
    }
    pub fn has_section_rules(&self) -> bool {
        self.section_tables.iter().any(|t| t.len() > 0)
    }

    pub fn parse(bytes: &[u8]) -> Result<Database, Error> {
        if bytes.len() > MAX_DB_BYTES {
            return perr(0, "database exceeds size limit");
        }
        let text = std::str::from_utf8(bytes).or_else(|_| perr(0, "not valid UTF-8"))?;
        let mut lines = text.split('\n').enumerate().map(|(i, l)| (i + 1, l));
        let version = match lines.next() {
            Some((_, "LITRIC-SIGDB 1")) => 1u32,
            Some((_, "LITRIC-SIGDB 2")) => 2u32,
            _ => return perr(1, "bad magic/version, expected `LITRIC-SIGDB 1` or `LITRIC-SIGDB 2`"),
        };
        let mut db = Database { version, ..Default::default() };
        let mut fb: [HashTable; 3] = [HashTable::with_klen(16), HashTable::with_klen(20), HashTable::with_klen(32)];
        let mut sb: [HashTable; 3] = [HashTable::with_klen(16), HashTable::with_klen(20), HashTable::with_klen(32)];
        let mut ab: [HashTable; 3] = [HashTable::with_klen(16), HashTable::with_klen(20), HashTable::with_klen(32)];
        let mut fam_idx: HashMap<String, u32> = HashMap::new();
        let (mut serial, mut created, mut min_engine, mut count) = (None, None, None, None);
        let mut ids: HashSet<String> = HashSet::new();
        let mut ended = false;
        let mut declared = 0usize;
        for (n, line) in lines.by_ref() {
            if ended {
                if line.is_empty() {
                    continue; // trailing newline only
                }
                return perr(n, "data after END");
            }
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "serial" | "created" | "min-engine" | "rule-count" => {
                    if f.len() != 2 {
                        return perr(n, "header needs exactly one value");
                    }
                    let v: u64 = f[1].parse().or_else(|_| perr(n, "header value must be a number"))?;
                    let slot = match f[0] {
                        "serial" => &mut serial,
                        "created" => &mut created,
                        "min-engine" => &mut min_engine,
                        _ => &mut count,
                    };
                    if slot.replace(v).is_some() {
                        return perr(n, "duplicate header");
                    }
                }
                "H" | "P" => {
                    declared += 1;
                    if declared > MAX_RULES {
                        return perr(n, "too many rules");
                    }
                    let want = if f[0] == "H" { 6 } else { 7 };
                    if f.len() != want {
                        return perr(n, format!("{} record needs {want} fields", f[0]));
                    }
                    let (id, family) = (f[1], f[2]);
                    if !valid_name(id) || !valid_name(family) {
                        return perr(n, "id/family must be 1-64 chars of [A-Za-z0-9._-]");
                    }
                    if !ids.insert(id.to_string()) {
                        return perr(n, format!("duplicate rule id {id}"));
                    }
                    let severity = match f[3] {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => return perr(n, "severity must be low|medium|high|critical"),
                    };
                    let confidence: u8 = match f[4].parse() {
                        Ok(c) if c <= 100 => c,
                        _ => return perr(n, "confidence must be 0..=100"),
                    };
                    let rule = Rule { id: id.into(), family: family.into(), severity, confidence };
                    if f[0] == "H" {
                        let h = hex_decode(f[5]).filter(|h| h.len() == 32);
                        let Some(h) = h else { return perr(n, "sha256 must be 64 hex chars") };
                        db.hash_rules.insert(h.try_into().unwrap(), rule);
                    } else {
                        let Some(target) = Target::parse(f[5]) else { return perr(n, "unknown target") };
                        let Some(pat) = hex_decode(f[6]) else { return perr(n, "pattern is not valid hex") };
                        if pat.len() < MIN_PATTERN || pat.len() > MAX_PATTERN {
                            return perr(n, format!("pattern must be {MIN_PATTERN}..={MAX_PATTERN} bytes"));
                        }
                        db.patterns.push(PatternRule { rule, target, pattern: pat });
                    }
                }
                "source" => {
                    if version < 2 {
                        return perr(n, "`source` requires LITRIC-SIGDB 2");
                    }
                    let txt = line.strip_prefix("source ").unwrap_or("");
                    if txt.is_empty() || txt.len() > 200 || txt.chars().any(|c| c.is_control()) {
                        return perr(n, "source needs 1-200 printable characters");
                    }
                    if db.sources.len() >= MAX_SOURCES {
                        return perr(n, "too many source lines");
                    }
                    db.sources.push(txt.to_string());
                }
                "HX" | "S" => {
                    if version < 2 {
                        return perr(n, "HX/S records require LITRIC-SIGDB 2");
                    }
                    declared += 1;
                    if declared > MAX_RULES {
                        return perr(n, "too many rules");
                    }
                    if f.len() != 8 {
                        return perr(n, format!("{} record needs 8 fields", f[0]));
                    }
                    let (id, family) = (f[1], f[2]);
                    if !valid_name(id) || !valid_name(family) {
                        return perr(n, "id/family must be 1-64 chars of [A-Za-z0-9._-]");
                    }
                    let sev: u8 = match f[3] {
                        "low" => 0,
                        "medium" => 1,
                        "high" => 2,
                        "critical" => 3,
                        _ => return perr(n, "severity must be low|medium|high|critical"),
                    };
                    let conf: u8 = match f[4].parse() {
                        Ok(c) if c <= 100 => c,
                        _ => return perr(n, "confidence must be 0..=100"),
                    };
                    let Some(algo) = Algo::parse(f[5]) else { return perr(n, "algorithm must be md5|sha1|sha256") };
                    let Some(h) = hex_decode(f[6]).filter(|h| h.len() == algo.len()) else {
                        return perr(n, "hash length does not match algorithm");
                    };
                    let Ok(size) = f[7].parse::<u32>() else { return perr(n, "size must be a number 0..=4294967295") };
                    let fam = match fam_idx.get(family) {
                        Some(&i) => i,
                        None => {
                            let i = db.families.len() as u32;
                            db.families.push(family.to_string());
                            fam_idx.insert(family.to_string(), i);
                            i
                        }
                    };
                    if db.id_arena.len() + id.len() > u32::MAX as usize {
                        return perr(n, "id arena overflow");
                    }
                    let m = Meta { family: fam, id_off: db.id_arena.len() as u32, id_len: id.len() as u8, sev, conf };
                    db.id_arena.push_str(id);
                    let t = if f[0] == "HX" { &mut fb[algo.idx()] } else { &mut sb[algo.idx()] };
                    t.push(&h, size, m);
                }
                "NDB" => {
                    if version < 2 {
                        return perr(n, "NDB requires LITRIC-SIGDB 2");
                    }
                    declared += 1;
                    if declared > MAX_RULES {
                        return perr(n, "too many rules");
                    }
                    if f.len() != 8 {
                        return perr(n, "NDB record needs 8 fields");
                    }
                    let (id, family) = (f[1], f[2]);
                    if !valid_name(id) || !valid_name(family) {
                        return perr(n, "id/family must be 1-64 chars of [A-Za-z0-9._-]");
                    }
                    let severity = match f[3] {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => return perr(n, "severity must be low|medium|high|critical"),
                    };
                    let confidence: u8 = match f[4].parse() {
                        Ok(c) if c <= 100 => c,
                        _ => return perr(n, "confidence must be 0..=100"),
                    };
                    let target = match Target::parse(f[5]) {
                        Some(t @ (Target::Any | Target::Pe | Target::Elf | Target::Pdf)) => t,
                        _ => return perr(n, "NDB target must be any|pe|elf|pdf"),
                    };
                    let offset = ndb::parse_offset(f[6]).or_else(|e| perr(n, e.to_string()))?;
                    let sig = ndb::parse_sig(f[7]).or_else(|e| perr(n, e.to_string()))?;
                    ndb::locatable(&sig, &offset).or_else(|e| perr(n, e.to_string()))?;
                    if offset.needs_pe() && target != Target::Pe {
                        return perr(n, "EP/section offsets require target pe");
                    }
                    let fam = match fam_idx.get(family) {
                        Some(&i) => i,
                        None => {
                            let i = db.families.len() as u32;
                            db.families.push(family.to_string());
                            fam_idx.insert(family.to_string(), i);
                            i
                        }
                    };
                    if db.id_arena.len() + id.len() > u32::MAX as usize {
                        return perr(n, "id arena overflow");
                    }
                    let meta = Meta { family: fam, id_off: db.id_arena.len() as u32, id_len: id.len() as u8, sev: severity as u8, conf: confidence };
                    db.id_arena.push_str(id);
                    db.ndb.push(NdbRule { meta, target, offset, code: ndb::compile(&sig.toks).into_boxed_slice() });
                }
                "LDB" => {
                    if version < 2 {
                        return perr(n, "LDB requires LITRIC-SIGDB 2");
                    }
                    declared += 1;
                    if declared > MAX_RULES {
                        return perr(n, "too many rules");
                    }
                    if f.len() < 9 || f.len() > 8 + ldb::MAX_SUBSIGS {
                        return perr(n, "LDB record needs 8 fields plus 1..=64 subsignatures");
                    }
                    let (id, family) = (f[1], f[2]);
                    if !valid_name(id) || !valid_name(family) {
                        return perr(n, "id/family must be 1-64 chars of [A-Za-z0-9._-]");
                    }
                    let severity = match f[3] {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => return perr(n, "severity must be low|medium|high|critical"),
                    };
                    let confidence: u8 = match f[4].parse() {
                        Ok(c) if c <= 100 => c,
                        _ => return perr(n, "confidence must be 0..=100"),
                    };
                    let target = match Target::parse(f[5]) {
                        Some(t @ (Target::Any | Target::Pe | Target::Elf | Target::Pdf)) => t,
                        _ => return perr(n, "LDB target must be any|pe|elf|pdf"),
                    };
                    let constraints = ldb::parse_constraints(f[6]).or_else(|e| perr(n, e.to_string()))?;
                    let expr = ldb::parse_expr(f[7]).or_else(|e| perr(n, e.to_string()))?;
                    let nsub = f.len() - 8;
                    if expr.max_index() as usize >= nsub {
                        return perr(n, "expression refers to a subsignature that does not exist");
                    }
                    let mut subs = Vec::with_capacity(nsub);
                    for sf in &f[8..] {
                        let Some((off_s, hex)) = sf.split_once(':') else { return perr(n, "subsignature must be offset:hexsig") };
                        let offset = ndb::parse_offset(off_s).or_else(|e| perr(n, e.to_string()))?;
                        let sig = ndb::parse_sig(hex).or_else(|e| perr(n, e.to_string()))?;
                        ndb::locatable(&sig, &offset).or_else(|e| perr(n, e.to_string()))?;
                        if offset.needs_pe() && target != Target::Pe {
                            return perr(n, "EP/section offsets require target pe");
                        }
                        subs.push(LdbSub { offset, code: ndb::compile(&sig.toks).into_boxed_slice() });
                    }
                    let fam = match fam_idx.get(family) {
                        Some(&i) => i,
                        None => {
                            let i = db.families.len() as u32;
                            db.families.push(family.to_string());
                            fam_idx.insert(family.to_string(), i);
                            i
                        }
                    };
                    if db.id_arena.len() + id.len() > u32::MAX as usize {
                        return perr(n, "id arena overflow");
                    }
                    let meta = Meta { family: fam, id_off: db.id_arena.len() as u32, id_len: id.len() as u8, sev: severity as u8, conf: confidence };
                    db.id_arena.push_str(id);
                    db.ldb.push(LdbRule { meta, target, constraints, expr_text: f[7].to_string(), expr, subs });
                }
                "AX" => {
                    if version < 2 {
                        return perr(n, "AX requires LITRIC-SIGDB 2");
                    }
                    if f.len() != 4 {
                        return perr(n, "AX record needs 4 fields");
                    }
                    let Some(algo) = Algo::parse(f[1]) else { return perr(n, "algorithm must be md5|sha1|sha256") };
                    let Some(h) = hex_decode(f[2]).filter(|h| h.len() == algo.len()) else {
                        return perr(n, "hash length does not match algorithm");
                    };
                    let Ok(size) = f[3].parse::<u32>() else { return perr(n, "size must be a number 0..=4294967295") };
                    ab[algo.idx()].push(&h, size, Meta::default());
                }
                "A" => {
                    if f.len() != 2 {
                        return perr(n, "A record needs one sha256");
                    }
                    let h = hex_decode(f[1]).filter(|h| h.len() == 32);
                    let Some(h) = h else { return perr(n, "sha256 must be 64 hex chars") };
                    db.allow.insert(h.try_into().unwrap());
                }
                "R" => {
                    if f.len() != 2 || !valid_name(f[1]) {
                        return perr(n, "R record needs one valid id");
                    }
                    db.revoked.insert(f[1].to_string());
                }
                "END" => {
                    if f.len() != 1 {
                        return perr(n, "END takes no fields");
                    }
                    ended = true;
                }
                _ => return perr(n, "unknown record type"),
            }
        }
        if !ended {
            return perr(0, "missing END (truncated database)");
        }
        let (Some(s), Some(c), Some(m), Some(k)) = (serial, created, min_engine, count) else {
            return perr(0, "missing header (serial/created/min-engine/rule-count)");
        };
        if k as usize != declared {
            return perr(0, format!("rule-count says {k} but {declared} rules present"));
        }
        db.serial = s;
        db.created = c;
        db.min_engine = m as u32;
        // Revocation removes rules from this bundle.
        db.hash_rules.retain(|_, r| !db.revoked.contains(&r.id));
        let rv = db.revoked.clone();
        db.patterns.retain(|p| !rv.contains(&p.rule.id));
        {
            let arena = &db.id_arena;
            db.ldb.retain(|r| !rv.contains(&arena[r.meta.id_off as usize..r.meta.id_off as usize + r.meta.id_len as usize]));
            db.ndb.retain(|r| !rv.contains(&arena[r.meta.id_off as usize..r.meta.id_off as usize + r.meta.id_len as usize]));
        }
        for i in 0..3 {
            let mut t = std::mem::take(&mut fb[i]);
            t.finalize(&rv, &db.id_arena).map_err(|m| Error::Parse { line: 0, msg: format!("file hash table: {m}") })?;
            db.file_tables[i] = t;
            let mut t = std::mem::take(&mut sb[i]);
            t.finalize(&rv, &db.id_arena).map_err(|m| Error::Parse { line: 0, msg: format!("section hash table: {m}") })?;
            db.section_tables[i] = t;
            let mut t = std::mem::take(&mut ab[i]);
            t.finalize(&HashSet::new(), "").map_err(|m| Error::Parse { line: 0, msg: format!("allow table: {m}") })?;
            db.allow_tables[i] = t;
        }
        Ok(db)
    }
}

// ---------------------------------------------------------------- signing

pub fn key_id(vk: &VerifyingKey) -> String {
    hex_encode(&sha256(vk.as_bytes())[..8])
}

#[derive(Default)]
pub struct TrustedKeys {
    keys: Vec<VerifyingKey>,
    revoked: HashSet<String>,
}

impl TrustedKeys {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, vk: VerifyingKey) {
        self.keys.push(vk);
    }
    pub fn add_hex(&mut self, hex: &str) -> Result<(), Error> {
        let b = hex_decode(hex).filter(|b| b.len() == 32).ok_or_else(|| Error::BadSignature("public key must be 64 hex chars".into()))?;
        let vk = VerifyingKey::from_bytes(&b.try_into().unwrap()).map_err(|e| Error::BadSignature(e.to_string()))?;
        self.add(vk);
        Ok(())
    }
    /// Key rotation: trust the new key, revoke the old key id.
    pub fn revoke(&mut self, key_id: &str) {
        self.revoked.insert(key_id.to_string());
    }
}

/// `sig` format: `<key-id 16 hex> <ed25519 signature 128 hex>`.
pub fn sign_bundle(seed: &[u8; 32], db: &[u8]) -> String {
    // Text databases: signature covers every byte. Binary databases: the header,
    // which carries the SHA-256 of every section.
    let msg = binary::signed_region(db).unwrap_or(db);
    let sk = SigningKey::from_bytes(seed);
    let sig = sk.sign(msg);
    format!("{} {}", key_id(&sk.verifying_key()), hex_encode(&sig.to_bytes()))
}

/// Authenticity + integrity of a bundle in either format (no decoding for binary beyond hashing).
pub fn verify_bundle(db: &[u8], sig_line: &str, keys: &TrustedKeys) -> Result<(), Error> {
    if binary::is_binary(db) {
        binary::verify_only(&mut std::io::Cursor::new(db), 0, sig_line, keys).map(|_| ())
    } else {
        verify_signature(db, sig_line, keys)
    }
}

/// Verify and decode a bundle in either format.
pub fn load_verified_bytes(db: &[u8], sig_line: &str, keys: &TrustedKeys) -> Result<Database, Error> {
    if binary::is_binary(db) {
        binary::load_bytes(db, Some((sig_line, keys)))
    } else {
        verify_signature(db, sig_line, keys)?;
        Database::parse(db)
    }
}

/// Verify and load a database file in either format. Binary files are streamed
/// (no whole-file buffer); text files are read whole.
pub fn load_file(path: &Path, sig_line: &str, keys: &TrustedKeys) -> Result<Database, Error> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut magic = [0u8; 8];
    let n = f.read(&mut magic)?;
    if binary::is_binary(&magic[..n]) {
        return binary::load(&mut f, 0, Some((sig_line, keys)));
    }
    drop(f);
    load_verified_bytes(&fs::read(path)?, sig_line, keys)
}

pub(crate) fn verify_signature(db: &[u8], sig_line: &str, keys: &TrustedKeys) -> Result<(), Error> {
    let f: Vec<&str> = sig_line.trim().split(' ').collect();
    if f.len() != 2 {
        return Err(Error::BadSignature("malformed signature line".into()));
    }
    if keys.revoked.contains(f[0]) {
        return Err(Error::KeyRevoked(f[0].into()));
    }
    let vk = keys.keys.iter().find(|k| key_id(k) == f[0]).ok_or_else(|| Error::UnknownKey(f[0].into()))?;
    let raw = hex_decode(f[1]).filter(|b| b.len() == 64).ok_or_else(|| Error::BadSignature("signature must be 128 hex chars".into()))?;
    let sig = Signature::from_bytes(&raw.try_into().unwrap());
    vk.verify_strict(db, &sig).map_err(|e| Error::BadSignature(e.to_string()))
}

// ---------------------------------------------------------------- store

#[derive(Debug, PartialEq)]
pub enum Install {
    Installed { serial: u64 },
    AlreadyCurrent,
}

enum Source<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
}

fn stream_sha256(r: &mut impl io::Read) -> io::Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

/// On-disk active database + anti-rollback floor.
/// `active.bundle` = signature line, `\n`, database bytes: one atomic rename.
/// Binary databases are loaded by streaming from this file (no whole-file buffer).
pub struct Store {
    dir: PathBuf,
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

impl Store {
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn floor(&self) -> Result<u64, Error> {
        match fs::read_to_string(self.dir.join("state.txt")) {
            Ok(t) => t
                .trim()
                .strip_prefix("serial ")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| Error::Corrupt("state.txt unreadable: refusing to reset anti-rollback floor".into())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Opens the active bundle: (file, signature line, byte offset where the database starts).
    fn open_bundle(&self) -> Result<Option<(fs::File, String, u64)>, Error> {
        use std::io::Read;
        let mut f = match fs::File::open(self.dir.join("active.bundle")) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut line = Vec::new();
        let mut one = [0u8; 1];
        loop {
            if f.read(&mut one)? == 0 || line.len() > 2048 {
                return Err(Error::Corrupt("bundle has no signature line".into()));
            }
            if one[0] == b'\n' {
                break;
            }
            line.push(one[0]);
        }
        let sig = String::from_utf8(line).map_err(|_| Error::Corrupt("bundle signature not UTF-8".into()))?;
        let base = sig.len() as u64 + 1;
        Ok(Some((f, sig, base)))
    }

    fn active_digest(&self) -> Result<Option<[u8; 32]>, Error> {
        use std::io::Seek;
        let Some((mut f, _, base)) = self.open_bundle()? else { return Ok(None) };
        f.seek(io::SeekFrom::Start(base))?;
        Ok(Some(stream_sha256(&mut f)?))
    }

    /// Loads and RE-VERIFIES the active database (signature and every section hash).
    /// `Ok(None)` = nothing installed. An `Err` means the on-disk copy was tampered with
    /// or damaged; callers must report degraded protection, never silently continue.
    pub fn load_active(&self, keys: &TrustedKeys) -> Result<Option<Database>, Error> {
        use std::io::{Read, Seek};
        let Some((mut f, sig, base)) = self.open_bundle()? else { return Ok(None) };
        f.seek(io::SeekFrom::Start(base))?;
        let mut magic = [0u8; 8];
        let n = f.read(&mut magic)?;
        if binary::is_binary(&magic[..n]) {
            return binary::load(&mut f, base, Some((&sig, keys))).map(Some);
        }
        f.seek(io::SeekFrom::Start(base))?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        load_verified_bytes(&bytes, &sig, keys).map(Some)
    }

    pub fn install(&self, db_bytes: &[u8], sig_line: &str, keys: &TrustedKeys) -> Result<Install, Error> {
        let db = load_verified_bytes(db_bytes, sig_line, keys)?;
        self.install_decoded(&db, Source::Bytes(db_bytes), sig_line)
    }

    /// Like `install`, but streams a (possibly very large) database from disk.
    pub fn install_file(&self, path: &Path, sig_line: &str, keys: &TrustedKeys) -> Result<Install, Error> {
        use std::io::Read;
        let mut f = fs::File::open(path)?;
        let mut magic = [0u8; 8];
        let n = f.read(&mut magic)?;
        if binary::is_binary(&magic[..n]) {
            let db = binary::load(&mut f, 0, Some((sig_line, keys)))?;
            return self.install_decoded(&db, Source::File(path), sig_line);
        }
        drop(f);
        let bytes = fs::read(path)?;
        self.install(&bytes, sig_line, keys)
    }

    fn install_decoded(&self, db: &Database, src: Source, sig_line: &str) -> Result<Install, Error> {
        use std::io::Write;
        if db.min_engine > ENGINE_VERSION {
            return Err(Error::EngineTooOld { need: db.min_engine });
        }
        let floor = self.floor()?;
        if db.serial < floor {
            return Err(Error::Rollback { current: floor, offered: db.serial });
        }
        if db.serial == floor && floor != 0 {
            let new = match &src {
                Source::Bytes(b) => sha256(b),
                Source::File(p) => stream_sha256(&mut fs::File::open(p)?)?,
            };
            return if self.active_digest()? == Some(new) { Ok(Install::AlreadyCurrent) } else { Err(Error::SerialReuse(db.serial)) };
        }
        // Raise the floor first: a crash can leave an older-but-valid active
        // database, but never a floor that allows rollback.
        atomic_write(&self.dir.join("state.txt"), format!("serial {}\n", db.serial).as_bytes())?;
        let target = self.dir.join("active.bundle");
        let tmp = target.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(sig_line.trim().as_bytes())?;
            f.write_all(b"\n")?;
            match src {
                Source::Bytes(b) => f.write_all(b)?,
                Source::File(p) => {
                    io::copy(&mut fs::File::open(p)?, &mut f)?;
                }
            }
            f.sync_all()?;
        }
        fs::rename(&tmp, &target)?;
        Ok(Install::Installed { serial: db.serial })
    }
}
