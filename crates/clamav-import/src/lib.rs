//! ClamAV signature compatibility adapter (offline import pipeline).
//!
//! OWNERSHIP: this crate is Litric code that reads ClamAV's *documented text
//! signature formats* and converts them to Litric's native database format.
//! It does not use libclamav, clamscan or clamd, and it never executes
//! bytecode. The runtime scanner never reads ClamAV files.
//!
//! SUPPORTED (round 1):  .hdb .hdu (MD5 file hash) | .hsb .hsu (SHA-1/SHA-256 file hash)
//!                       .mdb .mdu (MD5 PE-section hash) | .msb .msu (SHA-1/SHA-256 PE-section hash)
//!                       .ndb .ndu (extended signatures, documented subset only: see sigdb::ndb)
//!                       .ldb .ldu (logical signatures, documented subset only: see sigdb::ldb)
//!                       .fp (MD5 allowlist) .sfp (SHA-1/SHA-256 allowlist) | .ign .ign2 (disable by name)
//! UNSUPPORTED (reported, never silently skipped): everything else, incl. CBC, CVD/CLD,
//! and any NDB/LDB line using syntax/targets/offsets/subsignature kinds outside the supported subset.
//!
//! TRUST: this importer cannot verify that its input really came from ClamAV
//! (CVD/CLD signature verification is NOT implemented). The operator must
//! record how the files were obtained and verified (`source_note`); the
//! resulting Litric database is then signed with Litric's own key.

use sigdb::MAX_RULES;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

const MAX_SAMPLES: usize = 10;

#[derive(Debug, Clone)]
pub struct Options {
    pub serial: u64,
    pub created: u64,
    /// How the files were acquired and verified (required, 1-200 chars).
    pub source_note: String,
}

#[derive(Debug, Default, Clone)]
pub struct FileReport {
    pub name: String,
    pub format: String,
    pub supported: bool,
    pub reason: Option<String>,
    /// Non-empty lines seen (text formats) .
    pub lines: u64,
    pub imported: u64,
    pub allow_entries: u64,
    pub rejected: u64,
    /// Valid-looking lines using a feature we do not implement (e.g. `*` size).
    pub unsupported_lines: u64,
    /// Why lines were unsupported, with counts.
    pub unsupported_reasons: BTreeMap<String, u64>,
    pub duplicates: u64,
    pub dropped_by_ignore: u64,
    pub samples: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn total(&self, f: impl Fn(&FileReport) -> u64) -> u64 {
        self.files.iter().map(f).sum()
    }
    pub fn unsupported_files(&self) -> usize {
        self.files.iter().filter(|f| !f.supported).count()
    }
    pub fn render(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "ClamAV import report");
        for f in &self.files {
            let _ = writeln!(
                o,
                "- {} [{}] {}",
                f.name,
                f.format,
                if f.supported { "SUPPORTED" } else { "UNSUPPORTED" }
            );
            if let Some(r) = &f.reason {
                let _ = writeln!(o, "    reason: {r}");
            }
            let _ = writeln!(
                o,
                "    lines {} | imported {} | allowlist {} | rejected {} | unsupported lines {} | duplicates {} | disabled by ignore-list {}",
                f.lines, f.imported, f.allow_entries, f.rejected, f.unsupported_lines, f.duplicates, f.dropped_by_ignore
            );
            for (why, n) in &f.unsupported_reasons {
                let _ = writeln!(o, "    unsupported x{n}: {why}");
            }
            for s in &f.samples {
                let _ = writeln!(o, "    sample: {s}");
            }
        }
        let _ = writeln!(
            o,
            "TOTAL imported {} | allowlist {} | rejected {} | unsupported lines {} | unsupported FILES {}",
            self.total(|f| f.imported),
            self.total(|f| f.allow_entries),
            self.total(|f| f.rejected),
            self.total(|f| f.unsupported_lines),
            self.unsupported_files()
        );
        for w in &self.warnings {
            let _ = writeln!(o, "WARNING: {w}");
        }
        o
    }
}

pub struct Output {
    /// Litric database text (LITRIC-SIGDB 2), UNSIGNED.
    pub db: Vec<u8>,
    pub report: Report,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    FileHash { md5: bool, pua: bool },
    Section { md5: bool, pua: bool },
    Extended { pua: bool },
    Logical { pua: bool },
    Allow { md5: bool },
    Ignore { old: bool },
    Unsupported(&'static str),
}

fn classify(name: &str) -> (Kind, &'static str) {
    let ext = Path::new(name).extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "hdb" => (Kind::FileHash { md5: true, pua: false }, "HDB (MD5 file hash)"),
        "hdu" => (Kind::FileHash { md5: true, pua: true }, "HDU (MD5 file hash, PUA)"),
        "hsb" => (Kind::FileHash { md5: false, pua: false }, "HSB (SHA-1/256 file hash)"),
        "hsu" => (Kind::FileHash { md5: false, pua: true }, "HSU (SHA-1/256 file hash, PUA)"),
        "mdb" => (Kind::Section { md5: true, pua: false }, "MDB (MD5 PE-section hash)"),
        "mdu" => (Kind::Section { md5: true, pua: true }, "MDU (MD5 PE-section hash, PUA)"),
        "msb" => (Kind::Section { md5: false, pua: false }, "MSB (SHA-1/256 PE-section hash)"),
        "msu" => (Kind::Section { md5: false, pua: true }, "MSU (SHA-1/256 PE-section hash, PUA)"),
        "fp" => (Kind::Allow { md5: true }, "FP (MD5 allowlist)"),
        "sfp" => (Kind::Allow { md5: false }, "SFP (SHA-1/256 allowlist)"),
        "ign2" => (Kind::Ignore { old: false }, "IGN2 (disable signature by name)"),
        "ign" => (Kind::Ignore { old: true }, "IGN (disable signature)"),
        "cvd" | "cld" => (
            Kind::Unsupported("ClamAV container: unpacking and digital-signature verification are NOT implemented. Unpack with the official sigtool, verify provenance yourself, then import the extracted files."),
            "CVD/CLD container",
        ),
        "ndb" => (Kind::Extended { pua: false }, "NDB (extended signatures, subset)"),
        "ndu" => (Kind::Extended { pua: true }, "NDU (extended signatures, subset, PUA)"),
        "ldb" => (Kind::Logical { pua: false }, "LDB (logical signatures, subset)"),
        "ldu" => (Kind::Logical { pua: true }, "LDU (logical signatures, subset, PUA)"),
        "cbc" => (Kind::Unsupported("bytecode signatures are never executed by Litric"), "CBC bytecode"),
        "cdb" => (Kind::Unsupported("container metadata signatures are not implemented"), "CDB container metadata"),
        "ftm" => (Kind::Unsupported("file-type magic signatures are not implemented"), "FTM file type magic"),
        "pdb" | "gdb" | "wdb" | "pdu" | "gdu" => (Kind::Unsupported("phishing/URL signatures are not implemented"), "phishing/URL signatures"),
        "crb" | "idb" | "imp" | "cfg" | "info" | "ioc" | "yar" | "yara" => (
            Kind::Unsupported("not a supported signature format in this adapter (YARA rules belong to the separate YARA module)"),
            "other ClamAV/aux file",
        ),
        _ => (Kind::Unsupported("unknown file type"), "unknown"),
    }
}

fn sanitize_family(name: &str) -> String {
    let mut s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect();
    s.truncate(64);
    if s.is_empty() {
        s = "Unnamed".into();
    }
    s
}

fn hex_ok(h: &str) -> bool {
    h.bytes().all(|b| b.is_ascii_hexdigit())
}

struct Parsed<'a> {
    hash: String,
    algo: &'static str,
    size: u32,
    name: &'a str,
}

enum LineError {
    Reject(String),
    Unsupported(String),
}

/// `layout_section`: MDB/MSB lines are `size:hash:name`; others `hash:size:name`.
fn parse_line<'a>(line: &'a str, md5_only: bool, layout_section: bool, allow: bool) -> Result<Parsed<'a>, LineError> {
    let f: Vec<&str> = line.split(':').collect();
    let (min, max) = if allow { (3, 3) } else { (3, 5) };
    if f.len() < min || f.len() > max {
        return Err(LineError::Reject(format!("expected {min}..={max} ':'-separated fields, found {}", f.len())));
    }
    let (hash, size_s, name) = if layout_section { (f[1], f[0], f[2]) } else { (f[0], f[1], f[2]) };
    if f.len() > 3 && f[3..].iter().any(|x| x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit())) {
        return Err(LineError::Reject("functionality-level fields must be numbers".into()));
    }
    if name.is_empty() {
        return Err(LineError::Reject("empty signature name".into()));
    }
    if !hex_ok(hash) {
        return Err(LineError::Reject("hash is not hexadecimal".into()));
    }
    let algo = match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        n => return Err(LineError::Reject(format!("hash length {n} is not 32/40/64"))),
    };
    if md5_only != (algo == "md5") {
        return Err(LineError::Reject(format!("{algo} hash is not valid in this file type")));
    }
    if size_s == "*" {
        return Err(LineError::Unsupported("wildcard (*) size is not supported".into()));
    }
    let size: u64 = size_s.parse().map_err(|_| LineError::Reject("size is not a number".into()))?;
    let size = u32::try_from(size).map_err(|_| LineError::Reject("size exceeds 4 GiB (not representable in Litric DB v2)".into()))?;
    Ok(Parsed { hash: hash.to_ascii_lowercase(), algo, size, name })
}

fn unsupported(f: &mut FileReport, line: usize, why: &str) {
    f.unsupported_lines += 1;
    *f.unsupported_reasons.entry(why.to_string()).or_default() += 1;
    sample(f, format!("line {line}: unsupported: {why}"));
}

enum NdbLine {
    Ok { name: String, target: &'static str, offset: String, sig: String },
    Reject(String),
    Unsupported(String),
}

fn parse_ndb_line(line: &str) -> NdbLine {
    use sigdb::ndb::{locatable, parse_offset, parse_sig, SigError};
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 || f.len() > 6 {
        return NdbLine::Reject(format!("expected 4..=6 ':'-separated fields, found {}", f.len()));
    }
    if f.len() > 4 && f[4..].iter().any(|x| x.is_empty() || !x.bytes().all(|b| b.is_ascii_digit())) {
        return NdbLine::Reject("functionality-level fields must be numbers".into());
    }
    if f[0].is_empty() {
        return NdbLine::Reject("empty signature name".into());
    }
    let target = match f[1].parse::<u32>() {
        Ok(0) => "any",
        Ok(1) => "pe",
        Ok(6) => "elf",
        Ok(10) => "pdf",
        Ok(n @ (2 | 3 | 4 | 5 | 7 | 8 | 9 | 11 | 12)) => {
            return NdbLine::Unsupported(format!("target type {n} is not supported (only 0 any, 1 PE, 6 ELF, 10 PDF)"))
        }
        _ => return NdbLine::Reject("target type is not a known number".into()),
    };
    let offset = match parse_offset(f[2]) {
        Ok(o) => o,
        Err(SigError::Malformed(m)) => return NdbLine::Reject(format!("offset: {m}")),
        Err(SigError::Unsupported(m)) => return NdbLine::Unsupported(format!("offset: {m}")),
    };
    let sig = match parse_sig(f[3]) {
        Ok(x) => x,
        Err(SigError::Malformed(m)) => return NdbLine::Reject(format!("signature: {m}")),
        Err(SigError::Unsupported(m)) => return NdbLine::Unsupported(format!("signature: {m}")),
    };
    if let Err(SigError::Unsupported(m) | SigError::Malformed(m)) = locatable(&sig, &offset) {
        return NdbLine::Unsupported(m);
    }
    if offset.needs_pe() && target != "pe" {
        return NdbLine::Unsupported("EP/section offsets are only supported with target type 1 (PE)".into());
    }
    NdbLine::Ok { name: f[0].to_string(), target, offset: f[2].to_string(), sig: f[3].to_string() }
}

enum LdbLine {
    Ok { name: String, target: &'static str, constraints: String, expr: String, subs: Vec<String> },
    Reject(String),
    Unsupported(String),
}

fn parse_ldb_line(line: &str) -> LdbLine {
    use sigdb::ldb::{parse_expr, parse_target_block, MAX_SUBSIGS};
    use sigdb::ndb::{locatable, parse_offset, parse_sig, SigError};
    let parts: Vec<&str> = line.split(';').collect();
    if parts.len() < 4 {
        return LdbLine::Reject(format!("expected name;target;expression;subsignature..., found {} ';'-separated fields", parts.len()));
    }
    if parts[0].is_empty() {
        return LdbLine::Reject("empty signature name".into());
    }
    let (target, constraints) = match parse_target_block(parts[1]) {
        Ok(x) => x,
        Err(SigError::Malformed(m)) => return LdbLine::Reject(format!("target description: {m}")),
        Err(SigError::Unsupported(m)) => return LdbLine::Unsupported(format!("target description: {m}")),
    };
    let target_s = match target {
        sigdb::Target::Any => "any",
        sigdb::Target::Pe => "pe",
        sigdb::Target::Elf => "elf",
        _ => "pdf",
    };
    let expr = match parse_expr(parts[2]) {
        Ok(e) => e,
        Err(SigError::Malformed(m)) => return LdbLine::Reject(format!("expression: {m}")),
        Err(SigError::Unsupported(m)) => return LdbLine::Unsupported(format!("expression: {m}")),
    };
    let raw = &parts[3..];
    if raw.len() > MAX_SUBSIGS {
        return LdbLine::Unsupported(format!("more than {MAX_SUBSIGS} subsignatures"));
    }
    if expr.max_index() as usize >= raw.len() {
        return LdbLine::Reject("expression refers to a subsignature that does not exist".into());
    }
    let mut subs = Vec::with_capacity(raw.len());
    for sub in raw {
        if sub.contains("::") {
            return LdbLine::Unsupported("subsignature modifiers (::iwfa and similar)".into());
        }
        if sub.contains("${") {
            return LdbLine::Unsupported("macro subsignature".into());
        }
        if sub.contains('/') {
            return LdbLine::Unsupported("PCRE subsignature".into());
        }
        if sub.contains('#') {
            return LdbLine::Unsupported("byte-compare / fuzzy-hash subsignature".into());
        }
        let (off_s, hex) = sub.split_once(':').unwrap_or(("*", sub));
        let offset = match parse_offset(off_s) {
            Ok(o) => o,
            Err(SigError::Malformed(m)) => return LdbLine::Reject(format!("subsignature offset: {m}")),
            Err(SigError::Unsupported(m)) => return LdbLine::Unsupported(format!("subsignature offset: {m}")),
        };
        let sig = match parse_sig(hex) {
            Ok(x) => x,
            Err(SigError::Malformed(m)) => return LdbLine::Reject(format!("subsignature: {m}")),
            Err(SigError::Unsupported(m)) => return LdbLine::Unsupported(format!("subsignature: {m}")),
        };
        if let Err(SigError::Unsupported(m) | SigError::Malformed(m)) = locatable(&sig, &offset) {
            return LdbLine::Unsupported(format!("subsignature: {m}"));
        }
        if offset.needs_pe() && target_s != "pe" {
            return LdbLine::Unsupported("EP/section offsets are only supported with target type 1 (PE)".into());
        }
        subs.push(format!("{off_s}:{hex}"));
    }
    LdbLine::Ok { name: parts[0].to_string(), target: target_s, constraints: constraints.to_text(), expr: parts[2].to_string(), subs }
}

fn sample(f: &mut FileReport, msg: String) {
    if f.samples.len() < MAX_SAMPLES {
        f.samples.push(msg);
    }
}

pub fn import_dir(dir: &Path, opts: &Options) -> io::Result<Output> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
    files.sort();
    import(&files, opts)
}

pub fn import(files: &[PathBuf], opts: &Options) -> io::Result<Output> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
    let note = opts.source_note.trim();
    if note.is_empty() || note.len() > 160 || note.chars().any(|c| c.is_control()) {
        return Err(bad("source_note is required: 1-160 printable characters describing how the files were obtained and verified"));
    }
    let mut files: Vec<PathBuf> = files.to_vec();
    files.sort();
    let mut report = Report::default();

    // pass 1: ignore lists
    let mut ignore: HashSet<String> = HashSet::new();
    for p in &files {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        if let (Kind::Ignore { old }, _) = classify(name) {
            if let Ok(text) = std::fs::read_to_string(p) {
                for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let parts: Vec<&str> = l.split(':').collect();
                    let n = if old { parts.get(2).copied() } else { parts.first().copied() };
                    if let Some(n) = n.filter(|n| !n.is_empty()) {
                        ignore.insert(n.to_string());
                    }
                }
            }
        }
    }

    let mut records = String::new();
    let mut count_rules = 0usize;
    let mut seen: HashSet<(u8, &'static str, String, u32)> = HashSet::new();
    let mut seen_allow: HashSet<(&'static str, String, u32)> = HashSet::new();
    let (mut n_file, mut n_sec, mut n_ndb, mut n_ldb) = (0u64, 0u64, 0u64, 0u64);
    let mut seen_ldb: HashSet<String> = HashSet::new();
    let mut seen_ndb: HashSet<(&'static str, String, String)> = HashSet::new();
    let mut imported_names: HashMap<String, u64> = HashMap::new();

    for p in &files {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
        let (kind, fmt) = classify(&name);
        let mut fr = FileReport { name: name.clone(), format: fmt.to_string(), ..Default::default() };
        match kind {
            Kind::Unsupported(reason) => {
                fr.reason = Some(reason.to_string());
                // count lines of text-like files so the size of what we skip is visible
                if !matches!(Path::new(&name).extension().and_then(|e| e.to_str()), Some("cvd" | "cld" | "cbc")) {
                    if let Ok(b) = std::fs::read(p) {
                        fr.lines = b.split(|&c| c == b'\n').filter(|l| !l.iter().all(|c| c.is_ascii_whitespace())).count() as u64;
                    }
                }
            }
            Kind::Ignore { .. } => {
                fr.supported = true;
                fr.lines = std::fs::read_to_string(p).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count() as u64).unwrap_or(0);
                fr.reason = Some("names are applied to the other imported files (semantics inferred from documentation, not verified against libclamav)".into());
            }
            Kind::FileHash { md5, pua } | Kind::Section { md5, pua } => {
                fr.supported = true;
                let is_section = matches!(kind, Kind::Section { .. });
                let text = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned())?;
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim_end_matches('\r');
                    if line.trim().is_empty() {
                        continue;
                    }
                    fr.lines += 1;
                    match parse_line(line, md5, is_section, false) {
                        Err(LineError::Reject(m)) => {
                            fr.rejected += 1;
                            sample(&mut fr, format!("line {}: rejected: {m}", i + 1));
                        }
                        Err(LineError::Unsupported(m)) => unsupported(&mut fr, i + 1, &m),
                        Ok(pl) => {
                            if ignore.contains(pl.name) {
                                fr.dropped_by_ignore += 1;
                                continue;
                            }
                            if !seen.insert((is_section as u8, pl.algo, pl.hash.clone(), pl.size)) {
                                fr.duplicates += 1;
                                continue;
                            }
                            count_rules += 1;
                            if count_rules > MAX_RULES {
                                return Err(bad("too many rules for one Litric database; split or filter the input"));
                            }
                            let is_pua = pua || pl.name.starts_with("PUA.");
                            let (sev, conf) = if is_pua { ("low", 50) } else { ("high", 90) };
                            let (tag, rec, ctr) = if is_section { ("s", "S", &mut n_sec) } else { ("h", "HX", &mut n_file) };
                            *ctr += 1;
                            let _ = writeln!(records, "{rec} clam.{tag}.{} {} {sev} {conf} {} {} {}", *ctr, sanitize_family(pl.name), pl.algo, pl.hash, pl.size);
                            *imported_names.entry(pl.name.to_string()).or_default() += 1;
                            fr.imported += 1;
                        }
                    }
                }
            }
            Kind::Extended { pua } => {
                fr.supported = true;
                let text = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned())?;
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim_end_matches('\r');
                    if line.trim().is_empty() {
                        continue;
                    }
                    fr.lines += 1;
                    match parse_ndb_line(line) {
                        NdbLine::Reject(m) => {
                            fr.rejected += 1;
                            sample(&mut fr, format!("line {}: rejected: {m}", i + 1));
                        }
                        NdbLine::Unsupported(m) => unsupported(&mut fr, i + 1, &m),
                        NdbLine::Ok { name, target, offset, sig } => {
                            if ignore.contains(name.as_str()) {
                                fr.dropped_by_ignore += 1;
                                continue;
                            }
                            if !seen_ndb.insert((target, offset.clone(), sig.clone())) {
                                fr.duplicates += 1;
                                continue;
                            }
                            count_rules += 1;
                            if count_rules > MAX_RULES {
                                return Err(bad("too many rules for one Litric database; split or filter the input"));
                            }
                            let is_pua = pua || name.starts_with("PUA.");
                            let (sev, conf) = if is_pua { ("low", 50) } else { ("high", 90) };
                            n_ndb += 1;
                            let _ = writeln!(records, "NDB clam.n.{n_ndb} {} {sev} {conf} {target} {offset} {sig}", sanitize_family(&name));
                            fr.imported += 1;
                        }
                    }
                }
            }
            Kind::Logical { pua } => {
                fr.supported = true;
                let text = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned())?;
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim_end_matches('\r');
                    if line.trim().is_empty() {
                        continue;
                    }
                    fr.lines += 1;
                    match parse_ldb_line(line) {
                        LdbLine::Reject(m) => {
                            fr.rejected += 1;
                            sample(&mut fr, format!("line {}: rejected: {m}", i + 1));
                        }
                        LdbLine::Unsupported(m) => unsupported(&mut fr, i + 1, &m),
                        LdbLine::Ok { name, target, constraints, expr, subs } => {
                            if ignore.contains(name.as_str()) {
                                fr.dropped_by_ignore += 1;
                                continue;
                            }
                            let body = format!("{target} {constraints} {expr} {}", subs.join(" "));
                            if !seen_ldb.insert(body.clone()) {
                                fr.duplicates += 1;
                                continue;
                            }
                            count_rules += 1;
                            if count_rules > MAX_RULES {
                                return Err(bad("too many rules for one Litric database; split or filter the input"));
                            }
                            let is_pua = pua || name.starts_with("PUA.");
                            let (sev, conf) = if is_pua { ("low", 50) } else { ("high", 90) };
                            n_ldb += 1;
                            let _ = writeln!(records, "LDB clam.l.{n_ldb} {} {sev} {conf} {body}", sanitize_family(&name));
                            fr.imported += 1;
                        }
                    }
                }
            }
            Kind::Allow { md5 } => {
                fr.supported = true;
                let text = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned())?;
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim_end_matches('\r');
                    if line.trim().is_empty() {
                        continue;
                    }
                    fr.lines += 1;
                    match parse_line(line, md5, false, true) {
                        Err(LineError::Reject(m)) => {
                            fr.rejected += 1;
                            sample(&mut fr, format!("line {}: rejected: {m}", i + 1));
                        }
                        Err(LineError::Unsupported(m)) => unsupported(&mut fr, i + 1, &m),
                        Ok(pl) => {
                            if !seen_allow.insert((pl.algo, pl.hash.clone(), pl.size)) {
                                fr.duplicates += 1;
                                continue;
                            }
                            let _ = writeln!(records, "AX {} {} {}", pl.algo, pl.hash, pl.size);
                            fr.allow_entries += 1;
                        }
                    }
                }
            }
        }
        report.files.push(fr);
    }
    // attribute ignore-list drops to the ignore files' report line for visibility
    let dropped: u64 = report.total(|f| f.dropped_by_ignore);
    if dropped > 0 {
        report.warnings.push(format!("{dropped} signatures were disabled by .ign/.ign2 lists"));
    }
    if report.unsupported_files() > 0 {
        let lines: u64 = report.files.iter().filter(|f| !f.supported).map(|f| f.lines).sum();
        report.warnings.push(format!(
            "{} input file(s) in unsupported formats (~{lines} lines) were NOT imported; detection coverage is lower than the original ClamAV database",
            report.unsupported_files()
        ));
    }
    if report.total(|f| f.rejected) + report.total(|f| f.unsupported_lines) > 0 {
        report.warnings.push("some lines were rejected or unsupported; see per-file samples".into());
    }
    report.warnings.push("TRUST: CVD/CLD signature verification is not implemented; the authenticity of the input rests on your source note and your own verification".into());

    let mut db = String::new();
    let _ = writeln!(db, "LITRIC-SIGDB 2\nserial {}\ncreated {}\nmin-engine 2\nrule-count {count_rules}", opts.serial, opts.created);
    let _ = writeln!(db, "source clamav-import (Litric adapter): {note}");
    let names: Vec<&str> = report.files.iter().filter(|f| f.supported).map(|f| f.name.as_str()).collect();
    let mut joined = names.join(",");
    joined.truncate(150);
    let _ = writeln!(db, "source input files: {joined}");
    db.push_str(&records);
    db.push_str("END\n");
    // Self-check: the output must be a valid Litric database.
    sigdb::Database::parse(db.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("internal error: generated database is invalid: {e}")))?;
    Ok(Output { db: db.into_bytes(), report })
}
