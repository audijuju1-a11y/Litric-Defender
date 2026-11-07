//! Litric PE analysis.
//!
//! * `parse`: hand-written, bounds-checked PE parser. Every read goes through
//!   a checked accessor; loops are capped. Malformed input yields anomalies
//!   and `partial = true`, never a panic.
//! * `assess`: explainable multi-signal scoring. Each reason carries a
//!   category and weight; categories are capped, and a Suspicious verdict
//!   requires corroboration from at least two independent categories.
//!
//! Limits (by design): no unpacking or emulation, no Authenticode validation
//! (a signature blob is only reported as present/unverified and NEVER lowers
//! the score). Heuristics produce false positives on legitimate tools such as
//! debuggers, installers and security software; results say "suspicious",
//! never "malware".

pub mod builder;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use std::collections::HashSet;
use std::sync::OnceLock;

const MAX_SECTIONS: usize = 96;
const MAX_DLLS: usize = 1024;
const MAX_THUNKS_PER_DLL: usize = 4096;
const MAX_IMPORTS: usize = 20_000;
const MAX_SECTION_ENTROPY_BYTES: usize = 16 << 20;
const MAX_STRING_SCAN_BYTES: usize = 8 << 20;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub vsize: u32,
    pub vaddr: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub chars: u32,
    pub entropy: f64,
    pub exec: bool,
    pub write: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PeInfo {
    pub machine: u16,
    pub is_64: bool,
    pub is_dll: bool,
    pub subsystem: u16,
    pub entry_rva: u32,
    /// File offset of the entry point, when it maps into section raw data.
    pub entry_offset: Option<u64>,
    pub entry_section: Option<String>,
    pub entry_outside_sections: bool,
    pub sections: Vec<SectionInfo>,
    /// (dll lowercase, function name)
    pub imports: Vec<(String, String)>,
    pub import_dlls: usize,
    pub overlay_size: u64,
    /// A certificate table exists. NOT validated.
    pub has_signature_blob: bool,
    /// Parsing stopped early or hit a limit; analysis is incomplete.
    pub partial: bool,
    pub anomalies: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum PeError {
    NotPe,
}

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    let b = d.get(o..o.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    let b = d.get(o..o.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    let b = d.get(o..o.checked_add(8)?)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut c = [0u64; 256];
    for &b in data {
        c[b as usize] += 1;
    }
    let n = data.len() as f64;
    c.iter().filter(|&&x| x > 0).map(|&x| { let p = x as f64 / n; -p * p.log2() }).sum()
}

fn read_cstr(d: &[u8], off: usize, max: usize) -> Option<String> {
    let s = d.get(off..)?;
    let end = s.iter().take(max).position(|&b| b == 0)?;
    Some(s[..end].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '?' }).collect())
}

fn rva_to_off(secs: &[SectionInfo], headers_size: u32, rva: u32) -> Option<usize> {
    for s in secs {
        let span = s.vsize.max(s.raw_size) as u64;
        let (va, r) = (s.vaddr as u64, rva as u64);
        if r >= va && r < va + span {
            let delta = r - va;
            if delta < s.raw_size as u64 && s.raw_ptr != 0 {
                return Some((s.raw_ptr as u64 + delta) as usize);
            }
            return None;
        }
    }
    if rva < headers_size {
        return Some(rva as usize);
    }
    None
}

pub fn parse(data: &[u8]) -> Result<PeInfo, PeError> {
    if data.get(..2) != Some(b"MZ") {
        return Err(PeError::NotPe);
    }
    let e = u32le(data, 0x3c).ok_or(PeError::NotPe)? as usize;
    if e.checked_add(4).and_then(|end| data.get(e..end)) != Some(b"PE\0\0") {
        return Err(PeError::NotPe);
    }
    let mut info = PeInfo::default();
    macro_rules! bail {
        ($msg:expr) => {{
            info.anomalies.push($msg.to_string());
            info.partial = true;
            return Ok(info);
        }};
    }
    let coff = e + 4;
    let (Some(machine), Some(nsec), Some(optsize), Some(chars)) =
        (u16le(data, coff), u16le(data, coff + 2), u16le(data, coff + 16), u16le(data, coff + 18))
    else {
        bail!("COFF header truncated")
    };
    info.machine = machine;
    info.is_dll = chars & 0x2000 != 0;
    let opt = coff + 20;
    let Some(magic) = u16le(data, opt) else { bail!("optional header missing") };
    info.is_64 = match magic {
        0x10b => false,
        0x20b => true,
        _ => bail!("unknown optional header magic"),
    };
    let (base, nrva_off) = if info.is_64 { (112usize, 108usize) } else { (96, 92) };
    let (Some(entry), Some(subsys), Some(hdr_size)) = (u32le(data, opt + 16), u16le(data, opt + 68), u32le(data, opt + 60)) else {
        bail!("optional header truncated")
    };
    info.entry_rva = entry;
    info.subsystem = subsys;
    let nrva = u32le(data, opt + nrva_off).unwrap_or(0).min(16) as usize;
    let mut dirs = [(0u32, 0u32); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(nrva) {
        match (u32le(data, opt + base + i * 8), u32le(data, opt + base + i * 8 + 4)) {
            (Some(a), Some(b)) => *d = (a, b),
            _ => bail!("data directories truncated"),
        }
    }
    if (optsize as usize) < base + nrva * 8 {
        info.anomalies.push("optional header size smaller than its data directories".into());
        info.partial = true;
    }
    if nsec == 0 {
        info.anomalies.push("no sections".into());
    }
    let mut n = nsec as usize;
    if n > MAX_SECTIONS {
        info.anomalies.push(format!("{n} sections declared (limit {MAX_SECTIONS}); extra ignored"));
        info.partial = true;
        n = MAX_SECTIONS;
    }
    let tbl = opt + optsize as usize;
    for i in 0..n {
        let off = tbl + i * 40;
        let (Some(vsize), Some(vaddr), Some(raw_size), Some(raw_ptr), Some(sc)) =
            (u32le(data, off + 8), u32le(data, off + 12), u32le(data, off + 16), u32le(data, off + 20), u32le(data, off + 36))
        else {
            info.anomalies.push("section table truncated".into());
            info.partial = true;
            break;
        };
        let nm = &data[off..off + 8];
        let end = nm.iter().position(|&b| b == 0).unwrap_or(8);
        let name: String = nm[..end].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '?' }).collect();
        let mut ent = 0.0;
        if raw_size > 0 && (raw_ptr as usize) < data.len() {
            let end = (raw_ptr as u64 + raw_size as u64).min(data.len() as u64) as usize;
            if (raw_ptr as u64 + raw_size as u64) > data.len() as u64 {
                info.anomalies.push(format!("section {name} raw data extends past end of file"));
            }
            let slice = &data[raw_ptr as usize..end];
            ent = entropy(&slice[..slice.len().min(MAX_SECTION_ENTROPY_BYTES)]);
        } else if raw_size > 0 {
            info.anomalies.push(format!("section {name} raw pointer outside file"));
        }
        info.sections.push(SectionInfo {
            name,
            vsize,
            vaddr,
            raw_size,
            raw_ptr,
            chars: sc,
            entropy: ent,
            exec: sc & 0x2000_0000 != 0 || sc & 0x20 != 0,
            write: sc & 0x8000_0000 != 0,
        });
    }
    // overlap in memory
    'o: for (i, a) in info.sections.iter().enumerate() {
        for b in info.sections.iter().skip(i + 1) {
            let (a0, a1) = (a.vaddr as u64, a.vaddr as u64 + a.vsize.max(1) as u64);
            let (b0, b1) = (b.vaddr as u64, b.vaddr as u64 + b.vsize.max(1) as u64);
            if a0 < b1 && b0 < a1 {
                info.anomalies.push("sections overlap in memory".into());
                break 'o;
            }
        }
    }
    // entry point
    if entry != 0 {
        let e = entry as u64;
        info.entry_section = info
            .sections
            .iter()
            .find(|s| e >= s.vaddr as u64 && e < s.vaddr as u64 + s.vsize.max(s.raw_size) as u64)
            .map(|s| s.name.clone());
        info.entry_outside_sections = info.entry_section.is_none() && e >= hdr_size as u64;
        info.entry_offset = rva_to_off(&info.sections, hdr_size, entry).map(|o| o as u64);
    }
    // overlay
    let max_end = info.sections.iter().map(|s| s.raw_ptr as u64 + s.raw_size as u64).max().unwrap_or(0);
    if max_end <= data.len() as u64 {
        info.overlay_size = data.len() as u64 - max_end;
    }
    info.has_signature_blob = dirs[4].1 > 0;
    // imports
    if dirs[1].0 != 0 {
        parse_imports(data, hdr_size, dirs[1].0, &mut info);
    }
    Ok(info)
}

fn parse_imports(data: &[u8], hdr: u32, dir_rva: u32, info: &mut PeInfo) {
    let Some(base) = rva_to_off(&info.sections, hdr, dir_rva) else {
        info.anomalies.push("import directory RVA is not mapped".into());
        info.partial = true;
        return;
    };
    let tsz = if info.is_64 { 8 } else { 4 };
    let mut total = 0usize;
    for i in 0..MAX_DLLS + 1 {
        if i == MAX_DLLS {
            info.anomalies.push("import descriptor limit reached".into());
            info.partial = true;
            return;
        }
        let d = base + i * 20;
        let (Some(orig), Some(name_rva), Some(first)) = (u32le(data, d), u32le(data, d + 12), u32le(data, d + 16)) else {
            info.anomalies.push("import directory truncated".into());
            info.partial = true;
            return;
        };
        if orig == 0 && name_rva == 0 && first == 0 {
            return;
        }
        let dll = rva_to_off(&info.sections, hdr, name_rva)
            .and_then(|o| read_cstr(data, o, 256))
            .unwrap_or_else(|| "?".into())
            .to_ascii_lowercase();
        info.import_dlls += 1;
        let thunk_rva = if orig != 0 { orig } else { first };
        let Some(t0) = rva_to_off(&info.sections, hdr, thunk_rva) else {
            info.anomalies.push("import thunk RVA is not mapped".into());
            info.partial = true;
            return;
        };
        for j in 0..MAX_THUNKS_PER_DLL + 1 {
            if j == MAX_THUNKS_PER_DLL {
                info.anomalies.push("per-DLL import limit reached".into());
                info.partial = true;
                break;
            }
            let entry = if tsz == 8 { u64le(data, t0 + j * 8) } else { u32le(data, t0 + j * 4).map(|v| v as u64) };
            let Some(entry) = entry else {
                info.anomalies.push("import thunk array truncated".into());
                info.partial = true;
                return;
            };
            if entry == 0 {
                break;
            }
            let ordinal = if tsz == 8 { entry >> 63 == 1 } else { entry >> 31 == 1 };
            if ordinal {
                continue;
            }
            let hn = (entry & 0x7FFF_FFFF) as u32;
            if let Some(name) = rva_to_off(&info.sections, hdr, hn).and_then(|o| read_cstr(data, o + 2, 256)) {
                if total >= MAX_IMPORTS {
                    info.anomalies.push("total import limit reached".into());
                    info.partial = true;
                    return;
                }
                info.imports.push((dll.clone(), name));
                total += 1;
            }
        }
    }
}

// ------------------------------------------------------------------ scoring

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Structure,
    Packing,
    Imports,
    Strings,
}

impl Category {
    fn cap(self) -> u32 {
        match self {
            Category::Structure => 40,
            Category::Packing => 40,
            Category::Imports => 45,
            Category::Strings => 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing notable.
    None,
    /// Weak anomalies: logged only.
    Weak,
    /// Multiple independent signals.
    Suspicious,
    /// Strong, corroborated signals.
    Strong,
}

#[derive(Debug, Clone)]
pub struct Reason {
    pub code: &'static str,
    pub category: Category,
    pub weight: u32,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct Risk {
    pub score: u32,
    pub level: Level,
    pub reasons: Vec<Reason>,
    /// The raw score reached the Suspicious range but only one category
    /// contributed meaningfully, so it was held back.
    pub held_for_lack_of_corroboration: bool,
}

const SUSPICIOUS_AT: u32 = 50;
const STRONG_AT: u32 = 80;
const WEAK_AT: u32 = 20;
const CORROBORATING_MIN: u32 = 10;

const PACKER_SECTIONS: &[&str] = &[
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite", "mpress1", "mpress2", ".enigma1",
    ".nsp0", ".nsp1", ".winlice", ".perplex", ".yp", ".packed",
];

/// (needle, weight, label). Weak by design: legitimate admin/security tools contain many.
const STRING_INDICATORS: &[(&str, u32, &str)] = &[
    ("delete shadows", 8, "shadow-copy deletion command"),
    ("files have been encrypted", 8, "ransom-note wording"),
    ("mimikatz", 8, "credential-theft tool name"),
    ("disableantispyware", 6, "attempt to disable Defender policy"),
    ("amsiscanbuffer", 5, "AMSI-related API name (bypass tooling references it)"),
    ("wevtutil cl", 5, "event-log clearing command"),
    ("net user /add", 5, "account creation command"),
    (".onion", 4, "Tor hidden-service address"),
    ("lsass.exe", 4, "references LSASS"),
    ("-encodedcommand", 4, "encoded PowerShell command line"),
    ("sedebugprivilege", 3, "debug privilege name"),
    ("bitcoin", 3, "cryptocurrency wording"),
    ("currentversion\\run", 3, "autorun registry key"),
    ("cmd.exe /c", 2, "shell command line"),
];

fn string_matchers() -> &'static (AhoCorasick, AhoCorasick) {
    static M: OnceLock<(AhoCorasick, AhoCorasick)> = OnceLock::new();
    M.get_or_init(|| {
        let ascii: Vec<Vec<u8>> = STRING_INDICATORS.iter().map(|s| s.0.as_bytes().to_vec()).collect();
        let wide: Vec<Vec<u8>> = STRING_INDICATORS.iter().map(|s| s.0.bytes().flat_map(|b| [b, 0]).collect()).collect();
        let build = |p: &Vec<Vec<u8>>| AhoCorasickBuilder::new().ascii_case_insensitive(true).build(p).expect("static patterns");
        (build(&ascii), build(&wide))
    })
}

fn has(set: &HashSet<String>, names: &[&str]) -> bool {
    names.iter().any(|n| set.contains(*n))
}

pub fn assess(data: &[u8], info: &PeInfo) -> Risk {
    let mut reasons: Vec<Reason> = vec![];
    let mut add = |code: &'static str, category: Category, weight: u32, text: String| {
        reasons.push(Reason { code, category, weight, text });
    };

    // ---- structure
    if info.entry_outside_sections && !info.is_dll {
        add("entry-outside-sections", Category::Structure, 25, "entry point lies outside every section".into());
    }
    if let (Some(es), Some(last)) = (&info.entry_section, info.sections.last()) {
        if info.sections.len() > 1 && *es == last.name && !info.is_dll {
            add("entry-in-last-section", Category::Structure, 8, format!("entry point is in the last section ({es}), common for packers"));
        }
    }
    for s in &info.sections {
        if s.exec && s.write {
            add("section-wx", Category::Structure, 12, format!("section {} is both writable and executable", s.name));
            break;
        }
    }
    for a in &info.anomalies {
        add("malformed", Category::Structure, 10, format!("structure anomaly: {a}"));
    }
    if info.sections.iter().any(|s| s.name.contains('?') || s.name.is_empty()) {
        add("odd-section-name", Category::Structure, 6, "section with empty or non-printable name".into());
    }

    // ---- packing
    for s in &info.sections {
        if PACKER_SECTIONS.contains(&s.name.to_ascii_lowercase().as_str()) {
            add("packer-section", Category::Packing, 25, format!("section name {} matches a known packer", s.name));
            break;
        }
    }
    for s in &info.sections {
        if s.exec && s.entropy >= 7.2 && s.raw_size >= 4096 {
            add("high-entropy-code", Category::Packing, 15, format!("executable section {} has entropy {:.2} (compressed/encrypted code)", s.name, s.entropy));
            break;
        }
    }
    for s in &info.sections {
        if s.raw_size == 0 && s.vsize >= 0x10000 && (s.exec || info.entry_section.as_deref() == Some(&s.name)) {
            add("empty-raw-large-virtual", Category::Packing, 15, format!("section {} reserves {} KiB but has no file content (unpack target)", s.name, s.vsize / 1024));
            break;
        }
    }
    let funcs: HashSet<String> = info.imports.iter().map(|(_, f)| f.to_ascii_lowercase()).collect();
    if !info.partial && info.imports.len() <= 4 && has(&funcs, &["loadlibrarya", "loadlibraryw"]) && has(&funcs, &["getprocaddress"]) {
        add("dynamic-imports-only", Category::Packing, 15, "almost no imports besides LoadLibrary/GetProcAddress (APIs resolved at runtime)".into());
    }
    if info.overlay_size > data.len() as u64 / 4 && info.overlay_size > 64 * 1024 {
        let start = data.len() - info.overlay_size as usize;
        let sample = &data[start..data.len().min(start + (1 << 20))];
        if entropy(sample) >= 7.5 {
            add("high-entropy-overlay", Category::Packing, 8, format!("{} KiB high-entropy data appended after the last section", info.overlay_size / 1024));
        }
    }

    // ---- imports
    let alloc = has(&funcs, &["virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory"]);
    let write = has(&funcs, &["writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"]);
    let exec = has(&funcs, &["createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "rtlcreateuserthread", "ntqueueapcthread"]);
    let groups = alloc as u32 + write as u32 + exec as u32;
    if groups == 3 {
        add("injection-api-set", Category::Imports, 30, "imports the full remote-process injection API set (allocate + write + execute)".into());
    } else if groups == 2 {
        add("injection-api-partial", Category::Imports, 10, "imports two of three remote-process injection API groups".into());
    }
    if has(&funcs, &["setwindowshookexa", "setwindowshookexw"]) && has(&funcs, &["getasynckeystate", "getkeyboardstate", "getkeystate"]) {
        add("keylogger-apis", Category::Imports, 15, "keyboard hook + key-state APIs (keylogger pattern)".into());
    }
    let anti = ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"]
        .iter()
        .filter(|n| funcs.contains(**n))
        .count();
    if anti >= 2 {
        add("anti-debug-apis", Category::Imports, 8, "multiple anti-debugging APIs".into());
    }
    let dl = funcs.iter().any(|f| f.starts_with("urldownloadtofile") || f.starts_with("internetopenurl") || f == "internetreadfile" || f == "winhttpreaddata");
    let run = funcs.iter().any(|f| f == "winexec" || f.starts_with("shellexecute") || f.starts_with("createprocess"));
    if dl && run {
        add("download-and-execute", Category::Imports, 15, "network download APIs together with process-launch APIs".into());
    }
    let crypt = funcs.iter().any(|f| f.starts_with("cryptencrypt") || f.starts_with("bcryptencrypt") || f.starts_with("cryptacquirecontext"));
    let enumf = funcs.iter().any(|f| f.starts_with("findfirstfile") || f.starts_with("findnextfile"));
    let mutf = funcs.iter().any(|f| f.starts_with("movefile") || f.starts_with("deletefile"));
    if crypt && enumf && mutf {
        add("file-encryption-combo", Category::Imports, 20, "crypto APIs + file enumeration + rename/delete (file-encryptor pattern; also backup/sync tools)".into());
    }

    // ---- strings (bounded scan, ASCII + UTF-16LE, case-insensitive)
    let window = &data[..data.len().min(MAX_STRING_SCAN_BYTES)];
    let (a, w) = string_matchers();
    let mut seen: HashSet<usize> = HashSet::new();
    for m in a.find_overlapping_iter(window) {
        seen.insert(m.pattern().as_usize());
    }
    for m in w.find_overlapping_iter(window) {
        seen.insert(m.pattern().as_usize());
    }
    let mut idx: Vec<usize> = seen.into_iter().collect();
    idx.sort();
    for i in idx {
        let (_, wt, label) = STRING_INDICATORS[i];
        add("string-indicator", Category::Strings, wt, format!("contains text: {label}"));
    }

    // ---- combine: per-category caps, then corroboration rule
    let mut per: std::collections::BTreeMap<Category, u32> = Default::default();
    for r in &reasons {
        *per.entry(r.category).or_default() += r.weight;
    }
    for (c, v) in per.iter_mut() {
        *v = (*v).min(c.cap());
    }
    let raw: u32 = per.values().sum::<u32>().min(100);
    let corroborating = per.values().filter(|&&v| v >= CORROBORATING_MIN).count();
    let (score, held) = if raw >= SUSPICIOUS_AT && corroborating < 2 { (SUSPICIOUS_AT - 1, true) } else { (raw, false) };
    let level = if score >= STRONG_AT {
        Level::Strong
    } else if score >= SUSPICIOUS_AT {
        Level::Suspicious
    } else if score >= WEAK_AT {
        Level::Weak
    } else {
        Level::None
    };
    Risk { score, level, reasons, held_for_lack_of_corroboration: held }
}

/// None when the data is not a PE file.
pub fn analyze(data: &[u8]) -> Option<(PeInfo, Risk)> {
    let info = parse(data).ok()?;
    let risk = assess(data, &info);
    Some((info, risk))
}
