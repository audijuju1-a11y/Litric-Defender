//! Litric Rule Syntax (`.lrs`) — Litric's original detection rule language.
//!
//! This is *not* YARA: no YARA code, grammar or data files are used. The format
//! is Litric's own, designed around what the rest of the engine can actually
//! observe (PE structure, entropy, format, import fingerprints, string sets).
//!
//! ```text
//! rule Win32.Dropper.EmbeddedPe_Gen {
//!     meta:
//!         description = "PE overlay carries a second executable"
//!         family      = "GenericDropper"
//!         severity    = "high"
//!         mitre       = "T1027.009,T1204.002"
//!         author      = "Litric Labs"
//!     strings:
//!         $mz  = "This program cannot be run in DOS mode" ascii
//!         $hex = { 4D 5A ?? 00 01 00 }
//!         $w   = "powershell -enc" wide nocase
//!     condition:
//!         pe.is_pe and pe.overlay_size > 4KB and 2 of them
//! }
//! ```
//!
//! Design goals, in order: total over hostile input, predictable cost, and
//! explainable matches. A rule can never execute code, loop unboundedly, or
//! allocate proportional to attacker-controlled numbers.

use std::collections::HashMap;
use std::fmt;

use crate::pe::PeInfo;

/// Maximum number of match positions retained per pattern.
const MAX_MATCHES_PER_PATTERN: usize = 4096;
/// Maximum number of pattern bytes in one rule file (compile-time guard).
const MAX_PATTERNS: usize = 20_000;
/// Files larger than this are not scanned with wildcard patterns (cost guard).
const WILDCARD_MAX_FILE: usize = 128 * 1024 * 1024;

/// Rule severity, which maps to a detection weight in the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    /// Unspecified rules default to Medium: enough to surface in results, not
    /// enough to auto-quarantine on their own.
    fn default() -> Self {
        Severity::Medium
    }
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        Some(match s.to_ascii_lowercase().as_str() {
            "informational" | "info" => Severity::Informational,
            "low" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Score contribution when the rule matches.
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Informational => 0,
            Severity::Low => 15,
            Severity::Medium => 35,
            Severity::High => 60,
            Severity::Critical => 85,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rule metadata block.
#[derive(Debug, Clone, Default)]
pub struct RuleMeta {
    pub description: String,
    pub family: Option<String>,
    pub severity: Severity,
    pub mitre: Vec<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub reference: Option<String>,
    pub tags: Vec<String>,
    pub revision: u32,
}

/// One pattern declared in the `strings:` section.
#[derive(Debug, Clone)]
pub enum PatternKind {
    Text {
        bytes: Vec<u8>,
        nocase: bool,
        wide: bool,
        ascii: bool,
        fullword: bool,
    },
    Hex { bytes: Vec<u8>, mask: Vec<bool> },
}

#[derive(Debug, Clone)]
pub struct RuleString {
    pub id: String,
    pub kind: PatternKind,
}

/// A parsed rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub meta: RuleMeta,
    pub strings: Vec<RuleString>,
    pub condition: Cond,
    /// Source file the rule came from (for diagnostics and attribution).
    pub source: String,
}

/// Rule parse/lint failure with a source position.
#[derive(Debug, Clone)]
pub struct RuleError {
    pub message: String,
    pub line: usize,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for RuleError {}

// ---------------------------------------------------------------------------
// Condition AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub enum Operand {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Field(Field),
    Call(Func, Vec<Operand>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    FileSize,
    Entropy,
    Format,
    Ext,
    PeIsPe,
    PeEntry,
    PeSections,
    PeTimestamp,
    PeImports,
    PeExports,
    PeImportHash,
    PeSigned,
    PeSignedNames,
    PeOverlaySize,
    PeOverlayMz,
    PeMaxSectionEntropy,
    PeCodeEntropy,
    PeWxSections,
    PeHighEntropySections,
    PeVirtualOnlySections,
    PeEntryOutsideSections,
    PeIsDotnet,
    PeIsDll,
    PeIsDriver,
    PePackerHints,
    PeHasVersionInfo,
    PeManifestAdmin,
    PeChecksumValid,
    PeRichHeader,
    PeDebugPdb,
    PeTls,
    PeTimestampYear,
    PeSectionCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    U8,
    U16,
    U16Be,
    U32,
    U32Be,
    U64,
    StrLen,
}

/// How many strings must match for a set expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetNeed {
    Any,
    All,
    Count(usize),
}

#[derive(Debug, Clone)]
pub enum Cond {
    Literal(bool),
    Match(String),
    Count(String, CmpOp, Operand),
    SetMatch {
        need: SetNeed,
        ids: Vec<String>,
    },
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    Compare(Operand, CmpOp, Operand),
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses a rule file that may contain several `rule` blocks.
pub fn parse_rule_file(text: &str, source: &str) -> Result<Vec<Rule>, RuleError> {
    let mut p = P::new(text);
    let mut rules = Vec::new();
    loop {
        p.skip_ws();
        if p.eof() {
            break;
        }
        let start = p.pos;
        let kw = p.ident_lower()?;
        if kw != "rule" {
            return Err(p.err_at(start, format!("expected `rule`, found `{kw}`")));
        }
        rules.push(p.parse_rule(source)?);
        if rules.len() > 10_000 {
            return Err(RuleError {
                message: "too many rules in one unit".into(),
                line: p.line(),
            });
        }
    }
    Ok(rules)
}

struct P<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> P<'a> {
    fn new(src: &'a str) -> Self {
        P {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn line(&self) -> usize {
        1 + self.src[..self.pos.min(self.src.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
    }

    fn err_at(&self, pos: usize, msg: impl Into<String>) -> RuleError {
        let line = 1 + self.src[..pos.min(self.src.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count();
        RuleError {
            message: msg.into(),
            line,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        loop {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.pos += 1;
            }
            // // line comment
            if self.peek() == Some(b'/') && self.bytes.get(self.pos + 1) == Some(&b'/') {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == b'\n' {
                        break;
                    }
                }
                continue;
            }
            // /* block comment */
            if self.peek() == Some(b'/') && self.bytes.get(self.pos + 1) == Some(&b'*') {
                self.pos += 2;
                while self.pos + 1 < self.bytes.len() {
                    if self.bytes[self.pos] == b'*' && self.bytes[self.pos + 1] == b'/' {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn ident_lower(&mut self) -> Result<String, RuleError> {
        self.skip_ws();
        let start = self.pos;
        let s = self.ident_raw()?;
        let _ = start;
        Ok(s.to_ascii_lowercase())
    }

    fn ident_raw(&mut self) -> Result<String, RuleError> {
        self.skip_ws();
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.err_at(start, "expected identifier"));
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn expect(&mut self, ch: u8) -> Result<(), RuleError> {
        self.skip_ws();
        if self.peek() == Some(ch) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err_at(self.pos, format!("expected `{}`", ch as char)))
        }
    }

    fn parse_rule(&mut self, source: &str) -> Result<Rule, RuleError> {
        let name = self.ident_raw()?;
        self.expect(b'{')?;
        let mut meta = RuleMeta {
            severity: Severity::Medium,
            ..Default::default()
        };
        let mut strings = Vec::new();
        let mut condition: Option<Cond> = None;

        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(self.err_at(self.pos, "unterminated rule")),
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => {}
            }
            let section = self.ident_lower()?;
            match section.as_str() {
                "meta" => {
                    self.expect(b':')?;
                    self.parse_meta(&mut meta)?;
                }
                "strings" => {
                    self.expect(b':')?;
                    self.parse_strings(&mut strings)?;
                }
                "condition" => {
                    self.expect(b':')?;
                    let (toks, after_brace) = tokenize_condition(self.src, self.pos)?;
                    let mut cp = CP::new(toks);
                    condition = Some(cp.parse_expr()?);
                    if !cp.at_end() {
                        return Err(self.err_at(self.pos, "trailing tokens in condition"));
                    }
                    self.pos = after_brace;
                    // `condition` is the terminal section of a rule.
                    break;
                }
                other => {
                    return Err(self.err_at(
                        self.pos,
                        format!("unknown section `{other}` (expected meta, strings, condition)"),
                    ))
                }
            }
        }

        let Some(condition) = condition else {
            return Err(self.err_at(self.pos, format!("rule `{name}` has no condition")));
        };
        // Validate that every referenced string exists.
        validate_refs(&condition, &strings, self.src)
            .map_err(|m| self.err_at(self.pos, m))?;

        Ok(Rule {
            name,
            meta,
            strings,
            condition,
            source: source.to_string(),
        })
    }

    fn parse_meta(&mut self, meta: &mut RuleMeta) -> Result<(), RuleError> {
        loop {
            self.skip_ws();
            if matches!(self.peek(), Some(b'}')) || self.eof() {
                return Ok(());
            }
            // Stop when the next section keyword appears.
            let save = self.pos;
            match self.peek() {
                Some(c) if c.is_ascii_alphabetic() => {}
                _ => return Ok(()),
            }
            let key = self.ident_lower()?;
            if matches!(key.as_str(), "strings" | "condition") {
                self.pos = save;
                return Ok(());
            }
            self.expect(b'=')?;
            self.skip_ws();
            let value = self.read_quoted()?;
            match key.as_str() {
                "description" => meta.description = value,
                "family" => meta.family = Some(value),
                "severity" => {
                    meta.severity = Severity::parse(&value).ok_or_else(|| RuleError {
                        message: format!("invalid severity `{value}`"),
                        line: self.line(),
                    })?;
                }
                "mitre" => {
                    meta.mitre = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "author" => meta.author = Some(value),
                "license" => meta.license = Some(value),
                "reference" => meta.reference = Some(value),
                "tags" => {
                    meta.tags = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "revision" => {
                    meta.revision = value.trim().parse().unwrap_or(0);
                }
                other => {
                    return Err(self.err_at(
                        self.pos,
                        format!("unknown meta key `{other}`"),
                    ))
                }
            }
        }
    }

    fn read_quoted(&mut self) -> Result<String, RuleError> {
        self.skip_ws();
        if self.peek() != Some(b'"') {
            return Err(self.err_at(self.pos, "expected a quoted string"));
        }
        self.pos += 1;
        let mut out = String::new();
        while let Some(c) = self.peek() {
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or_else(|| RuleError {
                        message: "unterminated escape".into(),
                        line: self.line(),
                    })?;
                    self.pos += 1;
                    out.push(match e {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'\\' => '\\',
                        b'"' => '"',
                        b'x' => {
                            let hi = self.hex_digit()?;
                            let lo = self.hex_digit()?;
                            char::from(hi * 16 + lo)
                        }
                        other => other as char,
                    });
                }
                _ => {
                    // Copy raw UTF-8 sequence bytes verbatim.
                    self.pos -= 1;
                    let ch_len = utf8_len(self.bytes[self.pos]);
                    let end = (self.pos + ch_len).min(self.bytes.len());
                    out.push_str(&self.src[self.pos..end]);
                    self.pos = end;
                }
            }
        }
        Err(self.err_at(self.pos, "unterminated string literal"))
    }

    fn hex_digit(&mut self) -> Result<u8, RuleError> {
        let c = self.peek().ok_or_else(|| RuleError {
            message: "unterminated hex escape".into(),
            line: self.line(),
        })?;
        self.pos += 1;
        Ok(match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => {
                return Err(self.err_at(self.pos, "bad hex escape"));
            }
        })
    }

    fn parse_strings(&mut self, out: &mut Vec<RuleString>) -> Result<(), RuleError> {
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(self.err_at(self.pos, "unterminated strings section")),
                Some(b'}') => return Ok(()),
                _ => {}
            }
            // Look ahead: if it's a section keyword, stop.
            let save = self.pos;
            if let Ok(kw) = self.ident_lower() {
                if kw == "condition" || kw == "meta" {
                    self.pos = save;
                    return Ok(());
                }
            }
            self.pos = save;
            self.expect(b'$')?;
            let id = self.ident_raw()?;
            self.expect(b'=')?;
            self.skip_ws();
            let kind = match self.peek() {
                Some(b'"') => {
                    let s = self.read_quoted()?;
                    let mut nocase = false;
                    let mut wide = false;
                    let mut ascii = false;
                    let mut fullword = false;
                    loop {
                        let save = self.pos;
                        self.skip_ws();
                        let Ok(m) = self.ident_lower() else {
                            self.pos = save;
                            break;
                        };
                        match m.as_str() {
                            "nocase" => nocase = true,
                            "wide" => wide = true,
                            "ascii" => ascii = true,
                            "fullword" => fullword = true,
                            _ => {
                                self.pos = save;
                                break;
                            }
                        }
                    }
                    if !ascii && !wide {
                        ascii = true;
                    }
                    PatternKind::Text {
                        bytes: s.into_bytes(),
                        nocase,
                        wide,
                        ascii,
                        fullword,
                    }
                }
                Some(b'{') => {
                    // Hex pattern with `??` and nibble wildcards.
                    self.pos += 1;
                    let mut bytes = Vec::new();
                    let mut mask = Vec::new();
                    loop {
                        self.skip_ws();
                        match self.peek() {
                            None => return Err(self.err_at(self.pos, "unterminated hex pattern")),
                            Some(b'}') => {
                                self.pos += 1;
                                break;
                            }
                            Some(b'?') => {
                                self.pos += 1;
                                if self.peek() == Some(b'?') {
                                    self.pos += 1;
                                    bytes.push(0);
                                    mask.push(false);
                                } else {
                                    return Err(self.err_at(
                                        self.pos,
                                        "nibble wildcards are not supported; use `??` for a whole byte",
                                    ));
                                }
                            }
                            Some(_) => {
                                let hi = self.hex_digit()?;
                                let lo = self.hex_digit()?;
                                bytes.push(hi * 16 + lo);
                                mask.push(true);
                            }
                        }
                    }
                    if bytes.is_empty() {
                        return Err(self.err_at(self.pos, "empty hex pattern"));
                    }
                    PatternKind::Hex { bytes, mask }
                }
                _ => return Err(self.err_at(self.pos, "expected string or hex pattern")),
            };
            if out.len() >= MAX_PATTERNS {
                return Err(self.err_at(self.pos, "too many strings in one rule"));
            }
            out.push(RuleString { id, kind });
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

fn validate_refs(cond: &Cond, strings: &[RuleString], _src: &str) -> Result<(), String> {
    let has = |id: &str| {
        if let Some(prefix) = id.strip_suffix('*') {
            strings.iter().any(|s| s.id.starts_with(prefix))
        } else {
            strings.iter().any(|s| s.id == id)
        }
    };
    match cond {
        Cond::Match(id) => {
            if !has(id) {
                return Err(format!("condition references unknown string `${id}`"));
            }
        }
        Cond::Count(id, _, _) => {
            if !has(id) {
                return Err(format!("condition references unknown string `${id}`"));
            }
        }
        Cond::SetMatch { ids, .. } => {
            for id in ids {
                if !has(id) {
                    return Err(format!("condition references unknown string `${id}`"));
                }
            }
        }
        Cond::And(a, b) | Cond::Or(a, b) => {
            validate_refs(a, strings, _src)?;
            validate_refs(b, strings, _src)?;
        }
        Cond::Not(a) => validate_refs(a, strings, _src)?,
        Cond::Compare(a, _, b) => {
            validate_operand(a, strings)?;
            validate_operand(b, strings)?;
        }
        Cond::Literal(_) => {}
    }
    Ok(())
}

fn validate_operand(op: &Operand, strings: &[RuleString]) -> Result<(), String> {
    match op {
        Operand::Call(_, args) => {
            for a in args {
                validate_operand(a, strings)?;
            }
        }
        _ => {
            let _ = strings;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Condition tokenizer / parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    Op(CmpOp),
    LParen,
    RParen,
    Comma,
    Hash,
    Dollar,
}

/// Tokenizes a condition and returns the tokens plus the byte offset just past
/// the rule's closing brace, so the file parser can continue with the next rule.
fn tokenize_condition(src: &str, from: usize) -> Result<(Vec<Tok>, usize), RuleError> {
    let b = src.as_bytes();
    let mut i = from;
    let mut out = Vec::new();
    let line_of = |pos: usize| {
        1 + src[..pos.min(src.len())].bytes().filter(|c| *c == b'\n').count()
    };
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b'}' => return Ok((out, i + 1)), // end of rule body
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'#' => {
                out.push(Tok::Hash);
                i += 1;
            }
            b'$' => {
                out.push(Tok::Dollar);
                i += 1;
            }
            b'=' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Op(CmpOp::Eq));
                    i += 2;
                } else {
                    return Err(RuleError {
                        message: "use `==` for comparison".into(),
                        line: line_of(i),
                    });
                }
            }
            b'!' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Op(CmpOp::Ne));
                    i += 2;
                } else {
                    return Err(RuleError {
                        message: "use `not` for negation".into(),
                        line: line_of(i),
                    });
                }
            }
            b'<' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Op(CmpOp::Le));
                    i += 2;
                } else {
                    out.push(Tok::Op(CmpOp::Lt));
                    i += 1;
                }
            }
            b'>' => {
                if b.get(i + 1) == Some(&b'=') {
                    out.push(Tok::Op(CmpOp::Ge));
                    i += 2;
                } else {
                    out.push(Tok::Op(CmpOp::Gt));
                    i += 1;
                }
            }
            b'"' => {
                let mut s = String::new();
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    s.push(b[i] as char);
                    i += 1;
                }
                if i >= b.len() {
                    return Err(RuleError {
                        message: "unterminated string in condition".into(),
                        line: line_of(i),
                    });
                }
                i += 1;
                out.push(Tok::Str(s));
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                let mut is_float = false;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    if b[i] == b'.' {
                        is_float = true;
                    }
                    i += 1;
                }
                let num = &src[start..i];
                // unit suffixes
                let mut mult: i64 = 1;
                if i < b.len() {
                    let rest = &src[i..];
                    let upper = rest.to_ascii_lowercase();
                    for (suffix, m) in [("kb", 1024i64), ("mb", 1024 * 1024), ("gb", 1024 * 1024 * 1024)] {
                        if upper.starts_with(suffix) {
                            mult = m;
                            i += suffix.len();
                            break;
                        }
                    }
                }
                if is_float {
                    let v: f64 = num.parse().map_err(|_| RuleError {
                        message: format!("bad number `{num}`"),
                        line: line_of(start),
                    })?;
                    out.push(Tok::Float(v * mult as f64));
                } else {
                    let v: i64 = if let Some(hex) = num.strip_prefix("0x") {
                        i64::from_str_radix(hex, 16).unwrap_or(0)
                    } else {
                        num.parse().unwrap_or(0)
                    };
                    out.push(Tok::Int(v * mult));
                }
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.')
                {
                    i += 1;
                }
                out.push(Tok::Ident(src[start..i].to_string()));
            }
            _ => {
                return Err(RuleError {
                    message: format!("unexpected character `{}` in condition", c as char),
                    line: line_of(i),
                })
            }
        }
    }
    Ok((out, src.len()))
}

struct CP {
    toks: Vec<Tok>,
    pos: usize,
    line: usize,
}

impl CP {
    fn new(toks: Vec<Tok>) -> Self {
        CP {
            toks,
            pos: 0,
            line: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn err(&self, msg: impl Into<String>) -> RuleError {
        RuleError {
            message: msg.into(),
            line: self.line,
        }
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case(kw))
    }

    /// True when the next token starts a comparison rather than continuing a
    /// boolean expression. Lets `pe.is_pe` stand alone as a truthiness test.
    fn is_cmp_start(&self) -> bool {
        match self.peek() {
            Some(Tok::Op(_)) => true,
            Some(Tok::Ident(s)) => matches!(
                s.to_ascii_lowercase().as_str(),
                "contains" | "startswith" | "endswith" | "is" | "eq"
            ),
            _ => false,
        }
    }

    fn parse_expr(&mut self) -> Result<Cond, RuleError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Cond, RuleError> {
        let mut left = self.parse_and()?;
        while self.is_kw("or") {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Cond::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Cond, RuleError> {
        let mut left = self.parse_not()?;
        while self.is_kw("and") {
            self.pos += 1;
            let right = self.parse_not()?;
            left = Cond::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Cond, RuleError> {
        if self.is_kw("not") {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(Cond::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Cond, RuleError> {
        match self.peek().cloned() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.parse_expr()?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err(self.err("expected `)`")),
                }
            }
            Some(Tok::Dollar) => {
                self.pos += 1;
                let id = match self.next() {
                    Some(Tok::Ident(s)) => s,
                    _ => return Err(self.err("expected string identifier after `$`")),
                };
                Ok(Cond::Match(id))
            }
            Some(Tok::Hash) => {
                self.pos += 1;
                let id = match self.next() {
                    Some(Tok::Ident(s)) => s,
                    _ => return Err(self.err("expected string identifier after `#`")),
                };
                let op = self.parse_cmp_op()?;
                let rhs = self.parse_operand()?;
                Ok(Cond::Count(id, op, rhs))
            }
            Some(Tok::Ident(ref kw)) if kw.eq_ignore_ascii_case("any") || kw.eq_ignore_ascii_case("all") => {
                let need = if kw.eq_ignore_ascii_case("any") {
                    SetNeed::Any
                } else {
                    SetNeed::All
                };
                self.pos += 1;
                if !self.is_kw("of") {
                    return Err(self.err("expected `of`"));
                }
                self.pos += 1;
                let ids = self.parse_set()?;
                Ok(Cond::SetMatch { need, ids })
            }
            Some(Tok::Ident(ref kw)) if kw.eq_ignore_ascii_case("true") => {
                self.pos += 1;
                Ok(Cond::Literal(true))
            }
            Some(Tok::Ident(ref kw)) if kw.eq_ignore_ascii_case("false") => {
                self.pos += 1;
                Ok(Cond::Literal(false))
            }
            Some(Tok::Int(n)) => {
                // `N of them`
                if matches!(self.toks.get(self.pos + 1), Some(Tok::Ident(k)) if k.eq_ignore_ascii_case("of"))
                {
                    self.pos += 2;
                    let ids = self.parse_set()?;
                    return Ok(Cond::SetMatch {
                        need: SetNeed::Count(n.max(0) as usize),
                        ids,
                    });
                }
                let lhs = self.parse_operand()?;
                if !self.is_cmp_start() {
                    return Ok(Cond::Compare(lhs, CmpOp::Ne, Operand::Int(0)));
                }
                let op = self.parse_cmp_op()?;
                let rhs = self.parse_operand()?;
                Ok(Cond::Compare(lhs, op, rhs))
            }
            Some(Tok::Float(_)) | Some(Tok::Str(_)) | Some(Tok::Ident(_)) => {
                let lhs = self.parse_operand()?;
                if !self.is_cmp_start() {
                    // A bare boolean field (`pe.is_pe`, `not pe.signed`) is a
                    // truthiness test against zero/false.
                    return Ok(Cond::Compare(lhs, CmpOp::Ne, Operand::Int(0)));
                }
                let op = self.parse_cmp_op()?;
                let rhs = self.parse_operand()?;
                Ok(Cond::Compare(lhs, op, rhs))
            }
            other => Err(self.err(format!("unexpected token in condition: {other:?}"))),
        }
    }

    fn parse_cmp_op(&mut self) -> Result<CmpOp, RuleError> {
        match self.next() {
            Some(Tok::Op(op)) => Ok(op),
            Some(Tok::Ident(s)) => {
                let lower = s.to_ascii_lowercase();
                match lower.as_str() {
                    "contains" => Ok(CmpOp::Contains),
                    "startswith" => Ok(CmpOp::StartsWith),
                    "endswith" => Ok(CmpOp::EndsWith),
                    "is" | "eq" => Ok(CmpOp::Eq),
                    _ => Err(self.err(format!("unknown operator `{s}`"))),
                }
            }
            _ => Err(self.err("expected comparison operator")),
        }
    }

    fn parse_set(&mut self) -> Result<Vec<String>, RuleError> {
        let mut ids = Vec::new();
        if self.is_kw("them") {
            self.pos += 1;
            ids.push("*".to_string());
            return Ok(ids);
        }
        if !matches!(self.peek(), Some(Tok::LParen)) {
            // single identifier set: `of $a*`
            if matches!(self.peek(), Some(Tok::Dollar)) {
                self.pos += 1;
                if let Some(Tok::Ident(id)) = self.next() {
                    ids.push(id);
                    return Ok(ids);
                }
            }
            return Err(self.err("expected `them` or a `(...)` string set"));
        }
        self.pos += 1;
        loop {
            match self.next() {
                Some(Tok::Dollar) => {
                    let id = match self.next() {
                        Some(Tok::Ident(s)) => s,
                        _ => return Err(self.err("expected identifier in string set")),
                    };
                    ids.push(id);
                }
                _ => return Err(self.err("expected `$identifier` in string set")),
            }
            match self.next() {
                Some(Tok::Comma) => continue,
                Some(Tok::RParen) => break,
                _ => return Err(self.err("expected `,` or `)` in string set")),
            }
        }
        if ids.is_empty() {
            return Err(self.err("empty string set"));
        }
        Ok(ids)
    }

    fn parse_operand(&mut self) -> Result<Operand, RuleError> {
        match self.next() {
            Some(Tok::Int(n)) => Ok(Operand::Int(n)),
            Some(Tok::Float(f)) => Ok(Operand::Float(f)),
            Some(Tok::Str(s)) => Ok(Operand::Str(s)),
            Some(Tok::Ident(name)) => {
                let lower = name.to_ascii_lowercase();
                if let Some(field) = field_from_name(&lower) {
                    return Ok(Operand::Field(field));
                }
                if matches!(self.peek(), Some(Tok::LParen)) {
                    let func = match lower.as_str() {
                        "uint8" | "u8" => Func::U8,
                        "uint16" | "u16" => Func::U16,
                        "uint16be" | "u16be" => Func::U16Be,
                        "uint32" | "u32" => Func::U32,
                        "uint32be" | "u32be" => Func::U32Be,
                        "uint64" | "u64" => Func::U64,
                        "strlen" => Func::StrLen,
                        _ => return Err(self.err(format!("unknown function `{name}`"))),
                    };
                    self.pos += 1;
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Tok::RParen)) {
                        loop {
                            args.push(self.parse_operand()?);
                            match self.next() {
                                Some(Tok::Comma) => continue,
                                Some(Tok::RParen) => break,
                                _ => return Err(self.err("expected `,` or `)` in call")),
                            }
                        }
                    } else {
                        self.pos += 1;
                    }
                    return Ok(Operand::Call(func, args));
                }
                if lower == "true" {
                    return Ok(Operand::Bool(true));
                }
                if lower == "false" {
                    return Ok(Operand::Bool(false));
                }
                Err(self.err(format!("unknown field `{name}`")))
            }
            other => Err(self.err(format!("expected operand, found {other:?}"))),
        }
    }
}

fn field_from_name(name: &str) -> Option<Field> {
    Some(match name {
        "filesize" => Field::FileSize,
        "entropy" => Field::Entropy,
        "format" => Field::Format,
        "ext" => Field::Ext,
        "pe.is_pe" => Field::PeIsPe,
        "pe.entry" => Field::PeEntry,
        "pe.sections" => Field::PeSections,
        "pe.timestamp" => Field::PeTimestamp,
        "pe.timestamp_year" => Field::PeTimestampYear,
        "pe.imports" => Field::PeImports,
        "pe.exports" => Field::PeExports,
        "pe.imphash" => Field::PeImportHash,
        "pe.signed" => Field::PeSigned,
        "pe.signer" => Field::PeSignedNames,
        "pe.overlay_size" => Field::PeOverlaySize,
        "pe.overlay_mz" => Field::PeOverlayMz,
        "pe.max_section_entropy" => Field::PeMaxSectionEntropy,
        "pe.code_entropy" => Field::PeCodeEntropy,
        "pe.wx_sections" => Field::PeWxSections,
        "pe.high_entropy_sections" => Field::PeHighEntropySections,
        "pe.virtual_only_sections" => Field::PeVirtualOnlySections,
        "pe.entry_outside_sections" => Field::PeEntryOutsideSections,
        "pe.is_dotnet" => Field::PeIsDotnet,
        "pe.is_dll" => Field::PeIsDll,
        "pe.is_driver" => Field::PeIsDriver,
        "pe.packer_hints" => Field::PePackerHints,
        "pe.has_version_info" => Field::PeHasVersionInfo,
        "pe.manifest_admin" => Field::PeManifestAdmin,
        "pe.checksum_valid" => Field::PeChecksumValid,
        "pe.rich_header" => Field::PeRichHeader,
        "pe.debug_pdb" => Field::PeDebugPdb,
        "pe.tls" => Field::PeTls,
        "pe.section_count" => Field::PeSectionCount,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Compilation and matching
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hay {
    Raw,
    Lower,
}

#[derive(Debug)]
struct CompiledPattern {
    rule: usize,
    string: usize,
    hay: Hay,
    kind: CK,
    fullword: bool,
    wide: bool,
}

#[derive(Debug)]
enum CK {
    Exact(Vec<u8>),
    Wild(Vec<u8>, Vec<bool>),
}

#[derive(Debug, Default)]
struct AcNode {
    next: HashMap<u8, usize>,
    fail: usize,
    out: Vec<usize>,
}

#[derive(Debug, Default)]
struct Ac {
    nodes: Vec<AcNode>,
}

impl Ac {
    fn new() -> Self {
        Ac {
            nodes: vec![AcNode::default()],
        }
    }

    fn insert(&mut self, pattern: &[u8], id: usize) {
        let mut node = 0usize;
        for &b in pattern {
            if let Some(&next) = self.nodes[node].next.get(&b) {
                node = next;
            } else {
                let idx = self.nodes.len();
                self.nodes.push(AcNode::default());
                self.nodes[node].next.insert(b, idx);
                node = idx;
            }
        }
        self.nodes[node].out.push(id);
    }

    fn build(&mut self) {
        let mut queue = std::collections::VecDeque::new();
        let root_children: Vec<usize> = self.nodes[0].next.values().copied().collect();
        for child in root_children {
            self.nodes[child].fail = 0;
            queue.push_back(child);
        }
        while let Some(node) = queue.pop_front() {
            let keys: Vec<u8> = self.nodes[node].next.keys().copied().collect();
            for b in keys {
                let child = self.nodes[node].next[&b];
                let mut f = self.nodes[node].fail;
                loop {
                    if let Some(&n) = self.nodes[f].next.get(&b) {
                        if n != child {
                            self.nodes[child].fail = n;
                            break;
                        }
                    }
                    if f == 0 {
                        self.nodes[child].fail = 0;
                        break;
                    }
                    f = self.nodes[f].fail;
                }
                let fail_out = self.nodes[self.nodes[child].fail].out.clone();
                self.nodes[child].out.extend(fail_out);
                queue.push_back(child);
            }
        }
    }

    fn search(&self, hay: &[u8], cb: &mut impl FnMut(usize, usize)) {
        let mut node = 0usize;
        for (i, &b) in hay.iter().enumerate() {
            loop {
                if let Some(&next) = self.nodes[node].next.get(&b) {
                    node = next;
                    break;
                }
                if node == 0 {
                    break;
                }
                node = self.nodes[node].fail;
            }
            for &pid in &self.nodes[node].out {
                cb(pid, i);
            }
        }
    }
}

/// A compiled, ready-to-scan rule set.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    patterns: Vec<CompiledPattern>,
    ac_raw: Ac,
    ac_lower: Ac,
    /// Per-rule: string id -> index into `counts`.
    rule_index: Vec<HashMap<String, usize>>,
    /// Per-rule: string ids in declaration order.
    rule_all: Vec<Vec<String>>,
}

/// A rule that fired, with the strings that matched.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_index: usize,
    pub name: String,
    pub severity: Severity,
    pub family: Option<String>,
    pub description: String,
    pub mitre: Vec<String>,
    pub matched_strings: Vec<String>,
}

impl RuleSet {
    pub fn empty() -> Self {
        let mut ac = Ac::new();
        ac.build();
        RuleSet {
            rules: Vec::new(),
            patterns: Vec::new(),
            ac_raw: Ac::new(),
            ac_lower: ac,
            rule_index: Vec::new(),
            rule_all: Vec::new(),
        }
    }

    /// Compiles rules into automatons.
    pub fn compile(rules: Vec<Rule>) -> Result<RuleSet, RuleError> {
        let mut patterns: Vec<CompiledPattern> = Vec::new();
        for (ri, rule) in rules.iter().enumerate() {
            for (si, s) in rule.strings.iter().enumerate() {
                match &s.kind {
                    PatternKind::Text {
                        bytes,
                        nocase,
                        wide,
                        ascii,
                        fullword,
                    } => {
                        if *ascii {
                            let (pat, hay) = if *nocase {
                                (lower_ascii(bytes), Hay::Lower)
                            } else {
                                (bytes.clone(), Hay::Raw)
                            };
                            patterns.push(CompiledPattern {
                                rule: ri,
                                string: si,
                                hay,
                                kind: CK::Exact(pat),
                                fullword: *fullword,
                                wide: false,
                            });
                        }
                        if *wide {
                            let wide_bytes = to_wide(bytes);
                            let (pat, hay) = if *nocase {
                                (lower_ascii(&wide_bytes), Hay::Lower)
                            } else {
                                (wide_bytes, Hay::Raw)
                            };
                            patterns.push(CompiledPattern {
                                rule: ri,
                                string: si,
                                hay,
                                kind: CK::Exact(pat),
                                fullword: false, // wide boundary checks are not enforced
                                wide: true,
                            });
                        }
                    }
                    PatternKind::Hex { bytes, mask } => {
                        let has_wild = mask.iter().any(|m| !*m);
                        if has_wild {
                            patterns.push(CompiledPattern {
                                rule: ri,
                                string: si,
                                hay: Hay::Raw,
                                kind: CK::Wild(bytes.clone(), mask.clone()),
                                fullword: false,
                                wide: false,
                            });
                        } else {
                            patterns.push(CompiledPattern {
                                rule: ri,
                                string: si,
                                hay: Hay::Raw,
                                kind: CK::Exact(bytes.clone()),
                                fullword: false,
                                wide: false,
                            });
                        }
                    }
                }
            }
        }

        let mut ac_raw = Ac::new();
        let mut ac_lower = Ac::new();
        for (pid, p) in patterns.iter().enumerate() {
            if let CK::Exact(bytes) = &p.kind {
                if bytes.is_empty() {
                    continue;
                }
                match p.hay {
                    Hay::Raw => ac_raw.insert(bytes, pid),
                    Hay::Lower => ac_lower.insert(bytes, pid),
                }
            }
        }
        ac_raw.build();
        ac_lower.build();

        let mut rule_index = Vec::with_capacity(rules.len());
        let mut rule_all = Vec::with_capacity(rules.len());
        for r in &rules {
            let mut map = HashMap::new();
            let mut all = Vec::with_capacity(r.strings.len());
            for (i, s) in r.strings.iter().enumerate() {
                map.insert(s.id.clone(), i);
                all.push(s.id.clone());
            }
            rule_index.push(map);
            rule_all.push(all);
        }

        Ok(RuleSet {
            rules,
            patterns,
            ac_raw,
            ac_lower,
            rule_index,
            rule_all,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Scans a buffer and returns every rule that fired.
    pub fn scan(&self, data: &[u8], pe: Option<&PeInfo>, format: &str, ext: &str) -> Vec<RuleMatch> {
        if self.rules.is_empty() {
            return Vec::new();
        }
        let mut counts: Vec<Vec<u32>> = self
            .rules
            .iter()
            .map(|r| vec![0u32; r.strings.len()])
            .collect();

        let lower = if self.ac_lower.nodes.len() > 1 {
            Some(lower_ascii(data))
        } else {
            None
        };

        // Exact patterns via Aho-Corasick.
        let mut hit = |pid: usize, end: usize, counts: &mut Vec<Vec<u32>>| {
            let p = &self.patterns[pid];
            if p.fullword {
                let bytes = match &p.kind {
                    CK::Exact(b) => b,
                    _ => return,
                };
                let start = end.saturating_sub(bytes.len().saturating_sub(1));
                if start > 0 {
                    let prev = data.get(start - 1).copied().unwrap_or(0);
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        return;
                    }
                }
                if let Some(&next) = data.get(end + 1) {
                    if next.is_ascii_alphanumeric() || next == b'_' {
                        return;
                    }
                }
            }
            let slot = &mut counts[p.rule][p.string];
            *slot = slot.saturating_add(1);
        };

        self.ac_raw.search(data, &mut |pid, end| {
            // Re-borrow inside the closure is avoided by passing counts explicitly.
            let p = &self.patterns[pid];
            if p.fullword {
                let bytes = match &p.kind {
                    CK::Exact(b) => b,
                    _ => return,
                };
                let start = end.saturating_sub(bytes.len().saturating_sub(1));
                if start > 0 {
                    let prev = data.get(start - 1).copied().unwrap_or(0);
                    if prev.is_ascii_alphanumeric() || prev == b'_' {
                        return;
                    }
                }
                if let Some(&next) = data.get(end + 1) {
                    if next.is_ascii_alphanumeric() || next == b'_' {
                        return;
                    }
                }
            }
            let slot = &mut counts[p.rule][p.string];
            *slot = slot.saturating_add(1);
        });
        if let Some(lower) = &lower {
            self.ac_lower.search(lower, &mut |pid, end| {
                let p = &self.patterns[pid];
                if p.fullword && !p.wide {
                    let bytes = match &p.kind {
                        CK::Exact(b) => b,
                        _ => return,
                    };
                    let start = end.saturating_sub(bytes.len().saturating_sub(1));
                    if start > 0 {
                        let prev = data.get(start - 1).copied().unwrap_or(0);
                        if prev.is_ascii_alphanumeric() || prev == b'_' {
                            return;
                        }
                    }
                    if let Some(&next) = data.get(end + 1) {
                        if next.is_ascii_alphanumeric() || next == b'_' {
                            return;
                        }
                    }
                }
                let slot = &mut counts[p.rule][p.string];
                *slot = slot.saturating_add(1);
            });
        }
        let _ = &mut hit;

        // Wildcard patterns: naive scan with a longest-run prefilter.
        if data.len() <= WILDCARD_MAX_FILE {
            for (pid, p) in self.patterns.iter().enumerate() {
                if let CK::Wild(bytes, mask) = &p.kind {
                    let n = wildcard_count(data, bytes, mask, MAX_MATCHES_PER_PATTERN);
                    if n > 0 {
                        let slot = &mut counts[p.rule][p.string];
                        *slot = slot.saturating_add(n as u32);
                    }
                    let _ = pid;
                }
            }
        }

        // Evaluate conditions.
        let mut out = Vec::new();
        for (ri, rule) in self.rules.iter().enumerate() {
            let ctx = EvalCtx {
                data,
                file_size: data.len() as u64,
                entropy: crate::entropy::entropy(data),
                format,
                ext,
                pe,
                counts: &counts[ri],
                ids: &self.rule_index[ri],
                all_ids: &self.rule_all[ri],
            };
            if eval(&rule.condition, &ctx) {
                let matched: Vec<String> = rule
                    .strings
                    .iter()
                    .enumerate()
                    .filter(|(si, _)| counts[ri][*si] > 0)
                    .map(|(_, s)| s.id.clone())
                    .collect();
                out.push(RuleMatch {
                    rule_index: ri,
                    name: rule.name.clone(),
                    severity: rule.meta.severity,
                    family: rule.meta.family.clone(),
                    description: rule.meta.description.clone(),
                    mitre: rule.meta.mitre.clone(),
                    matched_strings: matched,
                });
            }
        }
        out
    }
}

fn wildcard_count(hay: &[u8], pat: &[u8], mask: &[bool], cap: usize) -> usize {
    if pat.is_empty() || hay.len() < pat.len() {
        return 0;
    }
    // Prefilter on the longest fully-masked run.
    let (mut best_start, mut best_len, mut cur_start, mut cur_len) = (0usize, 0usize, 0usize, 0usize);
    for (i, &m) in mask.iter().enumerate() {
        if m {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }
    let mut count = 0usize;
    let limit = hay.len() - pat.len();
    let mut i = 0usize;
    while i <= limit {
        if best_len >= 2 {
            let needle = &pat[best_start..best_start + best_len];
            match find_from(hay, needle, i + best_start) {
                Some(found) => {
                    let base = found - best_start;
                    if base < i {
                        i += 1;
                        continue;
                    }
                    i = base;
                }
                None => break,
            }
        }
        // Verify the candidate at `i`.
        let mut ok = true;
        for k in 0..pat.len() {
            if mask[k] && hay[i + k] != pat[k] {
                ok = false;
                break;
            }
            if !mask[k] && pat[k] != 0 && (hay[i + k] & 0x0F) != (pat[k] & 0x0F) {
                // nibble-constrained wildcard
                ok = false;
                break;
            }
        }
        if ok {
            count += 1;
            if count >= cap {
                return count;
            }
            i += pat.len().max(1);
        } else {
            i += 1;
        }
    }
    count
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() || needle.is_empty() || hay.len() - from < needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn lower_ascii(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn to_wide(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(b);
        out.push(0);
    }
    out
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

struct EvalCtx<'a> {
    data: &'a [u8],
    file_size: u64,
    entropy: f64,
    format: &'a str,
    ext: &'a str,
    pe: Option<&'a PeInfo>,
    counts: &'a [u32],
    ids: &'a HashMap<String, usize>,
    all_ids: &'a [String],
}

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
}

impl Val {
    fn as_f64(&self) -> Option<f64> {
        match self {
            Val::Int(i) => Some(*i as f64),
            Val::Float(f) => Some(*f),
            Val::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Val::Str(_) => None,
        }
    }
    fn as_str(&self) -> Option<String> {
        match self {
            Val::Str(s) => Some(s.clone()),
            Val::Int(i) => Some(i.to_string()),
            Val::Float(f) => Some(f.to_string()),
            Val::Bool(b) => Some(b.to_string()),
        }
    }
}

fn eval(cond: &Cond, ctx: &EvalCtx<'_>) -> bool {
    match cond {
        Cond::Literal(b) => *b,
        Cond::Match(id) => match_string_count(id, ctx).is_some_and(|c| c > 0),
        Cond::Count(id, op, rhs) => {
            let n = match_string_count(id, ctx).unwrap_or(0) as i64;
            let rv = eval_operand(rhs, ctx);
            compare(&Val::Int(n), *op, &rv)
        }
        Cond::SetMatch { need, ids } => {
            let indices = resolve_ids(ids, ctx);
            let matched = indices.iter().filter(|i| ctx.counts[**i] > 0).count();
            match need {
                SetNeed::Any => matched > 0,
                SetNeed::All => !indices.is_empty() && matched == indices.len(),
                SetNeed::Count(n) => matched >= *n,
            }
        }
        Cond::And(a, b) => eval(a, ctx) && eval(b, ctx),
        Cond::Or(a, b) => eval(a, ctx) || eval(b, ctx),
        Cond::Not(a) => !eval(a, ctx),
        Cond::Compare(a, op, b) => compare(&eval_operand(a, ctx), *op, &eval_operand(b, ctx)),
    }
}

/// Expands a string set into rule-local string indices.
///
/// `*` means every string in the rule; `prefix*` globs over declared ids.
fn resolve_ids(ids: &[String], ctx: &EvalCtx<'_>) -> Vec<usize> {
    if ids.len() == 1 && ids[0] == "*" {
        return (0..ctx.counts.len()).collect();
    }
    let mut out: Vec<usize> = Vec::new();
    for id in ids {
        if let Some(prefix) = id.strip_suffix('*') {
            for (i, s) in ctx.all_ids.iter().enumerate() {
                if s.starts_with(prefix) {
                    out.push(i);
                }
            }
        } else if let Some(i) = ctx.ids.get(id) {
            out.push(*i);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Total match count for a string reference, including `prefix*` globs.
fn match_string_count(id: &str, ctx: &EvalCtx<'_>) -> Option<u32> {
    if let Some(prefix) = id.strip_suffix('*') {
        let mut total = 0u32;
        for (i, s) in ctx.all_ids.iter().enumerate() {
            if s.starts_with(prefix) {
                total = total.saturating_add(ctx.counts[i]);
            }
        }
        return Some(total);
    }
    ctx.ids.get(id).map(|i| ctx.counts[*i])
}

fn eval_operand(op: &Operand, ctx: &EvalCtx<'_>) -> Val {
    match op {
        Operand::Int(i) => Val::Int(*i),
        Operand::Float(f) => Val::Float(*f),
        Operand::Str(s) => Val::Str(s.clone()),
        Operand::Bool(b) => Val::Bool(*b),
        Operand::Field(f) => field_val(*f, ctx),
        Operand::Call(func, args) => {
            let a = args.first().map(|x| eval_operand(x, ctx)).unwrap_or(Val::Int(0));
            let off = match a {
                Val::Int(i) if i >= 0 => i as usize,
                _ => usize::MAX,
            };
            Val::Int(read_int(*func, ctx.data, off))
        }
    }
}

fn field_val(f: Field, ctx: &EvalCtx<'_>) -> Val {
    let pe = ctx.pe;
    match f {
        Field::FileSize => Val::Int(ctx.file_size as i64),
        Field::Entropy => Val::Float(ctx.entropy),
        Field::Format => Val::Str(ctx.format.to_string()),
        Field::Ext => Val::Str(ctx.ext.to_string()),
        Field::PeImportHash => Val::Str(
            pe.map(|p| p.import_fingerprint.to_hex())
                .unwrap_or_default(),
        ),
        Field::PeSignedNames => Val::Str(
            pe.map(|p| p.signature.subject_names.join(";"))
                .unwrap_or_default(),
        ),
        Field::PeIsPe => Val::Bool(pe.is_some()),
        Field::PeSigned => Val::Bool(pe.map(|p| p.signature.present).unwrap_or(false)),
        Field::PeOverlayMz => Val::Bool(pe.map(|p| p.overlay_mz).unwrap_or(false)),
        Field::PeEntryOutsideSections => {
            Val::Bool(pe.map(|p| p.entry_outside_sections).unwrap_or(false))
        }
        Field::PeIsDotnet => Val::Bool(pe.map(|p| p.is_dotnet).unwrap_or(false)),
        Field::PeIsDll => Val::Bool(pe.map(|p| p.is_dll).unwrap_or(false)),
        Field::PeIsDriver => Val::Bool(pe.map(|p| p.is_driver).unwrap_or(false)),
        Field::PeHasVersionInfo => Val::Bool(pe.map(|p| p.version_info.present).unwrap_or(false)),
        Field::PeManifestAdmin => Val::Bool(pe.map(|p| p.manifest.require_admin).unwrap_or(false)),
        Field::PeChecksumValid => Val::Bool(pe.map(|p| p.checksum_valid).unwrap_or(false)),
        Field::PeRichHeader => Val::Bool(pe.map(|p| p.rich_header_present).unwrap_or(false)),
        Field::PeDebugPdb => Val::Bool(pe.map(|p| p.pdb_path.is_some()).unwrap_or(false)),
        Field::PeTls => Val::Bool(pe.map(|p| p.has_tls).unwrap_or(false)),
        Field::PeMaxSectionEntropy => {
            Val::Float(pe.map(|p| p.max_section_entropy).unwrap_or(-1.0))
        }
        Field::PeCodeEntropy => Val::Float(pe.map(|p| p.code_entropy()).unwrap_or(-1.0)),
        other => Val::Int(field_int_numeric(other, ctx)),
    }
}

fn field_int_numeric(f: Field, ctx: &EvalCtx<'_>) -> i64 {
    let pe = ctx.pe;
    match f {
        Field::PeEntry => pe.map(|p| p.entry_point_rva as i64).unwrap_or(-1),
        Field::PeSections => pe.map(|p| p.section_count as i64).unwrap_or(-1),
        Field::PeSectionCount => pe.map(|p| p.section_count as i64).unwrap_or(-1),
        Field::PeTimestamp => pe.map(|p| p.timestamp as i64).unwrap_or(-1),
        Field::PeTimestampYear => pe.map(|p| p.timestamp_year).unwrap_or(-1),
        Field::PeImports => pe.map(|p| p.total_imports() as i64).unwrap_or(-1),
        Field::PeExports => pe.map(|p| p.exports.len() as i64).unwrap_or(-1),
        Field::PeOverlaySize => pe.map(|p| p.overlay_size as i64).unwrap_or(-1),
        Field::PeWxSections => pe.map(|p| p.wx_sections() as i64).unwrap_or(-1),
        Field::PeHighEntropySections => pe.map(|p| p.high_entropy_exec_sections() as i64).unwrap_or(-1),
        Field::PeVirtualOnlySections => pe.map(|p| p.virtual_only_sections() as i64).unwrap_or(-1),
        Field::PePackerHints => pe.map(|p| p.packer_hints().len() as i64).unwrap_or(-1),
        _ => -1,
    }
}

fn read_int(func: Func, data: &[u8], off: usize) -> i64 {
    let r = crate::bytes::Reader::new(data);
    match func {
        Func::U8 => r.u8_at(off).map(|v| v as i64).unwrap_or(-1),
        Func::U16 => r.u16_at(off).map(|v| v as i64).unwrap_or(-1),
        Func::U16Be => r
            .slice(off, 2)
            .map(|b| i16::from_be_bytes([b[0], b[1]]) as i64)
            .unwrap_or(-1),
        Func::U32 => r.u32_at(off).map(|v| v as i64).unwrap_or(-1),
        Func::U32Be => r
            .slice(off, 4)
            .map(|b| i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64)
            .unwrap_or(-1),
        Func::U64 => r.u64_at(off).map(|v| v as i64).unwrap_or(-1),
        Func::StrLen => r
            .cstr(off, 4096)
            .map(|s| s.len() as i64)
            .unwrap_or(-1),
    }
}

fn compare(a: &Val, op: CmpOp, b: &Val) -> bool {
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return match op {
            CmpOp::Eq => (x - y).abs() < 1e-9,
            CmpOp::Ne => (x - y).abs() >= 1e-9,
            CmpOp::Lt => x < y,
            CmpOp::Le => x <= y,
            CmpOp::Gt => x > y,
            CmpOp::Ge => x >= y,
            CmpOp::Contains | CmpOp::StartsWith | CmpOp::EndsWith => false,
        };
    }
    let sa = a.as_str().unwrap_or_default();
    let sb = b.as_str().unwrap_or_default();
    match op {
        CmpOp::Eq => sa.eq_ignore_ascii_case(&sb),
        CmpOp::Ne => !sa.eq_ignore_ascii_case(&sb),
        CmpOp::Contains => sa.to_ascii_lowercase().contains(&sb.to_ascii_lowercase()),
        CmpOp::StartsWith => sa.to_ascii_lowercase().starts_with(&sb.to_ascii_lowercase()),
        CmpOp::EndsWith => sa.to_ascii_lowercase().ends_with(&sb.to_ascii_lowercase()),
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => sa < sb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
rule Test.Basic {
    meta:
        description = "basic test"
        severity    = "high"
        family      = "TestFam"
        mitre       = "T1027,T1055"
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $b = { 4D 5A ?? 00 }
        $c = "powershell" wide nocase
    condition:
        $a or 2 of them
}
"#;

    fn compile(text: &str) -> RuleSet {
        let rules = parse_rule_file(text, "test").expect("parse");
        RuleSet::compile(rules).expect("compile")
    }

    #[test]
    fn parses_and_matches_text() {
        let rs = compile(SAMPLE);
        assert_eq!(rs.len(), 1);
        let data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let m = rs.scan(data, None, "script", "com");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "Test.Basic");
        assert_eq!(m[0].severity, Severity::High);
        assert_eq!(m[0].family.as_deref(), Some("TestFam"));
        assert!(m[0].matched_strings.contains(&"a".to_string()));
    }

    #[test]
    fn wildcard_hex_matches_and_misses() {
        let raw = r#"
rule Test.Wild { strings: $b = { 4D 5A ?? 00 } condition: $b }
"#;
        let rs = compile(raw);
        // MZ ?? 00 -> MZ 90 00 matches; MZ 90 01 does not.
        let hit = rs.scan(b"junkMZ\x90\x00junk", None, "pe", "exe");
        assert!(!hit.is_empty(), "wildcard pattern should match");
        let miss = rs.scan(b"junkMZ\x90\x01junk", None, "pe", "exe");
        assert!(miss.is_empty(), "wildcard pattern should not match");
        // A pattern with no wildcards still matches exact bytes only.
        let raw = r#"rule Test.Exact { strings: $b = { 4D 5A 90 00 } condition: $b }"#;
        let rs = compile(raw);
        assert_eq!(rs.scan(b"xxMZ\x90\x00xx", None, "pe", "exe").len(), 1);
        assert!(rs.scan(b"xxMZ\x90\x01xx", None, "pe", "exe").is_empty());
    }

    #[test]
    fn wide_nocase_matches() {
        let rs = compile(SAMPLE);
        let mut data = Vec::new();
        for u in "PowerShell".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        // Only $c matches, and condition needs $a or 2-of -> must not fire.
        assert!(rs.scan(&data, None, "script", "ps1").is_empty());
        // Add $b so "2 of them" is satisfied.
        data.extend_from_slice(b"MZ\x90\x00");
        assert_eq!(rs.scan(&data, None, "script", "ps1").len(), 1);
    }

    #[test]
    fn filesize_and_entropy_conditions() {
        let raw = r#"
rule Test.Size { strings: $a = "MAGIC" condition: filesize < 1KB and $a and entropy > 1.0 }
rule Test.Big  { strings: $a = "MAGIC" condition: filesize > 10MB and $a }
"#;
        let rs = compile(raw);
        let data = b"MAGIC several bytes here to lift entropy a bit".to_vec();
        let m = rs.scan(&data, None, "binary", "bin");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "Test.Size");
    }

    #[test]
    fn count_operator_works() {
        let raw = r#"
rule Test.Count { strings: $a = "AB" condition: #a >= 3 }
"#;
        let rs = compile(raw);
        assert_eq!(rs.scan(b"ABAB", None, "binary", "bin").len(), 0);
        assert_eq!(rs.scan(b"ABABAB", None, "binary", "bin").len(), 1);
    }

    #[test]
    fn fullword_prevents_substring_false_positive() {
        let raw = r#"
rule Test.Full { strings: $a = "cat" fullword condition: $a }
"#;
        let rs = compile(raw);
        assert!(rs.scan(b"concatenate", None, "binary", "bin").is_empty());
        assert_eq!(rs.scan(b"a cat here", None, "binary", "bin").len(), 1);
    }

    #[test]
    fn rejects_bad_conditions() {
        let bad = r#"rule X { strings: $a = "x" condition: $b }"#;
        let e = parse_rule_file(bad, "t").unwrap_err();
        assert!(e.message.contains("unknown string"), "{}", e.message);

        let bad2 = r#"rule X { strings: $a = "x" condition: 1 of }"#;
        assert!(parse_rule_file(bad2, "t").is_err());

        let bad3 = r#"rule X { condition: true }"#;
        assert!(parse_rule_file(bad3, "t").is_ok(), "empty strings must be legal");
    }

    #[test]
    fn unknown_meta_key_is_an_error() {
        let bad = r#"rule X { meta: desc = "x" condition: true }"#;
        assert!(parse_rule_file(bad, "t").is_err());
    }

    #[test]
    fn comments_are_ignored() {
        let raw = r#"
// leading comment
rule X {
    meta:
        description = "d" // trailing
    strings:
        $a = "q" /* inline */
    condition:
        $a // done
}
"#;
        let rs = compile(raw);
        assert_eq!(rs.scan(b"q", None, "binary", "bin").len(), 1);
    }

    #[test]
    fn matcher_is_linear_in_file_size() {
        // A pathological 4 MB buffer of 'A' must not blow up with the pattern "AAAA".
        let raw = r#"rule X { strings: $a = "AAAA" condition: #a > 5 }"#;
        let rs = compile(raw);
        let data = vec![b'A'; 4 * 1024 * 1024];
        let start = std::time::Instant::now();
        let m = rs.scan(&data, None, "binary", "bin");
        let elapsed = start.elapsed();
        assert_eq!(m.len(), 1);
        assert!(elapsed.as_secs() < 10, "scan took {elapsed:?}");
    }

    #[test]
    fn empty_ruleset_is_safe() {
        let rs = RuleSet::empty();
        assert!(rs.scan(b"anything", None, "binary", "bin").is_empty());
    }
}
