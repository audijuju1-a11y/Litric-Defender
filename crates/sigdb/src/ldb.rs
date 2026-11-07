//! ClamAV-style logical (LDB) signatures: expression parser, target-description
//! parser and data model. OWNERSHIP: Litric implementation of the documented
//! syntax subset; semantics NOT verified against libclamav.
//!
//! Supported:  expressions of subsignature indexes joined by `&` or `|` with
//! parentheses, each index optionally followed by `=n`, `>n` or `<n` (match-count
//! conditions on that subsignature). Target description keys: `Target`, `FileSize`,
//! `NumberOfSections`, `Engine` (parsed, ignored).
//! Rejected as Unsupported: mixing `&` and `|` in one group without parentheses
//! (precedence not verified), group-level counts `(..)>n`, `,m` distinct-count
//! modifiers, EntryPoint/Container/Intermediates/IconGroup keys, targets other
//! than 0/1/6/10.

use crate::ndb::SigError;
use crate::Target;

pub const MAX_SUBSIGS: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 256;
const MAX_COUNT: u64 = 1 << 20;
pub const MAX_EXPR_CHARS: usize = 512;

fn mal<T>(m: impl Into<String>) -> Result<T, SigError> {
    Err(SigError::Malformed(m.into()))
}
fn uns<T>(m: impl Into<String>) -> Result<T, SigError> {
    Err(SigError::Unsupported(m.into()))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cond {
    /// plain index: at least one match
    AtLeastOne,
    Eq(u32),
    Gt(u32),
    Lt(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Term { idx: u8, cond: Cond },
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

impl Expr {
    pub fn eval(&self, counts: &[u32]) -> bool {
        match self {
            Expr::Term { idx, cond } => {
                let c = counts.get(*idx as usize).copied().unwrap_or(0);
                match cond {
                    Cond::AtLeastOne => c >= 1,
                    Cond::Eq(n) => c == *n,
                    Cond::Gt(n) => c > *n,
                    Cond::Lt(n) => c < *n,
                }
            }
            Expr::And(v) => v.iter().all(|e| e.eval(counts)),
            Expr::Or(v) => v.iter().any(|e| e.eval(counts)),
        }
    }
    pub fn max_index(&self) -> u8 {
        match self {
            Expr::Term { idx, .. } => *idx,
            Expr::And(v) | Expr::Or(v) => v.iter().map(|e| e.max_index()).max().unwrap_or(0),
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    nodes: usize,
}

impl P<'_> {
    fn number(&mut self, what: &str, max: u64) -> Result<u64, SigError> {
        let s = self.i;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        if s == self.i || self.i - s > 8 {
            return mal(format!("{what} expected"));
        }
        let v: u64 = std::str::from_utf8(&self.b[s..self.i]).unwrap().parse().or_else(|_| mal("number"))?;
        if v > max {
            return mal(format!("{what} out of range"));
        }
        Ok(v)
    }

    fn group(&mut self, depth: usize) -> Result<Expr, SigError> {
        if depth > MAX_DEPTH {
            return uns("expression nesting too deep");
        }
        let mut items = vec![self.atom(depth)?];
        let (mut and, mut or) = (false, false);
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'&' => and = true,
                b'|' => or = true,
                _ => break,
            }
            self.i += 1;
            items.push(self.atom(depth)?);
        }
        if and && or {
            return uns("`&` and `|` mixed in one group without parentheses (operator precedence not verified)");
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else if and {
            Expr::And(items)
        } else {
            Expr::Or(items)
        })
    }

    fn atom(&mut self, depth: usize) -> Result<Expr, SigError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return uns("expression too large");
        }
        if self.b.get(self.i) == Some(&b'(') {
            self.i += 1;
            let e = self.group(depth + 1)?;
            if self.b.get(self.i) != Some(&b')') {
                return mal("missing `)`");
            }
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'=' | b'>' | b'<' | b',')) {
                return uns("match-count modifier on a parenthesised group");
            }
            return Ok(e);
        }
        let idx = self.number("subsignature index", (MAX_SUBSIGS - 1) as u64)? as u8;
        let cond = match self.b.get(self.i) {
            Some(b'=') | Some(b'>') | Some(b'<') => {
                let op = self.b[self.i];
                self.i += 1;
                let n = self.number("match count", MAX_COUNT)? as u32;
                if self.b.get(self.i) == Some(&b',') {
                    return uns("`,m` distinct-subsignature count modifier");
                }
                match op {
                    b'=' => Cond::Eq(n),
                    b'>' => Cond::Gt(n),
                    _ => Cond::Lt(n),
                }
            }
            Some(b',') => return uns("`,m` distinct-subsignature count modifier"),
            _ => Cond::AtLeastOne,
        };
        Ok(Expr::Term { idx, cond })
    }
}

pub fn parse_expr(s: &str) -> Result<Expr, SigError> {
    if s.is_empty() || s.len() > MAX_EXPR_CHARS {
        return mal("expression must be 1..=512 characters");
    }
    if !s.bytes().all(|c| c.is_ascii_digit() || b"&|()=<>,".contains(&c)) {
        return mal("expression contains invalid characters");
    }
    let mut p = P { b: s.as_bytes(), i: 0, nodes: 0 };
    let e = p.group(0)?;
    if p.i != s.len() {
        return mal("unexpected trailing characters in expression");
    }
    Ok(e)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Constraints {
    pub filesize: Option<(u64, u64)>,
    pub sections: Option<(u64, u64)>,
}

impl Constraints {
    /// `sections` is None when the file is not a parsed PE.
    pub fn check(&self, file_len: u64, sections: Option<u64>) -> bool {
        if let Some((a, b)) = self.filesize {
            if file_len < a || file_len > b {
                return false;
            }
        }
        if let Some((a, b)) = self.sections {
            match sections {
                Some(n) if n >= a && n <= b => {}
                _ => return false,
            }
        }
        true
    }
    pub fn to_text(&self) -> String {
        let mut v = vec![];
        if let Some((a, b)) = self.filesize {
            v.push(format!("FileSize:{a}-{b}"));
        }
        if let Some((a, b)) = self.sections {
            v.push(format!("NumberOfSections:{a}-{b}"));
        }
        if v.is_empty() {
            "-".into()
        } else {
            v.join(",")
        }
    }
}

fn range(v: &str) -> Result<(u64, u64), SigError> {
    let Some((a, b)) = v.split_once('-') else { return mal("range must look like min-max") };
    let (Ok(a), Ok(b)) = (a.parse::<u64>(), b.parse::<u64>()) else { return mal("range bounds must be numbers") };
    if a > b {
        return mal("range min exceeds max");
    }
    Ok((a, b))
}

/// Parses `-` or `FileSize:a-b,NumberOfSections:a-b` (no Target key).
pub fn parse_constraints(s: &str) -> Result<Constraints, SigError> {
    if s == "-" {
        return Ok(Constraints::default());
    }
    let (t, c) = parse_target_block(s)?;
    if t != Target::Any || s.contains("Target:") {
        return mal("Target is not allowed in a constraint list");
    }
    Ok(c)
}

/// Parses a ClamAV target-description block like `Target:1,FileSize:100-2000`.
pub fn parse_target_block(s: &str) -> Result<(Target, Constraints), SigError> {
    let mut target = Target::Any;
    let mut c = Constraints::default();
    let (mut seen_t, mut seen_f, mut seen_s) = (false, false, false);
    for part in s.split(',') {
        let Some((k, v)) = part.split_once(':') else { return mal("target-description entries must be Key:Value") };
        match k {
            "Target" => {
                if std::mem::replace(&mut seen_t, true) {
                    return mal("duplicate Target");
                }
                target = match v.parse::<u32>() {
                    Ok(0) => Target::Any,
                    Ok(1) => Target::Pe,
                    Ok(6) => Target::Elf,
                    Ok(10) => Target::Pdf,
                    Ok(n @ (2 | 3 | 4 | 5 | 7 | 8 | 9 | 11 | 12)) => {
                        return uns(format!("target type {n} is not supported (only 0 any, 1 PE, 6 ELF, 10 PDF)"))
                    }
                    _ => return mal("Target is not a known number"),
                };
            }
            "FileSize" => {
                if std::mem::replace(&mut seen_f, true) {
                    return mal("duplicate FileSize");
                }
                c.filesize = Some(range(v)?);
            }
            "NumberOfSections" => {
                if std::mem::replace(&mut seen_s, true) {
                    return mal("duplicate NumberOfSections");
                }
                c.sections = Some(range(v)?);
            }
            "Engine" => {
                range(v)?; // accepted and ignored (functionality level)
            }
            "EntryPoint" => return uns("EntryPoint constraint (semantics not verified)"),
            "Container" | "Intermediates" => return uns("container/intermediates constraints"),
            "IconGroup1" | "IconGroup2" => return uns("icon-group constraints"),
            _ => return uns(format!("unknown target-description key `{k}`")),
        }
    }
    Ok((target, c))
}
