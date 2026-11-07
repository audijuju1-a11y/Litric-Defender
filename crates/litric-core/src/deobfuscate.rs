//! Bounded script de-obfuscation.
//!
//! Commodity malware hides its payload behind an encoding layer: a PowerShell
//! `-EncodedCommand`, a `FromBase64String(...)` call, an `atob(...)` in a
//! script, or a character array such as `[char[]](0x4e -bxor 0x2a, ...)`.
//! The engine already *flags* encoded content as a weak signal; this module
//! takes the next step and decodes bounded layers so the rules and heuristics
//! can see what the payload really is.
//!
//! Design rules:
//!
//! * **Only explicit decode constructs.** A bare base64-looking string appears
//!   in ordinary data (keys, images, IDs). Decoding it would create noise, so a
//!   blob must follow `-EncodedCommand`, `-enc`, `FromBase64String` or `atob(`,
//!   and a character array must be written as an explicit `[char[]](...)` or
//!   `[char]` cast chain. No blind key search and no guessing.
//! * **Bounded work.** Input, blob count, blob size, decoded volume, recursion
//!   depth and *total decode steps* are capped. The decoder never allocates
//!   based on a declared size.
//! * **Text only.** Binary input is skipped before any allocation, and a
//!   character array is only accepted when every code is printable ASCII, so a
//!   random number table cannot masquerade as a decoded payload.
//! * **No verdict here.** The engine decides what a decoded payload means, and
//!   escalates only when the decoded content is itself conclusive.

/// Caps applied to one decode pass. The step budget itself lives in
/// [`WorkBudget`] so it can be shared across nested layers of one file.
#[derive(Debug, Clone)]
pub struct DecodeLimits {
    /// Files larger than this are not decoded at all.
    pub max_input_bytes: usize,
    /// Characters considered part of one base64 blob or one character array.
    pub max_blob_chars: usize,
    /// Total decoded bytes across all blobs in one pass.
    pub max_decoded_bytes: usize,
    /// Maximum number of payloads returned by one pass.
    pub max_blobs: usize,
    /// Maximum decode layers. The original file is layer 0.
    pub max_depth: usize,
    /// Decode steps granted to a fresh [`WorkBudget`].
    pub max_steps: u64,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        DecodeLimits {
            max_input_bytes: 4 * 1024 * 1024,
            max_blob_chars: 256 * 1024,
            max_decoded_bytes: 1024 * 1024,
            max_blobs: 8,
            max_depth: 3,
            max_steps: 8_000_000,
        }
    }
}

/// A shared work budget for one file analysis.
///
/// Every byte inspected or decoded and every character-array item parsed costs
/// one step. The budget is deliberately not an emulator: it cannot execute
/// branching script logic, but it does bound the total decoder work across
/// nested layers, archive members and every decoded payload of one file, so a
/// stack of encoded layers cannot turn into unbounded work.
#[derive(Debug, Clone)]
pub struct WorkBudget {
    remaining: u64,
    exhausted: bool,
}

impl WorkBudget {
    pub fn new(steps: u64) -> Self {
        WorkBudget {
            remaining: steps,
            exhausted: false,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// True once some request could not be paid for.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Charges `steps` to the budget. Returns false, and marks the budget
    /// exhausted, when the request does not fit.
    pub fn spend(&mut self, steps: u64) -> bool {
        if self.exhausted {
            return false;
        }
        if steps > self.remaining {
            self.remaining = 0;
            self.exhausted = true;
            return false;
        }
        self.remaining -= steps;
        true
    }
}

/// Where a decoded payload came from, for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeSource {
    PowerShellEncodedCommand,
    FromBase64String,
    Atob,
    CharArray,
    XorCharArray,
}

impl DecodeSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeSource::PowerShellEncodedCommand => "powershell-encodedcommand",
            DecodeSource::FromBase64String => "frombase64string",
            DecodeSource::Atob => "atob",
            DecodeSource::CharArray => "char-array",
            DecodeSource::XorCharArray => "xor-char-array",
        }
    }
}

/// One decoded layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayload {
    pub source: DecodeSource,
    pub bytes: Vec<u8>,
    /// 1 for the first decoded layer, 2 for a layer decoded from that, ...
    pub layer: usize,
}

const MARKERS: &[(&[u8], DecodeSource)] = &[
    (b"-encodedcommand", DecodeSource::PowerShellEncodedCommand),
    (b"-enc", DecodeSource::PowerShellEncodedCommand),
    (b"frombase64string", DecodeSource::FromBase64String),
    (b"atob(", DecodeSource::Atob),
];

/// Decodes every marked base64 blob and character array in `data`, at most one
/// layer.
///
/// `depth` is the number of layers already decoded; `budget` is shared with the
/// caller so nested layers of one file stay inside a single work allowance. A
/// malformed or oversized payload is skipped, never guessed at.
pub fn decode(
    data: &[u8],
    depth: usize,
    limits: &DecodeLimits,
    budget: &mut WorkBudget,
) -> Vec<DecodedPayload> {
    let mut out = Vec::new();
    if depth >= limits.max_depth
        || data.is_empty()
        || data.len() > limits.max_input_bytes
        || !crate::format::looks_like_text(data)
    {
        return out;
    }
    if !budget.spend(data.len() as u64) {
        return out;
    }

    // Case-insensitive marker search without a regex engine. The lowercased
    // copy is bounded by `max_input_bytes`.
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut decoded_total = 0usize;

    for (marker, source) in MARKERS {
        let mut from = 0usize;
        while let Some(pos) = find(&lower[from..], marker) {
            let at = from + pos + marker.len();
            from = at;
            if out.len() >= limits.max_blobs
                || decoded_total >= limits.max_decoded_bytes
                || budget.exhausted()
            {
                return out;
            }
            let Some(blob) = blob_after(&lower, data, at, limits.max_blob_chars) else {
                continue;
            };
            if !budget.spend(blob.len() as u64) {
                return out;
            }
            let Some(bytes) = decode_base64(blob) else {
                continue;
            };
            let bytes = normalize_utf16le(bytes);
            if bytes.len() < 8
                || decoded_total + bytes.len() > limits.max_decoded_bytes
                || bytes == data
                || out.iter().any(|p| p.bytes == bytes)
            {
                continue;
            }
            decoded_total += bytes.len();
            out.push(DecodedPayload {
                source: *source,
                bytes,
                layer: depth + 1,
            });
        }
    }

    if out.len() < limits.max_blobs && !budget.exhausted() {
        let remaining = limits.max_blobs - out.len();
        for payload in decode_char_arrays(&lower, data, limits, budget, remaining, depth + 1) {
            if out.len() >= limits.max_blobs
                || decoded_total + payload.bytes.len() > limits.max_decoded_bytes
            {
                break;
            }
            if out.iter().any(|p| p.bytes == payload.bytes) {
                continue;
            }
            decoded_total += payload.bytes.len();
            out.push(payload);
        }
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay[..needle.len()].eq_ignore_ascii_case(needle)
}

fn skip_ws(raw: &[u8], i: &mut usize) {
    while *i < raw.len() && raw[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

/// Collects the contiguous base64 run that follows a marker.
///
/// Up to 64 characters of punctuation/quoting may appear before the blob, so
/// `FromBase64String('...')` and `-EncodedCommand "..."` both work. A line break
/// before the blob means there is no inline payload to decode.
///
/// Positions come from the lowercased copy used for marker search, but the bytes
/// are sliced from the original: base64 is case-sensitive, so decoding the
/// lowercased text would silently corrupt every payload.
fn blob_after<'a>(lower: &[u8], raw: &'a [u8], start: usize, max_chars: usize) -> Option<&'a [u8]> {
    let mut i = start;
    let mut begin = None;
    while i < lower.len() && i - start < 64 {
        let c = lower[i];
        if is_base64_char(c) {
            begin = Some(i);
            break;
        }
        if c == b'\n' || c == b'\r' {
            return None;
        }
        i += 1;
    }
    let begin = begin?;
    let mut end = begin;
    while end < lower.len()
        && end - begin < max_chars
        && (is_base64_char(lower[end]) || lower[end] == b'=')
    {
        end += 1;
    }
    let blob = &raw[begin..end];
    if blob.len() < 24 {
        return None;
    }
    Some(blob)
}

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_')
}

fn decode_base64(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut count = 0usize;
    for &c in raw {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        count += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= if bits == 0 { 0 } else { (1u32 << bits) - 1 };
        }
    }
    if count < 2 {
        return None;
    }
    Some(out)
}

/// PowerShell's `-EncodedCommand` is UTF-16LE base64. Convert that back to UTF-8
/// when the byte pattern is unambiguous; leave genuine binary payloads alone so
/// the engine can classify them as bytes.
fn normalize_utf16le(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return bytes;
    }
    let units = bytes.len() / 2;
    let zero_high = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    if zero_high * 5 < units * 4 {
        return bytes;
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s).into_bytes()
}

// --- character-array decoding -------------------------------------------

/// Handles `[char[]](...)` and `[char]... + [char]...` forms.
fn decode_char_arrays(
    lower: &[u8],
    raw: &[u8],
    limits: &DecodeLimits,
    budget: &mut WorkBudget,
    max: usize,
    layer: usize,
) -> Vec<DecodedPayload> {
    let mut out: Vec<DecodedPayload> = Vec::new();
    let mut i = 0usize;
    while i < lower.len() && out.len() < max && !budget.exhausted() {
        let payload = if lower[i..].starts_with(b"[char[]]") {
            let payload = array_at(raw, i + 8, budget, layer);
            i += 8;
            payload
        } else if lower[i..].starts_with(b"[char]") {
            let payload = char_chain_at(raw, i, budget, layer);
            i += 6;
            payload
        } else {
            i += 1;
            None
        };
        let Some(payload) = payload else { continue };
        if payload.bytes.len() > limits.max_blob_chars || out.iter().any(|p| p.bytes == payload.bytes)
        {
            continue;
        }
        out.push(payload);
    }
    out
}

/// Parses one `[char[]](<int> [-bxor <int>], ...)` expression.
///
/// Only constant items are accepted. A variable, a nested expression or a
/// missing closing paren rejects the whole array instead of guessing.
fn array_at(
    raw: &[u8],
    mut i: usize,
    budget: &mut WorkBudget,
    layer: usize,
) -> Option<DecodedPayload> {
    skip_ws(raw, &mut i);
    if i < raw.len() && raw[i] == b'@' {
        i += 1;
        skip_ws(raw, &mut i);
    }
    if i >= raw.len() || raw[i] != b'(' {
        return None;
    }
    i += 1;
    let mut codes = Vec::new();
    let mut xored = false;
    loop {
        skip_ws(raw, &mut i);
        if i >= raw.len() {
            return None;
        }
        if raw[i] == b')' {
            break;
        }
        if !budget.spend(1) {
            return None;
        }
        let mut value = parse_number(raw, &mut i)?;
        skip_ws(raw, &mut i);
        if let Some(key) = parse_bxor(raw, &mut i) {
            if key == 0 {
                return None;
            }
            value ^= key;
            xored = true;
        }
        codes.push(value);
        if codes.len() > 4096 {
            return None;
        }
        skip_ws(raw, &mut i);
        if i < raw.len() && raw[i] == b',' {
            i += 1;
            continue;
        }
        if i < raw.len() && raw[i] == b')' {
            break;
        }
        return None;
    }
    Some(DecodedPayload {
        source: if xored {
            DecodeSource::XorCharArray
        } else {
            DecodeSource::CharArray
        },
        bytes: codes_to_text(&codes)?,
        layer,
    })
}

/// Parses a chain like `[char]0x48 + [char](0x69) -bxor 0x2a + ...`.
fn char_chain_at(
    raw: &[u8],
    mut i: usize,
    budget: &mut WorkBudget,
    layer: usize,
) -> Option<DecodedPayload> {
    let mut codes = Vec::new();
    let mut xored = false;
    loop {
        // `i` points at "[char]".
        let mut j = i + 6;
        skip_ws(raw, &mut j);
        let mut value = if j < raw.len() && raw[j] == b'(' {
            j += 1;
            let value = parse_number(raw, &mut j)?;
            skip_ws(raw, &mut j);
            if j >= raw.len() || raw[j] != b')' {
                return None;
            }
            j += 1;
            value
        } else {
            parse_number(raw, &mut j)?
        };
        skip_ws(raw, &mut j);
        if let Some(key) = parse_bxor(raw, &mut j) {
            if key == 0 {
                return None;
            }
            value ^= key;
            xored = true;
        }
        if !budget.spend(1) {
            return None;
        }
        codes.push(value);
        if codes.len() > 4096 {
            return None;
        }
        skip_ws(raw, &mut j);
        if j < raw.len() && raw[j] == b'+' {
            let mut next = j + 1;
            skip_ws(raw, &mut next);
            if starts_with_ci(&raw[next..], b"[char]") {
                i = next;
                continue;
            }
        }
        break;
    }
    Some(DecodedPayload {
        source: if xored {
            DecodeSource::XorCharArray
        } else {
            DecodeSource::CharArray
        },
        bytes: codes_to_text(&codes)?,
        layer,
    })
}

/// Parses a decimal or `0x`-hexadecimal integer literal at `*i`.
fn parse_number(raw: &[u8], i: &mut usize) -> Option<u32> {
    skip_ws(raw, i);
    let start = *i;
    if start >= raw.len() {
        return None;
    }
    let hex = raw[start] == b'0'
        && start + 1 < raw.len()
        && (raw[start + 1] == b'x' || raw[start + 1] == b'X');
    if hex {
        *i += 2;
    }
    let digits = *i;
    while *i < raw.len() {
        let c = raw[*i];
        let ok = if hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() };
        if !ok {
            break;
        }
        *i += 1;
    }
    if *i == digits || *i - digits > 8 {
        *i = start;
        return None;
    }
    let text = std::str::from_utf8(&raw[digits..*i]).ok()?;
    u32::from_str_radix(text, if hex { 16 } else { 10 }).ok()
}

/// Parses an optional `-bxor <int>` suffix at `*i`.
fn parse_bxor(raw: &[u8], i: &mut usize) -> Option<u32> {
    let mut j = *i;
    if j >= raw.len() || raw[j] != b'-' {
        return None;
    }
    j += 1;
    skip_ws(raw, &mut j);
    if !starts_with_ci(&raw[j..], b"bxor") {
        return None;
    }
    j += 4;
    let key = parse_number(raw, &mut j)?;
    *i = j;
    Some(key)
}

/// Turns constant codes into text only when every code is a printable ASCII
/// character (plus tab/newline). Anything else is treated as data, not as a
/// string payload, which keeps a random number table from creating a finding.
fn codes_to_text(codes: &[u32]) -> Option<Vec<u8>> {
    if codes.len() < 8 {
        return None;
    }
    let mut text = Vec::with_capacity(codes.len());
    for &code in codes {
        let ch = char::from_u32(code)?;
        let printable = ch == '\t' || ch == '\r' || ch == '\n' || (' '..='~').contains(&ch);
        if !printable {
            return None;
        }
        text.push(ch as u8);
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn run(data: &[u8]) -> Vec<DecodedPayload> {
        let limits = DecodeLimits::default();
        let mut budget = WorkBudget::new(limits.max_steps);
        decode(data, 0, &limits, &mut budget)
    }

    #[test]
    fn powershell_encoded_command_is_decoded_to_text() {
        let command = "Write-Host 'hello from the payload'";
        let script = format!(
            "powershell.exe -NoProfile -EncodedCommand {}",
            b64(&utf16le(command))
        );
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::PowerShellEncodedCommand);
        assert_eq!(payloads[0].layer, 1);
        assert_eq!(String::from_utf8_lossy(&payloads[0].bytes), command);
    }

    #[test]
    fn from_base64_string_is_decoded() {
        let script = format!(
            "$b = [Convert]::FromBase64String('{}')\n",
            b64(b"write-output encoded-marker")
        );
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::FromBase64String);
        assert_eq!(&payloads[0].bytes, b"write-output encoded-marker");
    }

    #[test]
    fn atob_is_decoded() {
        let script = "eval(atob('d3JpdGUtaG9zdCBlbmNvZGVkLW1hcmtlcg=='));";
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::Atob);
        assert_eq!(&payloads[0].bytes, b"write-host encoded-marker");
    }

    #[test]
    fn base64_without_a_marker_is_ignored() {
        let text = format!("config = \"{}\"", b64(b"a plain value nobody encoded"));
        assert!(run(text.as_bytes()).is_empty());
    }

    #[test]
    fn binary_input_is_ignored() {
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(b"-enc\0\0\0\0");
        assert!(run(&data).is_empty());
    }

    #[test]
    fn the_depth_budget_stops_a_second_layer() {
        let script = format!("-EncodedCommand {}", b64(&utf16le("payload")));
        let limits = DecodeLimits::default();
        let mut budget = WorkBudget::new(limits.max_steps);
        assert!(decode(script.as_bytes(), limits.max_depth, &limits, &mut budget).is_empty());
    }

    #[test]
    fn malformed_base64_is_skipped() {
        let script = "-EncodedCommand \"!!!! not base64 at all !!!!\"";
        assert!(run(script.as_bytes()).is_empty());
    }

    #[test]
    fn tiny_blobs_are_ignored() {
        let script = format!("-enc {}", b64(b"abc"));
        assert!(run(script.as_bytes()).is_empty());
    }

    #[test]
    fn the_decoded_volume_is_capped() {
        let blob = b64(&utf16le("this payload is long enough to be decoded"));
        let script = format!("-enc {blob}\n-enc {blob}\n");
        let limits = DecodeLimits {
            max_decoded_bytes: 1,
            ..Default::default()
        };
        let mut budget = WorkBudget::new(limits.max_steps);
        assert!(decode(script.as_bytes(), 0, &limits, &mut budget).is_empty());
    }

    #[test]
    fn duplicate_payloads_are_returned_once() {
        let blob = b64(&utf16le("write-host duplicated-payload"));
        let script = format!("-enc {blob}\n-enc {blob}\n");
        assert_eq!(run(script.as_bytes()).len(), 1);
    }

    #[test]
    fn a_char_array_literal_is_decoded() {
        let script = "$s = -join ([char[]](0x48,0x65,0x6c,0x6c,0x6f,0x2c,0x20,0x77,0x6f,0x72,0x6c,0x64))";
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::CharArray);
        assert_eq!(&payloads[0].bytes, b"Hello, world");
    }

    #[test]
    fn an_xor_char_array_literal_is_decoded() {
        // "Write-Host 'pwned'" XORed with 0x2a, the usual constant-key form.
        let text = "Write-Host 'pwned'";
        let items: Vec<String> = text
            .bytes()
            .map(|b| format!("0x{:02x} -bxor 0x2a", b ^ 0x2a))
            .collect();
        let script = format!("$s = -join ([char[]]({})); iex $s", items.join(","));
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::XorCharArray);
        assert_eq!(&payloads[0].bytes, text.as_bytes());
    }

    #[test]
    fn a_char_cast_chain_is_decoded() {
        let script = "$s = [char]0x48 + [char](0x69) + [char]0x20 + [char]0x74 + [char]0x68 + [char]0x65 + [char]0x72 + [char]0x65";
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].source, DecodeSource::CharArray);
        assert_eq!(&payloads[0].bytes, b"Hi there");
    }

    #[test]
    fn decimal_and_hex_items_mix() {
        let script = "[char[]](72, 0x65, 108, 108, 111, 32, 0x77, 111, 114, 108, 100)";
        let payloads = run(script.as_bytes());
        assert_eq!(payloads.len(), 1);
        assert_eq!(&payloads[0].bytes, b"Hello world");
    }

    #[test]
    fn a_char_array_of_non_printable_codes_is_ignored() {
        let script = "[char[]](1,2,3,4,5,6,7,8,9,10,11)";
        assert!(run(script.as_bytes()).is_empty());
    }

    #[test]
    fn an_unterminated_array_is_ignored() {
        let script = "[char[]](0x48,0x65,0x6c,0x6c,0x6f,0x2c,0x20,0x77";
        assert!(run(script.as_bytes()).is_empty());
    }

    #[test]
    fn an_array_with_a_variable_is_ignored() {
        let script = "[char[]](0x48, $x, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77)";
        assert!(run(script.as_bytes()).is_empty());
    }

    #[test]
    fn the_step_budget_stops_decoding() {
        let blob = b64(&utf16le("a payload hidden behind the budget"));
        let script = format!("-enc {blob}");
        let limits = DecodeLimits::default();
        let mut budget = WorkBudget::new(16);
        let payloads = decode(script.as_bytes(), 0, &limits, &mut budget);
        assert!(payloads.is_empty());
        assert!(budget.exhausted());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn a_spent_budget_refuses_further_work() {
        let mut budget = WorkBudget::new(4);
        assert!(budget.spend(4));
        assert_eq!(budget.remaining(), 0);
        assert!(!budget.spend(1));
        assert!(budget.exhausted());
    }
}
