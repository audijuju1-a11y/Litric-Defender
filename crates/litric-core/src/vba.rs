//! Office VBA macro extraction for the portable detection engine.
//!
//! Macro malware hides its payload from a byte-level scan: the source lives in
//! MS-OVBA compressed streams inside an OLE2 compound file (`vbaProject.bin`),
//! which in modern documents is itself a member of a ZIP/OOXML package. This
//! module walks both containers, decompresses every VBA module it can account
//! for, and returns the source so the engine can analyse it as a script.
//!
//! Design rules:
//!
//! * **Read-only and bounded.** Nothing is written to disk. Project size,
//!   stream count, compressed stream size, decompressed module size and total
//!   output are capped; a chunk that claims more data than the container holds
//!   is rejected instead of allocated.
//! * **No guessing.** A stream is only decoded as MS-OVBA when the chunk header
//!   has the required signature. Streams that do not decompress are reported,
//!   not replaced with partial garbage.
//! * **No verdict here.** The engine analyses the returned source with the same
//!   rules, heuristics, hash database and de-obfuscation as any other input.

use std::io::{Cursor, Read};

use zip::ZipArchive;

const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREE_SECTOR: u32 = 0xFFFF_FFFF;
const MAX_REGULAR_SECTOR: u32 = 0xFFFF_FFFA;

/// Caps for one VBA extraction pass.
#[derive(Debug, Clone)]
pub struct VbaLimits {
    /// Largest `vbaProject.bin` part accepted from an OOXML package.
    pub max_project_bytes: usize,
    /// Maximum number of module streams inspected in one project.
    pub max_streams: usize,
    /// Maximum compressed bytes for one module stream.
    pub max_stream_bytes: usize,
    /// Maximum decompressed bytes for one module.
    pub max_module_bytes: usize,
    /// Maximum decompressed bytes across all modules of one project.
    pub max_total_bytes: usize,
}

impl Default for VbaLimits {
    fn default() -> Self {
        VbaLimits {
            max_project_bytes: 8 * 1024 * 1024,
            max_streams: 64,
            max_stream_bytes: 2 * 1024 * 1024,
            max_module_bytes: 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
        }
    }
}

/// One decompressed VBA module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VbaModule {
    pub name: String,
    pub code: Vec<u8>,
    /// Bytes before the compressed source: the PerformanceCache (compiled
    /// p-code). Zero means the project was purged (source only).
    pub cache_bytes: usize,
}

/// Extraction result for one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VbaProject {
    pub modules: Vec<VbaModule>,
    /// Modules whose stream carries a PerformanceCache (p-code) before the
    /// source. P-code itself is not decompiled here.
    pub pcode_modules: usize,
    /// True when a cap stopped some module from being inspected. A truncated
    /// project must never be treated as fully analysed.
    pub truncated: bool,
    pub notes: Vec<String>,
}

impl VbaProject {
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    fn note(&mut self, text: impl Into<String>) {
        if self.notes.len() < 16 {
            self.notes.push(text.into());
        }
    }
}

/// Extracts VBA modules from an OOXML package (`vbaProject.bin` member) or a
/// legacy OLE2 document containing a `VBA` storage.
///
/// Returns an empty project for files that carry no macros. Malformed input
/// produces notes, never a panic and never fabricated source.
pub fn extract(data: &[u8], limits: &VbaLimits) -> VbaProject {
    let mut out = VbaProject::default();
    if data.starts_with(&CFB_SIGNATURE) {
        parse_project(data, limits, &mut out, "vbaProject.bin");
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        extract_from_ooxml(data, limits, &mut out);
    }
    out
}

fn extract_from_ooxml(data: &[u8], limits: &VbaLimits, out: &mut VbaProject) {
    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => {
            out.note(format!("OOXML package could not be parsed: {e}"));
            return;
        }
    };
    for index in 0..archive.len().min(1024) {
        let Ok(member) = archive.by_index(index) else {
            continue;
        };
        let name = member.name().to_ascii_lowercase();
        if !name.ends_with("vbaproject.bin") {
            continue;
        }
        let member_name = member.name().to_string();
        if member.size() > limits.max_project_bytes as u64 {
            out.truncated = true;
            out.note(format!(
                "`{member_name}` is {} bytes, above the {} byte project cap; macros were not inspected",
                member.size(),
                limits.max_project_bytes
            ));
            continue;
        }
        let mut bytes = Vec::new();
        let limit = limits.max_project_bytes as u64 + 1;
        if let Err(e) = member.take(limit).read_to_end(&mut bytes) {
            out.note(format!("`{member_name}` could not be read: {e}"));
            continue;
        }
        if bytes.len() > limits.max_project_bytes {
            out.truncated = true;
            out.note(format!(
                "`{member_name}` expanded beyond the project cap; macros were not inspected"
            ));
            continue;
        }
        parse_project(&bytes, limits, out, &member_name);
    }
}

fn parse_project(data: &[u8], limits: &VbaLimits, out: &mut VbaProject, label: &str) {
    let Some(cfb) = Cfb::parse(data) else {
        out.note(format!("`{label}` is not a valid OLE2 compound file"));
        return;
    };
    let Some(vba) = cfb.find_storage("VBA") else {
        return;
    };
    let mut total = 0usize;
    for id in cfb.children(vba) {
        let Some(entry) = cfb.entries.get(id) else {
            continue;
        };
        if entry.kind != 2 || entry.name.is_empty() || skip_stream_name(&entry.name) {
            continue;
        }
        if out.modules.len() >= limits.max_streams {
            out.truncated = true;
            out.note(format!(
                "VBA project has more than {} module streams; the rest were not inspected",
                limits.max_streams
            ));
            break;
        }
        if entry.size > limits.max_stream_bytes as u64 {
            out.truncated = true;
            out.note(format!(
                "VBA stream `{}` is {} bytes, above the stream cap; not inspected",
                entry.name, entry.size
            ));
            continue;
        }
        let Some(raw) = cfb.read_stream(entry) else {
            out.note(format!("VBA stream `{}` could not be read", entry.name));
            continue;
        };
        let remaining = limits
            .max_total_bytes
            .saturating_sub(total)
            .min(limits.max_module_bytes);
        if remaining == 0 {
            out.truncated = true;
            out.note("VBA decompression total cap reached; remaining modules not inspected");
            break;
        }
        match split_module(&raw, remaining) {
            Ok((code, cache)) if !code.is_empty() => {
                if cache > 0 {
                    out.pcode_modules += 1;
                }
                total += code.len();
                out.modules.push(VbaModule {
                    name: entry.name.clone(),
                    code,
                    cache_bytes: cache,
                });
            }
            Ok(_) => {}
            Err(e) => {
                if raw.len() >= 8 {
                    // A non-empty stream with no decodable source is the shape
                    // of VBA stomping: compiled p-code present, source hidden.
                    out.pcode_modules += 1;
                    out.notes.push(format!(
                        "VBA stream `{}` has a performance cache but no decodable source ({e}); \
                         possible VBA stomping",
                        entry.name
                    ));
                    out.modules.push(VbaModule {
                        name: entry.name.clone(),
                        code: Vec::new(),
                        cache_bytes: raw.len(),
                    });
                } else {
                    out.note(format!(
                        "VBA stream `{}` could not be decompressed: {e}",
                        entry.name
                    ));
                }
            }
        }
    }
    if out.truncated {
        out.note("VBA extraction was truncated by a resource cap");
    }
}

/// Splits one module stream into decoded source and the p-code cache before it.
///
/// A real module stream is `PerformanceCache || CompressedSourceCode`, where the
/// cache length is implementation-specific. The cache is not documented enough
/// to parse, so candidate container offsets are tried in order and accepted only
/// when the chunk chain decompresses to text that looks like VBA source. A stream
/// with no such container is reported by the caller as cache-only.
fn split_module(raw: &[u8], max_out: usize) -> Result<(Vec<u8>, usize), &'static str> {
    let mut candidates: Vec<usize> = vec![0];
    let window = raw.len().min(64 * 1024);
    let mut i = 1usize;
    while i + 3 < window && candidates.len() < 16 {
        if looks_like_chunk_header(&raw[i..]) {
            candidates.push(i);
        }
        i += 1;
    }
    let mut last_error = "no MS-OVBA source container found";
    for start in candidates {
        match decompress(&raw[start..], max_out) {
            Ok(code) if !code.is_empty() && looks_like_source(&code) => {
                return Ok((code, start));
            }
            Ok(_) => {}
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

fn looks_like_chunk_header(raw: &[u8]) -> bool {
    if raw.len() < 3 {
        return false;
    }
    let header = u16::from_le_bytes([raw[0], raw[1]]);
    let signature = (header >> 12) & 0x7;
    let size = (header & 0x0FFF) as usize;
    signature == 3 && size >= 1 && 3 + size <= raw.len()
}

/// VBA source is text; this keeps an accidental chunk-like pattern inside the
/// binary performance cache from being accepted as decoded source.
fn looks_like_source(code: &[u8]) -> bool {
    code.len() >= 8 && crate::format::looks_like_text(code)
}

/// Reads a named top-level stream from an OLE2 compound file. Used by the
/// Excel 4.0 parser to reach the `Workbook`/`Book` stream.
///
/// `Ok(None)` means the container parsed but has no stream with that name (a
/// legitimate non-Excel OLE document). An unparseable container, a stream above
/// the cap, or a chain that cannot be read completely is an error so callers
/// can report "not inspected" instead of treating it as "nothing found".
pub(crate) fn read_stream_named(
    data: &[u8],
    names: &[&str],
) -> Result<Option<Vec<u8>>, &'static str> {
    let cfb = Cfb::parse(data).ok_or("not a valid OLE2 compound file")?;
    let Some(index) = cfb.entries.iter().position(|e| {
        e.kind == 2 && names.iter().any(|n| e.name.eq_ignore_ascii_case(n))
    }) else {
        return Ok(None);
    };
    let entry = cfb
        .entries
        .get(index)
        .ok_or("Workbook directory entry is missing")?;
    if entry.size > 64 * 1024 * 1024 {
        return Err("Workbook stream is above the 64 MiB cap");
    }
    let stream = cfb
        .read_stream(entry)
        .ok_or("Workbook stream could not be read completely")?;
    Ok(Some(stream))
}

/// Module streams that are project structure, not source code.
fn skip_stream_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "dir" || lower.starts_with("__srp") || lower.starts_with('_')
}

// --- MS-OVBA decompression ----------------------------------------------

/// Decompresses one MS-OVBA compressed container.
///
/// The chunk header is a little-endian `u16`: the low 12 bits are the chunk
/// size minus three, bits 12-14 must be `0b011`, and bit 15 marks compressed
/// data. Trailing bytes that do not form another chunk are the module's
/// performance cache and end the container cleanly.
pub fn decompress(raw: &[u8], max_out: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= raw.len() {
        let header = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
        let size = (header & 0x0FFF) as usize;
        let signature = (header >> 12) & 0x7;
        let compressed = header & 0x8000 != 0;
        if signature != 3 {
            if pos == 0 {
                return Err("missing MS-OVBA chunk signature");
            }
            break;
        }
        let data_len = size + 1;
        let end = pos + 2 + data_len;
        if end > raw.len() {
            return Err("truncated compressed chunk");
        }
        if !compressed {
            if out.len() + data_len > max_out {
                return Err("decompressed module exceeds the configured cap");
            }
            out.extend_from_slice(&raw[pos + 2..end]);
        } else {
            let mut i = pos + 2;
            while i < end {
                let control = raw[i];
                i += 1;
                for bit in 0..8 {
                    if i >= end {
                        break;
                    }
                    if control & (1 << bit) == 0 {
                        if out.len() >= max_out {
                            return Err("decompressed module exceeds the configured cap");
                        }
                        out.push(raw[i]);
                        i += 1;
                    } else {
                        if i + 1 >= end {
                            return Err("truncated copy token");
                        }
                        let token = u16::from_le_bytes([raw[i], raw[i + 1]]);
                        i += 2;
                        let count = (token & 0x0FFF) as usize + 3;
                        let offset = ((token >> 12) + 1) as usize;
                        if offset > out.len() {
                            return Err("copy token points before the decoded data");
                        }
                        if out.len() + count > max_out {
                            return Err("decompressed module exceeds the configured cap");
                        }
                        let start = out.len() - offset;
                        for k in 0..count {
                            let byte = out[start + k];
                            out.push(byte);
                        }
                    }
                }
            }
        }
        pos = end;
    }
    Ok(out)
}

// --- OLE2 compound file reader ------------------------------------------

struct DirEntry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

struct Cfb<'a> {
    data: &'a [u8],
    sector_size: usize,
    major: u16,
    fat: Vec<u32>,
    entries: Vec<DirEntry>,
    mini_fat: Vec<u32>,
    mini_stream: Vec<u8>,
    cutoff: u64,
}

impl<'a> Cfb<'a> {
    fn parse(data: &'a [u8]) -> Option<Cfb<'a>> {
        if data.len() < 512 || !data.starts_with(&CFB_SIGNATURE) {
            return None;
        }
        let sector_shift = u16::from_le_bytes([data[0x1E], data[0x1F]]);
        if !(9..=12).contains(&sector_shift) {
            return None;
        }
        let sector_size = 1usize << sector_shift;
        if data.len() < sector_size {
            return None;
        }
        let major = u16::from_le_bytes([data[0x1A], data[0x1B]]);
        let num_fat = get_u32(data, 0x2C)?;
        if num_fat == 0 || num_fat > 65_536 {
            return None;
        }
        let first_dir = get_u32(data, 0x30)?;
        let cutoff = get_u32(data, 0x38)? as u64;
        let first_mini_fat = get_u32(data, 0x3C)?;
        let num_mini_fat = get_u32(data, 0x40)?;
        let first_difat = get_u32(data, 0x44)?;
        let num_difat = get_u32(data, 0x48)?;

        let mut fat_ids: Vec<u32> = Vec::new();
        for i in 0..109 {
            let id = get_u32(data, 0x4C + i * 4)?;
            if id < MAX_REGULAR_SECTOR {
                fat_ids.push(id);
            }
        }
        if num_difat > 0 && first_difat < MAX_REGULAR_SECTOR {
            let mut sector = first_difat;
            let mut seen = 0u32;
            while sector < MAX_REGULAR_SECTOR && seen < num_difat.min(1024) {
                let bytes = sector_bytes(data, sector_size, sector)?;
                let slots = sector_size / 4 - 1;
                for i in 0..slots {
                    let id = get_u32(bytes, i * 4)?;
                    if id < MAX_REGULAR_SECTOR {
                        fat_ids.push(id);
                    }
                }
                sector = get_u32(bytes, slots * 4)?;
                seen += 1;
            }
        }

        let mut fat = Vec::new();
        for id in fat_ids.iter().take(num_fat as usize) {
            let bytes = sector_bytes(data, sector_size, *id)?;
            for chunk in bytes.chunks_exact(4) {
                fat.push(u32::from_le_bytes(chunk.try_into().ok()?));
            }
        }
        if fat.is_empty() {
            return None;
        }

        let dir_bytes = read_chain_bytes(data, sector_size, &fat, first_dir, 4096 * 128)?;
        let entries = parse_directory(&dir_bytes);
        if entries.is_empty() {
            return None;
        }

        let root = entries.iter().position(|e| e.kind == 5).unwrap_or(0);
        let mini_stream = {
            let root = &entries[root];
            if root.size > 0 && root.size <= (16 * 1024 * 1024) {
                read_regular(data, sector_size, &fat, root.start, root.size as usize)?
            } else {
                Vec::new()
            }
        };

        let mini_fat = if num_mini_fat > 0 && first_mini_fat < MAX_REGULAR_SECTOR {
            let bytes = read_chain_bytes(
                data,
                sector_size,
                &fat,
                first_mini_fat,
                num_mini_fat as usize * sector_size,
            )?;
            bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        } else {
            Vec::new()
        };

        Some(Cfb {
            data,
            sector_size,
            major,
            fat,
            entries,
            mini_fat,
            mini_stream,
            cutoff,
        })
    }

    fn find_storage(&self, wanted: &str) -> Option<usize> {
        let root = self
            .entries
            .iter()
            .position(|e| e.kind == 5)
            .unwrap_or(0);
        let mut stack = vec![self.entries.get(root)?.child];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = stack.pop() {
            if id >= MAX_REGULAR_SECTOR || !seen.insert(id) {
                continue;
            }
            let entry = self.entries.get(id as usize)?;
            if entry.kind == 1 && entry.name.eq_ignore_ascii_case(wanted) {
                return Some(id as usize);
            }
            stack.push(entry.left);
            stack.push(entry.right);
            if entry.kind == 1 {
                stack.push(entry.child);
            }
        }
        None
    }

    fn children(&self, storage: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![self.entries.get(storage).map(|e| e.child).unwrap_or(FREE_SECTOR)];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = stack.pop() {
            if id >= MAX_REGULAR_SECTOR || !seen.insert(id) {
                continue;
            }
            let Some(entry) = self.entries.get(id as usize) else {
                continue;
            };
            out.push(id as usize);
            stack.push(entry.left);
            stack.push(entry.right);
        }
        out.sort_unstable();
        out
    }

    fn read_stream(&self, entry: &DirEntry) -> Option<Vec<u8>> {
        let size = if self.major == 3 {
            (entry.size & 0xFFFF_FFFF) as usize
        } else {
            usize::try_from(entry.size).ok()?
        };
        if size == 0 {
            return Some(Vec::new());
        }
        if entry.size < self.cutoff {
            self.read_mini(entry.start, size)
        } else {
            read_regular(self.data, self.sector_size, &self.fat, entry.start, size)
        }
    }

    fn read_mini(&self, start: u32, size: usize) -> Option<Vec<u8>> {
        if self.mini_stream.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(size);
        let mut sector = start;
        let mut guard = 0usize;
        while sector < MAX_REGULAR_SECTOR && out.len() < size {
            if guard > 65_536 {
                return None;
            }
            guard += 1;
            let offset = sector as usize * 64;
            let chunk = self.mini_stream.get(offset..offset + 64)?;
            out.extend_from_slice(chunk);
            sector = *self.mini_fat.get(sector as usize)?;
        }
        out.truncate(size);
        if out.len() != size {
            return None;
        }
        Some(out)
    }
}

fn parse_directory(bytes: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    for chunk in bytes.chunks_exact(128) {
        let kind = chunk[0x42];
        let name_len = u16::from_le_bytes([chunk[0x40], chunk[0x41]]) as usize;
        let name = if kind != 0 && (2..=64).contains(&name_len) {
            let chars = (name_len / 2).saturating_sub(1).min(31);
            let units: Vec<u16> = chunk[..chars * 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::new()
        };
        entries.push(DirEntry {
            name,
            kind,
            left: get_u32(chunk, 0x44).unwrap_or(FREE_SECTOR),
            right: get_u32(chunk, 0x48).unwrap_or(FREE_SECTOR),
            child: get_u32(chunk, 0x4C).unwrap_or(FREE_SECTOR),
            start: get_u32(chunk, 0x74).unwrap_or(FREE_SECTOR),
            size: get_u64(chunk, 0x78).unwrap_or(0),
        });
    }
    entries
}

fn sector_bytes(data: &[u8], sector_size: usize, id: u32) -> Option<&[u8]> {
    if id >= MAX_REGULAR_SECTOR {
        return None;
    }
    let offset = sector_size.checked_add((id as usize).checked_mul(sector_size)?)?;
    data.get(offset..offset + sector_size)
}

/// Reads a FAT chain until the end-of-chain marker or `max_bytes`, without
/// requiring the chain to be exactly `max_bytes` long. Used for the directory
/// and the mini FAT, whose final sector is partially used.
fn read_chain_bytes(
    data: &[u8],
    sector_size: usize,
    fat: &[u32],
    start: u32,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    if start >= MAX_REGULAR_SECTOR {
        return None;
    }
    let mut out = Vec::new();
    let mut sector = start;
    let mut guard = 0usize;
    while sector < MAX_REGULAR_SECTOR && out.len() < max_bytes {
        if guard > fat.len().saturating_add(1) {
            return None;
        }
        guard += 1;
        out.extend_from_slice(sector_bytes(data, sector_size, sector)?);
        sector = *fat.get(sector as usize)?;
    }
    out.truncate(max_bytes);
    Some(out)
}

fn read_regular(
    data: &[u8],
    sector_size: usize,
    fat: &[u32],
    start: u32,
    size: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(size.min(16 * 1024 * 1024));
    let mut sector = start;
    let mut guard = 0usize;
    while sector < MAX_REGULAR_SECTOR && out.len() < size {
        if guard > fat.len().saturating_add(1) {
            return None;
        }
        guard += 1;
        let bytes = sector_bytes(data, sector_size, sector)?;
        out.extend_from_slice(bytes);
        sector = *fat.get(sector as usize)?;
    }
    out.truncate(size);
    if out.len() != size {
        return None;
    }
    Some(out)
}

fn get_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn get_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Minimal but structurally real OLE2/OOXML fixtures.
    //!
    //! The compound-file writer implements the sector layout the reader
    //! consumes (header, FAT, directory, mini stream and mini FAT), so these
    //! tests exercise the same paths a real `vbaProject.bin` does instead of
    //! stubbing the parser out.

    use super::*;

    const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
    const FAT_SECTOR: u32 = 0xFFFF_FFFD;

    /// Encodes `data` as literal-only MS-OVBA chunks (compressed flag set).
    pub fn ovba(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(3500) {
            let mut body = Vec::new();
            for group in chunk.chunks(8) {
                body.push(0u8);
                body.extend_from_slice(group);
            }
            let size = (body.len() - 1) as u16;
            out.extend_from_slice(&(size | 0x3000 | 0x8000).to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_directory_entry(
        buf: &mut [u8],
        index: usize,
        name: &str,
        kind: u8,
        links: (u32, u32),
        stream: (u32, u32),
    ) {
        let (right, child) = links;
        let (start, size) = stream;
        let base = index * 128;
        let units: Vec<u16> = name.encode_utf16().take(31).collect();
        for (i, unit) in units.iter().enumerate() {
            put_u16(buf, base + i * 2, *unit);
        }
        put_u16(buf, base + 0x40, ((units.len() + 1) * 2) as u16);
        buf[base + 0x42] = kind;
        buf[base + 0x43] = 1;
        put_u32(buf, base + 0x44, FREE_SECTOR);
        put_u32(buf, base + 0x48, right);
        put_u32(buf, base + 0x4C, child);
        put_u32(buf, base + 0x74, start);
        put_u32(buf, base + 0x78, size);
        put_u32(buf, base + 0x7C, 0);
    }

    /// Builds an OLE2 compound file with a `VBA` storage and one stream per
    /// module. Modules smaller than 4096 bytes go through the mini stream.
    pub fn cfb_project(modules: &[(&str, &[u8])]) -> Vec<u8> {
        const SECTOR: usize = 512;
        const MINI: usize = 64;

        let entry_count = modules.len() + 2;
        let dir_sectors = entry_count.div_ceil(4);
        let mut mini = Vec::new();
        let mut mini_fat: Vec<u32> = Vec::new();
        let mut placement: Vec<(u32, u32, bool)> = Vec::new();

        for (_, code) in modules {
            if code.len() < 4096 {
                let start = (mini.len() / MINI) as u32;
                let chunks = code.len().div_ceil(MINI).max(1);
                mini.extend_from_slice(code);
                mini.resize((start as usize + chunks) * MINI, 0);
                for k in 0..chunks {
                    let index = start as usize + k;
                    if mini_fat.len() <= index {
                        mini_fat.resize(index + 1, FREE_SECTOR);
                    }
                    mini_fat[index] = if k + 1 == chunks {
                        END_OF_CHAIN
                    } else {
                        (index + 1) as u32
                    };
                }
                placement.push((start, code.len() as u32, true));
            } else {
                placement.push((0, code.len() as u32, false));
            }
        }

        let mini_sectors = mini.len().div_ceil(SECTOR);
        let mini_fat_sectors = mini_fat.len().div_ceil(128);
        let dir_start = 1usize;
        let mini_start = dir_start + dir_sectors;
        let mini_fat_start = mini_start + mini_sectors;
        let mut total_sectors = mini_fat_start + mini_fat_sectors;

        for (i, (_, code)) in modules.iter().enumerate() {
            if !placement[i].2 {
                placement[i].0 = total_sectors as u32;
                total_sectors += code.len().div_ceil(SECTOR);
            }
        }
        assert!(
            total_sectors <= 128,
            "fixture does not fit in one FAT sector ({total_sectors})"
        );

        let mut fat = vec![FREE_SECTOR; total_sectors];
        fat[0] = FAT_SECTOR;
        for (start, count) in [
            (dir_start, dir_sectors),
            (mini_start, mini_sectors),
            (mini_fat_start, mini_fat_sectors),
        ] {
            for (offset, slot) in fat[start..start + count].iter_mut().enumerate() {
                *slot = if offset + 1 == count {
                    END_OF_CHAIN
                } else {
                    (start + offset + 1) as u32
                };
            }
        }
        for (i, (_, code)) in modules.iter().enumerate() {
            if placement[i].2 {
                continue;
            }
            let start = placement[i].0 as usize;
            let count = code.len().div_ceil(SECTOR);
            for (offset, slot) in fat[start..start + count].iter_mut().enumerate() {
                *slot = if offset + 1 == count {
                    END_OF_CHAIN
                } else {
                    (start + offset + 1) as u32
                };
            }
        }

        let mut out = vec![0u8; SECTOR];
        out[..8].copy_from_slice(&CFB_SIGNATURE);
        put_u16(&mut out, 0x18, 0x003E);
        put_u16(&mut out, 0x1A, 0x0003);
        put_u16(&mut out, 0x1C, 0xFFFE);
        put_u16(&mut out, 0x1E, 9);
        put_u16(&mut out, 0x20, 6);
        put_u32(&mut out, 0x28, 0); // v3: directory sector count is not used
        put_u32(&mut out, 0x2C, 1); // one FAT sector
        put_u32(&mut out, 0x30, dir_start as u32);
        put_u32(&mut out, 0x34, 0); // transaction signature
        put_u32(&mut out, 0x38, 4096);
        put_u32(
            &mut out,
            0x3C,
            if mini_fat_sectors > 0 {
                mini_fat_start as u32
            } else {
                END_OF_CHAIN
            },
        );
        put_u32(&mut out, 0x40, mini_fat_sectors as u32);
        put_u32(&mut out, 0x44, END_OF_CHAIN);
        put_u32(&mut out, 0x48, 0);
        for i in 0..109 {
            put_u32(&mut out, 0x4C + i * 4, if i == 0 { 0 } else { FREE_SECTOR });
        }

        out.extend(fat.iter().flat_map(|v| v.to_le_bytes()));
        // The FAT sector is a full sector, never just the used entries.
        out.resize(SECTOR * 2, 0);
        out.resize(out.len() + 512 * dir_sectors, 0);
        let dir_offset = SECTOR + 512; // header + FAT sector
        {
            let dir = &mut out[dir_offset..dir_offset + 512 * dir_sectors];
            write_directory_entry(
                dir,
                0,
                "Root Entry",
                5,
                (FREE_SECTOR, 1),
                (
                    if mini_sectors > 0 {
                        mini_start as u32
                    } else {
                        END_OF_CHAIN
                    },
                    mini.len() as u32,
                ),
            );
            write_directory_entry(dir, 1, "VBA", 1, (FREE_SECTOR, 2), (END_OF_CHAIN, 0));
            for (i, (name, code)) in modules.iter().enumerate() {
                let entry = i + 2;
                let right = if i + 1 < modules.len() {
                    (entry + 1) as u32
                } else {
                    FREE_SECTOR
                };
                write_directory_entry(
                    dir,
                    entry,
                    name,
                    2,
                    (right, FREE_SECTOR),
                    (placement[i].0, placement[i].1.max(code.len() as u32)),
                );
            }
        }

        out.extend_from_slice(&mini);
        out.resize(out.len() + (SECTOR - (mini.len() % SECTOR)) % SECTOR, 0);
        let mini_fat_len = mini_fat_sectors * 512;
        let mini_fat_start_offset = out.len();
        out.resize(out.len() + mini_fat_len, 0);
        {
            let bytes = &mut out[mini_fat_start_offset..];
            for (i, value) in mini_fat.iter().enumerate() {
                put_u32(bytes, i * 4, *value);
            }
        }

        for (i, (_, code)) in modules.iter().enumerate() {
            if placement[i].2 {
                continue;
            }
            out.extend_from_slice(code);
            out.resize(out.len() + (SECTOR - (code.len() % SECTOR)) % SECTOR, 0);
        }
        out
    }

    /// Builds an OLE2 compound file with one top-level stream (no VBA storage).
    /// Used for the legacy `Workbook` stream in Excel 4.0 tests.
    pub fn cfb_stream(name: &str, data: &[u8]) -> Vec<u8> {
        const SECTOR: usize = 512;
        const MINI: usize = 64;

        let chunks = data.len().div_ceil(MINI).max(1);
        let mut mini = data.to_vec();
        mini.resize(chunks * MINI, 0);
        let mut mini_fat = vec![END_OF_CHAIN; chunks];
        for (index, slot) in mini_fat.iter_mut().enumerate() {
            if index + 1 < chunks {
                *slot = (index + 1) as u32;
            }
        }

        let dir_start = 1usize;
        let mini_start = dir_start + 1;
        let mini_sectors = mini.len().div_ceil(SECTOR);
        let mini_fat_start = mini_start + mini_sectors;
        let mini_fat_sectors = mini_fat.len().div_ceil(128);
        let total_sectors = mini_fat_start + mini_fat_sectors;

        let mut fat = vec![FREE_SECTOR; total_sectors];
        fat[0] = FAT_SECTOR;
        fat[dir_start] = END_OF_CHAIN;
        for (offset, slot) in fat[mini_start..mini_start + mini_sectors].iter_mut().enumerate() {
            *slot = if offset + 1 == mini_sectors {
                END_OF_CHAIN
            } else {
                (mini_start + offset + 1) as u32
            };
        }
        for (offset, slot) in fat[mini_fat_start..mini_fat_start + mini_fat_sectors]
            .iter_mut()
            .enumerate()
        {
            *slot = if offset + 1 == mini_fat_sectors {
                END_OF_CHAIN
            } else {
                (mini_fat_start + offset + 1) as u32
            };
        }

        let mut out = vec![0u8; SECTOR];
        out[..8].copy_from_slice(&CFB_SIGNATURE);
        put_u16(&mut out, 0x18, 0x003E);
        put_u16(&mut out, 0x1A, 0x0003);
        put_u16(&mut out, 0x1C, 0xFFFE);
        put_u16(&mut out, 0x1E, 9);
        put_u16(&mut out, 0x20, 6);
        put_u32(&mut out, 0x28, 0);
        put_u32(&mut out, 0x2C, 1);
        put_u32(&mut out, 0x30, dir_start as u32);
        put_u32(&mut out, 0x34, 0);
        put_u32(&mut out, 0x38, 4096);
        put_u32(&mut out, 0x3C, mini_fat_start as u32);
        put_u32(&mut out, 0x40, mini_fat_sectors as u32);
        put_u32(&mut out, 0x44, END_OF_CHAIN);
        put_u32(&mut out, 0x48, 0);
        for i in 0..109 {
            put_u32(&mut out, 0x4C + i * 4, if i == 0 { 0 } else { FREE_SECTOR });
        }
        out.extend(fat.iter().flat_map(|v| v.to_le_bytes()));
        out.resize(SECTOR * 2, 0);
        out.resize(out.len() + SECTOR, 0);
        let dir_offset = SECTOR * 2;
        {
            let dir = &mut out[dir_offset..dir_offset + SECTOR];
            write_directory_entry(
                dir,
                0,
                "Root Entry",
                5,
                (FREE_SECTOR, 1),
                (mini_start as u32, mini.len() as u32),
            );
            write_directory_entry(
                dir,
                1,
                name,
                2,
                (FREE_SECTOR, FREE_SECTOR),
                (0, data.len() as u32),
            );
        }
        out.extend_from_slice(&mini);
        out.resize(out.len() + (SECTOR - (mini.len() % SECTOR)) % SECTOR, 0);
        let mini_fat_offset = out.len();
        out.resize(out.len() + mini_fat_sectors * SECTOR, 0);
        for (i, value) in mini_fat.iter().enumerate() {
            put_u32(&mut out[mini_fat_offset..], i * 4, *value);
        }
        out
    }

    /// Builds a `.docm`-shaped ZIP carrying `word/vbaProject.bin`.
    pub fn docm(modules: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let project = cfb_project(modules);
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in [
            ("[Content_Types].xml", b"<Types/>".as_slice()),
            ("word/document.xml", b"<w:document/>".as_slice()),
            ("word/vbaProject.bin", project.as_slice()),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{cfb_project, docm, ovba};
    use super::*;

    fn project(modules: &[(&str, &[u8])]) -> VbaProject {
        extract(&cfb_project(modules), &VbaLimits::default())
    }

    #[test]
    fn literal_chunks_round_trip() {
        let code = b"Sub AutoOpen()\r\n    MsgBox \"hello\"\r\nEnd Sub\r\n";
        let encoded = ovba(code);
        assert_eq!(decompress(&encoded, 4096).unwrap(), code);
    }

    #[test]
    fn copy_tokens_expand_history() {
        // Control 0b0000_1000: three literals then one copy token that copies
        // six bytes starting three bytes back, so "ABC" becomes "ABCABCABC".
        let chunk = [
            0x05, 0xB0, // size 5, signature 0b011, compressed flag
            0x08, b'A', b'B', b'C', 0x03, 0x20,
        ];
        assert_eq!(decompress(&chunk, 64).unwrap(), b"ABCABCABC");
    }

    #[test]
    fn truncated_chunk_is_rejected() {
        // Header claims a 100-byte chunk, only a few bytes follow.
        let chunk = [0x63, 0xB0, 0x00, b'a'];
        assert!(decompress(&chunk, 4096).is_err());
    }

    #[test]
    fn decompression_output_is_capped() {
        let encoded = ovba(b"this macro source is longer than the tiny cap");
        assert!(decompress(&encoded, 8).is_err());
    }

    #[test]
    fn a_missing_signature_is_rejected() {
        assert!(decompress(b"plain text, not a compressed container", 4096).is_err());
    }

    #[test]
    fn a_small_module_is_read_from_the_mini_stream() {
        let code = b"Sub Hello()\r\n    MsgBox \"hi\"\r\nEnd Sub\r\n";
        let encoded = ovba(code);
        assert!(encoded.len() < 4096, "fixture must use the mini stream");
        let project = project(&[("Module1", &encoded)]);
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert_eq!(project.modules[0].name, "Module1");
        assert_eq!(project.modules[0].code, code);
        assert_eq!(project.modules[0].cache_bytes, 0);
        assert_eq!(project.pcode_modules, 0);
    }

    #[test]
    fn a_performance_cache_before_the_source_is_skipped_and_counted() {
        let code = b"Sub AutoOpen()\r\n    Shell \"calc\"\r\nEnd Sub\r\n";
        // Real Office streams put the p-code cache first; its size is
        // version-dependent, so this is arbitrary binary data.
        let mut stream = vec![0x41u8; 96];
        stream.extend_from_slice(&ovba(code));
        let project = project(&[("Module1", &stream)]);
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert_eq!(project.modules[0].code, code);
        assert_eq!(project.modules[0].cache_bytes, 96);
        assert_eq!(project.pcode_modules, 1);
    }

    #[test]
    fn a_cache_only_module_is_reported_as_possible_stomping() {
        // No valid chunk container anywhere: compiled cache with the source
        // removed or replaced.
        let stream = vec![0x5Au8; 256];
        let project = project(&[("Module1", &stream)]);
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert!(project.modules[0].code.is_empty());
        assert_eq!(project.modules[0].cache_bytes, 256);
        assert!(project.notes.iter().any(|n| n.contains("VBA stomping")));
    }

    #[test]
    fn a_large_module_is_read_from_regular_sectors() {
        let code = vec![b'A'; 9000];
        let encoded = ovba(&code);
        assert!(encoded.len() > 4096, "fixture must use regular sectors");
        let project = project(&[("Module1", &encoded)]);
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert_eq!(project.modules[0].code, code);
    }

    #[test]
    fn the_project_category_stream_is_skipped() {
        let code = b"Sub Hello()\r\nEnd Sub\r\n";
        let encoded = ovba(code);
        let project = project(&[("dir", &encoded), ("Module1", &encoded)]);
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert_eq!(project.modules[0].name, "Module1");
    }

    #[test]
    fn an_ooxml_package_yields_its_macro_module() {
        let code = b"Sub AutoOpen()\r\n    Shell \"cmd.exe\"\r\nEnd Sub\r\n";
        let data = docm(&[("Module1", &ovba(code))]);
        let project = extract(&data, &VbaLimits::default());
        assert_eq!(project.modules.len(), 1, "notes: {:?}", project.notes);
        assert_eq!(project.modules[0].code, code);
    }

    #[test]
    fn a_compound_file_without_vba_storage_has_no_modules() {
        // Header-only compound file: parser rejects it rather than inventing a
        // project, and the failure is reported.
        let mut data = vec![0u8; 512];
        data[..8].copy_from_slice(&CFB_SIGNATURE);
        let project = extract(&data, &VbaLimits::default());
        assert!(project.is_empty());
        assert!(!project.notes.is_empty());
    }

    #[test]
    fn corrupt_projects_never_panic() {
        let mut data = vec![0x41u8; 4096];
        data[..8].copy_from_slice(&CFB_SIGNATURE);
        let _ = extract(&data, &VbaLimits::default());
        let _ = extract(b"PK\x03\x04 not really a zip", &VbaLimits::default());
        let _ = extract(b"", &VbaLimits::default());
    }

    #[test]
    fn the_project_size_cap_is_reported() {
        let limits = VbaLimits {
            max_project_bytes: 16,
            ..Default::default()
        };
        let data = docm(&[("Module1", &ovba(b"Sub Hello()\r\nEnd Sub\r\n"))]);
        let project = extract(&data, &limits);
        assert!(project.truncated);
        assert!(project.modules.is_empty());
        assert!(project.notes.iter().any(|n| n.contains("cap")));
    }
}
