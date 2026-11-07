//! Content format identification.
//!
//! Format detection is content-based and deliberately *independent of the file
//! extension*. Extension mismatch is itself a detection signal, and malware
//! routinely lies about its type (`report.pdf.exe`, `.docm` that is really a
//! PE, LNK files named like documents).

use std::path::Path;

/// Broad content classes the engine understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    JavaClass,
    Pdf,
    /// OLE2 compound file: legacy Office, MSI, some installers.
    Ole2,
    Zip,
    /// OOXML (docx/xlsx/pptx) — ZIP with an `[Content_Types].xml`.
    Ooxml,
    /// ZIP containing `META-INF/MANIFEST.MF`.
    Jar,
    Rar,
    SevenZip,
    Gzip,
    Bzip2,
    Xz,
    Cab,
    Iso,
    Rtf,
    Script(ScriptKind),
    Lnk,
    RegistryHive,
    Evtx,
    Sqlite,
    OleAcc,
    /// Unknown but containing an embedded PE at a non-standard offset.
    EmbeddedPe,
    Binary,
    Empty,
}

/// Scripting languages identified by content sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
    PowerShell,
    Vbs,
    Js,
    Batch,
    Shell,
    Hta,
    Python,
    Php,
    Wsf,
    Unknown,
}

impl FileFormat {
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            FileFormat::Pe | FileFormat::Elf | FileFormat::MachO | FileFormat::JavaClass
        )
    }

    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            FileFormat::Zip
                | FileFormat::Ooxml
                | FileFormat::Jar
                | FileFormat::Rar
                | FileFormat::SevenZip
                | FileFormat::Gzip
                | FileFormat::Bzip2
                | FileFormat::Xz
                | FileFormat::Cab
                | FileFormat::Iso
        )
    }

    /// ZIP-family containers have a reader in the portable engine. Other
    /// archive formats are identified but are not unpacked yet.
    pub fn is_zip_family(&self) -> bool {
        matches!(
            self,
            FileFormat::Zip | FileFormat::Ooxml | FileFormat::Jar
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            FileFormat::Pe => "pe",
            FileFormat::Elf => "elf",
            FileFormat::MachO => "macho",
            FileFormat::JavaClass => "java-class",
            FileFormat::Pdf => "pdf",
            FileFormat::Ole2 => "ole2",
            FileFormat::Zip => "zip",
            FileFormat::Ooxml => "ooxml",
            FileFormat::Jar => "jar",
            FileFormat::Rar => "rar",
            FileFormat::SevenZip => "7z",
            FileFormat::Gzip => "gzip",
            FileFormat::Bzip2 => "bzip2",
            FileFormat::Xz => "xz",
            FileFormat::Cab => "cab",
            FileFormat::Iso => "iso",
            FileFormat::Rtf => "rtf",
            FileFormat::Script(_) => "script",
            FileFormat::Lnk => "lnk",
            FileFormat::RegistryHive => "registry-hive",
            FileFormat::Evtx => "evtx",
            FileFormat::Sqlite => "sqlite",
            FileFormat::OleAcc => "oleacc",
            FileFormat::EmbeddedPe => "embedded-pe",
            FileFormat::Binary => "binary",
            FileFormat::Empty => "empty",
        }
    }

    /// Script flavour, for rule conditions such as `format == "powershell"`.
    pub fn script_label(&self) -> Option<&'static str> {
        match self {
            FileFormat::Script(k) => Some(match k {
                ScriptKind::PowerShell => "powershell",
                ScriptKind::Vbs => "vbs",
                ScriptKind::Js => "js",
                ScriptKind::Batch => "batch",
                ScriptKind::Shell => "shell",
                ScriptKind::Hta => "hta",
                ScriptKind::Python => "python",
                ScriptKind::Php => "php",
                ScriptKind::Wsf => "wsf",
                ScriptKind::Unknown => "script",
            }),
            _ => None,
        }
    }
}

/// Detect the content format from magic bytes and structural cues.
pub fn detect(data: &[u8]) -> FileFormat {
    if data.is_empty() {
        return FileFormat::Empty;
    }
    if data.len() > 2 && data[0] == b'M' && data[1] == b'Z' && lenient_pe(data) {
        return FileFormat::Pe;
    }
    if data.starts_with(b"\x7fELF") {
        return FileFormat::Elf;
    }
    if data.len() > 4 {
        let m = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if m == 0xFEED_FACE || m == 0xFEED_FACF || m == 0xCEFA_EDFE || m == 0xCFFA_EDFE {
            return FileFormat::MachO;
        }
        if m == 0xCAFE_BABE {
            return FileFormat::JavaClass;
        }
    }
    if data.starts_with(b"%PDF-") {
        return FileFormat::Pdf;
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileFormat::Ole2;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return detect_zip_family(data);
    }
    if data.starts_with(b"Rar!\x1a\x07") {
        return FileFormat::Rar;
    }
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return FileFormat::SevenZip;
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return FileFormat::Gzip;
    }
    if data.starts_with(b"BZh") {
        return FileFormat::Bzip2;
    }
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return FileFormat::Xz;
    }
    if data.starts_with(b"MSCF") {
        return FileFormat::Cab;
    }
    if data.len() > 0x8006 && &data[0x8001..0x8006] == b"CD001" {
        return FileFormat::Iso;
    }
    if data.starts_with(b"{\\rtf") {
        return FileFormat::Rtf;
    }
    if data.len() > 76
        && data[0] == 0x4C
        && data[1] == 0x00
        && data[2] == 0x00
        && data[3] == 0x00
        && data[4] == 0x01
        && data[5] == 0x14
        && data[6] == 0x02
        && data[7] == 0x00
    {
        return FileFormat::Lnk;
    }
    if data.starts_with(b"regf") {
        return FileFormat::RegistryHive;
    }
    if data.starts_with(b"ElfFile\x00") {
        return FileFormat::Evtx;
    }
    if data.starts_with(b"SQLite format 3\x00") {
        return FileFormat::Sqlite;
    }
    if data.len() > 0x52 && data.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        // ICO/CUR are common false positives here; keep the check narrow.
        let count = u16::from_le_bytes([data[4], data[5]]);
        if count > 0 && count < 64 {
            return FileFormat::OleAcc;
        }
    }
    if let Some(kind) = sniff_script(data) {
        return FileFormat::Script(kind);
    }
    if find_embedded_pe(data).is_some() {
        return FileFormat::EmbeddedPe;
    }
    if looks_like_text(data) {
        return FileFormat::Binary;
    }
    FileFormat::Binary
}

/// True if the buffer is a structurally plausible PE (has an e_lfanew and NT
/// signature), used to avoid false positives on files that merely start "MZ".
fn lenient_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if off < 0x40 || off + 4 > data.len() {
        return false;
    }
    &data[off..off + 4] == b"PE\x00\x00"
}

fn detect_zip_family(data: &[u8]) -> FileFormat {
    // Central-directory entry names live in the trailing part of the archive.
    let tail_start = data.len().saturating_sub(128 * 1024);
    let tail = &data[tail_start..];
    if contains(tail, b"[Content_Types].xml") {
        if contains(tail, b"word/") || contains(tail, b"xl/") || contains(tail, b"ppt/") {
            return FileFormat::Ooxml;
        }
        return FileFormat::Ooxml;
    }
    if contains(tail, b"META-INF/MANIFEST.MF") {
        return FileFormat::Jar;
    }
    FileFormat::Zip
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Finds an embedded `MZ`/`PE` pair at an offset other than 0.
pub fn find_embedded_pe(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(16 * 1024 * 1024);
    let mut i = 0usize;
    while i + 0x40 < limit {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let pe = u32::from_le_bytes([
                data[i + 0x3C],
                data[i + 0x3D],
                data[i + 0x3E],
                data[i + 0x3F],
            ]) as usize;
            let abs = i + pe;
            if pe >= 0x40 && abs + 4 <= data.len() && &data[abs..abs + 4] == b"PE\x00\x00" {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub fn looks_like_text(data: &[u8]) -> bool {
    let n = data.len().min(4096);
    let sample = &data[..n];
    if sample.is_empty() {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|b| **b == b'\n' || **b == b'\r' || **b == b'\t' || (0x20..0x7f).contains(*b))
        .count();
    (printable as f64 / sample.len() as f64) > 0.95
}

/// Decodes a small text prefix as UTF-8/UTF-16 for script sniffing.
fn text_prefix(data: &[u8]) -> String {
    let n = data.len().min(8192);
    let sample = &data[..n];
    if sample.len() > 2 && sample[0] == 0xFF && sample[1] == 0xFE {
        let units: Vec<u16> = sample[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units).to_ascii_lowercase();
    }
    if sample.len() > 2 && sample[0] == 0xFE && sample[1] == 0xFF {
        let units: Vec<u16> = sample[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units).to_ascii_lowercase();
    }
    let start = if sample.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    String::from_utf8_lossy(&sample[start..]).to_ascii_lowercase()
}

fn sniff_script(data: &[u8]) -> Option<ScriptKind> {
    if !looks_like_text(data) {
        return None;
    }
    let t = text_prefix(data);
    let head = &t[..t.len().min(2048)];
    if head.starts_with("#!") {
        if head.contains("python") {
            return Some(ScriptKind::Python);
        }
        if head.contains("php") {
            return Some(ScriptKind::Php);
        }
        return Some(ScriptKind::Shell);
    }
    if head.contains("<html") && head.contains("<script") {
        return Some(ScriptKind::Hta);
    }
    if head.contains("<package") && head.contains("<job") {
        return Some(ScriptKind::Wsf);
    }
    if head.contains("function ") && head.contains("dim ") || head.contains("wscript.echo") {
        return Some(ScriptKind::Vbs);
    }
    if head.contains("param(")
        || head.contains("get-item")
        || head.contains("invoke-expression")
        || head.contains("add-mppreference")
        || head.contains("$env:")
        || head.contains("new-object")
        || head.contains("write-output")
        || head.contains("$psversiontable")
        || head.contains("[system.io")
        || head.contains(" iex ")
        || head.starts_with("iex ")
        || (head.contains("write-host") && head.contains("$"))
    {
        return Some(ScriptKind::PowerShell);
    }
    if head.starts_with("@echo") || head.contains("\r\necho ") || head.contains("goto :eof") {
        return Some(ScriptKind::Batch);
    }
    if head.contains("require(") || head.contains("document.write(") || head.contains("new activexobject") {
        return Some(ScriptKind::Js);
    }
    // Not recognisably a script. Claiming "unknown script" for every text file
    // would create extension-mismatch false positives, so return nothing.
    None
}

/// Extensions that are commonly spoofed by malware, and the formats that are
/// plausible for them. Returns `None` when the extension is not in the map.
pub fn expected_formats(ext: &str) -> Option<&'static [FileFormat]> {
    let ext = ext.trim_start_matches('.').to_ascii_lowercase();
    let list: &'static [FileFormat] = match ext.as_str() {
        "exe" | "dll" | "sys" | "scr" | "cpl" | "ocx" | "drv" | "efi" | "mui" => &[FileFormat::Pe],
        "pdf" => &[FileFormat::Pdf],
        "doc" | "xls" | "ppt" | "msi" | "msg" => &[FileFormat::Ole2],
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => &[FileFormat::Ooxml, FileFormat::Zip],
        "zip" | "jar" | "apk" => &[FileFormat::Zip, FileFormat::Jar, FileFormat::Ooxml],
        "rar" => &[FileFormat::Rar],
        "7z" => &[FileFormat::SevenZip],
        "gz" | "tgz" => &[FileFormat::Gzip],
        "bz2" => &[FileFormat::Bzip2],
        "xz" => &[FileFormat::Xz],
        "cab" => &[FileFormat::Cab],
        "iso" => &[FileFormat::Iso],
        "rtf" => &[FileFormat::Rtf],
        "lnk" => &[FileFormat::Lnk],
        "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse" | "bat" | "cmd" | "sh" | "py" | "php"
        | "wsf" | "hta" => &[FileFormat::Script(ScriptKind::Unknown), FileFormat::Binary],
        "evtx" => &[FileFormat::Evtx],
        "txt" | "log" | "csv" | "xml" | "json" | "ini" | "cfg" => &[FileFormat::Binary],
        _ => return None,
    };
    Some(list)
}

/// True when the actual content is plausible for the given extension.
pub fn extension_matches(ext: &str, format: FileFormat) -> bool {
    match expected_formats(ext) {
        None => true, // unknown extension: nothing to contradict
        Some(list) => list.iter().any(|f| {
            *f == format
                || (matches!(f, FileFormat::Script(_))
                    && matches!(format, FileFormat::Script(_)))
        }),
    }
}

/// Strips the trailing extension (lowercased) from a path.
pub fn extension_of(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Returns the full multi-part extension chain, e.g. `report.pdf.exe` -> `["pdf","exe"]`.
pub fn extension_chain(path: &Path) -> Vec<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            n.split('.')
                .skip(1)
                .map(|s| s.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_basic_magics() {
        assert_eq!(detect(b"%PDF-1.7\n"), FileFormat::Pdf);
        assert_eq!(detect(b"\x7fELF\x02\x01"), FileFormat::Elf);
        assert_eq!(detect(b"MSCF\x00\x00\x00\x00"), FileFormat::Cab);
        assert_eq!(detect(b"{\\rtf1\\ansi"), FileFormat::Rtf);
        assert_eq!(detect(b"regf\x00\x00"), FileFormat::RegistryHive);
        assert_eq!(detect(b"SQLite format 3\x00"), FileFormat::Sqlite);
        assert_eq!(detect(b""), FileFormat::Empty);
    }

    #[test]
    fn detects_scripts_by_content() {
        let ps = b"param([string]$x)\nInvoke-Expression $payload\n";
        assert_eq!(
            detect(ps),
            FileFormat::Script(ScriptKind::PowerShell),
            "powershell script not detected"
        );
        assert_eq!(
            detect(b"@echo off\r\necho hello\r\n"),
            FileFormat::Script(ScriptKind::Batch)
        );
        assert_eq!(
            detect(b"#!/bin/sh\ncurl x | sh\n"),
            FileFormat::Script(ScriptKind::Shell)
        );
    }

    #[test]
    fn extension_mismatch_is_visible() {
        assert!(extension_matches("exe", FileFormat::Pe));
        assert!(!extension_matches("pdf", FileFormat::Pe));
        assert!(extension_matches("docx", FileFormat::Ooxml));
        assert!(extension_matches("xyz", FileFormat::Pe), "unknown ext must not lie");
        assert_eq!(extension_chain(Path::new("report.pdf.exe")), vec!["pdf", "exe"]);
    }

    #[test]
    fn embedded_pe_is_found() {
        // Minimal synthetic PE embedded at offset 100.
        let mut data = vec![0u8; 100 + 0x40 + 4];
        let base = 100;
        data[base] = b'M';
        data[base + 1] = b'Z';
        data[base + 0x3C] = 0x40;
        data[base + 0x40..base + 0x44].copy_from_slice(b"PE\x00\x00");
        assert_eq!(find_embedded_pe(&data), Some(base));
    }

    #[test]
    fn text_detection_does_not_crash_on_binary() {
        let mut data = vec![0u8; 8192];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 37 % 256) as u8;
        }
        let f = detect(&data);
        assert!(matches!(f, FileFormat::Binary | FileFormat::EmbeddedPe));
    }
}
