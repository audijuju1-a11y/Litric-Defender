//! Original PE (Portable Executable) parser.
//!
//! This is Litric's own structural analyser: it does not depend on any external
//! AV or PE library. It is written to be *total* over hostile input — every read
//! is bounds-checked, every loop is capped, and a malformed file yields a
//! `ParseError` instead of a panic or a hang.
//!
//! What it extracts and why:
//! * headers/sections/characteristics — structural anomaly detection
//! * imports/exports/delay-imports — capability inference, import fingerprinting
//! * resources/version info/manifest — publisher identity, privilege request
//! * overlay, Rich header, debug directory — packer and build-chain indicators
//! * TLS callbacks, CFG/ASLR/DEP flags, CLR header — hardening and .NET detection
//! * security directory — Authenticode blob offset for `authenticode`

use crate::bytes::{timestamp_to_year, Reader};
use crate::entropy::entropy;
use crate::error::ParseError;
use crate::hash::{import_fingerprint, Digest32};

/// Hard cap on parsed import descriptors (DLLs) per image.
const MAX_IMPORT_DLLS: usize = 512;
/// Hard cap on imported function names per image.
const MAX_IMPORT_FUNCS: usize = 20_000;
/// Hard cap on exported names retained per image.
const MAX_EXPORTS: usize = 4_096;
/// Hard cap on resource directory nodes visited.
const MAX_RESOURCE_NODES: usize = 4_096;
/// Resource directory recursion depth (RT -> name -> lang).
const RESOURCE_DEPTH: u32 = 3;

pub const MACHINE_I386: u16 = 0x014c;
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_ARM64: u16 = 0xaa64;
pub const MACHINE_ARMNT: u16 = 0x01c4;

// DLL characteristics
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

// Section characteristics
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const DIR_BASERELOC: usize = 5;
const DIR_DEBUG: usize = 6;
const DIR_TLS: usize = 9;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_DELAY_IMPORT: usize = 13;
const DIR_CLR: usize = 14;

/// A single PE section header plus derived facts.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    /// Shannon entropy of the section's raw bytes (0.0 if no raw data).
    pub entropy: f64,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }
    pub fn has_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }
    /// Writable *and* executable is a classic self-modifying/packed indicator.
    pub fn is_wx(&self) -> bool {
        self.is_writable() && self.is_executable()
    }
    /// Uninitialized section (e.g. `UPX0`): virtual size with no raw data.
    pub fn is_virtual_only(&self) -> bool {
        self.raw_size == 0 && self.virtual_size > 0
    }
    /// Raw bytes of this section, clipped to the file.
    pub fn raw<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        let start = self.raw_pointer as usize;
        if start >= file.len() {
            return &[];
        }
        let want = (self.raw_size as usize).min(file.len() - start);
        &file[start..start + want]
    }
}

/// One imported DLL and its function names.
#[derive(Debug, Clone)]
pub struct ImportedDll {
    pub name: String,
    pub functions: Vec<String>,
    pub ordinal_count: usize,
}

/// Version resource strings (best-effort extraction).
#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub present: bool,
    pub company: Option<String>,
    pub product: Option<String>,
    pub original_filename: Option<String>,
    pub description: Option<String>,
}

/// Embedded application manifest facts.
#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub present: bool,
    /// `requireAdministrator` or `highestAvailable` requested.
    pub require_admin: bool,
    /// Declares `uiAccess="true"`.
    pub ui_access: bool,
}

/// Authenticode blob location and a certificate summary.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    pub present: bool,
    /// File offset of the WIN_CERTIFICATE structure.
    pub file_offset: u32,
    pub size: u32,
    /// PKCS#7 (`WIN_CERT_TYPE_PKCS_SIGNED_DATA`) vs. legacy types.
    pub pkcs7: bool,
    /// Certificate subject common names found in the PKCS#7 blob.
    pub subject_names: Vec<String>,
    /// Latest `notAfter` year found among embedded certificates, if parsed.
    pub not_after_year: Option<i64>,
    /// A code-signing EKU OID (`1.3.6.1.5.5.7.3.3`) was present.
    pub code_signing_eku: bool,
    /// The blob contained a timestamp/countersignature token.
    pub timestamped: bool,
}

/// Everything Litric's static engine knows about one PE image.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub machine: u16,
    pub is_64: bool,
    pub timestamp: u32,
    pub timestamp_year: i64,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub characteristics: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub checksum_valid: bool,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportedDll>,
    pub delay_imports: Vec<String>,
    pub exports: Vec<String>,
    pub import_fingerprint: Digest32,
    pub import_function_count: usize,
    pub overlay_size: u64,
    /// An `MZ` signature was found at the start of the overlay (embedded EXE).
    pub overlay_mz: bool,
    pub version_info: VersionInfo,
    pub manifest: ManifestInfo,
    pub signature: SignatureInfo,
    pub has_relocations: bool,
    pub has_tls: bool,
    pub has_load_config: bool,
    pub guard_cfg: bool,
    pub aslr: bool,
    pub dep: bool,
    pub high_entropy_va: bool,
    pub force_integrity: bool,
    pub is_dotnet: bool,
    pub is_dll: bool,
    pub is_driver: bool,
    pub is_system: bool,
    pub rich_header_present: bool,
    pub pdb_path: Option<String>,
    /// Entry point does not fall inside any section — strong packing indicator.
    pub entry_outside_sections: bool,
    pub section_count: usize,
    pub max_section_entropy: f64,
    pub overlay_entropy: f64,
}

impl PeInfo {
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            MACHINE_I386 => "x86",
            MACHINE_AMD64 => "x64",
            MACHINE_ARM64 => "arm64",
            MACHINE_ARMNT => "arm",
            _ => "unknown",
        }
    }

    /// Sum of imported function counts.
    pub fn total_imports(&self) -> usize {
        self.import_function_count
    }

    pub fn imported_dll_names(&self) -> impl Iterator<Item = &str> {
        self.imports.iter().map(|d| d.name.as_str())
    }

    /// True when the image imports a given function (case-insensitive).
    pub fn imports_function(&self, func: &str) -> bool {
        self.imports.iter().any(|d| {
            d.functions
                .iter()
                .any(|f| f.eq_ignore_ascii_case(func))
        })
    }

    /// Section names that commonly indicate a known packer/protector.
    pub fn packer_hints(&self) -> Vec<&'static str> {
        let mut hints = Vec::new();
        for s in &self.sections {
            let lower = s.name.to_ascii_lowercase();
            let hint = match lower.as_str() {
                "upx0" | "upx1" | "upx2" => Some("UPX"),
                ".aspack" | ".adata" => Some("ASPack"),
                ".mpress1" | ".mpress2" => Some("MPRESS"),
                ".themida" | ".winlice" => Some("Themida/WinLicense"),
                ".vmp0" | ".vmp1" | ".vmp2" => Some("VMProtect"),
                ".enigma1" | ".enigma2" => Some("Enigma"),
                ".packed" => Some("generic packer"),
                ".petite" => Some("Petite"),
                ".nsp0" | ".nsp1" | ".nsp2" => Some("NsPack"),
                _ => None,
            };
            if let Some(h) = hint {
                if !hints.contains(&h) {
                    hints.push(h);
                }
            }
        }
        hints
    }

    /// Entropy of the executable sections, weighted by raw size.
    pub fn code_entropy(&self) -> f64 {
        let mut total = 0u64;
        let mut acc = 0f64;
        for s in &self.sections {
            if s.is_executable() && s.raw_size > 0 {
                acc += s.entropy * s.raw_size as f64;
                total += s.raw_size as u64;
            }
        }
        if total == 0 {
            0.0
        } else {
            acc / total as f64
        }
    }

    pub fn high_entropy_exec_sections(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| s.is_executable() && s.raw_size >= 256 && s.entropy > 7.2)
            .count()
    }

    pub fn wx_sections(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| s.is_wx() && s.raw_size > 0)
            .count()
    }

    pub fn virtual_only_sections(&self) -> usize {
        self.sections.iter().filter(|s| s.is_virtual_only()).count()
    }

    pub fn has_version_info(&self) -> bool {
        self.version_info.present
    }

    pub fn is_signed(&self) -> bool {
        self.signature.present
    }
}

/// Maps an RVA to a file offset using the section table.
pub fn rva_to_offset(info_sections: &[Section], size_of_headers: u32, rva: u32) -> Option<usize> {
    if rva < size_of_headers {
        return Some(rva as usize);
    }
    for s in info_sections {
        let start = s.virtual_address;
        // Prefer raw size: bytes past SizeOfRawData are zero-filled and not on disk.
        let end = start.checked_add(s.raw_size.max(1))?;
        if rva >= start && rva < end {
            let delta = rva - start;
            return Some(s.raw_pointer.checked_add(delta)? as usize);
        }
    }
    None
}

/// Parses a PE image. Returns `Err` for non-PE input or structural corruption.
pub fn parse(data: &[u8]) -> Result<PeInfo, ParseError> {
    let r = Reader::new(data);
    if r.u16_at(0) != Some(0x5A4D) {
        return Err(ParseError::NotThisFormat);
    }
    let pe_off = r.u32_at(0x3C).ok_or(ParseError::Truncated {
        what: "e_lfanew",
        need: 0x40,
        have: data.len(),
    })? as usize;
    if r.u32_at(pe_off) != Some(0x0000_4550) {
        return Err(ParseError::BadMagic("NT signature"));
    }

    let coff = pe_off.checked_add(4).ok_or(ParseError::Overflow("coff"))?;
    let machine = r.u16_at(coff).ok_or(ParseError::NotThisFormat)?;
    let section_count = r.u16_at(coff + 2).unwrap_or(0) as usize;
    let timestamp = r.u32_at(coff + 4).unwrap_or(0);
    let size_of_optional = r.u16_at(coff + 16).unwrap_or(0) as usize;
    let characteristics = r.u16_at(coff + 18).unwrap_or(0);

    let opt = coff + 20;
    let magic = r.u16_at(opt).ok_or(ParseError::Invalid("missing optional header"))?;
    let (is_64, dirs_off, num_dirs_off, base_off) = match magic {
        0x010b => (false, 96usize, 92usize, 28usize),
        0x020b => (true, 112usize, 108usize, 24usize),
        _ => return Err(ParseError::BadMagic("optional header magic")),
    };

    let entry_point_rva = r.u32_at(opt + 16).unwrap_or(0);
    let image_base = if is_64 {
        r.u64_at(opt + 24).unwrap_or(0)
    } else {
        r.u32_at(opt + 28).unwrap_or(0) as u64
    };
    let _ = base_off;
    let size_of_image = r.u32_at(opt + 56).unwrap_or(0);
    let size_of_headers = r.u32_at(opt + 60).unwrap_or(0);
    let checksum = r.u32_at(opt + 64).unwrap_or(0);
    let subsystem = r.u16_at(opt + 68).unwrap_or(0);
    let dll_characteristics = r.u16_at(opt + 70).unwrap_or(0);
    let num_dirs = r.u32_at(opt + num_dirs_off).unwrap_or(0).min(16) as usize;

    let mut dirs = [(0u32, 0u32); 16];
    for (i, slot) in dirs.iter_mut().take(num_dirs).enumerate() {
        let off = opt + dirs_off + i * 8;
        if let (Some(va), Some(sz)) = (r.u32_at(off), r.u32_at(off + 4)) {
            *slot = (va, sz);
        }
    }

    // --- section table -----------------------------------------------------
    let sec_off = opt
        .checked_add(size_of_optional)
        .ok_or(ParseError::Overflow("section table"))?;
    let mut sections = Vec::with_capacity(section_count.min(96));
    for i in 0..section_count.min(96) {
        let base = sec_off + i * 40;
        let name = r.fixed_name(base, 8).unwrap_or_default();
        let virtual_size = r.u32_at(base + 8).unwrap_or(0);
        let virtual_address = r.u32_at(base + 12).unwrap_or(0);
        let raw_size = r.u32_at(base + 16).unwrap_or(0);
        let raw_pointer = r.u32_at(base + 20).unwrap_or(0);
        let chars = r.u32_at(base + 36).unwrap_or(0);
        let start = raw_pointer as usize;
        let ent = if raw_size > 0 && start < data.len() {
            let end = (start + raw_size as usize).min(data.len());
            entropy(&data[start..end])
        } else {
            0.0
        };
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            raw_pointer,
            raw_size,
            characteristics: chars,
            entropy: ent,
        });
    }
    if sections.is_empty() && section_count > 0 {
        return Err(ParseError::Truncated {
            what: "section table",
            need: sec_off + 40,
            have: data.len(),
        });
    }

    let rva = |rva: u32| -> Option<usize> { rva_to_offset(&sections, size_of_headers, rva) };

    // --- imports -----------------------------------------------------------
    let mut imports = Vec::new();
    let mut delay_imports = Vec::new();
    let mut func_total = 0usize;
    if dirs[DIR_IMPORT].0 != 0 {
        let mut sink = ImportSink {
            dlls: &mut imports,
            func_total: &mut func_total,
        };
        parse_imports(
            &r,
            &sections,
            size_of_headers,
            dirs[DIR_IMPORT],
            is_64,
            image_base,
            &mut sink,
        )?;
    }
    if dirs[DIR_DELAY_IMPORT].0 != 0 {
        parse_delay_imports(&r, &rva, &sections, dirs[DIR_DELAY_IMPORT], image_base, &mut delay_imports);
    }

    // --- exports -----------------------------------------------------------
    let mut exports = Vec::new();
    if dirs[DIR_EXPORT].0 != 0 {
        parse_exports(&r, &rva, dirs[DIR_EXPORT], &mut exports);
    }

    // --- structural features ----------------------------------------------
    let overlay_start = sections
        .iter()
        .filter(|s| s.raw_size > 0)
        .map(|s| s.raw_pointer as u64 + s.raw_size as u64)
        .max()
        .unwrap_or(0);
    let file_len = data.len() as u64;
    let overlay_size = file_len.saturating_sub(overlay_start);
    let overlay_mz = overlay_size >= 2
        && overlay_start + 1 < file_len
        && data.get(overlay_start as usize) == Some(&b'M')
        && data.get(overlay_start as usize + 1) == Some(&b'Z');
    let overlay_entropy = if overlay_size > 64 && (overlay_start as usize) < data.len() {
        entropy(&data[overlay_start as usize..])
    } else {
        0.0
    };

    let entry_outside_sections = entry_point_rva != 0
        && !sections.iter().any(|s| {
            let end = s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size));
            entry_point_rva >= s.virtual_address && entry_point_rva < end
        });

    let rich_header_present = detect_rich_header(data);
    let pdb_path = parse_pdb_path(&r, &rva, dirs[DIR_DEBUG]);

    // --- resources ---------------------------------------------------------
    let mut version_info = VersionInfo::default();
    let mut manifest = ManifestInfo::default();
    if dirs[DIR_RESOURCE].0 != 0 {
        let mut res = Vec::new();
        walk_resources(&r, &rva, dirs[DIR_RESOURCE].0, &mut res);
        for (rtype, _rid, data_rva, size) in res {
            if rtype != 16 && rtype != 24 {
                continue;
            }
            let Some(off) = rva(data_rva) else { continue };
            let Some(blob) = r.slice(off, size.min(1 << 20) as usize) else {
                continue;
            };
            if rtype == 16 {
                version_info = parse_version_blob(blob);
            } else {
                manifest = parse_manifest(blob);
            }
        }
    }

    // --- signature ---------------------------------------------------------
    let signature = if dirs[DIR_SECURITY].0 != 0 && dirs[DIR_SECURITY].1 > 8 {
        crate::authenticode::parse_win_certificate(
            data,
            dirs[DIR_SECURITY].0,
            dirs[DIR_SECURITY].1,
        )
    } else {
        SignatureInfo::default()
    };

    let import_fingerprint = import_fingerprint(
        &imports
            .iter()
            .flat_map(|d| {
                d.functions
                    .iter()
                    .map(move |f| (d.name.clone(), f.clone()))
            })
            .collect::<Vec<_>>(),
    );

    let checksum_valid = checksum != 0 && pe_checksum(data, opt + 64) == checksum;

    let parsed_section_count = sections.len();
    let parsed_max_section_entropy = sections.iter().map(|s| s.entropy).fold(0.0, f64::max);
    Ok(PeInfo {
        machine,
        is_64,
        timestamp,
        timestamp_year: timestamp_to_year(timestamp),
        subsystem,
        dll_characteristics,
        characteristics,
        entry_point_rva,
        image_base,
        size_of_image,
        size_of_headers,
        checksum,
        checksum_valid,
        sections,
        imports,
        delay_imports,
        exports,
        import_fingerprint,
        import_function_count: func_total,
        overlay_size,
        overlay_mz,
        version_info,
        manifest,
        signature,
        has_relocations: dirs[DIR_BASERELOC].0 != 0 || dirs[DIR_BASERELOC].1 != 0,
        has_tls: dirs[DIR_TLS].0 != 0,
        has_load_config: dirs[DIR_LOAD_CONFIG].0 != 0,
        guard_cfg: dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0,
        aslr: dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
        dep: dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0,
        high_entropy_va: dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0,
        force_integrity: dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0,
        is_dotnet: dirs[DIR_CLR].0 != 0,
        is_dll: characteristics & 0x2000 != 0,
        is_driver: subsystem == 1,
        is_system: subsystem == 1 || subsystem == 2,
        rich_header_present,
        pdb_path,
        entry_outside_sections,
        section_count: parsed_section_count,
        max_section_entropy: parsed_max_section_entropy,
        overlay_entropy,
    })
}

/// Collects import results without growing the argument list of the parser.
struct ImportSink<'a> {
    dlls: &'a mut Vec<ImportedDll>,
    func_total: &'a mut usize,
}

fn parse_imports(
    r: &Reader<'_>,
    sections: &[Section],
    size_of_headers: u32,
    dir: (u32, u32),
    is_64: bool,
    image_base: u64,
    sink: &mut ImportSink<'_>,
) -> Result<(), ParseError> {
    let Some(mut desc_off) = rva_to_offset(sections, size_of_headers, dir.0) else {
        return Ok(());
    };
    for _ in 0..MAX_IMPORT_DLLS {
        let Some(desc) = r.slice(desc_off, 20) else { break };
        let oft = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
        let ft = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let Some(name_off) = rva_to_offset(sections, size_of_headers, name_rva) else {
            desc_off += 20;
            continue;
        };
        let name = r.cstr(name_off, 256).unwrap_or_default();
        if name.is_empty() {
            desc_off += 20;
            continue;
        }

        let thunk_rva = if oft != 0 { oft } else { ft };
        let mut functions = Vec::new();
        let mut ordinals = 0usize;
        if let Some(thunk_off) = rva_to_offset(sections, size_of_headers, thunk_rva) {
            let width = if is_64 { 8 } else { 4 };
            for i in 0..MAX_IMPORT_FUNCS {
                let off = thunk_off + i * width;
                let value = if is_64 {
                    match r.u64_at(off) {
                        Some(v) => v,
                        None => break,
                    }
                } else {
                    match r.u32_at(off) {
                        Some(v) => v as u64,
                        None => break,
                    }
                };
                if value == 0 {
                    break;
                }
                if is_64 && value & (1u64 << 63) != 0 {
                    ordinals += 1;
                    functions.push(format!("#{}", value & 0xffff));
                    continue;
                }
                if !is_64 && value & (1u64 << 31) != 0 {
                    ordinals += 1;
                    functions.push(format!("#{}", value & 0xffff));
                    continue;
                }
                // Hint/name RVA. Some malformed/VA-based binaries store VAs.
                let hint_rva = if value <= u32::MAX as u64 {
                    let v = value as u32;
                    if v < image_base as u32 && image_base > u32::MAX as u64 {
                        0
                    } else {
                        v
                    }
                } else {
                    0
                };
                let hint_rva = if hint_rva == 0 {
                    // Fallback: treat as VA and subtract image base.
                    match (value as u32).checked_sub(image_base as u32) {
                        Some(v) => v,
                        None => break,
                    }
                } else {
                    hint_rva
                };
                let Some(hint_off) = rva_to_offset(sections, size_of_headers, hint_rva) else {
                    break;
                };
                let Some(fname) = r.cstr(hint_off + 2, 512) else {
                    break;
                };
                if fname.is_empty() {
                    break;
                }
                functions.push(fname);
                if *sink.func_total + functions.len() >= MAX_IMPORT_FUNCS * 4 {
                    break;
                }
            }
        }
        *sink.func_total += functions.len();
        sink.dlls.push(ImportedDll {
            name,
            functions,
            ordinal_count: ordinals,
        });
        desc_off += 20;
        if *sink.func_total >= MAX_IMPORT_FUNCS * 4 {
            break;
        }
    }
    Ok(())
}

fn parse_delay_imports(
    r: &Reader<'_>,
    rva: &dyn Fn(u32) -> Option<usize>,
    sections: &[Section],
    dir: (u32, u32),
    image_base: u64,
    out: &mut Vec<String>,
) {
    let Some(mut off) = rva_to_offset(sections, 0, dir.0).or_else(|| rva(dir.0)) else {
        return;
    };
    for _ in 0..MAX_IMPORT_DLLS {
        let Some(d) = r.slice(off, 32) else { break };
        let attrs = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        let name_rva = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        if name_rva == 0 {
            break;
        }
        // Attributes bit 0 clear => fields are VAs, not RVAs.
        let name_rva = if attrs & 1 == 0 {
            (name_rva as u64).saturating_sub(image_base) as u32
        } else {
            name_rva
        };
        if let Some(no) = rva(name_rva) {
            if let Some(name) = r.cstr(no, 256) {
                if !name.is_empty() {
                    out.push(name);
                }
            }
        }
        off += 32;
    }
}

fn parse_exports(r: &Reader<'_>, rva: &dyn Fn(u32) -> Option<usize>, dir: (u32, u32), out: &mut Vec<String>) {
    let Some(off) = rva(dir.0) else { return };
    let Some(hdr) = r.slice(off, 40) else { return };
    let num_names = u32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]) as usize;
    let names_rva = u32::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35]]);
    let Some(names_off) = rva(names_rva) else { return };
    for i in 0..num_names.min(MAX_EXPORTS) {
        let Some(name_rva) = r.u32_at(names_off + i * 4) else { break };
        let Some(no) = rva(name_rva) else { break };
        if let Some(n) = r.cstr(no, 256) {
            if !n.is_empty() {
                out.push(n);
            }
        }
    }
}

fn parse_pdb_path(r: &Reader<'_>, rva: &dyn Fn(u32) -> Option<usize>, dir: (u32, u32)) -> Option<String> {
    if dir.0 == 0 {
        return None;
    }
    let off = rva(dir.0)?;
    let count = (dir.1 / 28).min(16);
    for i in 0..count {
        let base = off + i as usize * 28;
        let typ = r.u32_at(base + 12)?;
        let size = r.u32_at(base + 16)? as usize;
        let raw = r.u32_at(base + 24)? as usize;
        if typ == 2 && size > 24 {
            // CodeView RSDS: "RSDS" + GUID(16) + age(4) + NUL-term path.
            if r.u32_at(raw) == Some(0x5344_5352) {
                return r.cstr(raw + 24, 260);
            }
        }
    }
    None
}

fn detect_rich_header(data: &[u8]) -> bool {
    let end = data.len().min(4096);
    let hay = &data[..end];
    let mut i = 0usize;
    while i + 4 <= hay.len() {
        if &hay[i..i + 4] == b"Rich" {
            // The DanS marker must appear before the Rich block.
            return hay[..i].windows(4).any(|w| w == b"DanS");
        }
        i += 1;
    }
    false
}

/// PE image checksum as documented by Microsoft.
fn pe_checksum(data: &[u8], checksum_field: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        if i == checksum_field || i == checksum_field + 1 {
            i += 2;
            continue;
        }
        let w = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        sum += w;
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    if i < data.len() {
        sum += data[i] as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

/// Resource leaf: (type id, name id, data RVA, data size).
fn walk_resources(
    r: &Reader<'_>,
    rva: &dyn Fn(u32) -> Option<usize>,
    base_rva: u32,
    out: &mut Vec<(u32, u32, u32, u32)>,
) {
    let Some(base_off) = rva(base_rva) else { return };
    let mut budget = MAX_RESOURCE_NODES;
    let mut stack: Vec<(usize, u32, u32)> = vec![(base_off, 0, 0)]; // (dir offset, depth, parent id)
    while let Some((dir_off, depth, parent_id)) = stack.pop() {
        if depth >= RESOURCE_DEPTH {
            continue;
        }
        let Some(hdr) = r.slice(dir_off, 16) else { continue };
        let named = u16::from_le_bytes([hdr[12], hdr[13]]) as usize;
        let ids = u16::from_le_bytes([hdr[14], hdr[15]]) as usize;
        let count = named.saturating_add(ids).min(1024);
        for i in 0..count {
            if budget == 0 {
                return;
            }
            budget -= 1;
            let e = dir_off + 16 + i * 8;
            let Some(name_field) = r.u32_at(e) else { break };
            let Some(offset_field) = r.u32_at(e + 4) else { break };
            let id = if name_field & 0x8000_0000 != 0 {
                0 // named entry; we only key off numeric IDs
            } else {
                name_field & 0xFFFF
            };
            let this_id = if depth == 0 { id } else { parent_id };
            if offset_field & 0x8000_0000 != 0 {
                let sub = base_off + (offset_field & 0x7FFF_FFFF) as usize;
                if sub < r.len() {
                    stack.push((sub, depth + 1, this_id));
                }
            } else {
                let data_entry = base_off + offset_field as usize;
                let Some(de) = r.slice(data_entry, 16) else { continue };
                let data_rva = u32::from_le_bytes([de[0], de[1], de[2], de[3]]);
                let size = u32::from_le_bytes([de[4], de[5], de[6], de[7]]);
                out.push((this_id, id, data_rva, size));
                if out.len() > 512 {
                    return;
                }
            }
        }
    }
}

/// Best-effort VS_VERSIONINFO string extraction.
///
/// The structure is a nested, aligned block tree. Rather than reimplement every
/// alignment rule, we locate the well-known UTF-16 keys and read the value that
/// follows the next `String` node header. Unparseable blobs yield no strings,
/// never an error.
fn parse_version_blob(blob: &[u8]) -> VersionInfo {
    let mut vi = VersionInfo::default();
    if !contains_bytes(blob, b"V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0") {
        return vi;
    }
    vi.present = true;
    vi.company = find_utf16_value(blob, "CompanyName");
    vi.product = find_utf16_value(blob, "ProductName");
    vi.original_filename = find_utf16_value(blob, "OriginalFilename");
    vi.description = find_utf16_value(blob, "FileDescription");
    vi
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn find_utf16_value(blob: &[u8], key: &str) -> Option<String> {
    let mut needle = Vec::new();
    for u in key.encode_utf16() {
        needle.extend_from_slice(&u.to_le_bytes());
    }
    let pos = blob.windows(needle.len()).position(|w| w == needle.as_slice())?;
    // After the key: NUL terminator, alignment padding, then a WORD length and
    // the UTF-16 value. Scan forward for the first plausible wide string.
    let search_from = pos + needle.len();
    let end = (search_from + 512).min(blob.len());
    let mut i = search_from;
    while i + 2 <= end {
        let unit = u16::from_le_bytes([blob[i], blob[i + 1]]);
        if (2..0x400).contains(&unit) && i + 2 + unit as usize <= blob.len() {
            let cand = Reader::new(&blob[i + 2..]);
            let chars = (unit as usize) / 2;
            if let Some(s) = cand.utf16_at(0, chars) {
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty()
                    && trimmed.chars().all(|c| !c.is_control())
                    && trimmed.len() >= 2
                {
                    return Some(trimmed);
                }
            }
        }
        i += 2;
    }
    None
}

fn parse_manifest(blob: &[u8]) -> ManifestInfo {
    let mut m = ManifestInfo::default();
    if blob.len() < 16 {
        return m;
    }
    m.present = true;
    // Manifests are UTF-8 XML; tolerate a UTF-16 manifest too.
    let text = if blob[0] == 0xFF && blob[1] == 0xFE {
        let units: Vec<u16> = blob[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(blob).to_string()
    };
    let lower = text.to_ascii_lowercase();
    m.require_admin = lower.contains("requireadministrator");
    m.ui_access = lower.contains("uiaccess=\"true\"");
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert_eq!(parse(b"not a pe file at all").err(), Some(ParseError::NotThisFormat));
        assert_eq!(parse(&[]).err(), Some(ParseError::NotThisFormat));
    }

    #[test]
    fn rejects_truncated_mz() {
        let mut d = vec![0u8; 0x40];
        d[0] = b'M';
        d[1] = b'Z';
        // e_lfanew points far past the buffer
        d[0x3C..0x40].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert!(matches!(parse(&d), Err(ParseError::BadMagic(_))));
    }

    #[test]
    fn rva_mapping_respects_sections() {
        let secs = vec![Section {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_pointer: 0x400,
            raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_EXECUTE,
            entropy: 0.0,
        }];
        assert_eq!(rva_to_offset(&secs, 0x400, 0x1000), Some(0x400));
        assert_eq!(rva_to_offset(&secs, 0x400, 0x1100), Some(0x500));
        assert_eq!(rva_to_offset(&secs, 0x400, 0x2000), None);
        assert_eq!(rva_to_offset(&secs, 0x400, 0x100), Some(0x100));
    }

    #[test]
    fn checksum_of_zero_buffer_matches_formula() {
        // A buffer of 0x100 zero bytes has a well-defined checksum: 0x100.
        let data = vec![0u8; 0x100];
        assert_eq!(pe_checksum(&data, 0), 0x100);
    }
}
