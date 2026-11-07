//! Deterministic parser fuzz/soak tests.
//!
//! Scope: the four parsers that consume untrusted containers or executables
//! directly — PE (`pe::parse`), ZIP-family (`archive::inspect_zip`), VBA
//! (`vba::extract`) and Excel 4.0 macros (`xlm::extract`).
//!
//! These are **mutation campaigns**, not coverage-guided fuzzing. Inputs are
//! derived from valid synthetic fixtures with a fixed PRNG seed, so a failure
//! reproduces exactly. Every campaign asserts the parser's advertised resource
//! caps, catches panics, and samples the test process's private/working set to
//! detect runaway growth across soak batches.
//!
//! The only `unsafe` here is a read-only `GetProcessMemoryInfo` probe, confined
//! to `sample_memory`. No parser or production code is modified by the probe.
//!
//! Run with output:
//! `cargo test -p litric-core --test parser_fuzz_soak -- --nocapture --test-threads=1`

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant};

use litric_core::archive::{inspect_zip, ArchiveLimits, MemberReport};
use litric_core::engine::Verdict;
use litric_core::pe;
use litric_core::vba::{self, VbaLimits};
use litric_core::xlm::{self, XlmLimits};

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        // SplitMix64: fixed, dependency-free, reproducible across runs.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn mutate(seed: &[u8], rng: &mut Rng, preserve_prefix: usize) -> Vec<u8> {
    let mut data = seed.to_vec();
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        if data.is_empty() {
            break;
        }
        match rng.below(12) {
            0..=4 => {
                let at = rng.below(data.len());
                data[at] ^= 1u8 << rng.below(8);
            }
            5..=6 => {
                if data.len() >= 4 {
                    let at = rng.below(data.len() - 3);
                    let value = rng.next() as u32;
                    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            7 => {
                if data.len() >= 2 {
                    let at = rng.below(data.len() - 1);
                    let values = [0u16, 1, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE];
                    let value = values[rng.below(values.len())];
                    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
                }
            }
            8 => {
                if data.len() > preserve_prefix + 16 {
                    let span = data.len() - preserve_prefix - 8;
                    let cut = preserve_prefix + 1 + rng.below(span);
                    data.truncate(cut);
                }
            }
            9 => {
                // Duplicate a small chunk (tests offset/overlap handling).
                let start = rng.below(data.len());
                let len = 1 + rng.below((data.len() - start).min(48));
                let chunk = data[start..start + len].to_vec();
                let at = rng.below(data.len());
                data.splice(at..at, chunk);
            }
            10 => {
                // Delete a small chunk.
                if data.len() > preserve_prefix + 16 {
                    let start = preserve_prefix + rng.below(data.len() - preserve_prefix);
                    let len = 1 + rng.below((data.len() - start).min(32));
                    data.drain(start..start + len);
                }
            }
            _ => {
                // Increment/decrement a 32-bit field, the classic fuzzer trick
                // for length and offset fields.
                if data.len() >= 4 {
                    let at = rng.below(data.len() - 3);
                    let old = u32::from_le_bytes([
                        data[at],
                        data[at + 1],
                        data[at + 2],
                        data[at + 3],
                    ]);
                    let new = if rng.below(2) == 0 {
                        old.wrapping_add(1 + rng.below(16) as u32)
                    } else {
                        old.wrapping_sub(1 + rng.below(16) as u32)
                    };
                    data[at..at + 4].copy_from_slice(&new.to_le_bytes());
                }
            }
        }
    }
    if data.len() > 256 * 1024 {
        data.truncate(256 * 1024);
    }
    data
}

// ---------------------------------------------------------------------------
// Process memory probe (test-only)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Mem {
    private: usize,
    working: usize,
    /// OS-tracked lifetime peak private bytes (not resettable).
    lifetime_peak_private: usize,
}

#[cfg(windows)]
fn sample_memory() -> Option<Mem> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // Read-only query; the handle is the pseudo-handle for this process.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    if ok == 0 {
        None
    } else {
        Some(Mem {
            private: counters.PagefileUsage,
            working: counters.WorkingSetSize,
            lifetime_peak_private: counters.PeakPagefileUsage,
        })
    }
}

// ---------------------------------------------------------------------------
// Campaign driver
// ---------------------------------------------------------------------------

struct Campaign {
    iterations: usize,
    ok: usize,
    panics: Vec<String>,
    max_input: Duration,
    baseline: Option<Mem>,
    peak: Option<Mem>,
    batch_private: Vec<usize>,
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn run_campaign<M, P>(
    name: &str,
    iterations: usize,
    batches: usize,
    seed: u64,
    mut make: M,
    mut probe: P,
) -> Campaign
where
    M: FnMut(&mut Rng) -> Vec<u8>,
    P: FnMut(&[u8]) -> bool,
{
    assert!(iterations > 0 && batches > 0);
    let per_batch = iterations.div_ceil(batches);
    let mut rng = Rng::new(seed);
    let baseline = sample_memory();
    let mut peak = baseline;
    let mut batch_private = Vec::new();
    let mut ok = 0usize;
    let mut error = 0usize;
    let mut panics = Vec::new();
    let mut max_input = Duration::ZERO;
    let started = Instant::now();

    for _ in 0..batches {
        for iteration in 0..per_batch {
            let data = make(&mut rng);
            let input_started = Instant::now();
            let result = catch_unwind(AssertUnwindSafe(|| probe(&data)));
            let elapsed = input_started.elapsed();
            if elapsed > max_input {
                max_input = elapsed;
            }
            match result {
                Ok(true) => ok += 1,
                Ok(false) => error += 1,
                Err(payload) => panics.push(panic_text(payload)),
            }
            // Sampling between inputs catches retained growth; it is not an
            // instantaneous allocation peak (documented in the report).
            if iteration % 64 == 0 {
                if let (Some(mem), Some(current)) = (sample_memory(), peak.as_mut()) {
                    current.private = current.private.max(mem.private);
                    current.working = current.working.max(mem.working);
                    current.lifetime_peak_private =
                        current.lifetime_peak_private.max(mem.lifetime_peak_private);
                }
            }
        }
        if let Some(mem) = sample_memory() {
            batch_private.push(mem.private);
            if let Some(current) = peak.as_mut() {
                current.private = current.private.max(mem.private);
                current.working = current.working.max(mem.working);
                current.lifetime_peak_private =
                    current.lifetime_peak_private.max(mem.lifetime_peak_private);
            }
        }
    }

    let elapsed = started.elapsed();
    let peak_delta = match (baseline, peak) {
        (Some(base), Some(peak)) => Some(peak.private.saturating_sub(base.private)),
        _ => None,
    };
    println!(
        "PARSER_SOAK parser={name} iterations={iterations} batches={batches} ok={ok} \
         error={error} panics={} elapsed_ms={} max_input_us={} peak_private_kib={} \
         peak_delta_kib={} lifetime_peak_private_kib={} batch_private_kib={:?}",
        panics.len(),
        elapsed.as_millis(),
        max_input.as_micros(),
        peak.map(|m| m.private / 1024).unwrap_or(0),
        peak_delta.map(|d| d / 1024).unwrap_or(0),
        peak.map(|m| m.lifetime_peak_private / 1024).unwrap_or(0),
        batch_private
            .iter()
            .map(|bytes| bytes / 1024)
            .collect::<Vec<_>>(),
    );

    Campaign {
        iterations,
        ok,
        panics,
        max_input,
        baseline,
        peak,
        batch_private,
    }
}

fn assert_campaign_sane(name: &str, campaign: &Campaign) {
    assert!(
        campaign.panics.is_empty(),
        "{name}: {} panic(s) in {} iterations: {:?}",
        campaign.panics.len(),
        campaign.iterations,
        campaign.panics
    );
    // A campaign that never reaches a successful parse only exercises early
    // rejection and would give false confidence about deep parser paths.
    assert!(
        campaign.ok > 0,
        "{name}: no input parsed successfully in {} iterations ({:?})",
        campaign.iterations,
        campaign.panics
    );
    // No single bounded input should stall the parser.
    assert!(
        campaign.max_input < Duration::from_secs(5),
        "{name}: one input took {:?}",
        campaign.max_input
    );

    if let (Some(base), Some(peak)) = (campaign.baseline, campaign.peak) {
        let delta = peak.private.saturating_sub(base.private);
        assert!(
            delta < 96 * 1024 * 1024,
            "{name}: private bytes grew by {delta} (baseline {}, peak {})",
            base.private,
            peak.private
        );
        if campaign.batch_private.len() >= 2 {
            let first = campaign.batch_private[0];
            let last = *campaign.batch_private.last().unwrap();
            assert!(
                last <= first + 32 * 1024 * 1024,
                "{name}: batch memory kept growing: {first} -> {last} bytes; all={:?}",
                campaign.batch_private
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const FREE_SECTOR: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const FAT_SECTOR: u32 = 0xFFFF_FFFD;

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

/// CFB with `Root Entry` -> `VBA` storage -> one module stream. Mirrors the
/// in-crate VBA fixture; kept here so the integration test exercises the
/// released library, not `cfg(test)` helpers.
fn cfb_project_fixture(modules: &[(&str, &[u8])]) -> Vec<u8> {
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
    put_u32(&mut out, 0x28, 0);
    put_u32(&mut out, 0x2C, 1);
    put_u32(&mut out, 0x30, dir_start as u32);
    put_u32(&mut out, 0x34, 0);
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
    out.resize(SECTOR * 2, 0);
    out.resize(out.len() + 512 * dir_sectors, 0);
    let dir_offset = SECTOR + 512;
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

/// CFB with one top-level stream (used for a legacy `Workbook` stream).
fn cfb_stream_fixture(name: &str, data: &[u8]) -> Vec<u8> {
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

/// Literal-only MS-OVBA chunks (compressed flag set).
fn ovba_literal(data: &[u8]) -> Vec<u8> {
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

fn zip_package(files: &[(&str, &[u8])]) -> Vec<u8> {
    zip_package_with(files, zip::CompressionMethod::Stored)
}

fn zip_package_with(files: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(method);
    for (name, data) in files {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn vba_project_fixture() -> Vec<u8> {
    let code = ovba_literal(
        b"Sub AutoOpen()\r\nShell \"calc.exe\", vbHide\r\nEnd Sub\r\n\
          Sub Document_Open()\r\nCreateObject(\"WScript.Shell\").Run \"calc.exe\"\r\nEnd Sub\r\n",
    );
    cfb_project_fixture(&[("Module1", &code)])
}

fn docm_fixture() -> Vec<u8> {
    let project = vba_project_fixture();
    zip_package(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
        ("word/vbaProject.bin", &project),
    ])
}

fn xlsm_fixture(xml: &[u8]) -> Vec<u8> {
    zip_package(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("xl/workbook.xml", b"<workbook/>"),
        ("xl/macrosheets/sheet1.xml", xml),
    ])
}

fn biff_formula_record(rgce: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_le_bytes()); // row
    body.extend_from_slice(&0u16.to_le_bytes()); // col
    body.extend_from_slice(&0u16.to_le_bytes()); // xf
    body.extend_from_slice(&0f64.to_le_bytes()); // result
    body.extend_from_slice(&0u16.to_le_bytes()); // flags
    body.extend_from_slice(&0u32.to_le_bytes()); // cache
    body.extend_from_slice(&(rgce.len() as u16).to_le_bytes()); // cce
    body.extend_from_slice(rgce);
    let mut record = Vec::new();
    record.extend_from_slice(&0x0006u16.to_le_bytes());
    record.extend_from_slice(&(body.len() as u16).to_le_bytes());
    record.extend_from_slice(&body);
    record
}

fn biff_workbook_fixture(name: &str, hidden: bool, formula: &[u8]) -> Vec<u8> {
    let version = 0x0600u16;
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut boundsheet_body = Vec::new();
    boundsheet_body.extend_from_slice(&0u32.to_le_bytes()); // lbPlyPos, patched below
    boundsheet_body.push(if hidden { 2 } else { 0 });
    boundsheet_body.push(1); // macro sheet
    boundsheet_body.push(units.len() as u8);
    boundsheet_body.push(1); // UTF-16LE
    for unit in &units {
        boundsheet_body.extend_from_slice(&unit.to_le_bytes());
    }

    let mut globals = Vec::new();
    globals.extend_from_slice(&0x0809u16.to_le_bytes());
    globals.extend_from_slice(&16u16.to_le_bytes());
    globals.extend_from_slice(&version.to_le_bytes());
    globals.extend_from_slice(&0x0005u16.to_le_bytes()); // workbook globals
    globals.extend_from_slice(&[0u8; 12]);
    globals.extend_from_slice(&0x0085u16.to_le_bytes());
    globals.extend_from_slice(&(boundsheet_body.len() as u16).to_le_bytes());
    globals.extend_from_slice(&boundsheet_body);
    globals.extend_from_slice(&0x000Au16.to_le_bytes());
    globals.extend_from_slice(&0u16.to_le_bytes());

    let mut sheet = Vec::new();
    sheet.extend_from_slice(&0x0809u16.to_le_bytes());
    sheet.extend_from_slice(&16u16.to_le_bytes());
    sheet.extend_from_slice(&version.to_le_bytes());
    sheet.extend_from_slice(&0x0040u16.to_le_bytes()); // macro sheet
    sheet.extend_from_slice(&[0u8; 12]);
    sheet.extend_from_slice(formula);
    sheet.extend_from_slice(&0x000Au16.to_le_bytes());
    sheet.extend_from_slice(&0u16.to_le_bytes());

    let sheet_offset = globals.len() as u32;
    // BOUNDSHEET header is bytes 20..24; its body (lbPlyPos) starts at 24.
    globals[24..28].copy_from_slice(&sheet_offset.to_le_bytes());
    globals.extend_from_slice(&sheet);
    globals
}

/// Minimal PE32+ with one imported DLL/function and a section table.
fn pe_fixture() -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    d[0] = b'M';
    d[1] = b'Z';
    d[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    d[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84usize;
    d[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    d[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    d[coff + 4..coff + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes());
    d[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    d[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    let opt = coff + 20;
    d[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    d[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    d[opt + 70..opt + 72].copy_from_slice(&0x0140u16.to_le_bytes());
    d[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    let dd = opt + 112 + 8;
    d[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    d[dd + 4..dd + 8].copy_from_slice(&40u32.to_le_bytes());

    let sh = opt + 240;
    d[sh..sh + 8].copy_from_slice(b".rdata\0\0");
    d[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes());
    d[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
    d[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
    d[sh + 36..sh + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    d[0x200..0x204].copy_from_slice(&0x1030u32.to_le_bytes());
    d[0x20C..0x210].copy_from_slice(&0x1080u32.to_le_bytes());
    d[0x210..0x214].copy_from_slice(&0x1040u32.to_le_bytes());
    d[0x230..0x238].copy_from_slice(&0x1090u64.to_le_bytes());
    d[0x280..0x28D].copy_from_slice(b"KERNEL32.dll\0");
    d[0x292..0x29E].copy_from_slice(b"CreateFileW\0");
    d
}

// ---------------------------------------------------------------------------
// Parser-specific invariants
// ---------------------------------------------------------------------------

fn check_pe(data: &[u8]) -> bool {
    match pe::parse(data) {
        Ok(info) => {
            assert!(info.sections.len() <= 96, "section cap exceeded");
            assert!(info.imports.len() <= 512, "import DLL cap exceeded");
            assert!(
                info.import_function_count <= 80_000,
                "import function cap exceeded"
            );
            assert!(info.exports.len() <= 4_096, "export cap exceeded");
            assert_eq!(info.section_count, info.sections.len());
            true
        }
        Err(_) => false,
    }
}

fn archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_entries: 32,
        max_member_bytes: 16 * 1024,
        max_total_bytes: 64 * 1024,
        max_depth: 2,
        max_ratio: 50,
    }
}

fn check_archive(data: &[u8]) -> bool {
    let limits = archive_limits();
    let mut handed = 0usize;
    let scan = inspect_zip(data, 0, &limits, |name, bytes, depth| {
        assert!(depth <= limits.max_depth, "member depth exceeds cap");
        let normalized = name.replace('\\', "/");
        assert!(
            !normalized.starts_with('/')
                && !normalized.contains('\0')
                && !normalized.split('/').any(|part| part == "..")
                && !(normalized.as_bytes().len() >= 2 && normalized.as_bytes()[1] == b':'),
            "unsafe member name reached the callback: {name:?}"
        );
        handed += bytes.len();
        MemberReport {
            name: name.to_string(),
            verdict: Verdict::Unknown,
            score: 0,
            threat_name: None,
            family: None,
        }
    });
    assert!(
        handed <= limits.max_total_bytes as usize,
        "callback received {handed} bytes, above the {} byte total cap",
        limits.max_total_bytes
    );
    assert!(
        scan.scanned <= limits.max_entries,
        "scanned {} entries, above cap {}",
        scan.scanned,
        limits.max_entries
    );
    scan.scanned > 0
}

fn vba_limits() -> VbaLimits {
    VbaLimits {
        max_project_bytes: 256 * 1024,
        max_streams: 8,
        max_stream_bytes: 64 * 1024,
        max_module_bytes: 64 * 1024,
        max_total_bytes: 128 * 1024,
    }
}

fn check_vba(data: &[u8]) -> bool {
    let limits = vba_limits();
    let project = vba::extract(data, &limits);
    assert!(
        project.modules.len() <= limits.max_streams,
        "module cap exceeded"
    );
    let mut total = 0usize;
    for module in &project.modules {
        assert!(
            module.code.len() <= limits.max_module_bytes,
            "module cap exceeded for {}",
            module.name
        );
        total += module.code.len();
    }
    assert!(total <= limits.max_total_bytes, "total source cap exceeded");
    project.modules.iter().any(|m| !m.code.is_empty())
}

fn xlm_limits() -> XlmLimits {
    XlmLimits {
        max_sheets: 8,
        max_formulas: 64,
        max_formula_bytes: 4 * 1024,
        max_sheet_bytes: 64 * 1024,
        max_total_bytes: 128 * 1024,
    }
}

fn check_xlm(data: &[u8]) -> bool {
    let limits = xlm_limits();
    let report = xlm::extract(data, &limits);
    assert!(
        report.sheets.len() <= limits.max_sheets,
        "sheet cap exceeded"
    );
    let mut formulas = 0usize;
    for sheet in &report.sheets {
        for formula in &sheet.formulas {
            assert!(
                formula.chars().count() <= limits.max_formula_bytes,
                "formula cap exceeded"
            );
            formulas += 1;
        }
    }
    // The OOXML path caps formulas per sheet, so the global bound is
    // sheets * per-sheet; assert the real bound instead of inventing one.
    assert!(
        formulas <= limits.max_sheets * limits.max_formulas,
        "formula count {formulas} exceeds bounded maximum"
    );
    !report.sheets.is_empty()
}

// ---------------------------------------------------------------------------
// Fuzz/soak campaigns
// ---------------------------------------------------------------------------

#[test]
fn pe_mutations_are_total_and_bounded() {
    let seed = pe_fixture();
    let campaign = run_campaign(
        "pe",
        20_000,
        4,
        0x5045_0001,
        |rng| mutate(&seed, rng, 2),
        |data| check_pe(data),
    );
    assert_campaign_sane("pe", &campaign);
}

#[test]
fn zip_mutations_respect_limits() {
    let seed = zip_package(&[
        ("doc.xml", b"<document>ordinary content</document>"),
        ("bin/payload.dat", b"not executable, just bytes"),
        ("empty.txt", b""),
    ]);
    let campaign = run_campaign(
        "zip",
        8_000,
        4,
        0x5A49_5001,
        |rng| mutate(&seed, rng, 0),
        |data| check_archive(data),
    );
    assert_campaign_sane("zip", &campaign);
}

#[test]
fn vba_mutations_are_bounded() {
    let project = vba_project_fixture();
    let direct = run_campaign(
        "vba-cfb",
        6_000,
        4,
        0x5642_4101,
        |rng| mutate(&project, rng, 8),
        |data| check_vba(data),
    );
    assert_campaign_sane("vba-cfb", &direct);

    // Rebuild the OOXML wrapper around a mutated `vbaProject.bin`. Mutating the
    // finished ZIP mostly exercises ZIP rejection; rebuilding reaches the
    // project parser through the OOXML path on every iteration.
    let ooxml_project = vba_project_fixture();
    let ooxml = run_campaign(
        "vba-ooxml",
        3_000,
        4,
        0x5642_4102,
        |rng| {
            let mutated = mutate(&ooxml_project, rng, 8);
            zip_package(&[
                ("[Content_Types].xml", b"<Types/>"),
                ("word/document.xml", b"<w:document/>"),
                ("word/vbaProject.bin", &mutated),
            ])
        },
        |data| check_vba(data),
    );
    assert_campaign_sane("vba-ooxml", &ooxml);
}

#[test]
fn xlm_mutations_are_bounded() {
    let mut rgce = Vec::new();
    rgce.push(0x17); // ptgStr
    rgce.push(8);
    rgce.push(0x01); // UTF-16LE
    for unit in "calc.exe".encode_utf16() {
        rgce.extend_from_slice(&unit.to_le_bytes());
    }
    rgce.extend_from_slice(&[0x22, 0x01, 0x6E, 0x80]); // EXEC, 1 arg, macro call
    let workbook = biff_workbook_fixture("Macro1", true, &biff_formula_record(&rgce));
    let seed = cfb_stream_fixture("Workbook", &workbook);
    let biff = run_campaign(
        "xlm-biff",
        5_000,
        4,
        0x584C_4D01,
        |rng| mutate(&seed, rng, 8),
        |data| check_xlm(data),
    );
    assert_campaign_sane("xlm-biff", &biff);

    let xml =
        br#"<xm:worksheet><xm:f>EXEC("calc.exe")</xm:f><xm:f>URLDownloadToFileA()</xm:f></xm:worksheet>"#;
    let ooxml = run_campaign(
        "xlm-ooxml",
        3_000,
        4,
        0x584C_4D02,
        |rng| {
            let mutated = mutate(xml, rng, 0);
            xlsm_fixture(&mutated)
        },
        |data| check_xlm(data),
    );
    assert_campaign_sane("xlm-ooxml", &ooxml);
}

// ---------------------------------------------------------------------------
// Crafted security cases
// ---------------------------------------------------------------------------

#[test]
fn archive_refuses_bombs_and_unsafe_names() {
    // 1 MiB of zeros deflates to about 1 KiB; the declared size is within the
    // member cap but the expansion ratio is far above `max_ratio`, so it must
    // never be expanded.
    let bomb = zip_package_with(
        &[("bomb.bin", &vec![0u8; 1024 * 1024])],
        zip::CompressionMethod::Deflated,
    );
    let limits = ArchiveLimits {
        max_entries: 8,
        max_member_bytes: 2 * 1024 * 1024,
        max_total_bytes: 2 * 1024 * 1024,
        max_depth: 2,
        max_ratio: 100,
    };
    let mut handed = 0usize;
    let scan = inspect_zip(&bomb, 0, &limits, |_, bytes, _| {
        handed += bytes.len();
        MemberReport {
            name: "member".into(),
            verdict: Verdict::Unknown,
            score: 0,
            threat_name: None,
            family: None,
        }
    });
    assert_eq!(handed, 0, "bomb bytes were handed to analysis");
    assert!(scan.skipped >= 1 || scan.truncated);
    assert!(
        scan.notes
            .iter()
            .any(|n| n.contains("ratio") || n.contains("cap")),
        "no accounting note for the skipped bomb: {:?}",
        scan.notes
    );
    assert!(
        scan.notes.iter().any(|n| n.contains("compression ratio")),
        "bomb was not rejected by the ratio limit: {:?}",
        scan.notes
    );

    let traversal = zip_package(&[
        ("../escape.exe", b"MZ"),
        ("..\\escape.exe", b"MZ"),
        ("C:/escape.exe", b"MZ"),
        ("/absolute.exe", b"MZ"),
        ("safe.txt", b"ordinary"),
    ]);
    let mut names = Vec::new();
    let scan = inspect_zip(&traversal, 0, &ArchiveLimits::default(), |name, _, _| {
        names.push(name.to_string());
        MemberReport {
            name: name.to_string(),
            verdict: Verdict::Unknown,
            score: 0,
            threat_name: None,
            family: None,
        }
    });
    assert_eq!(names, vec!["safe.txt"]);    assert_eq!(
        scan.notes
            .iter()
            .filter(|n| n.contains("unsafe name"))
            .count(),
        4,
        "notes: {:?}",
        scan.notes
    );

    // More central-directory entries than the cap: only max_entries are
    // considered and the result is marked truncated.
    let names: Vec<String> = (0..40).map(|i| format!("file{i}.txt")).collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), b"small".as_slice()))
        .collect();
    let many = zip_package(&files);
    let count_limit = ArchiveLimits {
        max_entries: 32,
        ..ArchiveLimits::default()
    };
    let mut scanned = 0usize;
    let scan = inspect_zip(&many, 0, &count_limit, |_, _, _| {
        scanned += 1;
        MemberReport {
            name: "member".into(),
            verdict: Verdict::Unknown,
            score: 0,
            threat_name: None,
            family: None,
        }
    });
    assert_eq!(scan.entries, 40);
    assert_eq!(scanned, 32);
    assert!(scan.truncated);

    // Aggregate bytes across members are capped even when every individual
    // member is below the per-member limit.
    let chunks: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 8 * 1024]).collect();
    let files: Vec<(String, &[u8])> = chunks
        .iter()
        .enumerate()
        .map(|(i, data)| (format!("chunk{i}.bin"), data.as_slice()))
        .collect();
    let file_refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(name, data)| (name.as_str(), *data))
        .collect();
    let total_bomb = zip_package(&file_refs);
    let total_limit = ArchiveLimits {
        max_total_bytes: 20 * 1024,
        ..ArchiveLimits::default()
    };
    let mut handed = 0usize;
    let scan = inspect_zip(&total_bomb, 0, &total_limit, |_, bytes, _| {
        handed += bytes.len();
        MemberReport {
            name: "member".into(),
            verdict: Verdict::Unknown,
            score: 0,
            threat_name: None,
            family: None,
        }
    });
    assert!(handed <= 20 * 1024, "handed {handed} bytes");
    assert!(scan.truncated);
}

#[test]
fn corrupt_containers_are_reported_not_clean() {
    let limits = vba_limits();
    let project = vba_project_fixture();
    for cut in [8usize, 64, project.len() / 2, project.len() - 8] {
        let report = vba::extract(&project[..cut], &limits);
        assert!(
            !report.notes.is_empty() || report.truncated,
            "truncated VBA project at {cut} was not reported: {report:?}"
        );
    }

    let docm = docm_fixture();
    for cut in [4usize, 64, docm.len() / 2, docm.len() - 8] {
        let report = vba::extract(&docm[..cut], &limits);
        assert!(
            !report.notes.is_empty() || report.truncated,
            "truncated OOXML package at {cut} was not reported: {report:?}"
        );
    }

    let xml_limits = xlm_limits();
    let xml = br#"<xm:f>EXEC("calc.exe")</xm:f>"#;
    let xlsm = xlsm_fixture(xml);
    for cut in [4usize, 64, xlsm.len() / 2, xlsm.len() - 8] {
        let report = xlm::extract(&xlsm[..cut], &xml_limits);
        assert!(
            !report.notes.is_empty() || report.truncated,
            "truncated XLM package at {cut} was not reported: {report:?}"
        );
    }

    let workbook = biff_workbook_fixture("Macro1", false, &[]);
    let cfb = cfb_stream_fixture("Workbook", &workbook);
    for cut in [8usize, 64, cfb.len() / 2, cfb.len() - 8] {
        let report = xlm::extract(&cfb[..cut], &xml_limits);
        assert!(
            !report.notes.is_empty() || report.truncated,
            "truncated BIFF workbook at {cut} was not reported: {report:?}"
        );
    }
}

#[test]
fn targeted_header_values_do_not_panic() {
    // PE fields an attacker controls: e_lfanew, section count, optional-header
    // size, optional magic, directory count, import directory, section extents.
    let pe_seed = pe_fixture();
    let pe_fields: &[(usize, u32)] = &[
        (0x3C, 0),
        (0x3C, 0xFFFF_FFFF),
        (0x86, 0xFFFF),
        (0x94, 0),
        (0x94, 0xFFFF),
        (0x98, 0),
        (0x98, 0xFFFF),
        (0x104, 0xFFFF_FFFF),
        (0x110, 0xFFFF_FFFF),
        (0x114, 0xFFFF_FFFF),
        (0x198, 0xFFFF_FFFF),
        (0x19C, 0xFFFF_FFFF),
        (0x188, 0xFFFF_FFFF),
    ];
    for (offset, value) in pe_fields {
        let mut data = pe_seed.clone();
        data[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
        let _ = check_pe(&data);
    }

    // CFB header fields: sector shifts, FAT/dir/mini-FAT placement and counts.
    let project = vba_project_fixture();
    let cfb_fields: &[(usize, u32)] = &[
        (0x1A, 0xFFFF),
        (0x1E, 0),
        (0x1E, 0xFFFF),
        (0x20, 0),
        (0x20, 0xFFFF),
        (0x2C, 0xFFFF_FFFF),
        (0x30, 0xFFFF_FFFF),
        (0x38, 0),
        (0x38, 0xFFFF_FFFF),
        (0x3C, 0xFFFF_FFFF),
        (0x40, 0xFFFF_FFFF),
        (0x44, 0xFFFF_FFFF),
        (0x48, 0xFFFF_FFFF),
        // Module directory entry: start sector and size.
        (0x400 + 2 * 128 + 0x74, 0xFFFF_FFFF),
        (0x400 + 2 * 128 + 0x78, 0xFFFF_FFFF),
        // VBA storage child/right links.
        (0x400 + 128 + 0x48, 0xFFFF_FFFF),
        (0x400 + 128 + 0x4C, 0xFFFF_FFFF),
    ];
    for (offset, value) in cfb_fields {
        let mut data = project.clone();
        if *offset + 4 <= data.len() {
            data[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
            let _ = check_vba(&data);
        }
    }

    // BIFF BOUNDSHEET offset and FORMULA length fields.
    let workbook = biff_workbook_fixture("Macro1", true, &biff_formula_record(&[0x1E, 0, 1]));
    let cfb = cfb_stream_fixture("Workbook", &workbook);
    for (offset, value) in [(24usize, 0u32), (24, 0xFFFF_FFFF), (24, 0x7FFF_FFFF)] {
        let mut data = cfb.clone();
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let _ = check_xlm(&data);
    }
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

fn fingerprint(vba_project: &vba::VbaProject, report: &xlm::XlmReport, pe: &pe::PeInfo) -> u64 {
    let mut hasher = DefaultHasher::new();
    pe.machine.hash(&mut hasher);
    pe.section_count.hash(&mut hasher);
    pe.imports.len().hash(&mut hasher);
    pe.import_function_count.hash(&mut hasher);
    pe.exports.len().hash(&mut hasher);
    pe.overlay_size.hash(&mut hasher);
    for module in &vba_project.modules {
        module.name.hash(&mut hasher);
        module.code.len().hash(&mut hasher);
        module.code.hash(&mut hasher);
    }
    vba_project.truncated.hash(&mut hasher);
    for sheet in &report.sheets {
        sheet.name.hash(&mut hasher);
        sheet.hidden.hash(&mut hasher);
        for formula in &sheet.formulas {
            formula.hash(&mut hasher);
        }
    }
    report.truncated.hash(&mut hasher);
    hasher.finish()
}

fn fingerprint_all(data: &[u8]) -> u64 {
    // Use a real PE only for the PE branch; non-PE input is tagged separately.
    let pe_info = pe::parse(data);
    let vba_project = vba::extract(data, &vba_limits());
    let xlm_report = xlm::extract(data, &xlm_limits());
    match pe_info {
        Ok(info) => fingerprint(&vba_project, &xlm_report, &info),
        Err(_) => {
            let mut hasher = DefaultHasher::new();
            for module in &vba_project.modules {
                module.name.hash(&mut hasher);
                module.code.hash(&mut hasher);
            }
            vba_project.truncated.hash(&mut hasher);
            for sheet in &xlm_report.sheets {
                sheet.name.hash(&mut hasher);
                for formula in &sheet.formulas {
                    formula.hash(&mut hasher);
                }
            }
            xlm_report.truncated.hash(&mut hasher);
            hasher.finish()
        }
    }
}

#[test]
fn concurrent_parsing_is_deterministic() {
    // A mixed corpus: PE, docm, xlsm, BIFF workbook and malformed variants.
    let pe_seed = pe_fixture();
    let docm = docm_fixture();
    let xlsm = xlsm_fixture(
        br#"<xm:worksheet><xm:f>EXEC("calc.exe")</xm:f></xm:worksheet>"#,
    );
    let biff = cfb_stream_fixture(
        "Workbook",
        &biff_workbook_fixture("Macro1", false, &biff_formula_record(&[0x1E, 0, 1])),
    );
    let seeds = [pe_seed, docm, xlsm, biff];
    let mut rng = Rng::new(0x434F_4E43_5552);
    let cases: Arc<Vec<Vec<u8>>> = Arc::new(
        (0..64)
            .map(|i| {
                let seed = &seeds[i % seeds.len()];
                mutate(seed, &mut rng, 0)
            })
            .collect(),
    );
    let expected: Arc<Vec<u64>> = Arc::new(cases.iter().map(|c| fingerprint_all(c)).collect());

    let started = Instant::now();
    let mut handles = Vec::new();
    for thread in 0..8 {
        let cases = Arc::clone(&cases);
        let expected = Arc::clone(&expected);
        handles.push(std::thread::spawn(move || {
            let mut mismatch = None;
            for pass in 0..8usize {
                for i in 0..cases.len() {
                    // Every thread visits cases in a different rotation.
                    let index = (i + thread + pass) % cases.len();
                    let got = fingerprint_all(&cases[index]);
                    if got != expected[index] {
                        mismatch = Some((index, expected[index], got));
                        break;
                    }
                }
                if mismatch.is_some() {
                    break;
                }
            }
            mismatch
        }));
    }
    let mut mismatches = Vec::new();
    for handle in handles {
        if let Some(mismatch) = handle.join().unwrap() {
            mismatches.push(mismatch);
        }
    }
    let elapsed = started.elapsed();
    println!(
        "PARSER_SOAK_CONCURRENCY threads=8 cases={} parses={} elapsed_ms={} parses_per_sec={}",
        cases.len(),
        8 * 8 * cases.len() * 3,
        elapsed.as_millis(),
        (8 * 8 * cases.len() * 3) as f64 / elapsed.as_secs_f64().max(0.001)
    );
    assert!(
        mismatches.is_empty(),
        "concurrent parser results differed from sequential: {mismatches:?}"
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "concurrent campaign took {elapsed:?}"
    );
}

/// Writes the seed corpus used by `fuzz/fuzz_targets/*`. Run explicitly:
/// `cargo test -p litric-core --test parser_fuzz_soak write_coverage_fuzz_seeds -- --ignored`
///
/// The seeds are the same synthetic fixtures the deterministic campaigns use,
/// so a libFuzzer corpus starts from every parser's valid input shape instead of
/// random bytes. CI can regenerate them if the fixtures change.
#[test]
#[ignore = "writes fuzz/seeds; run explicitly when fixtures change"]
fn write_coverage_fuzz_seeds() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
    let mut files = Vec::new();

    let pe = pe_fixture();
    files.push(("pe/minimal-pe64.bin", pe));

    let nested = zip_package(&[("inner.txt", b"nested seed")]);
    files.push((
        "zip/ordinary.zip",
        zip_package(&[
            ("doc.xml", b"<document>ordinary content</document>"),
            ("bin/payload.dat", b"not executable, just bytes"),
            ("empty.txt", b""),
        ]),
    ));
    files.push(("zip/nested.zip", zip_package(&[("nested.zip", &nested)])));
    files.push(("zip/macro.docm", docm_fixture()));

    files.push(("vba/project.cfb", vba_project_fixture()));
    files.push(("vba/macro.docm", docm_fixture()));

    let mut rgce = Vec::new();
    rgce.push(0x17); // ptgStr
    rgce.push(8);
    rgce.push(0x01); // UTF-16LE
    for unit in "calc.exe".encode_utf16() {
        rgce.extend_from_slice(&unit.to_le_bytes());
    }
    rgce.extend_from_slice(&[0x22, 0x01, 0x6E, 0x80]); // EXEC, 1 arg, macro call
    let workbook = biff_workbook_fixture("Macro1", true, &biff_formula_record(&rgce));
    files.push((
        "xlm/workbook.cfb",
        cfb_stream_fixture("Workbook", &workbook),
    ));
    files.push((
        "xlm/macro.xlsm",
        xlsm_fixture(
            br#"<xm:worksheet><xm:f>EXEC("calc.exe")</xm:f><xm:f>URLDownloadToFileA()</xm:f></xm:worksheet>"#,
        ),
    ));

    for (relative, bytes) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}
