# Core engine area memory

Crate: `crates/litric-core` (232 tests in the latest run). Safe Rust everywhere except the isolated `winplatform` module (`dpapi`, `acl`, `filemeta`), which wraps Windows API pairs; no other module contains `unsafe`.

| Module | Responsibility |
|---|---|
| `bytes.rs` | bounds-checked little-endian readers, C strings, UTF-16 |
| `hash.rs` | SHA-256 (`Digest32::to_hex`) |
| `entropy.rs` | Shannon entropy, windowed entropy |
| `format.rs` | content-type detection, extension chains, embedded PE |
| `pe.rs` | PE32/PE32+ parse, sections, imports, resources, overlay, flags |
| `authenticode.rs` | WIN_CERTIFICATE/DER walk (no chain validation) |
| `rules.rs` | `.lrs` lexer/parser/validator + Aho-Corasick matcher |
| `heuristics.rs` | weighted, explained signals with MITRE IDs |
| `archive.rs` | bounded in-memory ZIP/OOXML/JAR member reader; limits, truncation accounting, unsafe-name rejection |
| `deobfuscate.rs` | bounded base64 / `[char[]]` / `[char]` chain / constant-key XOR decoding behind explicit constructs; shared `WorkBudget`; UTF-16LE normalisation; no verdict |
| `vba.rs` | bounded OOXML/OLE2 macro extraction: CFB reader (FAT, mini stream, mini FAT), MS-OVBA decompression, PerformanceCache detection; returns source only, never a verdict |
| `xlm.rs` | Excel 4.0 macro sheets: OOXML `xl/macrosheets/*.xml` formulas, legacy BIFF5/BIFF7/BIFF8 `BOUNDSHEET` records and `FORMULA` token extraction (passes `rgcb` so array constants decode); no verdict |
| `biff.rs` | BIFF5/BIFF7/BIFF8 `rgce` formula-token decoder for legacy XLM: MS-XLS Ftab names/arity, literals, refs, operators, array constants (`PtgExtraArray`) and memory wrappers; version-specific token sizes, bounded, no evaluation, unknown ids never guessed |
| `engine.rs` | verdict aggregation; `Clean` only via trusted hash; container verdict follows the worst member |
| `threatdb.rs` | Ed25519-signed DB, anti-rollback, atomic install; `DbTrustPolicy` + `load_for_runtime` fail closed unless a key is pinned or `LITRIC_ALLOW_DEV_DB=1` |
| `scan.rs` | walker, budgets, cache, progress/cancel hooks |
| `quarantine.rs` | XChaCha20-Poly1305 vault, versioned container payload (body + named ADS + timestamps), verify-before-delete, identity-bound handle deletion, journaled restore/purge/recovery; key file DPAPI-wrapped (`LKDK1`) with legacy-key migration |
| `winplatform.rs` | Windows-only FFI: machine-scoped DPAPI protect/unprotect, protected `SY/BA/OW` DACL helper, file identity + handle deletion, bounded ADS enumeration, timestamp capture/apply |
| `ranshield.rs` | behavioural scoring, honey vault, response policy |

Invariants: `Unknown` is never counted as clean; `Suspicious`/`Malicious` require
evidence; scan budgets are hard; cancellation is cooperative via `AtomicBool`.

Parser robustness: `tests/parser_fuzz_soak.rs` runs deterministic mutation
campaigns over PE/ZIP/VBA/XLM (45,000 inputs), crafted bomb/traversal/truncation
cases, 4-batch memory sampling and an 8-thread determinism check. Four
coverage-guided `cargo-fuzz` targets under `fuzz/` add corpus-evolving campaigns
(8,380,123 executions, 0 crash artifacts, `--sanitizer none`). Method and limits:
`docs/PHASE1_COVERAGE_FUZZ.md`. The only
`unsafe` in that file is a read-only `GetProcessMemoryInfo` probe. A truncated
legacy OLE2 workbook now produces an XLM note via
`vba::read_stream_named -> Result<Option<Vec<u8>>, &str>` instead of an empty,
unqualified report.

Known gaps: recursive scanning for non-ZIP containers (RAR/7z/ISO/MSI/CAB/gzip),
XLM external-reference resolution, p-code decompilation or encrypted VBA analysis, variable-key XOR / string-splitting de-obfuscation, fuzzy hashing,
parallel scan, Windows file-id dedupe, and native `WinVerifyTrust` execution. The service wires
`WinVerifyTrust` into `safeos_assess` for Windows, but that path is unproven.
Quarantine metadata covers named `$DATA` streams and created/accessed/modified
times only; EAs, security descriptors, file attributes and stream ACLs/timestamps
are not preserved. Restore temporary-name races in an attacker-controlled
parent directory are not solved. Quarantine recovery is proven by simulated
journal states, not a real power-loss test; clippy is not clean repository-wide.
