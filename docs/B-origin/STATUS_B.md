# Litric Defender — status (historical origin record)

> Historical snapshot from the original code line. Current Windows status:
> `docs/STATUS.md` and `docs/WINDOWS_EVIDENCE.md`.

Tests at that time: 141 passing on the original container. The merged code now
builds and passes natively on Windows 11; see `docs/STATUS.md`.
Toolchain note: Cargo.lock pins `base64ct 1.6.0`, `zeroize 1.8.1`, `ed25519-dalek 2.1.1` because the
authoring environment had Rust 1.75. Newer toolchains may update these; keep the lock file in git.

## Real-time protection / RansomShield
| Component | State | Notes |
|---|---|---|
| `ransomshield` scoring core | IMPLEMENTED, TESTED | Multi-signal, explainable, trusted list, correlation |
| `realtime` pipeline | IMPLEMENTED, TESTED | Bounded queue, loss => degraded, unattributed actor never contained |
| `honeyvault`, `recovery`, tamper classifier, `service` + periodic snapshots | IMPLEMENTED, TESTED | E2E: simulated ransomware -> suspend (fake) -> byte-exact restore |
| Windows watcher / process suspend / console runner | WRITTEN, NOT COMPILED | `realtime/src/windows.rs`, `service/src/main.rs` |
| Process attribution (ETW) + command-line source | BLOCKED on Windows VM | watcher events are alert-only (pid 0) |
| Windows Service (SCM), vault ACL hardening, minifilter | PLANNED | |

## Scan engine (this round: core + signatures + quarantine)
| Component | State | Notes |
|---|---|---|
| `sigdb`: strict LSDB parser | IMPLEMENTED, TESTED | all-or-nothing; size/rule/pattern limits; count + END check detects truncation |
| `sigdb`: Ed25519 signed bundles, key rotation/revocation | IMPLEMENTED, TESTED | uses `ed25519-dalek` (no custom crypto) |
| `sigdb`: anti-rollback, atomic install, re-verify on load | IMPLEMENTED, TESTED | floor raised before swap; corrupt floor refuses install |
| `sigtool` (pubkey / sign / check) | IMPLEMENTED, manually run | seed must be generated and kept offline by you |
| `scanner`: file scan, SHA-256, hash + multi-pattern (Aho-Corasick), file-kind targets, allowlist | IMPLEMENTED, TESTED | |
| `scanner`: honest outcomes (skipped/unscannable/error never "clean"), warnings for empty/tiny DB, exit codes 0/1/2/3 | IMPLEMENTED, TESTED | |
| `scanner`: progress callback, cancel, depth + size limits, symlinks not followed | IMPLEMENTED, TESTED | Windows reparse-point check is untested |
| `peanalysis`: bounds-checked PE parser (headers, sections, entropy, imports, overlay, cert-table presence) | IMPLEMENTED, TESTED | all reads checked; section/import loops capped; malformed input => anomalies + `partial`, no panic |
| `peanalysis`: explainable risk scoring (structure / packing / imports / strings; per-category caps; Suspicious needs 2 corroborating categories) | IMPLEMENTED, TESTED on SYNTHETIC PEs only | weights are untuned guesses; no real-world false-positive data |
| Mutation fuzzing of the PE parser | TESTED (7,500 deterministic mutations + every truncation point, no panic) | NOT coverage-guided fuzzing (no cargo-fuzz available); real fuzzing still PLANNED |
| Scanner integration: `Suspicious` outcome, weak-anomaly counter, parser panic containment, exit code 4 | IMPLEMENTED, TESTED | |
| `sigdb` v2 format: compact sorted hash tables (file hash, PE-section hash, allowlist; MD5/SHA-1/SHA-256, size-exact), provenance lines | IMPLEMENTED, TESTED | ~45 B/rule measured on synthetic data; limit 512 MiB / 10M rules per database |
| `clamav-import` adapter: HDB/HDU/HSB/HSU, MDB/MDU/MSB/MSU, FP/SFP, IGN/IGN2 (name only) -> Litric DB; report of every unsupported file/line | IMPLEMENTED, TESTED (synthetic + EICAR) | no libclamav/clamscan/clamd; section-hash semantics unverified vs libclamav; FL fields ignored |
| NDB extended signatures: parser (`sigdb::ndb`), `NDB` DB records, hashed anchor prefilter + bounded backtracking matcher (`scanner::ndb`), importer support for `.ndb/.ndu` | IMPLEMENTED (documented subset), TESTED on synthetic data + EICAR | semantics not verified vs libclamav; ~750 B/rule memory; unsupported lines reported per reason; per-file work budget -> Unscannable |
| LDB logical signatures: expression/constraint parser (`sigdb::ldb`), `LDB` text records and binary section 0x201, subsignature counting + evaluation in the shared anchor index, importer support for `.ldb/.ldu` | IMPLEMENTED (documented subset), TESTED on synthetic data | semantics not verified vs libclamav; ~606 B/rule memory; unsupported lines reported per reason; whole rule skipped if any piece is unsupported |
| Compact NDB rules (bytecode, ~114 B/rule instead of ~750) | IMPLEMENTED, TESTED | matcher interprets validated bytecode |
| Binary database `LSDBBIN1`: header-only signature + per-section SHA-256, streaming verify/load, strict validation, `sigtool compile`, `importer --binary`, `Store::install_file`, scanner CLI support | IMPLEMENTED, TESTED | 8M/16M-rule databases load in 2.3/4.9 s (synthetic, signed); see docs/DB_FORMAT.md and BENCHMARKS.md. Format 1 not frozen |
| Scanner: MD5/SHA-1 computed only when needed, ClamAV-derived file/section hash detection, provenance printed | IMPLEMENTED, TESTED | |
| Docs: ARCHITECTURE, OWNERSHIP, DEPENDENCIES (generated), CLAMAV_COMPAT, YARA_COMPAT, CLAMAV_IMPORT, BENCHMARKS, INTEGRATION_REPORT | WRITTEN | in `docs/` |
| `quarantine`: verified copy, move-after-verify, restore w/o overwrite, dedupe, purge needs authorization, hash-chained audit log | IMPLEMENTED, TESTED | XOR neutralization is NOT encryption; audit log cannot detect truncation of its newest lines |

## Not done (explicitly)
| Item | State |
|---|---|
| ClamAV CVD-CLD verification / bytecode / NDB and LDB features outside the subsets (PCRE, modifiers, macros, byte-compare, fuzzy, group counts, EntryPoint/Container constraints, ...) | NOT IMPLEMENTED; reported as UNSUPPORTED by the importer. A real ClamAV DB imports only a fraction of its coverage |
| Compact LDB in-memory representation | PLANNED |
| Memory-mapped/shared database across processes, delta updates, binary-format compatibility tests across versions | PLANNED |
| Importer and sigtool memory at millions of rules (they hold whole databases in memory) | NOT MEASURED / NOT OPTIMIZED |
| YARA module | NOT IMPLEMENTED (engine choice pending, see docs/YARA_COMPAT.md) |
| ClamAV signature database license / redistribution terms | NOT VERIFIED |
| Binary/chunked DB format for >10M rules | PLANNED |
| Detection signatures for real malware | NONE by default. The database is empty by default; tests use EICAR + synthetic rules only. Coverage is zero until a legitimately licensed signature source is added. |
| PE: unpacking/emulation, .NET metadata, resources, export analysis, Authenticode validation (a certificate table is only reported as present, never trusted) | NOT DONE |
| Script heuristics (PowerShell/VBS/JS obfuscation) | PLANNED |
| Archives (ZIP/7Z/RAR) with bomb limits; Office/PDF/script parsing | PLANNED (parsers must be isolated/fuzzed first) |
| Authenticode / signature trust (Windows API) | BLOCKED on Windows |
| Alternate Data Streams, NTFS reparse junctions, file locking, network paths | PLANNED / UNTESTED |
| Update download channel, scheduled scans, USB scan, scan-orchestration levels L0-L8 | PLANNED |
| Parser fuzzing, detection-rate / false-positive / performance measurements | NOT DONE — no numbers exist |
| UI, installer, Security Center registration, driver | PLANNED |
