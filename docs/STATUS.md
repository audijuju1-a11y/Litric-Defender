# Litric Defender — implementation status

States are used strictly:
`IMPLEMENTED` = code exists and does what it says ·
`TESTED` = exercised by automated tests in this repository ·
`PARTIALLY IMPLEMENTED` = some real behaviour, known gaps ·
`PLANNED` = designed, not written ·
`BLOCKED` = cannot be built or shipped by this project under current constraints ·
`UNSUPPORTED` = deliberately out of scope.

Nothing in this file may be upgraded without the corresponding code and test.

---

## 1. Detection engine (`crates/litric-core`)

| Feature | State | Evidence / notes |
|---|---|---|
| PE parser: DOS/COFF/optional headers, sections, characteristics, entropy | TESTED | `pe.rs`, unit tests for RVA mapping, truncation, checksum |
| Imports (PE32/PE32+, ordinals, delay imports), exports | TESTED | import fingerprint test (order-sensitive, case-folding) |
| Resource walker: version info, embedded manifest (`requireAdministrator`) | TESTED | best-effort VS_VERSIONINFO string extraction |
| Overlay analysis incl. embedded `MZ` detection | TESTED | `format::find_embedded_pe`, engine test |
| Rich header, debug PDB path, TLS callbacks, CLR/.NET, ASLR/DEP/CFG flags | TESTED | surfaced in reports |
| Authenticode blob parsing: presence, PKCS#7, subjects, expiry, EKU, timestamp | TESTED | `authenticode.rs`; parser only, chain trust is a separate verifier |
| Certificate chain / revocation / page-hash verification | UNPROVEN (Windows-only) | `WinVerifyTrust` wiring in `litric-service`; native execution, revocation, and page hashes are not tested |
| Content-type detection independent of extension | TESTED | PE/ELF/PDF/OLE2/ZIP/OOXML/JAR/RAR/7z/CAB/ISO/LNK/scripts |
| Litric Rule Syntax: lexer, parser, validator, 22 rules | TESTED | `rules.rs`, `rules/core.lrs` (lint: 22 ok, 0 problems) |
| Aho–Corasick multi-pattern matcher (original) | TESTED | linear-time test on 4 MB adversarial buffer |
| Hex patterns with `??` wildcards, wide/nocase/fullword strings | TESTED | wildcard, wide, fullword tests |
| Heuristic signals (30+, weighted, explained, MITRE-mapped) | TESTED | `heuristics.rs`, 8 tests |
| Verdict aggregation, trust dampening, explicit `Unknown` | TESTED | `engine.rs`, threshold tests |
| Hash reputation (SHA-256) against signed DB | TESTED | `threatdb.rs` |
| Fuzzy/rolling hashes (ssdeep-style), section hashing | PLANNED | |
| ZIP-family recursion (ZIP/OOXML/JAR) in memory: entry/size/ratio/depth limits, explicit truncation | TESTED | `archive.rs` 4 unit tests + 4 engine tests (EICAR member, nested archive, benign, depth limit) + 1 real-binary E2E (container quarantined); limits 512 entries, 16 MiB/member, 64 MiB/layer, 1000:1 ratio, depth 3; no member is written to disk |
| Recursive scanning for RAR/7z/ISO/MSI/CAB/gzip/bzip2 | PLANNED | those formats are identified only as containers |
| Bounded script de-obfuscation (base64, `[char[]]`/`[char]` chains, constant-key XOR; up to 3 layers) | TESTED | `deobfuscate.rs`, 19 unit tests and a shared `WorkBudget`; every decoded layer is re-analysed and escalates only when conclusive (5 engine tests, 2 real-binary E2E where a rule can only match after decoding); no variable-key XOR search, string splitting, VBA string-building or emulation |
| VBA macro extraction and source analysis (OOXML + legacy OLE2, MS-OVBA); PerformanceCache (p-code) presence reported | TESTED | `vba.rs`: OLE2 CFB reader (FAT, mini stream, mini FAT), MS-OVBA chunk and copy-token decompressor, 14 unit tests plus 4 engine tests over real ZIP/OLE2 fixtures; cache-first streams are handled and cache-only streams are flagged as possible VBA stomping; p-code is not decompiled |
| Excel 4.0 (XLM) macro sheets: OOXML formulas + legacy BIFF5/BIFF7/BIFF8 `FORMULA` tokens | TESTED | `xlm.rs` (13 unit tests) + `biff.rs` (16 decoder tests) + 4 engine tests on real XLSM/BIFF fixtures; OOXML formulas and decoded legacy formula text are analysed as source by the same rules/heuristics; BIFF5/7 use one-byte Latin-1 strings and three-byte references; array constants are decoded from the record's `RgbExtra` and `PtgMemArea`/`PtgMemErr`/`PtgMemFunc` keep the expression they wrap; unknown function ids render as `FUNC_/MACRO_0xNNNN` and mark the result incomplete; external-reference resolution and BIFF4-and-earlier workbooks are not decoded |
| Memory scanning | PLANNED | needs kernel/PPL telemetry |
| Disassembly / emulation / ML classification | UNSUPPORTED (for now) | deliberate: no fake AI scoring |

## 2. Scanner and orchestration

| Feature | State | Notes |
|---|---|---|
| Directory walker with symlink/reparse skip, hard-link dedupe | TESTED | recursive nested folders; inode dedupe on Unix; Windows file-id dedupe PLANNED |
| File/time budgets, per-file size cap with truncation flag | TESTED | budget test |
| Smart-scan cache keyed on (path, size, mtime) | TESTED | invalidation tested |
| Honest accounting (clean/unknown/suspicious/malicious/skipped/unreadable) | TESTED | unknown ≠ clean asserted |
| Named scan profiles (Quick/Smart/Full/Deep/Memory/Rootkit/Offline L0–L8) | PARTIALLY IMPLEMENTED | engine supports all modes; only path/custom profile exposed in CLI |
| Scheduled scans, USB/network-drive triggers, idle-aware scheduling | PLANNED | |
| Parallel worker pool | PLANNED | single-threaded today; measured 505 files/s on 767 PowerShell files, 56 files/s on 603 driver images (native Windows 11) |
| Progress/ETA events for UI | PLANNED | summary returned at end only |
| Scan-time automatic quarantine (`scan --quarantine-malicious`): file or recursive directory; only `Malicious` moved; Clean/Unknown untouched | TESTED | 6 CLI end-to-end tests + 1 daemon/service test on native Windows 11 x86_64 (2026-11-07); nested folder, byte-identical retained files, repeat scan, forced failure retains source and exits 4 |
| Pre-execution guard (`litric guard`): scan → **block** malicious/suspicious/unknown/truncated → re-hash → launch; `--quarantine` opts in to moving the malicious original | TESTED | 8 policy tests + 4 CLI end-to-end tests on native Windows 11 x86_64; blocking never deletes; only launches through this command; no system-wide interception; TOCTOU narrowed, not eliminated |

## 3. Quarantine

| Feature | State | Notes |
|---|---|---|
| Encrypted vault (XChaCha20-Poly1305, Argon2id, per-entry nonce) | TESTED | plaintext-absence asserted in test |
| Header authenticated as AAD (tamper detection) | TESTED | header-bit-flip test |
| Quarantine lifecycle: encrypt → verify → index → remove original | TESTED | temp decrypt/hash before touching source; scan-time moves require the scanned digest to match (`quarantine_file_checked`); conservative index row if interrupted; source deleted by held handle after identity re-check, never by path |
| List / inspect / integrity audit (`verify_all`) | TESTED | every entry decrypted and re-hashed; failures reported, not hidden |
| Restore: refuse overwrite, temp → close → atomic publish → re-read | TESTED | existing bytes unchanged; double restore and restore-after-purge return `NotFound` |
| Windows/NTFS no-clobber and occupied-destination semantics | TESTED | restore/overwrite/occupied-destination tests executed natively on Windows 11 x86_64/NTFS (2026-11-06) |
| Purge with explicit confirmation and journal | TESTED | 404 for unknown/already-purged; never a silent success |
| Crash recovery from `ops.jsonl` (`intent`/`done`, reconcile on open) | TESTED | interrupted quarantine/restore/purge tests; conflicting target preserved; orphan entry re-indexed; idempotent |
| Native path/ADS/metadata preservation | TESTED (NTFS) | Named `$DATA` streams (max 64; 16 MiB each, 64 MiB total) and created/accessed/modified times are stored in the encrypted container and restored before publish; legacy raw entries still restore. EAs, security descriptors, file attributes and stream ACLs/timestamps are **not** preserved; access time is applied but not asserted because reads can update it. See `docs/PHASE1_QUARANTINE_METADATA.md` |
| DPAPI wrapping of the vault key | TESTED | Windows: new keys are sealed with machine-scoped DPAPI (`LKDK1` header, entropy-bound); legacy 32-byte keys are migrated in place with a `vault.key.legacy` recovery copy; a corrupt wrapper is refused without modifying the file; the effective DACL is asserted, not just the SDDL constant. 9 new tests across core/service; see `docs/PHASE1_SAFETY_REPORT.md` |

## 4. RansomShield

| Feature | State | Notes |
|---|---|---|
| Behavioural scoring (write burst, extension churn, rename burst, entropy, mass delete) | TESTED | `ranshield.rs`, 8 tests |
| Decoy (HoneyVault) creation, identification, canary tokens | TESTED | synthetic content only, no personal data |
| Backup/recovery destruction detection | TESTED | `vssadmin`/`wbadmin`/`bcdedit` is critical |
| Benign suppression for archivers/backup tools | TESTED | 7-Zip bulk archive → not escalated |
| Response policy (alert / block writes / suspend / isolate / snapshot) | TESTED (decisions only) | actions are *requests*; no OS enforcement yet |
| Protected Folder Guard (pre-write blocking) | BLOCKED | needs minifilter (see §7) |
| Recovery Vault (file versions, VSS integration, NAS/external) | PLANNED | |
| Sensor: ETW `Kernel-File` + minifilter for enforcement | PLANNED / BLOCKED | see §7 |

## 5. Threat database and updates

| Feature | State | Notes |
|---|---|---|
| Ed25519-signed manifest + payload hash | TESTED | tamper, forged-payload and wrong-key tests |
| Anti-rollback, `min_engine` gate | TESTED | both refused with typed errors |
| Revocation of rules and hashes | TESTED | |
| Atomic install with `.prev` retention | TESTED | |
| Production key pinning, key rotation tooling | PARTIALLY IMPLEMENTED | `ThreatDb::load_for_runtime` reads pinned keys from `LITRIC_DB_PUBKEY` and refuses the fixture key unless `LITRIC_ALLOW_DEV_DB=1`; a malformed pin is an error. `Production` vs `DevelopmentOnly` is preserved in `DbTrust`. No production keypair or rotation runbook exists yet |
| HTTPS update channel, incremental updates, offline update files | PLANNED | no network code yet |

## 6. User interface

| Feature | State |
|---|---|
| CLI client (`litric`): status / scan with progress / cancel / analyze / quarantine lifecycle (add, list, verify, restore, purge) over the daemon API, with `--local` standalone escape hatch; `scan --quarantine-malicious` moves only malicious scan hits; `guard` runs in-process by design | TESTED — 16 daemon end-to-end + 4 guard + 4 scan-quarantine + 2 platform evidence integration tests |
| Rule lint, DB build/verify, bench (in-process engine tooling) | TESTED |
| Local API backend (`litricd`): loopback HTTP/JSON, bearer auth, scan jobs with progress + cancellation, analyze, scan-time quarantine, quarantine control (404/409 mapping), readiness gate, settings/history persistence, RansomShield event ingestion | TESTED — 40 service-library tests incl. socket-level auth, readiness refusal, quarantine error mapping and auto-quarantine repeatability |
| Native Windows GUI (WinUI 3 / WPF) with all 22 sections | PLANNED — no UI project exists yet |
| Tray icon, notifications, threat explanations UI | PLANNED |
| Installer / uninstaller | DEFERRED by decision — no MSI is built in this revision; the install path is `litricd service install` |
| Windows service host (SCM wrapper around `litricd`) | IMPLEMENTED, PARTIALLY VERIFIED — `litricd service install|uninstall|status`, `run-service`, `--process-gate` install-time selection, state reporting, stop handling, ACL-hardened data dir, file logging, and `SERVICE_CONFIG_FAILURE_ACTIONS` restart policy (5 s / 30 s / 60 s / 300 s, one-day reset) applied on install and refresh; 13 SCM unit tests + 3 CLI-default tests + unelevated guards measured. An **elevated** install/start/stop/delete cycle has not been run yet (no admin test in this session) |
| IPC | IMPLEMENTED as loopback HTTP; a named-pipe transport is PLANNED |

## 7. Windows integration and kernel components

| Feature | State | Reason |
|---|---|---|
| Process gate (suspend new process → scan → resume/terminate) | IMPLEMENTED, TESTED — 16 tests incl. real suspend/resume and a real hash-based termination; live daemon run blocked a fixture process. **Defaults to off (`serve`) / monitor (`run-service` install); kill requires `--process-gate enforce`.** Hash-only kill policy, protected OS/vendor paths, never kills on rules/heuristics. Best-effort: not pre-execution |
| ETW consumer (`Kernel-Process`, `Kernel-File`) | PLANNED | design only; no consumer code written |
| AMSI provider DLL | PLANNED | not written |
| WFP application firewall rules | PLANNED | user-mode `FwpmFilterAdd` is viable |
| Windows Security Center registration | BLOCKED | vendor enrolment is MVI-gated and not publicly documented |
| Minifilter driver (scan-before-execute, write blocking) | BLOCKED | Microsoft-signed driver package required |
| ELAM boot driver | BLOCKED | MVI membership + WHQL; attestation explicitly cannot produce ELAM |
| AM-PPL service (`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`) | BLOCKED | requires ELAM |
| ETW Threat-Intelligence provider | BLOCKED | requires AM-PPL |
| `ObRegisterCallbacks` / `PsSetCreateProcessNotifyRoutineEx2` | BLOCKED | require signed kernel image |
| Self-defence (service protection, tamper resistance) | PARTIALLY IMPLEMENTED | safety policy/audit guards; data-directory/vault DACL hardening is implemented and tested for service, `serve` and CLI local mode; no PPL/service-protection, so an administrator can still stop the service |
| Microsoft Defender coexistence policy | PLANNED | design: never disable WinDefend; passive-mode handoff only after WSC recognition |

## 8. Testing

| Area | State |
|---|---|
| Unit and integration tests across engine, rules, PE, vault, DB, scan, guard policy, SafeOS, RansomShield | TESTED — full workspace run on native Windows 11 x86_64 (GNU toolchain), 2026-11-07: **597 passed, 0 failed, 1 ignored** in 57 test binaries, of which **18 contain tests** and 39 are empty; the 20 doctest harnesses contain **0** doctests |
| Native Windows suite | TESTED — 597 passed, 0 failed, 1 ignored (2026-11-07, after the Phase 0/1 fixes); Windows-only repository, no POSIX-only tests and no test is Windows-excluded |
| Fuzz/adversarial input handling | PARTIALLY IMPLEMENTED — random/truncated buffers, malformed PE, garbage DER, bounded ZIP fixtures, 45,000 deterministic mutations, and four coverage-guided `cargo-fuzz` targets (8,380,123 executions, 0 crash artifacts, 2026-11-07; plus an independent 2,498,974-execution rerun from seeds with 14,462 new units and 0 artifacts, and a clean-checkout empty-CARGO_HOME build plus 871,292-execution PE campaign with 0 artifacts; `--sanitizer none`). See `docs/PHASE1_PARSER_SOAK.md` and `docs/PHASE1_COVERAGE_FUZZ.md` |
| Continuous fuzzing (cargo-fuzz, AFL) | PARTIAL — `fuzz/run_campaign.sh`, `fuzz/Makefile` and `.github/workflows/fuzz.yml` are checked in; the GitHub workflow has not yet run on GitHub Actions |
| Malware corpus evaluation, FP/FN measurement | PARTIAL — EICAR detection plus a 1,370-file benign Windows system corpus (767 PowerShell files, 603 drivers); no labelled real-malware corpus with a usable licence |
| Windows VM test matrix, driver tests, E2E | NOT PRESENT — no Hyper-V backend, WFP gateway or driver code |
| Performance benchmarks | PARTIALLY IMPLEMENTED — release build on native Windows 11: 505 files/s on 767 PowerShell files, 56 files/s on 603 driver images; a Phase 0 debug-build run of the same corpora measured 222.6 and 39.9 files/s, so the build profile must always be quoted; single-threaded |
| Crash/recovery and event-loss tests | PARTIALLY IMPLEMENTED — quarantine journal/recovery is tested; VM/VHDX recovery is not written |
| Platform labelling and readiness evidence sync | TESTED — `platform_evidence` rejects reintroduced POSIX gates, checks the empty exclusion list, and compares the gate `test_evidence` with `docs/SAFEOS_READINESS.md`; Windows Sandbox guest behavior remains unproven |

## 10. SafeOS (application isolation)

Checked against the actual code in `crates/litric-safeos`; native Windows
execution is available, but Hyper-V, WFP and WDK components are still absent.
**Production readiness: NOT READY** — see `docs/SAFEOS_READINESS.md` for the
criterion-by-criterion verdict.

| Feature | State | Evidence / notes |
|---|---|---|
| Host facts model + readiness (RAM/disk/build/virtualization/NAT conflict) | TESTED | `model.rs`, 8 tests; facts must come from an agent, never guessed |
| Windows platform agent (read-only collection + daemon ingest) | TESTED offline | `litric-agent`, 7 unit + 3 e2e; the PowerShell collector path is not exercised by automated tests, and no facts were collected from this host in the suite |
| Risk classification L0-L3 with evidence and confidence | TESTED | `risk.rs`, 6 tests; unsigned ≠ malicious |
| Fail-closed execution policy | TESTED | `policy.rs`, 6 tests; non-trusted levels can never run on host |
| Resource governor: RAM/vCPU/disk/session budget, reduce-not-oversubscribe, fail-closed refusal | TESTED | `governor.rs`, 10 tests; enforced by `sandbox::prepare`, which refuses without a plan and writes the plan's memory into the `.wsb` (2 sandbox tests: reduced 2048 MB plan, missing-CPU refusal); Hyper-V session accounting still absent |
| Secure file broker: staged import/export, SHA-256 verify, approval, scan gate | TESTED | `broker.rs`, 9 tests incl. symlink/traversal/ADS/overwrite |
| Session journal, crash detection, idempotent cleanup planner | TESTED | `journal.rs`, 5 tests |
| Windows Sandbox `.wsb` generation (network/redirect off, read-only maps, verbatim-path rewrite, RAM sizing) | TESTED | `sandbox.rs` unit tests incl. locked-down XML and path normalization |
| Windows Sandbox launch (Windows builds only) | IMPLEMENTED, UNVERIFIED | runtime readiness gate + `.wsb` + spawn; every readiness blocker and path rule is unit/API tested on native Windows, but the launcher has never started a real Windows Sandbox guest — see `docs/SAFEOS_WINDOWS_VERIFICATION.md` |
| Hyper-V managed backend, VHDX lifecycle | BLOCKED | requires Windows + Hyper-V; not written |
| Local network gateway, WFP, WinNAT integration | BLOCKED | requires Windows + admin; not written |
| Guest behaviour monitoring / ETW correlation | BLOCKED | requires a running guest |
| SafeLaunch UI, Explorer integration, installer | PLANNED | no Windows UI in this repository |
| API integration (`/api/v1/safeos/status`, `/assess`, `/readiness`) and CLI (`litric safeos`) | TESTED | through the real daemon in end-to-end tests |
| Fail-closed readiness gate (503, `production_ready:false`, guest runtime `UNPROVEN`) | TESTED | `/api/v1/readiness`, `/status`, `/health`, `/assess`, `safeos status`; refusal test rejects any `READY` outside the tested allowlist; `test_evidence` records native Windows execution and the remaining UNPROVEN guest runtime |

## 11. Summary

Working and tested: the detection engine, rules, verdicts, the full journaled
quarantine lifecycle (quarantine, inspect, verify, restore, purge, recovery),
signed database, scan accounting and cancellation, scan-time quarantine of
malicious files from a file or recursive folder, RansomShield decisions, the
fail-closed CLI pre-execution guard, CLI, and the fail-closed readiness gate.
Scan-time quarantine is on-demand only: it sees files present during the walk,
not files created or downloaded afterwards, and it has no ETW/AMSI/minifilter
sensor. It is not real-time protection for the whole machine.

Not working: any form of OS-level or system-wide enforcement, the Windows UI,
the installer, and all kernel components. The CLI guard protects only launches
made through it. A user cannot yet *install* Litric Defender, and it does
not replace Microsoft Defender or Malwarebytes — see
`docs/MALWAREBYTES_COMPARISON.md` for the measured capability comparison. It
must not be described as providing real-time protection.

**SafeOS is not production-ready.** It has a tested safety core and a
native-tested Windows Sandbox launcher that has never started a guest, but no
Hyper-V backend, WFP/WinNAT gateway, behaviour monitoring, UI, installer or
real-host verification. Details:
`docs/SAFEOS_READINESS.md`.
