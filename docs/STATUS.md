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
| Authenticode blob parsing: presence, PKCS#7, subjects, expiry, EKU, timestamp | TESTED | `authenticode.rs`; **chain trust NOT validated** |
| Certificate chain / revocation / page-hash verification | PLANNED | requires `WinVerifyTrust` on Windows |
| Content-type detection independent of extension | TESTED | PE/ELF/PDF/OLE2/ZIP/OOXML/JAR/RAR/7z/CAB/ISO/LNK/scripts |
| Litric Rule Syntax: lexer, parser, validator, 15 rules | TESTED | `rules.rs`, `rules/core.lrs` (lint: 15 ok, 0 problems) |
| Aho–Corasick multi-pattern matcher (original) | TESTED | linear-time test on 4 MB adversarial buffer |
| Hex patterns with `??` wildcards, wide/nocase/fullword strings | TESTED | wildcard, wide, fullword tests |
| Heuristic signals (30+, weighted, explained, MITRE-mapped) | TESTED | `heuristics.rs`, 8 tests |
| Verdict aggregation, trust dampening, explicit `Unknown` | TESTED | `engine.rs`, threshold tests |
| Hash reputation (SHA-256) against signed DB | TESTED | `threatdb.rs` |
| Fuzzy/rolling hashes (ssdeep-style), section hashing | PLANNED | |
| Archive recursion (ZIP/RAR/7z/ISO/MSI) with bomb limits | PLANNED | containers are identified, not unpacked |
| Script de-obfuscation (base64/PowerShell) | PLANNED | encoded payloads are flagged, not decoded |
| Office macro (VBA) stream extraction | PLANNED | |
| Memory scanning | PLANNED | needs kernel/PPL telemetry |
| Disassembly / emulation / ML classification | UNSUPPORTED (for now) | deliberate: no fake AI scoring |

## 2. Scanner and orchestration

| Feature | State | Notes |
|---|---|---|
| Directory walker with symlink/reparse skip, hard-link dedupe | TESTED | inode dedupe on Unix; Windows file-id dedupe PLANNED |
| File/time budgets, per-file size cap with truncation flag | TESTED | budget test |
| Smart-scan cache keyed on (path, size, mtime) | TESTED | invalidation tested |
| Honest accounting (clean/unknown/suspicious/malicious/skipped/unreadable) | TESTED | unknown ≠ clean asserted |
| Named scan profiles (Quick/Smart/Full/Deep/Memory/Rootkit/Offline L0–L8) | PARTIALLY IMPLEMENTED | engine supports all modes; only path/custom profile exposed in CLI |
| Scheduled scans, USB/network-drive triggers, idle-aware scheduling | PLANNED | |
| Parallel worker pool | PLANNED | single-threaded today; measured 3 050 files/s |
| Progress/ETA events for UI | PLANNED | summary returned at end only |

## 3. Quarantine

| Feature | State | Notes |
|---|---|---|
| Encrypted vault (XChaCha20-Poly1305, Argon2id, per-entry nonce) | TESTED | plaintext-absence asserted in test |
| Header authenticated as AAD (tamper detection) | TESTED | header-bit-flip test |
| Verify-before-delete of original | TESTED | reads back temp entry, hash-compares |
| Restore without overwriting existing files, hash re-verified | TESTED | |
| Vault integrity audit (`verify_all`), purge | TESTED | |
| Native path/ADS/metadata preservation | PARTIALLY IMPLEMENTED | POSIX mode/mtime and NTFS ADS not yet preserved |
| DPAPI wrapping of the vault key | PLANNED | Windows service responsibility |

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
| Production key pinning, key rotation tooling | PARTIALLY IMPLEMENTED | key id + rotation-friendly API; production key not provisioned |
| HTTPS update channel, incremental updates, offline update files | PLANNED | no network code yet |

## 6. User interface

| Feature | State |
|---|---|
| CLI client (`litric`): status / scan with live progress / analyze / quarantine-list over the daemon API, with `--local` standalone escape hatch | TESTED — 8 end-to-end tests invoke the real binary against a real daemon |
| Rule lint, DB build/verify, bench (in-process engine tooling) | TESTED |
| Local API backend (`litricd`): loopback HTTP/JSON, bearer auth, scan jobs with live progress + cancellation, analyze, quarantine control, settings/history persistence, RansomShield event ingestion | TESTED — 14 service tests incl. socket-level auth |
| Native Windows GUI (WinUI 3 / WPF) with all 22 sections | PLANNED — no Windows host to build or test it |
| Tray icon, notifications, threat explanations UI | PLANNED |
| Installer / uninstaller | PLANNED |
| Windows service host (SCM wrapper around `litricd`) | PLANNED — backend daemon exists, SCM shim does not |
| IPC | IMPLEMENTED as loopback HTTP; a named-pipe transport is PLANNED |

## 7. Windows integration and kernel components

| Feature | State | Reason |
|---|---|---|
| ETW consumer (`Kernel-Process`, `Kernel-File`) | PLANNED | needs a Windows host to develop against; design done |
| AMSI provider DLL | PLANNED | signing not required by default, but cannot be tested here |
| WFP application firewall rules | PLANNED | user-mode `FwpmFilterAdd` is viable |
| Windows Security Center registration | BLOCKED | vendor enrolment is MVI-gated and not publicly documented |
| Minifilter driver (scan-before-execute, write blocking) | BLOCKED | Microsoft-signed driver package required |
| ELAM boot driver | BLOCKED | MVI membership + WHQL; attestation explicitly cannot produce ELAM |
| AM-PPL service (`SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`) | BLOCKED | requires ELAM |
| ETW Threat-Intelligence provider | BLOCKED | requires AM-PPL |
| `ObRegisterCallbacks` / `PsSetCreateProcessNotifyRoutineEx2` | BLOCKED | require signed kernel image |
| Self-defence (service protection, tamper resistance) | PARTIALLY IMPLEMENTED | vault/key permissions; service hardening PLANNED |
| Microsoft Defender coexistence policy | PLANNED | design: never disable WinDefend; passive-mode handoff only after WSC recognition |

## 8. Testing

| Area | State |
|---|---|
| Unit tests across engine, rules, PE, vault, DB, scan, RansomShield | TESTED — 81 tests |
| Fuzz/adversarial input handling | PARTIALLY IMPLEMENTED — random/truncated buffers, malformed PE, garbage DER, archive-free |
| Continuous fuzzing (cargo-fuzz, AFL) | PLANNED |
| Malware corpus evaluation, FP/FN measurement | PLANNED — no labelled corpus with a usable licence |
| Windows VM test matrix, driver tests, E2E | BLOCKED by environment |
| Performance benchmarks | PARTIALLY IMPLEMENTED — CLI `bench` on Linux VM only |
| Crash/recovery and event-loss tests | PLANNED |

## 10. SafeOS (application isolation)

Checked against the actual code in `crates/litric-safeos`; the Windows half is
BLOCKED in this environment (Linux, no Hyper-V/WFP/WDK).

| Feature | State | Evidence / notes |
|---|---|---|
| Host facts model + readiness (RAM/disk/build/virtualization/NAT conflict) | TESTED | `model.rs`, 8 tests; facts must come from an agent, never guessed |
| Windows platform agent (read-only collection + daemon ingest) | TESTED offline; Windows probe compile-check only | `litric-agent`, 7 unit + 3 e2e; collector not executed on a real Windows host here |
| Risk classification L0-L3 with evidence and confidence | TESTED | `risk.rs`, 6 tests; unsigned ≠ malicious |
| Fail-closed execution policy | TESTED | `policy.rs`, 6 tests; non-trusted levels can never run on host |
| Secure file broker: staged import/export, SHA-256 verify, approval, scan gate | TESTED | `broker.rs`, 9 tests incl. symlink/traversal/ADS/overwrite |
| Session journal, crash detection, idempotent cleanup planner | TESTED | `journal.rs`, 5 tests |
| Windows Sandbox `.wsb` generation (network/redirect off, read-only maps) | TESTED | `sandbox.rs`, 6 tests |
| Windows Sandbox launch (Windows builds only) | IMPLEMENTED, UNVERIFIED | runtime readiness gate + `.wsb` + spawn behind `cfg(windows)`, 5 tests; Linux returns 501. Never executed on a real host yet — see `docs/SAFEOS_WINDOWS_VERIFICATION.md` |
| Hyper-V managed backend, VHDX lifecycle | BLOCKED | requires Windows + Hyper-V; not written |
| Local network gateway, WFP, WinNAT integration | BLOCKED | requires Windows + admin; not written |
| Guest behaviour monitoring / ETW correlation | BLOCKED | requires a running guest |
| SafeLaunch UI, Explorer integration, installer | PLANNED | no Windows UI in this repository |
| API integration (`/api/v1/safeos/status`, `/assess`) and CLI (`litric safeos`) | TESTED | through the real daemon in end-to-end tests |

## 11. Summary

Working and tested: the detection engine, rules, verdicts, quarantine, signed
database, scan accounting, RansomShield decisions, CLI.

Not working: any form of OS-level enforcement, the Windows UI, the installer, and
all kernel components. A user cannot yet *install* Litric Defender, and it does
not replace Microsoft Defender. It must not be described as providing real-time
protection.
