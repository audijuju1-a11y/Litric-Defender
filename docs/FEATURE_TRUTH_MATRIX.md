# Litric Defender — feature truth matrix (Phase 0)

Status as of 2026-11-07, verified against source and the native Windows test run.
This is the machine-checkable truth for what exists; `docs/STATUS.md` is the
long-form status page and `docs/LIMITATIONS.md` is the public limitation list.

Status vocabulary (strict):

| Status | Meaning |
|---|---|
| `TESTED` | Code exists and automated tests in this repository exercise it. |
| `IMPLEMENTED` | Code exists and does what it says, but the claim is not fully test-covered. |
| `PARTIAL` | Real behaviour with a named, material gap. |
| `STUB` | Placeholder reachable from a release path. **There is currently no such row.** |
| `ABSENT` | Not written. |
| `BLOCKED` | Cannot be built or shipped by this project under current constraints. |
| `UNVERIFIED` | Implemented and compiles, but has never been executed in the claimed environment. |

`Reachable` names a binary that actually uses the code today:
`litric` (CLI), `litricd` (daemon/service), `litric-rtp` (watcher),
`litric-scan` (standalone signature scanner), `litric-guard` (legacy console),
`agent` (host facts), `none` (tests/library only).

---

## 1. Detection core (`crates/litric-core`)

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 1 | Content-type identification | `format.rs::detect` | Magic/structure based, ignores extension; PE/ELF/PDF/OLE2/ZIP/OOXML/JAR/RAR/7z/CAB/ISO/LNK/scripts | all scanners | unit tests, 1,370 OS files | TESTED |
| 2 | SHA-256 / MD5 / SHA-1 | `hash.rs` | Bounded primitives over bytes/files; RustCrypto, no custom crypto | all scanners | unit tests | TESTED |
| 3 | PE parser | `pe.rs::parse` | DOS/COFF/optional headers, sections, imports/exports, resources, overlay, Rich, PDB, TLS, CLR, ASLR/DEP/CFG | all scanners | PE tests incl. truncation/mutation; 603 driver images | TESTED |
| 4 | Authenticode blob parsing | `authenticode.rs` | Presence, PKCS#7, subjects, expiry, EKU, timestamp; **not chain trust** | engine | unit tests | TESTED |
| 5 | Authenticode chain verification | `litric-wintrust`; `litric-service/src/lib.rs` | `WinVerifyTrust` on `/analyze`; embedded signatures only, catalog-signed unsupported, revocation cache-only | litricd (`/analyze`) | 3 mapping tests | PARTIAL |
| 6 | Litric rule language | `rules.rs` | Lexer/parser/validator, 73 rules (22 core + 51 extended), boolean/hex/field conditions | all scanners | lint 73 ok; rule tests | TESTED |
| 7 | Pattern matcher | `rules.rs` | Aho–Corasick raw+lowercase automata, wildcards, wide/nocase/fullword, bounded fallback | all scanners | adversarial 4 MB buffer test | TESTED |
| 8 | Heuristic signals | `heuristics.rs` | 56 unique weighted, explained, MITRE-mapped signals | all scanners | 8+ unit tests | TESTED |
| 9 | Verdict aggregation | `engine.rs` | `Clean` only with positive trust record; `Unknown` first-class; evidence/confidence retained | all scanners | decision tests | TESTED |
| 10 | ZIP-family recursion | `archive.rs` | 512 entries / 16 MiB member / 64 MiB layer / depth 3 / 1000:1 ratio; in-memory; traversal names rejected | all scanners | 4 unit + engine/E2E tests | TESTED |
| 11 | RAR/7z/CAB/ISO/MSI/gzip recursion | — | Identified as containers only; members not analysed | — | — | ABSENT |
| 12 | VBA extraction | `vba.rs`, `biff.rs` | OOXML + OLE2 `vbaProject.bin`, MS-OVBA decompression, source analysis; p-code presence only | all scanners | 14 unit + 4 engine tests | TESTED |
| 13 | XLM macro sheets | `xlm.rs`, `biff_ftab.rs` | OOXML macrosheets + BIFF5–8 `FORMULA` token decoding; `.xlsb` not parsed | all scanners | 13 + 16 + 4 tests | TESTED |
| 14 | Script de-obfuscation | `deobfuscate.rs` | 3 layers base64/char-chain/constant-key XOR, shared work budget | all scanners | 19 unit + engine/E2E | TESTED |
| 15 | Scan orchestration | `scan.rs` | Budgets, cache, progress, cancellation, honest unreadable/truncated accounting | litric, litricd | 16 scanner tests + daemon E2E | TESTED |
| 16 | 190-category taxonomy | `taxonomy.rs` | 190 ids; measured coverage 126 Specific / 55 GenericOnly / 3 Planned / 2 Blocked / 4 OutOfScope | litricd (`/analyze`) | 190-entry/reverse-lookup tests | TESTED |

## 2. Signatures, ClamAV, YARA

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 17 | Native signature DB | `sigdb` (text v1/v2, binary LSDBBIN1) | Strict parser; hash/pattern/section records; compact tables | litric-scan, litric-rtp | 14 binary + 10 sigdb + 4 ldb + 10 ndb | TESTED |
| 18 | Ed25519 DB signing / anti-rollback | `sigdb::Store`, `threatdb.rs` | Manifest+payload hash, signature, serial rollback refusal, atomic install, `.prev` | litric, litricd, sigtool | tamper/forgery/rollback tests | TESTED |
| 19 | Production signing key / key provisioning | `threatdb.rs::DbTrustPolicy`, `dev_signing_key` | Runtime loads are fail-closed: a pinned key (`LITRIC_DB_PUBKEY`) yields `Production`; the fixed public fixture key is refused unless `LITRIC_ALLOW_DEV_DB=1`, and is then `DevelopmentOnly`. `db build` still signs only with the fixture key | litric, litricd | 4 unit + 1 E2E | PARTIAL (no production keypair; S-01 closed) |
| 20 | ClamAV format importer | `clamav-import` | HDB/HDU/HSB/HSU/MDB/MDU/MSB/MSU/FP/SFP/IGN2/IGN/NDB/NDU/LDB/LDU; unsupported reported per line/reason; CVD/CLD/CBC/CDB/FTM/phishing rejected explicitly | litric-clamav-import (offline) | 17 import tests | TESTED (subset) |
| 21 | ClamAV CVD/CLD verification | `clamav-import` | Container unpacking and signature verification not implemented; user must use official sigtool | — | — | ABSENT |
| 22 | Imported signatures in `litric`/`litricd` scans | — | Neither binary links `scanner`/`sigdb`; only `litric-scan`, `litric-rtp` and tests use them | — | — | ABSENT |
| 23 | YARA module | `litric-yara` (`yara-x` 1.22.1, BSD-3) | .yar/.yara loading, strings/hex/regex/boolean, metadata, timeout 5 s, 10k files, 256 MiB input | **none** | 8 tests | TESTED (module only) |
| 24 | YARA in a shipping binary | — | No binary depends on `litric-yara`; no bundled rules | — | — | ABSENT |
| 25 | Detection pipeline aggregation | `litric-pipeline` | Keeps native/ClamAV/YARA provenance separate; external conviction needs severity+confidence; lists incomplete checks | litric-rtp, litric-guard | 14 tests | TESTED (module only) |
| 26 | Pipeline in normal scan/daemon | — | `litric` and `litricd` call `litric_core::engine::Engine` directly | — | — | ABSENT |

## 3. Quarantine, safety, recovery

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 27 | Encrypted vault | `quarantine.rs` | XChaCha20-Poly1305, Argon2id portable path, header as AAD, versioned container payload, digest-bound removal | litric, litricd | lifecycle/tamper tests | TESTED |
| 28 | Restore without overwrite | `quarantine.rs::restore` | Temp → close → atomic publish → re-hash; refuses occupied/protected destinations | litric, litricd | NTFS tests | TESTED |
| 29 | Purge with confirmation | `quarantine.rs::purge` | Explicit confirmation + `allow_permanent_delete` policy + audit | litric, litricd | 404/409 tests | TESTED |
| 30 | Crash recovery | `ops.jsonl`, `safety.rs` | intent/done reconciliation, ambiguous target preserved, idempotent; interrupted restore reapplies ADS/timestamps before removing the entry | litric, litricd | interrupted-operation tests | TESTED |
| 31 | ADS/timestamps preservation | `quarantine.rs`, `winplatform::filemeta` | Up to 64 named `$DATA` streams (16 MiB each / 64 MiB total) and created/accessed/modified times stored in the encrypted container; restored and verified before publish; legacy raw entries still restore. No EAs, security descriptors, file attributes or stream ACLs | litric, litricd | 4 `filemeta` + 2 container + 1 CLI E2E | TESTED (NTFS) |
| 32 | DPAPI key wrap | `quarantine.rs`, `winplatform::dpapi` | New keys sealed with machine-scoped DPAPI (`LKDK1`); legacy raw keys migrated with a `vault.key.legacy` copy; corrupt wrapper refused without rewriting | litric, litricd | 3 DPAPI + 3 key-file tests | TESTED |
| 33 | Safety guard / audit chain | `safety.rs` | Protected paths, scope, digest re-check, removal budget, hash-chained log, self-protection | litric, litricd | 10+ tests | TESTED |

## 4. Real-time, behaviour, process gate

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 34 | Post-write file monitor | `litric-monitor` | `notify` events → bounded queue/debounce → pipeline scan → verified quarantine; auto-quarantine on by default (`--no-quarantine` opts out) | litric-rtp | 3 unit + 9 E2E | TESTED |
| 35 | Monitor as a service / always-on | — | `litric-rtp` is a console runner; `litricd` does not watch files | — | — | ABSENT (S-03) |
| 36 | Process attribution for file events | — | File events carry no PID; RansomShield cannot contain the writer | — | — | ABSENT |
| 37 | RansomShield scoring | `litric-core::ranshield`, `ransomshield` | Weighted write/rename/entropy/decoy/backup-tamper logic; returns action requests | litric (via core), litric-guard | 8 + 6 tests | TESTED (logic) |
| 38 | Ransomware enforcement | — | No pre-write blocking; `litric-guard` suspender is unreachable because events have no PID | — | — | ABSENT |
| 39 | HoneyVault / Recovery Vault | `honeyvault`, `recovery` | Synthetic decoys, content-addressed versions | litric-guard | 6 + 2 tests | TESTED (logic) |
| 40 | Process gate | `processgate` | Snapshot → suspend threads → scan image → resume, or terminate only on exact malicious hash in signed DB | litricd (`--process-gate`) | 12 unit + 4 real-process E2E | PARTIAL (S-04) |
| 41 | Pre-execution blocking | — | Gate is poll-based and starts after `CreateProcess`; kernel/AMSI path absent | — | — | ABSENT |

## 5. Windows service, IPC, installation

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 42 | SCM install/uninstall/status | `litric-service::winsvc` | `CreateServiceW` for current exe, auto-start, delayed, LocalSystem, description, plus `SERVICE_CONFIG_FAILURE_ACTIONS` restart policy; uninstall stops/deletes only `LitricDefender` | litricd | 13 unit + unelevated guards | IMPLEMENTED (PARTIAL) |
| 43 | SCM start/stop lifecycle | `winsvc::run` | `StartServiceCtrlDispatcherW`, state transitions, stop token | litricd `run-service` | state-machine unit tests | UNVERIFIED (elevated) |
| 44 | Service crash recovery | `winsvc::apply_failure_actions` | Restart at 5 s / 30 s / 60 s / 300 s, one-day reset, applied on create and refresh; best-effort, not surfaced if it fails | litricd (install) | 1 plan unit test; not run against a live SCM | IMPLEMENTED |
| 45 | Loopback HTTP IPC | `server.rs`, `api.rs` | 127.0.0.1 only, peer loopback check, bearer token constant-time compare, 1 MiB body cap | litricd, litric | socket-level tests | TESTED |
| 46 | Named-pipe IPC / ACL | — | Only HTTP; no pipe | — | — | ABSENT |
| 47 | Data-directory ACL | `winplatform::acl`, `winsvc`, CLI `harden_local_vault` | Protected SDDL `SY/BA/OW` applied by service, `litricd serve` and CLI local vaults; fails closed if it cannot | litric, litricd | SDDL unit test + owner-still-works test + live `icacls` evidence | TESTED (NTFS) |
| 48 | Installer / repair / upgrade / rollback | — | No MSI; deliberately deferred; `service install` is the only install path | — | — | ABSENT |
| 49 | Settings / history persistence | `store.rs` | Atomic writes, corrupt-file fallback | litricd | service tests | TESTED |

## 6. Updates and threat intelligence

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 50 | Signed DB install / rollback | `threatdb.rs::install`, `sigtool` | Verify → temp → fsync → rename, `.prev` retained, anti-rollback | litric, litricd, sigtool | tamper/rollback tests | TESTED |
| 51 | Network update channel | — | No HTTP client dependency; no downloader | — | — | ABSENT |
| 52 | Incremental updates / CDN / key rotation tooling | — | Not written; only a rotation-friendly key id | — | — | ABSENT |
| 53 | Bundled hash/pattern feed | — | DB empty by design; only 73 authored rules | — | — | ABSENT |

## 7. SafeOS (application isolation)

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 54 | Host facts + readiness | `litric-safeos::model`, `litric-agent` | RAM/disk/build/virtualization/NAT conflict; facts must come from agent | agent, litricd | 8 + 7 + 4 tests | TESTED (offline) |
| 55 | Risk classification L0–L3 | `risk.rs` | Evidence + confidence; unsigned ≠ malicious | litricd (`/safeos`) | 6 tests | TESTED |
| 56 | Fail-closed policy | `policy.rs` | Non-trusted levels never run on host | litricd | 6 tests | TESTED |
| 57 | Resource governor | `governor.rs` | RAM cap, host reserve, vCPU, disk, one heavy session; refuses when unsafe | litricd | 10 tests | TESTED |
| 58 | Windows Sandbox `.wsb` | `sandbox.rs` | Networking/clipboard/audio/video/printer off, read-only maps, verbatim path rewrite, RAM from plan | none | 15+ unit tests | TESTED |
| 59 | Windows Sandbox launch | `sandbox::launch` | Spawns `WindowsSandbox.exe` after checks; never executed on this host | none | capability-only test | UNVERIFIED |
| 60 | Hyper-V backend / VHDX lifecycle | — | Not written | — | — | ABSENT |
| 61 | Network gateway / WFP / WinNAT | — | Not written | — | — | ABSENT |
| 62 | Guest behaviour telemetry | — | Not written; needs a guest | — | — | ABSENT |
| 63 | Secure file broker + journal | `broker.rs`, `journal.rs` | Staged import/export, hash verify, approval, traversal/symlink/ADS checks, crash planner | none | 9 + 5 tests | TESTED |

## 8. Windows integration and hardening

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 64 | AMSI provider | — | Not written | — | — | ABSENT |
| 65 | ETW consumers (`Kernel-Process`/`Kernel-File`) | — | Not written | — | — | ABSENT |
| 66 | WFP filters | — | Not written | — | — | ABSENT |
| 67 | Minifilter driver | — | No driver code; needs Microsoft signing | — | — | BLOCKED |
| 68 | ELAM / AM-PPL / Threat-Intelligence ETW | — | Requires MVI + WHQL + ELAM | — | — | BLOCKED |
| 69 | Windows Security Center registration | — | Vendor enrolment gated; not attempted | — | — | BLOCKED |
| 70 | Defender coexistence policy | docs only | No Defender API call anywhere; installer dry-run test asserts this | — | `dry_run_plan_never_mentions_defender_configuration` | IMPLEMENTED (policy) |
| 71 | Self-defence / tamper resistance | `safety.rs` | Protects its own policy/audit; no PPL, no service protection | litric, litricd | safety tests | PARTIAL |

## 9. Product surface, testing, operations

| # | Feature | Source | Actual behaviour | Reachable | Tests | Status |
|---|---|---|---|---|---|---|
| 72 | CLI | `litric-cli` | scan/status/analyze/guard/quarantine/rules/db/safeos/bench; daemon-first with `--local` escape hatch | litric | 8 unit + 16 daemon + 4 guard + 8 scan-quarantine + 2 platform | TESTED |
| 73 | Native UI / tray / notifications | — | No UI project | — | — | ABSENT |
| 74 | Scheduled / background scans | — | No scheduler | — | — | ABSENT |
| 75 | Web / malicious-site blocking | — | No network filter or reputation client | — | — | ABSENT |
| 76 | Exploit / injection protection | — | No ETW-TI, AMSI, or kernel callbacks | — | — | ABSENT |
| 77 | Automated suite | workspace | 597 passed, 0 failed, 1 ignored (opt-in fuzz seed generator), 57 test binaries (77 result lines incl. 20 doctest harnesses) of which 18 hold tests; 0 doctests | — | exit 0 | TESTED |
| 78 | Malware corpus / detection-rate measurement | — | None; only EICAR-class fixtures | — | — | ABSENT |
| 79 | False-positive corpus | `windows_os_files.rs` | 1,370 Windows system files: 0 malicious, 0 suspicious, 1 unreadable | — | 2 tests | PARTIAL |
| 80 | Parser fuzzing | `litric-core/tests/parser_fuzz_soak.rs`, `fuzz/` | 45,000 deterministic mutations + four coverage-guided `cargo-fuzz` targets; 8,380,123 executions, 0 crash artifacts on 2026-11-07, independently reproduced with 2,498,974 executions from seeds (14,462 new units, 0 artifacts), then rebuilt from a clean `fuzz/target` with an empty `CARGO_HOME` and rerun PE for 871,292 executions (0 artifacts); no sanitizer/corpus minimisation | tests + fuzz | 8 tests + 4 targets | PARTIAL (no sanitizer) |
| 81 | Performance harness / p50/p95 | — | Ad-hoc `bench` only; no latency harness | — | — | PARTIAL |
| 82 | Memory / soak / concurrency tests | `litric-core/tests/parser_fuzz_soak.rs` | 4-batch sampled private/working bytes; 8-thread determinism (12,288 calls, 0 mismatches); sampled between inputs, not an allocation hook | tests | 8 tests | TESTED |
| 83 | Independent lab validation | — | None | — | — | ABSENT |
| 84 | SBOM / license metadata | `docs/DEPENDENCIES.md` | 270 external crates declare licenses; all 20 workspace crates now declare `LicenseRef-Proprietary`; **no `LICENSE` file with actual terms exists** | — | — | PARTIAL |
| 85 | Documentation truth | `docs/` | Mostly honest; specific drifted counts are listed in `PHASE0_REPOSITORY_AUDIT.md` §6 | — | — | PARTIAL |

---

## Status roll-up (counted from the rows above)

| Status | Rows |
|---|---|
| TESTED | 42 |
| IMPLEMENTED | 3 |
| PARTIAL | 9 |
| UNVERIFIED | 2 |
| ABSENT | 26 |
| BLOCKED | 3 |
| STUB | 0 |
| **Total** | **85** |

The headline is not the number of rows: it is that **detection, quarantine and
the safety guard are real and tested**, while **real-time enforcement, the
kernel/AMSI/ETW layers, update delivery, the UI, the installer and SafeOS guest
execution are not**. No row was upgraded because a document said so.
