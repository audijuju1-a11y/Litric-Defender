# Litric Defender — Full Product & Engineering Blueprint

**Version:** 1.1 (`FULL_BLUEPRINT`)

**Date:** 2026-11-03

**Status:** `DESIGNED` decision document with two portable correctness fixes implemented and tested in the working tree. Native Windows execution, the installer, SCM service, kernel/ETW/AMSI/WFP work, and independent validation remain `UNPROVEN` or `NOT_IMPLEMENTED`; no system setting, driver, or external service was changed.

**Scope:** Windows 11 x64, original Litric detection and product workflows, local-first operation, coexistence with Microsoft Defender.

**Reading rule:** `[FACT]` = repository or primary-source evidence; `[SOURCE]` = cited external claim not independently reproduced; `[JUDGMENT]` = engineering/product judgement; `[ASSUMPTION]` = unverified premise; `[HYPOTHESIS]` = testable belief; `[TARGET]` = proposed threshold, not a result; `[UNKNOWN]` = evidence missing.

---

## 0. Scope contract

```text
Mode:                 FULL_BLUEPRINT
Question:             What should Litric Defender build, in what order, for whom,
                      and what must it refuse to claim?
Deliverable:          Product thesis, evidence ledger, repository audit, market and
                      customer analysis, architecture, Windows feasibility, threat
                      coverage, validation plan, commercial plan, gated roadmap,
                      risks, ADRs, open questions, final recommendation.
Known constraints:    Windows 11 x64; original engine; no ClamAV backend; YARA only
                      optional; do not disable Defender or Windows controls;
                      local-first/consent-based cloud; no native Windows host in
                      the current environment; no installer, SCM service, UI,
                      sensor, enforcement, or production signing key.
Working assumptions:  Prosumer/creator and small-team buyers value explainable
                      verdicts and recoverability; Defender remains primary AV
                      until Litric earns a different role.
Explicit non-goals:   Code changes, driver creation/loading, Windows settings,
                      malware execution, cloud upload, commit, push, deployment.
Evidence gaps:        Native Windows 11 execution, NTFS semantics, Windows Sandbox
                      guest runtime, licensed corpus, customer interviews, lab
                      results, production key/signing path, MVI eligibility.
```

---

## 1. Executive decision summary

### Recommendation

**Litric should not launch as a primary antivirus.** It should launch as a **local-first Windows 11 file-trust, quarantine, and recovery layer** that coexists with Microsoft Defender and explains every verdict. The first commercial promise should be:

> “Litric tells you what it actually knows, preserves the evidence, and helps you get your files back — without pretending to be the only protection on the PC.”

This is narrower than “beat Defender,” but it is defensible with the code that actually exists and the Windows gates that actually apply. `[JUDGMENT]`

### Why this direction

1. The portable core is real: PE parsing, Litric Rule Syntax, 30+ heuristics, explicit `Unknown`, encrypted journaled quarantine, signed threat DB, RansomShield decision logic, CLI, and loopback daemon are implemented and tested. `[FACT]` `[E-01]`–`[E-08]`
2. The installed-product layer is absent: no installer, SCM service, native UI, ETW consumer, AMSI provider, WFP policy, minifilter, production update channel, or production signing key. `[FACT]` `[E-03]` `[E-09]`
3. The portable suite is green (210/210 on Linux after this pass), but the Windows claims are unproven: the last recorded Wine 11.21 run was 195/195 before these tests were added, 8 tests are excluded, and native Windows 11/NTFS/Sandbox execution remains `UNPROVEN`. `[FACT]` `[E-02]`
4. Kernel, ELAM, PPL, and Windows Security Center are not ordinary backlog items. MVI requires a commercially available real-time product with independent certification; ELAM additionally requires MVI and WHQL. That is a circular late-stage gate for a pre-launch product. `[SOURCE]` `[S5]` `[S6]`
5. Windows Sandbox is not universal: it is supported on Pro, Enterprise, Pro Education/SE, and Education, but **not Windows Home**, and its default configuration enables networking and clipboard redirection. SafeOS must be an explicit, supported-edition feature, not “all Windows 11 PCs.” `[SOURCE]` `[S2]` `[S3]` `[S4]`
6. Detection alone is a poor wedge against incumbents with decades of content, distribution, and lab history. Transactional quarantine, explainable evidence, and tested recovery are more differentiated and more honest. `[JUDGMENT]`

### First critical path

| Order | Work package | Why first | Exit evidence |
|---|---|---|---|
| 1 | **Native Windows 11 lab and proof harness** | Every Windows claim is currently unproven; Wine cannot substitute | Native build/test matrix on 25H2 and 26H2; NTFS restore tests; crash recovery |
| 2 | **Installable product skeleton** | A scanner users cannot install is not a product | Signed development installer, SCM service, named-pipe IPC, WinUI 3 shell, clean uninstall/rollback |
| 3 | **Trustworthy scanning and recovery** | The defensible wedge must be operationally excellent | Parser isolation, fuzzing, corpus/FP baseline, production key path, protected-folder versioning, restore verification |
| 4 | **User-mode visibility** | Adds value without pretending to enforce | ETW process/file telemetry with loss accounting, AMSI provider, WFP policy; no blocking claim |
| 5 | **Independent validation** | Earn the right to make comparative claims | AV-TEST/AV-Comparatives/SE Labs engagement where eligible; reproducible internal benchmark |

### Top risks

- No native Windows evidence; the current “Windows” result is a Wine ABI result. `[FACT]`
- No installer, service host, or UI; the product cannot be deployed. `[FACT]`
- No enforceable real-time control; “protection” would be false. `[FACT]`
- False positives and `Unknown` verdicts can destroy trust faster than a missed detection. `[JUDGMENT]`
- MVI/ELAM/WSC and kernel enforcement are externally gated and may never be attainable for this team. `[SOURCE]` `[S5]` `[S6]`
- A recovery product without a tested restore path is more dangerous than no recovery feature. `[JUDGMENT]`

### Explicit no-gos for the next release

- No “primary antivirus,” “real-time protection,” “kernel-protected,” “WSC-registered,” or “AI-powered” claim.
- No unsigned/test-signed driver; no instruction to disable Secure Boot, Memory Integrity, or signature enforcement.
- No disabling or tampering with Defender, Firewall, or Windows Security Center.
- No universal Hyper-V/Sandbox claim; no silent host fallback when isolation is unavailable.
- No default upload of files or sensitive telemetry.
- No third-party rule/hash feed without a verified redistribution licence.
- No benchmark score presented as a Litric result.

### What would change this recommendation

- Native Windows tests and a signed installer prove the runtime and recovery path.
- Customer interviews show that a scanner-plus-recovery product is not a viable purchase.
- A licensed corpus and lab pathway make detection a credible wedge.
- MVI eligibility becomes realistic earlier than expected.
- A Windows-native competitor offers the same transparency/recovery wedge at lower support cost.

---

## 2. Scope, assumptions, and non-goals

### Target platform

- Primary: Windows 11 x64, **25H2 and 26H2** test targets; 26H1 verified separately.
- Windows 11 24H2 Home/Pro reached end of updates on **2026-10-14**; it must not be presented as a supported target. `[SOURCE]` `[S1]`
- Windows 11 Home is supported for scanning/UI, but **not** for Windows Sandbox; SafeOS must report `UNSUPPORTED` rather than degrade silently. `[SOURCE]` `[S2]`
- Enterprise/Education lifecycle differs from Home/Pro; test and document each edition separately. `[SOURCE]` `[S1]`

### Working assumptions

- `[ASSUMPTION]` A meaningful segment will pay for trustworthy recovery and explanation, not another detection score.
- `[ASSUMPTION]` Defender remains the primary real-time antivirus during Litric 1.x.
- `[ASSUMPTION]` A signed per-machine installer and SCM service are acceptable to target buyers.
- `[ASSUMPTION]` A licensed clean/malicious corpus can be obtained for internal evaluation.
- `[ASSUMPTION]` The team can support a Windows installer, service, UI, and update channel.
- `[UNKNOWN]` Whether MVI membership, EV signing, WHQL, and independent certification are economically attainable.

### Non-goals for this blueprint

- Implementing or modifying code.
- Creating, signing, loading, or testing a driver.
- Executing live malware or destructive ransomware.
- Changing Windows features, firewall, NAT, VPN, WSL2, Docker, or Defender settings.
- Publishing, committing, or deploying anything.
- Claiming a benchmark, customer, price, or competitor result that was not measured or sourced.

---

## 3. Evidence and assumptions ledger

| ID | Claim or decision | Type | Evidence | What it proves | What it does not prove | Confidence |
|---|---|---|---|---|---|---|
| E-01 | Portable detection, rules, heuristics, verdict aggregation are implemented and tested | `[FACT]` | `README.md`, `docs/STATUS.md`, `crates/litric-core`, native suite | Code exists and passes repository tests on Linux | Native Windows behaviour or competitive detection | HIGH |
| E-02 | Portable suite 210/210 on Linux after this pass; last recorded Windows-target run was 195/195 under Wine 11.21 before these tests were added; 8 excluded | `[FACT]` | `cargo test --workspace`; `docs/WINDOWS_WINE_TESTING.md`; `WINDOWS_WINE_TEST_EVIDENCE.txt` | Portable and Wine ABI paths mostly execute | Native Windows, NTFS, Sandbox guest, excluded paths; Wine run not repeated | HIGH for the portable run; LOW for Windows support |
| E-03 | No installer, SCM service, native UI, ETW, AMSI, WFP, minifilter, ELAM/PPL/WSC | `[FACT]` | `docs/STATUS.md`, `docs/LIMITATIONS.md`, source tree | Those layers are absent | Whether they can be built later | HIGH |
| E-04 | Quarantine lifecycle is journaled, encrypted, verify-before-remove, no-clobber restore | `[FACT]` | `crates/litric-core/src/quarantine.rs`, tests | Portable lifecycle and crash reconciliation work on Linux | NTFS/Windows publish semantics, power-loss durability | HIGH for Linux; `UNPROVEN` for Windows |
| E-05 | Threat DB uses Ed25519, anti-rollback, revocation, atomic install; production key absent | `[FACT]` | `crates/litric-core/src/threatdb.rs`, `docs/LIMITATIONS.md` | Signed-content mechanism exists | Production key custody, rotation, distribution | HIGH |
| E-06 | RansomShield scores behaviour and returns response requests; no enforcement | `[FACT]` | `crates/litric-core/src/ranshield.rs`, `docs/LIMITATIONS.md` | Decision logic is tested | Real sensor, blocking, suspend, isolate, snapshot | HIGH for decisions; role is decisions only |
| E-07 | SafeOS has tested policy/broker/journal/config; Windows launch compiled but never executed natively; guest runtime `UNPROVEN` | `[FACT]` | `docs/SAFEOS_READINESS.md`, `docs/SAFEOS_WINDOWS_VERIFICATION.md` | Safety core and refusal paths work; runtime is not proven | Guest network/clipboard/read-only boundary, native launch | HIGH |
| E-08 | Local daemon is loopback HTTP with bearer token; no SCM host | `[FACT]` | `crates/litric-service`, `docs/STATUS.md` | Development API works | Production IPC/ACL, Windows service security | HIGH |
| E-09 | One narrow Windows-only `unsafe` FFI block calls `WinVerifyTrust`; no external network client | `[FACT]` | `crates/litric-service/src/lib.rs`; source/dependency audit | The block is confined to the platform verifier; the portable build does not execute it | Native FFI/memory-safety review; future dependencies and parser logic | HIGH for the portable tree; native block `UNPROVEN` |
| E-10 | Windows 11 25H2/26H2 support dates; 24H2 Home/Pro ended 2026-10-14 | `[SOURCE]` | Microsoft Lifecycle `[S1]`; release information `[S15]` | Build lifecycle target | Feature/API availability on each build | HIGH |
| E-11 | Windows Sandbox: Pro/Enterprise/Education only, not Home; 4 GB RAM/1 GB disk/2 cores; network/clipboard default on; one instance | `[SOURCE]` | Microsoft Learn `[S2]` `[S3]` `[S4]` | SafeOS cannot be universal | Actual guest behaviour on a specific host | HIGH |
| E-12 | ELAM requires MVI + WHQL; MVI requires a shipping real-time product and independent certification | `[SOURCE]` | Microsoft Learn `[S5]` `[S6]` | Kernel/ELAM/WSC path is a late external gate | Whether Litric can ever qualify | HIGH |
| E-13 | Defender compatibility: a registered non-Microsoft AV can cause Defender to be disabled; passive mode generally requires MDE onboarding | `[SOURCE]` | Microsoft Learn `[S7]` `[S8]` | Litric must not assume passive coexistence | Exact behaviour on every edition/configuration | HIGH, verify per build |
| E-14 | Driver signing requires EV certificate/Partner Center; attestation is not a path to ELAM | `[SOURCE]` | Microsoft Learn `[S9]`; repo audit | Signing is a procurement gate | Cost/timeline/eligibility | HIGH |
| E-15 | AV-Comparatives Feb–May 2026: 400 cases, Windows 11 64-bit, cloud allowed, false-alarm test, not repeatable | `[SOURCE]` | `[S10]` | A relevant consumer test design exists | A Litric score or competitor ranking | HIGH for methodology; no Litric result |
| E-16 | AV-TEST evaluates protection, performance, usability | `[SOURCE]` | `[S11]` | Independent test dimensions | Current scores for any product | HIGH for method |
| E-17 | SE Labs has Endpoint Protection 1.21, Enterprise Advanced Security, ransomware methodology | `[SOURCE]` | `[S12]` | Enterprise/EDR evaluation is separate from consumer AV | Applicability/cost/result | MEDIUM; detailed methodology not read |
| E-18 | MITRE ATT&CK v20 is current | `[SOURCE]` | `[S13]` | Technique taxonomy version | ATT&CK Evaluations result/coverage | HIGH for taxonomy |
| E-19 | No customer interviews, pricing evidence, or licensed corpus exist in the repo | `[UNKNOWN]` | Repository inspection | The commercial thesis is unvalidated | Willingness to pay, segment fit | `UNKNOWN` |
| E-20 | No Litric independent lab result exists | `[UNKNOWN]` | Repository inspection | No comparative claim is permissible | Future performance | `UNKNOWN` |
| E-21 | SafeOS build acceptance uses one Windows 11 lifecycle table with edition-specific end dates and an injectable date | `[FACT]` | `crates/litric-safeos/src/model.rs`; `model::tests::supported_25h2_and_26h2_builds_are_accepted`, `model::tests::expired_24h2_is_rejected_with_lifecycle_reason`, `model::tests::enterprise_24h2_uses_its_own_end_date`, `model::tests::unknown_build_is_not_accepted_by_a_numeric_floor` | 24H2 Home/Pro is rejected after 2026-10-14; 25H2/26H2 are accepted on 2026-11-03; unknown builds are not accepted by a numeric floor | Native execution on each build; LTSC/edition edge cases | HIGH for portable logic; native `UNPROVEN` |
| E-22 | `safeos_assess` derives `signature_chain_valid` from a `SignatureVerifier`; the trusted allowlist path is reachable and tested | `[FACT]` | `crates/litric-service/src/lib.rs`; `crates/litric-service/src/api.rs`; `api::tests::safeos_assess_trusts_an_allowlisted_chain_valid_entry`, `api::tests::safeos_assess_does_not_trust_tampered_or_unsigned_input`; `risk::tests::validated_chain_plus_allowlist_is_trusted`, `risk::tests::unvalidated_signature_never_grants_trust` | The flag is no longer hard-coded; a trusted allowlist entry yields `trusted`, while tampered/unsigned input does not | Native `WinVerifyTrust` execution and certificate matrix | HIGH for plumbing; native verifier `UNPROVEN` |

**Quantitative rule:** every number below is either a recorded measurement, a dated source, or marked `[TARGET]`. No target is a result.

---

## 4. Repository capability audit

### 4.1 Current state

| Capability | Status | Evidence | Platform | Gap / next proof |
|---|---|---|---|---|
| PE parser, imports/exports, resources, overlay, Rich header, TLS/CLR, flags | `TESTED` | `crates/litric-core/src/pe.rs`, tests | Linux | Native Windows corpus and malformed-input fuzzing |
| Litric Rule Syntax and Aho–Corasick matcher (15 rules) | `TESTED` | `rules.rs`, `rules/core.lrs` | Linux | Larger authored ruleset; FP measurement; rule governance |
| 30+ weighted heuristics and ATT&CK labels | `TESTED` | `heuristics.rs` | Linux | Independent efficacy study; avoid overfitting |
| Verdict aggregation with explicit `Unknown` | `TESTED` | `engine.rs` | Linux | Calibrate thresholds on labelled corpus; UX for unknown |
| SHA-256 hash reputation against signed DB | `TESTED` | `threatdb.rs` | Linux | No production feed; zero hash coverage by design |
| Scan budgets, cache, honest counters, cancellation | `TESTED` | `scan.rs`, daemon E2E | Linux | Parallel workers; Windows file-ID dedupe; native path/ADS tests |
| Encrypted quarantine, journal, verify, restore, purge | `TESTED` | `quarantine.rs`, 15 tests | Linux | NTFS no-clobber, ADS, ACL, power-loss, DPAPI key wrapping |
| Ed25519 threat DB, anti-rollback, revocation, atomic install | `TESTED` | `threatdb.rs` | Linux | Production key ceremony, HSM, rotation, HTTPS distribution |
| RansomShield scoring, decoys, response policy | `TESTED` (decisions) | `ranshield.rs` | Linux | ETW sensor, enforcement, real false-positive data |
| Local HTTP/JSON daemon, CLI, auth, readiness gate | `TESTED` | `litric-service`, CLI E2E | Linux | SCM service, named pipe, Windows ACL, UI |
| SafeOS host facts, risk, fail-closed policy, broker, journal, `.wsb` | `TESTED` / `PARTIALLY_IMPLEMENTED` | `litric-safeos` | Linux | Native launch and guest boundary; Hyper-V/gateway absent |
| SafeOS build lifecycle allowlist | `TESTED` (portable) | `model.rs`, lifecycle tests | Linux | Native execution on each declared build/edition |
| Authenticode trust plumbing (`safeos_assess`) | `TESTED` (portable); native `UNPROVEN` | `litric-service/src/lib.rs`, `api.rs`, API tests | Linux; Windows target compiles | Native `WinVerifyTrust` execution and certificate matrix |
| Native Windows runtime, installer, UI, ETW/AMSI/WFP, minifilter, ELAM/PPL/WSC | `NOT_IMPLEMENTED` / `BLOCKED` | `docs/STATUS.md` | — | Whole product layer; external signing/partner gates |

### 4.2 Critical audit findings

1. **The product is not installable.** There is no installer, SCM service, native UI, or signed binary distribution. A user can build and run a CLI/daemon, not install protection. `[FACT]`
2. **The Windows claim is not native.** Wine 11.21 is useful ABI evidence, but not Windows 11/NTFS/Sandbox evidence. The repository says this correctly; the blueprint must preserve it. `[FACT]`
3. **No enforcement exists.** RansomShield actions are requests; there is no minifilter, process suspension, network isolation, or pre-write blocking. `[FACT]`
4. **No Windows sensor exists.** ETW, AMSI, WFP, process/file provenance, and event-loss accounting are planned, not implemented. `[FACT]`
5. **Build acceptance is lifecycle-driven (resolved in this pass).** `Readiness` no longer uses a bare 22000 floor. One `WINDOWS_11_RELEASES` table supplies build and edition end dates, and `Readiness::evaluate_at` takes an injectable date. A 24H2 Home/Pro report on 2026-11-03 is rejected with the end-of-support date; 25H2 and 26H2 are accepted. Exact tests: `model::tests::supported_25h2_and_26h2_builds_are_accepted`, `model::tests::expired_24h2_is_rejected_with_lifecycle_reason`, `model::tests::enterprise_24h2_uses_its_own_end_date`, `model::tests::unknown_build_is_not_accepted_by_a_numeric_floor`. Native execution on those builds remains `UNPROVEN`. `[FACT]` `[S1]`
6. **Signature trust is verifier-driven (resolved in this pass).** `safeos_assess` no longer hard-codes `signature_chain_valid: false`; it consumes `SignatureVerifier`, whose production implementation calls `WinVerifyTrust` on Windows. Tests inject a deterministic verifier, so the documented trusted-allowlist path is reachable: `api::tests::safeos_assess_trusts_an_allowlisted_chain_valid_entry` yields `trusted`, while `api::tests::safeos_assess_does_not_trust_tampered_or_unsigned_input` does not. Native `WinVerifyTrust` execution remains `UNPROVEN`. `[FACT]`
7. **The development API is not a production boundary.** It uses loopback HTTP and a bearer-token file; the token gets POSIX `0600` only on Unix. Windows ACLs, named pipes, and service identity are not implemented. `[FACT]`
8. **Parsing runs in-process.** Rust and bounds-checked readers reduce memory-safety risk, but a parser logic bug or resource exhaustion still affects the daemon. Production needs parser workers with job-object limits and no network. `[JUDGMENT]`
9. **No production content or key.** The distributed DB has rules only; `dev_signing_key()` is a public fixture key; hash reputation is intentionally zero. `[FACT]`
10. **The security claim is honest but incomplete.** The engine says `Unknown` instead of `Clean`; that is a strength, but it makes UX, support, and customer expectations harder. `[JUDGMENT]`

### 4.3 What the repository proves

- The original engine is not a mock-up and has meaningful tested behaviour. `[FACT]`
- Transactional quarantine and crash reconciliation are designed with data preservation as a first principle. `[FACT]`
- The project has unusually strong status discipline for an early product. `[JUDGMENT]`
- The current test suite is repository evidence, not independent validation. `[FACT]`

### 4.4 Portable correctness evidence from this pass

| Defect | Change | Exact test evidence | Remaining limit |
|---|---|---|---|
| `safeos_assess` hard-coded `signature_chain_valid: false`, so the `Trusted` branch was unreachable | Added `SignatureVerifier`/`SignatureTrust`; `safeos_assess` derives the flag from the verifier; production uses `WinVerifyTrust`, tests inject a deterministic verifier | `api::tests::safeos_assess_trusts_an_allowlisted_chain_valid_entry`; `api::tests::safeos_assess_does_not_trust_tampered_or_unsigned_input`; `risk::tests::validated_chain_plus_allowlist_is_trusted`; `risk::tests::unvalidated_signature_never_grants_trust` | Native `WinVerifyTrust` execution and a signed/tampered/revoked certificate matrix are not run in this environment; the Windows target compiles |
| `MIN_WINDOWS_BUILD = 22000` accepted 24H2 after end of support and rejected nothing by lifecycle | Replaced the bare floor with `WINDOWS_11_RELEASES` (build, Home/Pro end, Enterprise/Education end); `Readiness::evaluate_at` is deterministic and tests inject dates | `model::tests::supported_25h2_and_26h2_builds_are_accepted`; `model::tests::expired_24h2_is_rejected_with_lifecycle_reason`; `model::tests::enterprise_24h2_uses_its_own_end_date`; `model::tests::unknown_build_is_not_accepted_by_a_numeric_floor`; `api::tests::safeos_assess_surfaces_lifecycle_expired_build` | Native Windows build/edition execution and LTSC edge cases remain open; no Windows host is used |

**Production wiring:** `AppState::new` installs `PlatformSignatureVerifier`; only tests call `AppState::new_with_verifier`. The trusted branch is therefore reachable outside test injection on Windows, although native `WinVerifyTrust` execution remains `UNPROVEN`. `[FACT]`

**Run:** `cargo test --workspace` — **210 passed, 0 failed** on Linux after these changes. `cargo check -p litric-service --target x86_64-pc-windows-gnu` also succeeds; this is compile evidence, not native execution. `[FACT]`

---

## 5. Market and competitor matrix

### 5.1 Market split

Consumer antivirus and enterprise EDR/XDR are different markets with different buying centres, telemetry, deployment, and evidence. They must not be combined into one ranking. `[JUDGMENT]`

| Market | Buyer | What wins | What Litric lacks today |
|---|---|---|---|
| Consumer AV | Household/user | Trust, default-on protection, low false positives, price, brand, support | Installer, UI, real-time enforcement, content, lab history |
| Prosumer/creator | Individual/small studio | File safety, performance, recovery, clear explanations | Recovery product, installer, support, customer proof |
| SMB | Owner/IT generalist | Easy deployment, policy, reporting, support | Fleet plane, MSI, RBAC, SLA |
| Enterprise EDR/XDR | Security team/procurement | Telemetry, detection/response, integrations, governance, services | ETW/EDR plane, multi-tenancy, SIEM, certifications |
| MSSP | Service owner | Multi-tenancy, API, delegation, margin | Everything enterprise, plus partner model |

### 5.2 Competitor map without fabricated rankings

AV-Comparatives’ February–May 2026 consumer test included 20 products, including Microsoft Defender, Bitdefender, ESET, Malwarebytes, McAfee, Norton, Sophos, and others, against 400 cases on Windows 11 x64. `[SOURCE]` `[S10]` This proves the **test landscape**, not a Litric position. No Litric lab score exists. `[UNKNOWN]`

| Product/group | Market role | Relevant strength to respect | Litric implication | Evidence limit |
|---|---|---|---|---|
| Microsoft Defender | Default Windows AV + enterprise security | OS integration, default distribution, real-time protection | Baseline and coexistence partner; not a UI skin | No head-to-head run; behaviour varies by edition/config `[S7]` |
| Bitdefender / ESET / G DATA / Kaspersky | Consumer suites with layered protection | Mature content, behaviour, brand, lab participation | Do not compete on “more features” at launch | No ranking or score used here `[S10]` |
| Malwarebytes | Consumer remediation/second opinion | Remediation brand and simplicity | A second-opinion wedge is credible only with better evidence/recovery | No independent comparison in this run |
| Norton / McAfee / Sophos / Trend Micro | Broad consumer/SMB suites | Distribution, suites, support, backup/identity bundles | Bundle pressure; Litric must be sharply differentiated | No pricing or capability audit in this run |
| CrowdStrike / SentinelOne / Microsoft Defender for Endpoint | Enterprise EDR/XDR | Telemetry, response, integrations, services | Litric has no EDR plane; do not enter enterprise early | Separate market; not comparable to consumer AV `[S12]` |
| Free/OS built-ins | “Good enough” baseline | Zero price, zero install, default | Litric must justify a new install with a job Defender does not do well for this buyer | Customer evidence missing `[UNKNOWN]` |

### 5.3 Opportunity hypotheses

- `[HYPOTHESIS]` A segment will pay for **evidence and recovery** rather than another detection percentage.
- `[HYPOTHESIS]` “Unknown is not clean” can be a trust differentiator if the UI explains it without alarming users.
- `[HYPOTHESIS]` Coexistence with Defender is easier to sell than replacement, especially before WSC/MVI.
- `[HYPOTHESIS]` Small studios with valuable project files are a better beachhead than consumers or enterprises.
- `[UNKNOWN]` Price, willingness to pay, churn, support cost, and channel economics.

**Conclusion:** Litric cannot win a feature-count or detection-score war at launch. It can win a narrow trust/recovery job if it proves the installable product, recovery path, and false-positive economics. `[JUDGMENT]`

## 6. Customer and problem matrix

| Segment | Job to be done | Pain today | Purchase driver | Requirements | Adoption barrier | Evidence |
|---|---|---|---|---|---|---|
| Consumer | Stay safe without thinking about security | Alerts are confusing; false positives; unknown files | Trust, price, low impact | Installer, UI, default protection, support | Defender is “good enough”; Litric has no real-time layer | `[UNKNOWN]` |
| Prosumer/creator | Protect project files and recover from ransomware | Backups are separate; AV says “clean” without evidence; recovery is manual | File integrity, recovery, performance | Explainable verdicts, quarantine/restore, protected-folder versioning, low overhead | Must prove recovery under real failure | `[HYPOTHESIS]` |
| Small studio/SMB (5–50) | Deploy and manage without a security team | No visibility; ransomware recovery is ad hoc | Simple install, policy, support, proof | MSI, central settings, audit, support | No fleet plane or SLA; buying risk | `[UNKNOWN]` |
| Enterprise | Detect, investigate, respond, govern | EDR data volume; integration and staffing | Evidence, integrations, RBAC, SLA | ETW/EDR, SIEM, tenancy, certifications | Years of platform work; not credible now | `[UNKNOWN]` |
| MSSP | Operate protection across customers | Multi-tenancy and margin | API, delegation, scalable ops | Everything enterprise + partner model | No platform | `[UNKNOWN]` |

### Beachhead decision

**Primary beachhead:** prosumer/creator and small studios with high-value local files, Windows 11 Pro/Enterprise/Education, 16 GB+ RAM, and a willingness to pay for recovery. **Secondary:** small teams that already use Defender and want a second opinion. `[JUDGMENT]` `[ASSUMPTION]`

Why not consumer first: consumer AV requires always-on protection, massive distribution, low-cost support, and brand trust that Litric does not have. Why not enterprise first: no EDR plane, fleet management, tenancy, or certifications. `[JUDGMENT]`

Customer discovery required before pricing: 12–15 interviews across the two segments; 3–5 design partners; test the recovery promise with real (benign) file-loss scenarios; measure willingness to install a second product alongside Defender. `[TARGET]`

---

## 7. Product thesis and editions

### One-sentence thesis

**For Windows 11 prosumers and small teams who cannot afford to lose project files or trust a verdict they cannot inspect, Litric is a local-first file-trust and recovery layer that explains its evidence, quarantines transactionally, and restores safely — while coexisting with Microsoft Defender instead of pretending to replace it.** `[JUDGMENT]`

### Editions

| Edition | Promise | Included | Explicit limits | Gate |
|---|---|---|---|---|
| **Litric Core (free)** | Scan, understand, quarantine, restore | On-demand scan, PE/rules/heuristics, evidence report, encrypted vault, signed rules, CLI/UI | Not real-time protection; `Unknown` is normal; no hash feed | G1 + G2 + G5 |
| **Litric Recovery (paid)** | Detect suspicious file activity and recover selected folders | ETW-based monitoring, RansomShield alerts, versioned backup of selected folders, guided restore, support | Not pre-write blocking; not a backup replacement; not primary AV | G3 + G4 + G5 |
| **Litric Business (later)** | Managed protection for small teams | Fleet policy, central quarantine, audit, RBAC, SIEM/API, MSI | No enterprise EDR claim until telemetry/response is proven | G6+ |
| **Litric SafeOS (research/add-on)** | Run unknown/high-risk apps in isolation | Explicit launch, Windows Sandbox, broker, fail-closed policy | Pro/Enterprise/Education only; no Home; no universal Hyper-V/gateway | Native guest proof |

### What Litric must not become

- A feature-count antivirus with no enforcement.
- A Defender skin or a renamed third-party engine.
- A kernel-first product that cannot be signed or tested.
- A cloud upload service with a local UI.
- An “AI detection” brand with no model, data, or evaluation.
- A universal sandbox that silently runs unknown apps on the host.

### Proof obligations before any paid launch

1. Native Windows install/uninstall/rollback on declared builds.
2. A tested recovery path with no data loss in safe simulations.
3. A false-positive baseline and a user-facing correction flow.
4. A production signing/key/update path.
5. Independent evidence or a precise, limited claim that does not imply it.

---

## 8. Capability map and prioritisation

Scores are `[JUDGMENT]` on a 1–5 scale; weighted score uses the prompt’s weights (security 20, customer 20, differentiation 15, feasibility 15, evidence 10, leverage 10, commercial 10). Scores support, but do not replace, vetoes.

| ID | Capability | Role | Status | Priority | Score | Dependencies |
|---|---|---|---|---|---:|---|
| C1 | Portable detection engine (PE, rules, heuristics, verdict) | Detection | `TESTED` | `NOW` | 4.7 | Corpus, FP baseline |
| C2 | Scan orchestration, budgets, cache, accounting | Detection | `TESTED` | `NOW` | 4.4 | Worker pool, Windows file IDs |
| C3 | Quarantine vault and lifecycle | Containment/recovery | `TESTED` (Linux) | `NOW` | 4.8 | NTFS proof, DPAPI |
| C4 | Signed threat database and update verifier | Content integrity | `TESTED` | `NOW` | 4.5 | Production key/HSM, HTTPS |
| C5 | Local service/API/CLI | Control plane | `TESTED` (dev) | `NOW` | 3.8 | SCM, named pipe, ACL |
| C6 | Native installer, service host, WinUI 3 shell | Product | `NOT_IMPLEMENTED` | `NOW` | 4.9 | Native Windows lab |
| C7 | ETW/AMSI/WFP user-mode visibility | Telemetry/network | `NOT_IMPLEMENTED` | `NEXT` | 3.9 | Native Windows lab |
| C8 | RansomShield sensor + recovery vault | Detection/recovery | `PARTIALLY_IMPLEMENTED` | `NEXT` | 4.6 | ETW, versioned backup |
| C9 | SafeOS explicit isolation | Isolation | `PARTIALLY_IMPLEMENTED` / `UNPROVEN` | `LATER` | 2.8 | Native guest proof |
| C10 | Hyper-V backend + gateway | Isolation/network | `NOT_IMPLEMENTED` | `RESEARCH` | 1.8 | WFP/WinNAT, guest tests |
| C11 | Enterprise fleet/RBAC/SIEM | Commercial | `NOT_IMPLEMENTED` | `LATER` | 2.0 | C5/C7, support |
| C12 | Kernel minifilter | Enforcement | `BLOCKED` | `NO-GO` until MVI | 3.0 | Signing, native test, WHQL |
| C13 | ELAM/PPL/WSC | Protected service/integration | `BLOCKED` | `NO-GO` until MVI | 3.2 | MVI, WHQL, shipping product |
| C14 | AI/ML enforcement | Detection | `NOT_IMPLEMENTED` | `RESEARCH`/no enforcement | 1.5 | Data, model, evaluation |
| C15 | Cloud reputation/telemetry | Detection/ops | `NOT_IMPLEMENTED` | `RESEARCH` | 1.8 | Consent, privacy, cost |

### Key capability specifications

| Capability | Sensor/evidence | Control point | Failure behaviour | Acceptance evidence | Owner |
|---|---|---|---|---|---|
| C1 Detection | File bytes, PE structure, signature blob, rules, heuristics | Verdict only | Parse failure → report with notes; never `Clean` | Labelled corpus, FP/FN, native parser tests | Litric |
| C2 Scan | Walker, cache, budgets | None (read-only) | Unreadable/skipped separate; unknown ≠ clean | Throughput, memory, Windows paths/ADS | Litric |
| C3 Quarantine | Encrypted entry, authenticated header, journal | Move/restore/purge | Verify first; no-clobber; preserve ambiguous data | Native NTFS lifecycle, power-loss, DPAPI | Litric |
| C4 Update | Signed manifest, payload hash, revocation | Install/rollback | Keep last working; no rollback below minimum | Key ceremony, rotation, offline update | Litric |
| C5 Service | Named pipe, caller SID, policy | Scan/vault/update coordination | Degraded state visible; no silent fallback | ACL tests, service crash recovery | Litric |
| C6 UI/installer | Service API, no mock data | User actions | Show limited/unknown; no green shield | Install/upgrade/repair/uninstall matrix | Litric |
| C7 Telemetry | ETW/AMSI/WFP | Detection/network policy only where supported | Event loss visible; no enforcement claim | Loss accounting, IPv4/IPv6/VPN/WSL2 tests | Litric |
| C8 Recovery | ETW + versioned backup | Snapshot/restore, containment request | Never delete source; refuse overwrite; preserve evidence | Safe ransomware simulations, RPO/RTO | Litric |
| C9 SafeOS | Host facts, risk, broker, `.wsb` | Explicit launch | Deny if unavailable; never host fallback | Native launch/guest boundary | Litric + Microsoft |

---

## 9. Architecture blueprint

### 9.1 Principles

- Detection stays in the portable Rust core; Windows is a sensor/actuator, not a second detection engine.
- Control plane is separate from data plane; UI is unprivileged.
- No kernel component until signing, native testing, and maintenance are real.
- Every privileged operation is explicit, auditable, and recoverable.
- `Unknown` and degraded states are first-class.
- Local-first; cloud is optional and off by default.

### 9.2 Target topology

```text
[WinUI 3 UI] [CLI]
       \       /
        \     /  named pipe (production) / loopback HTTP (dev only)
         [litric-svc: SCM service]
           |-- scan orchestrator --> [parser worker: restricted token + job limits]
           |-- quarantine vault (privileged)
           |-- content/update verifier
           |-- RansomShield correlation
           |-- recovery coordinator --> versioned backup + USN/ETW
           |-- SafeOS broker --> Windows Sandbox (.wsb)
           `-- optional cloud: OFF by default

Current tree: no SCM host, no named pipe, no parser worker, no ETW/AMSI/WFP,
no minifilter. The diagram is target-state, not implemented state.
```

### 9.3 Components and boundaries

| Component | Runs as | Trust boundary | Responsibility | Current state |
|---|---|---|---|---|
| WinUI 3 shell | User | Untrusted UI → service | Status, scan, quarantine, recovery, explanations | `NOT_IMPLEMENTED` |
| CLI | User | Same as UI | Scriptable operations/testing | `TESTED` (dev API) |
| `litric-svc` | LocalSystem (proposed) | Privileged broker | Sensors, vault, update, recovery, policy | `NOT_IMPLEMENTED` |
| Parser worker | Restricted token/job | Untrusted input | Parse untrusted bytes with CPU/memory/time caps | `PROPOSED` |
| Portable core | In worker/service | Pure logic | Detection, rules, quarantine format, RansomShield | `TESTED` |
| SafeOS broker | Service | Host/guest boundary | Stage files, launch, journal, cleanup | `PARTIALLY_IMPLEMENTED` |
| Windows Sandbox | Guest | Microsoft hypervisor | Disposable isolation | `UNPROVEN` |
| Cloud | External | Consent boundary | Optional reputation/telemetry | Not built |

### 9.4 Interfaces and event envelope

Service API: versioned JSON over named pipe; commands for status, scan, analyze, quarantine, restore, settings, history, RansomShield, SafeOS. The current loopback HTTP API remains a development/test transport only. `[FACT]`

Minimum event fields:

`event_id, schema_version, timestamp, host_id, boot_id, sequence, source, category, subject, action, object, correlation_id, confidence, privacy_class, evidence_ref, dropped_before`

Rules:

- `sequence` is monotonic per boot; `dropped_before` makes loss visible.
- Missing telemetry is `UNKNOWN`, not benign.
- Content and metadata have separate privacy classes.
- Event schema and pipe protocol are versioned; old clients fail closed.

### 9.5 Critical flows

1. **Scan:** UI → service → parser worker → verdict/evidence → history. Parser crash yields `UNKNOWN`, not `CLEAN`.
2. **Quarantine/restore:** verify source hash → encrypt temp → verify temp → index → remove source → journal; restore refuses occupied destination. `[FACT]`
3. **Update:** fetch signed manifest → verify length/hash/signature/key → check `min_engine`/rollback → atomic install → retain `.prev`. `[FACT]`
4. **Ransomware:** ETW events → correlation → alert/snapshot request; enforcement only if a supported control point exists. No control point = no block claim. `[FACT]`
5. **Isolation:** risk assessment → fail-closed policy → `.wsb` → Sandbox launch → journal → cleanup. Unsupported = deny, never host fallback. `[FACT]`

### 9.6 Failure matrix

| Failure | Required behaviour | User-visible state |
|---|---|---|
| Parser crash/hang | Kill worker, keep service alive, mark file unknown | “Analysis unavailable” |
| Service crash | Recover journal, no duplicate destructive action | Degraded/restarting |
| Event loss | Surface gap; do not infer benign | Telemetry degraded |
| Vault full/corrupt | Preserve source; refuse destructive action | Quarantine error |
| Restore target exists | Refuse before writing | Conflict, no overwrite |
| Update invalid | Keep last signed working version | Update failed, old version active |
| Sandbox unavailable | Deny launch | Unsupported/blocked |
| UI disconnect | Service continues safe operations; no fake status | Reconnect required |
| Defender conflict | Do not modify Defender; report coexistence state | Limited/unsupported |

---

## 10. Windows feasibility matrix

### 10.1 Lifecycle target

The executable source of truth is `WINDOWS_11_RELEASES` in `crates/litric-safeos/src/model.rs`; `lifecycle_status` compares the report to the relevant edition channel and `Readiness::evaluate_at` takes the date. A build absent from this table is rejected even when its number is above the old 22000 floor. `[FACT]`

| Build | Home/Pro end of updates | Enterprise/Education end | Decision |
|---|---|---|---|
| 24H2 | 2026-10-14 | 2027-10-12 | Home/Pro rejected after 2026-10-14; Enterprise/Education accepted while in its own window `[SOURCE]` `[S1]` `[S15]` |
| 25H2 | 2027-10-12 | 2028-10-10 | Primary test target; accepted on 2026-11-03 `[SOURCE]` `[S1]` `[S15]` |
| 26H1 | 2028-03-14 | 2029-03-13 | Separate device-scoped validation `[SOURCE]` `[S1]` `[S15]` |
| 26H2 | 2028-10-10 | 2029-10-09 | Primary test target; accepted on 2026-11-03 `[SOURCE]` `[S1]` `[S15]` |

### 10.2 Feasibility

| Capability | Mechanism | Editions/builds | Privilege/signing | Coexistence/limits | State | Fallback |
|---|---|---|---|---|---|---|
| Static scan/PE | User-mode Rust parser | Windows 11 x64 | None | Untrusted input; parser isolation needed | `TESTED` Linux; Windows `UNPROVEN` | Refuse/unknown |
| Quarantine/restore | User-mode file APIs | NTFS/ReFS; declared builds | Service or user | No-clobber/ADS/ACL; native proof missing | `TESTED` Linux; Windows `UNPROVEN` | Preserve source |
| SCM service | Win32 service | Windows 11 | Service account; signing | Recovery, least privilege, uninstall | `NOT_IMPLEMENTED` | Foreground daemon |
| Named-pipe IPC | Win32 pipes + ACL | Windows 11 | Caller SID | Same-user malware; no remote pipes | `PROPOSED` | Dev loopback HTTP only |
| ETW process/file | User-mode consumer | Windows 11 | SYSTEM/admin for kernel providers | Notification, not blocking; loss | `NOT_IMPLEMENTED` | No telemetry claim |
| AMSI provider | In-process DLL | Apps that opt in | Signing/registration | Script/.NET only; not native PE | `NOT_IMPLEMENTED` | Static scan |
| WFP app policy | User-mode filter API | Windows 11 | Admin | VPN/WSL2/Docker/NAT conflicts | `NOT_IMPLEMENTED` | No network claim |
| Minifilter | Kernel driver | Windows 11 | Microsoft signature, WHQL path | Block-before-execute/write; crashes/performance | `BLOCKED` | No enforcement claim |
| ELAM/PPL/WSC | Boot/protected service | Windows 11 | MVI + WHQL + certification | Circular late gate | `BLOCKED` | Companion only |
| Windows Sandbox | `.wsb` + WindowsSandbox.exe | Pro/Enterprise/Pro Education/SE/Education; **not Home** | User/admin feature | 4 GB RAM, 1 GB disk, 2 cores; network/clipboard default on; one instance | `PARTIALLY_IMPLEMENTED`; guest `UNPROVEN` | Deny |
| Hyper-V/gateway | Hyper-V + WFP/WinNAT | Supported editions | Admin | WinNAT single network; conflicts | `NOT_IMPLEMENTED` | Offline sandbox only |
| VSS recovery | VSS snapshots | Windows editions | Admin | Attacker can delete shadows; not a backup | `NOT_IMPLEMENTED` | Independent versioned backup |
| Installer/update | Signed MSI/EXE + service | Windows 11 | EV/Trusted Signing | Rollback/repair/uninstall | `NOT_IMPLEMENTED` | Portable CLI only |
| UI | WinUI 3 | Windows 11 | Unsigned dev / signed release | Accessibility/performance | `NOT_IMPLEMENTED` | CLI |

### 10.3 Windows evidence gates

- **W0:** No Windows support claim without native Windows 11 x64 evidence on the exact build/edition.
- **W1:** No driver claim without a signed loadable package and native tests; never disable signature enforcement.
- **W2:** No ELAM/PPL/WSC claim without MVI eligibility, WHQL/partner path, and evidence.
- **W3:** No real-time protection claim without an enforceable control point and Defender coexistence tests.
- **W4:** No universal SafeOS/Hyper-V claim; prove edition, hardware, resource, network, and fallback.
- **W5:** No network-control claim without IPv4/IPv6/DNS/VPN/WSL2/Docker/NAT leak tests and rollback.
- **W6:** No “secure by design” claim without a product threat model, security review, and residual-risk disclosure.

### 10.4 The MVI circularity

MVI requires a **commercially available** security solution with **real-time protection**, independent lab certification within the last 12 months, Trusted Signing, and program agreements. `[SOURCE]` `[S6]` ELAM requires MVI membership and a WHQL submission. `[SOURCE]` `[S5]` Therefore ELAM/PPL/WSC cannot be the foundation of a pre-launch product. It is a late gate reached only after shipping a credible real-time product — which itself is blocked by the missing kernel enforcement. `[JUDGMENT]`

**Decision:** plan the business as a companion product unless/until an external signing/MVI path is secured. Do not schedule kernel work as an ordinary engineering task. `[JUDGMENT]`

### 10.5 Sandbox reality

- Windows Sandbox is available on Pro, Enterprise, Pro Education/SE, and Education; **not Windows Home**. `[SOURCE]` `[S2]`
- Minimums: 4 GB RAM, 1 GB free disk, 2 CPU cores; one instance at a time. `[SOURCE]` `[S3]` `[S2]`
- Defaults: networking enabled, clipboard enabled; mapped folders can be writable. Litric’s `.wsb` disables networking/clipboard/redirection and maps read-only, which is safer but still not a universal product. `[SOURCE]` `[S4]`; repo `.wsb` `[FACT]`
- The repo’s 10 GB free-disk threshold is a deliberate safety margin above Microsoft’s 1 GB minimum, not a platform requirement. `[JUDGMENT]`

## 11. Threat coverage matrix

Coverage labels: `PREVENTION`, `DETECTION`, `TELEMETRY_ONLY`, `WINDOWS_MITIGATION`, `PARTIAL`, `NOT_COVERED`, `NOT_TESTED`. Telemetry is not detection; detection is not prevention. `[JUDGMENT]`

| Scenario | ATT&CK | Sensor/evidence today | Role | Current status | Required proof |
|---|---|---|---|---|---|
| Commodity PE loader/dropper | T1204, T1105 | PE structure, imports, strings, rules, heuristics | Detection | `PARTIAL`; synthetic tests | Labelled corpus, FP/FN, native tests |
| EICAR self-test | — | Authored rule | Detection | `TESTED` | Keep as self-test only |
| Encoded PowerShell | T1059.001 | Encoded-content heuristics | Detection (flag only) | `PARTIAL`; no decoder | Decoder with instruction budget, tests |
| Office macro delivery | T1204.002 | OOXML/OLE2 container detection | Detection (container only) | `PARTIAL`; no VBA extraction | Safe parser, macro extraction, corpus |
| Archive-contained malware | T1027 | Format identification only | Detection (container only) | `NOT_COVERED` for members | Recursive extraction + bomb limits |
| Ransomware encryption | T1486 | RansomShield event scoring (simulator) | Detection/recovery request | `PARTIAL`; no ETW, no enforcement | ETW sensor, safe simulation, recovery |
| Shadow-copy deletion | T1490 | Command-line/string signal | Detection | `PARTIAL`; definitive signal tested | Real telemetry, FP validation |
| Process injection | T1055 | None | — | `NOT_COVERED`; needs memory/PPL telemetry | Native sensor; PPL gate |
| Persistence/service/task | T1547 | None | — | `NOT_COVERED` | ETW/registry telemetry, correlation |
| C2/network | T1071 | None | — | `NOT_COVERED` | WFP/DNS telemetry, leak tests |
| Vulnerable/unsigned driver | T1068 | PE driver flag only | Detection (limited) | `PARTIAL` | Driver inventory/reputation, native data |
| Credential access | T1003 | None | — | `NOT_COVERED` | ETW/AMSI/EDR plane; not v1 |
| Unknown app execution | T1204 | SafeOS risk + fail-closed policy | Isolation decision | `TESTED` on Linux; guest `UNPROVEN` | Native launch + guest boundary |

**What the current engine does not provide:** hash reputation at scale, archive recursion, macro extraction, emulation/unpacking, de-obfuscation, memory scanning, process provenance, network enforcement, or kernel blocking. These are not small gaps; they are separate product layers. `[FACT]`

---

## 12. Security and privacy threat model

### 12.1 Assets and actors

Assets: user files, credentials, backups, quarantine vault, update keys, signing keys, telemetry, product reputation, availability.

Actors: commodity malware, ransomware crews, targeted attackers, malicious insiders, supply-chain attackers, and users who make unsafe decisions. `[JUDGMENT]`

Surfaces: untrusted file parsers, local IPC, service privilege, UI, quarantine vault, update channel, installer, SafeOS guest boundary, optional cloud.

### 12.2 Abuse cases and controls

| Abuse case | Mitigation | Residual risk |
|---|---|---|
| Parser RCE or resource exhaustion | Rust, bounds checks, process isolation, job limits, fuzzing, no network in parser | Logic bugs, zero-days, malformed input |
| Local IPC token theft | Production named pipe + caller SID + ACL; no token file; dev HTTP only | Same-user malware can act as user |
| Service tampering | Signed binaries, SCM recovery, least privilege, protected service only after ELAM/MVI | Admin malware can stop service without PPL |
| Quarantine key theft | DPAPI/ACL, key separation, restricted vault directory | Same-user compromise can decrypt vault |
| Update/key compromise | Offline root/HSM, signed manifests, anti-rollback, revocation, staged rollout | Key misuse before revocation |
| False positive deletes data | Verify before source removal; copy-only option; no-clobber restore; journal | User-approved purge remains irreversible |
| Sandbox escape/host leak | Microsoft hypervisor boundary; read-only mapping; networking/clipboard off | Hypervisor escape, misconfiguration |
| Telemetry/privacy breach | Local-first, no upload default, minimisation, consent, retention | Metadata can still be sensitive |
| Supply-chain compromise | SBOM, pinned deps, provenance, review, reproducible builds | Build-system compromise |
| Installer tampering | Code signing, signature verification, rollback | Stolen signing key |

### 12.3 Privacy contract

- Default: no file content leaves the device. `[FACT]`
- Optional cloud: explicit purpose, data classes, retention, deletion, residency, subprocessors, legal review.
- Hash/metadata can be sensitive; do not treat “no file upload” as “no privacy risk.” `[JUDGMENT]`
- Enterprise policy must not silently enable content upload.
- Produce a data-flow diagram and DPIA before any cloud feature.

### 12.4 Security findings that block an installer

| ID | Finding | Severity | Resolution |
|---|---|---|---|
| SEC-01 | No native Windows security test; no SCM/ACL design proven | Critical | Complete native lab and service threat model |
| SEC-02 | Parsers run in-process in the daemon | High | Parser worker isolation + fuzzing |
| SEC-03 | Dev HTTP token; Windows ACL not explicit; `0600` is Unix-only | High | Named pipe + SID/ACL; remove token file from production |
| SEC-05 | Development signing key is public | High | Production key ceremony/HSM before distribution |
| SEC-06 | No PPL/self-defence; service can be stopped by admin malware | High | Accept as residual until MVI; disclose |
| SEC-07 | No native NTFS no-clobber/ADS/power-loss proof | High | Native filesystem test matrix |
| SEC-08 | SafeOS unavailable on Home; guest runtime unproven | High | Detect and deny; no universal claim |

SEC-04 (hard-coded `signature_chain_valid`) was resolved by the verifier plumbing and its tests; native `WinVerifyTrust` execution remains part of SEC-01/G2, not a portable correctness defect.

---

## 13. Performance strategy

### Measured baseline

Release build on a 2 vCPU Linux VM, 2,000 small files, 15 rules: approximately **3,050 files/s** and **3.1 MB/s** across three runs. `[FACT]` This is not Windows, not whole-disk, and not comparable with vendor benchmarks. `[FACT]`

### Required profiles

Low-end 4C/8T with HDD and 8 GB RAM; mainstream 6C/12T SSD/16 GB; high-end 8C+/NVMe/32 GB; enterprise-managed. Record actual hardware, Windows edition/build, virtualization state, and free space; never assume the development machine. `[JUDGMENT]`

### Metrics and initial guardrails

| Metric | Initial `[TARGET]` | Method |
|---|---:|---|
| Idle CPU (service + UI) | ≤1% average on 4C/8T | 30-min WPR/Get-Counter |
| Idle working set | ≤200 MB combined | Process counters |
| Quick scan 10,000 small files | ≤60 s on SSD | Reproducible harness |
| Scan throughput | ≥1,000 files/s low-end | Same corpus/version |
| App-launch impact | ≤100 ms p95 | Controlled app launch |
| Event latency | ≤1 s p95 | Timestamped fixtures |
| Event loss | 0 silent loss; gaps reported | Sequence/dropped_before |
| Restore integrity | 100% hash match | Safe recovery suite |
| Crash/hang | 0 unhandled in defined suite | Soak + fault injection |

Targets are proposals until a baseline exists. Do not disable security controls to improve a benchmark. Test low-memory, disk-full, thermal, slow-storage, and VM contention. `[JUDGMENT]`

---

## 14. Validation and benchmark programme

### 14.1 Independent validation

| Programme | Scope | Eligibility/limitation | Use |
|---|---|---|---|
| AV-TEST | Protection, performance, usability | Participation/cost/current criteria must be confirmed | Consumer claim only after result |
| AV-Comparatives | Real-world/malware/performance/FP | 2026 test: 400 cases, Windows 11 x64, cloud allowed, not repeatable `[S10]` | Comparable consumer evidence, not a universal ranking |
| SE Labs | Endpoint protection, EAS, ransomware | Separate enterprise/EDR methodology `[S12]` | Enterprise/response evidence later |
| MITRE ATT&CK Evaluations | Adversary behaviour visibility/response | Separate methodology; not an AV score `[S13]` | EDR maturity later |
| Qualified auditor | Code, privacy, supply chain | Scope/cost unknown | Release assurance |

MVI requires certification within the last 12 months, but certification does not guarantee MVI acceptance. `[SOURCE]` `[S6]` Do not promise a lab submission before confirming eligibility, cost, and product readiness.

### 14.2 Internal reproducible benchmark

Datasets: EICAR/self-test; authored synthetic fixtures; licensed clean corpus; licensed malicious corpus; benign file-operation simulators. Record provenance, licence, version, deduplication, freshness, train/test separation, and holdout. Never embed a feed without redistribution rights. `[JUDGMENT]`

Test card: `ID | Hypothesis | Scenario | Dataset/licence | Sample size | Environment | Build | Procedure | Metrics | Acceptance | Result | Limitations | Owner | Date`.

Metrics: precision/recall, FP/FN, protection stage, detection/containment latency, files affected, recovery integrity, event loss, CPU/RAM/I/O/network, boot/app-launch, scan throughput, crash/hang/BSOD, update/rollback, compatibility. Separate online/offline, cold/warm cache, idle/active, hardware tiers, editions. `[JUDGMENT]`

### 14.3 Release gates

- **G0 Evidence:** scope, audit, sources, threat model, no-gos accepted.
- **G1 Core:** parser isolation, fuzzing, corpus/FP baseline, performance baseline.
- **G2 Native Windows:** native execution on 25H2/26H2; NTFS/ADS/crash tests; no Wine substitution.
- **G3 Protection:** enforceable control point, Defender coexistence, event-loss test. If no enforcement, G3 is not met.
- **G4 Recovery:** tested restore, safe ransomware simulations, zero unrecoverable data loss in the defined suite, RPO/RTO evidence.
- **G5 Product:** installer, UI, upgrade/rollback/repair/uninstall, accessibility, support.
- **G6 Commercial:** licensing, privacy, editions, support economics, incident response.
- **G7 Validation:** independent evidence and release review; claims match results.

A gate passes only with evidence. A document, compile, Wine run, or mock UI does not pass a gate. `[JUDGMENT]`

---

## 15. Commercial and operational plan

### Licensing and content

- Proprietary product; third-party crates are permissive (MIT/Apache-2.0/BSD) and unmodified. `[FACT]`
- No ClamAV, no YARA engine/rules, no commercial feed embedded. `[FACT]`
- YARA remains a `RESEARCH` option only; verify exact version licence, compatibility, performance, and redistribution before adoption. `[JUDGMENT]`
- MITRE ATT&CK IDs are identifiers under their terms; EICAR is the self-test. `[FACT]`
- Any corpus/feed requires written redistribution and commercial-use clearance. `[JUDGMENT]`

### Privacy and enterprise operations

Local-first; no default upload; consent and data-flow documentation; retention/deletion; DPIA where required. Enterprise later: tenant isolation, RBAC, SSO/MFA, audit, SIEM/API, DPA, residency. Do not claim enterprise readiness before those exist. `[JUDGMENT]`

### Release and support

- Signed per-machine installer with SCM service; MSIX is not the primary path for a service/kernel product without a verified packaging design. `[JUDGMENT]`
- SBOM, dependency scanning, build provenance, separated signing keys, reproducible release records.
- PSIRT, vulnerability disclosure, incident response, revocation, rollback, and a bad-signature/bad-update playbook.
- Critical security updates are never paywalled.
- Support must handle false positives, quarantine recovery, install/rollback, and data-loss reports.
- Uninstall: remove product components, preserve user files; quarantine disposition requires explicit user choice; never delete unrelated data.

### Commercial hypotheses

`[HYPOTHESIS]` A paid Recovery edition can sustain the business before full AV capabilities exist. `[UNKNOWN]` Price, conversion, churn, support cost, channel, and willingness to pay. No prices or market size are asserted here.

---

## 16. Prioritised roadmap

No calendar promises. Work is ordered by dependencies and exit evidence. `NOW` means the next critical path, not “easy.”

| Stage | Goal | Deliverables | Dependencies | Exit evidence | Explicit non-goals |
|---|---|---|---|---|---|
| 0. Evidence and scope | Make decisions auditable | This blueprint, native lab plan, corpus/licence plan, customer interviews, no-go register | Owner decisions | G0 accepted; evidence gaps owned | Feature build |
| 1. Core hardening | Make the portable engine trustworthy | Parser workers, fuzzing, archive/script limits, labelled corpus, FP baseline, performance baseline | G0 | G1; reproducible tests | Windows claims |
| 2. Native Windows runtime | Prove the product runs on declared builds | Build/test matrix, SCM service, named pipe, NTFS/ADS/crash tests, installer skeleton | Native lab; G1 | G2; W0 for tested surfaces | Real-time enforcement |
| 3. Product experience | Make it installable and usable | WinUI 3, onboarding, verdict/evidence UX, accessibility, upgrade/rollback/repair/uninstall | Stage 2 | G5; install matrix | Fleet/enterprise |
| 4. User-mode visibility | Add honest observability | ETW process/file, AMSI provider, WFP policy, event-loss accounting | Stage 2 | G3 partial; loss/attribution tests | Blocking claims |
| 5. Recovery | Deliver the wedge | Protected-folder versioning, RansomShield sensor, safe simulation, restore verification, RPO/RTO | Stages 2–4 | G4; zero unrecoverable loss in suite | Universal pre-write blocking |
| 6. Commercial launch | Operate the product | Production keys, signed updates, support, privacy, licensing, incident response | G2–G5 | G6; launch review | Unsupported superiority claims |
| 7. Independent validation | Earn external evidence | Lab/auditor engagement, compatibility/performance matrix, published limitations | Shipping product | G7; published results | Marketing reinterpretation |
| 8. SafeOS | Isolate unknown/high-risk apps on supported editions | Native Sandbox verification, broker, resource governor, guest policy | Native lab; G2 | Guest boundary evidence | Universal Hyper-V/Home support |
| 9. Enterprise/kernel research | Explore later platforms | Fleet plane, EDR, driver/ELAM only if MVI path exists | G6/G7 + external eligibility | Separate go/no-go | Scheduling kernel as ordinary work |

### First three work packages

1. **WP1 Native proof:** Windows 11 25H2/26H2 lab, build/test matrix, NTFS/ADS/restore/power-loss tests, SCM/named-pipe prototype. **Exit:** W0 for tested surfaces; no claim beyond evidence.
2. **WP2 Installable skeleton:** signed development installer, service, UI shell, install/upgrade/rollback/uninstall, no fake protection state. **Exit:** a user can install, see `LIMITED`, scan, quarantine, restore, uninstall.
3. **WP3 Trustworthy core:** parser worker isolation, fuzzing, corpus/FP baseline, production key path, recovery prototype. **Exit:** G1/G4 evidence for the defined scope.

Parallelizable: corpus/licensing, customer interviews, UI design, threat model, privacy review. Not parallelizable before native proof: driver, ELAM/PPL/WSC, universal SafeOS.

---

## 17. Risk register

| ID | Risk | Severity | Likelihood | Detectability | Mitigation | Residual | Trigger |
|---|---|---|---|---|---|---|---|
| R1 | No native Windows evidence | Critical | High | High | Build native lab; W0 gate | Claims remain limited | Any Windows marketing |
| R2 | No installer/SCM/UI | Critical | High | High | WP2; install matrix | Cannot ship | Paid launch |
| R3 | No enforcement; AV claim false | Critical | High | Medium | Companion positioning; G3 gate | Limited protection | “Antivirus” claim |
| R4 | False positives/`Unknown` distrust | High | High | Medium | FP baseline, explanations, restore, support | Brand/support cost | Review spike |
| R5 | No licensed corpus/feed | High | High | Medium | Licence review, synthetic/clean corpus | Weak evidence | Lab/claim |
| R6 | MVI/ELAM/WSC circularity | Critical | High | High | Treat as external gate; no kernel schedule | No primary AV | Roadmap pressure |
| R7 | Parser RCE/resource exhaustion | High | Medium | Medium | Worker isolation, fuzzing, limits | Zero-day | Parser incident |
| R8 | Performance/compatibility | High | Medium | Medium | Profiles, soak, compatibility matrix | Uninstall | Low-end pilot |
| R9 | SafeOS not Home; guest unproven | High | High | High | Edition detection; deny; native guest proof | Limited market | Universal claim |
| R10 | Key/supply-chain compromise | High | Low | Medium | HSM, separation, SBOM, revocation | Trust damage | Key anomaly |
| R11 | False-positive data loss | Critical | Low | High | Verify-first, no-clobber, copy-only, journal | Irreversible purge | Data-loss report |
| R12 | Support economics | Medium | High | Low | Design partners, scoped support, telemetry-free operations | Margin | Renewal/support load |
| R13 | Windows lifecycle drift | Medium | Medium | High | Build allowlist, lifecycle review | Unsupported installs | New release |
| R14 | Competitor bundling | Medium | High | Medium | Narrow wedge, coexistence | Adoption | Pricing launch |

Top five: R1, R2, R3, R6, R11. These block a commercial “protection” launch; they do not block a scanner/recovery pilot. `[JUDGMENT]`

---

## 18. Architecture Decision Records

| ADR | Decision | Alternatives | Reason/evidence | Revisit trigger |
|---|---|---|---|---|
| ADR-001 | Portable Rust detection core | C/C++; platform-specific engine | Memory safety; reuse; current tests `[FACT]` | Performance/native API need |
| ADR-002 | No ClamAV backend | ClamAV/libclamav | Product rule; licence; original-engine requirement `[FACT]` | Owner reverses policy |
| ADR-003 | YARA optional, not adopted | YARA engine; authored rules | Original language; licence/compatibility risk | Clear rule-authoring need after licence review |
| ADR-004 | `Unknown` is not `Clean` | Clean-by-default | Truthfulness; current engine `[FACT]` | Customer evidence proves unusable |
| ADR-005 | User-mode first; kernel blocked | Kernel-first | Signing/MVI gates; no native test `[SOURCE]` `[S5]` `[S6]` | MVI/WHQL/native lab secured |
| ADR-006 | Encrypted journaled quarantine | Simple file move | Data preservation; tests `[FACT]` | Native NTFS proof fails |
| ADR-007 | Loopback HTTP dev only; named pipe production | HTTP production; ALPC | ACL/SID; token file risk `[FACT]` | Named-pipe prototype fails |
| ADR-008 | WinUI 3 UI (proposed) | Tauri/WebView2; WPF | Windows-native; no web attack surface | Native build/accessibility cost |
| ADR-009 | Recovery-first wedge | Full AV; enterprise EDR; SafeOS-first | Defensible with current core; enforcement blocked `[JUDGMENT]` | Customer/lab evidence changes |
| ADR-010 | SQLite metadata store (proposed) | JSON; redb | Mature local indexing; separate from vault | Native performance/integrity issues |
| ADR-011 | Parser worker isolation | In-process parsing | Blast-radius reduction | Worker overhead unacceptable |
| ADR-012 | No cloud by default | Cloud-first reputation | Privacy/local-first; no backend | Consent/privacy review approves |
| ADR-013 | No kernel until MVI/signing | Driver now | Cannot load/ship/test; unsafe fiction `[FACT]` | External gate achieved |

---

## 19. Open questions and validation plan

| ID | Question | Why it matters | Method | Success criterion | Owner |
|---|---|---|---|---|---|
| Q1 | Will prosumers/small studios pay for recovery? | Commercial thesis | 12–15 interviews; 3–5 design partners; price tests | Repeatable willingness to install/pay | Product |
| Q2 | Can recovery be delivered without kernel blocking? | Wedge feasibility | Prototype versioned backup + ETW; safe simulations | Restore integrity/RPO/RTO in suite | Engineering |
| Q3 | Is Windows 11 Home required? | Sandbox unsupported there | Segment interviews; scanner-only offer | Explicit supported-edition decision | Product |
| Q4 | Can a licensed corpus/feed be obtained? | Evidence quality | Licence review; vendor quotes | Written redistribution/eval rights | Legal |
| Q5 | Is MVI/WHQL attainable? | Kernel/primary AV path | Partner/legal inquiry; certification plan | Written eligibility/path | Business |
| Q6 | Which UI/installer stack? | Delivery | Native prototype; accessibility/performance | Install matrix passes | Engineering |
| Q7 | What FP rate is acceptable? | Trust/support | Labelled clean corpus; user studies | Defined threshold + support plan | Product/Eng |
| Q8 | Is enterprise demand real? | Roadmap | 5–8 enterprise/MSSP interviews | Evidence of budget/integration need | Business |

These are genuinely unresolved. Do not convert them into roadmap promises. `[JUDGMENT]`

---

## 20. Final recommendation

### Strongest coherent strategy

Build **Litric Core + Litric Recovery** for Windows 11 prosumers and small studios, as a local-first companion to Microsoft Defender. Win on **truthful evidence, transactional quarantine, and tested recovery**, not on an unearned detection or antivirus claim. `[JUDGMENT]`

### First three work packages

1. **Native Windows proof** (G2): native 25H2/26H2 tests, NTFS/ADS/restore/power-loss, SCM/named pipe.
2. **Installable skeleton** (G5): signed development installer, service, WinUI 3, install/rollback/uninstall, `LIMITED` state.
3. **Trustworthy core + recovery** (G1/G4): parser isolation, fuzzing, corpus/FP baseline, production key path, versioned backup/restore.

### Defer or reject

- **Defer:** enterprise fleet, EDR, cloud reputation, Hyper-V gateway, AI/ML enforcement.
- **Reject now:** kernel driver, ELAM/PPL/WSC, universal SafeOS, “primary antivirus,” “real-time protection,” unlicensed feeds, default cloud upload.
- **Do not ship:** a green shield without enforcement, a quarantine that can lose the only copy, or a recovery feature without a restore test.

### Confidence

- Portable core evidence: **medium-high**.
- Native Windows product readiness: **low** until G2.
- Commercial thesis: **low** until customer evidence.
- Recovery wedge: **medium** as a hypothesis, **unproven** as a business.

### What would change the decision

Native Windows evidence; a tested restore path; customer willingness to pay; licensed corpus; an attainable signing/MVI path; independent lab results. If native Windows cannot be tested, Litric should remain a portable scanner/CLI research project and must not be sold as protection. `[JUDGMENT]`

---

## Appendix A — Review passes and pre-mortem

### Security review

| Finding | Resolution | Status |
|---|---|---|
| In-process parsers | Worker isolation, job limits, fuzzing | Open; blocks installer |
| Dev token/HTTP; Windows ACL gap | Named pipe + SID/ACL; no token file | Open; blocks installer |
| Native chain execution unproven | WinVerifyTrust matrix on signed, tampered, and revoked samples | Open; native Windows, not the portable plumbing |
| Public dev signing key | HSM/key ceremony | Open; blocks distribution |
| No PPL/self-defence | Accept/disclose until MVI | Residual |
| Native NTFS/restore unproven | Native matrix | Open; blocks Windows claim |
| Sandbox Home/runtime | Detect/deny; native guest proof | Open; limits market |

### Engineering review

Unsupported today: native Windows runtime, installer, SCM, named pipe, UI, ETW/AMSI/WFP, minifilter, ELAM/PPL/WSC, Hyper-V/gateway, production update channel. The architecture is feasible in stages, but only if the native lab and installer are funded before feature expansion. `[JUDGMENT]`

### Commercial review

The recovery wedge is plausible but unvalidated. There is no pricing, support model, channel, brand, or lab evidence. Consumer AV and enterprise EDR are not viable near-term entries. MVI circularity makes a primary-AV strategy especially risky. `[JUDGMENT]`

### Evidence review

Repository claims are unusually disciplined. External evidence is sufficient to establish Windows lifecycle, Sandbox limits, MVI/ELAM gates, Defender compatibility, and lab methodologies; it is **not** sufficient to rank competitors or claim Litric efficacy. No Litric lab score exists. `[JUDGMENT]`

### Pre-mortem: five plausible failure reasons

1. **“Everything is Unknown.”** Users see no green shield and uninstall. Earliest signal: low activation/retention in pilot.
2. **A false positive destroys a file or trust.** Earliest signal: restore/overwrite incident or support spike.
3. **Installer/UI never ships.** Earliest signal: roadmap repeatedly prioritizes engine features over G2/G5.
4. **MVI/signing never materializes.** Earliest signal: no written eligibility path after partner inquiry.
5. **Performance/compatibility causes uninstalls.** Earliest signal: low-end pilot CPU/IO or app conflicts.

---

## Appendix B — Final self-audit

| Check | Result |
|---|---|
| Actual request and no-implementation boundary respected | Yes; document plus the two authorized portable fixes; no native Windows work |
| Defect 1: hard-coded `signature_chain_valid` removed and tested | Yes; `api::tests::safeos_assess_trusts_an_allowlisted_chain_valid_entry`, `api::tests::safeos_assess_does_not_trust_tampered_or_unsigned_input` |
| Defect 2: bare build floor replaced by lifecycle table and tested | Yes; `model::tests::supported_25h2_and_26h2_builds_are_accepted`, `model::tests::expired_24h2_is_rejected_with_lifecycle_reason`, `api::tests::safeos_assess_surfaces_lifecycle_expired_build` |
| Repository inspected rather than trusting snapshot | Yes; docs, code, tests, markers |
| Current authoritative Windows/lab sources | Yes, limited set; access date recorded |
| Dates/versions/methods accurate | Yes for cited sources; no fabricated scores |
| Consumer AV vs enterprise EDR separated | Yes |
| Fact/source/judgement/assumption/target separated | Yes |
| Features challenged, not repeated | Yes; no-gos and gaps explicit |
| FP/data integrity/recovery/compatibility/privacy/cost | Yes |
| Telemetry vs enforcement; detection vs prevention | Yes |
| Editions/drivers/signing/Defender/network | Yes |
| Ownership attributed | Yes |
| Interfaces/dependencies/failure/tests | Yes, at design level; both portable defects implemented and tested |
| Dependency-aware roadmap/exit criteria | Yes |
| Targets labeled unachieved | Yes |
| No-gos and unresolved risks | Yes |
| Security/engineering/commercial/evidence reviews | Yes |
| Usable by another team without guessing | Mostly; native/UI specifics remain open |
| No fabricated citations/results | Yes |
| Limitations next to claims | Yes |
| One clear recommendation | Yes |
| No native Windows/system/external changes | Yes; portable source changed only for the two defects |

**Quality rubric (0–2):** scope 2, evidence 1, critical reasoning 2, technical feasibility 1, safety 2, roadmap 2, honesty 2, clarity 2 = **14/16**. Evidence and feasibility cannot score 2 without native Windows tests, a licensed corpus, customer evidence, and lab results. `[JUDGMENT]`

**Delivery gates:** A partial (source set not exhaustive); B partial (native/UI unproven); C pass (safety boundaries explicit); D partial (commercial evidence absent); E pass (decision, no-gos, gated roadmap). This is a blueprint, not a release approval. `[JUDGMENT]`

---

## Appendix C — Sources and repository evidence

### External sources (accessed 2026-11-03 unless noted)

| ID | Source | Date/version | What it proves | What it does not prove |
|---|---|---|---|---|
| S1 | Microsoft Lifecycle, “Windows 11 Home and Pro” — https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro | Accessed 2026-11-03 | 24H2/25H2/26H1/26H2 end dates | Feature/API behaviour |
| S2 | Microsoft Learn, “Windows Sandbox” — https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/ | Updated 2026-03-29 | Editions (not Home), one instance, isolation model | Litric guest behaviour |
| S3 | Microsoft Learn, “Install Windows Sandbox” — https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install | Updated 2026-03-29 | 4 GB RAM/1 GB disk/2 cores | Actual host compatibility |
| S4 | Microsoft Learn, “Use and configure Windows Sandbox” — https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file | Updated 2026-03-29 | Network/clipboard defaults; .wsb controls | Guest enforcement |
| S5 | Microsoft Learn, “ELAM Prerequisites” — https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites | Updated 2023-05-12 | MVI + WHQL requirement | Litric eligibility |
| S6 | Microsoft Learn, “Microsoft Virus Initiative” — https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria | Updated 2026-09-10 | Shipping real-time product, certification, Trusted Signing, agreements | Timeline/cost/acceptance |
| S7 | Microsoft Learn, “Defender Antivirus compatibility” — https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility | Updated 2026-08-21 | Defender active/passive/disabled behaviour | Every edition/configuration |
| S8 | Microsoft Learn, “Defender Antivirus in passive mode” — https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-passive-mode | Updated 2025-07-30 | Passive-mode prerequisites; MDE onboarding | Litric coexistence result |
| S9 | Microsoft Learn, “Driver Code Signing Requirements” — https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs | Updated 2026-04-14 | EV certificate/Partner Center path | Cost/timeline |
| S10 | AV-Comparatives, “Real-World Protection Test February–May 2026” — https://av-comparatives.org/tests/real-world-protection-test-february-may-2026/ | Release 2026-06-15 | 400 cases, Windows 11 x64, cloud, FP, non-repeatable | Litric result or universal ranking |
| S11 | AV-TEST, “Test Procedures” — https://www.av-test.org/en/about-the-institute/test-procedures/ | Accessed 2026-11-03 | Protection/performance/usability modules | Current product scores |
| S12 | SE Labs, “Review Guides” — https://selabs.uk/review-guides/ | Accessed 2026-11-03 | Endpoint 1.21, EAS, ransomware methodology | Detailed results/applicability |
| S13 | MITRE ATT&CK, “Data & Tools” — https://attack.mitre.org/resources/attack-data-and-tools/ | ATT&CK v20, accessed 2026-11-03 | Technique taxonomy version | Evaluations result/coverage |
| S14 | Microsoft Learn, “Protecting anti-malware services” — https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services- | Accessed 2026-11-03 | ELAM-dependent PPL service model | Litric eligibility |
| S15 | Microsoft Learn, “Windows 11 release information” — https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information | Accessed 2026-11-03 | ISO end-of-updates dates and build numbers used by `WINDOWS_11_RELEASES` | Feature/API availability on each build |

### Repository evidence

`README.md`; `docs/STATUS.md`; `docs/LIMITATIONS.md`; `docs/ARCHITECTURE.md`; `docs/AUDIT.md`; `docs/SAFEOS_READINESS.md`; `docs/SAFEOS_WINDOWS_VERIFICATION.md`; `docs/WINDOWS_WINE_TESTING.md`; `docs/WINDOWS_WINE_TEST_EVIDENCE.txt`; `crates/litric-core`; `crates/litric-service`; `crates/litric-safeos`; `crates/litric-cli`; `crates/litric-agent`; `Cargo.toml`; `rules/core.lrs`.

**Audit snapshot:** commit `673e2de`, 2026-11-03. The blueprint was written before this pass; the working tree now contains the two portable fixes and their tests, uncommitted. The untracked master prompt is also present. No native Windows execution was performed.
