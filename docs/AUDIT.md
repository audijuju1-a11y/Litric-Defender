# Repository audit — Litric Defender

**Date:** 2026-11-02
**Auditor:** Litric Defender Engineering
**Repository state at audit:** empty (0 tracked files, 2 commits: "Import cloud
project files", "Initial cloud project")

## 1. What existed

Nothing. There was no Litric Defender code, no driver, no service, no installer,
no documentation, and no build system. The directive's instruction "do not
assume the product is empty" was checked and the answer is that it *is* empty.

Consequently this is a greenfield build, and the audit's real value is the
constraint analysis below, not a survey of existing modules.

Environment available for this work:

| Item | Value |
|---|---|
| Host | Linux x86-64 cloud VM, 2 vCPU, 3.9 GB RAM |
| Toolchain | rustc/cargo 1.99.1 (stable) |
| Windows build | cargo target `x86_64-pc-windows-gnu` installed; no WDK, no MSVC, no Windows host |
| Windows runtime | none — no Windows VM available in this environment |

## 2. Constraints discovered by research (and what they force)

These findings changed the architecture. Sources are the Microsoft docs cited
inline; each was read during this session.

### 2.1 Kernel-mode AV is not shippable by this project

| Requirement | Consequence |
|---|---|
| Every kernel driver must be signed by Microsoft (Partner Center / Hardware Dev Center). Cross-signing is dead and violates the Trusted Root Program policy. ([deprecation notice](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/deprecation-of-software-publisher-certificates-and-commercial-release-certificates)) | A `.sys` built here could never load on a user's machine. |
| Registration requires an EV certificate, a legal entity, a D-U-N-S record and signed agreements. ([code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)) | Not an engineering decision; it is a procurement/legal gate. |
| `Attestation signing` is explicitly for testing, cannot publish to Windows Update, and **cannot produce ELAM binaries**. ([signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)) | The "cheap path" is closed for AV-class drivers. |
| ELAM requires Microsoft Virus Initiative membership **plus** WHQL, and MVI in turn requires independent lab certification of an already-shipping product. ([MVI criteria](https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria), [ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites)) | Circular gate. No boot-start driver, no AM-PPL service. |
| `Microsoft-Windows-Threat-Intelligence` ETW requires an Antimalware-PPL consumer, which requires ELAM. | No memory/injection telemetry from the OS's own EDR provider. |
| `ObRegisterCallbacks` and `PsSetCreateProcessNotifyRoutineEx2` require a signed image / `FORCE_INTEGRITY`. | Handle-stripping and process callback enforcement unavailable. |

**Decision:** build the portable detection core and user-mode architecture now;
specify the kernel components precisely and mark them `BLOCKED`, rather than
writing driver code that can never be loaded, signed or tested.

### 2.2 What remains genuinely possible in user mode

| Mechanism | Gives us | Limit |
|---|---|---|
| ETW `Microsoft-Windows-Kernel-File` / `Kernel-Process` | process, image-load, file create/write/rename/delete telemetry | notification only; no blocking |
| AMSI provider (`IAntimalwareProvider`) | script/macro/.NET content scanning | only what opts in; no native PE |
| WFP user-mode filters | per-application allow/block | no content inspection |
| WSC / Security Center | product visibility | vendor enrolment is MVI-gated; documented API surface is consumer-only |

This is why the architecture in `docs/ARCHITECTURE.md` separates **detection**
(working now, platform-neutral) from **enforcement** (Windows, user-mode first,
kernel later and gated on signing).

### 2.3 Threat-intelligence licensing review

| Source | Verdict for redistribution inside a shipped signature DB |
|---|---|
| ClamAV / libclamav | **Excluded** by product rule and GPL incompatibility for a proprietary engine. |
| `Yara-Rules/rules` (GPLv2) | **Excluded** — copyleft contaminates a proprietary database. |
| Elastic `protections-artifacts` (Elastic Licence 2.0) | **Excluded** — source-available, not redistributable in a competing product. |
| Neo23x0 `signature-base` (Detection Rule Licence 1.1) | Redistributable **with attribution**; not adopted yet because the rules are YARA syntax and our engine has its own format. |
| abuse.ch (MalwareBazaar/URLhaus/ThreatFox) | Auth-key gated; commercial use requires a Spamhaus licence. **Not redistributable** under community terms. |
| MITRE ATT&CK | Royalty-free for commercial use **with copyright notice**. Adopted for technique IDs only. |
| EICAR test file | Industry-standard self-test; every AV detects it. Adopted as the only test signature. |
| AMTSO SFC files | Terms forbid redistribution without written consent. **Not embedded.** |

**Decision:** ship only Litric-authored rules plus the EICAR self-test string. Do
not pretend otherwise: the engine reports "threat database is empty" when no
hash feed is installed.

## 3. Architecture decisions taken

1. **Rust for the engine.** The scanner parses attacker-controlled bytes; memory
   safety removes an entire vulnerability class (parser RCE) at the cost of some
   tuning work. No `unsafe` in `litric-core`.
2. **Original rule language, not YARA.** Requirement: original detection logic.
   The engine has its own grammar (`.lrs`), own parser and own Aho–Corasick
   matcher, with no YARA code or data.
3. **`Unknown` is a first-class verdict.** A file with no evidence is *not*
   reported clean. Only a trusted-hash allowlist hit yields `Clean`.
4. **Weighted, explainable signals instead of one big score.** Every detection
   carries an id, a weight, a human explanation and MITRE techniques, so a false
   positive can be argued with and fixed.
5. **Crypto from audited crates only.** `sha2`, `chacha20poly1305`, `argon2`,
   `ed25519-dalek`. Litric implements no primitives.
6. **Kernel and Windows-service work is separate and gated.** Nothing in the
   shipping engine pretends to block I/O.

## 4. Known weaknesses of the current state

| Weakness | Impact | Mitigation planned |
|---|---|---|
| No recursive archive scanning | Malware inside ZIP/ISO/MSI is identified only as a container | `archive` module with depth/size/ratio limits (`STATUS.md`) |
| Native Authenticode chain execution unproven | Engine trust dampening still treats "signed" as structural; `safeos_assess` uses `WinVerifyTrust` on Windows, but native execution, revocation, and page hashes are unproven | Native Windows certificate matrix; keep parser wording scoped to the engine |
| No script de-obfuscation | Encoded PowerShell is flagged, not decoded | Static decoder with instruction budget |
| Threat DB contains no hash feed | Zero hash-reputation coverage | Licensed feed or community corpus with clean licence |
| Rules tested only on synthetic fixtures | Unknown false-positive rate on real corpora | Labelled corpus + FP measurement harness |
| No Windows host | All Windows-specific behaviour is unverified | Windows VM test matrix |

## 5. Proposed order of work

1. ~~Detection core, rules, verdicts~~ (done)
2. ~~Quarantine vault, threat DB signing, scan accounting~~ (done)
3. ~~RansomShield decision engine + HoneyVault~~ (done)
4. Archive extraction with bomb limits; script decoding
5. Windows user-mode sensor (ETW `Kernel-Process` / `Kernel-File`) + service host
6. AMSI provider; WFP application rules
7. Windows UI bound to the real service
8. Signed installer/updater; PPL and minifilter only if MVI/WHQL becomes viable
