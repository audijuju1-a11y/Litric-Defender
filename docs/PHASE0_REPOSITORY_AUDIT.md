# Phase 0 repository audit — Litric Defender

## Summary

| Field | Value |
|---|---|
| Phase | 0 — Repository audit |
| Status | **PASS (audit)**; implementation of later phases NOT started |
| Branch | none — the workspace has no `.git` directory |
| Commit | unavailable (no repository metadata) |
| Date | 2026-11-07 |
| Host | Windows 11 Home 26H2, build 26300.9457, x64 |
| Toolchain | rustc/cargo 1.99.0, `x86_64-pc-windows-gnu` |
| Baseline | **568 tests passed** before fixes; **573 passed, 0 failed, 0 ignored** after them (exit 0) |

This phase read the complete workspace, reproduced the test baseline and two
benign corpus scans, verified every advertised capability against source, and
fixed the two highest-severity defects that were small and testable. It did not
start Phase 1 modules, did not build an installer, and did not touch Defender,
the firewall, Hyper-V, or any Windows security setting.

## Requirements addressed

| Requirement | Where |
|---|---|
| Inspect the whole repository, every crate and manifest | §1, `ARCHITECTURE_MAP.md` |
| Verify every documented capability | `FEATURE_TRUTH_MATRIX.md` (85 rows) |
| Reproduce the baseline with commands and counts | `BASELINE_EVIDENCE.md` |
| Classify features IMPLEMENTED/PARTIAL/STUB/ABSENT/BLOCKED/UNVERIFIED | truth matrix; **0 STUB rows** |
| Dependencies, licences, provenance | §4 of this file, `DEPENDENCIES.md` |
| Find TODOs/stubs/mocks, duplication, dead code | §3 |
| Map real data flows and destructive operations | `ARCHITECTURE_MAP.md` §2, §4 |
| Identify security gaps | `SECURITY_GAP_ANALYSIS.md` |
| Do not treat documentation as proof | §6 (documentation drift) |

## 1. Inventory

20 crates, 36,462 lines under `crates/*/src`, 5,318 lines of integration tests,
9 shipping binaries:

`litric`, `litricd`, `litric-rtp`, `litric-scan`, `litric-clamav-import`,
`sigtool`, `litric-guard`, `litric-agent`, `litric-pgate-selftest`.

Largest and most load-bearing: `litric-core` (17.4k), `litric-service` (4.3k),
`litric-safeos` (3.1k), `sigdb` (2.4k), `litric-cli` (2.3k).

The tree contains two generations of code. `litric-core` holds the current
engine, quarantine and safety layer; `quarantine`, `ransomshield`, `realtime`,
`recovery` and `honeyvault` are older standalone crates that the CLI and tests
still link. This is duplication, not dead code; consolidating it is a refactor,
not a Phase 0 action.

## 2. What is actually real

Verified by source and tests (details, symbols and evidence per row in
`FEATURE_TRUTH_MATRIX.md`):

* Detection: file identification, SHA-256/MD5/SHA-1, PE parser, 73 authored
  rules (22 core + 51 extended — counted, not quoted), Aho–Corasick matcher,
  56 heuristic signals, verdict aggregation that reserves `Clean` for a positive
  trust record, ZIP-family recursion with hard limits, VBA and XLM extraction,
  bounded script de-obfuscation, 190-category ledger.
* Safety: encrypted quarantine (XChaCha20-Poly1305, Argon2id), journaled
  crash recovery, no-clobber restore with re-hash, confirmed purge, protected
  paths, removal budgets, hash-chained audit.
* Integrity: Ed25519 signed threat DB, payload hash, anti-rollback, atomic
  install with `.prev`; native signature store with the same properties.
* Windows: working SCM install/uninstall code, loopback HTTP API with bearer
  token and constant-time compare, process gate with suspend→scan→resume,
  post-write watcher, SafeOS model/policy/governor/broker with tests.
* Optional modules: ClamAV text-format importer (hash + NDB/LDB subsets) and a
  YARA module on `yara-x` — both tested, neither wired into the shipping scanner
  (gap S-02).

## 3. TODOs, stubs, mocks, dead code

* `grep` for `TODO|FIXME|unimplemented!|todo!|panic!("not` over `crates/`
  returns **1** hit: a test fixture string in
  `crates/litric-core/tests/extended_rules.rs:83`. There are **no TODO/FIXME
  markers and no `todo!()`/`unimplemented!()` in source**.
* No mock backends in release paths. Test doubles exist only inside `#[cfg(test)]`
  and integration fixtures.
* Duplication: the five legacy crates listed above; `litric-core` also contains
  both the modern and the older RansomShield entry points.
* Dead-ish code: `sandbox::launch` is reachable through the API but has never been
  executed on this host; `litric-wintrust` is called only from `/analyze`.

## 4. Dependencies and licences

* 270 external crates, **all declare a licence** (no "unknown" entries).
  Dominant: MIT OR Apache-2.0 (123), LLVM-exception (27), MIT (24),
  Apache-2.0 OR MIT (21). Copyleft: one crate offers
  `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the permissive option is used.
* Third-party engines: `yara-x` (VirusTotal, BSD-3) and RustCrypto/dalek
  primitives. No ClamAV code is linked; only its documented text formats are
  parsed.
* **Fixed in this phase:** eight workspace manifests had no `license` field
  (`clamav-import`, `honeyvault`, `peanalysis`, `quarantine`, `ransomshield`,
  `realtime`, `recovery`, `scanner`, `sigdb` — nine files, eight crates plus
  `sigdb`). All now declare `LicenseRef-Proprietary`, matching the workspace.
  `docs/DEPENDENCIES.md` now lists all 20 workspace crates instead of 12.
* **Still missing:** a `LICENSE` file. The SPDX ref is a declaration, not terms;
  legal text must be supplied before distribution.

## 5. Fixes implemented in this phase

These were done because they are in the release path, small, and verifiable.
No feature was added that the audit did not justify.

### F-01 — fail-closed threat-database trust

* `crates/litric-core/src/threatdb.rs`: new `DbTrustPolicy`
  (`new`, `parse_keys`, `from_env`, `has_production_key`) and
  `ThreatDb::load_for_runtime`. Runtime trust now comes from
  `LITRIC_DB_PUBKEY` (64-hex, comma/semicolon list) and
  `LITRIC_ALLOW_DEV_DB`; with neither, loading fails closed with an actionable
  message. Malformed pinned keys are rejected rather than ignored.
* `crates/litric-cli/src/main.rs`, `crates/litric-service/src/main.rs`:
  `build_engine` uses `load_for_runtime` and warns when the database is
  `DevelopmentOnly`.
* `crates/litric-cli/tests/scan_quarantine_e2e.rs`: fixtures opt in explicitly;
  new end-to-end test proves the CLI refuses a fixture-signed DB without the
  opt-in and leaves the target untouched.
* 3 new unit tests + 1 E2E test.

### F-02 — service crash recovery

* `crates/litric-service/src/winsvc.rs`: `apply_failure_actions` applies
  `SERVICE_CONFIG_FAILURE_ACTIONS` (restart at 5 s / 30 s / 60 s / 300 s,
  one-day reset) on both create and refresh; the dry-run plan and its test
  include the policy.
* 1 new unit test.

### F-03 — licence metadata consistency

Manifests and `DEPENDENCIES.md` as described in §4. No code impact; `cargo
metadata` parses all manifests.

## Files changed

| File | Change | Why |
|---|---|---|
| `crates/litric-core/src/threatdb.rs` | trust policy + runtime loader + 4 tests | close the fixture-key bypass (S-01) |
| `crates/litric-cli/src/main.rs` | use runtime loader, warn on dev trust | same |
| `crates/litric-service/src/main.rs` | same | same |
| `crates/litric-cli/tests/scan_quarantine_e2e.rs` | explicit opt-in + refusal test | prove the gate end-to-end |
| `crates/litric-service/src/winsvc.rs` | failure actions + plan + test | service must come back after a crash (S-06) |
| 9 × `crates/*/Cargo.toml` | `license` field | metadata consistency |
| `docs/DEPENDENCIES.md` | full workspace list, licence note | was incomplete |
| `docs/FEATURE_TRUTH_MATRIX.md` | new | required deliverable |
| `docs/BASELINE_EVIDENCE.md` | new | required deliverable |
| `docs/ARCHITECTURE_MAP.md` | new | required deliverable |
| `docs/SECURITY_GAP_ANALYSIS.md` | new | required deliverable |
| `docs/PHASE0_REPOSITORY_AUDIT.md` | new (this file) | required deliverable |
| `docs/STATUS.md`, `docs/LIMITATIONS.md`, `README.md`, `docs/AUDIT.md`, `docs/INTEGRATION_REPORT.md`, `docs/MALWAREBYTES_COMPARISON.md`, `docs/SAFETY.md`, `docs/WINDOWS_STATUS.md`, blueprint, `docs/MEMORY/*` | corrected counts, doctest claim, DB trust, service recovery, Defender-RTP caveat | keep claims true |

No source file was deleted, moved, or reformatted wholesale.

## Tests

```
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

* Exit **0**; **573 passed, 0 failed, 0 ignored** (568 before the two fixes).
* Log: `target/evidence/phase0/workspace-tests-after-fixes.log`; pre-fix baseline in
  `target/evidence/phase0/workspace-tests-phase0.log`.
* Focused runs after the fixes:
  * `cargo test -p litric-core --lib threatdb` → 12 passed (3 new).
  * `cargo test -p litric-service --lib` → 40 passed (1 new).
  * `cargo test -p litric-cli --test scan_quarantine_e2e` → 7 passed (1 new).
* **No test was skipped, ignored, or weakened.** The E2E fixture now opts in via
  an environment variable instead of relying on an unsafe default; the new test
  covers the refusal path.

Correction to earlier reporting: the suite is 573 tests **in 17 non-empty
binaries**; 39 of the 56 `Running` entries contain zero tests, and the 20
`Doc-tests` entries contain zero doctests. "568 across 56 binaries + 20 doctests"
overstates breadth.

## Security review

* **Privilege boundaries:** unchanged. Service still runs as LocalSystem when
  installed; local CLI stays per-user. No new elevated operation was introduced;
  failure actions are written by the same elevated SCM call that already created
  the service.
* **Input validation:** new key parser validates length and hex before
  `VerifyingKey::from_bytes`; errors are typed, no panic path.
* **TOCTOU:** not worsened. The runtime loader reads the DB once at startup, as
  before.
* **File safety:** the new E2E test asserts the scanned file is untouched when
  the DB is refused.
* **Resource limits:** none added or removed.
* **Failure behaviour:** DB refusal is explicit and actionable; service install
  still succeeds if failure actions cannot be set (best effort, documented).
* **Recovery:** restart policy reduces the "silently dead AV" window; it does not
  mask service logic errors.
* **False-positive risk:** unchanged. No detection rule or threshold was touched.
* **Privacy:** no network call added; no telemetry.
* **Residual risks:** S-02…S-06 and S-09 in `SECURITY_GAP_ANALYSIS.md`, especially
  that the main scanner still does not consume the signature store, and that the
  watcher is not a service. S-07/S-08 are closed by `docs/PHASE1_SAFETY_REPORT.md`.

## Performance

Measured in this phase, debug CLI, default empty DB:

| Corpus | Files | Wall time | Files/s |
|---|---|---|---|
| PowerShell v1.0 | 767 | 3.446 s | 222.6 |
| drivers | 603 (+1 unreadable) | 15.103 s | 39.9 |

The repository also contains earlier release-build measurements (505 files/s and
56 files/s for the same directories, `target/evidence/bench-*.txt`). Those are
**not** comparable: different build profile and machine load. No percentile
latency, memory or soak data exists. No Malwarebytes run was performed, so no
comparative performance claim is made anywhere.

## Incomplete features / blockers

Summarised from the truth matrix (30 ABSENT, 4 BLOCKED rows):

* no kernel minifilter, AMSI provider, ETW consumers, WFP filters, or ELAM/PPL;
* no UI, tray, installer, updater, scheduler;
* no network reputation or web filtering;
* no Hyper-V backend, gateway, or guest telemetry;
* SafeOS launcher never executed (Windows 11 Home lacks Sandbox/Hyper-V);
* no labelled malware corpus, fuzzing, soak or leak testing, no lab validation.

## Documentation

Created: `FEATURE_TRUTH_MATRIX.md`, `BASELINE_EVIDENCE.md`,
`ARCHITECTURE_MAP.md`, `SECURITY_GAP_ANALYSIS.md`, this report.
Updated: `DEPENDENCIES.md` (workspace list, licence note), `STATUS.md`
(test counts, doctest correction, DB trust policy, service recovery),
`LIMITATIONS.md` (rule count, database trust variables, build profile for
performance), `README.md`, `AUDIT.md`, `INTEGRATION_REPORT.md`,
`MALWAREBYTES_COMPARISON.md`, `SAFETY.md`, `WINDOWS_STATUS.md`, the blueprint
evidence rows, and `MEMORY/{build,cli,core,service}.md` (stale counts and the
new trust/recovery facts).

## Documentation drift found (and what was done)

| Claim | Reality | Action |
|---|---|---|
| `docs/WINDOWS_EVIDENCE.md`: 536 tests | 568 baseline, 573 after the Phase 0 fixes | left as a dated historical record; baseline document is authoritative |
| "20 doctests" | 0 doctests in 20 empty harnesses | corrected in `STATUS.md` and baseline |
| "568 tests across 56 binaries" | 17 non-empty binaries, 39 empty harnesses | corrected in `STATUS.md` and baseline |
| `DEPENDENCIES.md`: 12 workspace crates | 20 crates exist | fixed |
| 8 manifests without a licence | all crates now declare one | fixed |
| `docs/STATUS.md`: "25 service tests" | 40 in the service library | corrected |
| "505 / 56 files/s" quoted without build profile | release build; Phase 0 measured debug at 222/40 | both recorded; no comparison claimed |
| `docs/B-origin/INTEGRATION_REPORT.md` implies the ClamAV adapter is in the scan chain | true for `scanner`/`litric-scan`; **not** for `litric`/`litricd` | recorded as gap S-02; text is marked historical |

## Exit gate

**PASS for the audit**, with one qualification: the audit is complete and
reproducible, but the product-level exit criteria of later phases are obviously
not met. The two fixes above are the only code changes; everything else is
documentation and measurement.

Evidence bundle:

* `docs/FEATURE_TRUTH_MATRIX.md`
* `docs/BASELINE_EVIDENCE.md`
* `docs/ARCHITECTURE_MAP.md`
* `docs/SECURITY_GAP_ANALYSIS.md`
* `target/evidence/phase0/workspace-tests-phase0.log` (pre-fix)
* `target/evidence/phase0/workspace-tests-after-fixes.log` (post-fix, 573)
* `target/evidence/phase0/corpus-powershell.json`
* `target/evidence/phase0/corpus-drivers.json`

## Next phase (proposed, not started)

Phase 1 — core safety and correctness, in this order:

1. ~~DPAPI-wrap the vault key; apply the SDDL in local mode (S-07/S-08).~~
   **Done** — see `docs/PHASE1_SAFETY_REPORT.md`.
2. ~~Fuzz PE/archive/VBA/XLM parsers and add soak/concurrency tests (S-15/S-16).~~
   **Delivered** — deterministic harness in `docs/PHASE1_PARSER_SOAK.md`; four
   coverage-guided targets in `docs/PHASE1_COVERAGE_FUZZ.md` (8.38M executions,
   0 crash artifacts, no sanitizer).
3. ~~Add TOCTOU and ADS/timestamp coverage where it can be done without changing
   restore semantics.~~ **Delivered** — see
   `docs/PHASE1_QUARANTINE_METADATA.md`.

Phase 2 should then wire the signature store and YARA into the real scanner with
provenance (S-02). Phase 4 must move the watcher into the service before any
"real-time protection" claim is made.
