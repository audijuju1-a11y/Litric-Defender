# Security gap analysis (Phase 0)

Findings are ordered by what actually weakens the product on a user's machine.
Each has a source reference, a concrete failure scenario, and a status. Five were
fixed because they were small, testable and in the release path — S-01/S-06 in
Phase 0, S-07/S-08 in the first Phase 1 slice, and S-14 in the quarantine
metadata slice; the rest are deliberately left open rather than papered over.

Status: **FIXED** (in this phase, with tests), **OPEN**, **BLOCKED** (needs
Microsoft signing / licensing / a platform capability this project cannot grant
itself), **ACCEPTED** (documented residual risk).

---

## 1. Critical / high

### S-01 — Runtime accepted the public fixture signing key for the threat DB — **FIXED**

**Evidence before fix:** `litric-cli/src/main.rs:1087` and
`litric-service/src/main.rs:535` called
`ThreatDb::open_dir(dir, &[], true, …)`: no pinned key, development key allowed,
unconditionally. `db build` (CLI) signs with `dev_signing_key()`, a fixed public
seed, so anyone could produce a "valid" database that the scanner would trust.

**Impact:** an attacker who can drop two files in the `--db` directory can inject
hash/rule content — including `Trusted` entries that suppress detection, or
`Malicious` entries that cause quarantine of a user's files. This is a
content-authenticity bypass, not merely a config error.

**Fix:** `litric-core/src/threatdb.rs` now has `DbTrustPolicy` and
`ThreatDb::load_for_runtime`:

* pinned keys come from `LITRIC_DB_PUBKEY` (comma/semicolon separated 64-hex);
* the fixture key is honoured only with `LITRIC_ALLOW_DEV_DB=1|true|yes`;
* with neither, loading fails closed with an actionable error;
* a malformed pinned key is an error, so a typo cannot silently empty the key set;
* a pinned key produces `DbTrust::Production`; the fixture key still produces
  `DevelopmentOnly`, which both binaries warn about on stderr.

Tests: `pinned_key_is_accepted_as_production`,
`policy_parses_and_rejects_bad_keys`, `runtime_load_fails_closed_without_a_policy`
(unit), plus the end-to-end
`dev_signed_database_is_refused_without_explicit_opt_in`, which asserts the CLI
refuses a fixture-signed DB, prints both variable names, and leaves the target
file untouched.

**Residual:** no production keypair exists yet, so a real deployment must generate
one; `db build` still signs with the fixture key (publishing path, not runtime).
Documented in `docs/STATUS.md` and `docs/LIMITATIONS.md`.

### S-02 — The scanner binaries do not use the imported ClamAV/native signature store or YARA — **OPEN**

**Evidence:** neither `litric-cli` nor `litric-service` depends on `scanner`,
`sigdb` or `litric-yara` (manifests). Only `litric-scan`, `litric-rtp` and
`litric-guard` link the pipeline. `litric scan --db` reads the JSON threat DB
(rules + hashes) — that is a different path from the binary signature store that
`litric-clamav-import`/`sigtool` produce.

**Impact:** the advertised "ClamAV signature adapter" and YARA engine cannot
affect a normal `litric scan` or `litricd` scan today. A user can import a
ClamAV database, see it verified, and still get no detection from it in the main
scanner. That is a capability/expectation gap rather than memory corruption.

**Why not fixed here:** it is an architecture change (engine must accept multiple
providers with provenance), not a patch. It is the top item of Phase 2.
**Mitigation now:** documented explicitly in `docs/STATUS.md` and the truth matrix.

### S-03 — File monitoring is not always-on — **OPEN**

**Evidence:** `litric-rtp` is a console runner (`crates/litric-monitor/src/main.rs`);
`litricd` has no file watcher. The service installs `litricd run-service` only.

**Impact:** protection exists only while the user keeps a console program running.
After reboot there is no real-time layer. This is the single biggest product gap
versus a consumer AV, and cannot be closed by documentation.

**Fix direction (Phase 4):** host the watcher inside `litricd`, add a bounded event
queue with loss accounting, start in audit-only mode.

### S-04 — Process gate is post-launch and can act on the wrong image — **PARTIAL**

**Evidence:** `processgate` polls process snapshots, opens and suspends threads,
then hashes the image. A process mapped from a replaced file, or a suspended
process whose image is swapped before hashing, can produce a decision about bytes
that no longer match what runs. Termination is limited to an exact SHA-256
`Malicious` entry in a *signed* DB, which bounds damage but does not make it a
pre-execution control.

**Mitigation in code:** suspend-before-hash, exact-hash-only termination, resume on
any doubt. **Residual:** a determined attacker can race it. Correct fix is kernel
callback/AMSI (S-05), plus ETW for attribution.

### S-05 — No kernel, AMSI or ETW layer — **BLOCKED**

No minifilter, no AMSI provider, no ETW-TI consumer. A minifilter requires a
Microsoft-assigned altitude and a signed driver (WHQL/attestation); AMSI provider
registration and PPL/ELAM need Microsoft onboarding. This project cannot grant
itself those, and shipping an unsigned driver is not an option.

**Consequence, stated plainly:** Litric cannot block a malicious executable
launched from Explorer before it runs. It is a scanner plus a post-write watcher
plus a safety-first quarantine, not a replacement for Defender or Malwarebytes.

### S-06 — Service had no crash recovery — **FIXED**

**Evidence before fix:** `winsvc::install` set description and delayed auto-start
but never `SERVICE_CONFIG_FAILURE_ACTIONS`. A crashed service stayed dead until
the next boot.

**Fix:** `apply_failure_actions` sets restart actions at 5 s / 30 s / 60 s / 300 s
with a one-day failure-count reset, applied on both create and refresh paths, and
listed in `planned_operations` (dry-run). Test:
`dry_run_plan_includes_crash_recovery` plus the existing "no Defender API" guard.

**Residual:** the recovery policy is best-effort; a failure to set it is not
reported to the operator yet. It does not affect service correctness.

### S-07 — Vault key was stored unwrapped — **FIXED (Phase 1)**

**Evidence before fix:** `quarantine.rs` wrote a raw 32-byte key file next to the
vault. Anyone who could read the directory could decrypt quarantined content.

**Fix:** new keys are sealed with machine-scoped DPAPI, entropy-bound to
`LitricDefender.VaultKey.v1`, behind a `LKDK1` file header. A legacy 32-byte key
is still accepted and migrated in place, with the original bytes preserved as
`vault.key.legacy` (same protected DACL) so a failed upgrade can never lock a
user out. A corrupt wrapper is refused with an explanation and the file is not
rewritten. Tests: DPAPI roundtrip/tamper/wrong-entropy, wrapped-key reopen,
legacy migration with restore, corrupt-key refusal. See
`docs/PHASE1_SAFETY_REPORT.md`.

**Residual:** machine scope means any local user who can read the file can
decrypt it (the DACL is the boundary); the vault cannot move machines; the
legacy backup is plaintext. Documented in `docs/LIMITATIONS.md` §11.

### S-08 — Local mode did not restrict the data directory ACL — **FIXED (Phase 1)**

**Evidence before fix:** `winsvc::restrict_to_system_and_admins` was called by the
service only. `litric --local` and `litricd serve` created the vault and key with
inherited profile/ProgramData ACLs.

**Fix:** the SDDL implementation moved to `litric_core::winplatform::acl` (one
copy for service, daemon and CLI). `litric --local` hardens the vault directory,
`vault.key` and, if present, `vault.key.legacy` **before** using the vault and
fails closed if it cannot; `litricd serve` hardens its `--data-dir` before the
token or key is written. Evidence: `icacls` shows only SYSTEM, Administrators and
OWNER RIGHTS, and the ACL test proves the owner can still read/write/delete.

**Residual:** requires NTFS; a local vault on FAT/exFAT is refused. An
elevated process can always take ownership — this is not tamper-proofing.

### S-09 — No UI, installer, or automatic updates — **OPEN**

No UI project, no MSI, no update client. `service install` is the only install
path. Users must run a console command elevated. This is a delivery gap, not a
detection bug, but it prevents "install once and forget".

**Explicitly deferred by the user** during this cycle ("ไม่ต้องทำ MSI installer").
Recorded so it is not mistaken for done.

---

## 2. Medium

| ID | Gap | Evidence / impact | Status |
|---|---|---|---|
| S-10 | YARA is a library with no shipping consumer and no bundled rules | `litric-yara` tests pass; no binary depends on it | OPEN (Phase 2) |
| S-11 | ClamAV CVD/CLD containers are not verified or unpacked; `sigtool` is the documented external step | `clamav-import` rejects them explicitly | OPEN (documented) |
| S-12 | No network update channel, incremental updates or key-rotation tooling | no HTTP client dependency | OPEN (Phase 2) |
| S-13 | Threat DB install signs with the fixture key only | `db build` path | OPEN (publishing tooling) |
| S-14 | Quarantine does not preserve ADS or original timestamps | **FIXED (Phase 1)**: named `$DATA` streams and created/accessed/modified times are stored in an encrypted container and restored before publish; identity-bound, handle-based deletion. EAs, security descriptors, attributes and stream ACLs/timestamps remain unsupported | FIXED (limited metadata scope) |
| S-15 | No coverage-guided fuzz harness | Four `cargo-fuzz` targets under `fuzz/` (PE/ZIP/VBA/XLM); 8,380,123 executions, 0 crash artifacts on 2026-11-07; `--sanitizer none`, no corpus minimisation | ADDRESSED (parser scope; sanitizer/process isolation open) |
| S-16 | Memory/soak/concurrency tests | 4-batch memory sampling and 8-thread determinism in `tests/parser_fuzz_soak.rs`; sampled retained bytes, not an allocation hook | ADDRESSED (Phase 1 slice) |
| S-17 | No latency percentiles; only throughput from ad-hoc scans | `bench` command | OPEN (Phase 11) |
| S-18 | Rule files are trusted input parsed at startup; a malformed `.lrs` is skipped with a stderr message | `build_engine` | ACCEPTED (visibility gap: service log only) |
| S-19 | No independent lab validation or labelled corpus | none | OPEN (release gate) |

## 3. Platform realities, not bugs

| ID | Reality | Consequence |
|---|---|---|
| P-1 | Host is Windows 11 **Home** (build 26300, Insider) | No Hyper-V, no Windows Sandbox, no WSL2-based isolation: SafeOS cannot execute here |
| P-2 | Minifilter/AMSI need Microsoft signing/onboarding | Kernel enforcement BLOCKED, not "planned but skipped" |
| P-3 | No Authenticode chain validation for catalog-signed files | `wintrust` is embedded-signature only; revocation uses the local cache |
| P-4 | `WinVerifyTrust` result is advisory | It never makes a file `clean`; a signature only contributes to trust when paired with a trust record |

## 4. Threat model summary

Assets: user files, quarantine originals, threat-DB integrity, API token, audit
log, host stability.

Adversaries considered:

1. **Malware already running as the user** — can read the local data dir, kill a
   console watcher, race the process gate. Mitigations today: digest-bound
   removal, vault encryption, audit chain. Not mitigated: killing `litric-rtp`.
2. **Malicious file content** — parsed by PE/archive/VBA/XLM code. Mitigations:
   bounded budgets, truncation checks, no `unsafe` in core parsers, 45,000
   deterministic mutations, crafted bomb/traversal/truncation cases, and four
   coverage-guided `cargo-fuzz` targets. Residual: no sanitizer run and no
   parser process isolation.
3. **Malicious update content** — blocked by signature + pinned key + rollback
   refusal (strong now that S-01 is fixed).
4. **Local unprivileged user** — blocked from the service by token + loopback +
   ACL; local CLI mode is same-user by design.
5. **Remote network attacker** — no listening socket beyond loopback; no network
   component at all.

Out of scope today (and must not be claimed): kernel exploitation, bootkits,
in-memory-only malware (no memory scanning), script hosts other than the ones
whose text reaches the scanner (no AMSI), network-borne attacks.

## 5. Invariants checked against code

| Invariant | Where enforced | Verified |
|---|---|---|
| Unknown never becomes Clean | `engine.rs` requires a positive trust record for `Clean` | unit + 1,370-file corpus (all unknown) |
| Error/unreadable never becomes Clean | `scan.rs` counters, report fields | unit + corpus `unreadable: 1` |
| No destructive action without identity check | `quarantine.rs` digest re-hash + volume serial/file index, handle-based delete, `safety.rs` | tests |
| Restore never overwrites | `quarantine.rs::restore` | NTFS tests |
| Unsigned DB never activates | `threatdb.rs` (now fail-closed) | new tests |
| No silent Defender/firewall changes | no API calls; install plan test | test |
| Bounded queues and budgets | `realtime`, `scan`, `governor` | tests |

## 6. Prioritised remediation

| Order | Item | Phase |
|---|---|---|
| 1 | Wire signature store + YARA into `litric`/`litricd` with provenance | 2 |
| 2 | Host the watcher in the service, audit-only first | 4 |
| 3 | ~~DPAPI-wrap the vault key; ACL the local data dir~~ — done | 1 |
| 4 | Parser mutation/soak/concurrency campaigns — **done**; coverage-guided targets **done** (8.38M executions, no sanitizer); add sanitizer/process isolation | 1 |
| 5 | AMSI provider + ETW process attribution | 5 |
| 6 | Minifilter after signing strategy is agreed | 6 |
| 7 | UI, installer, updates | 3 / 9 |

Items 5–6 cannot be completed without Microsoft-side approvals; they must be
reported as BLOCKED until then, never as "in progress".
