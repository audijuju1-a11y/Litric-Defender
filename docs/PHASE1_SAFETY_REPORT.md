# Phase 1 — vault key protection and data-directory ACL

## Summary

| Field | Value |
|---|---|
| Phase | 1 (first slice) — core safety |
| Status | **PARTIAL** (slice complete; Phase 1 has more work) |
| Date | 2026-11-07 |
| Host | Windows 11 Home 26H2, build 26300.9457, x64, NTFS |
| Toolchain | rustc/cargo 1.99.0, `x86_64-pc-windows-gnu` |
| Full suite | **582 passed, 0 failed, 0 ignored, exit 0** |
| Git | no repository metadata in this workspace |

Scope delivered: close S-07 (plaintext vault key) and S-08 (unhardened local data
directory) from `SECURITY_GAP_ANALYSIS.md`, with tests and live evidence. No
detection logic, verdict threshold, quarantine removal rule, Defender setting, or
Windows security control was changed.

## Requirements addressed

* The vault key must not sit on disk as plaintext.
* Existing vaults must keep working across the upgrade — no silent key loss.
* A wrapped key that cannot be unwrapped must fail loudly, not corrupt anything.
* Service, daemon and CLI local mode must all apply the same protected DACL.
* Local mode must not rely on the installer/service having hardened anything.
* Access control must be verified, not assumed.

## Implementation

### DPAPI key wrap — `crates/litric-core/src/winplatform.rs::dpapi`

* `protect(plaintext, entropy)` / `unprotect(blob, entropy)` wrap
  `CryptProtectData`/`CryptUnprotectData` with
  `CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN`.
* Entropy is the constant `LitricDefender.VaultKey.v1`, so another DPAPI blob
  from the same machine cannot be substituted as the vault key.
* Output size is capped before allocation; API errors keep their Win32 code.
* This is the only `unsafe` code in `litric-core`, isolated in one module.

### Key-file format and migration — `crates/litric-core/src/quarantine.rs`

* New format: `LKDK1\n` + DPAPI blob. A bare 32-byte file is accepted as the
  legacy format.
* On opening a legacy key, the bytes are wrapped **in place** and the original is
  first copied to `vault.key.legacy`. The raw key still opens the vault if the
  upgrade fails, so a failure cannot lock the user out of quarantined data.
* Writes go through a temporary file + `fsync` + rename; an interrupted write
  cannot truncate the key.
* Unwrap failure returns an explanatory error and leaves the file untouched.

### DACL enforcement — `winplatform::acl` + `QuarantineVault::open`

* One SDDL implementation:
  `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)` — protected inheritance,
  SYSTEM/Administrators full control, owner rights so the creating user is not
  locked out. No `Users` or `Everyone` ACE.
* `QuarantineVault::open` applies it to the vault directory, the key file and (if
  present) `vault.key.legacy`, and **fails closed** if that is impossible. This
  covers CLI, `litricd`, the watcher and every library caller in one place.
* `litricd serve` additionally hardens `--data-dir` before writing `api.token`
  (the token is created before the vault opens).
* `litric-service::winsvc::restrict_to_system_and_admins` now delegates to the
  same implementation, so service and local mode cannot drift.

### Defect found during live verification

The first implementation hardened only the CLI's scan/guard path. A real run of
`litric quarantine list` showed the vault, key and legacy backup with inherited
`Authenticated Users:(M)` / `Users:(RX)` ACEs: that command opened the vault
directly. Fixed by moving enforcement into `QuarantineVault::open` and adding an
assertion on the effective DACL (`dacl_sddl`), not just on the SDDL constant.
This is why the report distinguishes "code written" from "verified".

## Files changed

| File | Change |
|---|---|
| `crates/litric-core/src/winplatform.rs` | new: DPAPI protect/unprotect, ACL apply/read, tests |
| `crates/litric-core/src/quarantine.rs` | wrapped key format, legacy migration, DACL enforcement, 4 tests |
| `crates/litric-core/src/lib.rs` | register `winplatform` (Windows-only) |
| `crates/litric-core/Cargo.toml` | `windows-sys` for the Windows target |
| `crates/litric-service/src/winsvc.rs` | delegate ACL to core; owner-access test |
| `crates/litric-service/src/main.rs` | harden `--data-dir` before token creation |
| `crates/litric-service/src/lib.rs` | correct the "ACL not implemented" module doc |
| `crates/litric-cli/src/main.rs` | route all local vault opens through one path |
| `docs/STATUS.md`, `docs/LIMITATIONS.md`, `docs/ARCHITECTURE_MAP.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `docs/FEATURE_TRUTH_MATRIX.md`, `docs/BASELINE_EVIDENCE.md`, `docs/MEMORY/{core,service}.md`, counts in living docs | truth updates |

## Tests

```
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

* **582 passed, 0 failed, 0 ignored**, exit 0. Log:
  `target/evidence/phase0/workspace-tests-phase1-vault.log`.
* Nine new tests, none skipped or weakened:
  * DPAPI roundtrip, tampered blob, wrong entropy (3)
  * new key is wrapped and reopens (1)
  * legacy key migrates with backup and still restores (1)
  * corrupt wrapped key refused without rewriting (1)
  * vault and key carry the protected DACL, asserted via `GetFileSecurity`
    (1)
  * owner can still write/read/delete after hardening (1)
  * SDDL string guard against `WD`/`BU` (1)
* Focused runs: `litric-core` quarantine suite 24 passed; `litric-service` lib
  41 passed; `daemon_e2e` 16 passed; `scan_quarantine_e2e` 7 passed;
  `guard_e2e` 4 passed; `platform_evidence` 2 passed.

### Live evidence (`target/evidence/phase1/`)

1. `litric --local scan <EICAR copy> --quarantine-malicious --vault-dir … --key …`
   → exit 1, 1 malicious, 1 quarantined, original moved.
2. Key file: first bytes `4c 4b 44 4b 31 0a` (`LKDK1\n`), 268 bytes total — a
   DPAPI blob, not 32 plaintext bytes.
3. `icacls` on the vault directory, `vault.key` and (in the legacy run)
   `vault.key.legacy`: only
   `NT AUTHORITY\SYSTEM:(OI)(CI)(F)`,
   `BUILTIN\Administrators:(OI)(CI)(F)`,
   `OWNER RIGHTS:(OI)(CI)(F)`. No `Authenticated Users`, no `BUILTIN\Users`.
4. `quarantine restore` with the wrapped key → exit 0, restored SHA-256
   `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (the EICAR
   digest recorded at quarantine time); `quarantine verify` → 0 entries, 0 failed.
5. Legacy run: 32 raw bytes on disk → after one command the key is `LKDK1`,
   `vault.key.legacy` exists with the original 32 bytes and the protected DACL.

Caveat carried from the baseline: the test run had **Defender real-time
protection off**. That is a recorded environment limitation, not an instruction;
no Defender setting was changed.

## Security review

* **Privilege:** DPAPI machine scope lets the LocalSystem service and the user CLI
  share a vault; the DACL, not the user SID, is the boundary. An administrator
  can still read the key. This is stated in `LIMITATIONS.md` §11.
* **Key loss:** migration writes the backup before replacing the key; the raw key
  remains usable if wrapping fails; restore was re-tested with the wrapped key.
* **Downgrade:** an attacker who can write `vault.key` can replace it with a raw
  key and the vault will accept it — but the same attacker can already read or
  delete the vault. This does not add a new capability; it does mean the key file
  is not tamper-evident. Future work: bind the key id into the vault index.
* **ACL:** the effective DACL is asserted in a test; failures are fatal at vault
  open, not warnings. The owner ACE prevents a self-lockout.
* **TOCTOU:** unchanged. Key and vault paths are checked by the OS at open time;
  a directory swap between check and use is still possible for an attacker who
  already controls the parent directory.
* **Resource limits:** DPAPI output is capped (64 KiB); no new unbounded work.
* **Privacy:** no network calls, no telemetry; key material never logged.
* **Fail-open check:** none. Non-NTFS or DACL failure refuses the vault.

## Performance

DPAPI and two `SetFileSecurityW` calls happen once per vault open; no per-file
cost. No benchmark was run because the cost is not measurable at scan scale, and
no number is claimed.

## Incomplete / next Phase 1 items

* Fuzz PE/archive/VBA/XLM parsers (S-15) and add soak/concurrency tests (S-16).
* ~~ADS and original-timestamp preservation on quarantine (S-14).~~
  **Delivered in the quarantine-metadata follow-up** — see
  `docs/PHASE1_QUARANTINE_METADATA.md`.
* ~~TOCTOU/identity hardening beyond re-hash; alternate data streams on restore.~~
  **Delivered in that follow-up** for body/ADS capture, handle-bound deletion
  and restore publication; destination-parent races and non-ADS metadata remain
  open.
* Key rotation, TPM/DPAPI-NG, tamper-evident key binding to the vault index.
* Still no installer, UI, kernel/AMSI/ETW/WFP, or update channel.

> Follow-up (2026-11-07, later slice): the parser mutation/soak/concurrency
> harness was delivered in `docs/PHASE1_PARSER_SOAK.md` (45,000 deterministic
> inputs, memory sampling, 8-thread determinism). Coverage-guided targets were
> added later in `docs/PHASE1_COVERAGE_FUZZ.md` (8.38M executions, 0 crash
> artifacts, `--sanitizer none`). The 582 test count above is the state at this
> slice, not the current suite.
>
> Follow-up (2026-11-07, quarantine metadata): ADS/timestamps and
> identity-bound, handle-based deletion were delivered in
> `docs/PHASE1_QUARANTINE_METADATA.md`. The current suite is **597 passed, 0
> failed, 1 ignored**, exit 0. Phase 1 still lacks a sanitizer-backed fuzz run,
> real power-loss testing and preservation of EAs/security descriptors/attributes.

## Exit gate

**PARTIAL.** The two requested safety defects are fixed and verified with unit,
integration and live evidence. Phase 1 as a whole is not done: a
sanitizer-backed parser fuzz run, real power-loss testing and broader metadata
coverage remain open, so this must not be reported as "Phase 1 complete".

## Next

The parser fuzzing/soak follow-up is recorded in `docs/PHASE1_PARSER_SOAK.md`,
and the quarantine metadata/identity follow-up in
`docs/PHASE1_QUARANTINE_METADATA.md`; coverage-guided targets are in
`docs/PHASE1_COVERAGE_FUZZ.md`. The remaining Phase 1 work is sanitizer-backed
fuzzing and power-loss/recovery evidence; do not move to the
signature store/YARA wiring (S-02) before the Phase 1 gate is approved, and do
not claim stronger detection from either.
