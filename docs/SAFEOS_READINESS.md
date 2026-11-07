# Litric SafeOS — production readiness (2026-11-07)

## Verdict: NOT PRODUCTION READY

SafeOS today is a **tested safety core** plus a **Windows Sandbox launcher that
has never been executed**. The development host is Windows 11 Home, which has no
Sandbox feature and no Hyper-V role, so the launch path could not even be
attempted there. It is not an installable endpoint product and must not be
presented as one.

What can be used safely now:

- `litric` scanning, analysis and the full quarantine lifecycle: quarantine,
  list/inspect, verify, restore, purge, and recovery from an interrupted
  operation.
- `litric safeos status|assess` for honest capability/risk reporting.
- `litric-agent` read-only host facts on Windows.
- `litric safeos launch` on a Windows build: explicit, readiness-gated, fail-closed
  — but **unverified at runtime** and unable to start without the Sandbox feature.

## Acceptance criteria (from the master brief)

| # | Criterion | State |
|---|---|---|
| 1 | Unknown apps routed to isolation through supported launch paths | PARTIAL — only the explicit `safeos launch` path; no SafeLaunch UI/Explorer/App Control interception |
| 2 | High-risk apps cannot silently fall back to host | TESTED on reachable paths — policy never returns host for L1-L3; canary test asserts no host execution |
| 3 | Offline Windows Sandbox has networking disabled | TESTED in generated `.wsb`; UNVERIFIED in a running guest |
| 4 | Network-enabled VMs reach the Internet only via Litric Gateway | NOT IMPLEMENTED — no Hyper-V backend, no gateway |
| 5 | Gateway failure blocks guest egress | NOT IMPLEMENTED |
| 6 | IPv4/IPv6 leakage tests pass | BLOCKED — needs a running guest/gateway |
| 7 | Host user directories are not writable by guests | PARTIAL — read-only mapping and broker tests; runtime unverified |
| 8 | Source files unchanged during import/analysis | TESTED — broker import copies and verifies, source hash checked |
| 9 | Failed exports never replace source files | TESTED — temp/verify/scan/rename, approval required to overwrite |
| 10 | VM crashes preserve recoverable data | PARTIAL — journal/recovery planner only; no VHDX handling |
| 11 | Cleanup never deletes unrelated host files | TESTED — journal-scoped, idempotent cleanup; broker containment |
| 12 | Existing WSL2/Docker/NAT configuration untouched | TESTED — no mutation code; readiness detects/reports conflicts |
| 13 | No unrelated host processes are terminated | TESTED by inspection — no kill/VM-stop code exists |
| 14 | Resource limits work under constrained conditions | PARTIAL — readiness thresholds and 2-4 GB sandbox RAM sizing; no VM governor |
| 15 | UI reflects actual backend data | NOT IMPLEMENTED — no UI files exist in this repository |
| 16 | All system modifications auditable and reversible | PARTIAL — session journal; no installer/object rollback records |
| 17 | Windows restart and recovery tests pass | BLOCKED — requires a Windows 11 host |
| 18 | No known critical data-loss/isolation failure remains | UNPROVEN — cannot be established without the Windows test matrix |

Only criteria 2, 8, 9, 11, 12 and 13 have direct automated evidence on this
platform. Everything else is partial, unimplemented, or blocked.

## Quarantine lifecycle — implemented, tested, crash-reconciled

The Secure File Broker's quarantine store is a complete lifecycle, not just an
encrypted file dump. Its on-disk contract is:

| Path | Purpose |
|---|---|
| `<vault>/<id>.lq` | authenticated header + XChaCha20-Poly1305 ciphertext |
| `<vault>/index.json` | atomic index used by `list` / `inspect` |
| `<vault>/ops.jsonl` | append-only `intent` / `done` journal |

Operations:

1. **Quarantine** (`POST /api/v1/quarantine`): read and hash the source, encrypt
   to a temp entry, decrypt-and-rehash that temp copy, rename it into the vault,
   write a journal intent, add the index row with `original_removed=false`, then
   delete the source and update the row with the true flag. A failed verification
   deletes the temp entry and leaves the source untouched.
2. **List / inspect / verify** (`GET /api/v1/quarantine`, `.../verify`): the index
   is the list; `inspect` falls back to the authenticated header. `verify`
   decrypts every entry, checks its recorded SHA-256 and reports each failure
   instead of hiding it.
3. **Restore** (`POST .../{id}/restore`): an existing destination is refused
   before any write. The entry is decrypted and hash-checked, a temp file in the
   destination directory is written and re-hashed, then published with an atomic
   no-clobber `hard_link` and a `create_new` fallback; the temp handle is closed
   before publish so Windows can complete the link/removal. The target is then
   re-read and re-hashed. Only after that are the entry and index row removed.
   The journal intent is written before the temp file, so an interruption leaves
   enough evidence to finish the restore or to refuse it.
4. **Purge** (`DELETE .../{id}?confirm=true`): requires explicit confirmation,
   writes a journal intent, deletes the entry, removes the index row, then writes
   `done`. Purging an unknown, restored or already-purged id returns 404 rather
   than a false success.
5. **Cancel** (`POST /api/v1/scans/{id}/cancel`, CLI `litric cancel <id>`): only
   the scan job is cancelled; an unknown id is 404 and a terminal job is 409.
   Cancellation never deletes quarantine entries.

Failure behaviour, covered by tests:

* missing entry, double restore, restore after purge → `NotFound` (404)
* occupied destination → `Conflict` (409), existing bytes unchanged
* corrupted ciphertext/header or hash mismatch → 409, no destination created,
  and the entry is kept as evidence
* interrupted restore → recovery finishes only when the destination hash matches
  the journal; a different existing destination is preserved, never overwritten
* interrupted quarantine → an entry without an index row is re-indexed from its
  authenticated header; an index row whose entry is gone and whose source is
  also gone is **not** silently deleted (reported for manual recovery)
* interrupted purge → a ghost index row is removed only after the entry is gone.

Recovery runs when the vault is opened (`QuarantineVault::open`) and is
idempotent. `recover()` only acts on journal intents without a matching `done`;
unknown operations and ambiguous states are reported and left untouched. The
journal is append-only and is never used to justify deleting a user file on a
guess.

Automated evidence in this repository:

* unit: `quarantine::tests::{roundtrip_quarantine_and_restore,
  double_restore_and_restore_after_purge_are_not_found,
  corrupted_entry_is_refused_before_creating_a_target,
  recovery_completes_an_interrupted_restore,
  recovery_indexes_an_orphaned_quarantine_entry,
  recovery_cleans_an_index_after_a_completed_purge,
  recovery_preserves_a_conflicting_restore_target}`
* daemon + CLI end-to-end: `quarantine_lifecycle_restore_purge_and_terminal_errors`,
  `quarantine_refuses_overwrite_and_corrupt_entries`,
  `cancel_reports_unknown_and_finished_jobs`
* API mapping: `quarantine_http_errors_are_actionable` asserts 409 for an
  occupied destination and 404 after purge.

Limit: the crash cases write the same journal records a crash would leave, then
reopen and recover. They do not prove power-loss durability of the filesystem or
of directory entries. The no-clobber and occupied-destination paths now run
natively on Windows 11/NTFS; power-loss durability remains unproven.

## Test execution platform and exclusions

The repository is Windows-only. The full workspace suite is compiled and
executed natively on **Windows 11 x86_64** with the `x86_64-pc-windows-gnu`
toolchain. There is no cross-platform build path, no Wine runner and no
POSIX-only test; there are no Windows-excluded tests.

`crates/litric-cli/tests/platform_evidence.rs` fails if the source tree
reintroduces a `#[cfg(unix)]`/`#[cfg(not(windows))]` test gate or an exclusion
marker, if `WINDOWS_EXCLUDED_TESTS` is non-empty, if the gate's evidence fields
drift, or if this document's machine-readable block differs from the gate. The
gate's unverified map is derived from its own non-READY capabilities; the test
also rejects any READY capability listed as unverified.

<!-- TEST-EVIDENCE-BEGIN -->
```json
{
  "suite_executed_on": "Windows 11 x86_64 (native, x86_64-pc-windows-gnu)",
  "windows_suite_execution": "READY",
  "windows_suite_reason": "Full workspace suite executed natively on Windows 11 x86_64 with the x86_64-pc-windows-gnu toolchain on 2026-11-07; every test passed and no test is Windows-excluded.",
  "windows_excluded_tests": [],
  "unverified_capabilities": {
    "safeos_sandbox_launch": ["BLOCKED", "UNPROVEN"],
    "safeos_sandbox_guest_runtime": ["UNPROVEN"],
    "safeos_hyperv_backend": ["NOT_IMPLEMENTED"],
    "safeos_network_gateway": ["NOT_IMPLEMENTED"],
    "safeos_behavior_monitoring": ["NOT_IMPLEMENTED"],
    "safeos_ui": ["NOT_IMPLEMENTED"],
    "safeos_installer": ["NOT_IMPLEMENTED"],
    "safeos_vm_recovery": ["UNPROVEN"]
  }
}
```
<!-- TEST-EVIDENCE-END -->

## Readiness gate — fail closed

`GET /api/v1/readiness` always returns **503** with `production_ready: false`.
`/status` embeds the same object, `/health` returns `protection_ready: false`, and
`safeos/status` and `safeos/assess` embed the gate or its `system_readiness`
summary. Capability states are:

* `READY` only for capabilities with passing automated tests on the platform
  recorded above: on-demand scan, quarantine, risk assessment, fail-closed
  policy, sandbox config, the native test suite, and Windows/NTFS quarantine
  semantics.
* `UNPROVEN` for the Windows Sandbox launch itself and the guest runtime
  (networking, clipboard and read-only mapping have never been observed in a
  running guest). Native Windows execution of the engine is no longer unproven.
* `BLOCKED` is reserved for a build without the launcher; this Windows build
  reports the launch as `UNPROVEN`, not `BLOCKED`.
* `NOT_IMPLEMENTED` for Hyper-V, the WFP/WinNAT gateway, guest behaviour
  monitoring, UI and installer.

The test `readiness_gate_refuses_to_claim_ready` asserts the 503, the false
production verdict, that the guest runtime is `UNPROVEN`, that launch is
`UNPROVEN`/`BLOCKED`, and that no capability may be `READY` outside the tested
allowlist. `status` and `assess` are asserted through the daemon in the same
test; `safeos status --json` is asserted in the CLI end-to-end suite. Nothing on
these surfaces turns green because code merely compiles.

## Missing components

| Component | State | Why |
|---|---|---|
| Hyper-V managed backend | NOT IMPLEMENTED | needs Windows + Hyper-V + admin and a running guest to test |
| Immutable base image / differencing VHDX lifecycle | NOT IMPLEMENTED | same; unsafe to write untested |
| WFP policy provider / WinNAT gateway | NOT IMPLEMENTED | needs Windows admin and leak tests |
| Guest behaviour monitoring (ETW) | NOT IMPLEMENTED | needs a running guest |
| Behaviour correlation decision engine | NOT IMPLEMENTED | depends on telemetry above |
| SafeLaunch UI / Explorer integration | NOT IMPLEMENTED | no UI project in this repository |
| Windows service / installer / uninstaller | NOT IMPLEMENTED | no packaging or SCM code |
| Resource governor | PARTIAL | thresholds and sandbox RAM only; no VM controls |
| VM/VHDX recovery | PARTIAL | journal planner only |

## What this means for a user today

- You can install nothing: there is no installer or service.
- You can scan, quarantine (including verify/restore/purge and recovery from an
  interrupted operation) and classify; you can launch an explicit app into
  Windows Sandbox on Windows, but that launch path is unverified and does not
  intercept normal double-clicks.
- There is no protection of the host from an app you launch normally.
- Microsoft Defender remains the real-time protection on the machine.

## What would change the verdict

1. Run `docs/SAFEOS_WINDOWS_VERIFICATION.md` on a real Windows 11 host and record
   the evidence; only then can `LAUNCH_VERIFIED_ON_WINDOWS` become true.
2. Implement and test the Hyper-V backend, gateway/WFP policy and guest telemetry
   on that host, including the fault-injection matrix.
3. Build the UI, service and installer with rollback records.
4. Measure idle/VM/gateway resource use; no performance claims before that.

Until then the honest status is **NOT PRODUCTION READY**, `safeos status`
reports `windows_sandbox_launch_verified: false` on every build, and every
readiness surface continues to return `production_ready: false` with the guest
runtime marked `UNPROVEN`.

## Verification commands used here

```powershell
cargo +stable-x86_64-pc-windows-gnu test --workspace
cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
```

Result at this revision: every workspace test passes natively on Windows 11
x86_64 with no Windows-excluded tests. The exact pass count and per-crate
breakdown live in `docs/STATUS.md`; update both together. Windows Sandbox guest
behavior and Hyper-V isolation remain `UNPROVEN`.
