# SafeOS area memory

Crate: `crates/litric-safeos` (55 tests). Integrated into the daemon at
`/api/v1/safeos/{status,assess}` and the CLI at `litric safeos {status,assess}`.

## Files

| File | Responsibility | Tests |
|---|---|---|
| `model.rs` | `HostFacts`, `Readiness::evaluate`, `backend_status` | 7 |
| `risk.rs` | `ApplicationFacts` -> `RiskAssessment` (L0-L3) | 6 |
| `policy.rs` | `decide(level, BackendSet)` -> fail-closed `Action` | 6 |
| `broker.rs` | staged import/export, hash verify, scan gate | 9 |
| `journal.rs` | JSONL session journal, recovery, cleanup planner | 5 |
| `sandbox.rs` | `.wsb` generation, readiness-gated prepare, path/name safety, verbatim-path rewrite, RAM sizing, cfg(windows) launch | 17 |

## Invariants (do not break)

* `policy::decide` never returns `RunOnHost` for L1-L3. There is a test.
* `risk::assess` never returns `Trusted` without `signature_chain_valid`.
* Unsigned must never be treated as malicious.
* Broker import must leave the source byte-identical.
* Export must never overwrite without `approve_overwrite`.
* Cleanup must only touch `<journal_root>/<valid-id>/{input,output,vm}`.
* An invalid session id must be rejected before any path is built.

## Known gaps / next steps

1. No Windows platform agent: `HostFacts::unknown()` is the only reality in this
   build, so every backend is unavailable and policy returns `deny`.
2. Sandbox launch, Hyper-V, WFP/WinNAT, guest ETW: BLOCKED (no Windows host).
3. ACL hardening for the staging root: PLANNED.
4. Resource governor enforcement: PLANNED (thresholds exist, enforcement does not).
5. Installer/uninstaller and object rollback records: PLANNED.

## Agent and facts ingest (added after the first cut)

* `crates/litric-agent` collects read-only host facts on Windows and POSTs them
  to `/api/v1/safeos/host-facts`; see `docs/MEMORY/agent.md`.
* `AppState.host_facts: Mutex<Option<HostFacts>>` holds the last report.
* `safeos_status` reports `host_supported` (host capability) separately from
  `available` (what this build can launch). `available` stays false for every
  execution backend because no launcher exists.
* `safeos_assess` still passes `BackendSet::none()`; facts do not grant isolation.
* `nat_query_ok=false` blocks the gateway; do not treat an unreadable NAT state
  as zero.

## Readiness gate (service side)

* `/api/v1/readiness` always returns 503 with `production_ready:false`; `status`
  embeds it, `health` sets `protection_ready:false`, and `assess` embeds
  `system_readiness`. Its `test_evidence` block records the native Linux run and
  the 195/195 Wine Windows-ABI run separately; native Windows execution and NTFS
  semantics remain UNPROVEN. `platform_evidence` enforces the block.
* States are `READY` only for tested capabilities, `UNPROVEN` for launch on
  Windows and the guest runtime, `BLOCKED` for launch on non-Windows, and
  `NOT_IMPLEMENTED` for absent backends. The refusal test is
  `readiness_gate_refuses_to_claim_ready`.

## Where to change what

* New backend? Add to `BackendKind`/`backend_status`, extend `BackendSet`, add a
  policy branch and tests asserting no host fallback.
* New evidence type? Extend `ApplicationFacts`, add it to `assess` *before* the
  trusted branch, and add a test proving unsigned/unknown handling is unchanged.
* `launch` must never be reachable without `prepare` (readiness + config), and
  non-Windows builds must return `NotWindows`, never a host fallback.
* `LAUNCH_VERIFIED_ON_WINDOWS` stays false until the manual checklist passes.
* The canary test must keep its positive control; "no marker" alone proves nothing.
* New broker operation? Reuse `safe_file_name` and `hash_file`; never accept a
  path outside `Broker::root`.
