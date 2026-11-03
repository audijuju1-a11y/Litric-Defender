# SafeOS area memory

Crate: `crates/litric-safeos` (39 tests). Integrated into the daemon at
`/api/v1/safeos/{status,assess}` and the CLI at `litric safeos {status,assess}`.

## Files

| File | Responsibility | Tests |
|---|---|---|
| `model.rs` | `HostFacts`, `Readiness::evaluate`, `backend_status` | 7 |
| `risk.rs` | `ApplicationFacts` -> `RiskAssessment` (L0-L3) | 6 |
| `policy.rs` | `decide(level, BackendSet)` -> fail-closed `Action` | 6 |
| `broker.rs` | staged import/export, hash verify, scan gate | 9 |
| `journal.rs` | JSONL session journal, recovery, cleanup planner | 5 |
| `sandbox.rs` | `.wsb` XML generation, validation | 6 |

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

## Where to change what

* New backend? Add to `BackendKind`/`backend_status`, extend `BackendSet`, add a
  policy branch and tests asserting no host fallback.
* New evidence type? Extend `ApplicationFacts`, add it to `assess` *before* the
  trusted branch, and add a test proving unsigned/unknown handling is unchanged.
* New broker operation? Reuse `safe_file_name` and `hash_file`; never accept a
  path outside `Broker::root`.
