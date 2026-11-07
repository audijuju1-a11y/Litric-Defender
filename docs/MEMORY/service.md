# Daemon (litricd) area memory

Crates: `crates/litric-service` (39 library tests + 3 binary tests) and
`crates/processgate` (16 tests, 4 of them with real processes).

Binary `litricd` subcommands: `serve`, `run-service`, `token`,
`service install|uninstall|status` (Windows only).

| Module | Responsibility |
|---|---|
| `lib.rs` | `AppState`, token load/create, constant-time compare |
| `server.rs` | tiny_http loopback listener, auth, 1 MiB body cap, socket tests |
| `api.rs` | `dispatch(state, method, url, body)` pure router + handlers |
| `jobs.rs` | scan jobs on worker threads, progress, cancel, terminal states |
| `store.rs` | settings/history, atomic writes, corrupt-file fallback |
| `winsvc.rs` | SCM install/uninstall/status, `StartServiceCtrlDispatcherW`, stop token, ACL hardening, rotated file log, `SERVICE_CONFIG_FAILURE_ACTIONS` restart policy |
| `../processgate` | process snapshot → suspend → scan image → resume or hash-only terminate |

Routes: `/api/v1/{health,status,readiness,capabilities}`, `scan`,
`scans[/id][/cancel]`, `analyze`,
`quarantine[/verify|/id/restore|/id?confirm=true]`, `threat-db`, `settings`,
`history`, `ranshield[/events]`, `safeos/{status,assess}`.

Behaviour to preserve:

* Refuses non-loopback binds (tested).
* `/health` is the only unauthenticated route; everything else needs the bearer.
* `/readiness` is deliberately 503 with `production_ready:false`; `status` embeds
  it, `health` reports `protection_ready:false`, and `assess` embeds
  `system_readiness`. `test_evidence` records the native Windows 11 run
  (`docs/WINDOWS_EVIDENCE.md`); NTFS quarantine semantics were exercised in that
  run. Never mark the guest runtime ready without a guest run.
* `status` reports `limited` and `real_time_protection: false`; never "protected"
  without a real-time sensor. `process_gate` in `/status` is the gate's own
  counters, not a claim of pre-execution protection.
* Quarantine restore/purge map `VaultError::NotFound` to 404 and
  `Conflict`/integrity failures to 409; do not fold them into a generic 500.
* `capabilities()` is hard-coded per real code; SafeOS launch/HyperV/gateway stay
  `false` until implemented.
* Threat DB trust is decided by `litric_core::threatdb::DbTrustPolicy`:
  `LITRIC_DB_PUBKEY` pins production keys, `LITRIC_ALLOW_DEV_DB=1` is the only
  way to accept the public fixture key. Never reintroduce
  `open_dir(dir, &[], true, …)` in a runtime path (S-01).

Safety invariants (tested; do not "improve" them into an aggressive default):

* `litricd serve` starts with `--process-gate off`.
* `litricd service install` writes `run-service --process-gate monitor` into the
  SCM command line. `enforce` is opt-in; three binary tests pin the defaults.
* The gate terminates only when: image not under a protected root, not self or an
  ancestor, verdict `MALICIOUS`, exact SHA-256 listed malicious in the signed DB,
  and mode is `enforce`. Rules/heuristics alone never kill.
* Service startup refuses to run if the data-directory ACL cannot be restricted
  to SYSTEM/Administrators/owner; it never prints the API token.
* Installing the service requires elevation; an unelevated attempt exits 5 and
  creates nothing.

Do not put detection logic here: it belongs in `litric-core`.
