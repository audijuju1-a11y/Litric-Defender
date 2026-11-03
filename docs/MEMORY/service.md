# Daemon (litricd) area memory

Crate: `crates/litric-service` (21 tests). Binary `litricd`:
`serve` and `token` subcommands.

| Module | Responsibility |
|---|---|
| `lib.rs` | `AppState`, token load/create, constant-time compare |
| `server.rs` | tiny_http loopback listener, auth, 1 MiB body cap, socket tests |
| `api.rs` | `dispatch(state, method, url, body)` pure router + handlers |
| `jobs.rs` | scan jobs on worker threads, progress, cancel, terminal states |
| `store.rs` | settings/history, atomic writes, corrupt-file fallback |

Routes: `/api/v1/{health,status,readiness,capabilities}`, `scan`,
`scans[/id][/cancel]`, `analyze`,
`quarantine[/verify|/id/restore|/id?confirm=true]`, `threat-db`, `settings`,
`history`, `ranshield[/events]`, `safeos/{status,assess}`.

Behaviour to preserve:

* Refuses non-loopback binds (tested).
* `/health` is the only unauthenticated route; everything else needs the bearer.
* `/readiness` is deliberately 503 with `production_ready:false`; `status` embeds
  it, `health` reports `protection_ready:false`, and `assess` embeds
  `system_readiness`. Never mark the guest runtime ready without a guest run.
* `status` reports `limited` and `real_time_protection: false`; never "protected"
  without a real-time sensor.
* Quarantine restore/purge map `VaultError::NotFound` to 404 and
  `Conflict`/integrity failures to 409; do not fold them into a generic 500.
* `capabilities()` is hard-coded per real code; SafeOS launch/HyperV/gateway stay
  `false` until implemented.

Do not put detection logic here: it belongs in `litric-core`.
