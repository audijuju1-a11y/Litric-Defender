# Daemon (litricd) area memory

Crate: `crates/litric-service` (19 tests). Binary `litricd`:
`serve` and `token` subcommands.

| Module | Responsibility |
|---|---|
| `lib.rs` | `AppState`, token load/create, constant-time compare |
| `server.rs` | tiny_http loopback listener, auth, 1 MiB body cap, socket tests |
| `api.rs` | `dispatch(state, method, url, body)` pure router + handlers |
| `jobs.rs` | scan jobs on worker threads, progress, cancel, terminal states |
| `store.rs` | settings/history, atomic writes, corrupt-file fallback |

Routes: `/api/v1/{health,status,capabilities}`, `scan`, `scans[/id][/cancel]`,
`analyze`, `quarantine[/verify|/id/restore|/id?confirm=true]`, `threat-db`,
`settings`, `history`, `ranshield[/events]`, `safeos/{status,assess}`.

Behaviour to preserve:

* Refuses non-loopback binds (tested).
* `/health` is the only unauthenticated route; everything else needs the bearer.
* `status` reports `limited` and `real_time_protection: false`; never "protected"
  without a real-time sensor.
* `capabilities()` is hard-coded per real code; SafeOS launch/HyperV/gateway stay
  `false` until implemented.

Do not put detection logic here: it belongs in `litric-core`.
