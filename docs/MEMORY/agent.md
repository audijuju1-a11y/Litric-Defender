# Platform agent area memory

Crate: `crates/litric-agent` (7 unit + 3 end-to-end tests). Binary
`litric-agent`, library `litric_agent`.

| Function | Purpose |
|---|---|
| `COLLECT_SCRIPT` | read-only PowerShell, prints one JSON object |
| `validate` | rejects reports that cannot be a Windows host |
| `facts_from_json_text` | parse + validate |
| `facts_json` | same shape the collector emits |
| `summary` | host support vs Litric launch capability, separately |
| `collect` | runs PowerShell on Windows; clear error elsewhere |
| `submit` | POST to `/api/v1/safeos/host-facts` over loopback |
| `decode_chunked` | handles tiny_http chunked responses |

## Invariants

* Script must stay read-only; a test lists forbidden cmdlets.
* `nat_query_ok=false` must block the gateway, not mean "0 NATs".
* `known=false` or missing edition/build/RAM is rejected by agent and daemon.
* Agent never claims a launcher: status keeps `available=false` while
  `LAUNCH_IMPLEMENTED` is false.
* Token is read from `--token-file`, `LITRIC_TOKEN_FILE`, then
  `./litric-data/api.token`.

## Testing without Windows

`--fixture facts.json` feeds the same parser used by the collector. End-to-end
tests start a real daemon and run the real binary. The Windows branch compiles
only on a Windows target; on Linux `collect()` returns an explicit error.

## Next steps (ordered)

1. Run `litric-agent --print` on a real Windows 11 host and compare with
   `docs/SAFEOS_AGENT.md`; capture one real report as a fixture.
2. Implement the sandbox launcher on Windows; flip `LAUNCH_IMPLEMENTED` only
   when a real session starts and exits.
3. Then, and only then, let `safeos_assess` pass `BackendSet` from
   `Readiness` instead of `none()`.
