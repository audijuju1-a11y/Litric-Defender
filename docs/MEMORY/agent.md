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
* The agent summary reports per-backend host readiness and the blocking reason;
  it never claims a sandbox launch was verified.
* Token is read from `--token-file`, `LITRIC_TOKEN_FILE`, then
  `./litric-data/api.token`.

## Testing

`--fixture facts.json` feeds the same parser used by the collector. End-to-end
tests start a real daemon and run the real binary. The suite runs natively on
Windows 11; `collect()` returns an explicit error if PowerShell is unavailable.

## Next steps (ordered)

1. Capture one real `litric-agent --print` report as a fixture and compare it
   with `docs/SAFEOS_AGENT.md`.
2. Verify the existing sandbox launcher on a Pro host with the Sandbox feature;
   set `LAUNCH_VERIFIED_ON_WINDOWS` only after a real guest session starts and
   the boundary checks pass.
3. Then, and only then, let `safeos_assess` pass `BackendSet` from
   `Readiness` instead of `none()`.
