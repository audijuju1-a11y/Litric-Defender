# CLI area memory

Binary: `litric` (`crates/litric-cli`). Library: `litric_cli::client`
(HTTP transport + rendering, 8 unit tests). End-to-end: `tests/daemon_e2e.rs`
(16 tests, real binary against a real daemon), `tests/safeos_launch_verify.rs`
(4 host-execution canary tests) and `tests/platform_evidence.rs` (2 evidence-sync
tests). The full workspace suite ran natively on Windows 11 x86_64 on 2026-11-07:
597 passed, 0 failed, no excluded tests (568 before the Phase 0/1 fixes). Raw evidence: `docs/WINDOWS_EVIDENCE.md`;
gate evidence: the readiness doc's `test_evidence` block. Quarantine ADS/timestamp E2E:
`docs/PHASE1_QUARANTINE_METADATA.md`.

## Behaviour

* Operational commands go through `litricd`: `status`, `scan`, `cancel <job-id>`,
  `analyze`, `quarantine {list,add,restore,verify,purge}`,
  `safeos {status,launch,assess}`.
* Token discovery: `--token-file`, `LITRIC_TOKEN_FILE`, else
  `./litric-data/api.token`.
* Address: `--addr` / `LITRIC_ADDR` / `127.0.0.1:8787`.
* `--local` is the only standalone path and prints a stderr notice.
* Exit codes: 0 ok, 1 threat/failed job/blocked decision, 2 client or usage
  error, 3 cancelled.

## Error messages are part of the contract

* Daemon down: "cannot reach the Litric daemon at ..." + start command + mention
  of `--local`.
* Missing token: "cannot read the API token at ..." + `litricd serve`.
* Rejected token (401): "the daemon at ... rejected the API token from ..." +
  `litricd token`.
* Daemon 4xx: "daemon rejected METHOD path (HTTP n): <error field>".

Tests assert these strings; change them only with the tests.

## Gotchas

* `Client::discover` fails before any network I/O if the token file is missing.
* `quarantine purge` requires `--confirm` client-side; the daemon also requires
  `?confirm=true`.
* `cancel` reports an unknown job as "no scan job" and a terminal job as "already
  finished", both exit 2.
* `quarantine restore` refuses an occupied destination; the daemon returns 409 and
  the CLI exits 2 without replacing the existing file.
* `safeos assess` exits 1 for `deny` and `block_and_quarantine`, because both mean
  "do not launch".
* Don't add a silent fallback to the engine; the whole point of the client is that
  the daemon is the single source of truth.
