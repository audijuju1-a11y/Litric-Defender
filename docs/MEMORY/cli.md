# CLI area memory

Binary: `litric` (`crates/litric-cli`). Library: `litric_cli::client`
(HTTP transport + rendering, 8 unit tests). End-to-end: `tests/daemon_e2e.rs`
(15 tests, real binary against a real daemon) plus `tests/safeos_launch_verify.rs`
(4 POSIX-only tests) and `tests/platform_evidence.rs` (2 portable evidence-sync
tests). Windows execution of this suite is UNPROVEN; see the readiness doc's
`test_evidence` block.

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
