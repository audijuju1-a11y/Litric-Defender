# Litric Defender

An original Windows endpoint security platform: detection engine, scanner,
behavioural ransomware protection, encrypted quarantine and signed threat
database — written in Rust.

**This repository contains the real engine, not a mock-up.** Every number and
every verdict below comes from code that runs. Read
[docs/STATUS.md](docs/STATUS.md) before believing any claim about scope: the
project is early, and the status file lists what is *not* built.

## What actually works today

| Capability | State |
|---|---|
| Original PE parser (headers, sections, imports, exports, resources, overlay, Rich header, TLS, CLR, checksum) | IMPLEMENTED, TESTED |
| Litric Rule Syntax engine (own grammar, own Aho–Corasick matcher) | IMPLEMENTED, TESTED |
| Heuristic engine (30+ weighted, explainable signals with ATT&CK mapping) | IMPLEMENTED, TESTED |
| Verdict aggregation with trust dampening and explicit `Unknown` | IMPLEMENTED, TESTED |
| Encrypted quarantine vault with a journaled lifecycle (add, inspect, verify, restore, purge, crash recovery) | IMPLEMENTED, TESTED |
| Signed threat database (Ed25519, anti-rollback, revocation, atomic install) | IMPLEMENTED, TESTED |
| RansomShield behavioural engine + HoneyVault decoys | IMPLEMENTED, TESTED (simulator-driven) |
| Scan orchestration with budgets, cache, honest accounting | IMPLEMENTED, TESTED |
| CLI scanner (`litric`) | IMPLEMENTED, TESTED |
| Windows service, ETW sensor, minifilter, UI, installer | PLANNED / BLOCKED — see STATUS |

## Build and run

```bash
cargo build --release
cargo test                      # 203 tests on Linux x86_64
scripts/windows-wine/setup.sh  # one-time, no-root MinGW + Wine setup
scripts/windows-wine/run-tests.sh
                                # 195 tests under Wine 11.21; 8 Windows-excluded
                                # (6 POSIX-only, 2 coverage gaps)
./target/release/litric rules lint rules
./target/release/litric scan /path/to/scan
./target/release/litric analyze suspicious.exe
./target/release/litric bench /path/to/corpus --runs 3
```

### Local API backend

`litricd` is the service backend the UI is meant to talk to. It is loopback-only,
requires a bearer token, and caps request bodies at 1 MiB.

```bash
./target/release/litricd serve --addr 127.0.0.1:8787 --data-dir ./litric-data
# token is created at ./litric-data/api.token
curl -H "Authorization: Bearer $(cat ./litric-data/api.token)" \
     http://127.0.0.1:8787/api/v1/status
```

Endpoints: `/api/v1/health` (unauthenticated liveness), `/readiness` (always 503
while evidence is missing), `/status`, `/scan`, `/scans/{id}` (+ `/cancel`),
`/analyze`, `/quarantine` (add / list / verify / restore / purge-with-confirmation),
`/settings`, `/history`, `/ranshield/events`.

`/status` reports `state: "limited"` and `real_time_protection: false` on a host
without the kernel sensor — it will not display a green shield it has not earned.
`/readiness` and `/status.readiness` report `production_ready: false`, with the
Windows Sandbox guest runtime explicitly `UNPROVEN` until a real guest run exists.

The CLI is a client of that daemon; it does not scan in-process unless you ask:

```bash
litric status                       # honest protection state, from the daemon
litric scan C:\\Users            # queues a job, prints live progress, then the result
litric analyze suspicious.exe       # evidence behind the verdict
litric quarantine list             # what the service is holding
litric quarantine verify           # decrypt and re-hash every entry
litric quarantine restore <id>     # refuses to overwrite an existing file
litric quarantine purge <id> --confirm
litric cancel <job-id>             # refuse if the job is unknown or finished
```

Every command takes `--addr` and `--token-file` (or `LITRIC_ADDR` /
`LITRIC_TOKEN_FILE`; default `127.0.0.1:8787` and `./litric-data/api.token`).
If the daemon is down or the token is missing/rejected, the CLI exits non-zero
with instructions — it never falls back to the embedded engine on its own.
Pass `--local` to explicitly scan without a daemon (results are not shared with
the service).

Windows cross-check (compiles the portable crates against the Windows target):

```bash
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu -p litric-core
```

`cargo check` only compiles the Windows target; it does not run tests. The
readiness doc records that the native suite was executed on Linux and the
Windows-target suite under Wine 11.21 (195/195; 8 Windows-excluded tests: 6
POSIX-only, 2 coverage gaps). The reproducible setup and runner are in
[docs/WINDOWS_WINE_TESTING.md](docs/WINDOWS_WINE_TESTING.md). Wine is not native
Windows: NTFS, native Windows 11, and Windows Sandbox guest behavior remain
UNPROVEN.

## Measured baseline

Release build, 2 vCPU Linux VM, 2 000 files (mixed text, random binary, and
malicious scripts), 15 rules loaded:

```
run 1: 2000 files in 0.661s = 3027 files/s, 3.1 MB/s
run 2: 2000 files in 0.653s = 3064 files/s, 3.1 MB/s
run 3: 2000 files in 0.656s = 3050 files/s, 3.1 MB/s
```

Files in that corpus are small, so throughput is dominated by per-file
overhead — which is the number that matters for whole-disk quick scans. These
are **Linux VM** figures; no Windows benchmark has been run yet (no Windows
host in this environment). See [docs/STATUS.md](docs/STATUS.md).

## Honest limitations (short version)

* Nothing here runs in kernel mode. Real-time blocking of writes and
  block-before-execute need a signed minifilter; see
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the exact blocker.
* The threat database ships with **rules only**. It contains no commercial
  malware-hash feed, so hash reputation coverage is currently zero by design —
  the engine says so in every report.
* Authenticode parsing extracts signer names and validity dates but does **not**
  validate certificate chains (that needs WinVerifyTrust on Windows).
* Archive/binary containers are identified but their members are not yet scanned
  recursively.

## Layout

```
crates/litric-core/   detection engine, scan, quarantine, RansomShield (portable)
crates/litric-cli/    `litric` command line scanner and tooling
rules/core.lrs        15 authored detection rules
docs/                 audit, architecture, status matrix, limitations
```

## Licensing note

Detection rules in `rules/` are written by Litric Labs. No third-party rule set,
no ClamAV, no YARA code and no commercial signature feed is embedded. See
[docs/AUDIT.md](docs/AUDIT.md) for the licence review behind that decision.

---

Licence: proprietary (see `Cargo.toml`). The engine is original work; third-party
crates are permissively licensed (MIT/Apache-2.0/BSD) and unmodified.
