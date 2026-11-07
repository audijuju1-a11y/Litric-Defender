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
| Encrypted quarantine vault with a journaled lifecycle (add, inspect, verify, restore, purge, crash recovery), preserving named ADS and created/modified timestamps | IMPLEMENTED, TESTED — NTFS; EAs, ACLs and file attributes are not preserved |
| Signed threat database (Ed25519, anti-rollback, revocation, atomic install) | IMPLEMENTED, TESTED |
| RansomShield behavioural engine + HoneyVault decoys | IMPLEMENTED, TESTED (simulator-driven) |
| Scan orchestration with budgets, cache, honest accounting | IMPLEMENTED, TESTED |
| Recursive ZIP/OOXML/JAR member scanning (in memory, 512 entries, 16 MiB/member, 64 MiB/layer, 1000:1 ratio, depth 3) | IMPLEMENTED, TESTED — members get the full engine; skipped/truncated members are reported and can never make a container `Clean` |
| Scan-time automatic quarantine (`litric scan --quarantine-malicious`): file or recursive directory → encrypted vault → remove original after verify | IMPLEMENTED, TESTED — on-demand scans only; Clean/Unknown untouched; no real-time monitoring |
| Bounded script de-obfuscation: up to three layers of base64 (`-EncodedCommand`/`-enc`/`FromBase64String`/`atob(`), `[char[]]`/`[char]` cast chains and constant-key XOR, charged to one 8M-step budget per file | IMPLEMENTED, TESTED — escalates only when a decoded payload is conclusive; no variable-key XOR search, string splitting, VBA string-building or emulation |
| Office VBA macros: `vbaProject.bin` extracted from OOXML/ZIP or legacy OLE2, MS-OVBA module streams decompressed, every module analysed as source; p-code cache presence reported | IMPLEMENTED, TESTED — p-code is counted but not decompiled; encrypted modules are not parsed |
| Excel 4.0 (XLM) macro sheets: OOXML `xl/macrosheets/*.xml` formulas extracted and analysed; legacy BIFF5/BIFF7/BIFF8 `FORMULA` token streams decoded with the MS-XLS Ftab table and analysed as source | IMPLEMENTED, TESTED — BIFF5/7 code-page strings are mapped as Latin-1; array constants are decoded from the record's `RgbExtra` and memory tokens keep the reference expression they wrap; external-reference resolution and BIFF4-and-earlier workbooks are not decoded; unknown ids are marked incomplete, never guessed; OOXML hidden-state mapping not implemented |
| Resource governor: 40% RAM cap, ≥2 GB host reserve, ≤4 vCPU, one heavy session, disk reservation | IMPLEMENTED, TESTED — enforced by the Windows Sandbox prepare gate; Hyper-V execution is still absent |
| Pre-execution guard (`litric guard`): scan → block unsafe verdicts → re-hash → launch; `--quarantine` opts in to moving a malicious original | IMPLEMENTED, TESTED — CLI launches only; no system-wide interception; blocking never deletes |
| CLI scanner (`litric`) | IMPLEMENTED, TESTED |
| Windows service host (`litricd service install`, SCM, auto-start) | IMPLEMENTED, PARTIALLY VERIFIED — elevated install/start/stop/delete not yet run; see `docs/PROCESS_GATE.md` §5 |
| Process gate: suspend each new process, scan its image, resume — or terminate on an exact malicious hash | IMPLEMENTED, TESTED — 16 tests with real processes; **off in `serve`, `monitor` in the installed service**; `--process-gate enforce` is opt-in; never kills on rules/heuristics; not pre-execution |
| ETW sensor, minifilter, UI, installer | PLANNED / BLOCKED / DEFERRED — see STATUS |

## Build and run

```powershell
cargo build --release
cargo test --workspace          # 597 passed, 0 failed, 1 ignored on native Windows 11 x86_64 (2026-11-07)
# If the default MSVC host has no linker, use the Windows GNU toolchain explicitly:
#   cargo +stable-x86_64-pc-windows-gnu test --workspace
powershell -ExecutionPolicy Bypass -File scripts/windows_verify.ps1
.\target\release\litric.exe rules lint rules
.\target\release\litric.exe scan C:\path\to\scan
.\target\release\litric.exe scan C:\path\to\scan --quarantine-malicious
# analyze needs the daemon below; scan/bench/guard do not
.\target\release\litric.exe bench C:\path\to\corpus --runs 3
```

### Coverage-guided parser fuzzing

The `fuzz/` workspace has four libFuzzer targets for the PE, ZIP, VBA and XLM
parsers. It is pinned to `nightly-x86_64-pc-windows-gnu` and always builds a
small MinGW libFuzzer runtime first. The MSVC `cargo +nightly fuzz` route is not
implemented; use `cargo fuzz` from `fuzz/`. See
[`docs/PHASE1_COVERAGE_FUZZ.md`](docs/PHASE1_COVERAGE_FUZZ.md) for the full
method, measured campaign and limitations.

```bash
bash fuzz/build.sh
bash fuzz/run_campaign.sh all           # 120 s per target by default
# seeds are generated from the parser fixtures with:
#   cargo test -p litric-core --test parser_fuzz_soak write_coverage_fuzz_seeds -- --ignored
```

The measured run produced 8,380,123 executions with 0 crash artifacts; it used
`--sanitizer none`, so it is not a substitute for an ASan/MSan run.

### Local API backend

`litricd` is the service backend the UI is meant to talk to. It is loopback-only,
requires a bearer token, and caps request bodies at 1 MiB.

```powershell
.\target\release\litricd.exe serve --addr 127.0.0.1:8787 --data-dir .\litric-data
# or register it as a real auto-start service (elevated; monitor mode by default):
#   .\target\release\litricd.exe service install --dry-run
#   .\target\release\litricd.exe service install
#   .\target\release\litricd.exe service status
# token is created at .\litric-data\api.token
$token = Get-Content .\litric-data\api.token
curl.exe -H "Authorization: Bearer $token" http://127.0.0.1:8787/api/v1/status
```

Endpoints: `/api/v1/health` (unauthenticated liveness), `/readiness` (always 503
while evidence is missing), `/status`, `/scan`, `/scans/{id}` (+ `/cancel`),
`/analyze`, `/quarantine` (add / list / verify / restore / purge-with-confirmation),
`/settings`, `/history`, `/ranshield/events`.

`/status` reports `state: "limited"` and `real_time_protection: false` on a host
without the kernel sensor — it will not display a green shield it has not earned.
`/readiness` and `/status.readiness` report `production_ready: false`, with the
Windows Sandbox guest runtime explicitly `UNPROVEN` until a real guest run exists.

Most CLI commands are clients of that daemon. `litric guard` is the deliberate
exception: it runs in-process because it must scan, block and launch one
child under one policy, and it does not require a daemon.

```bash
litric status                       # honest protection state, from the daemon
litric scan C:\\Users            # queues a job, prints live progress, then the result
litric scan C:\\Users --quarantine-malicious  # move only MALICIOUS files into the vault
litric analyze suspicious.exe       # evidence behind the verdict
litric guard downloaded.exe -- --help  # scan/block before launch; UNKNOWN blocks; file is not removed
litric guard flagged.exe --quarantine   # opt in: move a MALICIOUS original into the vault
litric quarantine list             # what the service is holding
litric quarantine verify           # decrypt and re-hash every entry
litric quarantine restore <id>     # refuses to overwrite an existing file
litric quarantine purge <id> --confirm
litric cancel <job-id>             # refuse if the job is unknown or finished
```

Daemon-backed commands take `--addr` and `--token-file` (or `LITRIC_ADDR` /
`LITRIC_TOKEN_FILE`; default `127.0.0.1:8787` and `./litric-data/api.token`).
If the daemon is down or the token is missing/rejected, the CLI exits non-zero
with instructions — it never falls back to the embedded engine on its own.
Pass `--local` to explicitly scan without a daemon (results are not shared with
the service). `litric guard` is not daemon-backed; it uses `--rules`, `--db`,
`--vault-dir` and `--vault-key`. For a local scan, the same two vault flags select
the vault used by `--quarantine-malicious`; a daemon-backed scan uses the
daemon's vault. Clean and Unknown files are never quarantined.

`--quarantine-malicious` exits 1 when any malicious file is found (even after a
successful move), 0 when the scan finds none, and 4 when a vault move fails. In
the failure case the original is retained. A directory scan is recursive and
includes nested folders.

The repository is Windows-only. There is no cross-platform build path, no Wine
runner and no POSIX-only test; no test is Windows-excluded. The full workspace
suite was executed natively on **Windows 11 x86_64 with the
`x86_64-pc-windows-gnu` toolchain** on 2026-11-07: **597 passed, 0 failed,
1 ignored** in 57 test binaries, of which 18 contain tests; the 20 doctest
harnesses contain no tests. The ignored test is the opt-in fuzz seed generator,
not a skipped product test. The run had Microsoft Defender real-time protection off (see
`docs/BASELINE_EVIDENCE.md` §4.1); this is a reported limitation, not a
configuration instruction. `crates/litric-cli/tests/platform_evidence.rs`
fails if a `#[cfg(unix)]`/`#[cfg(not(windows))]` gate or exclusion marker is
reintroduced. Windows Sandbox guest behavior and Hyper-V isolation remain
UNPROVEN: the development host is Windows 11 Home, which has neither feature.

## Measured baseline (native Windows 11, 2026-11-06)

Release build, 73 rules (22 core + 51 extended), single-threaded engine, real
files read in place. These are measurements from this machine, not vendor
comparisons and not whole-disk estimates.

| Corpus | Files | Best wall | Throughput |
|---|---:|---:|---:|
| `C:\Windows\System32\WindowsPowerShell\v1.0` (scripts, XML, DLLs) | 767 | 1.520 s | 505 files/s, 10.4 MB/s |
| `C:\Windows\System32\drivers` (`.sys` PE images) | 603 | 10.832 s | 56 files/s, 12.8 MB/s |

Three runs of the PowerShell corpus: 1.520 s / 1.564 s / 1.567 s. The driver
corpus is dominated by PE parsing, not file count; small-file throughput is the
number relevant to a quick scan. An earlier on-demand scan of the same 767
PowerShell files (cold cache, JSON report) took 1.585 s = 484 files/s.

EICAR (safe industry test string) was detected as `MALICIOUS` with rule
`Test.EICAR`; a benign PowerShell script stayed `UNKNOWN` and untouched, and a
PowerShell download cradle, its base64 form and an EICAR ZIP member were also
detected. No real malware was executed on this host. See
[docs/WINDOWS_EVIDENCE.md](docs/WINDOWS_EVIDENCE.md) for the exact commands,
false-positive results and the limits of these measurements, and
[docs/MALWAREBYTES_COMPARISON.md](docs/MALWAREBYTES_COMPARISON.md) for the
measured answer on replacing Malwarebytes (it does not, yet).

## Honest limitations (short version)

* Nothing here runs in kernel mode. Real-time blocking of writes and
  block-before-execute need a signed minifilter; see
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the exact blocker.
* `litric guard` gates only launches made through that command. It cannot
  intercept Explorer double-clicks, another process, or system-wide execution;
  it re-hashes before launch but does not eliminate the scan-to-exec race.
* `litric scan --quarantine-malicious` is an on-demand pass over files that
exist during the walk. It does not monitor files created or downloaded later,
and it has no ETW, AMSI or minifilter component. It is **not** real-time
protection for the whole machine.
* The threat database ships with **rules only**. It contains no commercial
  malware-hash feed, so hash reputation coverage is currently zero by design —
  the engine says so in every report.
* Authenticode parsing extracts signer names and validity dates but the engine
  does **not** fully validate certificate chains. `safeos_assess` calls
  `WinVerifyTrust` for embedded signatures; that path now runs natively, but
  catalog-signed files, revocation and page hashes remain incomplete.
* ZIP, OOXML and JAR containers are opened in memory and their members are
  analysed by the same engine, with hard entry/size/ratio/depth limits. RAR, 7z,
  ISO, MSI, CAB and gzip/bzip2 are identified only as containers, and a
  container that hits a limit is reported as truncated instead of being called
  clean.

## Layout

```
crates/litric-core/   detection engine, scan, guard policy, quarantine, RansomShield
crates/litric-cli/    `litric` command line scanner and tooling
rules/core.lrs        22 authored detection rules
docs/                 audit, architecture, status matrix, limitations
```

## Licensing note

The 73 detection rules in `rules/` are written by Litric Labs. No third-party rule set,
no ClamAV, no YARA code and no commercial signature feed is embedded. See
[docs/AUDIT.md](docs/AUDIT.md) for the licence review behind that decision.

---

Licence: proprietary (see `Cargo.toml`). The engine is original work; third-party
crates are permissively licensed (MIT/Apache-2.0/BSD) and unmodified.
