# Windows 11 evidence (native)

This file records what was actually executed on the Windows host that produced
the current status. It is the evidence behind `README.md`, `docs/STATUS.md` and
`docs/MALWAREBYTES_COMPARISON.md`. Nothing here is an estimate, a synthetic
benchmark from another platform, or a vendor comparison.

**Run date:** 2026-11-07
**Repository state:** Windows-only tree; Linux/Wine support removed.

## 1. Environment (detected, not assumed)

| Item | Value | Source |
|---|---|---|
| OS | Microsoft Windows 11 Home, build 26300 | `Win32_OperatingSystem` |
| CPU | Intel Core i3-10105F, 4 cores / 8 threads | `Win32_Processor` |
| RAM | 16,233 MB installed | `Win32_ComputerSystem` |
| Windows Sandbox | **not present** — `C:\Windows\System32\WindowsSandbox.exe` does not exist | filesystem check |
| Hyper-V management | **not present** — no `vmms` service (`vmcompute` runs, but the Home edition has no Hyper-V role) | `Get-Service vmms,vmcompute` |
| Toolchain | `rustc 1.99.0`, `cargo 1.99.0`, target `x86_64-pc-windows-gnu` | `rustc --version` |
| Host AV | Windows Defender; real-time was reported disabled at the start of the run, but Defender re-engaged during testing and later blocked reads of the recognised EICAR file (`os error 225`) | `Get-MpComputerStatus`; reproduced |

The Sandbox/Hyper-V finding matters: Windows 11 Home does not include those
features. `litric safeos` correctly reports the backend as unavailable on this
host; no guest was started and no guest-boundary claim is made.

## 2. Test suite

```powershell
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

Result at this revision:

```
568 passed, 0 failed
56 test binaries + 20 doctest binaries
exit code 0
```

The raw log is `target/evidence/workspace-tests.log` (local artifact, not
committed). There are no `#[cfg(unix)]`/`#[cfg(not(windows))]` test gates and no
platform-exclusion markers; `crates/litric-cli/tests/platform_evidence.rs`
fails if one is reintroduced.

**Environment caveat:** four daemon end-to-end tests write the EICAR string to a
temporary file and then scan it. When Defender is active it removes or locks
those files, the scan reports `unreadable 1`, and those tests fail with exit
codes 0/2 instead of 1. That is the host AV intercepting the fixture, not a
Litric defect. The passing run above was made while Defender reported real-time
protection off; Defender later re-engaged and began returning `os error 225`
("file contains a virus") to Litric when it tried to read EICAR. In-memory EICAR
tests are unaffected. Do not add an AV exclusion silently; if you run the suite
with Defender active, expect those four tests to be blocked by Defender and
verify the cause before changing anything.

## 3. Detection on safe fixtures

Command (repeat for each target):

```powershell
.\target\release\litric.exe scan <path> --local --json
```

| Fixture | Content | Verdict | Rule | Exit |
|---|---|---|---|---|
| `eicar.com` (68 bytes) | EICAR standard test string | `malicious` | `Test.EICAR` (score 85); captured before Defender began blocking reads of the file | 0 |
| `cradle.ps1` | `IEX (New-Object Net.WebClient).DownloadString(...)` + `iwr ... Start-Process` | `malicious` | `Script.PowerShellDownloadCradle` | 0 |
| `encoded.ps1` | `powershell -EncodedCommand <base64 of the same cradle>` | `malicious` | `Script.PowerShellDownloadCradle` after bounded decoding | 0 |
| `eicar.zip` | ZIP containing `readme.txt` with the EICAR string | container `malicious` | `Test.EICAR` on the member | 0 |
| `benign.ps1` | `Get-ChildItem C:/Users`, `Write-Output 'hello'` | `unknown`, untouched | — | 0 |

Directory totals for `target/evidence/fixtures`: 4 files scanned, 3 malicious,
1 unknown, 0 clean, 0 unreadable. The benign script being `unknown` is correct:
Litric has no reputation feed including it, and `unknown` is not `clean`.

## 4. False positives on a benign Windows corpus

Both directories are Microsoft-signed Windows system content. They are read in
place; nothing is modified or quarantined.

| Corpus | Files | Malicious | Suspicious | Unknown | Clean | Unreadable |
|---|---:|---:|---:|---:|---:|---:|
| `C:\Windows\System32\WindowsPowerShell\v1.0` | 767 | 0 | 0 | 767 | 0 | 0 |
| `C:\Windows\System32\drivers` | 603 | 0 | 0 | 603 | 0 | 1 |
| **Total** | **1,370** | **0** | **0** | **1,370** | **0** | **1** |

Zero malicious and zero suspicious verdicts on 1,370 benign OS files is the
measured false-positive result for this corpus at this revision. It is not a
general FP rate: the corpus is one Windows installation, not a representative
sample, and there is no labelled malware set to measure false negatives against.

`clean` is 0 because the shipped threat database has no hash feed. Every file is
`unknown`, which is the honest verdict for "no evidence either way". Reporting
these files as clean would be a false statement.

## 5. Throughput

`litric bench <path> --local --rules rules --runs 3` (release build, 73 rules,
single-threaded, real files read in place):

| Corpus | Files | Best of 3 | Throughput |
|---|---:|---:|---:|
| PowerShell v1.0 | 767 | 1.520 s | 505 files/s, 10.4 MB/s |
| System32\drivers | 603 | 10.832 s | 56 files/s, 12.8 MB/s |

The end-to-end `scan --local --json` command on the same corpora took 2.503 s
(306 files/s) and 15.961 s (37.8 files/s) respectively; that path includes
process start-up, JSON rendering and report writing, so it is slower than the
in-process bench number. Use the bench number for engine comparisons and the
JSON number for user-visible latency. Peak memory was not captured reliably and
is not claimed.

## 6. Post-write monitor (`litric-rtp`)

A watcher was run over a staging directory while files were created:

```powershell
.\target\release\litric-rtp.exe --watch <dir> --rules rules --vault-dir <vault> --vault-key <key>
```

Observed journal (`target/evidence/rtp/events.jsonl`, local artifact):

```json
{"event":"quarantined","path":"...\\dropped-eicar.com","detail":{"threat":"Test.EICAR","sha256":"275a021b...","id":"6a077456...","reasons":["litric-native: malicious (score 85)"]}}
{"event":"scanned_incomplete","path":"...\\late-benign.txt","detail":{"verdict":"unknown","incomplete":["clamav-adapter: no signature database loaded"]}}
```

The dropped EICAR file was quarantined; the benign file stayed untouched and
`unknown`; the missing ClamAV signature database was disclosed instead of being
treated as clean. This watcher is **post-write only** and is not a real-time
pre-execution blocker.

## 7. Process gate and service host (`processgate`, `litricd`)

Measured on the same host, same day:

```powershell
cargo +stable-x86_64-pc-windows-gnu test -p processgate -p litric-service
```

| Check | Result |
|---|---|
| `processgate` suite | 16 passed, 0 failed — policy table, protected paths, baseline, failed-suspend safety, plus real-process suspend/resume and a real hash-listed termination |
| `litric-service` suite | 39 passed, 0 failed (includes 12 SCM host tests) + 3 binary tests pinning the gate defaults (`serve` off, `run-service` monitor, `enforce` opt-in) |
| `litricd service status` on a clean host | `service LitricDefender is not installed`, exit 3 |
| `litricd service install --dry-run` | 6 planned SCM operations printed, exit 0, nothing changed; binary path ends `run-service --process-gate monitor` |
| `litricd service install` unelevated | access denied reported, **exit 5**, no partial service object |
| Live daemon, monitor mode | gate `seen=16 scanned=5 allowed=8 vanished=7`; the fixture was suspended, scanned (`unknown`, score 28), resumed, logged `no-malicious-verdict` |
| Live daemon, enforce mode with a one-entry dev-signed DB | `/api/v1/status` → `process_gate.mode="enforce-hash"`, `stats.blocked=1`; event `action=block reason=hash-listed-malicious sha256=5762d531…`; the fixture PID was gone |

Not measured: an **elevated** SCM install/start/stop/delete cycle; the gate under
process-creation load or with a production-sized hash DB. See
`docs/PROCESS_GATE.md` §5.

## 8. What this evidence does not prove

* No real malware was executed on this host. Fixtures are EICAR, script
  patterns and an archive built from them.
* The zero-FP result is scoped to Windows system files. Scanning source text
  that quotes malware strings does produce matches; Litric's own `.lrs` files
  are flagged by two rules. See `docs/SAFETY.md` §7.1.
* No independent lab (AV-TEST, AV-Comparatives, SE Labs) result exists.
* Malwarebytes was not installed, so there is no head-to-head detection or
  performance measurement; see `docs/MALWAREBYTES_COMPARISON.md`.
* Windows Sandbox and Hyper-V were not available on this Home-edition host, so
  the SafeOS launch path and guest boundary remain `UNPROVEN`.
* The process gate was not run as an installed, elevated service. It kills only
  on an exact hash match and can lose the race between `CreateProcess` and
  suspension; that window is not closed in this build.
* Whole-disk scans, multi-threaded scanning, large (>1 GB) files, network shares,
  NTFS alternate data streams and power-loss durability are not measured here.
