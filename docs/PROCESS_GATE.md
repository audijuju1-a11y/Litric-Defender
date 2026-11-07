# Litric process gate and Windows service host

Status: **IMPLEMENTED and TESTED on Windows 11 x86_64 (2026-11-07)**.
Elevated service install/uninstall and a packaged installer were **not** run — see
"Not verified" below. This document records exactly what was measured.

## 1. Why this exists

The measured comparison in `docs/MALWAREBYTES_COMPARISON.md` found one decisive
gap: *if a user double-clicks a malicious executable in Explorer, Litric does not
stop it.* `litric guard` only covers launches made through that command, and the
file watcher reacts after the write.

The process gate narrows that gap in user mode, and the SCM host makes the daemon
an always-on service instead of a foreground process.

## 2. What the gate does

```
new PID (Toolhelp32 process snapshot, 250 ms poll)
    -> protected?                    (PID 0/4, self, ancestors, OS/vendor dirs) -> skip
    -> resolve image path            (QueryFullProcessImageNameW)
    -> suspend every thread          (OpenThread + SuspendThread, up to 3 passes)
    -> scan the image                (Litric Engine: rules, heuristics, signed DB)
    -> policy decision
         malicious + exact hash in signed DB + enforce -> TerminateProcess
         anything else                                  -> ResumeThread
    -> record event in the API (`/api/v1/status` -> `process_gate`)
```

The policy is a pure function (`processgate::decide`, table-tested), so the
decision to kill never depends on untestable glue code.

### Enforcement rule (deliberately narrow)

A process is terminated **only** when all of the following hold:

1. its image is not under a protected root,
2. it is not this process, an ancestor, or PID 0/4,
3. the engine returns `MALICIOUS`, **and**
4. the image's SHA-256 is listed as malicious in the signed threat database,
5. the gate is in `enforce` mode.

### Safety default: monitor, never enforce-by-accident

Both entry points start without kill authority:

* `litricd serve` defaults to `--process-gate off` (nothing is even inspected).
* `litricd service install` writes `run-service --process-gate monitor` into the
  SCM command line, so an installed service scans and reports new processes but
  terminates nothing until an operator re-installs with
  `--process-gate enforce` (or sets it explicitly in the SCM path).

Three unit tests in `crates/litric-service/src/main.rs` pin those defaults, so a
future edit cannot quietly make a machine start killing processes.

Rule-only and heuristic-only verdicts are reported and never kill. This is a
direct consequence of a measured false positive: a rule-level detection fired on
`kernel32.dll` during this project (`docs/SAFETY.md` §7.1). Treating rules as
kill authority would have terminated a system process.

### Protected locations

`%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`,
`%ProgramData%\Microsoft`, and the daemon's own directory. System binaries stay
in scope for on-demand scanning; they are simply never suspended or killed by the
gate.

### What it is not

* **Not pre-execution.** Between `CreateProcess` and the suspend, code can run.
  Closing that window needs a Microsoft-signed minifilter or a documented
  process-creation callback; neither exists in this build.
* **Not process attribution for file writes.** The file watcher still cannot say
  which process wrote a file.
* **Not deletion.** A blocked process is terminated; its file stays on disk and
  the user can still inspect or quarantine it with the existing tools.
* **Not full coverage.** Short-lived processes and images that cannot be opened
  are counted as `unprotected`/`vanished`, never as "clean".

## 3. Service host (SCM)

`litricd` now implements a real Windows service:

| Command | Behaviour |
|---|---|
| `litricd service install [--process-gate monitor\|enforce\|off]` | `CreateServiceW` for the **currently running** `litricd.exe`, `SERVICE_WIN32_OWN_PROCESS`, auto-start, delayed auto-start, LocalSystem, description set via `ChangeServiceConfig2W`. Defaults to `monitor`. There is no flag to point it at another binary. |
| `litricd service install --dry-run` | Prints every SCM operation and changes nothing. |
| `litricd service uninstall` | Stops (waits up to 30 s) and deletes only `LitricDefender`. User data and quarantine are preserved. |
| `litricd service status` | Prints the SCM's state and PID; exit 3 when not installed. |
| `litricd run-service` | Calls `StartServiceCtrlDispatcherW` on the main thread, reports `START_PENDING → RUNNING → STOP_PENDING → STOPPED`, and stops the HTTP listener on `SERVICE_CONTROL_STOP`. Never prints the bearer token. |

Service-mode startup also:

* resolves data to `%ProgramData%\Litric Defender`, rules to `<exe dir>\rules`,
  and the signed database to `<data>\db` when present;
* **hardens the data directory ACL** to `SYSTEM`, `Administrators` and owner
  (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)`) before opening the
  vault, because the directory holds `api.token` and `vault.key`;
* refuses to start if that ACL cannot be applied;
* writes diagnostics to `service.log` (rotated at 2 MiB), never the token;
* starts the process gate as configured at install time — `monitor` by
  default, `enforce` only when explicitly requested (hash-only, see above).

## 4. Measured evidence (2026-11-07, Windows 11 Home build 26300)

### Automated

| Suite | Result |
|---|---|
| `cargo test -p processgate` | **16 passed, 0 failed** — 12 unit (policy table, protected paths, baseline, failed-suspend safety) + 4 end-to-end with real processes |
| Real suspend/resume | fixture with `--hold 3` stayed alive while suspended for 2 s, then exited after resume |
| Real block | fixture's SHA-256 listed in a dev-signed DB → `TerminateProcess`; `blocked=1`, process gone |
| Benign process | empty DB → scanned, resumed, still alive, `blocked=0` |
| `cargo test -p litric-service` | **39 passed, 0 failed** (includes 12 SCM host tests) |
| CLI default tests | **3 passed** in the binary: `serve` = gate off, `run-service` = monitor, `enforce` reachable only by flag |
| `litricd service status` (not installed) | `service LitricDefender is not installed`, exit 3 |
| `litricd service install --dry-run` | printed 6 SCM operations, exit 0, no change; binary path ends `run-service --process-gate monitor` |
| `litricd service install --dry-run --process-gate enforce` | binary path ends `run-service --process-gate enforce` |
| `litricd service install --dry-run --process-gate off` | binary path ends `run-service --process-gate off` |
| `litricd service install` unelevated | clear access-denied message, **exit 5**, no partial service created |

### Live daemon runs

Monitor mode (`litricd serve --process-gate monitor --addr 127.0.0.1:8799`):

* gate reported `seen=16 scanned=5 allowed=8 vanished=7` after startup churn;
* the fixture in `target/pg-fixtures` was suspended, scanned (`verdict=unknown`,
  score 28), resumed, and recorded as `no-malicious-verdict`.

Enforce mode with a dev-signed DB containing exactly the fixture hash:

* `/api/v1/status` → `process_gate.mode = "enforce-hash"`, `stats.blocked = 1`;
* event: `action=block, reason=hash-listed-malicious, verdict=malicious,
  threat=Test.ProcessGate.Fixture, sha256=5762d531…`;
* `Get-Process -Id 16872` → process terminated.

## 5. Not verified

* **Elevated service install/uninstall on a real SCM**: not run in this session.
  The code paths are compiled and the unelevated guards are tested, but
  `CreateServiceW` success, SCM start, stop and delete were not exercised. Treat
  the service as *implemented, not yet proven on a live SCM* until
  `litricd service install` is run from an elevated prompt and
  `sc query LitricDefender` shows `RUNNING`.
* **MSI/installer**: deliberately out of scope for this revision (product
  decision). Nothing is packaged; `litricd service install` is the install path.
* **Kernel pre-execution**: blocked on Microsoft signing.
* **Gate under load / fork bombs**: the per-tick cap (8) exists, but no stress
  test was run.
* **Gate with a production-sized hash DB**: only a one-entry test DB was used.

## 6. Reproduce

```powershell
cargo +stable-x86_64-pc-windows-gnu test -p processgate -p litric-service

# service host, no admin required
.\target\debug\litricd.exe service status
.\target\debug\litricd.exe service install --dry-run
.\target\debug\litricd.exe service install        # exit 5 without elevation

# gate, monitor mode
.\target\debug\litricd.exe serve --process-gate monitor --data-dir target\pg --rules rules --addr 127.0.0.1:8799
# then read <data>\api.token and GET /api/v1/status
```
