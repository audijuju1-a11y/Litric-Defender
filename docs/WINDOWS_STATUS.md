# Windows 11 status (what is and is not verified)

Verified on this host on 2026-11-07. Raw results: `docs/WINDOWS_EVIDENCE.md`.
The repository is Windows-only; there is no cross-platform build path, no Wine
runner and no POSIX-only test.

| Item | State | Evidence |
|---|---|---|
| Whole workspace builds and tests natively for `x86_64-pc-windows-gnu` | **TESTED** | `cargo test --workspace`: 597 passed, 0 failed, 1 ignored, exit 0 (568 before the Phase 0/1 fixes); 57 test binaries, 18 with tests, 0 doctests; Defender RTP off during the run |
| Detection (EICAR, script cradle, encoded script, ZIP member) | **TESTED** | `scan --local --json` results in `docs/WINDOWS_EVIDENCE.md` §3 |
| False positives on benign Windows system files | **MEASURED** | 1,370 files: 0 malicious, 0 suspicious, 1 unreadable |
| Encrypted quarantine / restore / purge on NTFS | **TESTED** | no-clobber and occupied-destination tests ran natively; ADS and created/modified timestamps preserved through a CLI scan→quarantine→restore E2E |
| `litric-rtp` post-write monitor | **TESTED** | dropped EICAR quarantined; benign file left `unknown` |
| Authenticode via `WinVerifyTrust` | PARTIALLY IMPLEMENTED, UNPROVEN | compiles and links; result-code mapping tested; embedded signatures only, catalog-signed files unsupported, revocation uses cache only |
| SafeOS Windows Sandbox launch | **UNPROVEN** | this host is Windows 11 Home: `WindowsSandbox.exe` is absent, so no launch was possible; the code path remains unexecuted |
| Hyper-V managed backend | BLOCKED | Home edition has no Hyper-V role (`vmms` absent); no backend code exists |
| WFP / WinNAT gateway | NOT IMPLEMENTED | no filter or NAT code exists |
| Guest behaviour monitoring (ETW) | NOT IMPLEMENTED | needs a running guest |
| Process gate (suspend → scan → resume / hash-only terminate) | **TESTED** | 16 tests with real processes; live daemon run blocked a listed fixture; not pre-execution |
| SCM service host (`litricd service install/status/uninstall`, `run-service`) | IMPLEMENTED, PARTIALLY VERIFIED | 12 SCM unit tests + 3 gate-default tests + unelevated guards; an elevated install/start/stop cycle has not been run |
| Native Windows UI | NOT IMPLEMENTED | none |
| Installer / uninstaller | DEFERRED by decision | no MSI; `litricd service install` is the install path |
| Minifilter driver (pre-execution blocking, process attribution) | BLOCKED | needs the WDK, a test VM and Microsoft signing |
| ELAM driver | BLOCKED | requires an ELAM certificate and the Microsoft early-launch signing path |
| Windows Security Center registration | NOT IMPLEMENTED | requires the Microsoft antivirus-provider programme; do not claim Defender replacement |
| Signature update channel | NOT IMPLEMENTED | signed DB install exists; no downloader |

Toolchain: Rust ≥ 1.85 for the workspace; `litric-yara` needs ≥ 1.95 (yara-x).
The measured run used `rustc/cargo 1.99.0`.

## Environment limit on this host

Windows 11 Home, build 26300, i3-10105F (4C/8T), 16 GB RAM. Home edition does not
include Windows Sandbox or the Hyper-V role, so SafeOS cannot be exercised here
at all. Enabling those features requires a Pro/Enterprise edition and a reboot,
which is the user's decision; the agent must not change Windows features.

## Decisions on the remaining Windows work

- **Driver:** a minifilter is the documented mechanism for pre-execution
  inspection and process-attributed file events. It must stay thin (queue events
  to user mode, never parse in kernel). It cannot be responsibly written and
  shipped without a WDK build, a disposable Windows VM with kernel debugging,
  and Microsoft signing; none are available here, so no driver code is claimed.
- **Process attribution without a driver:** ETW (kernel file/process providers)
  is the documented user-mode alternative for filling the pid gap; it is
  planned, not implemented.
- **UI:** the service now has local IPC and an SCM host, so a native shell is
  the next product step; every control must call the real backend, never fake
  counts. Nothing is written yet.
- **Installer:** deferred by product decision for this revision. If it returns,
  it must not install a driver or alter Defender/Windows Security, and it must
  record every SCM/service object it creates for rollback.
