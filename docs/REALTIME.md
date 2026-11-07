# Real-time protection: what exists, what it protects, what it cannot

## Delivered and tested: user-mode, post-write protection (`litric-monitor`, runner `litric-rtp`)

Flow: OS change notification → bounded queue → per-path debounce (file must stop changing) → `Pipeline::scan_path` (native rules/heuristics, imported signatures, optional YARA, Authenticode on Windows) → `Malicious`: checked move into the AES-class encrypted quarantine vault (reversible) · `Suspicious`: alert only · unknown/incomplete: logged, never "clean".

Verified by automated tests with **real filesystem change events** — 10 end-to-end tests plus 3 unit tests, repeated runs stable. The full set passed natively on Windows 11 x86_64 (GNU toolchain) on 2026-11-06 using `ReadDirectoryChangesW` via `notify`:
- a dropped malware test file (EICAR) is detected, quarantined, original removed only after a verified vault write, and restored byte-for-byte
- benign files are untouched; files written in pieces are scanned only once complete
- files in new subdirectories are covered; the vault/log inside a watched tree are never scanned (no loop)
- oversized files are skipped loudly and reported as degraded protection (never "clean")
- auto-quarantine can be switched off
- queue overflow is counted and reported as degraded; startup refuses missing directories
- the real binary was also run as a separate process: it quarantined the test file, logged JSON lines, left a benign file alone and exited cleanly on Ctrl+C

Windows: the same code compiles for `x86_64-pc-windows-gnu` and uses `ReadDirectoryChangesW` there through `notify`. It has been exercised by the native Windows test suite (10 end-to-end + 3 unit tests, 2026-11-06); it is still a console runner, not a Windows Service, so boot-time protection is not implemented.

## What this layer is NOT (these are real gaps, not wording)
| Gap | Consequence | What closes it |
|---|---|---|
| Post-write, not pre-execution | a file can run between being written and being judged | kernel minifilter (pre-create/pre-write callbacks) — not implemented |
| No process attribution | cannot suspend the process encrypting files; RansomShield cannot contain | minifilter or ETW kernel providers — not implemented |
| Notification loss under heavy load | counted and shown as DEGRADED; files may be unscanned | periodic Smart/Full scan; a minifilter avoids buffer loss |
| Symlink/reparse skip has no Windows fixture | the check exists but no test creates a Windows reparse point, so the refusal path is unexercised | an unprivileged junction/symlink fixture or a documented privilege requirement |
| Files already present at start-up | not scanned by the monitor | run a scan on start (`litric` scan) |
| Not a Windows Service | no start at boot, no self-protection | SCM service + ACL hardening — not implemented |
| Not registered with Windows Security Center | Windows will not list Litric as the antivirus; keep Microsoft Defender active | Microsoft's AV-provider program — not applicable yet |
| Detection quality | rule/signature coverage is small and untested against real malware; the signature database ships empty | signature feed + independent testing |

Therefore: **this is real, tested monitoring and cleanup, but it is not "full-spectrum real-time protection" and must not replace Microsoft Defender or Malwarebytes.** Run it alongside Defender.

## Running it
```
litric-rtp --watch C:\Users\me\Downloads --vault C:\ProgramData\Litric\vault --key C:\ProgramData\Litric\vault.key ^
           --rules rules --log C:\ProgramData\Litric\events.jsonl
           [--sigdb-store DIR --trusted-keys FILE]   # verified signature database (anti-rollback)
```
Startup refuses to run with zero rules, a rule file that fails to parse, or a signature database that fails verification. Restore a quarantined file with the existing `litric quarantine` commands.
