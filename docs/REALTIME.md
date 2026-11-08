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
| No process attribution | cannot suspend the process encrypting files; RansomShield alerts but cannot contain | minifilter or ETW kernel providers — not implemented |
| Notification loss under heavy load | counted and shown as DEGRADED; files may be unscanned | periodic Smart/Full scan; a minifilter avoids buffer loss |
| Symlink/reparse skip has no Windows fixture | the check exists but no test creates a Windows reparse point, so the refusal path is unexercised | an unprivileged junction/symlink fixture or a documented privilege requirement |
| Files already present at start-up | scanned once by the startup sweep (`litricd`, bounded; reported in `/realtime`), not continuously | a scheduled Smart/Full scan |
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

## Connected in `litricd`: one watcher, scanner + ransomware behaviour layer

`litricd serve --realtime on` (and `run-service`) now run two layers on the same OS watcher; the monitor exposes an `Observer` tap so no second watcher is opened:

```
ReadDirectoryChangesW ─► litric-monitor ─┬─► debounce ► Pipeline ► quarantine vault        (scanner)
                                         └─► Observer ► ShieldBridge ► RansomShield engine  (behaviour)
                                                         (own thread)      │
                                      /api/v1/status · /realtime · /ranshield · `litric status`
```

- The bridge samples entropy of written files, pairs rename old/new names, and feeds the service's shared RansomShield engine (the same one `/api/v1/ranshield/events` feeds).
- **Decoys** (`--realtime-decoys` for the `Litric Decoys` folder inside every watched Documents/Desktop, or `--realtime-decoy-dir DIR`): any change under a decoy folder is a conclusive `critical` incident. Off by default because it creates files in the user's folders. A decoy folder outside the watched set is reported as degraded.
- `--realtime-no-ransomware` turns the behaviour layer off; the scanner is unaffected.
- Incidents are appended to `ransomware-events.jsonl` in the data dir and shown by `/status` and `litric status`. Every incident says `contained: false`.
- **Alert-only, stated plainly:** file notifications carry no process id, so all events are attributed to one unknown actor (pid 0). The bridge never suspends or kills anything. Only `critical` is reported as an incident; `suspicious` is counted (archive extraction produces it). The pid-0 state is reset every window so cumulative counters stay burst rates. Temp folders are ignored unless named with `--realtime-watch`.
- A write whose file was renamed before it could be examined (write-then-rename, the ransomware pattern) is re-sampled under the new name, so the entropy evidence is not lost.
- `ProcessGate` is intentionally **not** fed by monitor detections: it kills only on exact hashes in the signed database (rule matches were measured to false-positive on system DLLs). Both use the same rules and database.
- Queue overflow, a crashed analysis step, an unwritable incident log or an unwatched decoy folder make `/status` report `realtime_degraded`.

Verification: unit + end-to-end tests (`litric-service` `shield::tests`, `litric-monitor` `monitor_e2e`) and a run of the real `litricd.exe` as a separate process (EICAR dropped at runtime quarantined; decoy tamper → critical incident; `/status` consistent). Those runs were done by cross-compiling and running under Wine on Linux; Wine is not Windows 11. Run `scripts/realtime_verify.ps1` on the Windows 11 machine for the native result.
