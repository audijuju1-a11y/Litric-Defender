# End-to-end integration report

Status as of the native Windows 11 run on 2026-11-07. States: IMPLEMENTED /
TESTED / PARTIALLY IMPLEMENTED / PLANNED / BLOCKED. Raw evidence:
`docs/WINDOWS_EVIDENCE.md`.

| Area | State | Evidence / limits |
|---|---|---|
| Native engine (identification, hashing, rules, PE, archives, macros, deobfuscation, heuristics) | TESTED on Windows 11 x86_64 | full workspace suite: 597 passed, 0 failed, 1 ignored (568 before the Phase 0/1 fixes); 1,370 benign OS files scanned with 0 malicious / 0 suspicious. Defender real-time protection was off during the run |
| ClamAV-derived signature matcher (HDB/HSB/MDB/NDB/LDB) | TESTED | scanner + clamav-import + pipeline tests; unsupported lines are reported by the importer; CVD/CLD verification **not implemented**; no ClamAV database is shipped |
| `scan_bytes` buffer API | TESTED | shared code path with `scan_file` |
| Detection pipeline + aggregation | TESTED | 9 integration tests (separate provenance, no-DB disclosure, Unknown ≠ Clean, unsigned ≠ malware, archive disclosure) |
| 190-category taxonomy and coverage ledger | TESTED | 126 Specific, 55 GenericOnly, 3 Planned, 2 Blocked, 4 OutOfScope (Specific = a rule exists and passes synthetic fixtures; NOT a measured detection rate); evidence ids verified against real sources |
| Optional YARA module (yara-x) | TESTED | 8 tests incl. enforced timeout; no full-compatibility claim; Rust ≥ 1.95 |
| Extended category rules (`rules/extended.lrs`, 51 rules) | TESTED (synthetic fixtures only) | positive fixture per rule, 18 benign negatives, partial-indicator tests; never run on real malware; static strings miss packed/obfuscated samples |
| Quarantine (encrypted vault) | TESTED on Windows/NTFS | lifecycle, verify, restore, purge, journal recovery; no-clobber and occupied-destination paths executed natively; named ADS and created/modified timestamps preserved and verified end-to-end |
| RansomShield decision logic | TESTED (logic only) | no minifilter/OS enforcement |
| Real-time user-mode monitor (`litric-monitor` / `litric-rtp`) | TESTED on Windows (post-write) | 13 tests plus a real run: a dropped EICAR file was quarantined and a benign file left alone; post-write only, no process attribution, see `REALTIME.md` |
| Real-time monitoring core, Recovery Vault, HoneyVault, RansomShield-B | TESTED (logic) | crates `realtime`, `recovery`, `honeyvault`, `ransomshield`, `litric-guard`; Windows watcher path exercised; ransomware logic overlaps `litric-core::ranshield` (consolidation pending) |
| Authenticode via WinVerifyTrust | PARTIALLY IMPLEMENTED, UNPROVEN | `litric-wintrust` + `Pipeline::scan_path`; embedded signatures only; catalog-signed files unsupported; native certificate matrix not run |
| Kernel driver, ELAM, boot/UEFI/firmware scanning | BLOCKED / PLANNED | needs Microsoft signing and a Windows test VM |
| Native Windows UI | PLANNED | none in tree beyond CLI/service |
| Installer / secure update delivery | PARTIALLY | signed DB + anti-rollback exist; no installer, no network update channel |
| SafeOS launch / guest boundary | UNPROVEN | this host is Windows 11 Home (no Windows Sandbox, no Hyper-V role); the launcher was not executed and no guest was started |

## Workspace test result

```powershell
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

**597 passed, 0 failed, 1 ignored**, exit 0 (2026-11-07, after the Phase 0/1 fixes; 568
before them). 57 test binaries were reported, of which 18 contain tests; the 20
doctest harnesses contain 0 tests. There are no Windows-excluded tests. Defender
real-time protection was off during the run (see `BASELINE_EVIDENCE.md` §4.1).

## Detection and false-positive evidence

* EICAR file: `malicious`, rule `Test.EICAR`, score 85.
* PowerShell download cradle and its base64 form: `malicious`
  (`Script.PowerShellDownloadCradle`).
* EICAR inside a ZIP: container `malicious` via its member.
* Benign PowerShell script: `unknown`, untouched.
* 767 PowerShell files + 603 driver images: **0 malicious, 0 suspicious**, one
  unreadable. All are `unknown` because no hash feed is installed — `unknown` is
  not `clean`.

## Known limitations

Bundled signature/rule databases are empty by default; there is no commercial
malware-hash feed; there is no labelled real-malware corpus, so no detection
rate is claimed; ClamAV data licensing is unverified; archive members are not
matched by imported ClamAV signatures (disclosed per scan); RAR/7z/CAB/ISO are
identified but not recursed; no installer, service host, UI, kernel enforcement
or network update channel exists.
