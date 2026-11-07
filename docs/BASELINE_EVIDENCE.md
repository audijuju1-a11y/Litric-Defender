# Baseline evidence (Phase 0)

Everything below was produced on the machine that holds this checkout, on
2026-11-07, from the source in this directory. No number is copied from a
document without being reproduced.

## 1. Environment

| Item | Value | How it was read |
|---|---|---|
| Windows edition | **Windows 11 Home** (`EditionID=Core`) | `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionID` |
| Windows version | **26H2**, build **26300.9457** | `DisplayVersion`, `CurrentBuild`, `cmd /c ver` |
| Architecture | x86_64 | toolchain target |
| Rust | `rustc 1.99.0 (b940084d7 2026-09-28)` | `rustc +stable-x86_64-pc-windows-gnu --version` |
| Cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` | same toolchain |
| Host toolchain | `stable-x86_64-pc-windows-gnu` (GNU ABI) | every command below |
| Git commit | **none available** — the workspace contains no `.git` directory (`git rev-parse` fails) | `git rev-parse --short=12 HEAD` |
| Microsoft Defender | Tamper protection **on**, AV service on, **real-time protection off** (disabled by the user before this session; `RealTimeProtectionEnabled: False`) | `Get-MpComputerStatus` |

The edition matters: Windows 11 **Home** has no Hyper-V and no Windows Sandbox.
Any SafeOS execution claim is therefore UNVERIFIED on this host by platform, not
only by choice. Windows build 26300 is an Insider build; it is not a supported
general-availability build, and results are not generalised to it.

## 2. Test suite (reproduced)

```
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

| Metric | Value |
|---|---|
| Exit code | **0** |
| Test binaries (`Running …`) | **56** |
| `test result: ok.` lines | 76 (56 binaries + 20 doctest harnesses) |
| Tests passed (pre-fix baseline) | **568** |
| Failed | **0** |
| Ignored | **0** |
| Doctests actually executed | **0** (all 20 harnesses report `0 passed`) |
| Log | [`target/evidence/phase0/workspace-tests-phase0.log`](../target/evidence/phase0/workspace-tests-phase0.log) |

The log contains no `FAILED`, no `panicked`, and no compiler `error[` line.

After the two Phase 0 fixes (database trust gate and service recovery policy) the
same command reports **573 passed, 0 failed, 0 ignored, exit 0** in
`target/evidence/phase0/workspace-tests-after-fixes.log` (5 new tests, no test
removed or skipped). The 568 figure is the pre-fix baseline.

Harness detail: the current 57 `Running` entries are not 57 suites of tests.
**39 contain zero tests** (empty library/main harnesses); the current 597 tests
live in 18 harnesses. The earlier 568/573/582/590 runs had 17 non-empty
harnesses. All 20 `Doc-tests` harnesses contain zero doctests.

The Phase 1 safety slice (DPAPI vault key + DACL enforcement) added nine tests and
brought the same command to **582 passed, 0 failed, exit 0** — log
`target/evidence/phase0/workspace-tests-phase1-vault.log`. Live evidence for that
slice is in `target/evidence/phase1/`: the key file starts with `LKDK1`, `icacls`
shows only SYSTEM/Administrators/OWNER RIGHTS on the vault, key and migrated
legacy key, and a restore re-hashes to the original EICAR digest.

The parser-soak slice adds eight tests and brings the same command to **590
passed, 0 failed, exit 0** — log
`target/evidence/phase1/workspace-tests-parser-soak-final.log`. It runs 45,000
deterministic PE/ZIP/VBA/XLM mutations plus crafted bomb, traversal, truncation
and cap cases; details and limits are in `docs/PHASE1_PARSER_SOAK.md`.

The quarantine-metadata/identity slice adds seven tests and brings the same
command to **597 passed, 0 failed, 1 ignored, exit 0** — log
`target/evidence/phase1/workspace-tests-fuzz-slice.log` (the ignored test is the
opt-in fuzz seed generator; the earlier 597/0 line referred to the pre-fuzz
suite) and
`target/evidence/phase1/ads-quarantine-workspace.log`. It covers ADS and
timestamp preservation, legacy-entry compatibility, identity-bound handle
deletion and a CLI scan→quarantine→restore path; details are in
`docs/PHASE1_QUARANTINE_METADATA.md`.

Reconciliation with earlier documents: `docs/WINDOWS_EVIDENCE.md` says 536
tests, `docs/STATUS.md` previously said 568, and some notes counted "20 doctests".
All three describe different runs. The authoritative figures for this audit are
**568/568 before the Phase 0 fixes and 573/573 after them**; the Phase 1 slices
bring the current suite through **582 → 590 → 597**, all with 0 doctests. 536 is
stale, and the 20 doctest harnesses contain no tests, so "20 doctests" must not
be counted as coverage.

## 3. Detection fixture (reproduced with the current source)

```
litric --local scan target/evidence/eicar.com --json
```

Observed: `"verdict": "malicious"`, `"threat": "Test.EICAR"`, `"score": 85`,
1 file scanned. This proves the rule/matching path works on the industry
self-test. It says nothing about current malware, which was not tested.

## 4. Benign corpus scans (reproduced)

Two system directories were scanned with the default (empty) signature database,
so every file is expected to be `unknown` — a `clean` verdict requires a positive
trust record, by design.

| Corpus | Files scanned | clean | unknown | suspicious | malicious | unreadable | Duration | Files/s | JSON |
|---|---|---|---|---|---|---|---|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0` | 767 | 0 | 767 | 0 | 0 | 0 | 3,446 ms | 222.6 | [corpus-powershell.json](../target/evidence/phase0/corpus-powershell.json) |
| `C:\Windows\System32\drivers` | 603 | 0 | 603 | 0 | 0 | 1 | 15,103 ms | 39.9 | [corpus-drivers.json](../target/evidence/phase0/corpus-drivers.json) |
| **Total** | **1,370** | 0 | 1,370 | 0 | **0** | **1** | — | — | — |

Correct reading:

* The false-positive count for this corpus is **0 files flagged malicious or
  suspicious**. That is the meaningful FP number.
* It is **not** "1,370 clean files recognised". No content feed was installed, so
  the engine correctly refused to call any of them clean.
* One driver image was unreadable (locked/in use); it is reported as unreadable,
  not clean. The denominator differs between corpora (603 scanned + 1 unreadable),
  and the two runs must never be merged into a single detection-rate figure.
* These are two directories on one machine, not a representative benign corpus.
  No Malwarebytes run was performed on the same files, so no comparison exists.

### 4.1 Test-environment caveat (must travel with these numbers)

The whole suite — including the EICAR fixtures — ran with **Defender real-time
protection disabled**. `docs/MEMORY/build.md` records that four daemon tests fail
when Defender RTP is active, because Defender removes or locks the EICAR file
before Litric can read it. The green result therefore describes Litric on a host
without an active competing AV, which is the normal coexistence risk, not a
Litric defect. Nobody should reproduce this by disabling Defender; the honest
report is "passes with RTP off, conflicts with RTP on". No exclusion was added
and no Defender setting was changed by this audit.

## 5. What was not run

| Claim class | Status | Reason |
|---|---|---|
| Real malware detection rate | NOT MEASURED | no labelled corpus; unsafe on this host |
| Malwarebytes comparison | NOT MEASURED | requires identical corpus/environment; not authorised |
| Elevated service install/start/stop | NOT RUN in this phase | needs administrator; earlier work only exercised unelevated guards |
| Windows Sandbox / Hyper-V execution | NOT RUN | Windows 11 Home lacks both |
| Kernel driver / AMSI / ETW / WFP | NOT IMPLEMENTED | see the truth matrix |
| Memory leak, soak, concurrency | NOT RUN in Phase 0; later parser slice ran 4-batch sampling + 8-thread determinism | no harness at audit time; see `PHASE1_PARSER_SOAK.md` |
| Real power-loss / driver-level crash | NOT RUN | quarantine recovery is tested with simulated interrupted journal states, not an actual power cut |
| Independent lab validation | NONE | not attempted |

The previous deliverable set included elevation-dependent commands; this audit
did not repeat them because the outcome was already documented as unverified and
Phase 0 must not mutate the host. That limitation is carried forward, not hidden.

## 6. Reproduce

```powershell
cd "litric"
cargo +stable-x86_64-pc-windows-gnu test --workspace
.\target\debug\litric.exe --local scan .\target\evidence\eicar.com --json
.\target\debug\litric.exe --local scan 'C:\Windows\System32\WindowsPowerShell\v1.0' --json > .\target\evidence\phase0\corpus-powershell.json
.\target\debug\litric.exe --local scan 'C:\Windows\System32\drivers' --json > .\target\evidence\phase0\corpus-drivers.json
```

`litric` writes JSON to stdout and diagnostics to stderr; the exit code is 1 when
anything is malicious, 0 otherwise, 2 usage, 3 database integrity, 4 quarantine
failure.
