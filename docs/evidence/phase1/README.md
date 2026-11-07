# Phase 1 evidence bundle

This directory commits the small, reviewable evidence that supports
[`docs/PHASE1_COVERAGE_FUZZ.md`](../../PHASE1_COVERAGE_FUZZ.md) and the Phase 1
safety reports. It intentionally contains raw summaries and one raw campaign
log, not build caches, the evolved corpus, or local secrets.

## Environment

| Field | Value |
|---|---|
| Host | Windows 11 Home 26H2, build 26300.9457, x86_64 |
| Toolchain | `rustc 1.101.0-nightly (c980177d8 2026-11-06)`, `x86_64-pc-windows-gnu` |
| cargo-fuzz | 0.13.2 |
| C++ runtime | MinGW-W64 g++ 16.2.0, UCRT, POSIX threads |
| Sanitizer | `--sanitizer none` (no ASan/UBSan on this host) |

## Files

| File | What it proves |
|---|---|
| [`clean-build.log`](clean-build.log) | All four fuzz targets build with `fuzz/target` removed and an empty `CARGO_HOME`; `cargo fetch --locked` resolves `libfuzzer-sys` before the offline metadata lookup. |
| [`fuzz-clean-verify/SUMMARY.txt`](fuzz-clean-verify/SUMMARY.txt) | Clean-checkout build and PE campaign: 43,263 counters, coverage 183→606, 871,292 executions, 0 artifacts, 35 MB peak RSS. |
| [`fuzz-clean-verify/fuzz-pe.log`](fuzz-clean-verify/fuzz-pe.log) | Raw libFuzzer log for that 30-second campaign. |
| [`fuzz-clean-verify-console.log`](fuzz-clean-verify-console.log) | Console output of the same campaign, including the script's instrumentation check. |
| [`fuzz-120s-summary.txt`](fuzz-120s-summary.txt) | Original four-target 120-second campaign: 8,380,123 executions, 4,326 corpus files, 0 artifacts. |
| [`fuzz-30s-summary.txt`](fuzz-30s-summary.txt) | Independent seed-only rerun: 2,498,974 executions, 14,462 new units, 0 artifacts. |
| [`parser-soak-final.log`](parser-soak-final.log) | Deterministic parser mutation/soak/concurrency harness: 8 tests passed. |
| [`post-fuzz-verify-tests.log`](post-fuzz-verify-tests.log) | Full workspace suite: 597 passed, 0 failed, 1 ignored, 77 harness result lines. |

The original 120-second and 30-second raw libFuzzer logs, the evolved corpora,
and the 1,000-run post-build smoke logs remain in the local
`target/evidence/phase1/` tree. They are reproducible but too large and too
machine-specific for this repository.

## Reproduce the clean build

```bash
rm -rf fuzz/target ./target/evidence/phase1/clean-cargo-home
CARGO_HOME="$PWD/target/evidence/phase1/clean-cargo-home" bash fuzz/build.sh
bash fuzz/run_campaign.sh pe 30 target/evidence/phase1/fuzz-clean-verify
```

The campaign script owns the duration and all libFuzzer limits, refreshes every
checked-in seed, rejects an uninstrumented or zero-coverage binary, and fails if
it leaves a crash artifact.

## What is deliberately not committed

| Path | Why |
|---|---|
| `target/` (~17 GB) | Cargo build cache plus machine-local evidence logs and corpus. |
| `fuzz/target/` (~353 MB) | Fuzz build artifacts and the MinGW libFuzzer runtime. |
| `crates/litric-cli/litric-data/` | Local test vault, including `vault.key`. It is a secret-shaped artifact and must not be published. |
| Corpus files | 3+ MB of evolved inputs; they are libFuzzer output, not source. |

## Limitations

* `--sanitizer none`; this is not ASan/UBSan evidence.
* The clean-checkout proof runs one PE campaign, not all four targets.
* The nightly GitHub Actions workflow is checked in but has not executed yet.
* These logs are from one Windows 11 host; they do not establish coverage of
  other Windows editions or real malware corpora.
