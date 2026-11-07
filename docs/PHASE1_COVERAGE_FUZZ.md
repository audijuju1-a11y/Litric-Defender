# Phase 1 — coverage-guided parser fuzzing

Status: **DELIVERED for the four parser entry points; PARTIAL for Phase 1 as a whole.**
Date: 2026-11-07

This complements the deterministic mutation/soak harness in
[`PHASE1_PARSER_SOAK.md`](PHASE1_PARSER_SOAK.md). The deterministic harness stays
the fast regression check; the targets here are the corpus-evolving,
coverage-guided campaigns that were previously absent.

## 1. Scope

Four libFuzzer targets, one per untrusted parser entry point:

| Target | Entry point | Input shape |
|---|---|---|
| `fuzz_pe` | `litric_core::pe::parse` | PE/COFF image bytes |
| `fuzz_zip` | `litric_core::archive::inspect_zip` | ZIP-family container; nested ZIP members recurse within the engine's depth limit |
| `fuzz_vba` | `litric_core::vba::extract` | legacy CFB and OOXML `vbaProject.bin` bytes |
| `fuzz_xlm` | `litric_core::xlm::extract` | legacy BIFF workbook streams and OOXML macrosheet XML |

All targets are in-process, take `&[u8]`, and perform no filesystem, network or
registry access. They exercise the parsers' advertised caps; they do not scan
live malware and do not produce a product verdict.

## 2. Toolchain and the Windows GNU workaround

Recorded environment:

* Windows 11 x86_64, `x86_64-pc-windows-gnu`
* `rustc 1.101.0-nightly (c980177d8 2026-11-06)`, LLVM 23.1.5
* `cargo-fuzz 0.13.2`
* MinGW-W64 g++ 16.2.0 (UCRT, POSIX threads)
* `--sanitizer none`: this host has no Visual Studio/Windows SDK and
  AddressSanitizer is not available for `windows-gnu`. Coverage instrumentation
  is still emitted (inline 8-bit counters + PC table); ASan/UBSan are not.

Upstream `libfuzzer-sys 0.4.13` cannot build on MinGW as shipped:

* `FuzzerExtFunctionsWindows.cpp` uses MSVC `__pragma` / `/alternatename` and
  clang's `__builtin_function_start`. `fuzz/support/FuzzerExtFunctionsWindows.cpp`
  replaces it with the supported all-null optional-hook configuration.
* `FuzzerExtraCountersWindows.cpp` relies on MSVC section ordering; its
  `__stop - __start` underflows under GNU ld. The Litric targets define no extra
  counters, so `fuzz/support/FuzzerExtraCountersWindows.cpp` returns an empty
  range.
* rustc emits counters and PC entries into COFF sections `.SCOV$CM` and
  `.SCOVP$M`, but the generated constructor references ELF-style
  `__start___sancov_cntrs` / `__stop___sancov_pcs` symbols. GNU ld does not
  create them. `fuzz/support/sancov_mingw.ld` binds the four symbols to the real
  sections and reserves the 8-byte COFF header that the constructor adds.

The custom runtime is built by `fuzz/build_libfuzzer_mingw.sh` and selected by
`fuzz/.cargo/config.toml` via `CUSTOM_LIBFUZZER_PATH`. `fuzz/build.rs` passes the
linker script only to the fuzz binaries.

**This is a Windows GNU-only configuration, not an upstream-supported cargo-fuzz
configuration.** `fuzz/.cargo/config.toml` unconditionally selects the MinGW
libFuzzer archive and `stdc++`; there is no MSVC branch. On an MSVC host with
the Windows SDK, the normal `cargo +nightly fuzz` route is **not implemented**
here and fails while linking the MSVC build scripts.

The fuzz workspace is pinned by `fuzz/rust-toolchain.toml` to
`nightly-x86_64-pc-windows-gnu`. From `fuzz/`, plain `cargo fuzz` therefore uses
the GNU nightly. `cargo +nightly` overrides the pin, selects the MSVC host, and
fails; use plain `cargo fuzz` or `cargo +nightly-x86_64-pc-windows-gnu fuzz`.

`fuzz/build_libfuzzer_mingw.sh` runs `cargo fetch --locked` before its offline
metadata lookup, so a clean `CARGO_HOME` (including CI) can resolve
`libfuzzer-sys` instead of failing before the build starts.

## 3. Seed corpus

`fuzz/seeds/{pe,zip,vba,xlm}/` is generated from the same synthetic fixtures the
deterministic campaigns use:

```text
cargo test -p litric-core --test parser_fuzz_soak write_coverage_fuzz_seeds -- --ignored
```

The ignored test writes:

* `pe/minimal-pe64.bin` — PE32+ with one import.
* `zip/ordinary.zip`, `zip/nested.zip`, `zip/macro.docm` — ordinary archive,
  nested ZIP, and an OOXML package.
* `vba/project.cfb`, `vba/macro.docm` — direct CFB project and OOXML wrapper.
* `xlm/workbook.cfb`, `xlm/macro.xlsm` — BIFF8 workbook and OOXML macrosheet.

The campaigns copy these seeds into an evidence corpus and then let libFuzzer
evolve them. The checked-in seeds are the starting points, not the measured
corpus.

## 4. Commands

From the repository root:

```text
bash fuzz/build.sh
bash fuzz/run_campaign.sh all
```

The 120-second duration, all libFuzzer limits, seed refresh and artifact checks
are owned by `fuzz/run_campaign.sh`. A focused run is
`bash fuzz/run_campaign.sh pe`; an explicit duration remains optional:
`bash fuzz/run_campaign.sh pe 30 target/evidence/phase1/fuzz-verify`.

`fuzz/Makefile` exposes `make build`, `make campaign` and
`make campaign-<target> SECONDS=60`. `.github/workflows/fuzz.yml` calls the same
campaign script per target on a nightly schedule; it does not duplicate the
flags. The workflow has not yet been observed on GitHub Actions; the evidence
below is from this Windows 11 host.

The runtime builder fetches the locked fuzz dependencies before its offline
metadata lookup, so `bash fuzz/build.sh` is also the clean-checkout path, not
just a warm local build.

## 5. Measured campaign (2026-11-07)

Command: `bash fuzz/run_campaign.sh all` (120 s per target, the script default;
evidence goes to `target/evidence/phase1/fuzz`)

| Target | Counters | PC entries | Initial cov/ft | Final cov/ft | Executions | Exec/s | Corpus files | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PE | 43,263 | 43,263 | 183 / 183 | 653 / 3,099 | 1,680,830 | 13,891 | 1,144 | 55 MB |
| ZIP | 44,299 | 44,299 | 361 / 674 | 990 / 4,381 | 2,567,924 | 21,222 | 1,054 | 37 MB |
| VBA | 43,221 | 43,221 | 418 / 422 | 976 / 3,798 | 1,600,028 | 13,223 | 962 | 46 MB |
| XLM | 43,217 | 43,217 | 518 / 525 | 1,336 / 4,765 | 2,531,341 | 20,920 | 1,166 | 46 MB |

Totals: **8,380,123 executions**, **4,326 corpus files (5,345,669 bytes)**,
**0 crash/timeout/OOM/leak artifacts**, peak RSS **55 MB**.

Evidence:

* `target/evidence/phase1/fuzz/SUMMARY.txt` — environment, counts, hashes.
* `target/evidence/phase1/fuzz/fuzz-{pe,zip,vba,xlm}.log` — full libFuzzer logs.
* `target/evidence/phase1/fuzz/corpus/<target>/` — evolved corpus.
* `target/evidence/phase1/fuzz/artifacts/<target>/` — empty in this run.

The counter/PC-table equality is the argument that the build is genuinely
instrumented, not merely an exit-0 binary. The `INITED` line and the `NEW`/
`REDUCE` lines show `cov`/`ft` and the corpus growing during the run. These
numbers are coverage features, not detection rate, precision, recall or a
comparison with Malwarebytes.

### 5.1 Independent reproduction

A second bounded run used a fresh evidence directory so it could not reuse the
first run's corpus or logs:

```text
bash fuzz/run_campaign.sh all 30 target/evidence/phase1/fuzz-verify
```

| Target | Counters | Initial cov/ft | Final cov/ft | Executions | New units | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| PE | 43,263 | 183 / 183 | 648 / 2,784 | 986,681 | 3,017 | 35 MB |
| ZIP | 44,299 | 361 / 674 | 797 / 3,383 | 680,257 | 4,251 | 35 MB |
| VBA | 43,221 | 418 / 422 | 939 / 3,253 | 368,981 | 3,746 | 41 MB |
| XLM | 43,217 | 518 / 525 | 1,065 / 3,394 | 463,055 | 3,448 | 45 MB |

Totals: **2,498,974 executions**, **3,111 corpus files**, **14,462 new units**,
**0 artifacts**, peak RSS **45 MB**. This run started from the checked-in seeds
only; coverage grew in every target, so the result is not a replay of a
previously evolved corpus.

After those campaigns, `bash fuzz/build.sh` rebuilt the MinGW runtime and all
four targets from the current tree (exit 0, 47.5 s for the first target and
1–4 s for the rest), and a 1,000-run smoke per rebuilt binary again reported
43k+ counters and non-zero coverage. Evidence:
`target/evidence/phase1/fuzz-verify/SUMMARY.txt`, the four `fuzz-*.log` files,
`fuzz-verify-console.log`, `build.log` and `post-build-smoke.log`. Both runs are
bounded regression campaigns, not multi-hour fuzzing.

### 5.2 Clean-checkout reproduction (2026-11-07)

The local build cache was removed and the dependency registry was made empty, so
the former `cargo metadata --offline` failure could not be hidden by warm state:

```text
rm -rf fuzz/target target/evidence/phase1/clean-cargo-home
CARGO_HOME="$PWD/target/evidence/phase1/clean-cargo-home" bash fuzz/build.sh
bash fuzz/run_campaign.sh pe 30 target/evidence/phase1/fuzz-clean-verify
```

The build exited 0 after `cargo fetch --locked` downloaded the locked graph
(including `libfuzzer-sys`), rebuilt the MinGW runtime, and built all four
targets. The PE campaign then reported:

| Target | Counters | Initial cov/ft | Final cov/ft | Executions | New units | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| PE | 43,263 | 183 / 183 | 606 / 2,481 | 871,292 | 2,790 | 35 MB |

Corpus: 905 units reported by libFuzzer, 904 files on disk; artifacts: **0**.
The 63 MiB downloaded CARGO_HOME cache was removed after the run. Evidence:
`target/evidence/phase1/clean-build.log`,
`target/evidence/phase1/fuzz-clean-verify-console.log`, and
`target/evidence/phase1/fuzz-clean-verify/{SUMMARY.txt,fuzz-pe.log,corpus,artifacts}`.

This proves the clean registry path and one parser campaign, not all four
targets in a clean environment. The campaign script now also fails unless
libFuzzer reports at least one instrumented module and non-zero initial
coverage, so an uninstrumented binary cannot be recorded as a successful run.

## 6. Security review

* **No privileged operations.** Targets are pure byte parsers; no files are
  opened, deleted, quarantined or restored.
* **Bounded work.** The existing archive/VBA/XLM caps apply; libFuzzer runs with
  `-max_len=65536`, `-timeout=10`, `-rss_limit_mb=2048`.
* **No live malware.** Seeds are synthetic fixtures; the campaigns do not
  download or execute samples.
* **No silent Clean.** A parser result is discarded by the harness; fuzzing
  cannot turn Unknown or Error into Clean.
* **Failure containment.** A panic aborts the fuzz target and is saved as an
  artifact; it does not touch the user's files. The parsers remain in-process,
  so this does not provide process isolation.

## 7. Limitations

* **No sanitizer.** `--sanitizer none` was required. Coverage-guided fuzzing finds
  crashes and hangs; without ASan/UBSan it is weaker at finding silent memory
  errors. A sanitizer run on an MSVC/ASan or Linux host is still required.
* **Short campaigns.** 120 seconds per target is a bounded regression run, not a
  multi-hour soak. Corpus minimisation and long-duration leak/handle tests are
  not done.
* **Synthetic seeds.** They cover the synthetic fixture shapes, not the full
  PE/Office feature space or real malware families.
* **No structure-aware mutator.** libFuzzer mutates bytes; it does not know ZIP,
  CFB or BIFF grammar.
* **Custom runtime.** The MinGW libFuzzer shim is local support code and must be
  revalidated if `libfuzzer-sys` changes. It is not part of the product.
* **In-process parsers.** A memory-corrupting parser bug could still affect the
  scanner process; parser worker isolation remains open.
* **Windows-only.** The repository is Windows-only by policy; no Linux fuzzing
  evidence is claimed.
* **CI unverified.** The nightly workflow is checked in but has not run on
  GitHub Actions yet. Do not cite it as executed evidence.

## 8. Files

| File | Change |
|---|---|
| `fuzz/Cargo.toml` | fuzz workspace with four `[[bin]]` targets |
| `fuzz/fuzz_targets/fuzz_{pe,zip,vba,xlm}.rs` | target bodies |
| `fuzz/build.rs` | passes the COFF sancov linker script to fuzz binaries |
| `fuzz/build.sh` | builds the runtime and all targets |
| `fuzz/run_campaign.sh` | bounded campaigns, logs, corpus, artifact checks |
| `fuzz/build_libfuzzer_mingw.sh` | builds libFuzzer's C++ runtime with MinGW |
| `fuzz/support/FuzzerExtFunctionsWindows.cpp` | MinGW replacement for optional hooks |
| `fuzz/support/FuzzerExtraCountersWindows.cpp` | safe empty extra-counter range |
| `fuzz/support/sancov_mingw.ld` | COFF section boundary symbols |
| `fuzz/.cargo/config.toml`, `fuzz/rust-toolchain.toml` | local runtime/toolchain selection |
| `fuzz/seeds/**` | fixture-derived starting corpus |
| `fuzz/Makefile` | `build`/`campaign` targets |
| `.github/workflows/fuzz.yml` | nightly bounded CI campaign |
| `crates/litric-core/tests/parser_fuzz_soak.rs` | ignored seed generator |
| `docs/PHASE1_COVERAGE_FUZZ.md` | this report |

## 9. Exit gate

S-15 is **ADDRESSED for the parser scope**: four coverage-guided targets exist,
build, and ran real campaigns with non-zero, growing coverage and no crash
artifacts. S-15 is not fully closed for the product: sanitizer coverage, parser
process isolation and long-duration campaigns remain open. Phase 1 is therefore
still **PARTIAL**, not complete.
