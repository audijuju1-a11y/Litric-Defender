# Phase 1 — parser mutation, soak and concurrency evidence

## Summary

| Field | Value |
|---|---|
| Phase | 1 (second slice) — core safety |
| Status | **PARTIAL** (slice complete; Phase 1 still has open items) |
| Date | 2026-11-07 |
| Host | Windows 11 Home 26H2, build 26300.9457, x64, NTFS |
| Toolchain | rustc/cargo 1.99.0, target `x86_64-pc-windows-gnu` |
| Parser suite at this report | **8 passed, 0 failed, 0 ignored**, exit 0 (the later fuzz slice adds one ignored seed generator) |
| Full workspace | **590 passed, 0 failed, 0 ignored**, exit 0 (582 before this slice) |
| Evidence | `target/evidence/phase1/parser-soak-final.log`, `target/evidence/phase1/workspace-tests-parser-soak-final.log` |
| Git | no repository metadata in this workspace |

This slice adds a deterministic mutation/soak/concurrency harness for the four
parsers that take hostile input directly: PE, ZIP-family archives, VBA and
Excel 4.0 (XLM). It also fixes one accounting defect the harness found: a
truncated OLE2 workbook could produce an empty XLM report with no note, which is
indistinguishable from "no macro sheets".

The parser caps are the security boundary here; the tests assert them instead of
assuming they hold.

## Requirements addressed

* Fuzz PE, archive, VBA and XLM parsers with reproducible inputs (S-15).
* Exercise malformed, truncated and oversized containers without panics or hangs.
* Prove archive-bomb, path-traversal and per-layer byte/entry limits are enforced.
* Prove corrupt containers are reported as not inspected, not silently "clean".
* Measure retained memory across repeated batches and peak private bytes (S-16).
* Exercise the parsers concurrently and compare results with a sequential run.
* Keep the suite deterministic and fast enough for the normal workspace run.

## Implementation

### Harness — `crates/litric-core/tests/parser_fuzz_soak.rs`

* **Deterministic PRNG.** SplitMix64 with fixed seeds; a failing input reproduces
  exactly. No network, no time, no external corpus.
* **Mutation operators.** Bit flips, 32-bit field replacement, interesting 16-bit
  values, truncation, chunk duplication/deletion and increment/decrement of
  length/offset fields. Inputs are capped at 256 KiB.
* **Synthetic fixtures.** A PE32+ image with one import, a ZIP package, a valid
  OLE2 VBA project (mini stream + FAT), a BIFF8 workbook with a real Excel 4.0
  formula record, and OOXML packages. The CFB writers mirror the in-crate test
  fixtures so the released library is exercised through its public API.
* **Campaigns.** Each campaign records successes, expected parse errors, panics,
  maximum single-input time, and sampled private/working bytes after each batch.
  A campaign fails if any input panics, no input reaches a successful parse, or
  one input exceeds 5 seconds.
* **Crafted cases.** Separate tests cover:
  * a 1 MiB deflate bomb (ratio limit, no expansion into the callback),
  * traversal/drive-absolute/absolute member names (never handed to analysis),
  * 40 entries against a 32-entry cap,
  * 10 × 8 KiB members against a 20 KiB aggregate cap,
  * truncation of VBA CFB, VBA OOXML, XLM OOXML and XLM BIFF inputs,
  * extreme values in PE and CFB header fields,
  * a 12,288-call, 8-thread concurrent determinism run over 64 mixed inputs.
* **Memory probe.** `GetProcessMemoryInfo` reads private commit, working set and
  the OS lifetime peak. This is the only `unsafe` in the test file, is read-only,
  and is not called by any parser. It is not an instantaneous allocation hook:
  the report says "sampled", not "peak allocation".

### Production fix — `vba.rs::read_stream_named`, `xlm.rs::extract_biff`

The legacy XLM path used `Option<Vec<u8>>`, collapsing three different states:

1. valid OLE2 container with no `Workbook` stream (legitimate non-Excel file),
2. unreadable or above-cap stream,
3. malformed compound file.

All three returned `None`; `extract_biff` returned an empty report for all of
them. The first case may be empty, but cases 2 and 3 must be visible. The helper
now returns `Result<Option<Vec<u8>>, &'static str>`:

* `Ok(None)` — parsed container, no named stream;
* `Err(reason)` — malformed container, stream above 64 MiB, or an incomplete FAT
  chain.

`extract_biff` records `legacy workbook stream was not inspected: <reason>` and
returns. The engine already treats report notes as evidence, and `Clean` still
requires a positive trust record, so this cannot turn an uninspected file clean.

No detection threshold, rule, verdict weight or enforcement policy was changed.

## Files changed

| File | Change |
|---|---|
| `crates/litric-core/tests/parser_fuzz_soak.rs` | new: 8-test mutation/soak/concurrency harness |
| `crates/litric-core/src/vba.rs` | `read_stream_named` distinguishes missing from unparseable/unreadable |
| `crates/litric-core/src/xlm.rs` | reports an uninspected legacy workbook stream |
| `crates/litric-core/Cargo.toml` | enables `Win32_System_ProcessStatus` / `Win32_System_Threading` for the memory probe |
| `docs/PHASE1_PARSER_SOAK.md` | this report |
| `docs/PHASE1_COVERAGE_FUZZ.md` | follow-up: four coverage-guided `cargo-fuzz` targets and measured campaigns |
| `docs/SECURITY_GAP_ANALYSIS.md` | S-15/S-16 status |
| `docs/LIMITATIONS.md` | parser-robustness wording |
| living status/count docs | 582 → 590 where they describe the current suite |

## Tests

```text
cargo +stable-x86_64-pc-windows-gnu test -p litric-core --test parser_fuzz_soak -- --nocapture --test-threads=1
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

Parser-suite output (final serial run):

| Campaign | Iterations | Parsed | Rejected | Panics | Elapsed | Max input | Sampled private delta | Lifetime peak* |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PE | 20,000 | 16,516 | 3,484 | 0 | 580 ms | 804 µs | 20 KiB | 3,876 KiB |
| ZIP | 8,000 | 1,967 | 6,033 | 0 | 129 ms | 1,381 µs | 112 KiB | 20,628 KiB |
| VBA CFB | 6,000 | 2,378 | 3,622 | 0 | 346 ms | 6,478 µs | 100 KiB | 15,768 KiB |
| VBA OOXML | 3,000 | 1,158 | 1,842 | 0 | 394 ms | 1,205 µs | 796 KiB | 16,528 KiB |
| XLM BIFF | 5,000 | 2,124 | 2,876 | 0 | 178 ms | 5,936 µs | 12 KiB | 20,628 KiB |
| XLM OOXML | 3,000 | 3,000 | 0 | 0 | 206 ms | 616 µs | 0 KiB | 20,628 KiB |

\* Process-wide OS lifetime peak, including earlier tests and fixtures; it is not
per-campaign and must not be read as parser-only memory. The sampled delta is
the campaign baseline difference. Timings vary with host load; the exact final
run is in the evidence log. "Parsed" means the parser returned a non-empty
structural result; it is not a verdict and never means clean.

* **45,000** mutated inputs total, **0 panics**.
* Concurrency: **8 threads × 8 passes × 64 cases**, 12,288 parser calls, 44 ms,
  ~273k calls/s, **0 sequential/concurrent mismatches**.
* Full workspace: **590 passed, 0 failed, 0 ignored**, exit 0. The previous run
  was 582; this slice adds 8 tests.

## Security review

* **Resource caps are asserted, not assumed.** Every successful archive parse is
  checked against entry, member, total and depth caps; VBA against stream,
  module and total caps; XLM against sheet, formula and formula-size caps; PE
  against section, DLL, function and export caps.
* **Archive bombs.** A 1 MiB member that deflates to ~1 KiB is rejected by the
  ratio check; the callback receives zero bytes. The aggregate cap is tested with
  individually acceptable members.
* **Path traversal.** `../`, `..\`, `C:/` and `/` member names never reach the
  analysis callback; each is counted as skipped with a note.
* **Malformed input.** 45,000 mutations produced no panic. Truncated VBA/XLM
  containers now produce a note or `truncated`, never a silent empty result.
* **No unsafe in parser code.** The only unsafe in this slice is the test's
  read-only `GetProcessMemoryInfo` call. `litric-core` production code remains
  free of parser `unsafe`.
* **No data loss or privilege change.** Tests use temporary in-memory fixtures;
  they do not scan live malware, change Defender/firewall/UAC settings, or touch
  user files.
* **Concurrency.** Parsers take `&[u8]`, own their output and share no mutable
  state; identical inputs produced identical fingerprints under 8 threads.

Residual risks:

* The fixtures are synthetic; they do not represent the full PE/Office feature
  space or real-world malware.
* Deterministic mutation is not coverage-guided. Four `cargo-fuzz` targets now
  exist and ran 8.38M executions, but they use `--sanitizer none`, do not
  minimise the corpus and do not replace a sanitizer run. See
  [`PHASE1_COVERAGE_FUZZ.md`](PHASE1_COVERAGE_FUZZ.md).
* The harness runs in-process. A parser that aborts, corrupts memory or hangs
  cannot be contained by `catch_unwind`; there is no per-input watchdog or
  process isolation.
* The memory probe samples between inputs, so a short-lived allocation spike
  inside one parse is not measured. It is evidence against retained growth, not
  a heap profile. The "soak" is a bounded four-batch campaign, not a multi-hour
  run; handle/GDI counts and long-duration leak behaviour were not measured.
* The archive reader is the third-party `zip` crate; its internal behaviour is
  exercised but not audited here.
* No fuzzing has been run on non-Windows hosts. This repository is Windows-only
  by policy.

## Exit gate

**PARTIAL.** This deterministic harness remains the fast regression check.
S-15 is now addressed for its parser scope by the separate coverage-guided
harness in [`PHASE1_COVERAGE_FUZZ.md`](PHASE1_COVERAGE_FUZZ.md) (four targets,
8.38M executions, no crash artifacts), but that run has no sanitizer and no
parser process isolation. S-16 is addressed by batch memory sampling and a
concurrency determinism test. Phase 1 remains open for sanitizer/power-loss
coverage. This must not be reported as "Phase 1 complete".

## Next

ADS/timestamp preservation and identity-bound quarantine deletion were delivered
in the follow-up `docs/PHASE1_QUARANTINE_METADATA.md` (current suite: 597 passed,
0 failed). Coverage-guided fuzzing was delivered separately in
[`PHASE1_COVERAGE_FUZZ.md`](PHASE1_COVERAGE_FUZZ.md). The next Phase 1 work is a
sanitizer-backed fuzz run, real crash/power-loss recovery evidence and parser
process isolation; none is claimed here.
