# Build and verification memory

## Toolchain

* Windows 11 x64 is the only supported host. The repository has no POSIX test
  path, no Wine runner and no cross-platform build instructions.
* Rust 1.99.0 (`rustc`/`cargo`) with the `x86_64-pc-windows-gnu` target was used
  for the recorded run. Workspace minimum is Rust 1.85; `litric-yara` needs 1.95
  (yara-x).
* Put Cargo on `PATH` in Git Bash with `export PATH="$HOME/.cargo/bin:$PATH"`.

## Commands (PowerShell or Git Bash)

```powershell
cargo test --workspace
cargo test -p litric-safeos
cargo build --release
cargo clippy --workspace --all-targets -- -D warnings
```

For the GNU toolchain explicitly:

```powershell
cargo +stable-x86_64-pc-windows-gnu test --workspace
cargo +stable-x86_64-pc-windows-gnu build --release -p litric-cli
```

Run the daemon:

```powershell
.\target\release\litricd.exe serve --addr 127.0.0.1:8787 --data-dir .\litric-data --rules rules
# token: .\litric-data\api.token
.\target\release\litric.exe status --addr 127.0.0.1:8787 --token-file .\litric-data\api.token
```

## Test counts at last verification (2026-11-07)

**597 passed, 0 failed, 1 ignored**, exit 0, on Windows 11 Home build 26300 with
`x86_64-pc-windows-gnu` (568 before the Phase 0/1 fixes). 57 test binaries are
reported, but only 18 contain tests; the 20 doctest harnesses contain 0 tests.
Quarantine ADS/timestamp evidence: `docs/PHASE1_QUARANTINE_METADATA.md`;
clippy is **not** clean repository-wide, so do not cite a clippy pass.
Re-run and update this line; do not assume.

Parser mutation/soak suite:
`cargo test -p litric-core --test parser_fuzz_soak -- --nocapture --test-threads=1`
(8 runnable tests + 1 ignored seed generator; 45,000 deterministic PE/ZIP/VBA/XLM
mutations, crafted limit cases, memory sampling and 8-thread determinism).
Evidence and interpretation: `docs/PHASE1_PARSER_SOAK.md` and
`target/evidence/phase1/parser-soak-final.log`. The memory probe is a read-only
`GetProcessMemoryInfo` call in the test file; it samples retained private bytes
between inputs, not instantaneous allocation peaks.

Coverage-guided parser fuzzing:

```bash
bash fuzz/build.sh                 # fetches locked fuzz deps, so it works with an empty CARGO_HOME
bash fuzz/run_campaign.sh all      # 120 s per target, owned by the script
```

Four `cargo-fuzz` targets (PE/ZIP/VBA/XLM) pinned to
`nightly-x86_64-pc-windows-gnu`; the workspace is GNU-only, not MSVC. 8,380,123 executions and 0 crash artifacts on
2026-11-07, with `--sanitizer none`. Reproduced from the checked-in seeds in a
fresh directory: 2,498,974 executions, 14,462 new units, 0 artifacts. Evidence:
`target/evidence/phase1/fuzz/SUMMARY.txt` and
`target/evidence/phase1/fuzz-verify/SUMMARY.txt`; the clean-checkout proof is
`target/evidence/phase1/clean-build.log` plus
`target/evidence/phase1/fuzz-clean-verify/SUMMARY.txt`; committed summaries are
indexed in `docs/evidence/phase1/README.md`. Method and limitations:
`docs/PHASE1_COVERAGE_FUZZ.md`. `.github/workflows/fuzz.yml` runs the same
bounded campaign nightly but has not yet executed on GitHub Actions; do not
cite it as evidence.

`litric guard` contributes 8 policy tests in `litric-core` and 4 end-to-end
launch/quarantine tests in `litric-cli/tests/guard_e2e.rs`. Scan-time quarantine
contributes 3 real-binary folder/file/failure tests in
`crates/litric-cli/tests/scan_quarantine_e2e.rs`, 1 daemon/service repeatability
test, and 2 checked-vault unit tests.

`crates/litric-cli/tests/platform_evidence.rs` enforces the Windows-only rule:
it fails if a `#[cfg(unix)]`/`#[cfg(not(windows))]` gate or an exclusion marker
is reintroduced, and it compares the readiness gate's `test_evidence` block with
`docs/SAFEOS_READINESS.md`.

## Known test-environment interaction

Four daemon end-to-end tests write EICAR to a temporary file. With Windows
Defender real-time protection active, Defender removes or locks that file and
those tests fail (the scan reports `unreadable 1`). This is the host AV, not
Litric. The recorded 597/0 run had Defender real-time disabled by the user; do
not add an AV exclusion or disable Defender yourself.

## Quarantine and guard coverage

Quarantine lifecycle, recovery, ADS/timestamp and file-identity tests live in
`litric-core` (`quarantine::tests::*`, `winplatform::filemeta::tests::*`) and in
the CLI end-to-end suite (`quarantine_lifecycle_*`, `quarantine_refuses_*`,
`scan_quarantine_preserves_alternate_streams_and_timestamps`). The readiness
refusal is `litric-service`'s `readiness_gate_refuses_to_claim_ready`.

The pre-execution guard is covered by `guard::tests::*` and
`guard_e2e::{malicious_target_is_quarantined_before_it_can_run,
malicious_target_stays_in_place_but_is_blocked_without_quarantine,
unknown_is_blocked_by_default,unknown_can_run_only_with_the_explicit_override}`.
Run it with `cargo test -p litric-cli --test guard_e2e`.

Scan-time quarantine is covered by `scan_quarantine::*` (checked vault digest),
`scan_quarantine_e2e::{directory_scan_moves_only_malicious_and_is_safe_to_repeat,
single_file_target_is_quarantined,a_failed_vault_write_retains_the_original_and_exits_4}`,
and `api::tests::scan_auto_quarantines_only_malicious_and_is_repeatable`.
Run the real-binary suite with `cargo test -p litric-cli --test scan_quarantine_e2e`.
Exit codes for `scan --quarantine-malicious`: 0 no malicious files, 1 malicious
found (even after a successful move), 4 any quarantine failure.

ZIP-family recursion is covered by `archive::tests::*` (member cap, depth cap,
traversal names), `engine::tests::{zip_member_with_eicar_is_malicious,
benign_zip_stays_unknown,nested_zip_member_is_inspected,
archive_depth_limit_is_reported_not_silently_clean}`, and
`scan_quarantine_e2e::malicious_zip_member_quarantines_the_container_without_touching_benign_files`.
Members are read into memory, never extracted: 512 entries, 16 MiB/member,
64 MiB per layer, 1000:1 ratio, depth 3. Truncation is surfaced via
`FileReport::archive_truncated` and can never produce a `Clean` container.

De-obfuscation is covered by `deobfuscate::tests::*` (19),
`engine::tests::{an_encoded_powershell_payload_is_decoded_and_detected,
base64_of_a_benign_image_does_not_escalate_a_script,unmarked_base64_is_never_decoded,
a_two_layer_encoded_payload_is_decoded_end_to_end,
a_benign_char_array_does_not_escalate_a_script}`,
and `scan_quarantine_e2e::{an_encoded_powershell_dropper_is_quarantined,
an_xor_char_array_dropper_is_quarantined}`.
Decode limits: 4 MiB input, 256 KiB/blob, 1 MiB decoded, 8 blobs/layer,
depth 3, and one shared `WorkBudget` of 8,000,000 steps per file. Only explicit
constructs are decoded; char-array payloads must be printable ASCII; only a
malicious decoded result escalates the verdict.

VBA analysis is covered by `vba::tests::*` (14) and
`engine::tests::{an_ooxml_macro_dropper_is_flagged,
a_legacy_ole_document_with_a_macro_is_flagged,a_benign_macro_is_not_escalated}`.
Fixtures build real OLE2 sector layouts (header, FAT, directory, mini stream,
mini FAT) and real OOXML ZIPs, so extraction is exercised against the format
rather than a stub. Limits: 8 MiB project, 64 streams, 2 MiB/stream,
1 MiB/module, 8 MiB total. Source-level only: no p-code or encrypted modules;
XLM is handled by `xlm.rs`/`biff.rs`. The reader follows MS-CFB offsets (FAT count at 0x2C, first
directory sector at 0x30) and MS-OVBA chunk headers (low 12 bits = size - 3,
bits 12-14 = 0b011, bit 15 = compressed).

Excel 4.0 and VBA p-code coverage lives in `xlm::tests::*` (13),
`biff::tests::*` (16),
`vba::tests::{a_performance_cache_before_the_source_is_skipped_and_counted,
a_cache_only_module_is_reported_as_possible_stomping}`, and
`engine::tests::{an_xlsm_macro_sheet_is_flagged,
a_legacy_xls_macro_sheet_is_suspicious,a_legacy_xls_exec_formula_is_flagged,
a_biff5_xls_exec_formula_is_flagged,a_vba_pcode_cache_is_reported_not_interpreted}`.
XLSM fixtures are real ZIPs; legacy fixtures are real OLE2 compound files carrying
BIFF5, BIFF7 and BIFF8 `BOUNDSHEET` records and macro-sheet `FORMULA` records.
BIFF5/7 use one-byte code-page strings (decoded as Latin-1) and three-byte cell
references; the tokens of all three versions are decoded with the generated
MS-XLS Ftab table (`biff_ftab.rs`); array constants are resolved from the
record's `rgcb` (`PtgExtraArray`) and the `PtgMemArea`/`PtgMemErr`/`PtgMemFunc`
headers are skipped so the reference they wrap still renders; unknown ids render
as `FUNC_/MACRO_0xNNNN` and mark the formula incomplete. Module streams are `PerformanceCache || CompressedSourceCode`
per MS-OVBA, so extraction validates a chunk chain before accepting an offset;
cache-only streams are flagged as possible stomping. p-code is counted, never
decompiled. Caps: 64 sheets, 4096 formulas, 64 KiB/formula, 2 MiB/sheet part.

## Measured Windows baseline (2026-11-07)

`litric bench` on the host in `docs/WINDOWS_EVIDENCE.md`: 767 PowerShell files
in 1.520 s (505 files/s), 603 driver images in 10.832 s (56 files/s), 73 rules,
single-threaded. `scan --local --json` on the same corpora took 2.503 s and
15.961 s including process start-up and report writing. 1,370 benign OS files
produced 0 malicious and 0 suspicious verdicts. These are not vendor benchmarks.

## Environment constraints

* Windows 11 Home build 26300 has no Windows Sandbox and no Hyper-V role; the
  SafeOS launch path cannot be exercised on this host.
* `litricd` runs in the foreground; there is no SCM wrapper.
* Don't run `cargo fmt` blind on the whole tree; it rewrites hand-formatted tests.
* Don't leave a `litricd` listening on the demo port between runs: kill the PID
  you started, never by process-name patterns.
