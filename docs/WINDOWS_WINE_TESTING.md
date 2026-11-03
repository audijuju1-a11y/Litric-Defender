# Windows-target tests under Wine — reproduction

This page documents the **Wine Windows-ABI run**, not native Windows. The test
binaries are built for `x86_64-pc-windows-gnu` and executed by Wine on Linux.
Wine can catch Windows API/handle/path behavior, but it is not a Windows 11 host;
see `docs/SAFEOS_WINDOWS_VERIFICATION.md` for the manual host checklist.

## What was run

| Item | Value |
|---|---|
| Host | Ubuntu 24.04.5 LTS, x86_64 |
| Rust | `rustc 1.99.1`, `cargo 1.99.1` |
| Cross linker | MinGW-w64 GCC 13.2.0 (`x86_64-w64-mingw32-gcc-13-posix`) |
| Windows target | `x86_64-pc-windows-gnu` |
| Wine | **11.21** portable build, SHA-256 `1f12f2aef4f5d0b5c0548ceecdb20068edc59fcd23a5da481e7059a25070eac9` |
| Result | **195 passed, 0 failed, 0 ignored**, `cargo test` exit **0** |
| Native control | **203 passed, 0 failed**, `cargo test` exit **0** |

The final 195/195 run was made after `cargo clean` removed **6,041 files / 1.3
GiB** (an earlier full clean removed 12,835 files / 2.8 GiB). It was not reused
from a cached target directory. The setup script was also exercised from a
fresh user-owned root in this workspace: it exited 0, produced `wine-11.21`, and
ran a freshly compiled `hello.exe` with exit 0.

## One-time setup (no root)

The setup is user-local. It downloads packages and extracts them under a
persistent cache; it does **not** install system packages, use `sudo`, or write
to `/usr`.

```bash
# Default: ${XDG_CACHE_HOME:-$HOME/.cache}/litric-wine
# Keep this outside /tmp: Wine refuses a prefix directly under root-owned /tmp.
export LITRIC_WINE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/litric-wine"
scripts/windows-wine/setup.sh
```

`setup.sh` performs these steps:

1. Updates an apt state directory under `$LITRIC_WINE_ROOT` and downloads the
   MinGW-w64 GCC/binutils/headers, the i386 glibc/libgcc/libstdc++ runtime, and
   `patchelf`.
2. Extracts those `.deb` files into `$LITRIC_WINE_ROOT/{mingw,i386,host}`.
3. Creates the `x86_64-w64-mingw32-gcc` wrapper with the extracted includes,
   libraries and linker search path.
4. Downloads Kron4ek's Wine 11.21 build and verifies its SHA-256.
5. Patches only this Wine copy's 32-bit ELF interpreter to the extracted
   `ld-linux.so.2`:
   ```bash
   "$ROOT/host/usr/bin/patchelf" --set-interpreter \
       "$ROOT/i386/usr/lib/i386-linux-gnu/ld-linux.so.2" \
       "$ROOT/wine/lib/wine/i386-unix/wine"
   ```
6. Writes `$ROOT/run-wine.sh`; it sets `WINEPREFIX`, `WINEARCH=win64`,
   `WINELOADER`, `WINEDLLPATH`, `WINEDEBUG=-all` and the local i386 library path.
7. Initializes the Wine prefix. Keep `LITRIC_WINE_ROOT` in a user-owned
   directory; Wine will not create a prefix under root-owned `/tmp`.

No `.cargo/config.toml` is committed. A committed runner path would be
machine-specific; `run-tests.sh` supplies the two Cargo variables instead:

```bash
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$ROOT/bin/x86_64-w64-mingw32-gcc"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER="$ROOT/run-wine.sh"
```

## Clean run

```bash
# 1. Native POSIX suite from an empty target tree.
cargo clean
cargo test

# 2. Windows target: build, install the MinGW runtime DLLs, execute under Wine.
#    This is the same sequence encoded in the script.
scripts/windows-wine/run-tests.sh
```

Expected fresh results:

```text
cargo clean: Removed 6041 files, 1.3GiB total
native:      test result: ok. 203 passed; 0 failed; 0 ignored
windows:     test result: ok. 195 passed; 0 failed; 0 ignored
exit codes:  native 0, windows 0
```

The machine-readable per-test transcript from this run is in
[`WINDOWS_WINE_TEST_EVIDENCE.txt`](WINDOWS_WINE_TEST_EVIDENCE.txt).

The Windows suite runs one binary at a time (`--test-threads=1`) so an output
line belongs to the test that produced it. `run-tests.sh` first builds with
`--no-run`, copies `libwinpthread-1.dll` and `libgcc_s_seh-1.dll` into
`target/x86_64-pc-windows-gnu/debug{,/deps}`, then executes the suite with
`--no-fail-fast`.

## What the eight exclusions are

`cargo test` for the Windows target compiles 195 tests; the POSIX suite has 203.
The eight-test difference is **not** eight hidden failures. Six are genuinely
non-Windows platform tests; two are Windows coverage gaps, and those two are
reported as gaps rather than counted as passing.

| Test | Source guard | Classification |
|---|---|---|
| `litric-agent/tests/agent_e2e.rs::launch_refuses_politely_without_a_windows_launcher` | `#[cfg(not(windows))]` | POSIX-only: asserts the non-Windows 501 refusal |
| `litric-cli/tests/safeos_launch_verify.rs::every_readiness_blocker_is_named_and_reevaluated` | file-level `#![cfg(not(windows))]` | POSIX-only: non-Windows launch gate |
| `litric-cli/tests/safeos_launch_verify.rs::unsafe_paths_are_rejected_with_stable_messages` | file-level `#![cfg(not(windows))]` | POSIX-only: non-Windows path/gate expectations |
| `litric-cli/tests/safeos_launch_verify.rs::a_valid_request_writes_a_locked_down_config_and_stops_at_the_platform_gate` | file-level `#![cfg(not(windows))]` | POSIX-only: asserts the 501 platform gate |
| `litric-cli/tests/safeos_launch_verify.rs::no_launch_path_executes_the_host_application` | file-level `#![cfg(not(windows))]` | POSIX-only: `/bin/sh` canary and POSIX mode bits |
| `litric-safeos/src/sandbox.rs::a_file_name_with_separators_cannot_escape_the_mapping` | `#[cfg(not(windows))]` | POSIX-only: Windows treats `\` as a separator, so the fixture is not a filename there |
| `litric-core/src/scan.rs::hard_links_are_deduplicated` | `#[cfg(unix)]` | **Windows coverage gap**: NTFS hard links exist, but file-id dedupe is not implemented, so Windows would scan both names and the test would fail. This is a feature gap, not a passing test. |
| `litric-safeos/src/broker.rs::symlinks_are_refused` | `#[cfg(unix)]` | **Windows coverage gap**: the test creates a symlink as an unprivileged user; Windows needs a symlink privilege/developer mode. The refusal path has not been exercised on Windows. |

The first six are marked `// POSIX-ONLY-TEST:`; the two coverage gaps are marked
`// WINDOWS-EXCLUDED-TEST:` and carry a comment stating the gap. The gate's
`windows_excluded_tests` list and `platform_evidence` enforce that every excluded
test has one marker and appears in the doc/gate. The Windows counterparts remain
`UNPROVEN`; Wine does not make them pass.

## What this proves, and what it does not

**Proved by this run:**

- The Windows-target Rust test binaries build and execute as PE processes under
  Wine 11.21.
- The portable code paths exercised by 195 tests pass with Windows handle,
  path, process and filesystem API semantics supplied by Wine.
- The previously real broker export bug is fixed: Windows `FlushFileBuffers`
  requires a writable handle, so the temp file is now opened read/write before
  `sync_all`.
- The test harness has no hidden `#[ignore]`/skipped-test escape hatch; the
  eight exclusions are explicit source cfg sites.

**Not proved:**

- Native Windows 11, native NTFS, Windows Sandbox launch or the guest boundary.
- Windows file-id hard-link dedupe, because it is not implemented.
- Unprivileged Windows symlink refusal, because the fixture is not available.
- The four SafeOS launch tests and the agent non-Windows refusal, which are
  intentionally not Windows tests.

For the real-host checks, use `docs/SAFEOS_WINDOWS_VERIFICATION.md`. The
readiness gate continues to report native Windows execution and
`quarantine_windows_filesystem_semantics` as `UNPROVEN`; `safeos_sandbox_launch`
and `safeos_sandbox_guest_runtime` likewise remain `UNPROVEN` on native Windows.

Wine prints a non-fatal FreeType warning in this sandbox because the portable
build cannot find a font library; it does not change test exit codes or counts.
