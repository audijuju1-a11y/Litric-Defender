# Build and verification memory

## Toolchain

* Rust 1.99.1 at `$HOME/.cargo/bin` — export it first:
  `export PATH="$HOME/.cargo/bin:$PATH"`.
* Workspace members: `litric-core`, `litric-service`, `litric-cli`,
  `litric-safeos`.
* Windows cross-target installed: `x86_64-pc-windows-gnu`. It has been run under
  Wine 11.21; native Windows has not been available.

## Commands

```bash
cargo test                                   # all crates
cargo test -p litric-safeos                  # one crate
cargo build --release                        # must have zero warnings
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo test --workspace --all-targets --target x86_64-pc-windows-gnu
```

Run the daemon:

```bash
./target/release/litricd serve --addr 127.0.0.1:8787 --data-dir ./litric-data --rules rules
# token: ./litric-data/api.token
./target/release/litric status --addr 127.0.0.1:8787 --token-file ./litric-data/api.token
```

## Test counts at last verification

90 core + 24 service + 8 client + 21 cli integration + 55 safeos + 7 agent +
5 agent end-to-end = 210. Re-run and update this line; do not assume.

That count was produced on Linux x86_64 (POSIX host). The Windows-target suite
was also executed under Wine 11.21: 195 passed, 0 failed, with the 8 documented
Windows-excluded tests (6 POSIX-only, 2 coverage gaps). Wine is not native
Windows; NTFS, native Windows 11 and Windows Sandbox guest behavior remain
UNPROVEN. The local test command needs a MinGW cross-linker and a Wine runner;
`scripts/windows-wine/setup.sh` builds both without root and
`scripts/windows-wine/run-tests.sh` executes the suite. Full reproduction and
clean-run evidence: `docs/WINDOWS_WINE_TESTING.md`.
`tests/platform_evidence.rs` enforces the exclusion markers and the gate/doc
`test_evidence` block.

Quarantine lifecycle and recovery tests live in `litric-core` (`quarantine::tests::
recovery_*`, `double_restore_*`, `corrupted_entry_*`) and in the CLI end-to-end
suite (`quarantine_lifecycle_*`, `quarantine_refuses_*`). The readiness refusal is
`litric-service`'s `readiness_gate_refuses_to_claim_ready`.

## Environment constraints

* No Windows host, no Hyper-V, no WFP, no WDK, no browser automation.
* `litricd` runs in the foreground; there is no SCM wrapper.
* Don't run `cargo fmt` blind on the whole tree; it rewrites hand-formatted tests.
* Don't leave a `litricd` listening on the demo port between runs: kill by PID from
  `ss -ltnp`, never by process-name patterns.
