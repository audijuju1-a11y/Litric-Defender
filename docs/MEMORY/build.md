# Build and verification memory

## Toolchain

* Rust 1.99.1 at `$HOME/.cargo/bin` — export it first:
  `export PATH="$HOME/.cargo/bin:$PATH"`.
* Workspace members: `litric-core`, `litric-service`, `litric-cli`,
  `litric-safeos`.
* Windows cross-target installed: `x86_64-pc-windows-gnu` (compile check only).

## Commands

```bash
cargo test                                   # all crates
cargo test -p litric-safeos                  # one crate
cargo build --release                        # must have zero warnings
cargo check --target x86_64-pc-windows-gnu -p litric-core
```

Run the daemon:

```bash
./target/release/litricd serve --addr 127.0.0.1:8787 --data-dir ./litric-data --rules rules
# token: ./litric-data/api.token
./target/release/litric status --addr 127.0.0.1:8787 --token-file ./litric-data/api.token
```

## Test counts at last verification

83 core + 19 service + 8 client + 12 end-to-end + 39 safeos = 161. Re-run and
update this line; do not assume.

## Environment constraints

* No Windows host, no Hyper-V, no WFP, no WDK, no browser automation.
* `litricd` runs in the foreground; there is no SCM wrapper.
* Don't run `cargo fmt` blind on the whole tree; it rewrites hand-formatted tests.
* Don't leave a `litricd` listening on the demo port between runs: kill by PID from
  `ss -ltnp`, never by process-name patterns.
