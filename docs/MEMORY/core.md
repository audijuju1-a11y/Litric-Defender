# Core engine area memory

Crate: `crates/litric-core` (90 tests). Zero `unsafe`.

| Module | Responsibility |
|---|---|
| `bytes.rs` | bounds-checked little-endian readers, C strings, UTF-16 |
| `hash.rs` | SHA-256 (`Digest32::to_hex`) |
| `entropy.rs` | Shannon entropy, windowed entropy |
| `format.rs` | content-type detection, extension chains, embedded PE |
| `pe.rs` | PE32/PE32+ parse, sections, imports, resources, overlay, flags |
| `authenticode.rs` | WIN_CERTIFICATE/DER walk (no chain validation) |
| `rules.rs` | `.lrs` lexer/parser/validator + Aho-Corasick matcher |
| `heuristics.rs` | weighted, explained signals with MITRE IDs |
| `engine.rs` | verdict aggregation; `Clean` only via trusted hash |
| `threatdb.rs` | Ed25519-signed DB, anti-rollback, atomic install |
| `scan.rs` | walker, budgets, cache, progress/cancel hooks |
| `quarantine.rs` | XChaCha20-Poly1305 vault, verify-before-delete, journaled restore/purge/recovery |
| `ranshield.rs` | behavioural scoring, honey vault, response policy |

Invariants: `Unknown` is never counted as clean; `Suspicious`/`Malicious` require
evidence; scan budgets are hard; cancellation is cooperative via `AtomicBool`.

Known gaps: archive recursion, macro extraction, fuzzy hashing, parallel scan,
Windows file-id dedupe, and native `WinVerifyTrust` execution. The service wires
`WinVerifyTrust` into `safeos_assess` for Windows, but that path is unproven.
Quarantine recovery is proven by simulated journal states, not a real power-loss
test.
