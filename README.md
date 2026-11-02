# Litric Defender

An original Windows endpoint security platform: detection engine, scanner,
behavioural ransomware protection, encrypted quarantine and signed threat
database — written in Rust.

**This repository contains the real engine, not a mock-up.** Every number and
every verdict below comes from code that runs. Read
[docs/STATUS.md](docs/STATUS.md) before believing any claim about scope: the
project is early, and the status file lists what is *not* built.

## What actually works today

| Capability | State |
|---|---|
| Original PE parser (headers, sections, imports, exports, resources, overlay, Rich header, TLS, CLR, checksum) | IMPLEMENTED, TESTED |
| Litric Rule Syntax engine (own grammar, own Aho–Corasick matcher) | IMPLEMENTED, TESTED |
| Heuristic engine (30+ weighted, explainable signals with ATT&CK mapping) | IMPLEMENTED, TESTED |
| Verdict aggregation with trust dampening and explicit `Unknown` | IMPLEMENTED, TESTED |
| Encrypted quarantine vault (XChaCha20-Poly1305, Argon2id, tamper-evident) | IMPLEMENTED, TESTED |
| Signed threat database (Ed25519, anti-rollback, revocation, atomic install) | IMPLEMENTED, TESTED |
| RansomShield behavioural engine + HoneyVault decoys | IMPLEMENTED, TESTED (simulator-driven) |
| Scan orchestration with budgets, cache, honest accounting | IMPLEMENTED, TESTED |
| CLI scanner (`litric`) | IMPLEMENTED, TESTED |
| Windows service, ETW sensor, minifilter, UI, installer | PLANNED / BLOCKED — see STATUS |

## Build and run

```bash
cargo build --release
cargo test                      # 81 tests
./target/release/litric rules lint rules
./target/release/litric scan /path/to/scan
./target/release/litric analyze suspicious.exe
./target/release/litric bench /path/to/corpus --runs 3
```

Windows cross-check (compiles the portable crates against the Windows target):

```bash
rustup target add x86_64-pc-windows-gnu
cargo check --target x86_64-pc-windows-gnu -p litric-core
```

## Measured baseline

Release build, 2 vCPU Linux VM, 2 000 files (mixed text, random binary, and
malicious scripts), 15 rules loaded:

```
run 1: 2000 files in 0.661s = 3027 files/s, 3.1 MB/s
run 2: 2000 files in 0.653s = 3064 files/s, 3.1 MB/s
run 3: 2000 files in 0.656s = 3050 files/s, 3.1 MB/s
```

Files in that corpus are small, so throughput is dominated by per-file
overhead — which is the number that matters for whole-disk quick scans. These
are **Linux VM** figures; no Windows benchmark has been run yet (no Windows
host in this environment). See [docs/STATUS.md](docs/STATUS.md).

## Honest limitations (short version)

* Nothing here runs in kernel mode. Real-time blocking of writes and
  block-before-execute need a signed minifilter; see
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the exact blocker.
* The threat database ships with **rules only**. It contains no commercial
  malware-hash feed, so hash reputation coverage is currently zero by design —
  the engine says so in every report.
* Authenticode parsing extracts signer names and validity dates but does **not**
  validate certificate chains (that needs WinVerifyTrust on Windows).
* Archive/binary containers are identified but their members are not yet scanned
  recursively.

## Layout

```
crates/litric-core/   detection engine, scan, quarantine, RansomShield (portable)
crates/litric-cli/    `litric` command line scanner and tooling
rules/core.lrs        15 authored detection rules
docs/                 audit, architecture, status matrix, limitations
```

## Licensing note

Detection rules in `rules/` are written by Litric Labs. No third-party rule set,
no ClamAV, no YARA code and no commercial signature feed is embedded. See
[docs/AUDIT.md](docs/AUDIT.md) for the licence review behind that decision.

---

Licence: proprietary (see `Cargo.toml`). The engine is original work; third-party
crates are permissively licensed (MIT/Apache-2.0/BSD) and unmodified.
