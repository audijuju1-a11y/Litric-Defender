# Dependency and license audit

Generated from `cargo metadata` of this workspace (normal + build dependencies of the shipped crates,
all target platforms; dev-only test dependencies excluded). License strings are copied from each crate's
manifest and were NOT independently verified against the crate's license files. Read each license before redistributing.

## Rust crates (50 third-party)

| Crate | Version | License (manifest) |
|---|---|---|
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| base64ct | 1.6.0 | Apache-2.0 OR MIT |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| der | 0.7.10 | Apache-2.0 OR MIT |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.1.1 | BSD-3-Clause |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| zeroize | 1.8.1 | Apache-2.0 OR MIT |

## External data and tools (NOT crates)

| Item | How Litric uses it | Status |
|---|---|---|
| ClamAV signature databases (main/daily/bytecode) | Text formats are read by the offline adapter `clamav-import` and converted to a Litric database | **License and redistribution terms NOT verified.** A web search was inconclusive. Read Cisco/Talos' current terms before shipping or mirroring any ClamAV database. Do not redistribute without confirming. |
| ClamAV source code / libclamav | **Not used.** No code, no linking, no `clamscan`/`clamd` calls | libclamav is GPLv2 per its repository; not using it also avoids linking it into Litric |
| ClamAV `sigtool` | Optional manual tool for unpacking CVD/CLD **outside** Litric | Not invoked by any Litric code |
| ClamAV bytecode (.cbc) | **Never executed** | Policy |
| YARA / libyara / yara-x | **Not used yet** | See YARA_COMPAT.md. License to be audited when a module is chosen |
| EICAR test string | Standard harmless AV test file used in tests (assembled at runtime so the source is not flagged) | Public test artifact |
| Malware signatures from any other source | None shipped. The default database is EMPTY | |

## Notes
- MD5 and SHA-1 are used only to match ClamAV's hash formats, never for integrity. Integrity and authenticity use SHA-256 and Ed25519 (`ed25519-dalek`, no custom cryptography).
- Cargo.lock pins `base64ct 1.6.0`, `zeroize 1.8.1` and `ed25519-dalek 2.1.1` because the authoring toolchain was Rust 1.75.
