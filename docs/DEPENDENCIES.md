# Dependency and license audit (generated from `cargo metadata`)

Declared licenses as published in each crate manifest. **Not legal advice**; it does not cover redistribution terms of signature/rule *data*.

The table is generated from the lockfile and therefore includes crates that are
selected only for other targets (`libc`, `linux-raw-sys`, `mach2`, `js-sys`,
`memfd`). They are **not built on Windows**; `cargo tree -i linux-raw-sys` on the
Windows target prints nothing. Only `windows-sys` is used by platform code.


## Litric workspace crates (`LicenseRef-Proprietary`)

All 20 workspace crates declare `license = "LicenseRef-Proprietary"` (either
directly or via `license.workspace = true`). Phase 0 found eight manifests with
no license field and this list missing eight crates; both are corrected here.

- clamav-import 0.1.0
- honeyvault 0.1.0
- litric-agent 0.1.0
- litric-cli 0.1.0
- litric-core 0.1.0
- litric-guard 0.1.0
- litric-monitor 0.1.0
- litric-pipeline 0.1.0
- litric-safeos 0.1.0
- litric-service 0.1.0
- litric-wintrust 0.1.0
- litric-yara 0.1.0
- peanalysis 0.1.0
- processgate 0.1.0
- quarantine 0.1.0
- ransomshield 0.1.0
- realtime 0.1.0
- recovery 0.1.0
- scanner 0.1.0
- sigdb 0.1.0

There is still **no `LICENSE` file** in the repository; the SPDX ref above is a
declaration, not licence text. A lawyer must supply the actual terms before any
distribution.

## External crates by license expression

| License | Count |
|---|---|
| MIT OR Apache-2.0 | 123 |
| Apache-2.0 WITH LLVM-exception | 27 |
| MIT | 24 |
| Apache-2.0 OR MIT | 21 |
| MIT/Apache-2.0 | 8 |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 8 |
| Unlicense OR MIT | 6 |
| BSD-3-Clause | 6 |
| Unlicense/MIT | 2 |
| 0BSD OR MIT OR Apache-2.0 | 1 |
| MIT OR Apache-2.0 OR BSD-1-Clause | 1 |
| Apache-2.0 / MIT | 1 |
| Zlib | 1 |
| BSD-2-Clause OR MIT OR Apache-2.0 | 1 |
| MIT OR Zlib OR Apache-2.0 | 1 |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 1 |
| Apache-2.0/MIT | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |
| Apache-2.0 | 1 |

External crates with no declared license: 0 

## Components with special provenance

| Component | Provenance | Notes |
|---|---|---|
| yara-x | VirusTotal, BSD-3-Clause | external YARA engine, optional crate `litric-yara`, needs Rust 1.95+ |
| ClamAV signature data | Cisco / ClamAV | **data only**; license and redistribution terms NOT verified; no ClamAV code used or linked |
| ed25519-dalek, sha2, chacha20poly1305, argon2 | RustCrypto / dalek | no custom cryptography |


## All external crates

| Crate | Version | License |
|---|---|---|
| addr2line | 0.26.1 | Apache-2.0 OR MIT |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| aead | 0.5.2 | MIT OR Apache-2.0 |
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| allocator-api2 | 0.2.21 | MIT OR Apache-2.0 |
| annotate-snippets | 0.12.17 | MIT OR Apache-2.0 |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.104 | MIT OR Apache-2.0 |
| arbitrary | 1.5.0 | MIT OR Apache-2.0 |
| argon2 | 0.5.3 | MIT OR Apache-2.0 |
| ascii | 1.1.0 | Apache-2.0 OR MIT |
| ascii_tree | 0.1.1 | MIT |
| async-trait | 0.1.92 | MIT OR Apache-2.0 |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| base64 | 0.23.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| bincode | 2.0.1 | MIT |
| bincode_derive | 2.0.1 | MIT |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| bitvec | 1.1.1 | MIT |
| blake2 | 0.10.6 | MIT OR Apache-2.0 |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| bstr | 1.13.1 | MIT OR Apache-2.0 |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 |
| cc | 1.11.0 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| chacha20 | 0.9.1 | Apache-2.0 OR MIT |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT |
| chunked_transfer | 1.5.0 | MIT OR Apache-2.0 |
| cipher | 0.4.4 | MIT OR Apache-2.0 |
| clap | 4.6.7 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 |
| cobs | 0.3.0 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.9.6 | Apache-2.0 OR MIT |
| countme | 3.0.1 | MIT OR Apache-2.0 |
| cpp_demangle | 0.5.1 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| cranelift-assembler-x64 | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-assembler-x64-meta | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-bforest | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-bitset | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen-meta | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen-shared | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-control | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-entity | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-frontend | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-isle | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-native | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-srcgen | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| crc32fast | 1.5.4 | MIT OR Apache-2.0 |
| crossbeam-deque | 0.8.8 | MIT OR Apache-2.0 |
| crossbeam-epoch | 0.9.21 | MIT OR Apache-2.0 |
| crossbeam-utils | 0.8.23 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| curve25519-dalek | 4.1.3 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| daachorse | 5.1.0 | MIT OR Apache-2.0 |
| darling | 0.24.1 | MIT |
| darling_core | 0.24.1 | MIT |
| darling_macro | 0.24.1 | MIT |
| der | 0.7.10 | Apache-2.0 OR MIT |
| derive_arbitrary | 1.5.0 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT |
| ed25519-dalek | 2.2.0 | BSD-3-Clause |
| either | 1.19.0 | MIT OR Apache-2.0 |
| embedded-io | 0.4.0 | MIT OR Apache-2.0 |
| embedded-io | 0.6.1 | MIT OR Apache-2.0 |
| equivalent | 1.0.3 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause |
| find-msvc-tools | 0.1.15 | MIT OR Apache-2.0 |
| flate2 | 1.1.10 | MIT OR Apache-2.0 |
| fnv | 1.0.7 | Apache-2.0 / MIT |
| foldhash | 0.2.0 | Zlib |
| funty | 2.0.0 | MIT |
| futures | 0.3.34 | MIT OR Apache-2.0 |
| futures-channel | 0.3.34 | MIT OR Apache-2.0 |
| futures-core | 0.3.34 | MIT OR Apache-2.0 |
| futures-io | 0.3.34 | MIT OR Apache-2.0 |
| futures-sink | 0.3.34 | MIT OR Apache-2.0 |
| futures-task | 0.3.34 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| gimli | 0.32.3 | MIT OR Apache-2.0 |
| gimli | 0.33.0 | MIT OR Apache-2.0 |
| globset | 0.4.21 | Unlicense OR MIT |
| globwalk | 0.9.1 | MIT |
| hashbrown | 0.14.5 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| httpdate | 1.0.3 | MIT OR Apache-2.0 |
| id-arena | 2.3.0 | MIT/Apache-2.0 |
| ident_case | 1.0.1 | MIT/Apache-2.0 |
| ignore | 0.4.34 | Unlicense OR MIT |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| inout | 0.1.4 | MIT OR Apache-2.0 |
| intaglio | 1.15.1 | Apache-2.0 OR MIT |
| inventory | 0.3.25 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itertools | 0.14.0 | MIT OR Apache-2.0 |
| itertools | 0.15.0 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| js-sys | 0.3.107 | MIT OR Apache-2.0 |
| leb128 | 0.2.7 | MIT OR Apache-2.0 |
| leb128fmt | 0.1.0 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| libm | 0.2.16 | MIT |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| log | 0.4.35 | MIT OR Apache-2.0 |
| logos | 0.16.1 | MIT OR Apache-2.0 |
| logos-codegen | 0.16.1 | MIT OR Apache-2.0 |
| logos-derive | 0.16.1 | MIT OR Apache-2.0 |
| mach2 | 0.6.0 | BSD-2-Clause OR MIT OR Apache-2.0 |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| memfd | 0.6.6 | MIT OR Apache-2.0 |
| memmap2 | 0.9.12 | MIT OR Apache-2.0 |
| memoffset | 0.9.1 | MIT |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 |
| num-derive | 0.5.1 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| object | 0.39.1 | Apache-2.0 OR MIT |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| opaque-debug | 0.3.1 | MIT OR Apache-2.0 |
| password-hash | 0.5.0 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT |
| poly1305 | 0.8.0 | Apache-2.0 OR MIT |
| postcard | 1.1.3 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| protobuf | 3.7.2 | MIT |
| protobuf-support | 3.7.2 | MIT |
| pulley-interpreter | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| pulley-macros | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| radium | 0.7.0 | MIT |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| regalloc2 | 0.15.2 | Apache-2.0 WITH LLVM-exception |
| regex | 1.13.1 | MIT OR Apache-2.0 |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| rowan | 0.17.0 | MIT OR Apache-2.0 |
| rustc-demangle | 0.1.28 | MIT/Apache-2.0 |
| rustc-hash | 1.1.0 | Apache-2.0/MIT |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustix | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| same-file | 1.0.6 | Unlicense/MIT |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signature | 2.2.0 | Apache-2.0 OR MIT |
| simd-adler32 | 0.3.10 | MIT |
| slab | 0.4.12 | MIT |
| smallvec | 1.16.4 | MIT OR Apache-2.0 |
| spki | 0.7.3 | Apache-2.0 OR MIT |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| strum_macros | 0.28.0 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| tap | 1.0.1 | MIT |
| target-lexicon | 0.13.5 | Apache-2.0 WITH LLVM-exception |
| termcolor | 1.4.1 | Unlicense OR MIT |
| text-size | 1.1.1 | MIT OR Apache-2.0 |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 |
| tiny_http | 0.12.0 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-width | 0.2.3 | MIT OR Apache-2.0 |
| universal-hash | 0.5.1 | MIT OR Apache-2.0 |
| unty | 0.0.4 | MIT OR Apache-2.0 |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| virtue | 0.0.18 | MIT |
| walkdir | 2.5.0 | Unlicense/MIT |
| walrus | 0.27.3 | MIT/Apache-2.0 |
| walrus-macro | 0.26.0 | MIT/Apache-2.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.130 | MIT OR Apache-2.0 |
| wasm-encoder | 0.245.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-encoder | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmparser | 0.245.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmparser | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmprinter | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmtime | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-environ | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-component-util | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-core | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-cranelift | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-fiber | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-jit-debug | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-jit-icache-coherence | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-unwinder | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-versioned-export-macros | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| winapi-util | 0.1.11 | Unlicense OR MIT |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| wyz | 0.5.1 | MIT |
| yara-x | 1.22.1 | BSD-3-Clause |
| yara-x-macros | 1.22.1 | BSD-3-Clause |
| yara-x-parser | 1.22.1 | BSD-3-Clause |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |
| zip | 2.6.1 | MIT |
| zmij | 1.0.23 | MIT |
| zopfli | 0.8.4 | Apache-2.0 |
