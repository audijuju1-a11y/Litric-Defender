# End-to-end integration report (ClamAV hash + NDB/LDB-subset adapter)

> Historical origin record. The merged tree is Windows-only; current native
> results are in `docs/WINDOWS_EVIDENCE.md`.

Run at that time on the original container: **141 tests, 0 failed**. The merged
code now runs natively on Windows 11.

| Chain exercised | Test | Result |
|---|---|---|
| ClamAV `.hdb` (real EICAR MD5 + size) -> import -> DB -> scan EICAR file -> Detected | `scanner/tests/clamav.rs` | pass |
| Same entry, file with extra newline (different hash and size) -> not detected | same | pass |
| `.hsb` SHA-1 and SHA-256 -> detected; wrong size -> not detected | same | pass |
| `.fp` allowlist overrides a ClamAV hash detection | same | pass |
| `.mdb` PE-section hash -> detects the PE, not text or a different PE (synthetic PEs) | same | pass |
| Overlapping-section amplification bounded and reported Unscannable | same | pass |
| import -> Ed25519 sign -> `Store::install` -> `load_active` -> lookup | `clamav-import/tests/import.rs` | pass |
| Every input file appears in the import report; unsupported ones state a reason; wildcard-size lines counted | same | pass |
| Malformed lines rejected with line numbers; hash type must match file type | same | pass |
| v2 format: compact tables, size must match, duplicates rejected, v2 records rejected under v1, revocation | `sigdb/tests/sigdb.rs` | pass |
| CLI exit codes 0/1/2/3/4, tampered database, quarantine copy/move | `scanner/tests/cli.rs` | pass |
| 1M-rule pipeline (import, sign, scan 2,000 files, planted hit) | manual run, see BENCHMARKS.md | pass (one run) |
| NDB: exact bytes, `??`, nibbles, gaps, `*`, alternatives, absolute/EOF/maxshift offsets, PE EP/section offsets, ELF/PDF targets | `scanner/tests/ndb.rs` | pass |
| NDB: pathological backtracking is budgeted -> Unscannable, not clean | same | pass |
| NDB: 3,000 rules over 2 MiB random data, planted signature found | same | pass |
| NDB: ClamAV-style EICAR line + wildcard/gap variant -> import -> sign -> install -> scan | same | pass |
| NDB parser: supported/unsupported/malformed syntax and offsets classified; bytecode round trip and validation | `sigdb/tests/ndb.rs` | pass |
| Binary format: round trip of every record type (digest equal, re-encode byte-identical, semantic spot checks) | `sigdb/tests/binary.rs` | pass |
| Binary: every header byte flip, sampled section byte flips, truncations, appended data, wrong/revoked key all rejected | same | pass |
| Binary: signed-but-malformed tables, support sections, extended signatures and headers rejected (reasons inspected) | same | pass |
| Binary: 15,000 structural mutations with valid hashes + 10,000 whole-file mutations, no panic | same | pass |
| Binary: Store install/AlreadyCurrent/Rollback/SerialReuse, text<->binary upgrade, streaming load, on-disk tamper, `install_file` | same | pass |
| LDB: AND/OR/parentheses, count conditions (=,>,<; overlapping starts counted), constraints (FileSize, NumberOfSections), per-subsignature offsets incl. PE-relative, targets | `scanner/tests/ldb.rs` | pass |
| LDB: logical + extended rules reported together with correct methods; flooding is budgeted -> Unscannable | same | pass |
| LDB: ClamAV-style `.ldb` -> import -> binary -> sign -> install -> scan (counts, expressions) | same | pass |
| LDB parser: expressions, precedence refusal, group counts, target blocks, constraints, record validation | `sigdb/tests/ldb.rs` | pass |
| LDB importer: supported lines, 13 unsupported feature classes counted by reason, malformed rejected, PUA, duplicates, ignore list | `clamav-import/tests/import.rs` | pass |
| LDB binary section: round trip and 17 forged-but-signed malformed cases (reasons inspected) | `sigdb/tests/binary.rs` | pass |
| Binary through the CLI: detection (exit 1), tampered file (exit 3), `--store` after `install_file` | `scanner/tests/cli.rs` | pass |
| NDB importer: unsupported features counted per reason, malformed rejected, PUA, ignore list, duplicates | `clamav-import/tests/import.rs` | pass |

Also passing from earlier rounds: ransomware engine, real-time pipeline, recovery vault, quarantine, PE parser + mutation fuzz, signed-database store.

## What was NOT tested
- Any real ClamAV database (none could be downloaded). Real-world MDB semantics are unverified.
- False positives against a large corpus of legitimate files. Detection and false-positive rates are unknown.
- Windows builds, real-time monitoring on Windows, performance on Windows or on multi-core machines.
- Memory leaks (no leak-checking tool run), long-running stability, concurrent scanning.
- CVD/CLD, YARA, archives: not implemented. NDB and LDB only as subsets, matched on the raw file, semantics not verified against libclamav (counting and 'at least one match' rules are Litric's interpretation).
- Binary format forward/backward compatibility (format 1 is not frozen) and Windows behaviour.
- NDB performance on real signature sets and on real executables (only random data and synthetic signatures were measured).
