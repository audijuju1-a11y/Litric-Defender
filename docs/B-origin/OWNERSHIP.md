# Component ownership matrix

"Litric" = written in this repository. "Third party" = external code or data used as-is.

| Component | Owner | Origin / license | State |
|---|---|---|---|
| File scanning orchestration, traversal, limits, progress, cancel | Litric | `scanner` | IMPLEMENTED, TESTED |
| SHA-256 / MD5 / SHA-1 primitives | Third party | RustCrypto `sha2`, `md-5`, `sha1` (MIT/Apache-2.0) | used as libraries |
| Hash matching engine (compact sorted tables) | Litric | `sigdb` | IMPLEMENTED, TESTED |
| Logical (LDB) expression/constraint parser and evaluator (counts per subsignature) | Litric | `sigdb::ldb`, `scanner::ndb` | IMPLEMENTED (subset), TESTED |
| Extended (NDB) signature syntax parser and matcher (hashed anchor index + bounded backtracking) | Litric | `sigdb::ndb`, `scanner::ndb` | IMPLEMENTED (subset), TESTED |
| Byte-pattern matcher | Litric logic on a third-party automaton | `aho-corasick` (Unlicense/MIT); rules, targets, semantics are Litric's | IMPLEMENTED, TESTED |
| PE parser, static analysis, heuristics, risk scoring | Litric | `peanalysis` | IMPLEMENTED, TESTED (synthetic PEs) |
| Native signature formats (text LSDB v1/v2, binary LSDBBIN1) | Litric | `sigdb`, `sigdb::binary` | IMPLEMENTED, TESTED |
| Ed25519 signature algorithm | Third party | `ed25519-dalek` (BSD-3-Clause) | library; no custom crypto |
| Database signing, anti-rollback, atomic update, re-verify | Litric | `sigdb::Store`, `sigtool` | IMPLEMENTED, TESTED |
| ClamAV format reader / converter | Litric | `clamav-import` (implements ClamAV's documented text formats; contains no ClamAV code) | PARTIAL (hash formats only) |
| ClamAV signature content | **Third party (Cisco/Talos)** | License NOT verified | none shipped |
| YARA language/engine | **Third party** | not yet chosen | NOT IMPLEMENTED |
| Quarantine, restore, audit chain | Litric | `quarantine` | IMPLEMENTED, TESTED |
| Ransomware behaviour engine, recovery vault, honeyvault, real-time pipeline | Litric | `ransomshield`, `realtime`, `recovery`, `honeyvault`, `service` | IMPLEMENTED, TESTED on Windows 11 (logic); no OS enforcement |
| Windows API bindings | Third party | `windows-sys` (MIT/Apache-2.0) | used by uncompiled Windows glue |
| EICAR test string | Public test artifact | | tests only |

Litric's own native signature database currently contains **no real detections** (default is empty).
Any detection capability today comes from content you import and sign yourself.
