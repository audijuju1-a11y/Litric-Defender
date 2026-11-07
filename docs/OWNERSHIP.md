# Component ownership matrix

"Litric" = code written by the Litric team (inside this repository). "External" = third-party code or data. Nothing external is presented as Litric technology.

| Component | Crate / module | Owner | Notes |
|---|---|---|---|
| File identification, hashing, entropy | `litric-core` (`format`, `hash`, `entropy`) | Litric | |
| PE parser, Authenticode blob parser | `litric-core` (`pe`, `authenticode`) | Litric | chain trust verification not done |
| Rule language + Aho–Corasick matcher | `litric-core` (`rules`) | Litric | Litric Rule Syntax, **not** YARA |
| Heuristics (56 signals), MITRE mapping | `litric-core` (`heuristics`) | Litric | weights untuned on real-world data |
| Archive (ZIP family) limits, VBA/XLM macro, script de-obfuscation | `litric-core` | Litric | RAR/7z/CAB/ISO not recursed |
| Threat DB (signed, anti-rollback) | `litric-core` (`threatdb`), `sigdb` | Litric | Ed25519 via `ed25519-dalek` (external crypto) |
| Quarantine vault | `litric-core` (`quarantine`) | Litric | XChaCha20-Poly1305/Argon2id via RustCrypto (external crypto) |
| Quarantine (B variant, XOR) | `quarantine` | Litric | **not encryption**; kept only for the legacy B CLI; superseded |
| RansomShield decision logic | `litric-core` (`ranshield`) | Litric | no OS enforcement yet |
| Scan orchestration (A) | `litric-core` (`scan`), `litric-service`, `litric-cli` | Litric | |
| Signature matcher: hash, section hash, NDB, LDB | `scanner`, `sigdb` | Litric | matcher is Litric code; the *data* may come from ClamAV |
| ClamAV signature importer | `clamav-import` | Litric | contains no ClamAV code; CVD/CLD verification not implemented |
| ClamAV signature data | user-supplied files | **External (Cisco/ClamAV)** | license/redistribution NOT verified; none bundled |
| Pipeline and aggregation | `litric-pipeline` | Litric | |
| Malware taxonomy / coverage ledger | `litric-core` (`taxonomy`) | Litric | |
| YARA language, compiler, matcher | `yara-x` via `litric-yara` | **External (VirusTotal, BSD-3)** | optional; Litric owns only loading policy, limits, mapping |
| YARA rules | user-supplied | External | none bundled |
| SafeOS sandbox model | `litric-safeos`, `litric-agent` | Litric | Windows Sandbox launch UNPROVEN |
| Cryptographic primitives | RustCrypto, dalek | External | no custom crypto |
