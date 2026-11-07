# ClamAV signature compatibility matrix

Compatibility means: Litric's own adapter reads the format and Litric's own scanner implements the matching.
No libclamav, clamscan or clamd is used. Semantics are taken from ClamAV's public documentation as understood
when this was written; they have **not** been verified byte-for-byte against libclamav, and no real ClamAV
database could be downloaded in the authoring environment. All tests use synthetic files plus the well-known
EICAR MD5/size entry.

| Format | Meaning | State | Notes |
|---|---|---|---|
| `.hdb` | MD5 : size : name | IMPLEMENTED, TESTED | exact match of MD5 **and** exact size; FL fields parsed and **ignored**; `*` size => reported UNSUPPORTED per line |
| `.hdu` | same, PUA | IMPLEMENTED, TESTED | imported as low severity / 50 confidence (Litric policy) |
| `.hsb` | SHA-1/SHA-256 : size : name | IMPLEMENTED, TESTED | hash type must match file type, else rejected |
| `.hsu` | same, PUA | IMPLEMENTED, TESTED | |
| `.mdb` / `.mdu` | PE section MD5: size : hash : name | IMPLEMENTED, TESTED (synthetic PEs only) | **Litric semantics: hash of the section's raw bytes clamped to the file; size = bytes hashed. Not verified against libclamav**, so real MDB entries may fail to match or behave differently |
| `.msb` / `.msu` | PE section SHA-1/256 | IMPLEMENTED, TESTED (synthetic) | same caveat |
| `.fp` / `.sfp` | allowlist (MD5 / SHA-1,256) | IMPLEMENTED, TESTED | allowlist wins over every signature |
| `.ign` / `.ign2` | disable signature by name | PARTIAL | name only; optional MD5/line fields ignored; format details inferred, not verified |
| `.ndb` / `.ndu` | extended signatures (hex with wildcards) | **PARTIAL (documented subset)**, TESTED on synthetic files + EICAR | Supported: exact bytes, `??`, nibble `a?`/`?a`, `*`, `{n}` `{n-m}` `{-n}` `{n-}`, positive alternatives `(aa\|bbcc)`; offsets `*`, `N`, `EOF-N`, `EP+N`, `EP-N`, `Sn+m`, `SL+n`, each with optional `,maxshift`; targets 0 (any), 1 (PE), 6 (ELF), 10 (PDF). Matching is on the raw file only. Offset/maxshift semantics are inferred from documentation and **not verified against libclamav**. FL fields ignored |
| NDB lines outside the subset | negated `!(..)`, `(B)`/`(L)`, `[n-m]`, alternatives with wildcards, `VI`/`SEx`/negative-section offsets, targets 2,3,4,5,7,8,9,11,12, EP offsets with non-PE target, signatures with no 2-byte anchor and no exact offset, >64 wildcard segments | **NOT IMPLEMENTED, reported per line by reason** | the import report lists `unsupported xN: <reason>` |
| `.ldb` / `.ldu` | logical signatures `name;target;expression;subsig;...` | **PARTIAL (documented subset)**, TESTED on synthetic files | Supported: expressions of subsignature indexes with `&`, `\|` and parentheses, per-subsignature count conditions `=n` `>n` `<n`; hex subsignatures in the NDB syntax subset, each with its own offset; target description keys `Target` (0,1,6,10), `FileSize`, `NumberOfSections`, `Engine` (ignored). **Litric semantics, not verified against libclamav:** a match count is the number of distinct start positions at which the subsignature matches (overlapping occurrences count); a rule fires only if at least one subsignature matched AND the expression holds (so `0<5` alone never fires on a clean file) |
| LDB lines outside the subset | PCRE subsignatures, `::iwfa` modifiers, macros `${..}$`, byte-compare, fuzzy-hash; group counts `(..)>n`; `,m` distinct-count modifiers; `&` and `\|` mixed in one group without parentheses (precedence not verified); `EntryPoint`, `Container`, `Intermediates`, `IconGroup` keys; targets other than 0/1/6/10; unlocatable subsignatures; >64 subsignatures | **NOT IMPLEMENTED, reported per line by reason** | the whole rule is skipped (never partially applied), so some coverage is lost but no false positives are introduced by guessing |
| `.cbc` | bytecode | **NEVER EXECUTED** (policy) | reported UNSUPPORTED |
| `.cdb`, `.ftm`, `.pdb/.gdb/.wdb`, `.crb`, `.idb`, `.imp`, `.cfg`, `.info`, `.ioc` | container / type / phishing / misc | NOT IMPLEMENTED | reported UNSUPPORTED |
| `.cvd` / `.cld` | signed container | **NOT IMPLEMENTED** | no unpacking, **no ClamAV digital-signature verification**. Unpack with the official sigtool yourself and record provenance |
| `.yar` / `.yara` in a ClamAV directory | | not handled by this adapter | belongs to the YARA module (not built) |

Consequence: LDB (logical signatures), container metadata, bytecode, CVD/CLD handling and the unsupported NDB forms above are not covered, so importing
today still yields **only a fraction** of ClamAV's coverage. The import report states skipped files and per-reason line counts. How large the
fraction is for a real database is unknown: no real database was available to measure.

Limits: the file size field is capped at 4 GiB per entry (`u32`). Text databases: 512 MiB / 10M rules. Binary databases: 64M rules (see DB_FORMAT.md).
Security note (my assessment): MD5/SHA-1 allowlist entries are accepted only because ClamAV uses them; replacing an
existing allowlisted file with malware that has the same MD5 and size would need a second-preimage attack, which is
not currently practical for MD5, but allowlist entries still override all detections, so treat the source as trusted.
