# Litric database formats

Two interchangeable encodings of the same logical database. The runtime loads either; the signature scheme differs.

| | Text `LITRIC-SIGDB 1/2` (records: H P A R HX S AX NDB LDB) | Binary `LSDBBIN1` |
|---|---|---|
| Purpose | human-readable, easy to diff and generate | large databases, fast and low-memory loading |
| Signed bytes | the whole file | the **header only**, which carries SHA-256 of every section |
| Limits | 512 MiB, 10M rules | 64M rules, 4 GiB per section, 64 sections |
| Loading | read whole file, parse, sort | stream: verify signature, then verify + decode one section at a time |
| Created by | `litric-clamav-import`, hand/other tools | `sigtool compile` or `litric-clamav-import --binary` |

## Binary layout (little endian)

```
header (signed)   magic "LSDBBIN1" | header_len u32 | format u32 (=1) | serial u64 | created u64
                  | min_engine u32 | n_sections u32 | rule_count u64
                  | n x { type u32 | reserved u32 (=0) | offset u64 | length u64 | sha256[32] }
sections          contiguous in table order; no gaps; no trailing bytes
```

| Type | Content |
|---|---|
| 1 | provenance lines (UTF-8, `\n` separated) |
| 2 | family names: `count u32` then `len u8 + bytes` each |
| 3 | rule-id arena (ASCII identifier characters only) |
| 4 | native text records `H`/`P`/`A`/`R` (small sets stay text) |
| 0x100-0x102 | file-hash tables md5/sha1/sha256: `count u64`, keys, sizes `u32`, meta (12 B each) |
| 0x103-0x105 | PE-section-hash tables, same layout |
| 0x106-0x108 | allowlist tables: `count u64`, keys, sizes (no meta) |
| 0x200 | extended (NDB) rules: meta, target, offset, bytecode |
| 0x201 | logical (LDB) rules: meta, target, constraint flags + ranges, expression text, subsignatures (offset + bytecode) |

Tables are stored already sorted by (hash, size); the loader checks strict ordering instead of re-sorting.

## What the loader refuses (all covered by tests)
Bad magic or version; header length or section count inconsistent; non-zero reserved field; unknown or duplicate section
types; sections not contiguous, overflowing, truncated, or followed by extra bytes; any section hash mismatch; counts that
do not match lengths; unsorted or duplicate hash entries; family index, id range, severity, confidence or padding out of range;
ids outside the arena or arena with non-identifier bytes; malformed or unlocatable extended-signature or subsignature bytecode; logical expressions that do not parse, refer past their subsignatures, or exceed limits; EP/section
offsets on non-PE targets; header rule count not matching the decoded rules; `min_engine` above the engine's version.
A signed file can still be malformed (tool bug), so nothing in it is trusted.

## Compatibility policy
Format version 1 is NOT frozen: nothing promises that future versions can read it, and no cross-version tests exist.
New section types require a format bump; unknown types are rejected rather than skipped, so an old engine never runs
with part of a database silently ignored. `min_engine` gates content an old engine cannot evaluate.
Upgrading between text and binary requires a higher serial (the anti-rollback floor treats same-serial different bytes as reuse).
