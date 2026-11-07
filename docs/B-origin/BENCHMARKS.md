# Measurements (historical origin record)

> These numbers were taken on the original single-core container and are not
> Windows evidence or current performance. Native Windows numbers:
> `docs/BENCHMARKS.md`.

Environment at that time: 1 CPU core, ~4 GB RAM, Rust 1.75, `--release`. **All databases are SYNTHETIC
(random MD5 hashes), not ClamAV data.** One run each; no repetition, no variance estimate, no Windows measurements.
No detection rate, false-positive rate or real-world throughput exists.

| Measurement | Result |
|---|---|
| Parse 1,000,000 v2 hash rules (85 MiB text) | 1.47 s |
| Parse 3,000,000 v2 hash rules (258 MiB text) | 5.42 s |
| Process RSS after load, text freed: 1M / 3M rules | 46 MiB / 134 MiB (~44-46 B per rule incl. ~2 MiB baseline) |
| Hash lookups (incl. hex decode), 1M / 3M rules | ~1.27 M/s / ~1.03 M/s |
| Import 1M `.hdb` lines -> Litric DB (88 MB) | 5.4 s, peak 398 MiB |
| Sign that 88 MB database | 1.4 s, peak 164 MiB |
| Verify + load 1M rules + scan 2,000 random files (200 MiB, md5+sha256 computed) | 1.97 s total, peak 165 MiB |
| Same with one planted matching file | detected 1 of 2000, exit code 1 |

Not measured: peak memory *during* parse (it is at least text size + tables), behaviour with real ClamAV databases,
cold-disk I/O, multi-core scaling, real-time event latency.
Extrapolation (NOT a measurement): the text format is ~86 B/rule, so ~8M rules would be ~690 MiB, which exceeds the current
512 MiB database limit. A binary / chunked-signature format is the next scaling step.

## Extended signatures (NDB), synthetic

Same environment and caveats. 200,000 synthetic NDB rules (mix of exact 8-byte, wildcard+gap, alternatives, and `*` signatures; random bytes) scanned over 2,000 random files (200 MiB).

| Measurement | Result |
|---|---|
| Import 200k NDB lines -> Litric DB (14.7 MB) | 0.73 s, peak 203 MiB (one run) |
| **First implementation** (Aho-Corasick prefilter): scan 200 MiB | 34.6 s and 36.0 s, peak 519 MiB (2 runs) - too slow, replaced |
| **Current implementation** (hashed 2/3/4-byte key tables): scan 200 MiB | 3.45 s, 3.38 s, 3.79 s, peak 165 MiB (3 runs) |
| Hash-only 1M-rule database, same session, same files | 3.26 s, 3.15 s, 3.02 s (3 runs) |
| Steady-state memory after load: NDB rules vs hash rules | ~750 bytes/rule (145 MiB for 200k) vs ~46 bytes/rule |

Noise warning: the same hash-only scan took 1.8-2.0 s in an earlier session and 8.1 s in another run of this one, so this shared container varies by 4x or more.
Treat absolute numbers as indicative; the relative improvement of the prefilter (about 10x) is large enough to be real.
Not measured: data with many short-anchor hits (real binaries share byte sequences far more than random data),
real ClamAV NDB sets, extended-signature cost on large executables, memory with millions of NDB rules (750 B/rule would be ~750 MB per million; a compact encoding is PLANNED).
Each file has an evaluation budget (default 50M work units); a file that exhausts it is reported Unscannable, never clean.

## Binary database format and compact extended signatures, synthetic

Same environment and caveats (1 core, ~4 GB, synthetic random data, noisy container). "load" = verify signature and all hashes, decode, scan one file.

| Measurement | Text format | Binary format |
|---|---|---|
| 1M MD5 hash rules: file size | 88.4 MB | 45.0 MB (0.51x) |
| 1M MD5 hash rules: load time (4 runs each) | 1.16-1.26 s | 0.28-0.32 s |
| 1M MD5 hash rules: peak RSS | 165 MiB | 77 MiB |
| 200k NDB rules: file size | 14.7 MB | 14.4 MB |
| 200k NDB rules: load time (1 run each) | 0.31 s | 0.18 s |
| 200k NDB rules: peak RSS | 43 MiB | 42 MiB |
| `sigtool compile` of the 1M-rule text database | | 5.8 s, peak 216 MiB (1 run) |

NDB rules in memory after switching to bytecode: ~114 bytes/rule (was ~750), measured with the `dbmem` example (hash rules ~46 bytes/rule).

Binary databases far beyond the text format's 512 MiB limit (synthetic MD5 rules generated directly by the `genbin` example, signed with `sigtool`):

| Rules | File | `sigtool sign` | load (2 runs) | peak RSS during load |
|---|---|---|---|---|
| 8,000,000 | 349 MiB | 2.7 s, 947 MiB | 2.31 s / 2.37 s | 598 MiB |
| 16,000,000 | 706 MiB | 5.6 s, 1,905 MiB | 4.82 s / 4.93 s | 1,198 MiB |

Not measured / caveats: peak load memory is ~75 bytes per rule versus ~45 steady, because a raw section buffer and its decoded copy coexist briefly;
every scanner process holds its own copy (no memory mapping); `sigtool sign/compile` and the importer hold whole databases in memory (offline tools;
importer memory at millions of rules was not measured); no real ClamAV data; no Windows numbers; no repetition beyond what is listed.

## Logical signatures (LDB), synthetic

Same environment and caveats. 100,000 synthetic LDB rules (3 subsignatures each = 300,000 anchors; mixed expressions, wildcards, gaps, `*`, a FileSize constraint, a count condition), random data.

| Measurement | Result |
|---|---|
| Import 100k LDB lines (text 9.8 MB) | 0.57 s, peak 89 MiB (1 run); `--binary` output 12.9 MB (larger than text: fixed per-subsignature fields) |
| Steady memory after load | ~606 bytes/rule (60 MiB for 100k) - heavier than NDB (114 B) because every rule owns an expression tree, strings and several small allocations; a compact encoding is PLANNED |
| Load + verify, 1 file: text / binary | 0.44 s / 0.18 s, peak 99 / 98 MiB (1 run each) |
| Scan 2,000 files (200 MiB), binary DB | 1.78 s and 1.82 s (runs 2 and 3), peak 98 MiB |
| Control, hash-only 1M-rule DB, same files | 0.75 s and 0.70 s (runs 2 and 3) |

The FIRST run of each set was dramatically slower (36.7 s for LDB, 4.1 s for the control): cold disk cache after the files were evicted. Only warm runs are comparable.
Roughly 1.1 s of the 1.8 s is attributable to the 300k-anchor index (~110 MiB/s versus ~285 MiB/s for the control) on this one-core container with random data.
Not measured: real executables (far more short-anchor hits than random bytes), real ClamAV LDB sets, rules with many `*`/gap subsignatures at scale.
