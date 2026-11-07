# Architecture (historical origin record)

> Snapshot from the original code line. The merged tree is Windows-only; current
> status and evidence are in `docs/STATUS.md` and `docs/WINDOWS_EVIDENCE.md`.
> Some statements below ("not compiled", "YARA not implemented") describe that
> snapshot, not the current tree.

```
                     OFFLINE (separate from runtime)                     RUNTIME
 ClamAV text files ──► clamav-import ──► Litric DB v2 (unsigned) ──► sigtool sign ──► signed bundle
 (.hdb .hsb .mdb       [Litric adapter]   + provenance + report      [Ed25519,         │
  .fp .ign ...)        reports every                                  key kept          ▼
                       unsupported file                               offline]   sigdb::Store
                                                                                 (verify [streaming for binary], anti-rollback,
                                                                                  atomic install, re-verify on load)
                                                                                         │
 file ──► scanner ───────────────────────────────────────────────────────────────────────┘
          1 open once, stream SHA-256 (+MD5/SHA-1 only if DB needs them)   [IMPLEMENTED]
          2 allowlist (native + ClamAV .fp/.sfp)                           [IMPLEMENTED]
          3 hash signatures (native H, v2 HX)                              [IMPLEMENTED]
          4 byte-pattern signatures (native P, Aho-Corasick)               [IMPLEMENTED]
          5 PE parse -> section-hash signatures (v2 S)                     [IMPLEMENTED]
          6 PE static analysis + heuristic risk score                      [IMPLEMENTED]
          7a NDB extended signatures (documented subset, hashed anchor prefilter + bounded matcher)   [IMPLEMENTED]
          7b LDB logical signatures (subset: boolean expr + counts + constraints, shared anchor index)   [IMPLEMENTED]
          8 YARA module                                                    [NOT IMPLEMENTED]
          9 archives (ZIP/7Z/RAR) with bomb limits                         [NOT IMPLEMENTED]
          10 aggregation: Detected > Suspicious > Weak > NoThreatFound; Skipped/Unscannable/Error never "clean"
              │
              ▼
          quarantine (verified copy, hash-checked restore, audit chain)    [IMPLEMENTED]

 Real-time (separate path): watcher/ETW -> realtime::Pipeline -> ransomshield::Engine
   -> contain (suspend) + recovery vault + honeyvault + service/supervisor
   file-event source on Windows: WRITTEN, NOT COMPILED. Process attribution: BLOCKED.
   Real-time events are NOT yet routed through the file scanner pipeline.
```

Crates: `ransomshield`, `realtime`, `honeyvault`, `recovery`, `service` (real-time side);
`sigdb`, `clamav-import`, `scanner`, `peanalysis`, `quarantine` (scan side).

Trust boundaries: the runtime scanner reads only Litric-format, Ed25519-verified databases.
It never parses ClamAV files. The importer never runs at scan time.
