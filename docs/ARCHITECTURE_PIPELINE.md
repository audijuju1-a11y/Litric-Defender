# Detection pipeline architecture (merged workspace)

```mermaid
flowchart TD
  IN[File / buffer] --> ID[Litric file identification + SHA-256<br/>litric-core]
  ID --> NATIVE[Litric native analysis<br/>rules, PE, archive, macro, deobfuscation, heuristics<br/>litric-core Engine]
  ID --> CLAM[ClamAV-derived signature matcher<br/>hash / section hash / NDB / LDB<br/>scanner + sigdb, data imported by clamav-import]
  ID --> YARA[YARA module - optional, external engine yara-x<br/>litric-yara]
  NATIVE --> AGG[Aggregation<br/>litric-pipeline]
  CLAM --> AGG
  YARA --> AGG
  AGG --> CLS[Classification vs 190-category taxonomy<br/>litric-core taxonomy]
  CLS --> ACT{Action}
  ACT -->|Malicious| Q[Quarantine - encrypted vault]
  ACT -->|Suspicious| AL[Alert]
  ACT -->|Unknown / incomplete| LG[Log only]
```

Rules enforced in `litric-pipeline`:

1. Results are never merged by source: `native`, `clamav` and `yara` stay separate, each detection carries `Source`.
2. An external detection convicts only with high/critical severity and confidence ≥ 80 (medium needs ≥ 90); anything weaker is `Suspicious`.
3. `Clean` is reserved for a positive allow-list hit with a fully completed check. No detections means `Unknown`.
4. Anything not evaluated (no database, budget hit, archive members, missing PE facts, YARA timeout, no YARA rules) is listed in `incomplete`.
5. Unsigned or unknown files are never treated as malware by that fact alone (tested).

Import pipeline (offline, separate from the runtime scanner): ClamAV files → `clamav-import` → report of every unsupported line → Litric signed binary DB (`sigtool compile`/`sign`) → verified load.

Behavioural monitoring (RansomShield) feeds the service separately; it is not part of `scan_bytes` and has no OS-level enforcement in this tree.
