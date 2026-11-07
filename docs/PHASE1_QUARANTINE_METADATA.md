# Phase 1 — quarantine metadata preservation and file-identity hardening

## Summary

| Field | Value |
|---|---|
| Phase | 1 (slice 3) — core safety |
| Status | **PARTIAL** (slice complete; Phase 1 has more work) |
| Date | 2026-11-07 |
| Host | Windows 11 Home 26H2, build 26300.9457, x64, NTFS |
| Toolchain | rustc/cargo 1.99.0, `x86_64-pc-windows-gnu` |
| Full suite | **597 passed, 0 failed, 0 ignored, exit 0** (the later fuzz slice adds one ignored seed generator) |
| Git | no repository metadata in this workspace |

Scope delivered: quarantine now preserves NTFS alternate data streams and the
original creation/access/modification timestamps, and the destructive half of
quarantine is bound to the file object that was inspected rather than a path
that can be replaced. No detection threshold, rule, verdict, Defender setting,
or user file outside the requested quarantine operation was changed.

## Requirements addressed

* A quarantined file must not lose its ADS or timestamps.
* The preserved bytes must be encrypted, not left in the vault header.
* An entry written by an older build must still restore.
* The source must not be deleted if its bytes or identity changed.
* A replacement at the source path must never be deleted.
* A restore must apply metadata before the entry is discarded, and must not
  overwrite an occupied destination.
* A failed metadata capture or restore must retain the source/entry, not report
  a successful move.

## Implementation

### Container payload — `crates/litric-core/src/quarantine.rs`

* `QuarantineMeta.payload_version` distinguishes legacy raw payloads (`0`) from
  container payloads (`1`, `LQPAY1`). The field defaults to `0`, so existing
  vaults remain readable.
* The container stores the body length, stream count, each validated stream name,
  each stream length and each stream's bytes. Stream bytes are inside the
  XChaCha20-Poly1305 ciphertext; only names and sizes appear in the
  authenticated header.
* The header and payload are cross-checked on read: unknown payload versions,
  magic mismatches, count/length mismatches, duplicate/trailing bytes, invalid
  stream names, and stream-size overflow are rejected as `Corrupt`.
* Legacy raw entries without `file_times` or `alternate_streams` still restore.

### ADS and timestamp capture — `winplatform::filemeta`

* `FindFirstStreamW` / `FindNextStreamW` enumerate named `$DATA` streams; the
  unnamed stream is the body and is excluded.
* `validate_stream_name` rejects path separators, NULs, embedded colons and names
  longer than 255 UTF-16 units before a path is built from one.
* Limits are enforced while reading: **64 streams**, **16 MiB per stream** and
  **64 MiB total**. Exceeding a limit fails the quarantine operation rather than
  silently dropping metadata.
* `FileTimes` captures creation, access and modification times. Restoration uses
  `SetFileTime` through a `FILE_WRITE_ATTRIBUTES` handle, not a content handle.

### Quarantine transaction — `QuarantineVault::quarantine_file_impl`

1. Open the source once with `GENERIC_READ | DELETE` and share modes that deny
   new writers. If delete access is unavailable, fall back to a read-only handle
   and mark the source as retained; **do not delete by path**.
2. Capture metadata and the volume serial/file index from that same handle.
3. Read the body through the handle, hash it, and compare it with the scanner's
   expected digest when `quarantine_file_checked` was used.
4. Enumerate ADS by path, then re-open the path and confirm the volume serial and
   file index still match the opened object.
5. Encrypt the container payload, write a temporary entry, decrypt it again, and
   compare the body digest, alternate streams and timestamps with the captured
   values before renaming the entry into place.
6. Journal the intent, publish the conservative index row, re-hash the original
   through the held handle, re-check the path identity, run the safety
   authorization, and only then mark the **handle** for deletion.
7. If the content changed, the path identity changed, or delete access is
   missing, retain the source and record `source_retained_reason`; never call
   `remove_file` on the source path.

The handle is dropped only after the delete-on-close completes.

### Restore transaction — `QuarantineVault::restore`

* The authenticated header, not the mutable JSON index, supplies the digest,
  original path, ADS and timestamps.
* An existing target is refused before writing.
* The body is written to a temporary file, re-read and hashed, then ADS are
  written and read back for equality, and timestamps are applied. The temp file
  is published with `hard_link` (atomic no-clobber) or, where hard links are
  unavailable, `create_new` plus re-verification.
* The entry is removed only after the destination is published. An interrupted
  restore is reconciled by `recover_restore`, which reapplies ADS/timestamps to
  a matching target before removing the entry; any failure preserves both.

### Compatibility and failure behavior

* A vault created before this change keeps working; an entry with
  `payload_version = 0` is read as raw body and has no metadata to restore.
* A metadata capture failure (for example an unreadable stream) leaves the
  source untouched and creates no entry.
* A metadata write/verify failure during restore removes the temporary or
  unpublished target and leaves the entry intact for a retry.
* Quarantine is still **not** a real-time shield; this slice only changes what a
  completed on-demand quarantine preserves and refuses to delete.

## Files changed

| File | Change |
|---|---|
| `crates/litric-core/src/winplatform.rs` | `filemeta` module: stream enumeration/validation/limits, timestamp capture/apply, file identity, handle-based deletion, tests |
| `crates/litric-core/src/quarantine.rs` | versioned container payload, metadata in authenticated header, identity-bound transaction, metadata-aware restore/recovery, tests |
| `crates/litric-cli/tests/scan_quarantine_e2e.rs` | end-to-end scan → quarantine → restore test with ADS/timestamps and a plaintext-leak assertion |
| `docs/PHASE1_QUARANTINE_METADATA.md` | this report |
| `docs/STATUS.md`, `docs/LIMITATIONS.md`, `docs/FEATURE_TRUTH_MATRIX.md`, `docs/BASELINE_EVIDENCE.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `docs/ARCHITECTURE_MAP.md`, `docs/MEMORY/core.md` | truth updates and evidence links |

## Tests

### Full workspace

```
cargo +stable-x86_64-pc-windows-gnu test --workspace
```

* **597 passed, 0 failed, 0 ignored**, exit **0**.
* 57 test binaries plus 20 doctest harnesses; 18 harnesses contain tests, 39
  contain none, and all doctest harnesses contain 0 tests.
* Log: `target/evidence/phase1/ads-quarantine-workspace.log`.
* The previous recorded suite was **590**; this slice adds **7** tests.

### Focused evidence

```
cargo +stable-x86_64-pc-windows-gnu test -p litric-cli --test scan_quarantine_e2e
```

* **8 passed, 0 failed**, exit **0**; log
  `target/evidence/phase1/ads-quarantine-e2e.log`.
* The new end-to-end test creates an EICAR file with `Zone.Identifier` and a
  custom ADS, sets a known 2023 timestamp, runs the real CLI scan with
  `--quarantine-malicious`, verifies the source is moved, asserts the ADS marker
  is absent from every `.lq` file, restores to a new path, and verifies the ADS
  bytes and creation/modification times.

The seven tests added in this slice:

* `stream_names_are_validated_not_concatenated_blindly`
* `alternate_streams_roundtrip`
* `file_times_roundtrip_through_set_file_time`
* `delete_by_handle_targets_the_open_object_not_a_replacement_path`
* `quarantine_preserves_alternate_streams_and_timestamps`
* `legacy_raw_entries_without_new_metadata_still_restore`
* `scan_quarantine_preserves_alternate_streams_and_timestamps` (CLI E2E)

Focused core unit suite result from the same source: **232 passed, 0 failed**
(log `target/evidence/phase1/ads-quarantine-workspace.log`).

### Static analysis caveat

`cargo +stable-x86_64-pc-windows-gnu clippy -p litric-core -p litric-cli
--all-targets -- -D warnings` is **not clean** at this revision. It reports
pre-existing lints in `guard.rs` (derivable impl), `pe.rs` (argument count),
`safety.rs` (`map_err`/`format!`/default initialization), `taxonomy.rs`
(`map_or`) and older quarantine tests (default initialization). This slice did
not claim a clean clippy run and did not silence those warnings. The normal test
and build path is green.

## Security review

### Strengthened properties

* **No path-based source deletion.** The delete uses
  `SetFileInformationByHandle` on the handle that was read. The low-level test
  swaps a replacement into the path after opening the original; the open object
  is deleted and the replacement survives.
* **Digest binding.** `quarantine_file_checked` refuses a source whose bytes no
  longer match the scanner's digest. The vault copy is decrypted and re-hashed
  before the entry is published.
* **Identity binding.** Volume serial plus file index are checked after ADS
  capture and again immediately before deletion. A different object at the path
  cannot inherit the removal.
* **Metadata is authenticated, not trusted from JSON.** The entry header is the
  AAD for the ciphertext and is re-read on restore; a tampered header fails
  authentication.
* **Bounded metadata.** Stream count and bytes are limited during capture,
  encoding, decoding and writing; a crafted entry cannot force unbounded
  allocation from a declared length.
* **Plaintext check.** The E2E test proves the ADS marker does not appear in the
  `.lq` container. The body was already covered by the existing plaintext test.

### Residual risks and limits

* **NTFS only.** ADS and `SetFileTime` semantics assume NTFS; FAT/exFAT has no
  ADS. The vault's existing ACL requirement already refuses non-NTFS local
  vaults, but this report does not claim ReFS behavior.
* **Not every metadata class is preserved.** Security descriptors, EAs, file
  attributes (read-only/hidden/system), compression/encryption attributes,
  stream ACLs and stream timestamps are not captured. The original file name and
  body are preserved; the list above is not.
* **Access time is captured and applied but not asserted.** Reading a restored
  file can update last-access time depending on the volume's
  `NtfsDisableLastAccessUpdate` policy, so the tests assert creation and
  modification, not access.
* **ADS are read by path while the body is owned by a handle.** The path identity
  is checked before and after the stream walk, and delete-capable opens deny new
  writers. A writer that already had the object open can still force the
  read-only fallback; the source is then retained. In-place changes to a single
  stream on the same file object are not independently re-hashed.
* **Hard-link siblings survive.** Deleting the opened link does not delete other
  hard links to the same file object. This is correct filesystem behavior but
  means quarantine is not “every name for these bytes is gone”.
* **Reparse points are not rejected at the vault API.** The OS follows a symlink
  or junction on open; handle-based deletion then targets the opened object, not
  the link. The scanner walker skips reparse points, but a direct
  `quarantine_file` caller must pass a real file path.
* **Destination parent is trusted.** Restore's no-clobber check and atomic
  publish do not protect against an attacker who already controls the destination
  directory and can race the predictable temporary name. A same-user attacker
  who can write that directory can also replace the restored file afterwards.
* **No real power-loss test.** Journal reconciliation is simulated by interrupted
  states; no disk was physically cut during this slice.
* **In-memory body.** Quarantine reads the whole file body into memory as before;
  this slice adds up to 64 MiB of ADS on top. That is bounded, but not streaming.
* **No performance claim.** No benchmark was run for the metadata path. The added
  work is one stream enumeration and up to three `SetFileTime` fields per
  quarantine/restore, not per scanned file.
* **Clippy is not clean** (see above); this is a repository-wide pre-existing
  condition, not a property introduced by this slice.

### Privacy

Stream bytes and body bytes are encrypted. Stream **names** and sizes are visible
in the header because they are needed to interpret the payload; names such as
`:Zone.Identifier` reveal provenance, not content. No network call, telemetry or
external upload was added.

## Performance

No measured throughput or latency number is claimed. The metadata path performs
one directory stream enumeration, up to 64 stream reads, one container encode and
one decode for verification per quarantine, and one ADS write plus one read-back
per restore. Those costs are proportional to ADS size, which is capped at 64 MiB
total; they are not on the normal scan path.

## Incomplete / next Phase 1 items

* A sanitizer-backed fuzz run. Coverage-guided parser targets were delivered in
  [`PHASE1_COVERAGE_FUZZ.md`](PHASE1_COVERAGE_FUZZ.md) (8.38M executions, no crash
  artifacts) but use `--sanitizer none`.
* Real crash/power-loss testing and an allocation-peak measurement.
* Preserve or explicitly document security descriptors, EAs, attributes and
  stream ACLs/timestamps.
* Bind the key id to the vault index for tamper evidence; key rotation and
  DPAPI-NG/TPM remain absent.
* Trusted temporary-file creation for restore, or a handle-based publish step.
* The Windows installer, UI, kernel/AMSI/ETW/WFP layers and network updates are
  still absent.

## Exit gate

**PARTIAL.** The requested quarantine metadata and identity hardening is
implemented and exercised by unit, integration and CLI end-to-end tests, and no
unknown/error path is converted to a successful move. Phase 1 as a whole is not
complete: sanitizer-backed fuzzing, real power-loss testing and broader metadata
coverage remain open.

## Next

Remaining Phase 1 work is fuzzing depth and power-loss/recovery evidence, not a
new phase. Do not start Phase 2 until the Phase 1 exit gate is explicitly
approved.
