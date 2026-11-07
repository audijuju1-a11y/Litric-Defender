# Litric Safety Guard — data-protection model

**Status: IMPLEMENTED and TESTED on Windows 11 x86_64 (GNU toolchain).**
This document describes what Litric is allowed to do to the machine, not what it
claims to protect the machine from.

## 1. Why this exists

An antivirus is one of the few programs on a PC that is explicitly expected to
delete files. That power is also the fastest way to destroy a user's data if a
detection is wrong, a path is mis-resolved, or a loop runs away. Litric therefore
does not let any detection module, API handler or future UI call `remove_file`
directly. Every destructive operation passes through one component:
`litric_core::safety::SafetyGuard`.

The guard enforces five independent controls:

1. **Protected locations** — Windows system trees, Program Files, ProgramData,
   boot/recovery/recycle-bin trees, the user-profile root, and Litric's own
   policy and audit files can never be removed, written over, or used as a
   restore destination.
2. **Authorised scope** — a removal is only allowed for the exact object the
   caller was asked to move, or below the directory the user explicitly asked to
   scan. `..` segments and symlinks cannot widen it.
3. **Digest re-verification** — immediately before the unlink, the file is
   hashed again and compared with the digest the scanner classified. A file
   swapped after the scan is refused.
4. **Removal budget** — a rolling per-minute cap on the number of removals and
   total bytes. A bug or a compromised caller cannot wipe a disk in one pass.
5. **Hash-chained audit** — every allowed removal, every refusal and every
   outcome is appended to `safety-audit.jsonl` with `prev` and `hash` fields.
   Editing, deleting or reordering a record is detectable. If the chain is
   already broken, destructive operations fail closed.

The vault's own guarantees (encrypt → verify → index → remove; restore refuses
overwrite; purge needs confirmation) remain in place. The guard is an additional,
independent barrier, not a replacement.

## 2. Where it is enforced

| Operation | Enforcement |
|---|---|
| Quarantine move (`vault.quarantine_file`, `--quarantine-malicious`, API `/quarantine` with `copy_only:false`) | Protected/scope check **before** anything is written; digest-bound authorisation immediately before `remove_file` |
| Purge (`vault.purge`, `DELETE /api/v1/quarantine/{id}?confirm=true`) | `allow_permanent_delete` policy flag, explicit confirmation, audit of `allowed` and `completed` |
| Restore (`vault.restore`) | Protected-destination check before creating a temp file or directory |
| SafeOS cleanup | Existing journal-scoped cleanup; never touches paths outside the session directory (separate control) |
| SafeOS export over an existing file (`Broker::export` with explicit approval) | The old file is moved aside to a sibling `.litric-*.previous` path and kept; it is restored if publishing the verified new file fails. No `remove_file` of a user destination |

The guard is created when the vault is opened, so every CLI, daemon and test path
that uses a vault is covered. A caller cannot obtain a `RemovalPermit` for a
protected file, a changed file, a directory, a symlink, or a path outside its
scope.

### Destructive-action defaults

Removing the original file is always an explicit decision:

| Entry point | Default | Opt-in to remove the original |
|---|---|---|
| `litric guard` | block the launch, file untouched | `--quarantine` (requires `--vault-dir` / `--vault-key`) |
| `litric quarantine add` | store an encrypted copy, original stays | `--remove-original` |
| `POST /api/v1/quarantine` | store an encrypted copy (`copy_only: true`) | `"copy_only": false` in the request |
| `litric scan` / `POST /api/v1/scan` | report only | `--quarantine-malicious` / `"quarantine_malicious": true` |
| `DELETE /api/v1/quarantine/{id}` | refused without confirmation | `?confirm=true` and `allow_permanent_delete: true` |
| `litric guard --no-quarantine` | deprecated no-op (already the default) | never removes; kept so old scripts parse |

A blocking decision is not a destructive one. An API bug, a UI mistake or a
missed flag can therefore not delete a file by itself; the worst outcome is an
encrypted extra copy plus a blocked launch.

### Process-termination and install defaults

Terminating a process is destructive too, so the gate ships disarmed:

| Entry point | Default | Opt-in |
|---|---|---|
| `litricd serve` | `--process-gate off` — no process is inspected | `--process-gate monitor` (report) or `enforce` |
| `litricd service install` | writes `run-service --process-gate monitor` | reinstall with `--process-gate enforce` |
| `--process-gate enforce` | still kills only an image whose exact SHA-256 is malicious in the signed DB | n/a |

Protected roots (`%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`,
`%ProgramData%\Microsoft`, the daemon's own directory) and the daemon, its
ancestors and PIDs 0/4 are never suspended or killed. Rules and heuristics can
raise a verdict but never trigger a kill — a measured rule false positive on
`kernel32.dll` is why (`docs/SAFETY.md` §7.1).

Installation is an explicit, inspectable act: `litricd service install` points
only at the currently running executable (there is no binary-path flag), requires
elevation, refuses to start if the data-directory ACL cannot be restricted, and
`service uninstall` stops and deletes only `LitricDefender` — user data,
quarantine and the vault key are preserved. `--dry-run` prints every SCM
operation, and the install path never calls a Defender, firewall, WFP or
Security-Center API (the dry-run output states this).

The vault key is not left as plaintext: new keys are sealed with machine-scoped
DPAPI and the vault directory, key file and any legacy recovery copy receive the
protected `SY/BA/OW` DACL at vault open. A failure to apply it refuses the vault
rather than continuing with inherited `Users` access. Migration keeps the old raw
key as `vault.key.legacy` so an upgrade cannot lock the owner out. Details and
the scope limits are in `docs/PHASE1_SAFETY_REPORT.md` and
`docs/LIMITATIONS.md` §11.

## 3. Default policy

Written once to `<vault>/safety-policy.json`:

```json
{
  "schema": 1,
  "protected_paths": ["c:/windows", "c:/program files", "c:/program files (x86)",
                      "c:/programdata", "c:/recovery", "c:/boot",
                      "c:/$recycle.bin", "c:/system volume information"],
  "protected_exact": ["c:/", "c:/users/<name>"],
  "allowed_removal_roots": [],
  "max_removals_per_minute": 256,
  "max_removal_bytes_per_minute": 4294967296,
  "rehash_before_delete": true,
  "allow_permanent_delete": true
}
```

The actual lists are resolved from the live environment (`%SystemRoot%`,
`%ProgramFiles%`, `%ProgramData%`, `%SystemDrive%`, `%USERPROFILE%`), never from a
hard-coded drive letter. Paths are canonicalised before comparison, so a policy
written with an 8.3 short name (`AUDIM_~1`) still matches the long path returned
by the filesystem.

`allow_permanent_delete` is `true` by default because purge already requires an
explicit confirmation at both the CLI (`--confirm`) and API (`confirm=true`).
Setting it to `false` disables purge entirely.

## 4. Configuring it

* Edit `<vault>/safety-policy.json` while the daemon/CLI is not running.
* An unreadable or invalid policy is **not** replaced with a permissive default:
  `policy_trusted` becomes false and every destructive operation is refused with
  `PolicyUntrusted`. Restore (recovery) still works.
* The Windows system trees (`%SystemRoot%`, Program Files, ProgramData,
  `%SystemDrive%`\Recovery, `\Boot`, `$Recycle.Bin`, `System Volume Information`)
  are also protected **in code**. Editing them out of the policy file cannot
  unprotect them; the policy can only add more protected locations.
* `allowed_removal_roots` is an additional allowlist. Leave it empty to allow
  removals anywhere except protected paths; fill it to restrict quarantine to,
  for example, `D:/Downloads`.
* `max_removals_per_minute: 0` means "authorise no removals".
* Lowering `rehash_before_delete` to `false` weakens the scan-to-delete race
  protection and is not recommended.

Inspect the effective policy and verify the audit chain:

```bash
litric safety                       # via the daemon
litric safety --json
litric safety --local --vault-dir litric-data/quarantine --vault-key litric-data/vault.key
```

Exit code is 0 only when the policy is trusted **and** the audit chain verifies.

## 5. Audit log

One JSON object per line:

```json
{"seq":1,"unix":1762345678,"operation":"remove_source","decision":"allowed",
 "path":"C:\\Users\\a\\Downloads\\sample.exe","sha256":"…","detail":"4096 bytes, scope exactly …",
 "prev":"0000…","hash":"…"}
```

`hash = SHA-256` over the canonical serialisation of every field except `hash`,
including `prev`. `litric safety` reports the first broken record with its line
number. The log is append-only and is `sync_data`-ed after every record. It is
not encrypted; it contains paths and hashes, never file contents.

## 6. Failure behaviour

| Failure | Behaviour |
|---|---|
| Policy file invalid/unreadable | Destructive operations refused (`PolicyUntrusted`); list/verify/restore still available |
| Audit chain broken | Destructive operations refused (`AuditUntrusted`); the broken log is never rewritten or "repaired" |
| Audit write fails (disk full, permissions) | Removal is refused before the unlink |
| File changed after scan | Refused (`Changed`); original retained |
| Protected path | Refused (`Protected`); original retained |
| Outside scope | Refused (`OutsideScope`); original retained |
| Budget exhausted | Refused (`RateLimited`); remaining files retained and reported |
| Unlink fails after authorisation | Reported as a retained source with the OS error; the vault entry stays |

A refused quarantine may leave a verified encrypted copy in the vault while the
original stays in place. That is intentional: the copy is evidence, and the UI
must show "source retained" rather than pretending the file was moved.

## 7. Honest limits

* The guard protects against **Litric's own** destructive actions. It is not a
  kernel driver, does not intercept other processes, and cannot stop an attacker
  who already has the user's privileges.
* The per-minute budget is per process. A new process starts a new window.
* Re-hashing before delete narrows the scan-to-delete race; it does not eliminate
  it. A file can still be replaced in the microseconds between the hash check and
  the unlink.
* Canonicalisation does not resolve every Windows reparse-point edge case; the
  guard refuses symlinks and non-regular files, and uses canonical paths for all
  comparisons.
* Catalog-only signatures (Windows system binaries) are not verified by the
  guard. That is why OS-owned locations are protected by location rather than by
  heuristic weight; see `docs/STATUS.md` for the Authenticode boundary.
* The audit log is tamper-evident, not tamper-proof: an attacker with write access
  can delete the whole file. A missing log verifies as zero records, which is why
  the daemon also reports `authorised_removals` for the running process.

## 7.1 False positives on source text (measured)

Scanning `rules/` with the current rules produces two `MALICIOUS` verdicts on the
`.lrs` files themselves (`Iot.MiraiLikeMarkers`, `Ransom.ShadowCopyDestruction`),
because the rule sources contain both halves of those conjunctive patterns as
text. This is a real false positive, not a test artifact.

Consequences and guidance:

* `litric scan` without `--quarantine-malicious` only reports; nothing moves.
* `--quarantine-malicious` moves a matching file into the encrypted vault after
  a digest check; it is recoverable with `litric quarantine restore`, but it is
still a disruption. **Do not run it over source trees, signature repositories,
security documentation or test fixtures that quote malware strings.**
* This is why the measured FP corpus in `docs/WINDOWS_EVIDENCE.md` is limited to
Windows system files: it does not include text that intentionally contains
detection patterns, and the result must not be generalised to such corpora.
* A future rule-quality gate should score text-only matches differently from PE
matches; until that exists, treat this as a known limitation.

## 8. Test evidence (Windows 11 x86_64, 2026-11-07)

`cargo +stable-x86_64-pc-windows-gnu test --workspace`

| Test | Proves |
|---|---|
| `safety::tests::protected_location_is_refused_and_the_file_survives` | protected paths are refused and nothing is deleted |
| `safety::tests::a_path_cannot_escape_the_scope_with_dot_dot` | `..` cannot widen the authorised scope |
| `safety::tests::a_file_that_changed_after_the_scan_is_refused` | digest re-verification blocks a swapped file |
| `safety::tests::the_budget_stops_a_bulk_deletion` | the third removal is refused at a budget of 2 |
| `safety::tests::the_audit_chain_records_allowed_refused_and_completed_outcomes` | allowed + completed records, chain verifies |
| `safety::tests::an_edited_audit_log_fails_verification_and_blocks_removal` | editing a record is detected and blocks further removals |
| `safety::tests::removing_a_middle_record_breaks_the_chain` | deleting a record is detected |
| `safety::tests::an_invalid_policy_fails_closed` | invalid policy refuses removals |
| `safety::tests::the_guard_protects_its_own_policy_and_audit_files` | Litric cannot delete its own controls |
| `safety::tests::directories_are_never_removed_by_the_guard` | directory targets are refused |
| `safety::tests::restoring_into_a_protected_location_is_refused` | restore cannot write into a protected path |
| `quarantine::tests::quarantine_refuses_a_protected_source_and_writes_nothing` | integration: no vault entry is created for a protected source |
| `quarantine::tests::restore_refuses_a_protected_destination` | integration: no bytes written to a protected destination |
| `quarantine::tests::the_audit_chain_records_a_quarantine_removal` | integration: removal + digest recorded and chain verifies |
| `quarantine::tests::quarantine_preserves_alternate_streams_and_timestamps` | ADS and created/modified times survive quarantine and restore |
| `winplatform::filemeta::tests::delete_by_handle_targets_the_open_object_not_a_replacement_path` | a path replacement is not deleted; the opened object is |
| `winplatform::filemeta::tests::alternate_streams_roundtrip` | named `$DATA` streams are written, enumerated and read back exactly |
| `scan_quarantine_e2e::scan_quarantine_preserves_alternate_streams_and_timestamps` | real CLI scan→quarantine→restore preserves ADS/times and leaks no stream plaintext |

The exact pass counts are recorded in `docs/MEMORY/build.md`; this page does not
repeat a number that changes with every test run. The full suite passed natively
on 2026-11-07: 597 passed, 0 failed, 1 ignored (568 before the Phase 0/1 fixes), with Defender
real-time protection off.
