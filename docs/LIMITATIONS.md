# Litric Defender — known limitations

This file exists so that no claim in this repository can be read as more than it
is. If a limitation here contradicts a marketing sentence elsewhere, this file
wins.

## 1. Litric Defender is not yet an installed antivirus product, and it is not a Malwarebytes replacement

There is no installer and no UI, and no kernel-mode enforcement. There **is** a
real SCM service host (`litricd service install`, see `docs/PROCESS_GATE.md` §3)
and a best-effort process gate that suspends a new process, scans its image and
terminates it only on an exact malicious hash match — and only when installed or
started with `--process-gate enforce`; the default is `monitor`, which kills
nothing. Neither was exercised
through an elevated SCM start in this session, and the gate can lose the race
between `CreateProcess` and suspension. It does **not** replace Microsoft
Defender or Malwarebytes, does not register with Windows Security Center, and
does not block file writes in real time. Do not deploy it as sole protection.
The measured capability comparison behind this statement is
`docs/MALWAREBYTES_COMPARISON.md`.

## 2. No kernel-mode components (and why)

Real-time blocking of file writes and reliable block-before-execute require a
minifilter driver. Shipping one requires a Microsoft-issued signature obtained
through the Hardware Dev Center with an EV certificate and a legal entity, and
ELAM/PPL additionally require Microsoft Virus Initiative membership. Those are
procurement and certification gates, not code. Accordingly, no driver source is
included: writing a driver that could never be loaded or tested would be
fiction.

Consequences: no Protected Folder Guard enforcement, no OS-wide pre-execution
blocking, no tamper-resistant service, no memory/injection telemetry
(`Microsoft-Windows-Threat-Intelligence` requires AM-PPL, which requires ELAM).
The CLI guard can refuse a launch made through it, but it is not a system-wide
blocking control.

### 2.1 The CLI preflight guard is not a system-wide shield

`litric guard` scans one target, blocks it when the verdict is malicious, and
refuses to spawn the child for suspicious, unknown or truncated scans. The
original is left in place by default; `--quarantine` opts in to moving it into
the vault. That is a real gate, but only for launches made through that command. It does not
intercept Explorer double-clicks, services, scheduled tasks, another process, or
malware that a permitted program drops and runs later. It is not an ETW/AMSI
sensor and has no kernel enforcement.

The guard re-hashes the file immediately before launch, which narrows the
scan-to-exec race; it does not eliminate it. A path can still be replaced after
the check and before the operating system opens it. `--allow-unknown` is an
explicit fail-open override and should not be used without review.

### 2.2 Scan-time quarantine is still on-demand, not a real-time shield

`litric scan --quarantine-malicious` walks a file or recursive directory and
moves files whose verdict is `Malicious` into the encrypted vault. `Clean` and
`Unknown` files are left untouched. A move is accepted only when the current
bytes still match the digest recorded by the scan; the vault verifies the
encrypted copy before removing the source. If any move fails, the source is
retained and the command exits with status 4. A successful scan with malicious
content exits 1; a clean result exits 0.

This is an **on-demand pass**, not continuous protection. It sees only files
present during that walk. It does not monitor files created, downloaded, or
renamed afterwards, and it does not intercept Explorer, services, scheduled
tasks, or other processes. There is no ETW consumer, AMSI provider, WFP policy,
or minifilter in this build. Running a scan after a file has already executed is
too late to stop that execution. A move is bound to the opened file object: if
the bytes or path identity change, or delete access is unavailable, the source
is retained and the command reports failure rather than deleting a replacement.

## 3. Detection coverage is narrow and honestly so

* **Hash reputation: none.** The distributed database contains rules only. No
  commercial or community malware-hash feed is licensed for redistribution in
  this project. Every report says hash reputation is unavailable.
* **73 rules (22 core + 51 extended).** That is not a competitive signature set
  and is not presented as one. Neither set is a substitute for a maintained
  malware feed, and rule count is not detection coverage.
* **Archive recursion covers the ZIP family only.** ZIP, OOXML and JAR members
  are read into memory (never extracted to disk) and analysed by the same
  engine, bounded to 512 entries, 16 MiB per member, 64 MiB per layer, a 1000:1
  compression ratio and 3 nested layers. A member that exceeds a limit, a
  malformed or password-protected entry, and anything past the depth budget is
  reported as skipped/truncated, and a truncated container is never `Clean`.
  RAR, 7z, ISO, MSI, CAB, gzip and bzip2 are still identified only as
  containers.
* **Macro analysis is source-only.** VBA modules are extracted from
  `vbaProject.bin` (see below); BIFF5/BIFF7/BIFF8 Excel 4.0 formulas are decoded
  from `FORMULA` records (array constants from the record's `RgbExtra`), but
  compiled p-code and password-protected projects are not analysed, so a macro-capable document
  with an unparsable project is reported as such, never assumed benign.
* **No emulation, unpacking or disassembly.** Packed samples get structural
  signals, not payload recovery.
* **De-obfuscation is bounded pattern decoding, not emulation.** Up to three
  layers of base64, `[char[]](...)`/`[char]` cast chains and constant-key XOR
  (`-bxor <int>`) are decoded when written as explicit constructs, and a payload
  must be at least 8 printable ASCII characters, so a random number table is not
  treated as text. All decoding for one file shares an 8,000,000-step budget and
  the report states when it ran out. Variable-key XOR search, string
  splitting/reversal, multi-statement assembly, VBA `Chr`/string building and
  instruction-level emulation are not implemented; an unmarked base64 string is
  deliberately ignored to avoid false positives on ordinary data.
* **VBA analysis is source-level only.** Modules are extracted from the `VBA`
  storage of `vbaProject.bin` (OOXML member or legacy OLE2) and decompressed
  with MS-OVBA; a stream that fails the chunk signature is reported, not
  guessed. Each module's PerformanceCache (p-code) is detected and counted, but
  the p-code itself is not decompiled, so a source-only clean result cannot rule
  out VBA stomping; a cache-only stream is flagged separately. Password-protected
  modules and projects inside archives nested deeper than the top-level file are
  not analysed. Caps: 8 MiB project, 64 module streams, 2 MiB compressed
  stream, 1 MiB per module, 8 MiB decompressed total.
* **Excel 4.0 (XLM) coverage is split by container and BIFF version.** For OOXML, formulas are
  extracted from `xl/macrosheets/*.xml` and analysed as text; hidden state is not
  mapped from `workbook.xml`. For legacy `.xls`, BIFF5, BIFF7 and BIFF8
  `FORMULA` records inside macro-sheet substreams are decoded with the MS-XLS
  Ftab function table and analysed as text. BIFF5/7 use one-byte code-page
  strings (mapped as Latin-1, so a non-ASCII name may not match its original
  code page), three-byte cell references and the larger name/3-D token bodies.
  Unknown function ids are rendered as `FUNC_0xNNNN` / `MACRO_0xNNNN` and marked
  incomplete rather than guessed. Array constants are decoded from the
  record's `RgbExtra` (`PtgExtraArray`), and the `PtgMemArea`/`PtgMemErr`/
  `PtgMemNoMem`/`PtgMemFunc` wrappers keep the reference expression they enclose.
  External-reference resolution, BIFF4-and-earlier workbooks and `.xlsb` are not
  decoded.
* **Unknown is the common answer.** Most ordinary files will be reported
  `Unknown`, because that is the truthful result for a file with no trust record
  and no matching evidence.

## 4. Signature handling is partial

`authenticode.rs` parses the WIN_CERTIFICATE blob and extracts certificate
subjects, validity dates and the code-signing EKU using a small DER walker. It
does **not** validate the certificate chain to a trusted root, check revocation,
verify page hashes, or confirm that the signature actually covers the file. A
report saying "signature present" must be read as "a structurally plausible
signature blob exists". `safeos_assess` delegates embedded-signature chain
validity to `WinVerifyTrust`, and that path is now executed natively. Catalog
signatures, revocation freshness and page hashes remain absent.

## 5. RansomShield makes decisions, not enforcement

The scoring engine, decoy logic and response policy are real and tested, but they
are driven by a simulator here. On Windows the events would come from an ETW
`Microsoft-Windows-Kernel-File` consumer (passive) and enforcement would need a
minifilter. "Suspend process" and "block writes" are returned as action requests;
nothing in this repository performs them.

False positives remain possible: a legitimate tool that rewrites documents with
high entropy and renames them to an unusual extension can be escalated. That is
why actions are graded and a decoy hit is required for the most severe response.

## 6. Performance numbers are from one Windows 11 machine

The measured **505 files/s (10.4 MB/s)** on 767 real PowerShell files and
**56 files/s (12.8 MB/s)** on 603 real driver images come from this Windows 11
x86_64 host, a release build with 73 rules and a single-threaded engine. A debug
build of the same CLI measured 222.6 and 39.9 files/s on the same corpora on
2026-11-07, so any figure must state the build profile and the machine load.
These are not whole-disk figures and not comparable with vendor benchmarks. The driver
corpus is dominated by PE parsing; the small-file corpus is the better proxy for
a quick scan. No idle CPU/RAM, boot-impact, VM or network-gateway measurement has
been made because those components do not exist yet.

The engine is single-threaded today; a worker pool is planned.

## 7. Parser robustness is tested, not proven

Malformed input is handled by construction (bounds-checked readers, capped
loops, no `unsafe` in parser code, no indexing of attacker data). Tests cover
random, truncated and adversarial buffers, and `tests/parser_fuzz_soak.rs` runs
45,000 deterministic mutations plus crafted bomb, traversal and truncation cases.
Four `cargo-fuzz` targets now add coverage-guided campaigns (8.38M executions on
2026-11-07, no crash artifacts). They run with `--sanitizer none`, do not
minimise the corpus, and the parsers remain in-process; the memory probe samples
between inputs rather than recording instant allocation peaks. See
`docs/PHASE1_PARSER_SOAK.md` and `docs/PHASE1_COVERAGE_FUZZ.md`.

## 8. Threat database signing uses a development key

`dev_signing_key()` is a fixed, public test key. Runtime binaries accept it only
when the operator explicitly sets `LITRIC_ALLOW_DEV_DB=1`; otherwise the database
is **refused** (fail-closed), even if its signature is valid. Content signed with
a real key is accepted only when that key is pinned via `LITRIC_DB_PUBKEY`.
Databases loaded with the fixture key are reported as `DbTrust::DevelopmentOnly`
and the CLI/service prints a warning. There is no production key, no key
ceremony, no HSM and no rotation runbook yet. Do not ship content signed with the
development key.

## 9. Threat intelligence licensing

No third-party signature feed is embedded. Specifically excluded: ClamAV
(license and product rule), `Yara-Rules/rules` (GPLv2), Elastic
`protections-artifacts` (Elastic License 2.0), abuse.ch community feeds
(commercial use requires a Spamhaus licence), AMTSO SFC test files (redistribution
forbidden). MITRE ATT&CK technique IDs are used under its royalty-free licence
and are identifiers only. The EICAR test string is included because detecting it
is the industry-standard self-test.

## 10. Things this project deliberately does not do

* Disable, stop, bypass or tamper with Microsoft Defender or Windows Security.
* Install an unsigned driver or instruct users to disable Secure Boot / test
  signing.
* Upload user files anywhere.
* Delete user files during scanning or quarantine (quarantine *moves* a file into
  an encrypted vault and only after verifying the vault copy).
* Report a green "protected" state that is not backed by working code.
* Use an LLM or "AI" to make allow/block/quarantine decisions.

## 11. Vault key protection and its boundaries

The vault key is sealed with **machine-scoped** DPAPI (Windows Data Protection
API) and the key file gets a protected `SY/BA/OW` DACL. Machine scope is
deliberate: the installed service (LocalSystem) and the same machine's CLI must
be able to open the same vault. Consequences, stated plainly:

* DPAPI machine scope means **any user on this machine who can read the key file
  can decrypt it**. The DACL is the access boundary; the encryption is not a
  defence against a local user who is already allowed to read the file, nor
  against an administrator, nor against malware running as that user.
* Moving the vault (or just `vault.key`) to another machine makes the key
  unreadable. Export the key or keep the original recovery copy before moving.
* A migrated legacy key leaves a plaintext `vault.key.legacy` recovery copy with
the same protected DACL. Delete it deliberately once the migration has been
  verified, or keep it if losing the key would lose data you need.
* ACL hardening requires NTFS. A local vault on FAT/exFAT is refused rather than
  used with default permissions.
* Not implemented: key rotation UI, DPAPI-NG/TPM binding, HSM-backed keys. Do not
treat this as enterprise key management.

## 12. Quarantine preserves some metadata, not all

On NTFS, quarantine preserves the file body, up to 64 named `$DATA` alternate
streams (16 MiB each, 64 MiB total) and the creation, access and modification
timestamps, all inside the encrypted container. Restore writes and verifies the
streams and applies the timestamps before publishing.

It does **not** preserve security descriptors/ACLs, extended attributes, file
attributes (read-only/hidden/system), compression or EFS state, stream ACLs or
stream timestamps. Other hard links to the same file object survive deletion of
the quarantined link. Reparse points are followed by the OS rather than rejected
at the vault API; the scanner walker skips them, but a direct caller must pass a
real file. These are limits of the current implementation, not untested claims:
EAs/ACLs/attributes have no capture code at all.

Access time is stored but not asserted in tests, because reading a restored file
can update it depending on the volume's last-access policy. The test evidence
asserts creation and modification times.
