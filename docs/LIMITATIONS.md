# Litric Defender — known limitations

This file exists so that no claim in this repository can be read as more than it
is. If a limitation here contradicts a marketing sentence elsewhere, this file
wins.

## 1. Litric Defender is not yet an installed antivirus product

There is no installer, no Windows service, no UI and no OS-level enforcement in
this repository. It is a detection engine plus a CLI scanner. It does **not**
replace Microsoft Defender, does not register with Windows Security Center, and
does not block anything in real time. Do not deploy it as protection.

## 2. No kernel-mode components (and why)

Real-time blocking of file writes and reliable block-before-execute require a
minifilter driver. Shipping one requires a Microsoft-issued signature obtained
through the Hardware Dev Center with an EV certificate and a legal entity, and
ELAM/PPL additionally require Microsoft Virus Initiative membership. Those are
procurement and certification gates, not code. Accordingly, no driver source is
included: writing a driver that could never be loaded or tested would be
fiction.

Consequences: no Protected Folder Guard enforcement, no pre-execution blocking,
no tamper-resistant service, no memory/injection telemetry
(`Microsoft-Windows-Threat-Intelligence` requires AM-PPL, which requires ELAM).

## 3. Detection coverage is narrow and honestly so

* **Hash reputation: none.** The distributed database contains rules only. No
  commercial or community malware-hash feed is licensed for redistribution in
  this project. Every report says hash reputation is unavailable.
* **15 rules.** That is not a competitive signature set and is not presented as
  one.
* **No archive recursion.** ZIP/RAR/7z/ISO/MSI are identified as containers, but
  their members are not extracted or scanned. Malware inside an archive will be
  reported as a container, not as a threat.
* **No macro extraction.** OOXML/OLE2 documents are flagged only as
  macro-capable containers.
* **No emulation, unpacking or disassembly.** Packed samples get structural
  signals, not payload recovery.
* **No de-obfuscation.** Encoded PowerShell is flagged, not decoded.
* **Unknown is the common answer.** Most ordinary files will be reported
  `Unknown`, because that is the truthful result for a file with no trust record
  and no matching evidence.

## 4. Signature handling is partial

`authenticode.rs` parses the WIN_CERTIFICATE blob and extracts certificate
subjects, validity dates and the code-signing EKU using a small DER walker. It
does **not** validate the certificate chain to a trusted root, check revocation,
verify page hashes, or confirm that the signature actually covers the file. A
report saying "signature present" must be read as "a structurally plausible
signature blob exists". `safeos_assess` delegates chain validity to
`WinVerifyTrust` on Windows; that path is compiled but not executed on a native
Windows host here, and revocation/page-hash checks remain absent.

## 5. RansomShield makes decisions, not enforcement

The scoring engine, decoy logic and response policy are real and tested, but they
are driven by a simulator here. On Windows the events would come from an ETW
`Microsoft-Windows-Kernel-File` consumer (passive) and enforcement would need a
minifilter. "Suspend process" and "block writes" are returned as action requests;
nothing in this repository performs them.

False positives remain possible: a legitimate tool that rewrites documents with
high entropy and renames them to an unusual extension can be escalated. That is
why actions are graded and a decoy hit is required for the most severe response.

## 6. Performance numbers are from one Linux VM

The measured ~3 050 files/s and ~3.1 MB/s come from a 2 vCPU Linux VM with a
synthetic 2 000-file corpus of small files. They are **not** Windows figures, not
whole-disk figures, and not comparable with vendor benchmarks. No CPU, RAM, I/O
or boot-impact measurement has been made on Windows because no Windows host is
available in this environment.

The engine is single-threaded today; a worker pool is planned.

## 7. Parser robustness is tested, not proven

Malformed input is handled by construction (bounds-checked readers, capped
loops, no `unsafe`, no indexing of attacker data), and tests cover random,
truncated and adversarial buffers. That is not the same as fuzzing. Continuous
fuzzing (cargo-fuzz/AFL) is planned and has not been run.

## 8. Threat database signing uses a development key

`dev_signing_key()` is a fixed, public test key. Databases signed with it load
with `DbTrust::DevelopmentOnly` and the CLI prints a warning. There is no
production key, no key ceremony, no HSM and no rotation runbook yet. Do not ship
content signed with the development key.

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
