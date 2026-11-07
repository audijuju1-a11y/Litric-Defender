# ClamAV signature data: license and distribution position

**Not legal advice.** Findings come from secondary sources found in a web search (distribution package metadata, repository READMEs). The official ClamAV terms page was **not** read, so treat every statement below as unverified until checked against clamav.net and counsel.

## What was found
- ClamAV's engine is licensed GPL-2.0; its README states libclamav may not be linked into closed-source software.
- Linux distribution metadata (Fedora `clamav-data`) labels the virus-signature data package GPL-2.0-only.
- Third-party databases published through the ClamAV mirror network carry their own terms. Historical freshclam documentation states that the Safe Browsing database is provided under Google's terms of use, not ClamAV's.

## What Litric does and does not do
- No ClamAV code is used, linked or executed. The importer and matcher are Litric code.
- Litric reads signature *files the user supplies*. **Nothing from ClamAV is bundled** in this repository or the zip.

## Implications (to confirm with counsel before any release)
1. Do **not** ship ClamAV databases inside a Litric installer or update feed until the license of each database file is confirmed. If the data is GPL-2.0, redistributing it alongside a proprietary product raises compliance questions (source/notice obligations, whether the bundle is one work).
2. Preferred design: the user (or administrator) downloads signatures from the official mirrors themselves under ClamAV's terms; Litric only imports them. Do not scrape the public mirrors at scale; a private mirror is the documented route for large fleets.
3. Keep provenance per signature (already in the Litric DB `source_note`) so any file can be traced and removed.
4. Third-party and Safe-Browsing-derived data must be excluded unless their individual terms permit use.
5. Detection *names* and signature IDs copied into Litric reports are factual labels; still record the source.

## YARA
`yara-x` is BSD-3-Clause. YARA *rules* have per-rule-set licenses (many are GPL, CC or custom). Load only rule sets whose license permits your use, and record the license beside each file.
