# Importing ClamAV signatures (offline procedure)

1. **Acquire** ClamAV databases yourself from an official source, on a machine that may run ClamAV tools.
   Confirm the license/redistribution terms first (see DEPENDENCIES.md; not verified here).
2. **Verify and unpack with official tools** (e.g. `freshclam` + `sigtool --unpack`). Litric does **not** verify
   CVD/CLD signatures. Do not import files whose origin you cannot verify.
3. **Import:**
   `litric-clamav-import --serial N --source-note "how obtained and verified" --out db.lsdb --report report.txt <dir>`
   - `--serial` must increase on every release (anti-rollback).
   - Read `report.txt`: every input file is listed; unsupported files and lines are counted, never hidden.
   Add `--binary` for the compact LSDBBIN1 format (or run `sigtool compile db.lsdb db.bin` afterwards). See DB_FORMAT.md.
4. **Sign** with your offline Ed25519 key: `sigtool sign seed.txt db.lsdb db.sig` (for binary files only the header is signed; it contains every section's hash)
   (generate the seed with a trustworthy RNG, e.g. `openssl rand -hex 32`; never commit it).
5. **Install** through `sigdb::Store::install` / `install_file` (verifies signature and hashes, refuses rollback, atomic swap). `install_file` streams large databases from disk.
6. **Scan** with `litric-scan --pubkey <hex> --store <dir> ...`; the database provenance lines are printed with the results.

Trust chain gap: ClamAV's authenticity is vouched for only by step 2 (your actions) and your source note. After step 4,
the Litric signature proves only that *you* published this file.
