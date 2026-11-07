# Architecture map (Phase 0, verified)

Built from the manifests and source, not from the design documents. Where the
design and the code disagree, the code wins and the gap is listed in
`SECURITY_GAP_ANALYSIS.md`.

## 1. Crates and binaries

| Crate | Role | Binary |
|---|---|---|
| `litric-core` (17,385 LOC) | engine, rules, heuristics, PE, archives, VBA/XLM, deobfuscation, quarantine, safety, threat DB, RansomShield logic | — (library) |
| `litric-cli` (2,261) | user CLI; daemon-first with `--local` in-process mode | `litric` |
| `litric-service` (4,320) | HTTP API on loopback, scan jobs, settings, SCM host, process gate wiring | `litricd` |
| `litric-monitor` (544) | post-write watcher → pipeline scan → quarantine | `litric-rtp` |
| `litric-pipeline` (408) | provenance-preserving aggregation of native/ClamAV/YARA results | — |
| `litric-yara` (195) | optional YARA module on `yara-x` | — |
| `sigdb` (2,433) | native signature formats + signed store | `sigtool` |
| `scanner` (1,032) | standalone signature scanner over a signed store | `litric-scan` |
| `clamav-import` (663) | offline ClamAV text-format importer | `litric-clamav-import` |
| `litric-safeos` (3,059) | isolation model, policy, governor, Sandbox config, broker, journal | — |
| `litric-agent` (476) | read-only host facts | `litric-agent` |
| `litric-guard` (272) | legacy console entry (RansomShield + vault + gate) | `litric-guard` |
| `processgate` (1,291) | suspend → scan → resume/terminate process gate | `litric-pgate-selftest` |
| `peanalysis` (796) | PE parsing/analysis facade | — |
| `quarantine` (247), `ransomshield` (275), `realtime` (409), `recovery` (185), `honeyvault` (58) | older modules kept for compatibility; the live paths use `litric-core` | — |
| `litric-wintrust` (153) | `WinVerifyTrust` wrapper | — |

36,462 lines of Rust under `crates/*/src`; 5,318 lines of integration tests. The
crate set contains duplicate older implementations (`quarantine`, `ransomshield`,
`realtime`, `recovery` vs the same logic in `litric-core`). They are not dead
code: the CLI and tests still link some of them. They are a maintenance risk, not
a security hole.

## 2. Runtime flows that actually exist

### 2.1 On-demand CLI scan (local)

```
litric --local scan <path> [--rules DIR] [--db DIR]
  -> build_engine()                 cli/src/main.rs
     -> RuleSet from .lrs files + db.payload.rules
     -> ThreatDb::load_for_runtime()   fail-closed signature policy
  -> litric_core::scan::Scanner
     -> format::detect -> pe::parse -> rules -> heuristics
     -> archive recursion (ZIP family) -> VBA/XLM -> deobfuscation
  -> Engine verdict (clean/malicious/suspicious/unknown)
  -> optional scan_quarantine::quarantine_malicious
  -> JSON/text report; exit 0/1/2/3/4
```

### 2.2 Daemon scan

```
litric ... -> litric-cli/src/client.rs -> HTTP 127.0.0.1 + bearer token
litricd serve
  -> server.rs (loopback peer check, 1 MiB body, constant-time token)
  -> api.rs -> jobs.rs (bounded job registry) -> Engine scan
  -> store.rs (settings/history, atomic write)
  -> QuarantineVault (encrypted vault under --data-dir)
```

### 2.3 Post-write monitoring

```
notify watcher -> event filter/debounce -> bounded queue
  -> litric-pipeline (native + optional providers) -> quarantine on malicious
```

No PID is attached to events, so the response is limited to the file itself.

### 2.4 Process gate

```
litricd --process-gate
  -> processgate poll (new PIDs) -> OpenProcess/suspend threads
  -> hash image -> exact malicious hit in signed DB?
       yes -> TerminateProcess
       no  -> resume
```

Starts **after** `CreateProcess`, so it is not pre-execution protection.

### 2.5 SafeOS assessment

```
litricd /safeos endpoints
  -> model (host facts from agent) -> risk -> policy -> governor
  -> sandbox::plan (wsb) / broker::plan (import/export)
```

`sandbox::launch` exists but has never run on this host (Windows 11 Home).

## 3. Trust boundaries

| # | Boundary | Enforced by | Reality |
|---|---|---|---|
| B1 | Unprivileged caller → service | bearer token file + loopback peer check + 1 MiB body cap | real; token is readable by the owner of the data dir |
| B2 | Local user → data dir / vault | SDDL `SY/BA/OW` with protected inheritance | real for the service, for `litricd serve`, and for CLI local vaults (applied before use); requires NTFS |
| B3 | Untrusted content → parser | PE/archive/VBA/XLM field checks, size/depth/ratio limits, bounded work budgets | real, test-covered |
| B4 | Database content → engine | Ed25519 detached signature, pinned-key policy, anti-rollback | **hardened in this phase**; previously the fixture key was accepted unconditionally |
| B5 | Scan result → destructive action | digest re-hash through a held handle, volume serial/file index re-check, protected paths, scope check, removal budget, audit chain | real, test-covered; ADS stream-only concurrent mutation is not separately re-hashed |
| B6 | Kernel/user | none — no kernel component | absent |
| B7 | Network | none — no filter, no gateway | absent |
| B8 | Service → Windows security config | no code path calls Defender/firewall/UAC APIs | asserted by test on the install plan |

## 4. Destructive operations inventory

Every path that can remove or replace user data, and what gates it:

| Operation | Location | Gate |
|---|---|---|
| Quarantine (move original into vault) | `litric-core/src/quarantine.rs`, `scan_quarantine.rs` | verdict must be `Malicious`; body read and digest re-hashed through one handle; ADS/timestamps captured; path identity re-checked; protected-path and scope checks; audit intent before handle-based delete. A changed source or replacement path is retained, not deleted |
| Restore | `quarantine.rs::restore` | destination must not exist; temp file + atomic no-clobber publish; body digest re-verified; ADS written and read back; timestamps applied before publish |
| Purge (permanent delete) | `quarantine.rs::purge` | explicit confirmation + policy flag + audit |
| Vault key rotation / entry rewrite | `quarantine.rs` | journaled, `.prev` retained |
| Threat DB install | `threatdb.rs::install` | signature verified first; anti-rollback; temp+fsync+rename; previous files kept as `.prev` |
| Native signature store install | `sigdb::Store` | same pattern, serial rollback refused |
| Settings/history write | `litric-service/src/store.rs` | temp+rename; corrupt file falls back to defaults |
| SafeOS broker export | `litric-safeos/src/broker.rs` | hash-bound approval, no overwrite, traversal/symlink/ADS rejection |
| Process termination | `processgate` | exact SHA-256 hit with `Malicious` kind in a **signed** DB; resume otherwise |
| Service delete | `litric-service/src/winsvc.rs` | only `LitricDefender`; stops first; no other service touched |
| Log/audit append | `safety.rs`, `winsvc.rs` | hash-chained; never truncates user data |

No code path deletes a directory tree (`remove_dir_all` appears only in tests and
in `safety.rs` cleanup of Litric's own temp area — verify before changing).

## 5. Data locations

| Data | Default | Protection |
|---|---|---|
| API token | `<data-dir>/api.token` | file created once, random 32 bytes; service mode ACL-hidden |
| Vault key | `<vault-dir>/vault.key` | 32-byte key sealed with machine-scoped DPAPI (`LKDK1` header); legacy raw keys are migrated with a `vault.key.legacy` recovery copy; file DACL `SY/BA/OW` | 
| Quarantine entries | `<vault-dir>/entries/` | encrypted body + container payload with named ADS; digest, stream names/sizes and timestamps in the authenticated header |
| Audit log | `<data-dir>/audit.log`, vault `ops.jsonl` | hash chain |
| Threat DB | `--db` directory | Ed25519 manifest |
| Settings/history | `<data-dir>/settings.json`, `history.json` | atomic write, size cap |
| Rules | `rules/*.lrs` next to exe, or `--rules` | read-only input |

## 6. Diagram (implemented components only)

```
                      +-----------------------------+
   user/CLI  -------> | litric (CLI)                |
                      |  local mode | daemon client|
                      +------+--------------+-------+
                             |              |
                 in-process  |              | HTTP 127.0.0.1 + token
                             v              v
                  +------------------+  +-------------------------+
                  | litric-core      |  | litricd                 |
                  |  engine/scan     |<-|  api/jobs/store         |
                  |  rules/heuristics|  |  quarantine vault       |
                  |  PE/archive/VBA  |  |  process gate (poll)    |
                  |  threatdb (signed)| |  SafeOS model/policy    |
                  |  safety/audit    |  +-----------+-------------+
                  +--------+---------+              |
                           ^                        | (optional) SCM
                           |                        v
                  +--------+---------+        Windows SCM service
                  | litric-pipeline  |        (run-service)
                  | native/clamav/   |
                  | yara provenance  |
                  +--------+---------+
                           ^
        +------------------+------------------+
        |                                     |
  litric-rtp (notify)                  litric-scan (sigdb)
```

Not drawn because they do not exist: kernel minifilter, AMSI provider, ETW
consumers, WFP filters, network gateway, updater, UI, installer.
