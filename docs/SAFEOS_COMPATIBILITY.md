# Litric SafeOS — compatibility and capability matrix

This file is the authoritative list of what SafeOS can and cannot do. It is
deliberately blunt: `BLOCKED` means the environment cannot produce or verify the
component, not that it is scheduled.

## 1. Backends

| Backend | State | Evidence / blocker |
|---|---|---|
| Risk classification L0-L3 | TESTED | `litric-safeos/src/risk.rs`, 6 tests |
| Fail-closed policy | TESTED | `policy.rs`, 6 tests, "never host" assertion |
| Secure file broker | TESTED | `broker.rs`, 9 tests incl. symlink, ADS, traversal, overwrite |
| Session journal + recovery | TESTED | `journal.rs`, 5 tests incl. crash recovery and idempotent cleanup |
| Windows Sandbox `.wsb` generation | TESTED | `sandbox.rs`, 6 tests: networking off, redirection off, read-only maps |
| Windows platform agent (read-only facts) | PARTIAL | collector + ingest TESTED offline with fixtures and a real daemon; not executed on a real Windows host in this environment |
| Windows Sandbox launch | PARTIAL — IMPLEMENTED, UNVERIFIED | readiness gate + `.wsb` + spawn compiled only for Windows; refused with 501 elsewhere. Not yet run on a real Windows host |
| Hyper-V managed VM | BLOCKED | requires Windows 11 + Hyper-V + admin; no implementation |
| Local network gateway | BLOCKED | requires WFP + WinNAT on Windows; no implementation |
| WFP policy provider | BLOCKED | no Windows host, no way to test filter isolation |
| Guest behaviour monitoring | BLOCKED | needs ETW inside a running guest |
| SafeLaunch shell integration | PLANNED | no Windows shell or UI in this repo |
| Installer / uninstaller | PLANNED | no Windows packaging here |

## 2. Host requirements (from the brief) vs. what is checked here

| Requirement | Checked? |
|---|---|
| Windows 11 Pro x64 | No — no Windows host; `HostFacts` accepts agent-reported facts |
| VT-x / EPT | Modelled in `Readiness`, not probed |
| RAM installed | Modelled, not probed (`/proc/meminfo` would be meaningless for Windows) |
| SSD/HDD and free space | Modelled from reported facts |
| Hyper-V / Sandbox availability | Modelled; this build reports unavailable |
| Existing WinNAT networks | Modelled (`existing_nat_networks`); one NAT blocks the gateway |
| WSL2 / Docker switches | Modelled as facts; no mutation performed |
| Defender / Update state | Not collected in this build |

## 3. Network rules

| Rule | State |
|---|---|
| Sandbox networking disabled in generated config | TESTED |
| Gateway failure means offline VM or deny | TESTED (policy) |
| Direct host/default/external switch fallback | Not implemented at all — no code path |
| IPv4/IPv6 leak tests | BLOCKED (no hypervisor, no gateway) |
| DNS policy / DoH control | PLANNED |

## 4. Data safety

| Rule | State |
|---|---|
| Import copies and verifies, source unchanged | TESTED |
| Export refuses to overwrite without approval | TESTED |
| Export verifies temp file hash before commit | TESTED |
| Scan gate rejection preserves staging and destination | TESTED |
| Symlink / traversal / ADS rejection | TESTED |
| Cleanup only touches journal-owned session dirs, idempotent | TESTED |
| Crash leaves session in `RecoveryPending`, storage preserved | TESTED (journal) |
| Disk-full during export | PARTIAL — temp file is removed on error; no fault injection |

## 5. Windows platform gates

These are procurement/certification or hardware gates, not code:

* Hyper-V and Windows Sandbox features require user approval and a restart.
* A kernel driver (WFP callout, minifilter) requires Microsoft signing; not
  attempted, and SafeOS explicitly avoids a custom kernel callout in release one.
* Windows Security Center registration requires Microsoft Virus Initiative
  membership.
* Guest Windows licensing must be respected; no activation bypass is provided.
