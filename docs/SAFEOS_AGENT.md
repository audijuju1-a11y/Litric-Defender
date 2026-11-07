# Litric SafeOS platform agent (`litric-agent`)

State: **TESTED offline** (parser, validation, daemon ingest, end-to-end over
HTTP, dry-run). The Windows collector itself has been **compile-checked for
Windows only where a Windows target is installed**; it has not been executed on
a real Windows host in this environment. Do not describe it as "verified on
Windows".

## What it does

Collects host facts with read-only queries and POSTs them to the local daemon:

```
POST /api/v1/safeos/host-facts
```

It never enables a Windows feature, creates or deletes a network, changes a
service, starts a VM or writes outside its own process. A test asserts the
PowerShell script contains none of `Remove-`, `Set-NetNat`, `New-NetNat`,
`Disable-`, `Enable-`, `Start-Process`, `Stop-Service`, `Restart-`, `Set-Service`,
`New-VM`, `Remove-VM`.

## Usage

```powershell
# report to the daemon (default 127.0.0.1:8787)
litric-agent

# inspect without sending
litric-agent --print

# show exactly what would run, execute nothing
litric-agent --dry-run

# use a captured report (tests, air-gapped review)
litric-agent --fixture facts.json --addr 127.0.0.1:8787 --token-file .\litric-data\api.token
```

Exit codes: 0 reported, 1 daemon rejected the report, 2 client/probe error.

## Facts and failure behaviour

| Field | Source | If missing/failed |
|---|---|---|
| `windows_edition`, `windows_build` | `Win32_OperatingSystem` | report rejected (400) |
| `virtualization_enabled` | `Win32_Processor` firmware + SLAT flags | false → isolation unusable |
| `hyperv_feature_present` | optional feature, else `vmms` + hypervisor present | false |
| `sandbox_feature_present` | `WindowsSandbox.exe`, else optional feature | false |
| `total_ram_mb`, `free_disk_mb` | `Win32_ComputerSystem`, `Win32_LogicalDisk C:` | 0 → blockers |
| `logical_cpus` | `NUMBER_OF_PROCESSORS` | 0 → resource governor refuses (vCPU limits cannot be planned) |
| `existing_nat_networks` | `Get-NetNat` | query failure sets `nat_query_ok=false` |
| `nat_query_ok` | collector | **false blocks the gateway**; failure is never "zero NATs" |
| `wsl_switches`, `docker_switches` | adapter names/descriptions | 0, informational |

The collector needs **no elevation** for OS/CPU/RAM/disk/adapter queries.
`Get-NetNat` and `Get-WindowsOptionalFeature -Online` normally require elevation;
without it the agent reports `nat_query_ok=false` and feature presence falls back
to file/service checks. That is deliberate: unreadable state fails closed.

## What ingesting facts changes — and what it does not

`GET /api/v1/safeos/status` now separates:

* `host_supported` — the Windows host could run this backend (feature present,
  build new enough, enough RAM/disk, NAT state readable and compatible).
* `available` — **this build of Litric can actually launch it**. It stays `false`
  for sandbox/Hyper-V/gateway because no launcher exists yet, and the reason says
  so.

`POST /api/v1/safeos/assess` still uses an empty backend set, so an unverified
application is still denied. Reporting facts does not silently grant isolation.

## Why the launcher is still UNVERIFIED

Launching Windows Sandbox, Hyper-V, a WFP provider and a WinNAT-compatible
gateway requires virtualization, admin rights and a running guest. A Windows
Sandbox launcher exists, but no guest has been started, and the Hyper-V/WFP/WDK
components are not written. They are reported as UNVERIFIED or NOT IMPLEMENTED,
never as working.
