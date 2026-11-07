# SafeOS — verification on a real Windows 11 host

`LAUNCH_VERIFIED_ON_WINDOWS` is **false**. The launcher exists in Windows builds
and is readiness-gated, but no Windows Sandbox guest has ever been started by
this project. This document records what was actually observed on the development
host on 2026-11-07 and what must be run on a capable host before changing that
constant.

## 1. Current host result (Windows 11 Home, build 26300)

Facts collected by the real `litric-agent --print`:

```json
{
  "known": true,
  "windows_edition": "Microsoft Windows 11 Home",
  "windows_build": 26300,
  "virtualization_enabled": false,
  "hyperv_feature_present": false,
  "sandbox_feature_present": false,
  "total_ram_mb": 16233,
  "free_disk_mb": 103698,
  "logical_cpus": 8,
  "existing_nat_networks": 0,
  "nat_query_ok": false,
  "wsl_switches": 0,
  "docker_switches": 0
}
```

`VirtualizationFirmwareEnabled`, `VMMonitorModeExtensions` and
`SecondLevelAddressTranslationExtensions` are all `False` in `Win32_Processor`,
and `C:\Windows\System32\WindowsSandbox.exe` does not exist. This is a Home
edition with firmware virtualization disabled, so neither Windows Sandbox nor
Hyper-V can run here even if the feature were enabled. The agent is read-only:
it did not change firmware or Windows features.

Observed refusals (real daemon, real agent, real CLI):

| Action | Result |
|---|---|
| `litric safeos status --json` | `host_supported: false` for Windows Sandbox, Hyper-V and the gateway |
| `litric safeos launch notepad-copy.exe` | HTTP **409**: `sandbox is not ready: virtualization ... not enabled; windows_sandbox ... not installed or not enabled; network_gateway: WinNAT state could not be queried` |
| CLI exit code for that launch | **2** |
| Host execution canary | `Get-Process notepad` count **0** after the refusal — the target was never spawned |
| `litric safeos assess notepad-copy.exe` | level 1 `unknown`, action `deny`, exit **1** |
| `litric safeos assess eicar.com` | HTTP **500**: `os error 225` — Windows Defender blocks reads of the recognised EICAR file on this host, so analysis cannot open it. Litric does not treat that as clean. |

The refusal is the correct behaviour: no isolation backend, no host fallback.
It does **not** verify the launcher or the guest boundary.

## 2. Preconditions for a real launch verification

All of these are required; none may be changed silently by the agent:

- Windows 11 **Pro/Enterprise/Education** (Home has no Windows Sandbox/Hyper-V).
- `winver` build listed in `WINDOWS_11_RELEASES`.
- Firmware virtualization (VT-x/AMD-V) enabled; Task Manager → Performance → CPU
  reports "Virtualization: Enabled".
- Windows Sandbox installed (Windows Features; needs a restart and the user's
  consent).
- ≥ 4 GB RAM and ≥ 10 GB free on C: (≥ 20 GB for a managed Hyper-V VM).
- An interactive desktop session; a headless/SSH session cannot show the sandbox.
- Build on Windows: `cargo build --release`.

## 3. Start the daemon and collect facts

```powershell
.\target\release\litricd.exe serve --addr 127.0.0.1:8787 --data-dir .\litric-data --rules rules
.\target\release\litric-agent.exe --print
.\target\release\litric-agent.exe
.\target\release\litric.exe safeos status
```

Record from `status`:

- `host_facts.windows_build` matches `winver`
- `host_facts.sandbox_feature_present` = true (on a capable host)
- `backends[windows_sandbox].host_supported` = true
- `windows_sandbox_launch_verified` = **false** until step 5 passes
- `readiness.production_ready` = **false** and guest runtime `UNPROVEN`

If `host_supported` is false, read the blocker and stop. Do not work around it.

## 4. Prepare, then launch a harmless sample

Use a copy of `notepad.exe` or a tiny signed tool, never a user document:

```powershell
.\target\release\litric.exe safeos launch .\samples\sample.exe --json
```

The daemon writes a `.wsb` before spawning:

```
.\litric-data\safeos\litric-sandbox-<timestamp>.wsb
```

Inspect it yourself:

- `<Networking>Disable</Networking>`
- `<ClipboardRedirection>Disable</ClipboardRedirection>`
- `<ReadOnly>true</ReadOnly>`
- the mapped folder is the sample's own folder, never `C:\` or a user profile
- `<Command>` points at `C:\Litric\input\0\<file>`

## 5. Verify the boundary from inside the guest

1. `ping 1.1.1.1` fails ("Network cable unplugged") — networking is off.
2. Copy text in the guest and try to paste it on the host — clipboard redirection
   is off in both directions.
3. Try to create a file in `C:\Litric\input\0\` — the mapping is read-only.
4. Confirm the app started from the mapped folder (Task Manager → Details).
5. Confirm no host-side `notepad.exe` (or sample) process was created by Litric.

## 6. Refusals that must keep failing closed

| Scenario | Expected |
|---|---|
| daemon stopped | client error with start instructions, exit 2 |
| no host facts reported | HTTP 409 "sandbox is not ready" |
| `sandbox_feature_present=false` | 409 + feature blocker |
| 2 GB RAM / 5 GB free disk | 409 + memory/disk blocker |
| user-profile path (`C:\Users\...\app.exe`) | 400, never maps profiles |
| drive root `C:\` | 400, refuses to map a volume |
| filename with `\`, `/`, `:` or a reserved device name | 400 |
| directory target | 400 "must be a regular file" |
| launch when the host is Windows Home / no virtualization | 409, exit 2, target not spawned |

After every refusal, verify the host is untouched: no new Hyper-V VM, no new
WinNAT network, no changed Windows feature, no spawned target process.

## 7. Record the result

Capture `litric safeos status --json`, `litric-agent --print`, the `.wsb` file,
a guest screenshot showing no network, and the refusal outputs. Only then update
`LAUNCH_VERIFIED_ON_WINDOWS` in `crates/litric-safeos/src/sandbox.rs`, update the
STATUS row to "TESTED on hardware", and rerun the suite.

## 8. Limits even after a successful run

- Session is explicit: only apps launched through `litric safeos launch` are
  isolated. No Explorer/App Control interception exists.
- Windows Sandbox is Microsoft's boundary; a hypervisor escape is out of scope.
- No file brokering into/out of the guest exists beyond the read-only mapping.
- No WFP gateway or Hyper-V backend exists; sandbox networking is always off.
- `--wait` may return when the sandbox client exits, not when the guest is fully
  torn down; verify with Task Manager.
