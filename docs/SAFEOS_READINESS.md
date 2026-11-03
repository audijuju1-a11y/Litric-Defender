# Litric SafeOS — production readiness (2026-11-03)

## Verdict: NOT PRODUCTION READY

SafeOS today is a **tested portable safety core** plus a **Windows Sandbox
launcher that compiles for Windows but has never run on a real host**. It is not
an installable endpoint product and must not be presented as one.

What can be used safely now:

- `litric` scanning, analysis and quarantine (existing Litric engine).
- `litric safeos status|assess` for honest capability/risk reporting.
- `litric-agent` read-only host facts on Windows.
- `litric safeos launch` on a Windows build: explicit, readiness-gated, fail-closed
  — but **unverified at runtime** and unable to start without the Sandbox feature.

## Acceptance criteria (from the master brief)

| # | Criterion | State |
|---|---|---|
| 1 | Unknown apps routed to isolation through supported launch paths | PARTIAL — only the explicit `safeos launch` path; no SafeLaunch UI/Explorer/App Control interception |
| 2 | High-risk apps cannot silently fall back to host | TESTED on reachable paths — policy never returns host for L1-L3; canary test asserts no host execution |
| 3 | Offline Windows Sandbox has networking disabled | TESTED in generated `.wsb`; UNVERIFIED in a running guest |
| 4 | Network-enabled VMs reach the Internet only via Litric Gateway | NOT IMPLEMENTED — no Hyper-V backend, no gateway |
| 5 | Gateway failure blocks guest egress | NOT IMPLEMENTED |
| 6 | IPv4/IPv6 leakage tests pass | BLOCKED — needs a running guest/gateway |
| 7 | Host user directories are not writable by guests | PARTIAL — read-only mapping and broker tests; runtime unverified |
| 8 | Source files unchanged during import/analysis | TESTED — broker import copies and verifies, source hash checked |
| 9 | Failed exports never replace source files | TESTED — temp/verify/scan/rename, approval required to overwrite |
| 10 | VM crashes preserve recoverable data | PARTIAL — journal/recovery planner only; no VHDX handling |
| 11 | Cleanup never deletes unrelated host files | TESTED — journal-scoped, idempotent cleanup; broker containment |
| 12 | Existing WSL2/Docker/NAT configuration untouched | TESTED — no mutation code; readiness detects/reports conflicts |
| 13 | No unrelated host processes are terminated | TESTED by inspection — no kill/VM-stop code exists |
| 14 | Resource limits work under constrained conditions | PARTIAL — readiness thresholds and 2-4 GB sandbox RAM sizing; no VM governor |
| 15 | UI reflects actual backend data | NOT IMPLEMENTED — no UI files exist in this repository |
| 16 | All system modifications auditable and reversible | PARTIAL — session journal; no installer/object rollback records |
| 17 | Windows restart and recovery tests pass | BLOCKED — requires a Windows 11 host |
| 18 | No known critical data-loss/isolation failure remains | UNPROVEN — cannot be established without the Windows test matrix |

Only criteria 2, 8, 9, 11, 12 and 13 have direct automated evidence on this
platform. Everything else is partial, unimplemented, or blocked.

## Missing components

| Component | State | Why |
|---|---|---|
| Hyper-V managed backend | NOT IMPLEMENTED | needs Windows + Hyper-V + admin and a running guest to test |
| Immutable base image / differencing VHDX lifecycle | NOT IMPLEMENTED | same; unsafe to write untested |
| WFP policy provider / WinNAT gateway | NOT IMPLEMENTED | needs Windows admin and leak tests |
| Guest behaviour monitoring (ETW) | NOT IMPLEMENTED | needs a running guest |
| Behaviour correlation decision engine | NOT IMPLEMENTED | depends on telemetry above |
| SafeLaunch UI / Explorer integration | NOT IMPLEMENTED | no UI project in this repository |
| Windows service / installer / uninstaller | NOT IMPLEMENTED | no packaging or SCM code |
| Resource governor | PARTIAL | thresholds and sandbox RAM only; no VM controls |
| VM/VHDX recovery | PARTIAL | journal planner only |

## What this means for a user today

- You can install nothing: there is no installer or service.
- You can scan, quarantine and classify; you can launch an explicit app into
  Windows Sandbox on Windows, but that path is unverified and does not intercept
  normal double-clicks.
- There is no protection of the host from an app you launch normally.
- Microsoft Defender remains the real-time protection on the machine.

## What would change the verdict

1. Run `docs/SAFEOS_WINDOWS_VERIFICATION.md` on a real Windows 11 host and record
   the evidence; only then can `LAUNCH_VERIFIED_ON_WINDOWS` become true.
2. Implement and test the Hyper-V backend, gateway/WFP policy and guest telemetry
   on that host, including the fault-injection matrix.
3. Build the UI, service and installer with rollback records.
4. Measure idle/VM/gateway resource use; no performance claims before that.

Until then the honest status is **NOT PRODUCTION READY**, and `safeos status`
reports `windows_sandbox_launch_verified: false` on every build.
