# Litric SafeOS — architecture (as built)

Status vocabulary: `IMPLEMENTED`, `TESTED`, `PARTIAL`, `PLANNED`, `BLOCKED`,
`UNSUPPORTED`. See `docs/SAFEOS_COMPATIBILITY.md` for the per-component matrix.

## 1. What SafeOS is, and what this build contains

SafeOS is the application-isolation half of Litric Defender: an unverified
application should not run directly on the user's Windows host, and the decision
to isolate must be deterministic, explainable and fail closed.

This repository contains the **safety core** and its API integration:

```
crates/litric-safeos/
  model.rs     host facts, readiness, backend availability
  risk.rs      Level 0-3 classification with evidence
  policy.rs    fail-closed action selection
  broker.rs    staged import/export with hash verification
  journal.rs   session journal, crash detection, cleanup planner
  sandbox.rs   Windows Sandbox .wsb generation (not execution)
```

Windows-only execution (Hyper-V, Windows Sandbox launch, WFP, WinNAT) is **not
implemented here**. The Windows Sandbox launcher is compiled and unit/API tested,
but no guest has been started. Hyper-V and network enforcement report themselves
unavailable rather than being simulated.

## 2. Component ownership

| Component | Owner | State |
|---|---|---|
| Risk classification (L0-L3) | Litric | TESTED |
| Fail-closed policy | Litric | TESTED |
| Secure file broker (import/export) | Litric | TESTED |
| Session journal + recovery planner | Litric | TESTED |
| Windows Sandbox configuration generation | Litric | TESTED |
| Windows Sandbox launch | Litric | IMPLEMENTED (Windows only), UNVERIFIED on a real host |
| Hyper-V VM backend | Litric (planned) | BLOCKED — needs Windows + Hyper-V |
| Network gateway / WFP / WinNAT | Litric (planned) | BLOCKED — needs Windows + admin |
| Guest behaviour monitoring | Litric (planned) | BLOCKED — needs Windows ETW |
| UI | Litric (planned) | PLANNED — no UI exists |

No third-party isolation engine is wrapped. Microsoft's Hyper-V and Windows
Sandbox are platform facilities, not a scanner being renamed.

## 3. Decision flow (implemented)

```
file path
   |
   v
Scanner::analyze_file           (existing Litric engine)
   |
   v
ApplicationFacts                verdict, score, signature presence, hash trust
   |
   v
risk::assess                    Level 0 trusted / 1 unknown / 2 suspicious / 3 malicious
   |                            + evidence list + confidence
   v
policy::decide(level, backends) fail-closed action
   |
   +--> trusted ............ run_on_host
   +--> unknown ............ run_in_windows_sandbox  (when available)
   |                         run_in_vm_offline        (when Hyper-V only)
   |                         deny                     (no backend — this build)
   +--> suspicious ......... run_in_vm_with_gateway / run_in_vm_offline
   |                         deny                     (no Hyper-V — this build)
   +--> malicious .......... block_and_quarantine
```

`policy` has no branch that maps a non-trusted level to `run_on_host`. This is
asserted by a test over all non-trusted levels.

## 4. Trust boundaries

1. **Host filesystem** — the broker never exposes a source path to a guest. It
   copies into a staging directory, verifies SHA-256, and exports only from that
   staging tree (`Broker::owns`).
2. **Existing destination files** — never replaced without `approve_overwrite`;
   export writes a temp file, syncs, re-hashes, runs the scan gate, then renames.
3. **Guest network** — designed to be an internal switch behind a gateway; not
   implemented in this build. When the gateway is absent, policy uses an offline
   VM or denies, never an external/default switch.
4. **Risk evidence** — an unsigned binary is evidence of *unknown*, never of
   malice. A signature that has not had its chain validated never grants trust.

## 5. API surface

| Route | Method | Behaviour |
|---|---|---|
| `/api/v1/safeos/status` | GET | backends, blockers, launch-implemented flags; all `false` on this build |
| `/api/v1/safeos/assess` | POST | runs the engine, returns level, evidence, action, reasons, remediation |

Both require the bearer token and are loopback-only, like the rest of the API.

## 6. What would be needed for the Windows half

* Windows 11 Pro host with virtualization enabled.
* Hyper-V and/or Windows Sandbox optional features (user-approved, restart).
* WFP policy code and WinNAT compatibility handling; WinNAT chaos must be avoided
  (only one NAT network is supported by Windows).
* Guest image, licensing and integrity verification.
* ETW-based guest telemetry and correlation with host vNIC events.

None of these can be produced or validated in this environment. Claiming them
would be fabrication.
