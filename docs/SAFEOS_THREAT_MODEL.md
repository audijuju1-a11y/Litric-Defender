# Litric SafeOS — threat model

## 1. Assets

1. Host user data outside the isolation boundary.
2. Host integrity: Windows services, firewall, network configuration, boot.
3. Guest session data that may need recovery after a crash.
4. Evidence: verdicts, reasons, journals and exported files.
5. Availability: the machine must stay usable; one heavy VM maximum.

## 2. Adversaries

| Adversary | Capability | Primary mitigations |
|---|---|---|
| Untrusted application | Arbitrary code inside guest | VM/sandbox boundary; no host shares; gateway policy |
| Malicious file chosen by user | Crafted parser input | bounds-checked parsers, size caps, no `unsafe` |
| Network attacker | Inbound/outbound traffic | gateway default-deny, no inbound, no LAN access |
| Local unprivileged user | Read staging/journal | staging under service-owned root; ACL hardening still PLANNED |
| Malware disabling guest telemetry | Tamper guest monitoring | host-side vNIC/VM events correlated; telemetry gaps reported |
| Operator error | Wrong cleanup/overwrite | journal-scoped cleanup; overwrite requires approval |
| Supply chain | Tampered rules/database | Ed25519-signed database, anti-rollback (existing engine) |

## 3. Threats and current handling

| Threat | Handling | State |
|---|---|---|
| Malware executes on host because isolation is missing | `deny` for any non-trusted level | TESTED |
| Data exfiltration from host shares | broker only; no host folder mapping | TESTED (broker), BLOCKED (VM) |
| Overwriting user files on export | explicit approval + temp/verify/rename | TESTED |
| Path traversal / ADS smuggling | name validation + staging containment | TESTED |
| Symlink attack on import/export | `symlink_metadata` refusal | TESTED |
| Crash during session | journal marks `preparing`/`running` as recovery | TESTED |
| Cleanup deletes unrelated files | cleanup limited to `<root>/<id>/{input,output,vm}` | TESTED |
| Gateway down → guest gets direct internet | policy: offline VM or deny; no fallback path exists | TESTED (policy) |
| WinNAT conflict damages user networking | readiness blocks gateway when any NAT exists | TESTED |
| Sandbox config exposes clipboard/network | generated `.wsb` disables all redirection and networking | TESTED |
| Guest escapes VM | platform boundary; not verifiable here | BLOCKED |

## 4. Residual risks (explicit)

* No VM exists, so no isolation is actually enforced today.
* A user who runs an application outside SafeLaunch is not intercepted; there is
  no system-wide App Control policy in this build.
* Host-side ACLs for the staging root are not implemented; rely on service
  account permissions when the service exists.
* Native signing-chain validation is unproven. The portable path caps trust at
  Level 1; on Windows, `safeos_assess` may reach `Trusted` only after
  `WinVerifyTrust` accepts the chain, and that execution has not been tested here.
* Guest telemetry, even when built, can be tampered with by malware; host-side
  correlation reduces but does not eliminate blind spots.

## 5. Non-goals

* Preventing 100% of malware. The goal is a bounded blast radius with auditable
  decisions.
* Bypassing Windows security features, activation or driver signing.
* Cloud dependency for enforcement. Decisions are local and deterministic.
* AI-driven blocking. AI may explain; it never decides.
