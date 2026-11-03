# Litric SafeOS — known limitations

> **Production readiness: NOT READY.** See `docs/SAFEOS_READINESS.md`.

Read this before trusting any SafeOS claim elsewhere.

## 1. SafeOS does not isolate anything yet

There is no Hyper-V backend, network gateway or host driver. A Windows Sandbox
launcher exists in Windows builds, but it has **never been run on a real host**
and Linux builds refuse it with 501. `litric safeos assess` still returns `deny`
for every unverified application because policy uses an empty backend set;
launching is an explicit, separate command, not automatic enforcement.

## 2. The Windows half is BLOCKED, by environment

This work was produced on Linux with no Windows host, no Hyper-V, no WFP and no
WDK. Consequently:

* no Hyper-V provisioning, differencing VHDX lifecycle or checkpoint logic,
* no verified Windows Sandbox launch: the code exists for Windows builds and
  compiles, but no real session has been started, so it is UNVERIFIED,
* no WFP provider/sublayer/filters, no WinNAT integration,
* no ETW guest telemetry or behaviour correlation,
* no Windows UI, installer or service registration.

Writing those without the ability to run them would produce exactly the kind of
unverified security code this project refuses to ship.

## 3. Trust decisions are deliberately conservative

* A signature blob that has not had its chain validated never grants trust.
* Unsigned is not malicious, but it is also not trusted: unsigned applications
  land at Level 1 and require isolation.
* Unknown is the common verdict. `assess` on an ordinary text file returns
  Level 1 / `deny` here, which is correct behaviour for an unverified app with no
  isolation available — not a bug.

## 4. Broker guarantees and non-guarantees

Guaranteed and tested: staging copies, hash verification, refusal to overwrite
without approval, scan-gated export, rejection of symlinks/traversal/ADS names,
cleanup limited to journal-owned directories.

Not guaranteed: atomic replace on Windows (rename cannot replace, so the code
removes then renames, leaving a small window), disk-full behaviour beyond temp
cleanup, NTFS alternate data streams *inside* exported content (the name check is
not a content check), and resistance to an attacker with write access to the
staging root.

## 5. No performance claims

No VM startup, RAM overhead, gateway latency or scan throughput was measured for
SafeOS because no VM or gateway exists here. Any number in a design document that
is not in `docs/STATUS.md` with a measurement note is not a measurement.

## 6. Resource governor is modelled, not enforced

RAM/disk thresholds influence readiness (4 GB RAM, 10/20 GB free disk), but the
runtime governor that enforces concurrency, CPU limits and disk I/O has no
backend to control. It is not implemented.

## 7. Recovery is a planner, not a hypervisor operation

The journal detects sessions that never finished and plans cleanup, but it cannot
inspect VHDX chains, reopen disks read-only or recover guest files. Those need
Hyper-V and are BLOCKED.
