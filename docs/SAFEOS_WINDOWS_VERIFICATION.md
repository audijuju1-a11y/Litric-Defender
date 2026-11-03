# SafeOS — manual verification on a real Windows 11 host

`LAUNCH_VERIFIED_ON_WINDOWS` is **false** today. The launcher exists in Windows
builds, but it has never been executed on a real host by the person who wrote it.
Run every step below before changing that constant or describing SafeOS as
"working on Windows".

## 0. Preconditions (read-only checks)

- Windows 11 Pro/Enterprise, build **≥ 22000** (`winver`).
- Virtualization enabled in firmware (Task Manager → Performance → CPU →
  "Virtualization: Enabled").
- Windows Sandbox installed (Windows Features → "Windows Sandbox"; enabling it
  needs a restart and is **your** decision — the agent never enables it).
- ≥ 4 GB RAM and ≥ 10 GB free on C: for a sandbox session (≥ 20 GB for a managed Hyper-V VM).
- An interactive desktop session. Windows Sandbox is a desktop app; a headless
  service or SSH session will not show it.
- Build the binaries on Windows:

```powershell
cargo build --release
```

The Linux build only proves the code compiles; it cannot spawn `WindowsSandbox.exe`.

## 1. Start the daemon and collect facts

```powershell
.\target\release\litricd.exe serve --addr 127.0.0.1:8787 --data-dir .\litric-data --rules rules
.\target\release\litric-agent.exe --print
.\target\release\litric-agent.exe
.\target\release\litric.exe safeos status
```

Record, from `status`:

- `host_facts_known` = true
- `host_facts.windows_build` matches `winver`
- `host_facts.sandbox_feature_present` = true
- `backends[windows_sandbox].host_supported` = true
- `windows_sandbox_launch_implemented` = true (Windows build)
- `windows_sandbox_launch_verified` = **false** until step 5

If `host_supported` is false, read the blocker; do not work around it.

## 2. Prepare without executing

Use a harmless sample first (copy of `notepad.exe` or a tiny signed tool):

```powershell
.\target\release\litric.exe safeos launch .\samples\sample.exe --json
```

Expected on a ready host: a sandbox window opens. If you only want to inspect the
plan first, the daemon has already written:

```
.\litric-data\safeos\litric-sandbox-<timestamp>.wsb
```

Check the file yourself:

- `<Networking>Disable</Networking>`
- `<ClipboardRedirection>Disable</ClipboardRedirection>`
- `<ReadOnly>true</ReadOnly>`
- the mapped folder is the sample's own folder, never `C:\` or a user profile
- `<Command>` points at `C:\Litric\input\0\<file>`

## 3. Verify the boundary from inside the guest

Inside the sandbox window:

1. `ping 1.1.1.1` fails / "Network cable unplugged" — networking is off.
2. Copy text in Notepad and try to paste it on the host — clipboard redirection is
   off in both directions.
3. Try to create a file in `C:\Litric\input\0\` — the mapping is read-only.
4. Confirm the app started from the mapped folder (Task Manager → Details).

## 4. Verify refusals (these must fail, not fall back)

| Scenario | Expected |
|---|---|
| `litric safeos launch` with daemon stopped | client error with start instructions, exit 2 |
| `launch` before `litric-agent` has reported | HTTP 409 "sandbox is not ready" |
| facts with `sandbox_feature_present=false` | 409 + feature blocker |
| facts with 2 GB RAM / 5 GB free disk | 409 + memory/disk blocker |
| app inside a user profile (e.g. `C:\Users\you\app.exe`) | 400 invalid launch request (never maps profiles) |
| launch on a Linux build | HTTP 501 "requires a Windows build" |
| filename containing `\`, `/`, `:` or a reserved device name | 400 path/name refusal |
| `launch` a directory | 400 "must be a regular file" |

Also confirm the host is untouched after refusals: no new Hyper-V VM, no new
WinNAT network (`Get-NetNat`), no Windows feature changed.

## 4a. What was demonstrated on the non-Windows verification host (2026-11-03)

These are real captures from the `litric` binary against a real `litricd`, with
facts posted exactly as `litric-agent` posts them. Every refusal exited **2**.

| Case | HTTP | Daemon message |
|---|---|---|
| No facts reported | 409 | `platform_agent: no host facts have been reported by litric-agent` |
| Build 21999 | 409 | `windows_build: Windows build 21999 is older than the supported minimum 22000` |
| Virtualization off | 409 | `virtualization: hardware virtualization (VT-x/AMD-V) is not enabled` |
| Sandbox feature absent | 409 | `windows_sandbox: Windows Sandbox feature is not installed or not enabled` |
| RAM 2048 MB | 409 | `memory: 2048 MB installed is below the 4096 MB minimum for isolation` |
| Free disk 5120 MB | 409 | `disk: 5120 MB free is below the 10240 MB needed for a Windows Sandbox session` |
| Facts fixed on the same daemon | 501 | `Windows Sandbox launch requires a Windows build` (readiness re-evaluated, no cache) |
| Drive root `C:\` | 400 | `refusing to map an entire volume into the sandbox` |
| User profile `C:\Users\alice\app.exe` | 400 | `refusing to map a user profile into the sandbox` |
| Directory target | 400 | `path must be a regular file; directories are not supported` |
| Missing target | 400 | `cannot access ...: No such file or directory` |
| Filename `evil\..\..\Windows\cmd.exe` | 400 | `file name contains characters Windows treats as a path separator...` |
| Valid app (this Linux build) | 501 | `Windows Sandbox launch requires a Windows build` |
| Valid app with `--wait --json` | 501 | same message; `wait=true` reached the daemon |

The valid request wrote a `.wsb` before the platform gate, containing
`<Networking>Disable</Networking>`, clipboard/audio/video/printer/vGPU disabled,
`<ReadOnly>true</ReadOnly>`, `<SandboxFolder>C:\Litric\input\0</SandboxFolder>`, and
`<Command>"C:\Litric\input\0\sample.exe"</Command>`.

`safeos status --json` on this build reported
`windows_sandbox_launch_implemented=false`, `windows_sandbox_launch_verified=false`,
and `host_supported=true` / `available=false` for the sandbox backend.

Drive root and user profile are rejected from the **raw path before access**, so
the rule is testable here without those paths existing. The guest filename rule
is what keeps a hostile filename from walking out of the read-only mapping.

### Host-execution canary

`crates/litric-cli/tests/safeos_launch_verify.rs`
(`no_launch_path_executes_the_host_application`) proves both directions in one
test:

1. **Positive control:** it runs a `#!/bin/sh` canary that appends to a marker,
   asserts the marker appears, then deletes it.
2. **Absence:** it drives the real `litric` → `litricd` path for no facts (409),
   a user-profile path (400), and a valid app with no flags, `--wait`, `--json`
   and `--wait --json` (501 on this build). After each case it asserts the marker
   is absent and the canary still exists. The valid requests still write the
   `.wsb` (4 configs).

Captured with `cargo test -p litric-cli --test safeos_launch_verify
no_launch_path_executes_the_host_application -- --nocapture` (temporary directory
trimmed):

```text
control: marker after direct execution = present
control: marker removed; launch cases follow
launch no-facts: exit=Some(2) | ... (HTTP 409): sandbox is not ready: platform_agent: ...
readiness refusal: marker=absent canary=present
launch profile-path: exit=Some(2) | ... (HTTP 400): ... refusing to map a user profile ...
path refusal: marker=absent canary=present
launch [valid]: exit=Some(2) | ... (HTTP 501): Windows Sandbox launch requires a Windows build...
valid launch: marker=absent canary=present
launch [valid, --wait]: exit=Some(2) | ... (HTTP 501) ...
valid launch: marker=absent canary=present
launch [valid, --json]: exit=Some(2) | ... (HTTP 501) ...
valid launch: marker=absent canary=present
launch [valid, --wait, --json]: exit=Some(2) | ... (HTTP 501) ...
valid launch: marker=absent canary=present
prepared configs: 4
```

Spawn audit of the launcher path: `litric-safeos` has exactly one process
creation, `Command::new(SystemRoot\System32\WindowsSandbox.exe).arg(config_path)`
inside `#[cfg(windows)]`; `litric-service` and `litric-cli` have none. The agent's
`powershell.exe` collects facts and is not on this path. No fallback executes the
target on the host, so there was no red test to remove.

Writing the `.wsb` before the platform gate is preparation, not execution: it
touches the config directory only, never the target. This test runs on Linux; the
Windows spawn remains unverified.

What this does **not** prove: that `WindowsSandbox.exe` starts, that the guest
actually shows no network, or that the mapped folder is read-only to the guest.
Only the real-host steps above can prove those, which is why
`LAUNCH_VERIFIED_ON_WINDOWS` remains `false`.

## 5. Record the result

Capture (redact usernames if you publish them):

- `litric safeos status --json` and `litric-agent --print`
- the `.wsb` file
- the sandbox screenshot showing no network and the app running
- the refusal outputs above

Then update `LAUNCH_VERIFIED_ON_WINDOWS` to `true` in
`crates/litric-safeos/src/sandbox.rs`, update the STATUS row from
"IMPLEMENTED, UNVERIFIED" to "TESTED on hardware", and rerun `cargo test`.

## Known limits even after this passes

- Session is **explicit**: only apps launched through `litric safeos launch` are
  isolated. There is no App Control / shell interception yet.
- Windows Sandbox is Microsoft's boundary; a hypervisor escape is out of scope.
- The launcher does not broker files into the guest beyond a read-only mapping,
  and does not export anything back automatically.
- No WFP gateway or Hyper-V backend exists; sandbox networking is always disabled.
- Waiting (`--wait`) may return when the sandbox client exits, not when the guest
  is fully torn down; verify with Task Manager.
