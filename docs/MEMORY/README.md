# Project memory for future agents

Purpose: work on one area without reading the whole repository. Each file states
what exists, where it lives, how to test it, and what is deliberately absent.

Read in this order:

1. `build.md` — toolchain, commands, test counts, release build.
2. `core.md` — detection engine, scanner, quarantine, RansomShield.
3. `service.md` — `litricd` API, auth, jobs, persistence.
4. `cli.md` — `litric` client, flags, exit codes, error messages.
5. `safeos.md` — isolation policy, broker, journal, sandbox config, blockers.
6. `rules.md` — `.lrs` rule language and how to add a rule.

Rules of engagement for any future change:

* Never claim a state in `docs/STATUS.md` without code and a test.
* Never add a mock backend and call it implemented.
* Never make the CLI fall back to in-process scanning silently.
* Never disable Microsoft Defender, Secure Boot or driver-signing checks.
* Keep `git status` clean and commit with the attribution footer.

Current verification baseline (re-measure, do not trust blindly):

```
cargo test            # all crates
cargo build --release # must be warning-free
```
