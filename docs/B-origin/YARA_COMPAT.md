# YARA compatibility matrix

**State: NOT IMPLEMENTED. No YARA rule is parsed or matched today. Nothing here claims YARA compatibility.**

| Capability | State |
|---|---|
| `.yar` / `.yara` loading | NOT IMPLEMENTED |
| string / hex / regex patterns | NOT IMPLEMENTED |
| boolean conditions, modules (`pe`, `hash`, ...) | NOT IMPLEMENTED |
| rule metadata -> classification | NOT IMPLEMENTED |
| CPU / memory / timeout limits | NOT IMPLEMENTED |
| results kept separate from native results | design only |

Engine decision still open (needs your input):
1. **libyara via C binding.** Most faithful language support; needs a C toolchain on the build machine and must run behind
   strict time/memory limits. The authoring environment (Rust 1.75, no Windows toolchain) could not verify a build.
2. **yara-x (Rust).** Pure Rust but likely needs a newer Rust than this environment has; unverified here.
3. **Own subset matcher.** Only with an explicit, documented syntax subset; never to be called "YARA compatible"
   until it passes a compatibility suite.

The YARA project's own license and the licenses of every rule source must be audited before use.
