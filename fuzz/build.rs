//! Links each fuzz target with the MinGW SanitizerCoverage boundary script.
//!
//! rustc emits `.SCOV$CM` / `.SCOVP$M` sections on COFF but references
//! ELF-style `__start___sancov_*` symbols that GNU ld does not synthesize.
//! The script is required for coverage-guided fuzzing on the windows-gnu
//! toolchain; it is not used by the product workspace.

use std::path::PathBuf;

fn main() {
    // This workspace supports only the windows-gnu target. The guard keeps the
    // GNU ld script off any non-GNU target if someone overrides the target, but
    // .cargo/config.toml still selects the MinGW libFuzzer runtime; there is no
    // supported MSVC build here.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("gnu") {
        return;
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("support/sancov_mingw.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg=-Wl,-T,{}", script.display());
}
