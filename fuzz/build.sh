#!/usr/bin/env bash
# Build all coverage-guided fuzz targets on a Windows GNU host.
#
# The fuzz workspace is pinned to nightly-x86_64-pc-windows-gnu by
# rust-toolchain.toml and uses fuzz/.cargo/config.toml to select the locally
# built MinGW libFuzzer runtime. `rust-toolchain.toml` is not inherited when a
# caller explicitly selects another toolchain, which is why this script can be
# pointed at one with LITRIC_FUZZ_TOOLCHAIN.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$here"
export PATH="$HOME/.cargo/bin:$PATH"

if ! cargo fuzz --version >/dev/null 2>&1; then
    echo "cargo-fuzz is required: cargo install cargo-fuzz --version 0.13.2 --locked" >&2
    exit 1
fi

echo "== building MinGW libFuzzer runtime =="
bash "$here/build_libfuzzer_mingw.sh"

if [ -n "${LITRIC_FUZZ_TOOLCHAIN:-}" ]; then
    cargo_cmd=(cargo "+$LITRIC_FUZZ_TOOLCHAIN")
else
    cargo_cmd=(cargo)
fi

for target in pe zip vba xlm; do
    echo "== building fuzz_$target =="
    "${cargo_cmd[@]}" fuzz build "fuzz_$target" --sanitizer none
done

echo "built: $here/target/x86_64-pc-windows-gnu/release/fuzz_{pe,zip,vba,xlm}.exe"
