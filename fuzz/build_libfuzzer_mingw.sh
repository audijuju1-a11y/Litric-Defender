#!/usr/bin/env bash
# Build libFuzzer's C++ runtime with MinGW so `cargo fuzz` can use it on a
# Windows host that has GCC but no Visual Studio / Windows SDK.
#
# The upstream libfuzzer-sys runtime is MSVC/clang-only. The only source file
# that needs a MinGW replacement is FuzzerExtFunctionsWindows.cpp; see
# fuzz/support/ for the reason and the replacement.
#
# Usage:
#   fuzz/build_libfuzzer_mingw.sh
# Prints the archive path. Then:
#   CUSTOM_LIBFUZZER_PATH=<path> CUSTOM_LIBFUZZER_STD_CXX=stdc++ \
#     cargo +nightly-x86_64-pc-windows-gnu fuzz build fuzz_pe --sanitizer none
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out="$here/target/libfuzzer-mingw"

for tool in cargo python g++ ar; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 1
    fi
done

# A clean CARGO_HOME has no libfuzzer-sys source tree. Fetch first, then use
# offline metadata so the path lookup cannot silently resolve a different
# registry state. This is the clean-checkout/CI path, not just a warm local one.
cargo fetch --manifest-path "$here/Cargo.toml" --locked
meta=$(cargo metadata --manifest-path "$here/Cargo.toml" --format-version 1 --offline)
libfuzzer_src=$(printf '%s' "$meta" | python -c '
import json, os, sys
meta = json.load(sys.stdin)
for pkg in meta["packages"]:
    if pkg["name"] == "libfuzzer-sys":
        print(os.path.join(os.path.dirname(pkg["manifest_path"]), "libfuzzer"))
        break
else:
    raise SystemExit("libfuzzer-sys not found in cargo metadata")
')
if [ ! -d "$libfuzzer_src" ]; then
    echo "libfuzzer source not found: $libfuzzer_src" >&2
    exit 1
fi

rm -rf "$out"
mkdir -p "$out/obj"

# Match libfuzzer-sys's cc settings closely enough that the runtime has the same
# ABI and frame-pointer behavior as a normal cargo-fuzz build.
cxxflags=(
    -O3 -g -gdwarf-2 -m64 -std=c++17 -w
    -ffunction-sections -fdata-sections
    -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
    -I "$libfuzzer_src"
)

for cpp in "$libfuzzer_src"/*.cpp; do
    base=$(basename "$cpp")
    src="$cpp"
    case "$base" in
        FuzzerExtFunctionsWindows.cpp|FuzzerExtraCountersWindows.cpp)
            src="$here/support/$base"
            ;;
    esac
    g++ "${cxxflags[@]}" -c "$src" -o "$out/obj/${base%.cpp}.o"
done

ar rcs "$out/libfuzzer.a" "$out"/obj/*.o
printf '%s\n' "$out/libfuzzer.a"
