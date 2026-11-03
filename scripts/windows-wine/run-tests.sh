#!/bin/sh
# Execute the Windows-target test suite under the local Wine runner.
#
# This does not clean target/. Run `cargo clean` first when you need a
# from-scratch result; the reproduction doc records that procedure.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ROOT=${LITRIC_WINE_ROOT:-${XDG_CACHE_HOME:-"$HOME/.cache"}/litric-wine}
TARGET=x86_64-pc-windows-gnu

[ -x "$ROOT/run-wine.sh" ] || {
    echo "Wine runner missing: run scripts/windows-wine/setup.sh first" >&2
    exit 1
}

cd "$REPO_ROOT"
export PATH="$HOME/.cargo/bin:$ROOT/bin:$ROOT/mingw/usr/bin:$PATH"
export LD_LIBRARY_PATH="$ROOT/i386/usr/lib/i386-linux-gnu:$ROOT/i386/usr/lib:$ROOT/mingw/usr/lib/x86_64-linux-gnu:$ROOT/mingw/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$ROOT/bin/x86_64-w64-mingw32-gcc"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER="$ROOT/run-wine.sh"

cargo test --workspace --all-targets --target "$TARGET" --no-run

WINPTHREAD="$ROOT/mingw/usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll"
LIBGCC=$(find "$ROOT/mingw/usr/lib/gcc/x86_64-w64-mingw32" -name 'libgcc_s_seh-1.dll' -print -quit)
[ -f "$WINPTHREAD" ] && [ -n "$LIBGCC" ] || {
    echo "MinGW runtime DLLs were not found under $ROOT/mingw" >&2
    exit 1
}

for dir in \
    "target/$TARGET/debug" \
    "target/$TARGET/debug/deps"
do
    mkdir -p "$dir"
    cp "$WINPTHREAD" "$dir/"
    cp "$LIBGCC" "$dir/"
done

cargo test --workspace --all-targets --target "$TARGET" \
    --no-fail-fast -- --test-threads=1
