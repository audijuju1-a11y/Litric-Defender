#!/bin/sh
# Build a local MinGW-w64 + Wine 11.21 toolchain without root.
#
# Tested on Ubuntu 24.04 x86_64. Override the destination with
# LITRIC_WINE_ROOT; the default is a persistent user cache, not /tmp.
set -eu

ROOT=${LITRIC_WINE_ROOT:-${XDG_CACHE_HOME:-"$HOME/.cache"}/litric-wine}
SUITE=${LITRIC_UBUNTU_SUITE:-noble}
DL="$ROOT/downloads"
APT="$ROOT/apt"
MINGW="$ROOT/mingw"
I386="$ROOT/i386"
HOST="$ROOT/host"
WINE="$ROOT/wine"
BIN="$ROOT/bin"
PREFIX="$ROOT/prefix"
WINE_URL="https://github.com/Kron4ek/Wine-Builds/releases/download/11.21/wine-11.21-amd64.tar.xz"
WINE_SHA256="1f12f2aef4f5d0b5c0548ceecdb20068edc59fcd23a5da481e7059a25070eac9"

for tool in apt-get dpkg-deb curl sha256sum tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required host tool: $tool" >&2
        exit 1
    }
done

mkdir -p "$DL" "$APT/lists/partial" "$APT/archives/partial" \
    "$MINGW" "$I386" "$HOST" "$BIN" "$PREFIX"

# Keep apt's state and package downloads inside the user-owned tool root.
cat >"$APT/sources.list" <<EOF
deb http://archive.ubuntu.com/ubuntu $SUITE main universe
deb http://archive.ubuntu.com/ubuntu $SUITE-updates main universe
deb http://security.ubuntu.com/ubuntu $SUITE-security main universe
EOF

apt_get() {
    apt-get \
        -o "Dir::State::lists=$APT/lists" \
        -o "Dir::Cache::archives=$APT/archives" \
        -o "Dir::Etc::sourcelist=$APT/sources.list" \
        -o "Dir::Etc::sourceparts=-" \
        -o "APT::Architectures=amd64,i386" \
        "$@"
}

echo "== apt metadata =="
apt_get update

echo "== downloading MinGW-w64, i386 runtime and patchelf =="
cd "$DL"
for package in \
    gcc-mingw-w64-x86-64-posix \
    gcc-mingw-w64-x86-64-posix-runtime \
    gcc-mingw-w64-base \
    binutils-mingw-w64-x86-64 \
    mingw-w64-x86-64-dev \
    mingw-w64-common \
    libc6:i386 \
    libgcc-s1:i386 \
    libstdc++6:i386 \
    patchelf
do
    apt_get download "$package"
done

echo "== extracting local toolchain =="
# Extracting all downloaded debs into separate roots is deliberate: MinGW
# binaries and the 32-bit loader must not overwrite the host's system files.
for deb in "$DL"/*.deb; do
    case "$(basename "$deb")" in
        libc6_*|libgcc-s1_*|libstdc++6_*) dpkg-deb -x "$deb" "$I386" ;;
        patchelf_*) dpkg-deb -x "$deb" "$HOST" ;;
        *) dpkg-deb -x "$deb" "$MINGW" ;;
    esac
done

GCC=$(find "$MINGW/usr/bin" -maxdepth 1 -name 'x86_64-w64-mingw32-gcc-[0-9]*-posix' -print -quit)
[ -n "$GCC" ] || {
    echo "MinGW gcc wrapper executable was not extracted" >&2
    exit 1
}
case "$GCC" in
    *gcc-ranlib-*) echo "selected ranlib instead of GCC: $GCC" >&2; exit 1 ;;
esac

cat >"$BIN/x86_64-w64-mingw32-gcc" <<EOF
#!/bin/sh
exec "$GCC" \\
    -isystem "$MINGW/usr/x86_64-w64-mingw32/include" \\
    -L"$MINGW/usr/x86_64-w64-mingw32/lib" \\
    -B"$MINGW/usr/x86_64-w64-mingw32/lib/" \\
    "\$@"
EOF
chmod +x "$BIN/x86_64-w64-mingw32-gcc"

echo "== downloading Wine 11.21 =="
if [ ! -f "$DL/wine.tar.xz" ]; then
    curl -fL "$WINE_URL" -o "$DL/wine.tar.xz"
fi
printf '%s  %s\n' "$WINE_SHA256" "$DL/wine.tar.xz" | sha256sum -c -

if [ ! -x "$WINE/lib/wine/x86_64-unix/wine" ]; then
    rm -rf "$WINE" "$ROOT/wine-11.21-amd64"
    tar -xJf "$DL/wine.tar.xz" -C "$ROOT"
    mv "$ROOT/wine-11.21-amd64" "$WINE"
fi

# The portable Wine build expects the host's /lib/ld-linux.so.2 for its 32-bit
# loader. Point only that loader at the user-local i386 runtime; no root or
# system-wide ldconfig change is involved.
PATCHELF="$HOST/usr/bin/patchelf"
I386_LOADER="$I386/usr/lib/i386-linux-gnu/ld-linux.so.2"
[ -x "$PATCHELF" ] && [ -x "$I386_LOADER" ] || {
    echo "patchelf or the extracted i386 loader is missing" >&2
    exit 1
}
"$PATCHELF" --set-interpreter "$I386_LOADER" "$WINE/lib/wine/i386-unix/wine"
ln -sfn "$WINE/lib/wine/x86_64-unix/wine" "$BIN/wine64"

cat >"$ROOT/run-wine.sh" <<EOF
#!/bin/sh
export WINEPREFIX="$PREFIX"
export WINEARCH=win64
export WINELOADER="$BIN/wine64"
export WINEDLLPATH="$WINE/lib/wine/x86_64-windows:$WINE/lib/wine/i386-windows:$WINE/lib/wine"
export WINEDEBUG=-all
export LD_LIBRARY_PATH="$I386/usr/lib/i386-linux-gnu:$I386/usr/lib:$MINGW/usr/lib/x86_64-linux-gnu:$MINGW/usr/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "$BIN/wine64" "\$@"
EOF
chmod +x "$ROOT/run-wine.sh"

if [ ! -f "$PREFIX/system.reg" ]; then
    echo "== initialising Wine prefix =="
    # Wine refuses a prefix directly under a root-owned parent such as /tmp.
    # The default cache path is user-owned; override it outside /tmp if needed.
    timeout 120 "$ROOT/run-wine.sh" wineboot --init >/dev/null 2>&1 || {
        echo "wineboot failed; keep LITRIC_WINE_ROOT in a user-owned directory" >&2
        exit 1
    }
fi

echo "== ready =="
echo "LITRIC_WINE_ROOT=$ROOT"
echo "runner=$ROOT/run-wine.sh"
echo "wine=$("$BIN/wine64" --version)"
echo "linker=$BIN/x86_64-w64-mingw32-gcc"
