#!/usr/bin/env bash
#
# build.sh - build and package pipesix for Linux and Windows.
#
# Targets:
#   linux-amd64    native gcc build; .tar.gz and, with dpkg-deb, a .deb
#   linux-arm64    aarch64-linux-gnu-gcc cross build; .tar.gz and .deb
#   windows-amd64  x86_64-w64-mingw32-gcc cross build; .zip with pipesix.exe
#
# Every target is staged into dist/ with the files an operator needs. The
# archives and SHA256SUMS are what a release publishes; the staged trees
# are left in place so a failed packaging step can be inspected.
#
# Usage:
#   ./build.sh                          # host platform
#   ./build.sh --all                    # every target whose toolchain exists
#   ./build.sh --target windows-amd64   # one target, repeatable
#   ./build.sh --version 2.2.0 --all
#   ./build.sh --clean                  # remove dist/
#
# Cross toolchain packages on Debian/Ubuntu:
#   gcc-aarch64-linux-gnu gcc-mingw-w64-x86-64 zip dpkg-deb

set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIST="$ROOT/dist"
VERSION=""
TARGETS=()

usage() {
    cat <<'EOF'
Usage: ./build.sh [--version <ver>] [--target <name>]... [--all] [--clean]

Targets:
  linux-amd64     Linux x86-64 binary, tar.gz and (with dpkg-deb) .deb
  linux-arm64     Linux arm64 binary (aarch64-linux-gnu-gcc), tar.gz and .deb
  windows-amd64   Windows client (pipesix.exe, MinGW-w64), zip

Without --target or --all the host platform is built. A target whose
toolchain is missing is skipped with a warning, so --all works on a
machine that only has the native compiler.
EOF
}

warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ $# -gt 0 ]; do
    case $1 in
        --version)
            [ $# -ge 2 ] || die "--version needs a value"
            VERSION=$2
            shift 2
            ;;
        --target)
            [ $# -ge 2 ] || die "--target needs a value"
            TARGETS+=("$2")
            shift 2
            ;;
        --all)
            TARGETS=(linux-amd64 linux-arm64 windows-amd64)
            shift
            ;;
        --clean)
            rm -rf "$DIST"
            echo "removed $DIST"
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument '$1' (try --help)"
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION=$(sed -n 's/^#define PIPESIX_APP_VERSION "\(.*\)"/\1/p' \
                  "$ROOT/src/main.c" | head -n 1)
    VERSION=${VERSION:-0.0.0}
fi

case $VERSION in
    *[!0-9A-Za-z._+-]*) die "version '$VERSION' has unsupported characters" ;;
esac

if [ ${#TARGETS[@]} -eq 0 ]; then
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)                TARGETS=(linux-amd64) ;;
        Linux-aarch64|Linux-arm64)   TARGETS=(linux-arm64) ;;
        *)
            warn "no native target for $(uname -s)/$(uname -m); building" \
                 "windows-amd64"
            TARGETS=(windows-amd64)
            ;;
    esac
fi

mkdir -p "$DIST"

stage_linux() {
    local target=$1
    local stage="$DIST/pipesix-$VERSION-$target"

    rm -rf "$stage"
    mkdir -p "$stage"
    install -m 755 "$ROOT/pipesix" "$stage/pipesix"
    install -m 644 "$ROOT/pipesix.conf.example" "$ROOT/pipesix.service" \
                   "$ROOT/README.md" "$ROOT/LICENSE" "$stage/"
    install -m 755 "$ROOT/setup.sh" "$ROOT/netassist-up.sh" \
                   "$ROOT/wg-route64.sh" "$stage/"

    printf '%s\n' "$stage"
}

make_deb() {
    local target=$1
    local arch=$2
    local stage=$3
    local deb_version=${VERSION//-/\~}
    local root="$DIST/.deb-$target"

    if ! have dpkg-deb; then
        warn "dpkg-deb not found; skipping the .deb for $target"
        return 0
    fi

    rm -rf "$root"
    mkdir -p "$root/DEBIAN" "$root/usr/local/sbin" "$root/etc/pipesix" \
             "$root/lib/systemd/system" "$root/usr/share/doc/pipesix"

    install -m 755 "$stage/pipesix" "$root/usr/local/sbin/pipesix"
    install -m 644 "$ROOT/pipesix.conf.example" \
                   "$root/etc/pipesix/pipesix.conf.example"
    install -m 644 "$ROOT/pipesix.service" \
                   "$root/lib/systemd/system/pipesix.service"
    install -m 644 "$ROOT/README.md" "$ROOT/LICENSE" \
                   "$root/usr/share/doc/pipesix/"

    cat > "$root/DEBIAN/control" <<EOF
Package: pipesix
Version: $deb_version
Section: net
Priority: optional
Architecture: $arch
Depends: libc6, iproute2
Maintainer: pipesix maintainers <noreply@example.invalid>
Description: IPv6 over UDP tunnel with per-client pre-shared keys
 pipesix relays IPv6 traffic between a client TUN device and a server
 routed to an upstream IPv6 tunnel broker. Every client has its own key,
 and separate client-to-server and server-to-client session keys are
 negotiated per session.
EOF

    dpkg-deb --build --root-owner-group "$root" \
             "$DIST/pipesix_${deb_version}_${arch}.deb" >/dev/null
    rm -rf "$root"
}

build_linux() {
    local target=$1
    local cc=$2
    local arch=$3
    local stage

    if ! have "$cc"; then
        warn "$cc not found; skipping $target"
        return 0
    fi

    echo "==> $target ($cc)"
    make -C "$ROOT" clean >/dev/null
    make -C "$ROOT" CC="$cc"

    stage=$(stage_linux "$target")
    tar -C "$DIST" -czf "$DIST/pipesix-$VERSION-$target.tar.gz" \
        "pipesix-$VERSION-$target"

    make_deb "$target" "$arch" "$stage"
}

build_windows() {
    local cc=${CC_WINDOWS_AMD64:-x86_64-w64-mingw32-gcc}
    local stage="$DIST/pipesix-$VERSION-windows-amd64"

    if ! have "$cc"; then
        warn "$cc not found; skipping windows-amd64"
        return 0
    fi

    echo "==> windows-amd64 ($cc)"
    make -C "$ROOT" clean >/dev/null
    make -C "$ROOT" windows WINDOWS_CC="$cc"

    rm -rf "$stage"
    mkdir -p "$stage"
    install -m 755 "$ROOT/pipesix.exe" "$stage/pipesix.exe"
    install -m 644 "$ROOT/pipesix.conf.example" "$ROOT/README.md" \
                   "$ROOT/LICENSE" "$stage/"

    if have zip; then
        ( cd "$DIST" && zip -qr "pipesix-$VERSION-windows-amd64.zip" \
              "pipesix-$VERSION-windows-amd64" )
    else
        warn "zip not found; leaving $stage unarchived"
    fi
}

for target in "${TARGETS[@]}"; do
    case $target in
        linux-amd64)
            build_linux linux-amd64 "${CC_LINUX_AMD64:-gcc}" amd64
            ;;
        linux-arm64)
            build_linux linux-arm64 \
                        "${CC_LINUX_ARM64:-aarch64-linux-gnu-gcc}" arm64
            ;;
        windows-amd64)
            build_windows
            ;;
        *)
            die "unknown target '$target'"
            ;;
    esac
done

shopt -s nullglob
archives=("$DIST"/pipesix-*.tar.gz "$DIST"/pipesix-*.zip "$DIST"/pipesix_*.deb)

if [ ${#archives[@]} -gt 0 ]; then
    if have sha256sum; then
        ( cd "$DIST" && sha256sum "${archives[@]##*/}" > SHA256SUMS )
    elif have shasum; then
        ( cd "$DIST" && shasum -a 256 "${archives[@]##*/}" > SHA256SUMS )
    else
        warn "no sha256sum or shasum; SHA256SUMS not written"
    fi
fi

echo
echo "Artifacts in $DIST:"
( cd "$DIST" && ls -1 pipesix-*.tar.gz pipesix-*.zip pipesix_*.deb \
      SHA256SUMS 2>/dev/null || true )
