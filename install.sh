#!/bin/sh
# Install server-init from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/Mimic890/server-init/main/install.sh | sudo sh
#   curl -fsSL .../install.sh | sudo VERSION=v0.1.0 sh      # a specific version
#   BASE_URL=https://mirror.example/server-init sh install.sh # a mirror of the release files
#
# The archive is checked against the release's checksums.txt before the
# binary is installed to /usr/local/bin (BINDIR overrides it).
set -eu

REPO="Mimic890/server-init"
VERSION="${VERSION:-latest}"
BINDIR="${BINDIR:-/usr/local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "server-init runs on Linux only"
case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    *) die "unsupported architecture: $(uname -m) (only x86_64 builds are published)" ;;
esac

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
else
    die "curl or wget is required"
fi
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

if [ -n "${BASE_URL:-}" ]; then
    base="$BASE_URL"
elif [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi
archive="server-init_linux_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $archive ($VERSION)..."
fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

(cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c - >/dev/null) \
    || die "checksum mismatch for $archive"
say "Checksum OK."

tar -xzf "$tmp/$archive" -C "$tmp" server-init
if [ -w "$BINDIR" ]; then
    install -m 0755 "$tmp/server-init" "$BINDIR/server-init"
else
    die "cannot write to $BINDIR (run with sudo)"
fi

say "Installed $("$BINDIR/server-init" --version) to $BINDIR/server-init"
say "Start it with: sudo server-init   (or: sudo server-init --dry-run)"
