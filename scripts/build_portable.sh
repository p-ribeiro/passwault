#!/usr/bin/env bash
# Build the portable (USB) bundle: a one-file Linux binary plus its launcher.
# Usage: scripts/build_portable.sh [DEST]   (default: dist/portable)
# Re-running on an existing bundle replaces the program files only; data/ and
# backups/ are never touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-$ROOT/dist/portable}"
BUNDLE="$DEST/passwault"
ARCH="$(uname -m)"
NAME="passwault-linux-$ARCH"
VENV="$ROOT/build/portable-venv"
WORK="$ROOT/build/pyinstaller"

case "$ARCH" in
    x86_64 | aarch64) PLATFORM="$ARCH-manylinux_2_28" ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# Build on a uv-managed (python-build-standalone) interpreter: it targets old
# glibc, unlike a distro or pyenv Python linked against this host's glibc.
# --reinstall-package: uv's cached project wheel ignores edits to .py files.
echo ">> Syncing build environment ($PLATFORM)"
rm -rf "$ROOT/build/lib" # setuptools staging dir keeps files deleted from the source
UV_PROJECT_ENVIRONMENT="$VENV" uv sync --locked --no-dev --group portable \
    --no-editable --reinstall-package passwault-project \
    --managed-python --python 3.14 --python-platform "$PLATFORM"

if ! "$VENV/bin/python" -c 'import sys; sys.exit(sys.version_info.releaselevel != "final")'; then
    echo "uv only offers a pre-release CPython 3.14; run 'uv self update' and retry." >&2
    exit 1
fi

echo ">> Building $NAME"
"$VENV/bin/pyinstaller" --noconfirm --clean --log-level WARN \
    --distpath "$WORK/dist" --workpath "$WORK/build" \
    "$ROOT/scripts/portable/passwault.spec"

echo ">> Assembling $BUNDLE"
mkdir -p "$BUNDLE/bin" "$BUNDLE/data" "$BUNDLE/backups"
cp "$WORK/dist/$NAME" "$BUNDLE/bin/$NAME.tmp"
mv -f "$BUNDLE/bin/$NAME.tmp" "$BUNDLE/bin/$NAME"
cp "$ROOT/scripts/portable/passwault.sh" "$BUNDLE/passwault"
cp "$ROOT/scripts/portable/README.txt" "$BUNDLE/README.txt"
touch "$BUNDLE/.passwault-portable"
# chmod is refused on FAT/exFAT; the launcher copes with a missing exec bit
chmod +x "$BUNDLE/passwault" "$BUNDLE/bin/$NAME" 2>/dev/null || true
sync

if command -v objdump >/dev/null; then
    GLIBC_MAX="$(
        { cat "$WORK/build/passwault/binaries.txt"; echo; echo "$BUNDLE/bin/$NAME"; } |
            tr '\n' '\0' | xargs -0 objdump -T 2>/dev/null |
            grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
    )"
    echo ">> Highest glibc symbol required: ${GLIBC_MAX:-unknown}"
fi

echo ">> Done. Run: sh $BUNDLE/passwault vault status"
