#!/bin/sh
# Passwault portable launcher. Run as ./passwault or: sh /path/to/passwault <command>
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
BIN="$HERE/bin/passwault-linux-$(uname -m)"

if [ ! -f "$BIN" ]; then
    echo "passwault: no build for $(uname -m) in $HERE/bin" >&2
    exit 1
fi

export PASSWAULT_HOME="$HERE"

# vfat 'showexec' and noexec mounts hide the exec bit: run a private host copy
if [ ! -x "$BIN" ]; then
    CACHE="${XDG_RUNTIME_DIR:-/tmp}/passwault-bin-$(id -u)"
    mkdir -p "$CACHE"
    if [ ! -O "$CACHE" ]; then
        echo "passwault: $CACHE is not owned by you" >&2
        exit 1
    fi
    chmod 700 "$CACHE"
    if [ ! -x "$CACHE/passwault" ] || [ "$BIN" -nt "$CACHE/passwault" ]; then
        cp "$BIN" "$CACHE/passwault.tmp"
        chmod 700 "$CACHE/passwault.tmp"
        mv -f "$CACHE/passwault.tmp" "$CACHE/passwault"
    fi
    BIN="$CACHE/passwault"
fi

exec "$BIN" "$@"
