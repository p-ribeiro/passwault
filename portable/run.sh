#!/bin/sh
# Portable launcher for Passwault (Linux / macOS)
# Place this script in the USB drive root alongside the passwault/ folder.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/passwault/passwault" --portable "$@"
