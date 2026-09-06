#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PRESSWARDEN_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/presswarden}"
BIN="${PRESSWARDEN_BIN_DIR:-$HOME/.local/bin}/presswarden"
rm -f "$BIN"
rm -rf "$PREFIX"
printf 'PressWarden program files removed.\n'
printf 'Config, reports, cache, and quarantine were intentionally preserved.\n'
printf 'To remove those too, review ~/.config/presswarden, ~/.cache/presswarden, and ~/.local/state/presswarden manually.\n'
