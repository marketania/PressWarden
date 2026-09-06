#!/usr/bin/env bash
set -euo pipefail
PRESSWARDEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$PRESSWARDEN_DIR/.presswarden-portable" ]; then
  parent=$(cd "$PRESSWARDEN_DIR/.." && pwd -P)
  base=$(basename "$PRESSWARDEN_DIR")
  printf 'Portable PressWarden install detected:\n  %s\n\n' "$PRESSWARDEN_DIR"
  printf 'This removes the program plus its local config/reports/cache/quarantine. Continue? [y/N]: '
  read -r ans || ans=''
  case "$ans" in y|Y|yes|YES) ;; *) printf 'Cancelled.\n'; exit 0 ;; esac
  cd "$parent"
  rm -rf -- "$base"
  printf 'PressWarden portable folder removed.\n'
  exit 0
fi

PREFIX="${PRESSWARDEN_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/presswarden}"
BIN="${PRESSWARDEN_BIN_DIR:-$HOME/.local/bin}/presswarden"
rm -f "$BIN"
rm -rf "$PREFIX"
printf 'PressWarden program files removed.\n'
printf 'Config, reports, cache, and quarantine were intentionally preserved.\n'
printf 'To remove those too, review ~/.config/presswarden, ~/.cache/presswarden, and ~/.local/state/presswarden manually.\n'
