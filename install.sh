#!/usr/bin/env bash
set -euo pipefail
REPO="${PRESSWARDEN_REPO:-marketania/PressWarden}"
REF="${PRESSWARDEN_REF:-main}"
PREFIX="${PRESSWARDEN_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/presswarden}"
BIN_DIR="${PRESSWARDEN_BIN_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/presswarden"
TMP="${TMPDIR:-/tmp}/presswarden-install.$$"
ARCHIVE="$TMP/presswarden.tar.gz"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP" "$BIN_DIR" "$CONFIG_DIR"
URL="https://github.com/$REPO/archive/refs/heads/$REF.tar.gz"
printf 'Installing PressWarden from %s (%s)...\n' "$REPO" "$REF"
if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" -o "$ARCHIVE"
elif command -v wget >/dev/null 2>&1; then wget -qO "$ARCHIVE" "$URL"
else printf 'Error: curl or wget is required.\n' >&2; exit 2; fi
mkdir -p "$TMP/src"
tar -xzf "$ARCHIVE" -C "$TMP/src" --strip-components=1
rm -rf "$PREFIX.new"
mv "$TMP/src" "$PREFIX.new"
rm -rf "$PREFIX"
mv "$PREFIX.new" "$PREFIX"
chmod +x "$PREFIX/presswarden" "$PREFIX/install.sh" "$PREFIX"/checks/*.sh "$PREFIX"/suites/*.sh
ln -sfn "$PREFIX/presswarden" "$BIN_DIR/presswarden"
if [ ! -e "$CONFIG_DIR/config" ]; then
  cp "$PREFIX/config/config.example" "$CONFIG_DIR/config"
  chmod 600 "$CONFIG_DIR/config" 2>/dev/null || true
fi
printf '\n✓ PressWarden installed.\n'
printf '  CLI:    %s/presswarden\n' "$BIN_DIR"
printf '  Config: %s/config\n' "$CONFIG_DIR"
printf '\nIf %s is not in PATH, add:\n  export PATH="$HOME/.local/bin:$PATH"\n\n' "$BIN_DIR"
printf 'Start with:\n  presswarden doctor\n  presswarden fast\n'
