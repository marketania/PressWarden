#!/usr/bin/env bash
set -euo pipefail

REPO="${PRESSWARDEN_REPO:-marketania/PressWarden}"
REF="${PRESSWARDEN_REF:-main}"
MODE="${PRESSWARDEN_INSTALL_MODE:-portable}"
TMP="${TMPDIR:-/tmp}/presswarden-install.$$"
ARCHIVE="$TMP/presswarden.tar.gz"
trap 'rm -rf "$TMP"' EXIT

logo() {
cat <<'EOF'
+----------------------------------------------------------------------+
|                             PressWarden                              |
|   WordPress Fleet Security | Threat Intelligence | Incident Response |
+----------------------------------------------------------------------+
EOF
}

fetch_archive() {
  local url="https://github.com/$REPO/archive/refs/heads/$REF.tar.gz"
  mkdir -p "$TMP"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$ARCHIVE"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$ARCHIVE" "$url"
  else
    printf 'Error: curl or wget is required.\n' >&2
    exit 2
  fi
  mkdir -p "$TMP/src"
  tar -xzf "$ARCHIVE" -C "$TMP/src" --strip-components=1
}

version_from_dir() {
  local dir="$1"
  cat "$dir/VERSION" 2>/dev/null || printf 'unknown'
}

install_portable() {
  local target version
  if [ -n "${PRESSWARDEN_INSTALL_DIR:-}" ]; then
    target="$PRESSWARDEN_INSTALL_DIR"
  elif [ -f "$PWD/.presswarden-portable" ] && [ -f "$PWD/presswarden" ]; then
    target="$PWD"
  else
    target="$PWD/PressWarden"
  fi
  case "$target" in /*) : ;; *) target="$PWD/$target" ;; esac
  target=${target%/}

  mkdir -p "$target"
  fetch_archive

  # Copy program files in place. config/config and var/ are not part of the
  # repository, so an existing portable install keeps its private settings,
  # reports, cache, and quarantine during upgrades.
  cp -a "$TMP/src/." "$target/"
  : > "$target/.presswarden-portable"
  mkdir -p "$target/config" "$target/var/reports" "$target/var/cache" "$target/var/quarantine"
  if [ ! -f "$target/config/config" ]; then
    cp "$target/config/config.example" "$target/config/config"
  fi

  chmod +x "$target/presswarden" "$target/install.sh" "$target/uninstall.sh" "$target"/checks/*.sh "$target"/suites/*.sh
  chmod 600 "$target/config/config" 2>/dev/null || true
  version=$(version_from_dir "$target")

  logo
  printf '\nPressWarden v%s • portable shared-host install\n' "$version"
  printf '%s\n\n' 'No bin directory, symlink, PATH change, or system-wide access required.'
  printf '✓ Installed: %s\n' "$target"
  printf '✓ Config:    %s/config/config\n' "$target"
  printf '✓ Data:      %s/var\n' "$target"
  printf '\nNext steps:\n'
  printf '  cd %q\n' "$target"
  printf '  ./presswarden doctor\n'
  printf '  ./presswarden fast\n'
  printf '\nFuture upgrades: ./presswarden update\n'
  printf 'Tip: use ./presswarden full for the comprehensive audit.\n'
}

install_user() {
  local prefix="${PRESSWARDEN_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/presswarden}"
  local bin_dir="${PRESSWARDEN_BIN_DIR:-$HOME/.local/bin}"
  local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/presswarden"
  local version

  mkdir -p "$bin_dir" "$config_dir"
  fetch_archive
  rm -rf "$prefix.new"
  mv "$TMP/src" "$prefix.new"
  rm -rf "$prefix"
  mv "$prefix.new" "$prefix"
  chmod +x "$prefix/presswarden" "$prefix/install.sh" "$prefix/uninstall.sh" "$prefix"/checks/*.sh "$prefix"/suites/*.sh
  ln -sfn "$prefix/presswarden" "$bin_dir/presswarden"
  if [ ! -e "$config_dir/config" ]; then
    cp "$prefix/config/config.example" "$config_dir/config"
    chmod 600 "$config_dir/config" 2>/dev/null || true
  fi
  version=$(version_from_dir "$prefix")

  logo
  printf '\nPressWarden v%s • user install\n\n' "$version"
  printf '✓ CLI:    %s/presswarden\n' "$bin_dir"
  printf '✓ Config: %s/config\n' "$config_dir"
  printf '\nNext steps:\n  presswarden doctor\n  presswarden fast\n'
  printf '\nFuture upgrades: presswarden update\n'
}

case "$MODE" in
  portable|local) install_portable ;;
  user|legacy) install_user ;;
  *) printf 'Error: PRESSWARDEN_INSTALL_MODE must be portable or user.\n' >&2; exit 2 ;;
esac
