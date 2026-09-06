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
 ____                    __        __            _            
|  _ \ _ __ ___  ___ ___\ \      / /_ _ _ __ __| | ___ _ __ 
| |_) | '__/ _ \/ __/ __|\ \ /\ / / _` | '__/ _` |/ _ \ '_ \
|  __/| | |  __/\__ \__ \\ V  V / (_| | | | (_| |  __/ | | |
|_|   |_|  \___||___/___/ \_/\_/ \__,_|_|  \__,_|\___|_| |_|

          Fleet-scale WordPress security auditing from the shell.
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

install_portable() {
  local target="${PRESSWARDEN_INSTALL_DIR:-$PWD/PressWarden}"
  case "$target" in /*) : ;; *) target="$PWD/$target" ;; esac
  target=${target%/}

  mkdir -p "$(dirname "$target")"
  fetch_archive

  # Preserve private local configuration and runtime state across upgrades.
  if [ -f "$target/config/config" ]; then
    mkdir -p "$TMP/preserve/config"
    cp -p "$target/config/config" "$TMP/preserve/config/config"
  fi
  if [ -d "$target/var" ]; then
    mkdir -p "$TMP/preserve"
    cp -a "$target/var" "$TMP/preserve/var"
  fi

  rm -rf "$target.new"
  mv "$TMP/src" "$target.new"
  : > "$target.new/.presswarden-portable"
  mkdir -p "$target.new/config" "$target.new/var/reports" "$target.new/var/cache" "$target.new/var/quarantine"

  if [ -f "$TMP/preserve/config/config" ]; then
    cp -p "$TMP/preserve/config/config" "$target.new/config/config"
  elif [ ! -f "$target.new/config/config" ]; then
    cp "$target.new/config/config.example" "$target.new/config/config"
  fi
  if [ -d "$TMP/preserve/var" ]; then
    rm -rf "$target.new/var"
    cp -a "$TMP/preserve/var" "$target.new/var"
  fi

  chmod +x "$target.new/presswarden" "$target.new/install.sh" "$target.new/uninstall.sh" "$target.new"/checks/*.sh "$target.new"/suites/*.sh
  chmod 600 "$target.new/config/config" 2>/dev/null || true

  rm -rf "$target"
  mv "$target.new" "$target"

  logo
  printf '\n%s\n' 'PressWarden v1.0.3 • portable shared-host install'
  printf '%s\n\n' 'No bin directory, symlink, PATH change, or system-wide access required.'
  printf '✓ Installed: %s\n' "$target"
  printf '✓ Config:    %s/config/config\n' "$target"
  printf '✓ Data:      %s/var\n' "$target"
  printf '\nNext steps:\n'
  printf '  cd %q\n' "$target"
  printf '  ./presswarden doctor\n'
  printf '  ./presswarden fast\n'
  printf '\nTip: use ./presswarden full for the comprehensive audit.\n'
}

install_user() {
  local prefix="${PRESSWARDEN_PREFIX:-${XDG_DATA_HOME:-$HOME/.local/share}/presswarden}"
  local bin_dir="${PRESSWARDEN_BIN_DIR:-$HOME/.local/bin}"
  local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/presswarden"

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

  logo
  printf '\nPressWarden v1.0.3 • user install\n\n'
  printf '✓ CLI:    %s/presswarden\n' "$bin_dir"
  printf '✓ Config: %s/config\n' "$config_dir"
  printf '\nNext steps:\n  presswarden doctor\n  presswarden fast\n'
}

case "$MODE" in
  portable|local) install_portable ;;
  user|legacy) install_user ;;
  *) printf 'Error: PRESSWARDEN_INSTALL_MODE must be portable or user.\n' >&2; exit 2 ;;
esac
