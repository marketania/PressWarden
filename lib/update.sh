#!/usr/bin/env bash
# PressWarden self-update engine. Replaces only repository-managed program files.
# Private configuration and runtime state are intentionally outside the managed set.
set -uo pipefail

PRESSWARDEN_DIR="${PRESSWARDEN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PRESSWARDEN_UPDATE_REPO="${PRESSWARDEN_REPO:-marketania/PressWarden}"
PRESSWARDEN_UPDATE_REF="${PRESSWARDEN_REF:-main}"

# Program paths owned by the PressWarden distribution. Never add config/config,
# var/, or .presswarden-portable here: those are private/local runtime state.
_PRESSWARDEN_UPDATE_MANAGED=(
  .github .gitignore CHANGELOG.md CONTRIBUTING.md LICENSE README.md SECURITY.md VERSION
  checks docs integrations intel lib suites tests
  install.sh uninstall.sh presswarden
)

_pw_update_tmpf() {
  mktemp "${TMPDIR:-/tmp}/presswarden-update.XXXXXX" 2>/dev/null
}

_pw_update_fetch_archive() {
  local archive="$1" branch_url tag_url
  if [ -n "${PRESSWARDEN_UPDATE_ARCHIVE:-}" ]; then
    [ -r "$PRESSWARDEN_UPDATE_ARCHIVE" ] || { printf 'Update archive is not readable: %s\n' "$PRESSWARDEN_UPDATE_ARCHIVE" >&2; return 2; }
    cp "$PRESSWARDEN_UPDATE_ARCHIVE" "$archive" || return 2
    return 0
  fi

  branch_url="https://github.com/$PRESSWARDEN_UPDATE_REPO/archive/refs/heads/$PRESSWARDEN_UPDATE_REF.tar.gz"
  tag_url="https://github.com/$PRESSWARDEN_UPDATE_REPO/archive/refs/tags/$PRESSWARDEN_UPDATE_REF.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$branch_url" -o "$archive" 2>/dev/null || curl -fsSL "$tag_url" -o "$archive" 2>/dev/null || {
      printf 'Could not download PressWarden update for ref %s.\n' "$PRESSWARDEN_UPDATE_REF" >&2
      return 2
    }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$archive" "$branch_url" 2>/dev/null || wget -qO "$archive" "$tag_url" 2>/dev/null || {
      printf 'Could not download PressWarden update for ref %s.\n' "$PRESSWARDEN_UPDATE_REF" >&2
      return 2
    }
  else
    printf 'PressWarden update requires curl or wget.\n' >&2
    return 2
  fi
}

_pw_update_validate_source() {
  local src="$1" list f version
  [ -s "$src/VERSION" ] || { printf 'Update validation failed: VERSION is missing.\n' >&2; return 2; }
  [ -s "$src/presswarden" ] || { printf 'Update validation failed: presswarden CLI is missing.\n' >&2; return 2; }
  [ -s "$src/lib/_lib.sh" ] || { printf 'Update validation failed: runtime library is missing.\n' >&2; return 2; }
  [ -s "$src/suites/fast.sh" ] || { printf 'Update validation failed: FAST suite is missing.\n' >&2; return 2; }

  version=$(tr -d '[:space:]' < "$src/VERSION" 2>/dev/null || true)
  case "$version" in ''|*[!0-9A-Za-z._+-]*) printf 'Update validation failed: invalid VERSION value.\n' >&2; return 2 ;; esac

  list=$(_pw_update_tmpf) || return 2
  : > "$list"
  find "$src/checks" "$src/lib" "$src/suites" "$src/tests" -type f \( -name '*.sh' -o -name 'presswarden' \) -print 2>/dev/null >> "$list"
  printf '%s\n' "$src/presswarden" "$src/install.sh" "$src/uninstall.sh" >> "$list"
  sort -u "$list" -o "$list" 2>/dev/null || true
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    if ! bash -n "$f" 2>/dev/null; then
      printf 'Update validation failed: Bash syntax error in %s.\n' "${f#"$src"/}" >&2
      rm -f "$list"
      return 2
    fi
  done < "$list"
  rm -f "$list"

  if command -v php >/dev/null 2>&1; then
    list=$(_pw_update_tmpf) || return 2
    find "$src/lib" -type f -name '*.php' -print 2>/dev/null > "$list"
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      if ! php -l "$f" >/dev/null 2>&1; then
        printf 'Update validation failed: PHP syntax error in %s.\n' "${f#"$src"/}" >&2
        rm -f "$list"
        return 2
      fi
    done < "$list"
    rm -f "$list"
  fi
  return 0
}

_pw_update_backup_managed() {
  local target="$1" backup="$2" item src dest
  mkdir -p "$backup" || return 2
  for item in "${_PRESSWARDEN_UPDATE_MANAGED[@]}"; do
    src="$target/$item"; dest="$backup/$item"
    if [ -e "$src" ] || [ -L "$src" ]; then
      mkdir -p "$(dirname "$dest")" || return 2
      cp -a "$src" "$dest" || return 2
    fi
  done
  if [ -e "$target/config/config.example" ] || [ -L "$target/config/config.example" ]; then
    mkdir -p "$backup/config" || return 2
    cp -a "$target/config/config.example" "$backup/config/config.example" || return 2
  fi
}

_pw_update_replace_managed() {
  local src="$1" target="$2" item from to
  for item in "${_PRESSWARDEN_UPDATE_MANAGED[@]}"; do
    from="$src/$item"; to="$target/$item"
    rm -rf -- "$to" || return 2
    if [ -e "$from" ] || [ -L "$from" ]; then
      mkdir -p "$(dirname "$to")" || return 2
      cp -a "$from" "$to" || return 2
    fi
  done

  # Only the public example is distribution-managed. The user's real config is
  # intentionally neither removed, rewritten, merged, nor parsed here.
  mkdir -p "$target/config" || return 2
  rm -f -- "$target/config/config.example" || return 2
  cp -a "$src/config/config.example" "$target/config/config.example" || return 2

  chmod +x "$target/presswarden" "$target/install.sh" "$target/uninstall.sh" 2>/dev/null || true
  chmod +x "$target"/checks/*.sh "$target"/suites/*.sh 2>/dev/null || true
  return 0
}

_pw_update_restore_managed() {
  local backup="$1" target="$2" item from to
  for item in "${_PRESSWARDEN_UPDATE_MANAGED[@]}"; do
    to="$target/$item"; from="$backup/$item"
    rm -rf -- "$to" 2>/dev/null || true
    if [ -e "$from" ] || [ -L "$from" ]; then
      mkdir -p "$(dirname "$to")" 2>/dev/null || true
      cp -a "$from" "$to" 2>/dev/null || true
    fi
  done
  rm -f -- "$target/config/config.example" 2>/dev/null || true
  if [ -e "$backup/config/config.example" ] || [ -L "$backup/config/config.example" ]; then
    mkdir -p "$target/config" 2>/dev/null || true
    cp -a "$backup/config/config.example" "$target/config/config.example" 2>/dev/null || true
  fi
}

pw_update() {
  local tmp archive src backup old_version new_version rc=0

  if [ -d "$PRESSWARDEN_DIR/.git" ] && [ "${PRESSWARDEN_UPDATE_ALLOW_GIT:-0}" != "1" ]; then
    printf 'PressWarden update refused: this appears to be a Git checkout. Use git pull for a development checkout.\n' >&2
    return 2
  fi
  [ -w "$PRESSWARDEN_DIR" ] || { printf 'PressWarden program directory is not writable: %s\n' "$PRESSWARDEN_DIR" >&2; return 2; }
  command -v tar >/dev/null 2>&1 || { printf 'PressWarden update requires tar.\n' >&2; return 2; }

  old_version=$(tr -d '[:space:]' < "$PRESSWARDEN_DIR/VERSION" 2>/dev/null || printf 'unknown')
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-update.XXXXXX" 2>/dev/null) || { printf 'Could not create update workspace.\n' >&2; return 2; }
  archive="$tmp/presswarden.tar.gz"; src="$tmp/src"; backup="$tmp/backup"
  mkdir -p "$src" || { rm -rf "$tmp"; return 2; }

  printf 'Checking PressWarden updates from %s @ %s...\n' "$PRESSWARDEN_UPDATE_REPO" "$PRESSWARDEN_UPDATE_REF"
  _pw_update_fetch_archive "$archive" || { rc=$?; rm -rf "$tmp"; return "$rc"; }
  if ! tar -xzf "$archive" -C "$src" --strip-components=1 2>/dev/null; then
    printf 'Update validation failed: downloaded archive could not be extracted.\n' >&2
    rm -rf "$tmp"; return 2
  fi
  _pw_update_validate_source "$src" || { rc=$?; rm -rf "$tmp"; return "$rc"; }
  new_version=$(tr -d '[:space:]' < "$src/VERSION" 2>/dev/null || printf 'unknown')

  printf 'Validated PressWarden v%s. Preserving config and runtime data...\n' "$new_version"
  if ! _pw_update_backup_managed "$PRESSWARDEN_DIR" "$backup"; then
    printf 'Update aborted: could not create a rollback copy of the current program files.\n' >&2
    rm -rf "$tmp"; return 2
  fi

  if ! _pw_update_replace_managed "$src" "$PRESSWARDEN_DIR"; then
    printf 'Update failed while replacing program files; restoring previous code...\n' >&2
    _pw_update_restore_managed "$backup" "$PRESSWARDEN_DIR"
    rm -rf "$tmp"
    return 2
  fi

  # Validate the installed result before declaring success. Private data was
  # never part of the replacement set, so rollback also cannot overwrite it.
  if ! bash -n "$PRESSWARDEN_DIR/presswarden" 2>/dev/null || [ ! -s "$PRESSWARDEN_DIR/lib/_lib.sh" ]; then
    printf 'Updated files failed post-install validation; restoring previous code...\n' >&2
    _pw_update_restore_managed "$backup" "$PRESSWARDEN_DIR"
    rm -rf "$tmp"
    return 2
  fi

  rm -rf "$tmp"
  printf '\n✓ PressWarden updated: %s → %s\n' "$old_version" "$new_version"
  printf '✓ Preserved: config/config and all runtime state (reports, quarantine, baselines, cache, intel)\n'
  printf '✓ Program:   %s\n' "$PRESSWARDEN_DIR"
  printf '\nRun ./presswarden doctor to verify the environment after a major update.\n'
  return 0
}
