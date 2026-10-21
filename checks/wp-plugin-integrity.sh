#!/usr/bin/env bash
# wp-plugin-integrity — official checksums for active WordPress.org plugins.
NAME=wp-plugin-integrity; DESC="official WordPress.org plugin checksum verification (full)"
SCAN_DOES="Verifies active WordPress.org plugin files using one bounded WP-CLI verifier per site. Unknown vendor coverage and failed provider calls are incomplete, not clean."
SCAN_WHY="An integrity mismatch is a package deviation, not automatically malware. Custom packages need independent vendor evidence."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_integrity_incomplete() { PW_CHECK_INCOMPLETE=1; note "INCOMPLETE: $1"; }
# Do not use wpq here: it merges stderr into structured stdout. Preserve warnings
# so a provider's skipped plugin can never be confused with an empty clean list.
_integrity_wp() {
  local site="$1"; shift
  (ulimit -f 16384; timeout --kill-after=5s 120s wp "$@" --path="$site" "${WPQ[@]}" --quiet)
}
_integrity_records() { php -d memory_limit=64M "$PRESSWARDEN_DIR/lib/plugin-integrity-output.php" "$@"; }
_wporg_cached_status() {
  local slug="$1" f st=''
  f="$PRESSWARDEN_CACHE_DIR/wporg-plugin-status/${slug}.status"
  [ -f "$f" ] && [ ! -L "$f" ] || return 1
  st=$(head -c 100 "$f" 2>/dev/null)
  case "$st" in active|closed|removed) printf '%s' "$st" ;; *) return 1 ;; esac
}
_is_active_code_file() {
  local file="${1,,}"
  case "$file" in *.php|*.php[0-9]|*.phtml|*.phar|*.inc|*.js|*.mjs|*.cjs|*.html|*.htm|*.svg|*.htaccess|*.user.ini) return 0 ;; esac
  return 1
}

main() {
  require_wp; banner; discover_sites
  command -v timeout >/dev/null 2>&1 || { _integrity_incomplete 'GNU timeout is required for bounded provider calls.'; finish; return 2; }
  local s d inv active fallback available out err records name status ver title wpst
  local rc need_fallback plugin file msg deviations shown verified=0 inspected=0
  local -a eligible
  sec "WordPress.org plugin checksums" "active plugins • bounded provider calls • explicit coverage gaps"
  note 'WordPress/WP-CLI bootstrap executes site code, including MU-plugins; this is not a sandbox. Use an isolated copy when compromise is suspected.'
  note 'A checksum mismatch is not proof of malware. Added files, including OS metadata names, need review; their contents have not been declared safe.'
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); eligible=()
    inv=$(tmpf); active=$(tmpf); fallback=$(tmpf); available=$(tmpf)
    out=$(tmpf); err=$(tmpf); records=$(tmpf)
    if ! _integrity_wp "$s" plugin list --fields=name,status,version,title --format=json --skip-update-check > "$inv" 2> "$err" ||
       [ -s "$err" ] || ! _integrity_records inventory "$inv" > "$active" 2>/dev/null; then
      _integrity_incomplete "$d: plugin inventory failed or was invalid. Check WP-CLI/bootstrap in an isolated environment; no malware verdict was made."
      rm -f -- "$inv" "$active" "$fallback" "$available" "$out" "$err" "$records"; continue
    fi
    need_fallback=0
    while IFS='|' read -r name status ver title; do
      [ -n "$name" ] || continue
      _wporg_cached_status "$name" >/dev/null 2>&1 || need_fallback=1
    done < "$active"
    if [ "$need_fallback" -eq 1 ]; then
      if ! _integrity_wp "$s" plugin list --fields=name,status,wporg_status --format=json --skip-update-check > "$fallback" 2> "$err" ||
         [ -s "$err" ] || ! _integrity_records availability "$fallback" > "$available" 2>/dev/null; then
        _integrity_incomplete "$d: WordPress.org availability could not be established; unchecked plugins are not clean."
      fi
    fi
    while IFS='|' read -r name status ver title; do
      [ -n "$name" ] || continue
      inspected=$((inspected+1)); wpst=$(_wporg_cached_status "$name" 2>/dev/null || true)
      if [ -z "$wpst" ]; then wpst=$(awk -F'|' -v n="$name" '$1==n {print $2; exit}' "$available"); fi
      if [ "$wpst" = active ]; then eligible+=("$name")
      else _integrity_incomplete "$d: $name has unknown or unsupported WordPress.org checksum coverage. Obtain trusted vendor checksums; this is not a malware finding."
      fi
    done < "$active"
    if [ "${#eligible[@]}" -eq 0 ]; then
      note "$d: no eligible active WordPress.org plugins verified."
      rm -f -- "$inv" "$active" "$fallback" "$available" "$out" "$err" "$records"; continue
    fi
    _integrity_wp "$s" plugin verify-checksums "${eligible[@]}" --format=json > "$out" 2> "$err"; rc=$?
    if ! _integrity_records checksums "$out" "${eligible[@]}" > "$records" 2>/dev/null; then
      _integrity_incomplete "$d: invalid or unsafe checksum output; no verified claim."
      rm -f -- "$inv" "$active" "$fallback" "$available" "$out" "$err" "$records"; continue
    fi
    deviations=0; shown=0
    while IFS='|' read -r plugin file msg; do
      [ -n "$plugin" ] || continue
      deviations=$((deviations+1)); shown=$((shown+1))
      if [ "$shown" -le 100 ]; then
        if [ "$msg" = 'Checksum does not match' ] && _is_active_code_file "$file"; then
          issue "$d" "integrity mismatch — $plugin" "$file ($msg)"
        else flag "$d" "plugin package deviation — $plugin" "$file ($msg); inspect before any change"
        fi
      else TOTAL=$((TOTAL+1)); REVIEWS=$((REVIEWS+1)); fi
    done < "$records"
    [ "$shown" -le 100 ] || note "$d: $((shown-100)) additional deviations not displayed; this report is not a full raw-output archive."
    # Upstream emits this expected summary on a checksum finding. Other stderr,
    # especially warnings about skipped packages, means incomplete coverage.
    if [ "$rc" -gt 1 ] || { [ "$rc" -ne 0 ] && [ "$deviations" -eq 0 ]; } ||
       { [ -s "$err" ] && { [ "$deviations" -eq 0 ] || grep -qEv '^Error: (No plugins verified \([0-9]+ failed\)\.|Only verified [0-9]+ of [0-9]+ plugins\.)$' "$err"; }; }; then
      _integrity_incomplete "$d: provider failure, warning, timeout or skipped package (rc=$rc). Valid integrity findings above are retained; check provider availability and permissions."
    elif [ "$deviations" -eq 0 ]; then
      verified=$((verified+${#eligible[@]})); note "$d: ${#eligible[@]} active WordPress.org plugin(s) verified by WP-CLI."
    fi
    rm -f -- "$inv" "$active" "$fallback" "$available" "$out" "$err" "$records"
  done
  note "Scope: $inspected active plugin(s) inventoried; $verified in fully verified site batches. Inactive plugins, MU-plugins, themes and custom vendor packages need their own checks."
  if [ "$inspected" -eq 0 ] && [ "${PW_CHECK_INCOMPLETE:-0}" -eq 0 ]; then
    note 'SKIPPED: no active plugins were in the checksum-check scope.'
    return 0
  fi
  finish
}
run_logged wp-plugin-integrity
