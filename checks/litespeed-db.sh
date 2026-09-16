#!/usr/bin/env bash
# litespeed-db — explicit LiteSpeed Cache database cleanup/optimization action.
# LiteSpeed's litespeed-database command does not accept WP-CLI global parameters,
# so the actual optimize command is intentionally run from each site's cwd.
set -uo pipefail
NAME=litespeed-db
DESC="LiteSpeed Cache database cleanup and optimization"
SCAN_DOES="Checks whether LiteSpeed Cache database optimization is available and, when explicitly requested, runs LiteSpeed Cache's optimize_all cleanup for eligible WordPress sites."
SCAN_WHY="LiteSpeed Cache can remove revisions, drafts, trash, transients and other database clutter beyond PressWarden's native SQL table optimization. Keeping this as an explicit maintenance action avoids surprising cleanup during security scans."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

ACTION="${1:-status}"
case "$ACTION" in
  status|optimize) : ;;
  *) printf 'Use litespeed-db status or litespeed-db optimize.\n' >&2; exit 2 ;;
esac

# Built-in WP-CLI commands may safely use normal global parameters because they
# do not require LiteSpeed to load. The LiteSpeed command itself must not use
# this helper.
_wp_builtin() {
  local site="$1"; shift
  wp "$@" --path="$site" --skip-plugins --skip-themes --skip-packages --no-color
}

_wp_bootstrap_ok() { _wp_builtin "$1" core is-installed >/dev/null 2>&1; }
_lscwp_installed() { _wp_builtin "$1" plugin is-installed litespeed-cache >/dev/null 2>&1; }
_lscwp_active() { _wp_builtin "$1" plugin is-active litespeed-cache >/dev/null 2>&1; }
_lscwp_command_available() {
  local site="$1"
  (cd "$site" 2>/dev/null && PAGER=cat WP_CLI_PAGER=cat wp help litespeed-database optimize_all >/dev/null 2>&1)
}
_is_multisite() { _wp_builtin "$1" core is-installed --network >/dev/null 2>&1; }

_preflight_site() {
  # Prints: STATE<TAB>DETAIL where STATE is READY, SKIP, or ERROR.
  local site="$1"
  if ! _wp_bootstrap_ok "$site"; then
    printf 'ERROR\tWordPress/WP-CLI bootstrap failed\n'
    return 0
  fi
  if ! _lscwp_installed "$site"; then
    printf 'SKIP\tLiteSpeed Cache is not installed\n'
    return 0
  fi
  if ! _lscwp_active "$site"; then
    printf 'SKIP\tLiteSpeed Cache is installed but inactive\n'
    return 0
  fi
  if ! _lscwp_command_available "$site"; then
    printf 'ERROR\tLiteSpeed Cache is active but litespeed-database optimize_all is unavailable\n'
    return 0
  fi
  if _is_multisite "$site"; then
    printf 'READY\tmultisite detected; LiteSpeed optimize_all without blog <id> targets its default blog\n'
  else
    printf 'READY\tLiteSpeed optimize_all available\n'
  fi
}

_show_command_output() {
  local file="$1"
  [ -s "$file" ] || return 0
  # Keep terminal output bounded. The full command output is intentionally not
  # treated as a security finding or persisted as scan evidence.
  tr -d '\r' < "$file" | head -8 | sed 's/^/        /'
}

_confirm_optimize() {
  local count="$1" ans=''
  [ "${PRESSWARDEN_INTERACTIVE:-1}" = 0 ] && return 0
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf '\n  Run LiteSpeed optimize_all for %s eligible WordPress installation(s) under %s? [y/N]: ' "$count" "$ROOT" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) printf 'Cancelled.\n'; return 1 ;; esac
  fi
  printf 'Refusing LiteSpeed database optimization without an interactive terminal. Set PRESSWARDEN_INTERACTIVE=0 only for intentional automation.\n' >&2
  return 1
}

_status() {
  local site label row state detail ready=0 skipped=0 failed=0 multisite=0
  require_wp; discover_sites
  printf 'LiteSpeed database maintenance status — %s discovered WordPress installation(s)\n\n' "${#WP_SITES[@]}"
  for site in "${WP_SITES[@]}"; do
    label=$(site_label_from_root "$site")
    row=$(_preflight_site "$site")
    IFS=$'\t' read -r state detail <<< "$row"
    case "$state" in
      READY)
        ready=$((ready+1))
        [[ "$detail" == multisite* ]] && multisite=$((multisite+1))
        printf '  ✓ %-34s READY  %s\n' "$label" "$detail"
        ;;
      SKIP)
        skipped=$((skipped+1))
        printf '  - %-34s SKIP   %s\n' "$label" "$detail"
        ;;
      *)
        failed=$((failed+1))
        printf '  ✖ %-34s ERROR  %s\n' "$label" "$detail"
        ;;
    esac
  done
  printf '\nSummary: ready %s • skipped %s • errors %s' "$ready" "$skipped" "$failed"
  [ "$multisite" -eq 0 ] || printf ' • multisite warnings %s' "$multisite"
  printf '\n'
  [ "$multisite" -eq 0 ] || printf 'Note: PressWarden does not claim full multisite-network cleanup when LiteSpeed defaults to a single blog.\n'
  [ "$failed" -eq 0 ] || return 2
}

_optimize() {
  local site label row state detail out rc
  local ready=0 skipped=0 preflight_failed=0 optimized=0 failed=0 multisite=0
  local -a eligible=()
  require_wp; discover_sites

  printf 'LiteSpeed database optimization preflight — %s discovered WordPress installation(s)\n' "${#WP_SITES[@]}"
  printf 'Action: wp litespeed-database optimize_all\n'
  printf 'This is LiteSpeed Cache full database cleanup/optimization, not only SQL table optimization.\n\n'

  for site in "${WP_SITES[@]}"; do
    label=$(site_label_from_root "$site")
    row=$(_preflight_site "$site")
    IFS=$'\t' read -r state detail <<< "$row"
    case "$state" in
      READY)
        ready=$((ready+1)); eligible+=("$site")
        [[ "$detail" == multisite* ]] && multisite=$((multisite+1))
        printf '  ✓ %-34s READY  %s\n' "$label" "$detail"
        ;;
      SKIP)
        skipped=$((skipped+1))
        printf '  - %-34s SKIP   %s\n' "$label" "$detail"
        ;;
      *)
        preflight_failed=$((preflight_failed+1))
        printf '  ✖ %-34s ERROR  %s\n' "$label" "$detail"
        ;;
    esac
  done

  if [ "${#eligible[@]}" -eq 0 ]; then
    printf '\nNo eligible LiteSpeed Cache sites found; nothing changed.\n'
    [ "$preflight_failed" -eq 0 ] || return 2
    return 0
  fi

  [ "$multisite" -eq 0 ] || printf '\nWarning: %s multisite installation(s) use LiteSpeed\x27s default blog when no blog <id> is supplied; PressWarden will not claim network-wide cleanup for them.\n' "$multisite"
  _confirm_optimize "${#eligible[@]}" || return 1

  printf '\nRunning LiteSpeed database optimization sequentially...\n'
  for site in "${eligible[@]}"; do
    label=$(site_label_from_root "$site")
    out=$(tmpf)
    # IMPORTANT: do not add --path, --skip-plugins, --skip-themes, --no-color,
    # or other WP-CLI global parameters to litespeed-database. LiteSpeed's CLI
    # documents this command family as not accepting default WP-CLI parameters.
    (cd "$site" && wp litespeed-database optimize_all) > "$out" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
      optimized=$((optimized+1))
      printf '  ✓ %-34s OPTIMIZED\n' "$label"
      _show_command_output "$out"
    else
      failed=$((failed+1))
      printf '  ✖ %-34s FAILED  exit %s\n' "$label" "$rc"
      _show_command_output "$out"
    fi
    rm -f "$out"
  done

  printf '\nSummary: optimized %s • skipped %s • preflight errors %s • execution failures %s\n' "$optimized" "$skipped" "$preflight_failed" "$failed"
  [ "$preflight_failed" -eq 0 ] && [ "$failed" -eq 0 ] || return 2
}

case "$ACTION" in
  status) _status ;;
  optimize) _optimize ;;
esac
