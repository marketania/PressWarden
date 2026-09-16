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

# `wp db size --size_format=b` returns a bare byte count. It is intentionally
# separate from the LiteSpeed command because LiteSpeed's database CLI rejects
# normal WP-CLI global parameters. Failure to measure size never blocks cleanup.
_db_size_bytes() {
  local site="$1" n
  n=$(_wp_builtin "$site" db size --size_format=b 2>/dev/null | tr -d '[:space:]') || return 1
  case "$n" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s' "$n"
}

_format_bytes() {
  awk -v n="${1:-0}" 'BEGIN {
    split("B KB MB GB TB", u, " "); i=1;
    while (n >= 1024 && i < 5) { n/=1024; i++ }
    if (i == 1) printf "%.0f %s", n, u[i];
    else if (n >= 100) printf "%.0f %s", n, u[i];
    else if (n >= 10) printf "%.1f %s", n, u[i];
    else printf "%.2f %s", n, u[i];
  }'
}

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

LSDB_PHASE=''
_lsdb_interrupt() {
  trap - INT TERM
  if [ "$LSDB_PHASE" = preflight ]; then
    printf '\nInterrupted during LiteSpeed database preflight; no databases were changed.\n' >&2
  elif [ "$LSDB_PHASE" = optimize ]; then
    printf '\nInterrupted during LiteSpeed database optimization; sites already completed remain optimized.\n' >&2
  else
    printf '\nLiteSpeed database operation interrupted.\n' >&2
  fi
  exit 130
}

_status() {
  local site label row state detail ready=0 skipped=0 failed=0 multisite=0 idx=0 total
  require_wp; discover_sites
  total=${#WP_SITES[@]}
  printf 'LiteSpeed database maintenance status — %s discovered WordPress installation(s)\n\n' "$total"
  for site in "${WP_SITES[@]}"; do
    idx=$((idx+1))
    label=$(site_label_from_root "$site")
    row=$(_preflight_site "$site")
    IFS=$'\t' read -r state detail <<< "$row"
    case "$state" in
      READY)
        ready=$((ready+1))
        [[ "$detail" == multisite* ]] && multisite=$((multisite+1))
        printf '  [%3d/%3d] ✓ %-34s READY  %s\n' "$idx" "$total" "$label" "$detail"
        ;;
      SKIP)
        skipped=$((skipped+1))
        printf '  [%3d/%3d] - %-34s SKIP   %s\n' "$idx" "$total" "$label" "$detail"
        ;;
      *)
        failed=$((failed+1))
        printf '  [%3d/%3d] ✖ %-34s ERROR  %s\n' "$idx" "$total" "$label" "$detail"
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
  local site label row state detail out rc before after delta elapsed started ended
  local ready=0 skipped=0 preflight_failed=0 optimized=0 failed=0 multisite=0
  local idx=0 total exec_idx=0 exec_total measured=0 reduced_sites=0 unchanged_sites=0 increased_sites=0
  local total_before=0 total_after=0 total_delta=0
  local -a eligible=() eligible_multisite=()
  require_wp; discover_sites
  total=${#WP_SITES[@]}

  trap _lsdb_interrupt INT TERM
  LSDB_PHASE=preflight
  printf 'LiteSpeed database optimization preflight — %s discovered WordPress installation(s)\n' "$total"
  printf 'Action: wp litespeed-database optimize_all\n'
  printf 'This is LiteSpeed Cache full database cleanup/optimization, not only SQL table optimization.\n\n'

  for site in "${WP_SITES[@]}"; do
    idx=$((idx+1))
    label=$(site_label_from_root "$site")
    row=$(_preflight_site "$site")
    IFS=$'\t' read -r state detail <<< "$row"
    case "$state" in
      READY)
        ready=$((ready+1)); eligible+=("$site")
        if [[ "$detail" == multisite* ]]; then
          multisite=$((multisite+1)); eligible_multisite+=("1")
        else
          eligible_multisite+=("0")
        fi
        printf '  [%3d/%3d] ✓ %-34s READY  %s\n' "$idx" "$total" "$label" "$detail"
        ;;
      SKIP)
        skipped=$((skipped+1))
        printf '  [%3d/%3d] - %-34s SKIP   %s\n' "$idx" "$total" "$label" "$detail"
        ;;
      *)
        preflight_failed=$((preflight_failed+1))
        printf '  [%3d/%3d] ✖ %-34s ERROR  %s\n' "$idx" "$total" "$label" "$detail"
        ;;
    esac
  done

  printf '\nPreflight complete: ready %s • skipped %s • errors %s\n' "$ready" "$skipped" "$preflight_failed"
  if [ "${#eligible[@]}" -eq 0 ]; then
    printf 'No eligible LiteSpeed Cache sites found; nothing changed.\n'
    trap - INT TERM
    LSDB_PHASE=''
    [ "$preflight_failed" -eq 0 ] || return 2
    return 0
  fi

  [ "$multisite" -eq 0 ] || printf 'Warning: %s multisite installation(s) use LiteSpeed\x27s default blog when no blog <id> is supplied; PressWarden will not claim network-wide cleanup or database-size savings for them.\n' "$multisite"
  _confirm_optimize "${#eligible[@]}" || { trap - INT TERM; LSDB_PHASE=''; return 1; }

  LSDB_PHASE=optimize
  exec_total=${#eligible[@]}
  printf '\nRunning LiteSpeed database optimization sequentially...\n'
  for site in "${eligible[@]}"; do
    exec_idx=$((exec_idx+1))
    label=$(site_label_from_root "$site")
    before=''; after=''
    if [ "${eligible_multisite[$((exec_idx-1))]}" = 0 ]; then
      before=$(_db_size_bytes "$site" 2>/dev/null || true)
    fi
    out=$(tmpf)
    started=$(date +%s)
    # IMPORTANT: do not add --path, --skip-plugins, --skip-themes, --no-color,
    # or other WP-CLI global parameters to litespeed-database. LiteSpeed's CLI
    # documents this command family as not accepting default WP-CLI parameters.
    (cd "$site" && wp litespeed-database optimize_all) > "$out" 2>&1
    rc=$?
    ended=$(date +%s); elapsed=$((ended-started))
    if [ "$rc" -eq 0 ]; then
      optimized=$((optimized+1))
      if [ "${eligible_multisite[$((exec_idx-1))]}" = 0 ]; then
        after=$(_db_size_bytes "$site" 2>/dev/null || true)
      fi
      if [ -n "$before" ] && [ -n "$after" ]; then
        measured=$((measured+1)); total_before=$((total_before+before)); total_after=$((total_after+after)); delta=$((before-after))
        if [ "$delta" -gt 0 ]; then
          reduced_sites=$((reduced_sites+1))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s → %s  reported reduction %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$(_format_bytes "$delta")" "$elapsed"
        elif [ "$delta" -eq 0 ]; then
          unchanged_sites=$((unchanged_sites+1))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s → %s  no reported size change  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$elapsed"
        else
          increased_sites=$((increased_sites+1)); delta=$((-delta))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s → %s  reported increase %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$(_format_bytes "$delta")" "$elapsed"
        fi
      elif [ "${eligible_multisite[$((exec_idx-1))]}" = 1 ]; then
        printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  size statistics skipped for multisite  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$elapsed"
      else
        printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  database size unavailable  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$elapsed"
      fi
      _show_command_output "$out"
    else
      failed=$((failed+1))
      printf '  [%3d/%3d] ✖ %-34s FAILED  exit %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$rc" "$elapsed"
      _show_command_output "$out"
    fi
    rm -f "$out"
  done

  trap - INT TERM
  LSDB_PHASE=''
  printf '\nLiteSpeed database optimization complete.\n'
  printf 'Summary: optimized %s • skipped %s • preflight errors %s • execution failures %s\n' "$optimized" "$skipped" "$preflight_failed" "$failed"
  if [ "$measured" -gt 0 ]; then
    total_delta=$((total_before-total_after))
    printf 'Measured database size (%s site(s)): %s → %s' "$measured" "$(_format_bytes "$total_before")" "$(_format_bytes "$total_after")"
    if [ "$total_delta" -gt 0 ]; then
      printf ' • reported reduction %s' "$(_format_bytes "$total_delta")"
    elif [ "$total_delta" -eq 0 ]; then
      printf ' • no reported aggregate size change'
    else
      total_delta=$((-total_delta)); printf ' • reported increase %s' "$(_format_bytes "$total_delta")"
    fi
    printf '\n'
    printf 'Size results: reduced %s • unchanged %s • increased %s\n' "$reduced_sites" "$unchanged_sites" "$increased_sites"
    printf 'Note: reported database allocation can stay unchanged or grow even after rows are cleaned; these figures are size measurements, not counts of deleted records.\n'
  fi
  [ "$preflight_failed" -eq 0 ] && [ "$failed" -eq 0 ] || return 2
}

case "$ACTION" in
  status) _status ;;
  optimize) _optimize ;;
esac
