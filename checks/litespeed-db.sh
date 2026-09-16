#!/usr/bin/env bash
# litespeed-db — LiteSpeed Cache database cleanup/optimization.
#
# LiteSpeed's litespeed-database command family does not accept normal
# WP-CLI global parameters. Every real cleanup invocation therefore runs
# from the WordPress directory with no --path/--skip-*/--no-color flags.
set -uo pipefail
NAME=litespeed-db
DESC="LiteSpeed Cache database cleanup and optimization"
SCAN_DOES="Checks LiteSpeed Cache database-command availability and runs optimize_all for eligible WordPress installations."
SCAN_WHY="LiteSpeed can remove revisions, drafts, trash, comments, trackbacks, transients and other database clutter before PressWarden performs native SQL table maintenance."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

SUITE_MODE="${PW_LITESPEED_DB_SUITE:-0}"
ACTION="${1:-status}"
if [ "$#" -eq 0 ] && [ "$SUITE_MODE" = 1 ]; then ACTION=optimize; fi
case "$ACTION" in
  status|optimize) : ;;
  *) printf 'Use litespeed-db status or litespeed-db optimize.\n' >&2; exit 2 ;;
esac

_suite_cleanup_enabled() {
  case "${PRESSWARDEN_LITESPEED_DB_MAINTENANCE:-1}" in
    0|false|FALSE|no|NO|off|OFF) return 1 ;;
    *) return 0 ;;
  esac
}

if [ "$SUITE_MODE" = 1 ] && ! _suite_cleanup_enabled; then
  printf 'LiteSpeed database cleanup — SKIP (PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0)\n'
  exit 0
fi

# Built-in WP-CLI commands may use normal global parameters because they do
# not invoke the exceptional LiteSpeed database command family.
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

# Print one validated positive blog ID per line. The full list is validated
# before any multisite cleanup begins, so malformed/partial inventory cannot
# lead to a false network-wide success claim.
_multisite_blog_ids() {
  local site="$1" raw id clean seen='' count=0
  raw=$(_wp_builtin "$site" site list --field=blog_id 2>/dev/null) || return 1
  while IFS= read -r id; do
    clean="$id"
    clean="${clean#"${clean%%[![:space:]]*}"}"
    clean="${clean%"${clean##*[![:space:]]}"}"
    [ -n "$clean" ] || continue
    case "$clean" in *[!0-9]*) return 1 ;; esac
    [ "$clean" -gt 0 ] 2>/dev/null || return 1
    case " $seen " in *" $clean "*) continue ;; esac
    printf '%s\n' "$clean"
    seen="$seen $clean"
    count=$((count+1))
  done <<< "$raw"
  [ "$count" -gt 0 ]
}

# `wp db size --size_format=b` is best-effort telemetry. Failure to measure
# allocation never blocks cleanup or changes the maintenance verdict.
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
  # Prints STATE<TAB>DETAIL where STATE is READY, SKIP, or ERROR.
  local site="$1" ids count
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
    ids=$(_multisite_blog_ids "$site") || {
      printf 'ERROR\tmultisite blog-ID inventory failed; no cleanup will be attempted\n'
      return 0
    }
    count=$(printf '%s\n' "$ids" | awk 'NF { n++ } END { print n+0 }')
    printf 'READY\tmultisite detected; %s validated blog(s) will be cleaned\n' "$count"
  else
    printf 'READY\tLiteSpeed optimize_all available\n'
  fi
}

_show_command_output() {
  local file="$1"
  [ -s "$file" ] || return 0
  tr -d '\r' < "$file" | head -12 | sed 's/^/        /'
}

_confirm_optimize() {
  local count="$1" ans=''
  [ "$SUITE_MODE" = 1 ] && return 0
  [ "${PRESSWARDEN_INTERACTIVE:-1}" = 0 ] && return 0
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    printf '\n  Run LiteSpeed optimize_all for %s eligible WordPress installation(s) under %s? [y/N]: ' "$count" "$ROOT" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) printf 'Cancelled.\n'; return 1 ;; esac
  fi
  printf 'Refusing LiteSpeed database optimization without an interactive terminal. Set PRESSWARDEN_INTERACTIVE=0 only for intentional automation.\n' >&2
  return 1
}

# Result globals for one installation.
LSDB_RUN_BLOG_TOTAL=1
LSDB_RUN_BLOG_DONE=0
LSDB_RUN_FAILED_BLOG=''
LSDB_RUN_ENUM_FAILED=0

_run_site_optimization() {
  local site="$1" multisite="$2" out="$3" ids blog rc
  local -a blogs=()
  LSDB_RUN_BLOG_TOTAL=1
  LSDB_RUN_BLOG_DONE=0
  LSDB_RUN_FAILED_BLOG=''
  LSDB_RUN_ENUM_FAILED=0

  if [ "$multisite" = 1 ]; then
    ids=$(_multisite_blog_ids "$site") || {
      printf 'Multisite blog-ID inventory failed before cleanup; no blog was changed.\n' > "$out"
      LSDB_RUN_ENUM_FAILED=1
      return 96
    }
    while IFS= read -r blog; do [ -n "$blog" ] && blogs+=("$blog"); done <<< "$ids"
    [ "${#blogs[@]}" -gt 0 ] || {
      printf 'Multisite blog-ID inventory was empty; no blog was changed.\n' > "$out"
      LSDB_RUN_ENUM_FAILED=1
      return 96
    }
    LSDB_RUN_BLOG_TOTAL=${#blogs[@]}
    : > "$out" || return 97
    for blog in "${blogs[@]}"; do
      printf 'Blog %s:\n' "$blog" >> "$out"
      # Do not add WP-CLI global parameters here.
      (cd "$site" && wp litespeed-database optimize_all blog "$blog") >> "$out" 2>&1
      rc=$?
      if [ "$rc" -ne 0 ]; then
        LSDB_RUN_FAILED_BLOG="$blog"
        return "$rc"
      fi
      LSDB_RUN_BLOG_DONE=$((LSDB_RUN_BLOG_DONE+1))
    done
    return 0
  fi

  # Do not add WP-CLI global parameters here.
  (cd "$site" && wp litespeed-database optimize_all) > "$out" 2>&1
  rc=$?
  [ "$rc" -ne 0 ] || LSDB_RUN_BLOG_DONE=1
  return "$rc"
}

LSDB_PHASE=''
_lsdb_interrupt() {
  trap - INT TERM
  if [ "$LSDB_PHASE" = preflight ]; then
    printf '\nInterrupted during LiteSpeed database preflight; no databases were changed.\n' >&2
  elif [ "$LSDB_PHASE" = optimize ]; then
    printf '\nInterrupted during LiteSpeed database optimization; installations and multisite blogs already completed remain optimized.\n' >&2
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
  [ "$multisite" -eq 0 ] || printf ' • multisite installations %s' "$multisite"
  printf '\n'
  [ "$failed" -eq 0 ] || return 2
}

_optimize() {
  local site label row state detail out rc before after delta elapsed started ended is_multi scope_desc
  local ready=0 skipped=0 preflight_failed=0 optimized=0 failed=0 multisite=0
  local idx=0 total exec_idx=0 exec_total measured=0 reduced_sites=0 unchanged_sites=0 increased_sites=0
  local total_before=0 total_after=0 total_delta=0 completed_blog_scopes=0
  local -a eligible=() eligible_multisite=()
  require_wp; discover_sites
  total=${#WP_SITES[@]}

  trap _lsdb_interrupt INT TERM
  LSDB_PHASE=preflight
  printf 'LiteSpeed database optimization preflight — %s discovered WordPress installation(s)\n' "$total"
  printf 'Action: wp litespeed-database optimize_all [blog <id>]\n'
  if [ "$SUITE_MODE" = 1 ]; then
    printf 'Mode: DB maintenance suite (runs before native SQL table maintenance).\n'
  else
    printf 'This is LiteSpeed Cache full database cleanup/optimization, not only SQL table optimization.\n'
  fi
  printf '\n'

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

  _confirm_optimize "${#eligible[@]}" || { trap - INT TERM; LSDB_PHASE=''; return 1; }

  LSDB_PHASE=optimize
  exec_total=${#eligible[@]}
  printf '\nRunning LiteSpeed database optimization sequentially...\n'
  for site in "${eligible[@]}"; do
    exec_idx=$((exec_idx+1))
    label=$(site_label_from_root "$site")
    is_multi=${eligible_multisite[$((exec_idx-1))]}
    before=$(_db_size_bytes "$site" 2>/dev/null || true)
    out=$(tmpf)
    started=$(date +%s)
    _run_site_optimization "$site" "$is_multi" "$out"
    rc=$?
    ended=$(date +%s); elapsed=$((ended-started))
    completed_blog_scopes=$((completed_blog_scopes+LSDB_RUN_BLOG_DONE))

    if [ "$rc" -eq 0 ]; then
      optimized=$((optimized+1))
      after=$(_db_size_bytes "$site" 2>/dev/null || true)
      if [ "$is_multi" = 1 ]; then scope_desc="${LSDB_RUN_BLOG_TOTAL} blogs"; else scope_desc='single site'; fi
      if [ -n "$before" ] && [ -n "$after" ]; then
        measured=$((measured+1)); total_before=$((total_before+before)); total_after=$((total_after+after)); delta=$((before-after))
        if [ "$delta" -gt 0 ]; then
          reduced_sites=$((reduced_sites+1))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s • %s → %s • reported reduction %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$scope_desc" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$(_format_bytes "$delta")" "$elapsed"
        elif [ "$delta" -eq 0 ]; then
          unchanged_sites=$((unchanged_sites+1))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s • %s → %s • no reported size change  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$scope_desc" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$elapsed"
        else
          increased_sites=$((increased_sites+1)); delta=$((-delta))
          printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s • %s → %s • reported increase %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$scope_desc" "$(_format_bytes "$before")" "$(_format_bytes "$after")" "$(_format_bytes "$delta")" "$elapsed"
        fi
      else
        printf '  [%3d/%3d] ✓ %-34s OPTIMIZED  %s • database size unavailable  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$scope_desc" "$elapsed"
      fi
      _show_command_output "$out"
    else
      failed=$((failed+1))
      if [ "$is_multi" = 1 ] && [ "$LSDB_RUN_ENUM_FAILED" -eq 1 ]; then
        printf '  [%3d/%3d] ✖ %-34s FAILED  multisite inventory; no blog changed  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$elapsed"
      elif [ "$is_multi" = 1 ]; then
        printf '  [%3d/%3d] ✖ %-34s FAILED  blog %s; %s/%s blog(s) completed • exit %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "${LSDB_RUN_FAILED_BLOG:-unknown}" "$LSDB_RUN_BLOG_DONE" "$LSDB_RUN_BLOG_TOTAL" "$rc" "$elapsed"
      else
        printf '  [%3d/%3d] ✖ %-34s FAILED  exit %s  (%ss)\n' "$exec_idx" "$exec_total" "$label" "$rc" "$elapsed"
      fi
      _show_command_output "$out"
    fi
    rm -f "$out"
  done

  trap - INT TERM
  LSDB_PHASE=''
  printf '\nLiteSpeed database optimization complete.\n'
  printf 'Summary: optimized installations %s • completed blog scopes %s • skipped %s • preflight errors %s • execution failures %s\n' "$optimized" "$completed_blog_scopes" "$skipped" "$preflight_failed" "$failed"
  if [ "$measured" -gt 0 ]; then
    total_delta=$((total_before-total_after))
    printf 'Measured database size (%s installation(s)): %s → %s' "$measured" "$(_format_bytes "$total_before")" "$(_format_bytes "$total_after")"
    if [ "$total_delta" -gt 0 ]; then
      printf ' • reported reduction %s' "$(_format_bytes "$total_delta")"
    elif [ "$total_delta" -eq 0 ]; then
      printf ' • no reported aggregate size change'
    else
      total_delta=$((-total_delta)); printf ' • reported increase %s' "$(_format_bytes "$total_delta")"
    fi
    printf '\n'
    printf 'Size results: reduced %s • unchanged %s • increased %s\n' "$reduced_sites" "$unchanged_sites" "$increased_sites"
    printf 'Note: database allocation can stay unchanged or grow after rows are cleaned; these are size measurements, not deleted-record counts.\n'
  fi
  [ "$preflight_failed" -eq 0 ] && [ "$failed" -eq 0 ] || return 2
}

case "$ACTION" in
  status) _status ;;
  optimize) _optimize ;;
esac
