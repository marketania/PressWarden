#!/usr/bin/env bash
# Native table health + explicitly authorized LiteSpeed cleanup, then verification.
set -uo pipefail
NAME=wp-db-maintenance
DESC="database check, conditional repair, LiteSpeed cleanup, optimize and verify"
SCAN_DOES="Checks WordPress-prefixed tables, repairs genuine failures only, offers LiteSpeed cleanup, and verifies table health. Non-LiteSpeed sites retain native SQL optimization."
SCAN_WHY="Keeps database maintenance usable on restricted shared hosts while separating optional cleanup, unknown health, unsupported operations and genuine table failures."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"
. "$PRESSWARDEN_DIR/lib/litespeed-db.sh"

_db_native() {
  local site="$1" action="$2" out rc marker
  out=$(PRESSWARDEN_DB_ACTION="$action" wpq "$site" eval-file "$PRESSWARDEN_DIR/lib/db-maintenance.php"); rc=$?
  case "$action" in check|repair|optimize) ;; *) return 31 ;; esac
  # Exit zero alone is not proof that the helper actually executed.
  marker=$(printf '%s\n' "$out" | grep -Ec $'^PWDBM1\tDONE\t'"$action"$'\t[1-9][0-9]*$' || true)
  if { [ "$rc" -eq 0 ] || [ "$rc" -eq 10 ]; } && [ "$marker" != 1 ]; then rc=31; fi
  # Never print raw bootstrap errors, SQL or connection credentials.
  printf '%s\n' "$out" | grep -E $'^PWDBM1\t(BAD|UNRESOLVED|OPTFAIL|ERROR|SKIP|REPAIRED|OPTIMIZED)\t' | cut -f2- || true
  return "$rc"
}
_show_db_problems() {
  printf '%s\n' "$1" | grep -E '^(BAD|UNRESOLVED|OPTFAIL|ERROR)[[:space:]]' |
    awk 'NR <= 12 {gsub(/\t/, " > "); print "          " substr($0,1,300)}' || true
}
_db_skip_count() { printf '%s\n' "$1" | grep -cE '^SKIP[[:space:]]' || true; }

_cleanup_policy() {
  local policy="${PRESSWARDEN_DB_LITESPEED:-ask}" ans=''
  PW_DB_LS_ENABLED=0
  case "$policy" in
    on|1|true) PW_DB_LS_ENABLED=1 ;;
    off|0|false) ;;
    ask|'')
      if [ "${PRESSWARDEN_INTERACTIVE:-1}" != 0 ] && (exec 9<>/dev/tty && [ -t 9 ]) 2>/dev/null; then
        printf '\n  LiteSpeed optimize_all removes revisions, drafts/trash, comments and transients.\n  Confirm you have a current database backup. Include cleanup on eligible sites? [y/N]: ' > /dev/tty
        IFS= read -r ans < /dev/tty || ans=''
        case "$ans" in y|Y|yes|YES) PW_DB_LS_ENABLED=1 ;; esac
      fi ;;
    *) printf 'Invalid PRESSWARDEN_DB_LITESPEED; use ask, on or off. No maintenance started.\n' >&2; return 2 ;;
  esac
  if [ "$PW_DB_LS_ENABLED" = 1 ]; then
    note "LiteSpeed cleanup enabled; maintain a current database backup. No database backup is created by this command."
  else
    note "LiteSpeed cleanup skipped (not authorized). Use PRESSWARDEN_DB_LITESPEED=on for intentional unattended cleanup; native maintenance continues."
  fi
}

main() {
  require_wp; banner; discover_sites
  local s d out rc before after state detail row lsout started elapsed
  local repaired optimized health_bad runtime_failed optimize_failed ls_failed ls_done skip_n
  local repaired_n=0 optimized_n=0 unhealthy_n=0 runtime_n=0 unsupported_n=0
  local cleanup_n=0 cleanup_skipped_n=0 cleanup_failed_n=0 idx=0
  sec "Database maintenance" "${#WP_SITES[@]} sites • native SQL + optional LiteSpeed cleanup"
  note "workflow: CHECK → REPAIR genuine failures only → LiteSpeed cleanup or native OPTIMIZE → FINAL CHECK"
  note "Unsupported CHECK TABLE operations are informational and are not counted as unhealthy tables."
  note "Native maintenance and size reporting do not require proc_open/proc_close or an external MySQL client."
  _cleanup_policy || { PW_CHECK_INCOMPLETE=1; finish; return 2; }
  trap 'printf "\nDatabase maintenance interrupted; completed work remains, the current site may be partially changed.\n" >&2; exit 130' INT
  trap 'printf "\nDatabase maintenance terminated; the current site may be partially changed.\n" >&2; exit 143' TERM
  for s in "${WP_SITES[@]}"; do
    idx=$((idx+1)); d=$(site_domain "$s")
    state=''; repaired=0; optimized=0; health_bad=0; runtime_failed=0; optimize_failed=0; ls_failed=0; ls_done=0
    printf '\n    %s%s[%s/%s] %s%s\n' "$B" "$M" "$idx" "${#WP_SITES[@]}" "$d" "$X"
    before=''; after=''
    if ! pw_lsdb_is_multisite "$s"; then before=$(pw_lsdb_size_bytes "$s" || true); fi
    printf '      CHECK       running...\n'
    out=$(_db_native "$s" check); rc=$?; skip_n=$(_db_skip_count "$out"); unsupported_n=$((unsupported_n+skip_n))
    if [ "$rc" -eq 0 ]; then
      printf '      ✓ CHECK     no supported-table errors • unsupported checks: %s\n' "$skip_n"
    elif [ "$rc" -eq 10 ]; then
      _show_db_problems "$out"
      printf '      REPAIR      attempting genuine CHECK failures only...\n'
      out=$(_db_native "$s" repair); rc=$?
      if [ "$rc" -eq 0 ]; then
        repaired=1; repaired_n=$((repaired_n+1)); printf '      ✓ REPAIR    affected tables verified healthy\n'
      elif [ "$rc" -eq 10 ]; then
        health_bad=1; printf '      ✖ REPAIR    unresolved table problems; cleanup/optimization withheld\n'; _show_db_problems "$out"
      else
        runtime_failed=1; printf '      ✖ ENGINE    repair/verification unavailable (exit %s); not proof of corruption\n' "$rc"; _show_db_problems "$out"
      fi
    else
      runtime_failed=1; printf '      ✖ ENGINE    CHECK unavailable (exit %s); database health unknown\n' "$rc"; _show_db_problems "$out"
    fi

    if [ "$runtime_failed" -eq 0 ] && [ "$health_bad" -eq 0 ]; then
      if [ "$PW_DB_LS_ENABLED" = 1 ]; then
        row=$(pw_lsdb_preflight "$s"); IFS=$'\t' read -r state detail <<< "$row"
        if [ "$state" = READY ] && [[ "$detail" != multisite* ]]; then
          printf '      LITESPEED   optimize_all running...\n'
          lsout=$(tmpf) || { PW_CHECK_INCOMPLETE=1; finish; return 2; }
          started=$SECONDS
          pw_lsdb_run "$s" optimize_all > "$lsout" 2>&1; rc=$?; elapsed=$((SECONDS-started))
          if [ "$rc" -eq 0 ]; then
            ls_done=1; optimized=1; cleanup_n=$((cleanup_n+1))
            printf '      ✓ LITESPEED DB OPTIMIZED • %ss • native OPTIMIZE not repeated\n' "$elapsed"
          else
            ls_failed=1; printf '      ✖ LITESPEED FAILED (exit %s); partial cleanup possible • %ss\n' "$rc" "$elapsed"
          fi
          pw_lsdb_show_output "$lsout"; rm -f "$lsout"
        elif [ "$state" = SKIP ]; then
          printf '      - LITESPEED SKIP • %s; native optimization retained\n' "$detail"
        elif [ "$state" = READY ]; then
          printf '      - LITESPEED SKIP • multisite needs an explicit --blog=ID; native network-table maintenance retained\n'
        else
          ls_failed=1; printf '      ✖ LITESPEED UNAVAILABLE • %s; native optimization retained\n' "$detail"
        fi
      fi
      # A failed LiteSpeed execution is not hidden behind a second optimization.
      if [ "$ls_done" -eq 0 ] && [ "$ls_failed" -eq 0 ]; then
        printf '      OPTIMIZE    native SQL running...\n'
        out=$(_db_native "$s" optimize); rc=$?
        if [ "$rc" -eq 0 ]; then optimized=1; printf '      ✓ OPTIMIZE  completed\n'
        elif [ "$rc" -eq 10 ]; then optimize_failed=1; printf '      ✖ OPTIMIZE  one or more operations did not succeed\n'; _show_db_problems "$out"
        else runtime_failed=1; printf '      ✖ ENGINE    OPTIMIZE unavailable (exit %s)\n' "$rc"; _show_db_problems "$out"; fi
      fi
      # Missing plugin CLI still permits native SQL optimization, but stays INCOMPLETE.
      if [ "$ls_failed" = 1 ] && [ "${state:-}" != READY ]; then
        out=$(_db_native "$s" optimize); rc=$?
        if [ "$rc" -eq 0 ]; then optimized=1; printf '      ✓ OPTIMIZE  native fallback completed; LiteSpeed cleanup remains incomplete\n'
        else optimize_failed=1; printf '      ✖ OPTIMIZE  native fallback did not complete (exit %s)\n' "$rc"; _show_db_problems "$out"; fi
      fi
    fi

    if [ "$runtime_failed" -eq 0 ]; then
      printf '      VERIFY      final CHECK running...\n'
      out=$(_db_native "$s" check); rc=$?
      if [ "$rc" -eq 0 ]; then health_bad=0; printf '      ✓ VERIFY    no supported-table errors • unsupported checks: %s\n' "$(_db_skip_count "$out")"
      elif [ "$rc" -eq 10 ]; then health_bad=1; printf '      ✖ VERIFY    supported table problems remain\n'; _show_db_problems "$out"
      else runtime_failed=1; printf '      ✖ ENGINE    final verification unavailable (exit %s); health unknown\n' "$rc"; _show_db_problems "$out"; fi
    fi
    if [ -n "$before" ]; then after=$(pw_lsdb_size_bytes "$s" || true); fi
    if [ -n "$before" ] && [ -n "$after" ]; then
      printf '      SIZE        %s → %s (matching table prefix; allocated size)\n' "$(pw_lsdb_format_bytes "$before")" "$(pw_lsdb_format_bytes "$after")"
    else printf '      SIZE        unavailable or intentionally omitted for multisite\n'; fi
    [ "$optimized" -eq 0 ] || optimized_n=$((optimized_n+1))
    if [ "$ls_failed" -eq 1 ]; then cleanup_failed_n=$((cleanup_failed_n+1))
    elif [ "$ls_done" -eq 0 ]; then cleanup_skipped_n=$((cleanup_skipped_n+1)); fi
    if [ "$runtime_failed" -eq 1 ] || [ "$optimize_failed" -eq 1 ] || [ "$ls_failed" -eq 1 ]; then
      PW_CHECK_INCOMPLETE=1
      [ "$runtime_failed" -eq 0 ] || runtime_n=$((runtime_n+1))
      flag "$d" "database maintenance INCOMPLETE; review failed stages above"
    fi
    if [ "$health_bad" -eq 1 ]; then
      unhealthy_n=$((unhealthy_n+1)); issue "$d" "supported database tables remain unhealthy"
    elif [ "$runtime_failed" -eq 0 ] && [ "$optimize_failed" -eq 0 ] && [ "$ls_failed" -eq 0 ]; then
      if [ "$optimized" -eq 1 ]; then printf '      ✓ RESULT    optimized + verified%s\n' "$([ "$repaired" -eq 1 ] && printf ' + repaired')"
      else printf '      - RESULT    final CHECK passed; optimization was withheld\n'; fi
    fi
  done
  trap - INT TERM
  printf '\n    SUMMARY  repaired sites: %s • optimized sites: %s • unhealthy sites: %s • unsupported checks: %s • runtime errors: %s\n' "$repaired_n" "$optimized_n" "$unhealthy_n" "$unsupported_n" "$runtime_n"
  printf '    LITESPEED  optimized: %s • skipped: %s • failed: %s\n' "$cleanup_n" "$cleanup_skipped_n" "$cleanup_failed_n"
  note "Allocation may grow or remain unchanged after cleanup; these are not deleted-record counts or guaranteed disk savings."
  note "No reset, drop or import is performed. Authorized LiteSpeed cleanup does delete its configured cleanup categories."
  finish
}
run_logged wp-db-maintenance
