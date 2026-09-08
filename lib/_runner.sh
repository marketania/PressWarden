# _runner.sh — shared driver for PressWarden suites.
NAME="${RUN_NAME:-runall}"; DESC="${RUN_DESC:-}"
SUITE_DOES="${RUN_DOES:-}"
SUITE_WHY="${RUN_WHY:-}"
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
# Refresh discovery once per suite; children reuse the validated snapshot.
PRESSWARDEN_DISCOVERY_REFRESH=0; export PRESSWARDEN_DISCOVERY_REFRESH

strip_ansi() { sed $'s/\033\\[[0-9;]*[[:alpha:]]//g'; }

admin_check_wanted() {
  case "${PRESSWARDEN_ADMINS_CHECK:-}" in
    1|y|Y|yes|YES|run|RUN|true|TRUE) return 0 ;;
    0|n|N|no|NO|skip|SKIP|false|FALSE) return 1 ;;
  esac
  if [ "${PRESSWARDEN_INTERACTIVE:-1}" != 0 ] && [ -t 0 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    local ans=''
    printf '\n  %s%sADMINS CHECK%s  Run administrator inventory + application-password inventory? %s[y/N]%s: ' "$B" "$Y" "$X" "$B" "$X" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
  fi
  return 1
}

uploads_deep_check_wanted() {
  case "${PRESSWARDEN_UPLOADS_DEEP:-}" in
    1|y|Y|yes|YES|run|RUN|true|TRUE) return 0 ;;
    0|n|N|no|NO|skip|SKIP|false|FALSE) return 1 ;;
  esac
  if [ "${PRESSWARDEN_INTERACTIVE:-1}" != 0 ] && [ -t 0 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    local ans=''
    printf '\n  %s%sSLOW CHECK%s  Scan image-like uploads for embedded PHP? This can take a long time on large fleets. %s[y/N]%s: ' "$B" "$Y" "$X" "$B" "$X" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
  fi
  return 1
}

_run_checks() {
  local c rc n out seen="" start elapsed force="" total_checks=0 current_check=0 check_path
  local -a pipeline_status
  [ -n "$C" ] && force=1
  total_checks=$(printf '%s\n' $CHECKS | sort -u | grep -c .)

  printf '\n%s%s' "$B" "$C"; _repeat '═' "$W"; printf '%s\n' "$X"
  printf '%s%s  PRESSWARDEN SUITE%s  %s%s%s\n' "$B" "$C" "$X" "$B" "$NAME" "$X"
  [ -z "${PW_REPORT_ID:-}" ] || _meta_field 10 "RUN" "$PW_REPORT_ID"
  _meta_field 10 "MODE" "$DESC"
  _meta_field 10 "CHECKS" "$SUITE_DOES"
  _meta_field 10 "WHY" "$SUITE_WHY"
  printf '  %s%-10s%s %s\n' "$D" "ROOT" "$X" "$ROOT"
  printf '  %s%-10s%s %s%s%s WordPress install(s) across %s site group(s)\n' "$D" "SITES" "$X" "$B" "$(count_sites)" "$X" "$(count_domains)"
  [ "${#NESTED_SITES[@]}" -gt 0 ] && _meta_field 10 "NESTED" "$(nested_sites_summary)"
  [ "${#MANUAL_EXCLUDED_DOMAINS[@]}" -gt 0 ] && _meta_field 10 "EXCLUDED" "$(manual_exclusions_summary)"
  printf '  %s%-10s%s %s\n' "$D" "COUNT" "$X" "$total_checks"
  printf '  %s%-10s%s %s\n' "$D" "STARTED" "$X" "$(date '+%Y-%m-%d %H:%M:%S')"
  printf '%s%s' "$B" "$C"; _repeat '═' "$W"; printf '%s\n' "$X"
  if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    printf '  INCOMPLETE: no validated WordPress installations found; no site scan performed.\n' >&2
    return 2
  fi

  for c in $CHECKS; do
    case " $seen " in *" $c "*) continue ;; esac
    seen="$seen $c"; current_check=$((current_check+1)); check_path="$PRESSWARDEN_DIR/checks/$c.sh"
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
      printf '\n%s%s▶ SKIP%s %s[%s/%s]%s  %s%s%s  %s(administrator checks skipped)%s\n' "$B" "$Y" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$D" "$X"
      printf '%s|0|skipped|0\n' "$c" >> "$RES" || return 2; continue
    fi
    if [ "$c" = "wp-uploads-deep" ] && ! uploads_deep_check_wanted; then
      printf '\n%s%s▶ SKIP%s %s[%s/%s]%s  %s%s%s  %s(slow image-content scan skipped)%s\n' "$B" "$Y" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$D" "$X"
      printf '%s|0|skipped|0\n' "$c" >> "$RES" || return 2; continue
    fi
    if [ ! -r "$check_path" ]; then
      printf '\n%s%s▶ RUN%s  %s[%s/%s]%s  %s%s%s  %s(missing/unreadable)%s\n' "$B" "$BL" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$Y" "$X"
      printf '%s|-|missing|0\n' "$c" >> "$RES" || return 2; continue
    fi
    printf '\n%s%s▶ RUN%s  %s[%s/%s]%s  %s%s%s\n' "$B" "$BL" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X"
    start=$(date +%s); out=$(tmpf)
    if [ -n "$force" ]; then
      PRESSWARDEN_FORCE_COLOR=1 bash "$check_path" 2>&1 | tee "$out"
      pipeline_status=("${PIPESTATUS[@]}")
    else
      bash "$check_path" 2>&1 | tee "$out"
      pipeline_status=("${PIPESTATUS[@]}")
    fi
    rc=${pipeline_status[0]}
    [ "${pipeline_status[1]:-0}" -eq 0 ] || rc=2
    elapsed=$(( $(date +%s) - start ))
    n=$(strip_ansi < "$out" | grep -oE 'findings:[[:space:]]*[0-9]+' | tail -1 | grep -oE '[0-9]+$')
    rm -f "$out"
    case "$rc" in
      0) printf '%s|%s|clean|%s\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2 ;;
      1) printf '%s|%s|findings|%s\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2 ;;
      *) printf '%s|%s|ERROR rc=%s|%s\n' "$c" "${n:--}" "$rc" "$elapsed" >> "$RES" || return 2 ;;
    esac
  done

  local el=$(( $(date +%s) - T0 )) grand=0 st col icon tm failed=0 skipped=0 completed=0
  printf '\n\n%s%s  SUITE SUMMARY%s\n' "$B" "$C" "$X"; _rule
  printf '  %s%-20s %10s   %-12s   %s%s\n' "$D" "CHECK" "FINDINGS" "STATUS" "TIME" "$X"
  while IFS='|' read -r c n st tm; do
    [ -n "$c" ] || continue
    case "$n" in ''|*[!0-9]*) : ;; *) grand=$((grand+n)) ;; esac
    case "$st" in
      clean) col="$G"; icon='✓'; completed=$((completed+1)) ;;
      findings) col="$R"; icon='✖'; completed=$((completed+1)) ;;
      skipped) col="$Y"; icon='↷'; skipped=$((skipped+1)) ;;
      *) col="$Y"; icon='⚠'; failed=$((failed+1)) ;;
    esac
    printf '  %-20s %10s   %s%s %-10s%s   %s\n' "$c" "$n" "$B" "$col" "$icon $st" "$X" "$(human_time "${tm:-0}")"
  done < "$RES"
  _rule
  if [ "$failed" -gt 0 ] || [ "$completed" -eq 0 ]; then
    printf '  %s%s⚠ INCOMPLETE%s  findings: %s   failed: %s   completed: %s   skipped: %s\n' "$B" "$Y" "$X" "$grand" "$failed" "$completed" "$skipped"
  elif [ "$grand" -gt 0 ]; then
    printf '  %s%s✖ ATTENTION%s  total findings: %s   skipped: %s   elapsed: %s\n' "$B" "$R" "$X" "$grand" "$skipped" "$(human_time "$el")"
  elif [ "$skipped" -gt 0 ]; then
    printf '  %s%s✓ NO FINDINGS IN COMPLETED CHECKS%s  completed: %s   skipped: %s   elapsed: %s\n' "$B" "$G" "$X" "$completed" "$skipped" "$(human_time "$el")"
  else
    printf '  %s%s✓ ALL CLEAR%s  total findings: %s   elapsed: %s\n' "$B" "$G" "$X" "$grand" "$(human_time "$el")"
  fi
  printf '  %sindividual reports:%s %s\n\n' "$D" "$X" "$REPORTS"
  [ "$failed" -eq 0 ] && [ "$completed" -gt 0 ] || return 2
  [ "$grand" -eq 0 ]
}

run_all() {
  pw_report_init "$NAME" || return 2
  local json rc json_written=0
  local -a pipeline_status
  RES=$(tmpf) || { pw_report_remove_empty; return 2; }
  _run_checks 2>&1 | tee "$LOG"; pipeline_status=("${PIPESTATUS[@]}"); rc=${pipeline_status[0]}
  if [ "${pipeline_status[1]:-0}" -ne 0 ]; then
    printf 'INCOMPLETE: suite console log could not be written.\n' >&2; rc=2
  fi
  if [ "${PRESSWARDEN_OUTPUT_JSON:-1}" != "0" ] && command -v php >/dev/null 2>&1; then
    json="$PW_REPORT_PREFIX-summary.json"
    if ! php "$PRESSWARDEN_DIR/lib/suite-summary.php" "$RES" "$json" "$NAME" "$PRESSWARDEN_VERSION" "$ROOT" "$(count_sites)" "$(count_domains)" "$rc" "$LOG"; then
      printf 'INCOMPLETE: suite JSON report could not be written.\n' >&2; rc=2
    else
      json_written=1
      php "$PRESSWARDEN_DIR/lib/report-json.php" latest "$json" "$REPORTS/$NAME-latest-summary.json" || rc=2
    fi
  fi
  rm -f "$RES"
  pw_report_remove_empty
  printf '%ssummary log:%s %s\n' "$D" "$X" "$LOG"
  [ "$json_written" -eq 1 ] && printf '%sJSON summary:%s %s\n' "$D" "$X" "$json"
  return "$rc"
}
