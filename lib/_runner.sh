# _runner.sh — shared driver for PressWarden suites.
NAME="${RUN_NAME:-runall}"; DESC="${RUN_DESC:-}"
SUITE_DOES="${RUN_DOES:-}"
SUITE_WHY="${RUN_WHY:-}"
. "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
# If the suite itself was launched with PRESSWARDEN_DISCOVERY_REFRESH=1, _lib refreshed once above.
# Child scanners should now reuse that validated snapshot instead of rescanning the tree.
PRESSWARDEN_DISCOVERY_REFRESH=0; export PRESSWARDEN_DISCOVERY_REFRESH

strip_ansi() { sed $'s/\033\\[[0-9;]*[[:alpha:]]//g'; }

admin_check_wanted() {
  case "${PRESSWARDEN_ADMINS_CHECK:-}" in
    1|y|Y|yes|YES|run|RUN|true|TRUE) return 0 ;;
    0|n|N|no|NO|skip|SKIP|false|FALSE) return 1 ;;
  esac
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
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
  if [ "${PRESSWARDEN_INTERACTIVE:-1}" != "0" ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
    local ans=''
    printf '\n  %s%sSLOW CHECK%s  Scan image-like uploads for embedded PHP? This can take a long time on large fleets. %s[y/N]%s: ' "$B" "$Y" "$X" "$B" "$X" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=''
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
  fi
  return 1
}

_run_checks() {
  local c rc n out seen="" start elapsed force="" total_checks=0 current_check=0 check_path
  [ -n "$C" ] && force=1
  total_checks=$(printf '%s\n' $CHECKS | sort -u | grep -c .)

  printf '\n%s%s' "$B" "$C"; _repeat '═' "$W"; printf '%s\n' "$X"
  printf '%s%s  PRESSWARDEN SUITE%s  %s%s%s\n' "$B" "$C" "$X" "$B" "$NAME" "$X"
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

  for c in $CHECKS; do
    case " $seen " in *" $c "*) continue ;; esac
    seen="$seen $c"; current_check=$((current_check+1)); check_path="$PRESSWARDEN_DIR/checks/$c.sh"
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
      printf '\n%s%s▶ SKIP%s %s[%s/%s]%s  %s%s%s  %s(administrator checks skipped)%s\n' "$B" "$Y" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$D" "$X"
      printf '%s|0|skipped|0\n' "$c" >> "$RES"; continue
    fi
    if [ "$c" = "wp-uploads-deep" ] && ! uploads_deep_check_wanted; then
      printf '\n%s%s▶ SKIP%s %s[%s/%s]%s  %s%s%s  %s(slow image-content scan skipped)%s\n' "$B" "$Y" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$D" "$X"
      printf '%s|0|skipped|0\n' "$c" >> "$RES"; continue
    fi
    if [ ! -r "$check_path" ]; then
      printf '\n%s%s▶ RUN%s  %s[%s/%s]%s  %s%s%s  %s(missing/unreadable)%s\n' "$B" "$BL" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$Y" "$X"
      printf '%s|-|missing|0\n' "$c" >> "$RES"; continue
    fi
    printf '\n%s%s▶ RUN%s  %s[%s/%s]%s  %s%s%s\n' "$B" "$BL" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X"
    start=$(date +%s); out=$(tmpf)
    if [ -n "$force" ]; then PRESSWARDEN_FORCE_COLOR=1 bash "$check_path" 2>&1 | tee "$out"; else bash "$check_path" 2>&1 | tee "$out"; fi
    rc=${PIPESTATUS[0]}; elapsed=$(( $(date +%s) - start ))
    n=$(strip_ansi < "$out" | grep -oE 'findings:[[:space:]]*[0-9]+' | tail -1 | grep -oE '[0-9]+$')
    rm -f "$out"
    case "$rc" in
      0) printf '%s|%s|clean|%s\n' "$c" "${n:-0}" "$elapsed" >> "$RES" ;;
      1) printf '%s|%s|findings|%s\n' "$c" "${n:-0}" "$elapsed" >> "$RES" ;;
      *) printf '%s|-|ERROR rc=%s|%s\n' "$c" "$rc" "$elapsed" >> "$RES" ;;
    esac
  done

  local el=$(( $(date +%s) - T0 )) grand=0 st col icon tm
  printf '\n\n%s%s  SUITE SUMMARY%s\n' "$B" "$C" "$X"; _rule
  printf '  %s%-20s %10s   %-12s   %s%s\n' "$D" "CHECK" "FINDINGS" "STATUS" "TIME" "$X"
  while IFS='|' read -r c n st tm; do
    [ -n "$c" ] || continue
    case "$st" in clean) col="$G"; icon='✓' ;; findings) col="$R"; icon='✖'; grand=$((grand + n)) ;; skipped) col="$Y"; icon='↷' ;; *) col="$Y"; icon='⚠' ;; esac
    printf '  %-20s %10s   %s%s %-10s%s   %s\n' "$c" "$n" "$B" "$col" "$icon $st" "$X" "$(human_time "${tm:-0}")"
  done < "$RES"
  _rule
  if [ "$grand" -eq 0 ]; then printf '  %s%s✓ ALL CLEAR%s  total findings: %s   elapsed: %s\n' "$B" "$G" "$X" "$grand" "$(human_time "$el")"; else printf '  %s%s✖ ATTENTION%s  total findings: %s   elapsed: %s\n' "$B" "$R" "$X" "$grand" "$(human_time "$el")"; fi
  printf '  %sindividual reports:%s %s\n\n' "$D" "$X" "$REPORTS"
  [ "$grand" -eq 0 ]
}

run_all() {
  mkdir -p "$REPORTS" 2>/dev/null || die "cannot create $REPORTS"
  local stamp json rc
  stamp=$(date +%Y%m%d-%H%M%S); LOG="$REPORTS/$NAME-$stamp.log"; RES=$(tmpf)
  _run_checks 2>&1 | tee "$LOG"; rc=${PIPESTATUS[0]}
  if [ "${PRESSWARDEN_OUTPUT_JSON:-1}" != "0" ] && command -v php >/dev/null 2>&1; then
    json="$REPORTS/$NAME-$stamp-summary.json"
    php -r '[$res,$out,$suite,$ver,$root,$sites,$domains,$rc,$log]=array_slice($argv,1);$checks=[];$total=0;foreach(@file($res,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $line){$p=explode("|",$line);if(count($p)<4)continue;$n=is_numeric($p[1])?(int)$p[1]:null;if($n!==null)$total+=$n;$checks[]=["check"=>$p[0],"findings"=>$n,"status"=>$p[2],"elapsed_seconds"=>(int)$p[3]];}$j=["tool"=>"PressWarden","version"=>$ver,"suite"=>$suite,"generated_at"=>date(DATE_ATOM),"root"=>$root,"wordpress_sites"=>(int)$sites,"site_groups"=>(int)$domains,"exit_code"=>(int)$rc,"total_findings"=>$total,"console_log"=>$log,"checks"=>$checks];file_put_contents($out,json_encode($j,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n");' "$RES" "$json" "$NAME" "$PRESSWARDEN_VERSION" "$ROOT" "$(count_sites)" "$(count_domains)" "$rc" "$LOG" 2>/dev/null || rm -f "$json"
    [ -s "$json" ] && cp -f "$json" "$REPORTS/$NAME-latest-summary.json" 2>/dev/null || true
  fi
  rm -f "$RES"
  printf '%ssummary log:%s %s\n' "$D" "$X" "$LOG"
  [ -n "${json:-}" ] && [ -s "$json" ] && printf '%sJSON summary:%s %s\n' "$D" "$X" "$json"
  return "$rc"
}
