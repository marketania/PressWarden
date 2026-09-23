# Structured suite finding-history helpers. History is auxiliary evidence: a
# history failure never changes the malware/security verdict, but it is shown as
# unavailable/incomplete and never advances the comparison pointer.
PW_HISTORY_ACTIVE="${PW_HISTORY_ACTIVE:-0}"
PW_HISTORY_RUN_DIR="${PW_HISTORY_RUN_DIR:-}"
PW_HISTORY_RUN_ID="${PW_HISTORY_RUN_ID:-}"
PW_HISTORY_STATUS="${PW_HISTORY_STATUS:-}"
PW_HISTORY_REPORT="${PW_HISTORY_REPORT:-}"
PW_HISTORY_COMPARE="${PW_HISTORY_COMPARE:-}"
PW_HISTORY_NEW="${PW_HISTORY_NEW:-0}"
PW_HISTORY_RECURRING="${PW_HISTORY_RECURRING:-0}"
PW_HISTORY_CHANGED="${PW_HISTORY_CHANGED:-0}"
PW_HISTORY_RESOLVED="${PW_HISTORY_RESOLVED:-0}"
PW_HISTORY_NOT_RECHECKED="${PW_HISTORY_NOT_RECHECKED:-0}"

_pw_history_php() {
  command -v php >/dev/null 2>&1 || return 2
  php "$PRESSWARDEN_DIR/lib/finding-history.php" "$@"
}

pw_history_init() {
  local map s label run_dir
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] || return 0
  command -v php >/dev/null 2>&1 || return 0
  run_dir=${PW_RUN_STATE_FILE%/state.json}
  map=$(tmpf) || return 0
  : > "$map" || { rm -f "$map"; return 0; }
  for s in "${SCAN_ROOTS[@]}"; do
    label=$(site_label_from_root "$s")
    case "$s$label" in *[[:cntrl:]]*) rm -f "$map"; return 0 ;; esac
    printf '%s\t%s\n' "$s" "$label" >> "$map" || { rm -f "$map"; return 0; }
  done
  if _pw_history_php init "$run_dir" "$map" >/dev/null 2>&1; then
    PW_HISTORY_ACTIVE=1
    PW_HISTORY_RUN_DIR="$run_dir"
    PW_HISTORY_RUN_ID="$PW_REPORT_ID"
    export PW_HISTORY_ACTIVE PW_HISTORY_RUN_DIR PW_HISTORY_RUN_ID
  fi
  rm -f "$map"
  return 0
}

pw_history_capture() {
  local findings="$1" severity="$2" section="$3" check="$4"
  [ "${PW_HISTORY_ACTIVE:-0}" -eq 1 ] || return 0
  case "$severity" in issue|review) ;; *) return 0 ;; esac
  if ! _pw_history_php capture "$PW_HISTORY_RUN_DIR" "$check" "$section" "$severity" "$findings" >/dev/null 2>&1; then
    _pw_history_php error "$PW_HISTORY_RUN_DIR" "$check" >/dev/null 2>&1 || true
  fi
  return 0
}

pw_history_carry_check() {
  local parent="$1" check="$2"
  [ "${PW_HISTORY_ACTIVE:-0}" -eq 1 ] || return 0
  [ -n "$parent" ] || return 0
  if ! _pw_history_php carry "$PRESSWARDEN_STATE_DIR/runs" "$parent" "$PW_HISTORY_RUN_ID" "$check" >/dev/null 2>&1; then
    _pw_history_php error "$PW_HISTORY_RUN_DIR" "$check" >/dev/null 2>&1 || true
  fi
  return 0
}

pw_history_finalize() {
  local out rc key value
  [ "${PW_HISTORY_ACTIVE:-0}" -eq 1 ] || return 0
  if out=$(_pw_history_php finalize "$PRESSWARDEN_STATE_DIR/runs" "$PRESSWARDEN_STATE_DIR/history" "$PW_HISTORY_RUN_ID" 2>/dev/null); then rc=0; else rc=$?; fi
  PW_HISTORY_STATUS='INCOMPLETE'; PW_HISTORY_REPORT=''; PW_HISTORY_COMPARE=''
  PW_HISTORY_NEW=0; PW_HISTORY_RECURRING=0; PW_HISTORY_CHANGED=0; PW_HISTORY_RESOLVED=0; PW_HISTORY_NOT_RECHECKED=0
  while IFS=$'\t' read -r key value; do
    case "$key" in
      STATUS) PW_HISTORY_STATUS="$value" ;;
      REPORT) PW_HISTORY_REPORT="$value" ;;
      COMPARE) PW_HISTORY_COMPARE="$value" ;;
      NEW) PW_HISTORY_NEW="$value" ;;
      RECURRING) PW_HISTORY_RECURRING="$value" ;;
      CHANGED) PW_HISTORY_CHANGED="$value" ;;
      RESOLVED) PW_HISTORY_RESOLVED="$value" ;;
      NOT_RECHECKED) PW_HISTORY_NOT_RECHECKED="$value" ;;
    esac
  done <<< "$out"
  if [ -n "$PW_HISTORY_REPORT" ]; then
    printf '%sfinding history:%s NEW %s • RECURRING %s • CHANGED %s • RESOLVED %s • NOT RECHECKED %s\n' "$D" "$X" "$PW_HISTORY_NEW" "$PW_HISTORY_RECURRING" "$PW_HISTORY_CHANGED" "$PW_HISTORY_RESOLVED" "$PW_HISTORY_NOT_RECHECKED"
    printf '%shistory report:%s %s\n' "$D" "$X" "$PW_HISTORY_REPORT"
    [ "$PW_HISTORY_STATUS" = COMPLETE ] || printf 'History capture is INCOMPLETE; comparison pointer was not advanced and no missing finding was treated as resolved.\n' >&2
  else
    printf 'Finding history unavailable for this run; the security scan verdict above is unchanged.\n' >&2
  fi
  return "$rc"
}
