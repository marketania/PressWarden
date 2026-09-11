# Suite run-state tracking. Read-only checks continue if state tracking fails,
# but the suite verdict is forced INCOMPLETE so missing history is never silent.
PW_RUN_STATE_ACTIVE=0
PW_RUN_STATE_FINALIZED=0
PW_RUN_STATE_FAILED=0
PW_RUN_STATE_CURRENT=''
PW_RUN_STATE_FILE=''
PW_RUN_STATE_RUNS=''

_pw_run_state_warn() {
  [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ] || return 0
  PW_RUN_STATE_FAILED=1
  if [ -n "${PW_RUN_STATE_ERROR_FILE:-}" ]; then printf 'failed\n' > "$PW_RUN_STATE_ERROR_FILE" 2>/dev/null || true; fi
  printf 'INCOMPLETE: persistent run-state tracking failed; scan results will continue, but this suite cannot be considered complete.\n' >&2
}

_pw_run_state_php() {
  command -v php >/dev/null 2>&1 || return 2
  php "$PRESSWARDEN_DIR/lib/run-state.php" "$@"
}

pw_run_state_init() {
  local suite="$1" total="$2" checks="$3" discovery started
  discovery=complete; [ "${SUITE_DISCOVERY_INCOMPLETE:-0}" -eq 0 ] || discovery=incomplete
  PW_RUN_STATE_RUNS="$PRESSWARDEN_STATE_DIR/runs"
  PW_RUN_STATE_FILE="$PW_RUN_STATE_RUNS/$PW_REPORT_ID/state.json"
  started=$(date +%s 2>/dev/null || printf '0')
  if ! _pw_run_state_php init "$PW_RUN_STATE_RUNS" "$PW_REPORT_ID" "$suite" "$PRESSWARDEN_VERSION" "$ROOT" \
      "$(count_sites)" "$(count_domains)" "$total" "$discovery" "$$" "$checks" "${LOG:-}" "$started"; then
    _pw_run_state_warn
    return 2
  fi
  PW_RUN_STATE_ACTIVE=1
  PW_RUN_STATE_FINALIZED=0
  trap 'pw_run_state_signal HUP 129' HUP
  trap 'pw_run_state_signal INT 130' INT
  trap 'pw_run_state_signal TERM 143' TERM
  trap 'pw_run_state_exit $?' EXIT
  return 0
}

pw_run_state_step() {
  local index="$1" total="$2" check="$3"
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ] || return 0
  PW_RUN_STATE_CURRENT="$check"
  if ! _pw_run_state_php step "$PW_RUN_STATE_FILE" "$index" "$total" "$check"; then _pw_run_state_warn; return 2; fi
  return 0
}

pw_run_state_result() {
  local check="$1" status="$2" findings="$3" elapsed="$4"
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ] || return 0
  if ! _pw_run_state_php result "$PW_RUN_STATE_FILE" "$check" "$status" "$findings" "$elapsed"; then _pw_run_state_warn; return 2; fi
  return 0
}

pw_run_state_finish() {
  local status="$1" rc="$2"
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] || return 0
  [ "${PW_RUN_STATE_FINALIZED:-0}" -eq 0 ] || return 0
  if [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ]; then
    if ! _pw_run_state_php finish "$PW_RUN_STATE_FILE" "$status" "$rc"; then _pw_run_state_warn; return 2; fi
  fi
  PW_RUN_STATE_FINALIZED=1
  _pw_run_state_cleanup_marker
  return 0
}

_pw_run_state_cleanup_marker() {
  [ -z "${PW_RUN_STATE_ERROR_FILE:-}" ] || rm -f -- "$PW_RUN_STATE_ERROR_FILE" 2>/dev/null || true
}

pw_run_state_signal() {
  local sig="$1" code="$2"
  trap - HUP INT TERM
  if [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && [ "${PW_RUN_STATE_FINALIZED:-0}" -eq 0 ]; then
    if [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ]; then
      _pw_run_state_php interrupt "$PW_RUN_STATE_FILE" "$sig" "$code" "${PW_RUN_STATE_CURRENT:-}" >/dev/null 2>&1 || true
    fi
    PW_RUN_STATE_FINALIZED=1
  fi
  _pw_run_state_cleanup_marker
  printf '\nINCOMPLETE: PressWarden suite interrupted by %s; partial validated reports were retained. Use ./presswarden last-run to inspect the recorded state.\n' "$sig" >&2
  exit "$code"
}

pw_run_state_exit() {
  local rc="${1:-2}"
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] || return 0
  [ "${PW_RUN_STATE_FINALIZED:-0}" -eq 0 ] || return 0
  if [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ]; then
    _pw_run_state_php finish "$PW_RUN_STATE_FILE" FAILED "$rc" >/dev/null 2>&1 || true
  fi
  PW_RUN_STATE_FINALIZED=1
  return 0
}
