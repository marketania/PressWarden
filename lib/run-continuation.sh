# Safe continuation helpers. These never decide malware verdicts or modify WordPress.
PW_CONTINUE_CARRY_FILE=''
PW_CONTINUE_CARRIED=0
PW_CONTINUE_START=''

_pw_continue_scope_file() {
  local out="$1" p depth="${PRESSWARDEN_DISCOVERY_DEPTH:-8}"
  : > "$out" || return 2
  case "$ROOT" in *[[:cntrl:]]*) return 2 ;; esac
  printf 'ROOT\t%s\nDEPTH\t%s\n' "$ROOT" "$depth" >> "$out" || return 2
  for p in "${SCAN_ROOTS[@]}"; do
    case "$p" in *[[:cntrl:]]*) return 2 ;; esac
    printf 'SITE\t%s\n' "$p" >> "$out" || return 2
  done
  if [ -n "${_PW_TARGET_EXCLUSIONS:-}" ]; then
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      case "$p" in *[[:cntrl:]]*) return 2 ;; esac
      printf 'EXCLUDE\t%s\n' "$p" >> "$out" || return 2
    done <<< "$_PW_TARGET_EXCLUSIONS"
  fi
  return 0
}

pw_continue_capture_scope() {
  local scope run_dir
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] || return 0
  scope=$(tmpf) || return 2
  if ! _pw_continue_scope_file "$scope"; then rm -f "$scope"; return 2; fi
  run_dir=${PW_RUN_STATE_FILE%/state.json}
  php "$PRESSWARDEN_DIR/lib/run-continuation.php" capture "$run_dir" "$scope"
  local rc=$?; rm -f "$scope"; return "$rc"
}

pw_continue_prepare() {
  local suite="$1" checks="$2" scope carry out key value
  [ -n "${PRESSWARDEN_CONTINUE_FROM:-}" ] || return 0
  scope=$(tmpf) || return 2
  carry=$(tmpf) || { rm -f "$scope"; return 2; }
  if ! _pw_continue_scope_file "$scope"; then rm -f "$scope" "$carry"; return 2; fi
  if ! out=$(php "$PRESSWARDEN_DIR/lib/run-continuation.php" verify "$PRESSWARDEN_STATE_DIR/runs" "$PRESSWARDEN_CONTINUE_FROM" "$PRESSWARDEN_VERSION" "$suite" "$checks" "$scope" "$carry"); then
    rm -f "$scope" "$carry"; return 2
  fi
  rm -f "$scope"
  PW_CONTINUE_START=''; PW_CONTINUE_CARRIED=0
  while IFS=$'\t' read -r key value; do
    case "$key" in
      START) PW_CONTINUE_START="$value" ;;
      CARRY) PW_CONTINUE_CARRIED="$value" ;;
    esac
  done <<< "$out"
  case "$PW_CONTINUE_CARRIED" in ''|*[!0-9]*) rm -f "$carry"; return 2 ;; esac
  [ -n "$PW_CONTINUE_START" ] || { rm -f "$carry"; return 2; }
  PW_CONTINUE_CARRY_FILE="$carry"
  export PW_CONTINUE_START PW_CONTINUE_CARRIED PW_CONTINUE_CARRY_FILE
  return 0
}

pw_continue_carried_row() {
  local check="$1"
  [ -n "${PW_CONTINUE_CARRY_FILE:-}" ] && [ -f "$PW_CONTINUE_CARRY_FILE" ] || return 1
  awk -F '\t' -v c="$check" '$1==c {print; found=1; exit} END{exit(found?0:1)}' "$PW_CONTINUE_CARRY_FILE"
}

pw_continue_cleanup() {
  [ -z "${PW_CONTINUE_CARRY_FILE:-}" ] || rm -f -- "$PW_CONTINUE_CARRY_FILE"
  PW_CONTINUE_CARRY_FILE=''
}
