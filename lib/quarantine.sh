# Approved generic/metadata removals only. No automatic restoration or deletion.
_pw_quarantine_failure() {
  PW_REMEDIATION_FAILED=1
  printf 'INCOMPLETE: quarantine action did not complete; existing evidence is retained.\n' >&2
  return 2
}
_pw_quarantine_mark_failed() {
  # The PHP helper already emitted a controlled safeguard and INCOMPLETE line.
  # Mark the check incomplete without duplicating a third generic message.
  PW_REMEDIATION_FAILED=1
  return 2
}
_pw_quarantine_discard_plan() {
  # Only ephemeral plans are removed; quarantine cases are never cleaned here.
  [ -z "${PW_Q_WORK:-}" ] || rm -rf -- "$PW_Q_WORK"
  PW_Q_WORK=''
}
_pw_quarantine_prepare() {
  local list="$1" mode="${2:-generic}" p site
  PW_Q_WORK=''
  [ "${PW_REPORT_FAILED:-0}" -eq 0 ] && [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] || return 2
  command -v php >/dev/null 2>&1 || {
    printf 'Verified quarantine requires PHP CLI; no original files were removed.\n' >&2
    _pw_quarantine_failure; return 2
  }
  PW_Q_WORK=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-quarantine-plan.XXXXXX") || { _pw_quarantine_failure; return 2; }
  {
    printf '%s\0%s\0' root "$ROOT" quarantine "$QUARANTINE" mode "$mode" version "${PRESSWARDEN_VERSION:-unknown}" check "${NAME:-check}" section "${CURRENT_SECTION:-}" run_id "${PW_REPORT_ID:-}"
    for site in "${SCAN_ROOTS[@]}"; do printf 'site\0%s\0' "$site"; done
    for p in "$PRESSWARDEN_DIR" "$PRESSWARDEN_STATE_DIR" "$PRESSWARDEN_CACHE_DIR" "$REPORTS" "$PRESSWARDEN_CONFIG_FILE" "${MANUAL_EXCLUDED_ROOTS[@]}"; do
      [ -n "$p" ] && printf 'blocked\0%s\0' "$p"
    done
    while IFS= read -r p || [ -n "$p" ]; do [ -z "$p" ] || printf 'target\0%s\0' "$p"; done < "$list"
  } > "$PW_Q_WORK/context" || { _pw_quarantine_discard_plan; _pw_quarantine_failure; return 2; }
  if ! php "$PRESSWARDEN_DIR/lib/quarantine-cli.php" --prepare "$PW_Q_WORK/context" "$PW_Q_WORK/plan.json"; then
    _pw_quarantine_discard_plan; _pw_quarantine_mark_failed; return 2
  fi
}
_quarantine_delete() {
  local list="$1" plan="${2:-}" mode="${3:-generic}" own_plan=0 out rc helper_rc kind caseid original extra removed=0 completed=0 expected_case=''
  [ "${PW_REPORT_FAILED:-0}" -eq 0 ] && [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] || return 2
  if [ -z "$plan" ]; then
    _pw_quarantine_prepare "$list" "$mode" || return 2
    plan="$PW_Q_WORK/plan.json"; own_plan=1
  fi
  if [ -n "${DELETE_LOG:-}" ] && { [ ! -f "$DELETE_LOG" ] || [ -L "$DELETE_LOG" ] || [ ! -w "$DELETE_LOG" ]; }; then
    [ "$own_plan" -eq 0 ] || _pw_quarantine_discard_plan
    printf 'INCOMPLETE: unsafe or unwritable deletion report; no original files removed.\n' >&2
    _pw_quarantine_failure; return 2
  fi
  out=$(tmpf)
  php "$PRESSWARDEN_DIR/lib/quarantine-cli.php" --apply "$plan" > "$out"; helper_rc=$?; rc=$helper_rc
  while IFS=$'\t' read -r kind caseid original extra; do
    if [ -n "$extra" ] || [ "$completed" -ne 0 ] || ! [[ "$caseid" =~ ^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}$ ]]; then rc=2; continue; fi
    [ -z "$expected_case" ] && expected_case="$caseid"
    [ "$caseid" = "$expected_case" ] || { rc=2; continue; }
    case "$kind" in
      REMOVED)
        [[ "$original" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || { rc=2; continue; }
        removed=$((removed+1)); DELETED=$((DELETED+1))
        printf '    ✓ QUARANTINED  case %s • approved target %s\n' "$caseid" "$removed"
        # The complete original path mapping is in the private manifest. No source
        # payload, credentials or unescaped filenames are sent to the terminal.
        if [ -n "${DELETE_LOG:-}" ]; then
          printf 'case=%s | original_path_base64=%s | copied-and-verified-before-removal\n' "$caseid" "$original" >> "$DELETE_LOG" || rc=2
        fi
        ;;
      COMPLETE)
        [[ "$original" =~ ^[0-9]+$ ]] && [ "$original" -eq "$removed" ] || { rc=2; continue; }
        completed=1; printf '    Quarantine case: %s\n' "$caseid" ;;
      *) rc=2 ;;
    esac
  done < "$out"
  rm -f -- "$out"
  [ "$own_plan" -eq 0 ] || _pw_quarantine_discard_plan
  if ! { [ "$rc" -eq 0 ] && [ "$completed" -eq 1 ] && [ "$removed" -gt 0 ]; }; then
    if [ "${helper_rc:-0}" -ne 0 ]; then _pw_quarantine_mark_failed; else _pw_quarantine_failure; fi
    return 2
  fi
  return 0
}
