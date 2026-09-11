#!/usr/bin/env python3
from pathlib import Path
root = Path(__file__).resolve().parents[1]

def replace_once(path, old, new):
    p = root / path
    s = p.read_text()
    if old not in s:
        raise SystemExit(f'anchor not found: {path}: {old[:100]!r}')
    p.write_text(s.replace(old, new, 1))

# Temp failure marker is operational scratch state, not evidence; clean it on
# catchable interruption and ordinary unexpected shell exit.
replace_once('lib/run-state.sh',
"""pw_run_state_signal() {
  local sig="$1" code="$2"
  trap - HUP INT TERM
""",
"""_pw_run_state_cleanup_marker() {
  [ -z "${PW_RUN_STATE_ERROR_FILE:-}" ] || rm -f -- "$PW_RUN_STATE_ERROR_FILE" 2>/dev/null || true
}

pw_run_state_signal() {
  local sig="$1" code="$2"
  trap - HUP INT TERM
""")
replace_once('lib/run-state.sh',
"""  printf '\\nINCOMPLETE: PressWarden suite interrupted by %s; partial validated reports were retained. Use ./presswarden last-run to inspect the recorded state.\\n' "$sig" >&2
  exit "$code"
}
""",
"""  _pw_run_state_cleanup_marker
  printf '\\nINCOMPLETE: PressWarden suite interrupted by %s; partial validated reports were retained. Use ./presswarden last-run to inspect the recorded state.\\n' "$sig" >&2
  exit "$code"
}
""")
replace_once('lib/run-state.sh',
"""  PW_RUN_STATE_FINALIZED=1
  return 0
}
""",
"""  PW_RUN_STATE_FINALIZED=1
  _pw_run_state_cleanup_marker
  return 0
}
""")

# A pipeline-child state-write failure is known before suite JSON publication;
# force rc=2 first so the unique JSON coverage agrees with the final CLI verdict.
replace_once('lib/_runner.sh',
"""  if [ "${pipeline_status[1]:-0}" -ne 0 ]; then
    printf 'INCOMPLETE: suite console log could not be written.\\n' >&2; rc=2
  fi
  if [ "${PRESSWARDEN_OUTPUT_JSON:-1}" != "0" ] && command -v php >/dev/null 2>&1; then
""",
"""  if [ "${pipeline_status[1]:-0}" -ne 0 ]; then
    printf 'INCOMPLETE: suite console log could not be written.\\n' >&2; rc=2
  fi
  if [ "${PW_RUN_STATE_FAILED:-0}" -ne 0 ] || [ -s "$PW_RUN_STATE_ERROR_FILE" ]; then rc=2; fi
  if [ "${PRESSWARDEN_OUTPUT_JSON:-1}" != "0" ] && command -v php >/dev/null 2>&1; then
""")
replace_once('lib/_runner.sh',
"""  rm -f "$RES"
  pw_report_remove_empty
  if [ "${PW_RUN_STATE_FAILED:-0}" -ne 0 ] || [ -s "$PW_RUN_STATE_ERROR_FILE" ]; then rc=2; fi
  state_status=COMPLETED
""",
"""  rm -f "$RES"
  pw_report_remove_empty
  state_status=COMPLETED
""")

# Cover the SSH-relevant HUP path in addition to TERM.
p = root / 'tests/run-state.sh'
s = p.read_text()
anchor = """grep -q '\"interrupted_signal\": \"TERM\"' "$TMP/signal-state/runs/signal-run/state.json"

# Unexpected shell exit is fail-closed even without a catchable signal.
"""
insert = """grep -q '\"interrupted_signal\": \"TERM\"' "$TMP/signal-state/runs/signal-run/state.json"

# SSH disconnects commonly deliver SIGHUP; record the same fail-closed status.
cat > "$TMP/hup.sh" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_STATE_DIR="$2"; PW_REPORT_ID="$3"; PRESSWARDEN_VERSION=1.1.16
ROOT="$4"; LOG="$5"; SUITE_DISCOVERY_INCOMPLETE=0
count_sites(){ printf '1'; }
count_domains(){ printf '1'; }
. "$PRESSWARDEN_DIR/lib/run-state.sh"
PW_RUN_STATE_ERROR_FILE="$6"; : > "$PW_RUN_STATE_ERROR_FILE"
pw_run_state_init full 1 'alpha' || exit 9
pw_run_state_step 1 1 alpha || exit 9
kill -HUP $$
exit 99
SH
chmod +x "$TMP/hup.sh"
set +e
bash "$TMP/hup.sh" "$REPO" "$TMP/hup-state" hup-run "$TMP/root" "$TMP/hup.log" "$TMP/hup-marker" > "$TMP/hup.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 129 ]
grep -q 'interrupted by HUP' "$TMP/hup.out"
grep -q '\"status\": \"INTERRUPTED\"' "$TMP/hup-state/runs/hup-run/state.json"
grep -q '\"interrupted_signal\": \"HUP\"' "$TMP/hup-state/runs/hup-run/state.json"
[ ! -e "$TMP/hup-marker" ]

# A subshell/pipeline child cannot propagate shell variables to its parent, so
# the private marker is the cross-process fail-closed signal.
PW_RUN_STATE_ERROR_FILE="$TMP/child-marker"; : > "$PW_RUN_STATE_ERROR_FILE"
PW_RUN_STATE_FAILED=0
. "$REPO/lib/run-state.sh"
( _pw_run_state_warn >/dev/null 2>&1 )
[ -s "$PW_RUN_STATE_ERROR_FILE" ]
rm -f "$PW_RUN_STATE_ERROR_FILE"

# Unexpected shell exit is fail-closed even without a catchable signal.
"""
if anchor not in s:
    raise SystemExit('HUP test anchor not found')
p.write_text(s.replace(anchor, insert, 1))
