#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]

def replace_once(path, old, new):
    p = root / path
    s = p.read_text()
    if old not in s:
        raise SystemExit(f'anchor not found: {path}: {old[:100]!r}')
    p.write_text(s.replace(old, new, 1))

# Serialize parent signal finalization against pipeline-child step/result writes
# using PHP's built-in advisory flock; no external flock binary is required.
replace_once('lib/run-state.php',
"""function pwrs_atomic_json($path, $state, $createOnly = false) { pwrs_atomic_write($path, pwrs_encode($state), $createOnly); }
function pwrs_atomic_text($path, $text) {
""",
"""function pwrs_atomic_json($path, $state, $createOnly = false) { pwrs_atomic_write($path, pwrs_encode($state), $createOnly); }
function pwrs_create_lock($runDir) {
    $path = $runDir.'/.lock';
    $old = umask(0077);
    try { $h = @fopen($path, 'xb'); } finally { umask($old); }
    if ($h === false) pwrs_fail('cannot create run-state lock');
    if (!@fclose($h)) pwrs_fail('run-state lock close failed');
    pwrs_regular_file($path, 4096);
}
function pwrs_open_lock($statePath) {
    $path = dirname($statePath).'/.lock';
    $expected = pwrs_regular_file($path, 4096);
    $h = @fopen($path, 'r+');
    if ($h === false) pwrs_fail('cannot open run-state lock');
    $actual = @fstat($h);
    if (!$actual || $actual['dev'] !== $expected['dev'] || $actual['ino'] !== $expected['ino']
        || ($actual['mode'] & 0170000) !== 0100000 || $actual['nlink'] !== 1) {
        @fclose($h); pwrs_fail('run-state lock changed');
    }
    if (!@flock($h, LOCK_EX)) { @fclose($h); pwrs_fail('cannot lock run-state'); }
    return $h;
}
function pwrs_atomic_text($path, $text) {
""")
replace_once('lib/run-state.php',
"""function pwrs_update($path, $mutator) {
    $state = pwrs_read($path);
    $state = $mutator($state);
    $state['updated_at'] = pwrs_now();
    pwrs_atomic_json($path, $state, false);
}
""",
"""function pwrs_update($path, $mutator) {
    $lock = pwrs_open_lock($path);
    try {
        $state = pwrs_read($path);
        $state = $mutator($state);
        $state['updated_at'] = pwrs_now();
        pwrs_atomic_json($path, $state, false);
    } finally {
        @flock($lock, LOCK_UN);
        @fclose($lock);
    }
}
""")
replace_once('lib/run-state.php',
"""        if (!$ok) pwrs_fail('cannot create run directory');
        $state = array(
""",
"""        if (!$ok) pwrs_fail('cannot create run directory');
        pwrs_create_lock($runDir);
        $state = array(
""")

# Child processes in the suite logging pipeline cannot propagate shell variables
# back to the parent. Use one private temp marker so a failed state write still
# forces the parent suite verdict INCOMPLETE.
replace_once('lib/run-state.sh',
"""  PW_RUN_STATE_FAILED=1
  printf 'INCOMPLETE: persistent run-state tracking failed; scan results will continue, but this suite cannot be considered complete.\\n' >&2
""",
"""  PW_RUN_STATE_FAILED=1
  if [ -n "${PW_RUN_STATE_ERROR_FILE:-}" ]; then printf 'failed\\n' > "$PW_RUN_STATE_ERROR_FILE" 2>/dev/null || true; fi
  printf 'INCOMPLETE: persistent run-state tracking failed; scan results will continue, but this suite cannot be considered complete.\\n' >&2
""")
replace_once('lib/_runner.sh',
"""  local json rc json_written=0 total_checks state_status
  local -a pipeline_status
  total_checks=$(printf '%s\\n' $CHECKS | sort -u | grep -c .)
  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true
  RES=$(tmpf) || { pw_report_remove_empty; return 2; }
""",
"""  local json rc json_written=0 total_checks state_status
  local -a pipeline_status
  total_checks=$(printf '%s\\n' $CHECKS | sort -u | grep -c .)
  PW_RUN_STATE_ERROR_FILE=$(tmpf) || { pw_report_remove_empty; return 2; }
  : > "$PW_RUN_STATE_ERROR_FILE" || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_report_remove_empty; return 2; }
  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true
  RES=$(tmpf) || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_report_remove_empty; return 2; }
""")
replace_once('lib/_runner.sh',
"""  rm -f "$RES"
  pw_report_remove_empty
  [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ] || rc=2
""",
"""  rm -f "$RES"
  pw_report_remove_empty
  if [ "${PW_RUN_STATE_FAILED:-0}" -ne 0 ] || [ -s "$PW_RUN_STATE_ERROR_FILE" ]; then rc=2; fi
""")
replace_once('lib/_runner.sh',
"""  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && printf '%srun state:%s %s\\n' "$D" "$X" "$PW_RUN_STATE_FILE"
  return "$rc"
""",
"""  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && printf '%srun state:%s %s\\n' "$D" "$X" "$PW_RUN_STATE_FILE"
  rm -f "$PW_RUN_STATE_ERROR_FILE"
  return "$rc"
""")

# Deterministically prove state updates honor the per-run lock, and exercise the
# actual read-only CLI surface without site discovery or WordPress bootstrap.
p = root / 'tests/run-state.sh'
s = p.read_text()
anchor = """grep -q '\"checks_total\": 2' "$RUNS/$ID/state.json"

php "$PHP" step "$RUNS/$ID/state.json" 1 2 one
"""
insert = """grep -q '\"checks_total\": 2' "$RUNS/$ID/state.json"
[ "$(stat -c %a "$RUNS/$ID/.lock" 2>/dev/null)" = 600 ]

# A second writer must wait while another process owns the per-run advisory lock.
php -r '$h=fopen($argv[1],"r+"); if(!$h||!flock($h,LOCK_EX))exit(2); file_put_contents($argv[2],"ready"); usleep(400000);' "$RUNS/$ID/.lock" "$TMP/lock-ready" & holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$TMP/lock-ready" ] && break; sleep 0.05; done
[ -f "$TMP/lock-ready" ]
php "$PHP" step "$RUNS/$ID/state.json" 1 2 one > "$TMP/locked-step.out" 2>&1 & waiter=$!
sleep 0.10
kill -0 "$waiter" 2>/dev/null
wait "$holder"
wait "$waiter"

grep -q '\"current_check\": \"one\"' "$RUNS/$ID/state.json"

"""
if anchor not in s:
    raise SystemExit('run-state lock test anchor not found')
s = s.replace(anchor, insert, 1)
anchor = """DB_PASSWORD='super-secret-test-value' API_KEY='another-secret' php "$PHP" show "$RUNS" "$ID" > "$TMP/privacy.out"
! grep -R -q 'super-secret-test-value\\|another-secret' "$RUNS"

printf 'Run-state atomicity, interruption, privacy and fail-closed semantics: PASS\\n'
"""
insert = """DB_PASSWORD='super-secret-test-value' API_KEY='another-secret' php "$PHP" show "$RUNS" "$ID" > "$TMP/privacy.out"
! grep -R -q 'super-secret-test-value\\|another-secret' "$RUNS"

# CLI status is read-only and must work before history exists without discovery.
PRESSWARDEN_STATE_DIR="$TMP/cli-empty" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" last-run > "$TMP/cli-empty.out"
grep -q 'No recorded PressWarden suite runs' "$TMP/cli-empty.out"
PRESSWARDEN_STATE_DIR="$TMP" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" run-status "$ID" > "$TMP/cli-status.out"
grep -q 'STATUS     COMPLETED' "$TMP/cli-status.out"
set +e
PRESSWARDEN_STATE_DIR="$TMP" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" run-status '../escape' > "$TMP/cli-bad.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'invalid run id' "$TMP/cli-bad.out"

printf 'Run-state atomicity, interruption, privacy and fail-closed semantics: PASS\\n'
"""
if anchor not in s:
    raise SystemExit('run-state CLI test anchor not found')
s = s.replace(anchor, insert, 1)
p.write_text(s)

# Wording: each individual record is bounded; run history is intentionally
# preserved rather than silently pruned.
replace_once('CHANGELOG.md',
"Keep run history bounded to allowlisted operational metadata",
"Keep each run record bounded to allowlisted operational metadata")
