#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-run-state.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
PHP="$REPO/lib/run-state.php"

# No history is a normal read-only state, not an error.
php "$PHP" show "$TMP/empty-runs" > "$TMP/empty.out"
grep -q 'No recorded PressWarden suite runs' "$TMP/empty.out"

mkdir -p "$TMP/root"
RUNS="$TMP/runs"
ID='full-20260911-202000.ABC123'
php "$PHP" init "$RUNS" "$ID" full 1.1.16 "$TMP/root" 86 85 2 complete 12345 'one two' "$TMP/report.log" 1789150000
[ "$(stat -c %a "$RUNS/$ID" 2>/dev/null)" = 700 ]
[ "$(stat -c %a "$RUNS/$ID/state.json" 2>/dev/null)" = 600 ]
grep -q '"status": "RUNNING"' "$RUNS/$ID/state.json"
grep -q '"checks_total": 2' "$RUNS/$ID/state.json"
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

grep -q '"current_check": "one"' "$RUNS/$ID/state.json"

php "$PHP" result "$RUNS/$ID/state.json" one findings 3 7
php "$PHP" step "$RUNS/$ID/state.json" 2 2 two
php "$PHP" show "$RUNS" > "$TMP/live.out"
grep -q 'STATUS     RUNNING' "$TMP/live.out"
grep -q 'CURRENT    \[2/2\] two' "$TMP/live.out"
grep -q 'findings 1' "$TMP/live.out"

php "$PHP" result "$RUNS/$ID/state.json" two clean 0 4
php "$PHP" finish "$RUNS/$ID/state.json" COMPLETED 1
php "$PHP" show "$RUNS" "$ID" > "$TMP/done.out"
grep -q 'STATUS     COMPLETED' "$TMP/done.out"
grep -q 'EXIT       1' "$TMP/done.out"

# A finalized run cannot be modified or finalized twice.
set +e
php "$PHP" step "$RUNS/$ID/state.json" 1 2 one > "$TMP/reopen.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'run-state step mismatch\|run already finalized' "$TMP/reopen.out"

# Signal handling records the active check before exiting with the signal-style code.
cat > "$TMP/signal.sh" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_STATE_DIR="$2"; PW_REPORT_ID="$3"; PRESSWARDEN_VERSION=1.1.16
ROOT="$4"; LOG="$5"; SUITE_DISCOVERY_INCOMPLETE=0
count_sites(){ printf '1'; }
count_domains(){ printf '1'; }
. "$PRESSWARDEN_DIR/lib/run-state.sh"
pw_run_state_init full 2 'alpha beta' || exit 9
pw_run_state_step 1 2 alpha || exit 9
kill -TERM $$
exit 99
SH
chmod +x "$TMP/signal.sh"
set +e
bash "$TMP/signal.sh" "$REPO" "$TMP/signal-state" signal-run "$TMP/root" "$TMP/signal.log" > "$TMP/signal.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 143 ]
grep -q 'interrupted by TERM' "$TMP/signal.out"
grep -q '"status": "INTERRUPTED"' "$TMP/signal-state/runs/signal-run/state.json"
grep -q '"current_check": "alpha"' "$TMP/signal-state/runs/signal-run/state.json"
grep -q '"interrupted_signal": "TERM"' "$TMP/signal-state/runs/signal-run/state.json"

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
grep -q '"status": "INTERRUPTED"' "$TMP/hup-state/runs/hup-run/state.json"
grep -q '"interrupted_signal": "HUP"' "$TMP/hup-state/runs/hup-run/state.json"
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
cat > "$TMP/failed.sh" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_STATE_DIR="$2"; PW_REPORT_ID="$3"; PRESSWARDEN_VERSION=1.1.16
ROOT="$4"; LOG="$5"; SUITE_DISCOVERY_INCOMPLETE=0
count_sites(){ printf '1'; }
count_domains(){ printf '1'; }
. "$PRESSWARDEN_DIR/lib/run-state.sh"
pw_run_state_init full 1 'alpha' || exit 9
pw_run_state_step 1 1 alpha || exit 9
exit 7
SH
chmod +x "$TMP/failed.sh"
set +e
bash "$TMP/failed.sh" "$REPO" "$TMP/fail-state" fail-run "$TMP/root" "$TMP/fail.log" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 7 ]
grep -q '"status": "FAILED"' "$TMP/fail-state/runs/fail-run/state.json"
grep -q '"exit_code": 7' "$TMP/fail-state/runs/fail-run/state.json"

# A completed run is not rewritten by EXIT cleanup.
cat > "$TMP/completed.sh" <<'SH'
#!/usr/bin/env bash
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_STATE_DIR="$2"; PW_REPORT_ID="$3"; PRESSWARDEN_VERSION=1.1.16
ROOT="$4"; LOG="$5"; SUITE_DISCOVERY_INCOMPLETE=0
count_sites(){ printf '1'; }
count_domains(){ printf '1'; }
. "$PRESSWARDEN_DIR/lib/run-state.sh"
pw_run_state_init fast 1 'alpha' || exit 9
pw_run_state_step 1 1 alpha || exit 9
pw_run_state_result alpha clean 0 1 || exit 9
pw_run_state_finish COMPLETED 0 || exit 9
exit 0
SH
chmod +x "$TMP/completed.sh"
bash "$TMP/completed.sh" "$REPO" "$TMP/complete-state" complete-run "$TMP/root" "$TMP/complete.log"
grep -q '"status": "COMPLETED"' "$TMP/complete-state/runs/complete-run/state.json"

# Symlinked state destinations and malformed/corrupt state are refused.
mkdir "$TMP/real-runs"
ln -s "$TMP/real-runs" "$TMP/link-runs"
set +e
php "$PHP" init "$TMP/link-runs" bad-run fast 1.1.16 "$TMP/root" 1 1 1 complete 1 alpha '' 1789150000 > "$TMP/link.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'unsafe run-state directory' "$TMP/link.out"

printf '{bad json}\n' > "$TMP/bad.json"
mkdir "$TMP/corrupt-runs" "$TMP/corrupt-runs/corrupt"
cp "$TMP/bad.json" "$TMP/corrupt-runs/corrupt/state.json"
printf 'corrupt\n' > "$TMP/corrupt-runs/latest"
set +e
php "$PHP" show "$TMP/corrupt-runs" > "$TMP/corrupt.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'invalid run-state' "$TMP/corrupt.out"

# Run state is allowlisted metadata: unrelated secrets in the environment never appear.
DB_PASSWORD='super-secret-test-value' API_KEY='another-secret' php "$PHP" show "$RUNS" "$ID" > "$TMP/privacy.out"
! grep -R -q 'super-secret-test-value\|another-secret' "$RUNS"

# CLI status is read-only and must work before history exists without discovery.
PRESSWARDEN_STATE_DIR="$TMP/cli-empty" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" last-run > "$TMP/cli-empty.out"
grep -q 'No recorded PressWarden suite runs' "$TMP/cli-empty.out"
PRESSWARDEN_STATE_DIR="$TMP" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" run-status "$ID" > "$TMP/cli-status.out"
grep -q 'STATUS     COMPLETED' "$TMP/cli-status.out"
set +e
PRESSWARDEN_STATE_DIR="$TMP" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" bash "$REPO/presswarden" run-status '../escape' > "$TMP/cli-bad.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'invalid run id' "$TMP/cli-bad.out"

printf 'Run-state atomicity, interruption, privacy and fail-closed semantics: PASS\n'
