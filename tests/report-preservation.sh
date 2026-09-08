#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-report-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/reports"
DATE=$(command -v date)
cat > "$TMP/bin/date" <<EOF2
#!/usr/bin/env bash
case "\${1:-}" in +%Y%m%d-%H%M%S) printf '20260907-120000\\n' ;; *) exec "$DATE" "\$@" ;; esac
EOF2
chmod +x "$TMP/bin/date"
export PATH="$TMP/bin:$PATH"
export REPORTS="$TMP/reports" PW_TEST_LIB="$REPO/lib/reports.sh"
# Timestamp-only preexisting reports and traps must not be overwritten.
printf 'historical log\n' > "$REPORTS/test-20260907-120000.log"
printf 'private target\n' > "$TMP/target"
ln -s "$TMP/target" "$REPORTS/test-20260907-120000-findings.log"
pids=()
for i in 1 2 3 4 5 6 7 8; do
  bash -c 'set -e; umask 000; . "$PW_TEST_LIB"; pw_report_init test; printf "%s\n" "$1" > "$LOG"; printf "%s\n" "$PW_REPORT_ID"' _ "$i" > "$TMP/id-$i" &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done
[ "$(cat "$TMP"/id-* | sort -u | wc -l)" -eq 8 ]
[ "$(find "$REPORTS" -name 'test-20260907-120000.*.log' ! -name '*-findings.log' ! -name '*-deletions.log' | wc -l)" -eq 8 ]
[ "$(cat "$REPORTS/test-20260907-120000.log")" = 'historical log' ]
[ "$(cat "$TMP/target")" = 'private target' ]
[ -L "$REPORTS/test-20260907-120000-findings.log" ]
php -r 'foreach(glob($argv[1]."/test-20260907-120000.??????*") as $p) if((fileperms($p)&0077)!==0) exit(1);' "$REPORTS"
[ -z "$(find "$REPORTS" -maxdepth 1 -name '.test-*' -print)" ]
# Report initialization must not change the caller's umask or accept path traversal.
bash -c 'umask 0022; . "$PW_TEST_LIB"; pw_report_init good; [ "$(umask)" = 0022 ]; ! pw_report_init ../escape' > "$TMP/mask.out" 2>&1
[ ! -e "$TMP/escape" ]
# Finding write failure disables actions, retains counts and returns INCOMPLETE.
cat > "$TMP/detail-failure.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/reports.sh"
. "$PW_TEST_REPO/lib/remediation.sh"
B=''; D=''; R=''; G=''; Y=''; X=''; C=''; BL=''; NAME=test
ROOT=/tmp; SEC_T0=$(date +%s); T0=$SEC_T0
MANUAL_EXCLUDED_ROOTS=(); TOTAL=0; ALERTS=0; REVIEWS=0; DELETED=0; PROTECTED_SKIPPED=0
PRESSWARDEN_MAX=1; PRESSWARDEN_INTERACTIVE=1
_rule(){ :; }; human_time(){ echo 0s; }; compact_line(){ printf '%s' "$1"; }
_save_details(){ return 1; }
_prompt_file_action(){ echo 'UNSAFE_ACTION_OFFERED'; }
main(){ local f; f=$(mktemp); printf '/tmp/finding1\n/tmp/finding2\n' > "$f"; report "$f" issue; finish; }
run_logged test
STUB
set +e
PW_TEST_REPO="$REPO" bash "$TMP/detail-failure.sh" > "$TMP/failure.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q INCOMPLETE "$TMP/failure.out"
grep -q 'findings: 2' "$TMP/failure.out"
! grep -q 'UNSAFE_ACTION_OFFERED\|full list is in the findings log' "$TMP/failure.out"
# Concurrent atomic latest publishers never expose truncated JSON.
php -r 'require $argv[1];foreach(["a","b"] as $id)presswarden_report_json_write($argv[2]."/$id.json",json_encode(["tool"=>"PressWarden","suite"=>"atomic","checks"=>[],"coverage_status"=>"complete","marker"=>str_repeat($id,100000)]));' "$REPO/lib/report-json.php" "$TMP"
php "$REPO/lib/report-json.php" latest "$TMP/a.json" "$TMP/atomic-latest-summary.json"
pids=()
for letter in a b; do
  (for n in $(seq 1 15); do php "$REPO/lib/report-json.php" latest "$TMP/$letter.json" "$TMP/atomic-latest-summary.json" || exit 1; done) &
  pids+=("$!")
done
php -r 'for($i=0;$i<300;$i++){ $j=json_decode(file_get_contents($argv[1]),true);if(!is_array($j)||strlen($j["marker"]??"")!==100000)exit(1);usleep(1000);}' "$TMP/atomic-latest-summary.json"
for pid in "${pids[@]}"; do wait "$pid"; done
[ -z "$(find "$TMP" -name '.presswarden-json-*' -print)" ]
printf 'Report collision, privacy, evidence failure and atomic publication: PASS\n'
