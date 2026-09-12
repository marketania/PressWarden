#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-reliability.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/repo/lib" "$TMP/repo/checks" "$TMP/reports"
cp "$REPO/lib/_runner.sh" "$REPO/lib/suite-summary.php" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$REPO/lib/run-continuation.sh" "$REPO/lib/run-continuation.php" "$TMP/repo/lib/"
# Synthetic runtime exercises the actual suite driver, not a copy of its logic.
cat > "$TMP/repo/lib/_lib.sh" <<'EOF'
PRESSWARDEN_DIR="$PW_TEST_REPO"; ROOT="$PW_TEST_REPO"
REPORTS="$PW_TEST_REPORTS"; PRESSWARDEN_STATE_DIR="$PW_TEST_STATE"; PRESSWARDEN_VERSION=test; T0=$(date +%s)
B=''; C=''; X=''; D=''; Y=''; G=''; R=''; BL=''; W=60
SCAN_ROOTS=("$ROOT"); NESTED_SITES=(); MANUAL_EXCLUDED_DOMAINS=()
PW_DISCOVERY_FAILED="${PW_TEST_DISCOVERY_FAILED:-0}"
[ "${PW_TEST_EMPTY:-0}" = 0 ] || SCAN_ROOTS=()
count_sites() { echo "${#SCAN_ROOTS[@]}"; }
count_domains() { echo 1; }
_meta_field() { :; }
_repeat() { :; }
_rule() { echo '---'; }
human_time() { printf '%ss' "$1"; }
tmpf() { mktemp; }
die() { echo "$1" >&2; exit 2; }
. "$PW_TEST_REPO/lib/reports.sh"
EOF
printf 'echo "findings: 0"; exit 0\n' > "$TMP/repo/checks/good.sh"
printf 'echo "findings: 3"; exit 1\n' > "$TMP/repo/checks/finding.sh"
printf 'echo "validator failed" >&2; exit 2\n' > "$TMP/repo/checks/bad.sh"
run_case() {
  local name=$1 checks=$2 expected=$3 coverage=$4 rc
  set +e
  PW_TEST_REPO="$TMP/repo" PW_TEST_REPORTS="$TMP/reports" PW_TEST_STATE="$TMP/state" PRESSWARDEN_INTERACTIVE=0 \
    bash -c 'RUN_NAME="$1"; CHECKS="$2"; . "$3/lib/_runner.sh"; run_all' _ "$name" "$checks" "$TMP/repo" > "$TMP/$name.log" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq "$expected" ] || { cat "$TMP/$name.log"; echo "wrong exit code $rc" >&2; exit 1; }
  local discovery_status="${5:-complete}"
  php -r '$j=json_decode(file_get_contents($argv[1]),true); if(!$j || $j["coverage_status"]!==$argv[2] || $j["exit_code"]!==(int)$argv[3] || ($j["discovery_status"]??null)!==$argv[4])exit(1);' "$TMP/reports/$name-latest-summary.json" "$coverage" "$expected" "$discovery_status"
  if [ "$coverage" != complete ]; then ! grep -q 'ALL CLEAR' "$TMP/$name.log"; fi
}
run_case success 'good' 0 complete
run_case failure 'good bad' 2 incomplete
run_case findings 'good finding' 1 complete
run_case mixed 'finding bad' 2 incomplete
run_case absent 'good missing' 2 incomplete
run_case optional 'good wp-access wp-uploads-deep' 0 partial
run_case nothing 'wp-access wp-uploads-deep' 2 incomplete
export PW_TEST_EMPTY=1
run_case nosites 'good' 2 incomplete
unset PW_TEST_EMPTY
export PW_TEST_DISCOVERY_FAILED=1
run_case discovery 'good' 2 incomplete incomplete
unset PW_TEST_DISCOVERY_FAILED

# A validator failure is not a clean scan. The new CLI does not execute a file.
printf '%s\0' "$TMP/not-present.js" > "$TMP/paths"
set +e
php "$REPO/lib/js-threat-cli.php" < "$TMP/paths" > "$TMP/js.out" 2> "$TMP/js.err"
rc=$?
set -e
[ "$rc" -eq 2 ]; [ ! -s "$TMP/js.out" ]; grep -q INCOMPLETE "$TMP/js.err"
# Dynamic payloads are text only, and findings redact query/credential material.
cat > "$TMP/fixture.js" <<'JS'
if(document.cookie){location.href=atob('aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvP3Rva2VuPXByaXZhdGU=');}
JS
printf '%s\0' "$TMP/fixture.js" | php "$REPO/lib/js-threat-cli.php" > "$TMP/js.out"
grep -q PW-JS-004 "$TMP/js.out"
! grep -qE 'token=|private|aHR0' "$TMP/js.out"
# A no-action contract, independent of global interactive/remediation settings.
! grep -E 'report .*\b(issue|review)\b' "$REPO/checks/js-threat-intel.sh" | grep -v noaction
# Identical contents reuse a result but keep the correct per-site filename.
cp "$TMP/fixture.js" "$TMP/duplicate.js"
printf '%s\0' "$TMP/fixture.js" "$TMP/duplicate.js" | php "$REPO/lib/js-threat-cli.php" > "$TMP/cached.out" 2> "$TMP/cached.err"
[ "$(grep -c PW-JS-004 "$TMP/cached.out")" -eq 2 ]
grep -q '1 unique analyses; 1 identical-file results reused' "$TMP/cached.err"
grep -q 'duplicate.js' "$TMP/cached.out"
# The same basename with different bytes must not share a cached verdict.
printf "location.href='/account'; const x=atob('aGVsbG8=');\n" > "$TMP/duplicate.js"
printf '%s\0' "$TMP/fixture.js" "$TMP/duplicate.js" | php "$REPO/lib/js-threat-cli.php" > "$TMP/cached.out" 2> "$TMP/cached.err"
[ "$(grep -c PW-JS-004 "$TMP/cached.out")" -eq 1 ]
grep -q '2 unique analyses; 0 identical-file results reused' "$TMP/cached.err"

# HTML examples are not live iframe execution; actual markup stays reviewable.
cat > "$TMP/frame.html" <<'HTML'
<div>Test</div>
<iframe src="https://frame.invalid/" style="display:none" onload="eval(atob('Misy'))"></iframe>
HTML
printf '%s\0' "$TMP/frame.html" | php "$REPO/lib/js-threat-cli.php" > "$TMP/frame.out" 2> "$TMP/frame.err"
grep -q 'PW-JS-003; line 2;' "$TMP/frame.out"
printf '<!--\n%s\n-->\n' "$(cat "$TMP/frame.html")" > "$TMP/comment.html"
printf '<textarea>%s</textarea>\n' "$(cat "$TMP/frame.html")" > "$TMP/example.html"
printf '%s\0' "$TMP/comment.html" "$TMP/example.html" | php "$REPO/lib/js-threat-cli.php" > "$TMP/inert.out" 2> "$TMP/inert.err"
[ ! -s "$TMP/inert.out" ]
printf 'PressWarden runtime reliability: PASS\n'
