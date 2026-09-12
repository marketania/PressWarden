#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-continue.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
STATE="$REPO/lib/run-state.php"; CONT="$REPO/lib/run-continuation.php"
mkdir -p "$TMP/root/site-a/wp-admin" "$TMP/root/site-a/wp-content" "$TMP/root/excluded"
RUNS="$TMP/runs"; ID='full-20260911-210000.CONT01'
SCOPE="$TMP/scope.tsv"
printf 'ROOT\t%s\nDEPTH\t8\nSITE\t%s\nEXCLUDE\t%s\n' "$TMP/root" "$TMP/root/site-a" "$TMP/root/excluded" > "$SCOPE"
php "$STATE" init "$RUNS" "$ID" full 1.1.17 "$TMP/root" 1 1 2 complete 12345 'one two' "$TMP/report.log" 1789160000
php "$CONT" capture "$RUNS/$ID" "$SCOPE"
[ "$(stat -c %a "$RUNS/$ID/scope.json" 2>/dev/null)" = 600 ]
php "$STATE" step "$RUNS/$ID/state.json" 1 2 one
php "$STATE" result "$RUNS/$ID/state.json" one findings 2 4
php "$STATE" step "$RUNS/$ID/state.json" 2 2 two
php "$STATE" interrupt "$RUNS/$ID/state.json" HUP 129 two

php "$CONT" plan "$RUNS" "$ID" 1.1.17 > "$TMP/plan"
grep -q $'^SUITE\tfull$' "$TMP/plan"
grep -q $'^ROOT\t'"$TMP/root"'$' "$TMP/plan"
grep -q $'^START\ttwo$' "$TMP/plan"
grep -q $'^INDEX\t2$' "$TMP/plan"
grep -q $'^CARRY\t1$' "$TMP/plan"
grep -q $'^EXCLUDE\t'"$TMP/root/excluded"'$' "$TMP/plan"

CARRY="$TMP/carry.tsv"; : > "$CARRY"
php "$CONT" verify "$RUNS" "$ID" 1.1.17 full 'one two' "$SCOPE" "$CARRY" > "$TMP/verify"
grep -q $'^START\ttwo$' "$TMP/verify"
grep -q $'^CARRY\t1$' "$TMP/verify"
grep -q $'^one\t2\tfindings\t4$' "$CARRY"

# Stored scope is internally authenticated against its own canonical fields so
# accidental corruption cannot silently redirect a continuation.
cp "$RUNS/$ID/scope.json" "$TMP/scope-good.json"
php -r '$p=$argv[1]; $j=json_decode(file_get_contents($p),true); $j["root"].="/corrupt"; file_put_contents($p,json_encode($j,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n");' "$RUNS/$ID/scope.json"
set +e; php "$CONT" plan "$RUNS" "$ID" 1.1.17 > "$TMP/corrupt.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'scope fingerprint mismatch' "$TMP/corrupt.out"
cp "$TMP/scope-good.json" "$RUNS/$ID/scope.json"; chmod 600 "$RUNS/$ID/scope.json"

# Scope recording follows the same invalid/zero discovery-depth fallback used by discovery.
DEPTH_OUT="$TMP/depth.tsv"
PW_DEPTH_REPO="$REPO" PW_DEPTH_ROOT="$TMP/root" PW_DEPTH_OUT="$DEPTH_OUT" bash -c 'ROOT="$PW_DEPTH_ROOT"; PRESSWARDEN_DISCOVERY_DEPTH=bogus; SCAN_ROOTS=("$ROOT/site-a"); _PW_TARGET_EXCLUSIONS=""; . "$PW_DEPTH_REPO/lib/run-continuation.sh"; _pw_continue_scope_file "$PW_DEPTH_OUT"'
grep -q $'^DEPTH\t8$' "$DEPTH_OUT"
PW_DEPTH_REPO="$REPO" PW_DEPTH_ROOT="$TMP/root" PW_DEPTH_OUT="$DEPTH_OUT" bash -c 'ROOT="$PW_DEPTH_ROOT"; PRESSWARDEN_DISCOVERY_DEPTH=0; SCAN_ROOTS=("$ROOT/site-a"); _PW_TARGET_EXCLUSIONS=""; . "$PW_DEPTH_REPO/lib/run-continuation.sh"; _pw_continue_scope_file "$PW_DEPTH_OUT"'
grep -q $'^DEPTH\t8$' "$DEPTH_OUT"

# Scope/version/check-plan changes must refuse continuation rather than mixing audits.
printf 'ROOT\t%s\nDEPTH\t8\nSITE\t%s\n' "$TMP/root" "$TMP/root/site-a/changed" > "$TMP/scope-bad.tsv"
for mode in scope version plan; do
  set +e
  case "$mode" in
    scope) php "$CONT" verify "$RUNS" "$ID" 1.1.17 full 'one two' "$TMP/scope-bad.tsv" "$CARRY" > "$TMP/$mode.out" 2>&1 ;;
    version) php "$CONT" plan "$RUNS" "$ID" 9.9.9 > "$TMP/$mode.out" 2>&1 ;;
    plan) php "$CONT" verify "$RUNS" "$ID" 1.1.17 full 'one three' "$SCOPE" "$CARRY" > "$TMP/$mode.out" 2>&1 ;;
  esac
  rc=$?; set -e; [ "$rc" -eq 2 ]
done
grep -q 'site scope changed' "$TMP/scope.out"
grep -q 'version changed' "$TMP/version.out"
grep -q 'check plan changed' "$TMP/plan.out"

# Completed runs and old runs without scope metadata are not resumable.
DONE='fast-20260911-210100.DONE01'
php "$STATE" init "$RUNS" "$DONE" fast 1.1.17 "$TMP/root" 1 1 1 complete 12345 one "$TMP/done.log" 1789160010
php "$CONT" capture "$RUNS/$DONE" "$SCOPE"
php "$STATE" step "$RUNS/$DONE/state.json" 1 1 one
php "$STATE" result "$RUNS/$DONE/state.json" one clean 0 1
php "$STATE" finish "$RUNS/$DONE/state.json" COMPLETED 0
set +e; php "$CONT" plan "$RUNS" "$DONE" 1.1.17 > "$TMP/done.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'only interrupted' "$TMP/done.out"
OLD='fast-20260911-210200.OLD001'
php "$STATE" init "$RUNS" "$OLD" fast 1.1.17 "$TMP/root" 1 1 1 complete 12345 one "$TMP/old.log" 1789160020
php "$STATE" step "$RUNS/$OLD/state.json" 1 1 one
php "$STATE" interrupt "$RUNS/$OLD/state.json" TERM 143 one
set +e; php "$CONT" plan "$RUNS" "$OLD" 1.1.17 > "$TMP/old.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'predates safe continuation' "$TMP/old.out"

# Automatic DB maintenance is intentionally non-replayable when interrupted mid-check.
DBID='db-20260911-210300.DB0001'
php "$STATE" init "$RUNS" "$DBID" db 1.1.17 "$TMP/root" 1 1 2 complete 12345 'wp-db wp-db-maintenance' "$TMP/db.log" 1789160030
php "$CONT" capture "$RUNS/$DBID" "$SCOPE"
php "$STATE" step "$RUNS/$DBID/state.json" 1 2 wp-db
php "$STATE" result "$RUNS/$DBID/state.json" wp-db clean 0 2
php "$STATE" step "$RUNS/$DBID/state.json" 2 2 wp-db-maintenance
php "$STATE" interrupt "$RUNS/$DBID/state.json" HUP 129 wp-db-maintenance
set +e; php "$CONT" plan "$RUNS" "$DBID" 1.1.17 > "$TMP/db.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'automatic database writes' "$TMP/db.out"

# Scope metadata remains allowlisted/private; unrelated environment secrets are never captured.
DB_PASSWORD='continue-secret' API_KEY='also-secret' php "$CONT" plan "$RUNS" "$ID" 1.1.17 >/dev/null
! grep -R -q 'continue-secret\|also-secret' "$RUNS"


# End-to-end shared runner: completed prefix is carried, not executed again;
# first unfinished check runs and the combined summary preserves parent findings.
E2E="$TMP/e2e"; mkdir -p "$E2E/repo/lib" "$E2E/repo/checks" "$E2E/reports" "$E2E/state" "$E2E/root/site/wp-admin" "$E2E/root/site/wp-content"
cp "$REPO/lib/_runner.sh" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/suite-summary.php" \
   "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$REPO/lib/run-continuation.sh" "$REPO/lib/run-continuation.php" "$E2E/repo/lib/"
cat > "$E2E/repo/lib/_lib.sh" <<'EOF'
PRESSWARDEN_DIR="$PW_E2E_REPO"; ROOT="$PW_E2E_ROOT"; REPORTS="$PW_E2E_REPORTS"; PRESSWARDEN_STATE_DIR="$PW_E2E_STATE"
PRESSWARDEN_VERSION=1.1.17; PRESSWARDEN_DISCOVERY_DEPTH=8; PRESSWARDEN_INTERACTIVE=0; PRESSWARDEN_OUTPUT_JSON=1
B=''; C=''; X=''; D=''; Y=''; G=''; R=''; BL=''; W=60; T0=$(date +%s)
SCAN_ROOTS=("$ROOT/site"); NESTED_SITES=(); MANUAL_EXCLUDED_DOMAINS=(); PW_DISCOVERY_FAILED=0
count_sites(){ echo 1; }; count_domains(){ echo 1; }; nested_sites_summary(){ :; }; manual_exclusions_summary(){ :; }
_meta_field(){ :; }; _repeat(){ :; }; _rule(){ echo '---'; }; human_time(){ printf '%ss' "$1"; }; tmpf(){ mktemp; }; die(){ echo "$1" >&2; exit 2; }
. "$PRESSWARDEN_DIR/lib/reports.sh"
EOF
cat > "$E2E/repo/checks/one.sh" <<'EOF'
echo executed-one > "$PW_E2E_ONE_MARKER"
echo 'findings: 9'; exit 1
EOF
cat > "$E2E/repo/checks/two.sh" <<'EOF'
echo executed-two > "$PW_E2E_TWO_MARKER"
echo 'findings: 0'; exit 0
EOF
PARENT='fast-20260911-220000.E2E001'; E2ERUNS="$E2E/state/runs"; E2ESCOPE="$E2E/scope.tsv"
printf 'ROOT\t%s\nDEPTH\t8\nSITE\t%s\n' "$E2E/root" "$E2E/root/site" > "$E2ESCOPE"
php "$STATE" init "$E2ERUNS" "$PARENT" fast 1.1.17 "$E2E/root" 1 1 2 complete 12345 'one two' "$E2E/parent.log" 1789160100
php "$CONT" capture "$E2ERUNS/$PARENT" "$E2ESCOPE"
php "$STATE" step "$E2ERUNS/$PARENT/state.json" 1 2 one
php "$STATE" result "$E2ERUNS/$PARENT/state.json" one findings 2 4
php "$STATE" step "$E2ERUNS/$PARENT/state.json" 2 2 two
php "$STATE" interrupt "$E2ERUNS/$PARENT/state.json" HUP 129 two
set +e
PW_E2E_REPO="$E2E/repo" PW_E2E_ROOT="$E2E/root" PW_E2E_REPORTS="$E2E/reports" PW_E2E_STATE="$E2E/state" \
PW_E2E_ONE_MARKER="$E2E/one-ran" PW_E2E_TWO_MARKER="$E2E/two-ran" PRESSWARDEN_CONTINUE_FROM="$PARENT" \
bash -c 'RUN_NAME=fast; RUN_DESC=test; RUN_DOES=test; RUN_WHY=test; CHECKS="one two"; . "$1/lib/_runner.sh"; run_all' _ "$E2E/repo" > "$E2E/out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
[ ! -e "$E2E/one-ran" ]
[ -e "$E2E/two-ran" ]
grep -q '▶ CARRY.*one' "$E2E/out"
grep -q '▶ RUN.*two' "$E2E/out"
LATEST=$(cat "$E2E/state/runs/latest")
[ "$LATEST" != "$PARENT" ]
[ -f "$E2E/state/runs/$LATEST/scope.json" ]
grep -q '"continued_from": "'"$PARENT"'"' "$E2E/reports/fast-latest-summary.json"
grep -q '"checks_carried": 1' "$E2E/reports/fast-latest-summary.json"
grep -q '"total_findings": 2' "$E2E/reports/fast-latest-summary.json"

printf 'Safe continuation scope, replay and refusal semantics: PASS\n'
