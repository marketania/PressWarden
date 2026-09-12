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

printf 'Safe continuation scope, replay and refusal semantics: PASS\n'
