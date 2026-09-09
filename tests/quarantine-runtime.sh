#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-quarantine-runtime.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/fleet/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/demo" "$SITE/wp-includes" "$TMP/home"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
export ROOT="$TMP/fleet" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state"
export PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 HOME="$TMP/home"
export PW_TEST_REPO="$REPO" PW_TEST_SITE="$SITE"
# Direct library use represents an already-approved generic action, not an automatic scan.
cat > "$TMP/approved.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
pw_report_init quarantine-test
printf '%s\n' "$PW_TEST_SITE/$1" > "$2"
_quarantine_delete "$2"
STUB
printf 'original evidence\n' > "$SITE/sample.php"
bash "$TMP/approved.sh" sample.php "$TMP/list" > "$TMP/action.out" 2>&1
[ ! -e "$SITE/sample.php" ]; grep -q 'QUARANTINED' "$TMP/action.out"
caseid=$(sed -n 's/^    Quarantine case: //p' "$TMP/action.out")
[ -n "$caseid" ]
bash "$REPO/presswarden" quarantine list > "$TMP/list.out"
grep -q "$caseid" "$TMP/list.out"
bash "$REPO/presswarden" quarantine verify "$caseid" > "$TMP/verify.out"
grep -q 'VERIFIED COPY' "$TMP/verify.out"
grep -q 'recorded complete' "$TMP/verify.out"
[ "$(cat "$TMP/state/quarantine/$caseid/objects/00001.bin")" = 'original evidence' ]
! grep -q 'original evidence' "$TMP/state/reports/"*.log
# Protected core, excluded roots and scanner state cannot enter direct approved removal.
for rel in wp-load.php wp-includes/version.php; do
  set +e; bash "$TMP/approved.sh" "$rel" "$TMP/protected-list" > "$TMP/protected.out" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]; [ -f "$SITE/$rel" ]
done
printf 'keep' > "$SITE/excluded.php"
set +e
PRESSWARDEN_EXCLUDE=example.com bash "$TMP/approved.sh" excluded.php "$TMP/exclude-list" > "$TMP/exclude.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; [ -f "$SITE/excluded.php" ]
# A prepared snapshot cannot be used to remove a replacement/changed file.
cat > "$TMP/changed.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
pw_report_init changed
printf '%s\n' "$PW_TEST_SITE/changed.php" > "$1"
_pw_quarantine_prepare "$1" || exit 9
printf 'new state' > "$PW_TEST_SITE/changed.php"
_quarantine_delete "$1" "$PW_Q_WORK/plan.json"; rc=$?
_pw_quarantine_discard_plan
[ "$rc" -eq 2 ] && [ "$PW_REMEDIATION_FAILED" -eq 1 ] || exit 9
finish
STUB
printf 'old state' > "$SITE/changed.php"
set +e; bash "$TMP/changed.sh" "$TMP/change-list" > "$TMP/changed.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; [ "$(cat "$SITE/changed.php")" = 'new state' ]; grep -q INCOMPLETE "$TMP/changed.out"
# Non-interactive findings never invoke a quarantine plan, let alone delete.
cat > "$TMP/noaction.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
pw_report_init noaction
printf '%s\n' "$PW_TEST_SITE/excluded.php" > "$1"
_pw_quarantine_prepare(){ echo UNSAFE; return 9; }
_prompt_file_action "$1" issue
STUB
bash "$TMP/noaction.sh" "$TMP/noaction-list" > "$TMP/noaction.out" 2>&1
! grep -q UNSAFE "$TMP/noaction.out"; [ -f "$SITE/excluded.php" ]
# Failed detail saving blocks the cleanup action too.
cat > "$TMP/failure.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
PW_REPORT_FAILED=1
_quarantine_delete "$1"
STUB
set +e; bash "$TMP/failure.sh" "$TMP/noaction-list" > "$TMP/failure.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; [ -f "$SITE/excluded.php" ]
# Inspection does not bootstrap WordPress, discover sites or create runtime reports.
mkdir "$TMP/fakebin"
printf '#!/bin/sh\necho UNEXPECTED_WP >&2; exit 99\n' > "$TMP/fakebin/wp"; chmod +x "$TMP/fakebin/wp"
PATH="$TMP/fakebin:$PATH" PRESSWARDEN_STATE_DIR="$TMP/empty-state" bash "$REPO/presswarden" quarantine list > "$TMP/empty.out"
[ ! -e "$TMP/empty-state" ]; ! grep -q UNEXPECTED_WP "$TMP/empty.out"
for arg in ../escape invalid; do
  set +e; bash "$REPO/presswarden" quarantine verify "$arg" > "$TMP/bad.out" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]
done
set +e; bash "$REPO/presswarden" quarantine restore "$caseid" > "$TMP/bad.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]
# Parallel, identical-content targets create independent cases without overwriting history.
pids=()
for i in 1 2 3 4; do
  printf 'parallel evidence' > "$SITE/parallel-$i.php"
  bash "$TMP/approved.sh" "parallel-$i.php" "$TMP/parallel-list-$i" > "$TMP/parallel-$i.out" 2>&1 & pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done
[ "$(sed -n 's/^    Quarantine case: //p' "$TMP"/parallel-*.out | sort -u | wc -l)" -eq 4 ]
for i in 1 2 3 4; do [ ! -e "$SITE/parallel-$i.php" ]; done
printf 'Quarantine runtime, privacy, protected scope and concurrency: PASS\n'
