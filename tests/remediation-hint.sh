#!/usr/bin/env bash
# Routine scans only name the remediation command; explicit remediation covers exposure findings.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-remediation-hint.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/fleet/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content" "$SITE/wp-includes" "$TMP/home"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
printf 'SECRET=1\n' > "$SITE/.env"
export ROOT="$TMP/fleet" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state"
export PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 HOME="$TMP/home"
export PW_TEST_REPO="$REPO" PW_TEST_SITE="$SITE" _PW_EXPLICIT_REMEDIATION=0
cat > "$TMP/hint.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
NAME="$1"; pw_report_init "$1"
printf '%s\n' "$PW_TEST_SITE/.env" > "$2"
_pw_quarantine_prepare(){ echo UNSAFE; return 9; }
_prompt_file_action "$2" "$3"
STUB
bash "$TMP/hint.sh" sensitive-files "$TMP/l1" issue > "$TMP/hint.out" 2>&1
grep -q 'run: ./presswarden remediate files' "$TMP/hint.out"
! grep -q UNSAFE "$TMP/hint.out"; [ -f "$SITE/.env" ]
bash "$TMP/hint.sh" sensitive-files "$TMP/l2" info > "$TMP/info.out" 2>&1
! grep -q 'remediate files' "$TMP/info.out"
bash "$TMP/hint.sh" wp-plugins "$TMP/l3" issue > "$TMP/other.out" 2>&1
! grep -q 'remediate files' "$TMP/other.out"
# The explicit suite runs the exposure check; routine sections no longer opt out of its prompt.
grep -q "^CHECKS='.*sensitive-files" "$REPO/suites/remediate-files.sh"
! grep -E '^ *report .*noaction' "$REPO/checks/sensitive-files.sh"
printf 'Remediation hint and exposure remediation scope: PASS\n'
