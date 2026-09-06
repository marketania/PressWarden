#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/presswarden-incident-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
ROOT="$TMP/fleet"
STATE="$TMP/state"
SITE="$ROOT/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-includes" "$SITE/wp-content/plugins/demo" "$STATE" "$TMP/home"

cat > "$SITE/wp-includes/version.php" <<'PHP'
<?php
$wp_version = '6.8.2';
PHP
printf '%s\n' '<?php // wp settings' > "$SITE/wp-settings.php"
printf '%s\n' '<?php // wp load' > "$SITE/wp-load.php"
printf '%s\n' '<?php define("DB_NAME", "example");' > "$SITE/wp-config.php"
printf '%s\n' '<?php function incident_demo(){ return true; }' > "$SITE/wp-content/plugins/demo/demo.php"

export HOME="$TMP/home"
export PRESSWARDEN_CONFIG_FILE="$TMP/no-config"
export PRESSWARDEN_STATE_DIR="$STATE"
export PRESSWARDEN_CACHE_DIR="$STATE/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0
export PRESSWARDEN_INTERACTIVE=0
export PRESSWARDEN_NOCOLOR=1
export PRESSWARDEN_OUTPUT_JSON=0

help_out="$TMP/help.out"
bash "$REPO/presswarden" help > "$help_out"
grep -q './presswarden incident \[path\]' "$help_out"

# Incident response is evidence-first: it must include baseline/persistence/account
# investigation but must not run database maintenance/repair automatically.
grep -q 'baseline-changes' "$REPO/suites/incident.sh"
grep -q 'host-persistence' "$REPO/suites/incident.sh"
grep -q 'wp-access' "$REPO/suites/incident.sh"
grep -q 'wp-db-malware' "$REPO/suites/incident.sh"
grep -q 'PRESSWARDEN_ADMINS_CHECK=1' "$REPO/suites/incident.sh"
if grep -Eq 'CHECKS=.*(^|[[:space:]\"])(wp-db-maintenance)([[:space:]\"]|$)' "$REPO/suites/incident.sh"; then
  echo 'Incident suite must not run database repair/optimization.' >&2
  exit 1
fi

# A missing baseline is optional context, not an incident-mode error.
no_base="$TMP/no-baseline.out"
ROOT="$ROOT" PRESSWARDEN_DIR="$REPO" bash "$REPO/checks/baseline-changes.sh" > "$no_base"
grep -q 'No baseline exists' "$no_base"
grep -q 'findings:.*0' "$no_base"

# Once a baseline exists, a code change is review-only and never removed.
bash "$REPO/presswarden" baseline create "$ROOT" > "$TMP/create.out"
printf '%s\n' '<?php function incident_demo(){ return false; }' > "$SITE/wp-content/plugins/demo/demo.php"

change_out="$TMP/change.out"
set +e
ROOT="$ROOT" PRESSWARDEN_DIR="$REPO" bash "$REPO/checks/baseline-changes.sh" > "$change_out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$change_out" >&2; echo "Expected review exit code 1, got $rc" >&2; exit 1; }
grep -q 'REVIEW' "$change_out"
grep -q 'CHANGED FILE.*example.com.*demo.php' "$change_out"
grep -q 'findings:.*1' "$change_out"
[ -f "$SITE/wp-content/plugins/demo/demo.php" ] || { echo 'Baseline review unexpectedly removed a changed file.' >&2; exit 1; }

printf 'Incident mode regression tests passed.\n'
