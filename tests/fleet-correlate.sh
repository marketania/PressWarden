#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/presswarden-correlate-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
ROOT="$TMP/fleet"
STATE="$TMP/state"

make_site() {
  local site="$1"
  mkdir -p "$site/wp-admin" "$site/wp-includes" "$site/wp-content/plugins/demo"
  cat > "$site/wp-includes/version.php" <<'PHP'
<?php
$wp_version = '6.8.2';
PHP
  printf '%s\n' '<?php // wp settings' > "$site/wp-settings.php"
  printf '%s\n' '<?php // wp load' > "$site/wp-load.php"
  printf '%s\n' '<?php define("DB_NAME", "example");' > "$site/wp-config.php"
  printf '%s\n' '<?php function shared_legit_plugin(){ return true; }' > "$site/wp-content/plugins/demo/demo.php"
}

make_site "$ROOT/one.com/public_html"
make_site "$ROOT/two.com/public_html"

export HOME="$TMP/home"
mkdir -p "$HOME" "$STATE"
export PRESSWARDEN_CONFIG_FILE="$TMP/no-config"
export PRESSWARDEN_STATE_DIR="$STATE"
export PRESSWARDEN_CACHE_DIR="$STATE/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0
export PRESSWARDEN_INTERACTIVE=0
export PRESSWARDEN_NOCOLOR=1
export PRESSWARDEN_OUTPUT_JSON=0

bash "$REPO/presswarden" baseline create "$ROOT" > "$TMP/create.out"

# Identical legitimate files that were already present at baseline must not be
# flagged just because the same package exists on multiple sites.
clean_out="$TMP/clean.out"
ROOT="$ROOT" PRESSWARDEN_DIR="$REPO" bash "$REPO/checks/fleet-correlate.sh" > "$clean_out"
grep -q 'no repeated new/changed artifacts' "$clean_out"
grep -q 'findings:.*0' "$clean_out"

# The same new code artifact appearing on two sites is a fleet-spread signal.
payload='<?php $x = "same newly introduced artifact";'
printf '%s\n' "$payload" > "$ROOT/one.com/public_html/wp-content/plugins/demo/new-helper.php"
printf '%s\n' "$payload" > "$ROOT/two.com/public_html/wp-content/plugins/demo/new-helper.php"

corr_out="$TMP/correlate.out"
set +e
ROOT="$ROOT" PRESSWARDEN_DIR="$REPO" bash "$REPO/checks/fleet-correlate.sh" > "$corr_out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$corr_out" >&2; echo "Expected correlation review exit 1, got $rc" >&2; exit 1; }
grep -q 'FLEET FILE.*2 sites' "$corr_out"
grep -q 'one.com' "$corr_out"
grep -q 'two.com' "$corr_out"
grep -q 'REVIEW' "$corr_out"
grep -q 'findings:.*1' "$corr_out"

# Correlation is evidence only and must never remove the files it reports.
[ -f "$ROOT/one.com/public_html/wp-content/plugins/demo/new-helper.php" ]
[ -f "$ROOT/two.com/public_html/wp-content/plugins/demo/new-helper.php" ]

printf 'Fleet correlation regression tests passed.\n'
