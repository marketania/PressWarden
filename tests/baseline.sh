#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/presswarden-baseline-test.XXXXXX")"
trap 'rc=$?; printf "Baseline test failed near line %s (exit %s)\n" "$LINENO" "$rc" >&2; for f in "$TMP"/*.out; do [ -f "$f" ] && { printf "--- %s ---\n" "$f" >&2; cat "$f" >&2; }; done; exit "$rc"' ERR
trap 'rm -rf "$TMP"' EXIT
ROOT="$TMP/fleet"
STATE="$TMP/state"
BIN="$TMP/bin"
mkdir -p "$ROOT/example.com/public_html/wp-admin" "$ROOT/example.com/public_html/wp-includes" "$ROOT/example.com/public_html/wp-content/plugins/demo" "$ROOT/example.com/public_html/wp-content/themes/demo" "$ROOT/example.com/public_html/wp-content/uploads/2026/09" "$STATE" "$BIN" "$TMP/home"
SITE="$ROOT/example.com/public_html"

cat > "$SITE/wp-includes/version.php" <<'PHP'
<?php
$wp_version = '6.8.2';
PHP
printf '%s\n' '<?php // wp settings' > "$SITE/wp-settings.php"
printf '%s\n' '<?php // wp load' > "$SITE/wp-load.php"
printf '%s\n' '<?php define("DB_NAME", "example"); // TOP_SECRET_BASELINE_TEST' > "$SITE/wp-config.php"
printf '%s\n' '<?php function demo_plugin(){ return true; }' > "$SITE/wp-content/plugins/demo/demo.php"
printf '%s\n' 'console.log("baseline");' > "$SITE/wp-content/themes/demo/app.js"
printf '%s\n' '<?php echo "media";' > "$SITE/wp-content/uploads/2026/09/not-really-an-image.php"

cat > "$BIN/wp" <<'SH'
#!/usr/bin/env bash
set -eu
case "${1:-} ${2:-}" in
  'plugin list')
    printf 'name,status,version\n'
    printf 'demo,active,%s\n' "${FAKE_PLUGIN_VERSION:-1.0.0}"
    ;;
  'theme list')
    printf 'name,status,version\n'
    printf 'demo,active,1.0.0\n'
    ;;
  'user list')
    printf 'user_login\n'
    printf 'siteadmin\n'
    [ "${FAKE_EXTRA_ADMIN:-0}" = 1 ] && printf 'backupadmin\n'
    ;;
  'cron event')
    printf 'hook,recurrence\n'
    printf 'wp_version_check,Twice Daily\n'
    ;;
  *) exit 1 ;;
esac
SH
chmod +x "$BIN/wp"

export PATH="$BIN:$PATH"
export HOME="$TMP/home"
export PRESSWARDEN_CONFIG_FILE="$TMP/no-config"
export PRESSWARDEN_STATE_DIR="$STATE"
export PRESSWARDEN_CACHE_DIR="$STATE/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0
export PRESSWARDEN_INTERACTIVE=0
export PRESSWARDEN_NOCOLOR=1
export PRESSWARDEN_BASELINE_MAX_CHANGES=50

create_out="$TMP/create.out"
bash "$REPO/presswarden" baseline create "$ROOT" > "$create_out"
grep -q 'Baseline created' "$create_out"
grep -q 'Sites:.*1' "$create_out"

manifest=$(find "$STATE/baselines" -path '*/current/manifest.tsv' -type f -print -quit)
[ -n "$manifest" ] && [ -s "$manifest" ]
grep -q $'^F\texample.com\twp-config.php\t' "$manifest"
grep -q $'^P\texample.com\tdemo\tactive|1.0.0$' "$manifest"
grep -q $'^T\texample.com\tdemo\tactive|1.0.0$' "$manifest"
grep -q $'^A\texample.com\tsiteadmin\tadministrator$' "$manifest"
grep -q $'^C\texample.com\twp_version_check\tTwice Daily$' "$manifest"
if grep -q 'TOP_SECRET_BASELINE_TEST' "$manifest"; then
  echo 'Baseline leaked file contents instead of storing hashes.' >&2
  exit 1
fi
if grep -q 'wp-content/uploads' "$manifest"; then
  echo 'Volatile uploads unexpectedly entered the security baseline.' >&2
  exit 1
fi

status_out="$TMP/status.out"
bash "$REPO/presswarden" baseline status "$ROOT" > "$status_out"
grep -q 'Status:.*ready' "$status_out"

printf '%s\n' '<?php function demo_plugin(){ return false; }' > "$SITE/wp-content/plugins/demo/demo.php"
printf '%s\n' '<?php echo "new security-relevant file";' > "$SITE/wp-content/plugins/demo/new-helper.php"
rm -f "$SITE/wp-content/themes/demo/app.js"
printf '%s\n' '<?php echo "changed media";' > "$SITE/wp-content/uploads/2026/09/not-really-an-image.php"
export FAKE_PLUGIN_VERSION=1.1.0
export FAKE_EXTRA_ADMIN=1

diff_out="$TMP/diff.out"
set +e
bash "$REPO/presswarden" changes "$ROOT" > "$diff_out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$diff_out" >&2; echo "Expected baseline diff exit 1, got $rc" >&2; exit 1; }
grep -q 'BASELINE CHANGES' "$diff_out"
grep -q 'CHANGED.*demo.php' "$diff_out"
grep -q 'NEW FILE.*new-helper.php' "$diff_out"
grep -q 'REMOVED.*app.js' "$diff_out"
grep -q 'PLUGIN.*demo' "$diff_out"
grep -q 'ADMIN.*backupadmin' "$diff_out"
if grep -q 'not-really-an-image.php' "$diff_out"; then
  echo 'Upload-only change created baseline noise.' >&2
  exit 1
fi

bash "$REPO/presswarden" baseline create "$ROOT" > "$TMP/recreate.out"
history_count=$(find "$STATE/baselines" -path '*/history/*/manifest.tsv' -type f | wc -l | tr -d '[:space:]')
[ "$history_count" -ge 1 ] || { echo 'Previous baseline was not preserved in history.' >&2; exit 1; }

clean_out="$TMP/clean.out"
bash "$REPO/presswarden" baseline diff "$ROOT" > "$clean_out"
grep -q 'No security-baseline changes detected' "$clean_out"

printf 'Baseline regression tests passed.\n'
