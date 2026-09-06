#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-yara.$$"
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/demo" "$SITE/wp-includes" "$TMP/bin"
touch "$SITE/wp-settings.php" "$SITE/wp-load.php" "$SITE/wp-content/plugins/demo/bad.php"
printf '<?php $wp_version = "7.1";\n' > "$SITE/wp-includes/version.php"
printf 'rule FakeRule { condition: true }\n' > "$TMP/rules.yar"
cat > "$TMP/bin/yara" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = '-r' ]
target="$3"
printf 'FakeRule %s/wp-content/plugins/demo/bad.php\n' "$target"
SH
chmod +x "$TMP/bin/yara"

out=$(ROOT="$TMP/sites" PATH="$TMP/bin:$PATH" PRESSWARDEN_YARA_RULES="$TMP/rules.yar" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/external-yara.sh" 2>&1 || true)
printf '%s\n' "$out" | grep -q 'external YARA match — FakeRule'
printf '%s\n' "$out" | grep -q 'bad.php'
printf '%s\n' "$out" | grep -q 'REVIEW'

skip=$(ROOT="$TMP/sites" PATH="$TMP/bin:$PATH" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-skip" PRESSWARDEN_CACHE_DIR="$TMP/cache-skip" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/external-yara.sh" 2>&1)
printf '%s\n' "$skip" | grep -q 'PRESSWARDEN_YARA_RULES is not configured'

status=$(PATH="$TMP/bin:$PATH" PRESSWARDEN_YARA_RULES="$TMP/rules.yar" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-status" "$ROOTDIR/presswarden" intel status)
printf '%s\n' "$status" | grep -qE 'External YARA rules[[:space:]]+configured / ready$'
config=$(PATH="$TMP/bin:$PATH" PRESSWARDEN_YARA_RULES="$TMP/rules.yar" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state-config" "$ROOTDIR/presswarden" config)
printf '%s\n' "$config" | grep -qE 'External YARA:[[:space:]]+configured$'

if find "$ROOTDIR/intel" -type f \( -name '*.yar' -o -name '*.yara' \) | grep -q .; then
  printf 'bundled YARA signatures found under intel/; external-only contract violated\n' >&2
  exit 1
fi

grep -q 'external-yara' "$ROOTDIR/suites/full.sh"
grep -q 'external-yara' "$ROOTDIR/suites/intel.sh"
printf 'PressWarden external YARA integration: PASS\n'
