#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-php-runtime.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.invalid/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-includes" "$SITE/wp-content/plugins/example"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
cat > "$SITE/wp-content/plugins/example/fixture.php" <<'PHP'
<?php
$f=$_REQUEST['function'];
$f();
PHP
# No site file may be executed, and values do not belong in evidence output.
printf '\nfile_put_contents("%s", "executed");\n$secret="private-value-not-for-logs";\n' "$TMP/EXECUTED" >> "$SITE/wp-content/plugins/example/fixture.php"
cp "$SITE/wp-content/plugins/example/fixture.php" "$SITE/wp-content/plugins/example/copy.php"
printf '%s\0' "$SITE/wp-content/plugins/example/fixture.php" "$SITE/wp-content/plugins/example/copy.php" | php "$REPO/lib/php-threat-cli.php" > "$TMP/out" 2> "$TMP/err"
[ "$(grep -c PW-PHP-004 "$TMP/out")" -eq 2 ]
grep -q 'line 3;' "$TMP/out"
grep -q '1 unique analyses; 1 identical-file results reused' "$TMP/err"
! grep -q 'private-value-not-for-logs' "$TMP/out"
[ ! -e "$TMP/EXECUTED" ]
# Same name, changed bytes must invalidate the result cache.
printf '<?php $f=$_REQUEST["function"]; $f="strlen"; $f("x");\n' > "$SITE/wp-content/plugins/example/copy.php"
printf '%s\0' "$SITE/wp-content/plugins/example/fixture.php" "$SITE/wp-content/plugins/example/copy.php" | php "$REPO/lib/php-threat-cli.php" > "$TMP/out" 2> "$TMP/err"
[ "$(grep -c PW-PHP-004 "$TMP/out")" -eq 1 ]
grep -q '2 unique analyses; 0 identical-file results reused' "$TMP/err"
odd="$SITE/wp-content/plugins/example/"$'line\nwith\033control.php'
cp "$SITE/wp-content/plugins/example/fixture.php" "$odd"
printf '%s\0' "$odd" | php "$REPO/lib/php-threat-cli.php" > "$TMP/odd.out" 2> "$TMP/odd.err"
[ "$(wc -l < "$TMP/odd.out")" -eq 1 ]; ! grep -q $'\033' "$TMP/odd.out"
grep -Fq '\x0A' "$TMP/odd.out"
set +e
printf '%s\0' "$SITE/wp-content/plugins/example/fixture.php" "$TMP/missing.php" | php "$REPO/lib/php-threat-cli.php" > "$TMP/partial.out" 2> "$TMP/partial.err"
rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q PW-PHP-004 "$TMP/partial.out"; grep -q INCOMPLETE "$TMP/partial.err"
# Shell integration uses real discovery and reports findings, not exceptions as CLEAN.
scan() {
  ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 bash "$REPO/checks/php-threat-intel.sh"
}
set +e
scan > "$TMP/scan.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]; grep -q 'fixture.php' "$TMP/scan.out"
printf '<?php if(true){ base64_decode("private-payload");\n' > "$SITE/wp-content/plugins/example/broken.php"
set +e
scan > "$TMP/incomplete.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'INCOMPLETE' "$TMP/incomplete.out"
! grep -q 'CLEAN' "$TMP/incomplete.out"
! grep -q 'private-payload' "$TMP/incomplete.out"
grep -q 'fixture.php' "$TMP/incomplete.out"
grep -q 'findings: .*retained' "$TMP/incomplete.out"
! grep -E 'report .*\b(issue|review)\b' "$REPO/checks/php-threat-intel.sh" | grep -v noaction
# A failed PHP executable is a dependency/validator failure, never a clean pass.
mkdir "$TMP/bin"
printf '#!/usr/bin/env bash\nexit 99\n' > "$TMP/bin/php"; chmod +x "$TMP/bin/php"
set +e
PATH="$TMP/bin:$PATH" scan > "$TMP/failure.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]; ! grep -q 'CLEAN' "$TMP/failure.out"
# Output failure is also incomplete, not silent success.
if [ -c /dev/full ]; then
  set +e
  printf '%s\0' "$SITE/wp-content/plugins/example/fixture.php" | php "$REPO/lib/php-threat-cli.php" > /dev/full 2> "$TMP/full.err"
  rc=$?
  set -e
  [ "$rc" -eq 2 ]
fi
printf 'PHP runtime privacy, cache, read-only and incomplete-result tests: PASS\n'
