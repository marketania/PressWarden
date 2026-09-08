#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-inspect-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cp -a "$REPO" "$TMP/repo"
rm -rf "$TMP/repo/.git"
SITE="$TMP/sites/example.invalid/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/test" "$SITE/wp-includes" "$TMP/bin" "$TMP/state/quarantine" "$TMP/cache"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
printf '<?php $f=$_GET["fn"]; $f("test");\n' > "$SITE/wp-content/plugins/test/example.php"
printf "if(document.cookie){location.href=atob('aHR0cHM6Ly9leGFtcGxlLmludmFsaWQv');}\n" > "$SITE/wp-content/plugins/test/example.js"
cat > "$TMP/bin/wp" <<'WP'
#!/usr/bin/env bash
[ "$1" = eval-file ] || exit 90
printf 'PWDB1\tDONE\t0\t0\t1\t20\n'
WP
for bin in curl wget; do
  printf '#!/usr/bin/env bash\nprintf NETWORK_CALLED >> "$PW_TEST_NETWORK"\nexit 99\n' > "$TMP/bin/$bin"
done
chmod +x "$TMP/bin/"*
printf 'PRESSWARDEN_INTERACTIVE=1\n' > "$TMP/config"
printf 'quarantine evidence\n' > "$TMP/state/quarantine/evidence.php"
before=$(sha256sum "$TMP/config" "$TMP/state/quarantine/evidence.php" "$SITE/wp-content/plugins/test/"*)
export PRESSWARDEN_CONFIG_FILE="$TMP/config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache"
export PRESSWARDEN_NOCOLOR=1 PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PATH="$TMP/bin:$PATH" PW_TEST_NETWORK="$TMP/network"
run(){ bash "$TMP/repo/presswarden" "$@"; }
run inspect > "$TMP/help"
grep -q 'inspect php|js|db' "$TMP/help"
for spec in php:1:php-threat-intel js:1:js-threat-intel db:0:wp-db-malware; do
  kind=${spec%%:*}; rest=${spec#*:}; expected=${rest%%:*}; check=${rest#*:}
  set +e; run inspect "$kind" "$TMP/sites" > "$TMP/$kind.out" 2>&1; rc=$?; set -e
  [ "$rc" -eq "$expected" ] || { cat "$TMP/$kind.out"; echo "unexpected $kind exit $rc"; exit 1; }
  php -r '$j=json_decode(file_get_contents($argv[1]),true);if(!$j||count($j["checks"])!==1||$j["checks"][0]["check"]!==$argv[2]||$j["coverage_status"]!=="complete"||empty($j["run_id"]))exit(1);' "$TMP/state/reports/inspect-$kind-latest-summary.json" "$check"
  ! grep -qE 'delete \+ quarantine|repair|optimiz' "$TMP/$kind.out"
done
[ ! -e "$TMP/network" ]
[ "$(sha256sum "$TMP/config" "$TMP/state/quarantine/evidence.php" "$SITE/wp-content/plugins/test/"*)" = "$before" ]
# Explicit exclusions and missing scopes are handled by existing discovery.
set +e; PRESSWARDEN_EXCLUDE=example.invalid run inspect js "$TMP/sites" > "$TMP/excluded" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; ! grep -q 'ALL CLEAR' "$TMP/excluded"
for kind in ../php-threat-intel custom --bad; do
  set +e; run inspect "$kind" "$TMP/sites" > "$TMP/invalid" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]
done
set +e; run inspect php "$TMP/sites" extra > "$TMP/extra" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]
# A failed latest publication must retain both the target and the new unique JSON.
latest="$TMP/state/reports/inspect-db-latest-summary.json"
rm "$latest"; ln -s "$TMP/config" "$latest"
set +e; run inspect db "$TMP/sites" > "$TMP/alias-failure" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'INCOMPLETE: latest JSON' "$TMP/alias-failure"
[ -L "$latest" ]; [ "$(sha256sum "$TMP/config" "$TMP/state/quarantine/evidence.php" "$SITE/wp-content/plugins/test/"*)" = "$before" ]
[ "$(find "$TMP/state/reports" -name 'inspect-db-*-summary.json' ! -type l | wc -l)" -eq 2 ]
mkdir "$TMP/repo/.presswarden-update.lock"
set +e; run inspect js "$TMP/sites" > "$TMP/locked" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'update/recovery lock' "$TMP/locked"
printf 'Focused inspection, scope, status, privacy and update-lock regressions: PASS\n'
