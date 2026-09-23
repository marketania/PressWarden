#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-db-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.invalid/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-includes" "$SITE/wp-content" "$TMP/bin" "$TMP/temp"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
cat > "$TMP/bin/wp" <<'WP'
#!/usr/bin/env bash
case "$DB_CASE" in
  clean) printf 'PWDB1\tDONE\t0\t0\t20\t2500\n' ;;
  finding) printf 'PWDB1\tFINDING\tALERT\tPW-DB-001\toption\t1005\nPWDB1\tDONE\t0\t1\t1005\t30000\n' ;;
  failed) printf 'SQL_PASSWORD_must_not_leak\n'; exit 31 ;;
  partial) printf 'PWDB1\tFINDING\tALERT\tPW-DB-001\tpost\t17\nprivate_payload_must_not_leak\n'; exit 31 ;;
  truncated) printf 'PWDB1\tFINDING\tREVIEW\tPW-DB-004\tadmin\t2\n' ;;
  limit) printf 'PWDB1\tERROR\trow_limit\toption\t0\nPWDB1\tDONE\t1\t0\t5000\t30000\n'; exit 2 ;;
  bootstrap) printf 'raw_bootstrap_secret\nPWDB1\tDONE\t0\t0\t0\t0\n' ;;
  forged) printf 'PWDB1\tFINDING\tALERT\tPW-DB-001\toption\t1;secret\nPWDB1\tDONE\t0\t0\t0\t0\n' ;;
  wrongcount) printf 'PWDB1\tDONE\t0\t2\t3\t100\n' ;;
  afterdone) printf 'PWDB1\tDONE\t0\t0\t0\t0\nPWDB1\tFINDING\tALERT\tPW-DB-001\tpost\t1\n' ;;
esac
WP
chmod +x "$TMP/bin/wp"
scan() {
  PATH="$TMP/bin:$PATH" TMPDIR="$TMP/temp" ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 bash "$REPO/checks/wp-db-malware.sh"
}
for spec in clean:0 finding:1 failed:2 partial:2 truncated:2 limit:2 bootstrap:0 forged:2 wrongcount:2 afterdone:2; do
  export DB_CASE="${spec%:*}"
  set +e; scan > "$TMP/$DB_CASE.out" 2>&1; rc=$?; set -e
  [ "$rc" = "${spec#*:}" ] || { cat "$TMP/$DB_CASE.out"; echo "bad status for $DB_CASE: $rc"; exit 1; }
  if [ "$rc" -eq 2 ]; then grep -q INCOMPLETE "$TMP/$DB_CASE.out"; ! grep -q CLEAN "$TMP/$DB_CASE.out"; fi
  ! grep -Eq 'SQL_PASSWORD|private_payload|raw_bootstrap_secret|1;secret' "$TMP/$DB_CASE.out"
  [ -z "$(find "$TMP/temp" -name 'presswarden-db.*' -print)" ]
done
grep -q 'PW-DB-001; post row 17' "$TMP/partial.out"
grep -q 'findings: 1' "$TMP/partial.out"
! grep -R -E 'SQL_PASSWORD|private_payload|raw_bootstrap_secret|1;secret' "$TMP/state/reports"
! grep -E 'report .*(issue|review)' "$REPO/checks/wp-db-malware.sh" | grep -v noaction
printf '#!/usr/bin/env bash\nexit 99\n' > "$TMP/bin/php"; chmod +x "$TMP/bin/php"
export DB_CASE=clean
set +e; scan > "$TMP/missing.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; ! grep -q CLEAN "$TMP/missing.out"
rm "$TMP/bin/php"
printf 'PWDB1\tFINDING\tALERT\tPW-DB-001\tpost\t1\nPWDB1\tDONE\t0\t1\t1\t10\n' > "$TMP/raw"
php "$REPO/lib/db-report.php" "$TMP/raw" $'example\n\033[31m' 0 > "$TMP/escaped"
! grep -q $'\033' "$TMP/escaped"; grep -Fq '\x0A' "$TMP/escaped"
if [ -c /dev/full ]; then
  set +e; php "$REPO/lib/db-report.php" "$TMP/raw" example 0 > /dev/full 2>/dev/null; rc=$?; set -e
  [ "$rc" -eq 2 ]
fi
# A shared check logger must not hide a failed tee behind a clean main().
printf '#!/usr/bin/env bash\ncat\nexit 1\n' > "$TMP/bin/tee"; chmod +x "$TMP/bin/tee"
export DB_CASE=clean
set +e; scan > "$TMP/tee-failure.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 2 ]; grep -q 'INCOMPLETE: console report' "$TMP/tee-failure.out"
printf 'Database shell, failure, protocol, read-only and privacy regressions: PASS\n'
