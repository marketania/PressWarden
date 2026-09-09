#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
TMP=$(mktemp -d); trap 'rm -rf -- "$TMP"' EXIT
SYSTEM_PATH="$PATH"
export ROOT="$TMP/fleet" HOME="$TMP/home" PRESSWARDEN_CONFIG_FILE="$TMP/no-config"
export PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache"
export PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 PRESSWARDEN_OUTPUT_JSON=0
export PRESSWARDEN_DISCOVERY_CACHE_TTL=300 PRESSWARDEN_EXCLUDE=''
export REPO
mkdir -p "$HOME" "$TMP/bin" "$TMP/no-wp"
for name in bash dirname cat env grep stat mkdir date find sort cksum awk tr cmp mktemp rmdir rm wc readlink sha256sum tput cp mv ln; do
  ln -s "$(command -v "$name")" "$TMP/no-wp/$name"
done
make_site() {
  mkdir -p "$1/wp-admin" "$1/wp-includes" "$1/wp-content/plugins/demo"
  printf '<?php $wp_version="6.8.2";\n' > "$1/wp-includes/version.php"
  printf '<?php // settings\n' > "$1/wp-settings.php"
  printf '<?php // load\n' > "$1/wp-load.php"
  printf '<?php // BASELINE_PRIVATE_SOURCE_SENTINEL\n' > "$1/wp-content/plugins/demo/demo.php"
}
make_site "$ROOT/one.com/public_html"; make_site "$ROOT/two.com/public_html"
SITE="$ROOT/one.com/public_html"; export SITE
cat > "$TMP/bin/wp" <<'WP'
#!/usr/bin/env bash
if [ "${PW_TEST_MODE:-}" = "fail-${1:-}" ]; then printf 'BASELINE_PRIVATE_ERROR_SENTINEL\n' >&2; exit 1; fi
if [ "${PW_TEST_MODE:-}" = empty ]; then exit 0; fi
if [ "${PW_TEST_MODE:-}" = malformed ]; then printf 'BASELINE_PRIVATE_ERROR_SENTINEL\n'; exit 0; fi
case "${1:-}" in
 plugin) printf 'name,status,version\ndemo,active,1\n' ;;
 theme) printf 'name,status,version\ndemo,active,1\n' ;;
 user) printf 'user_login\nsiteadmin\n' ;;
 cron) printf 'hook,recurrence\nx,Daily\n' ;;
 *) exit 1 ;;
esac
[ "${PW_TEST_MODE:-}" != partial ] || exit 1
exit 0
WP
chmod +x "$TMP/bin/wp"
export PATH="$TMP/bin:$SYSTEM_PATH"
n=0
expect() {
  local expected="$1" rc=0; shift
  "$@" > "$TMP/output" 2>&1 || rc=$?
  if [ "$rc" -ne "$expected" ]; then cat "$TMP/output" >&2; printf 'Expected %s got %s: %s\n' "$expected" "$rc" "$*" >&2; exit 1; fi
  if grep -qE 'BASELINE_PRIVATE_(SOURCE|ERROR)_SENTINEL' "$TMP/output"; then echo 'Private diagnostic leak' >&2; exit 1; fi
  n=$((n+1))
}
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
CURRENT=$(find "$PRESSWARDEN_STATE_DIR/baselines" -type d -name current); SCOPE=${CURRENT%/current}; export CURRENT
cp -a "$CURRENT" "$TMP/reference"
intact() {
  local file
  for file in manifest meta scope coverage; do cmp "$TMP/reference/$file.tsv" "$CURRENT/$file.tsv"; done
  [ ! -e "$SCOPE/.baseline.lock" ]; n=$((n+1))
}
no_delta() { ! grep -qE 'REMOVED|ADMIN ADDED|No security-baseline changes|✓ CLEAN|FLEET ADMIN' "$TMP/output"; n=$((n+1)); }
for mode in fail-plugin fail-theme fail-user fail-cron empty malformed partial; do
  export PW_TEST_MODE="$mode"
  expect 2 bash "$REPO/presswarden" baseline create "$ROOT"; intact
  expect 2 bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
  expect 2 bash "$REPO/checks/baseline-changes.sh"; no_delta
  expect 2 bash "$REPO/presswarden" correlate "$ROOT"; no_delta
  [ -z "$(find "$SCOPE" -maxdepth 1 -name '.work.*' -print)" ]
done
unset PW_TEST_MODE
# Header-only inventories are valid empty results, not silently inferred failures.
# Strict reader tests cover this directly; verify unchanged runtime still compares.
expect 0 bash "$REPO/presswarden" changes "$ROOT"
# Dependency disappearance must never be interpreted as runtime-state removals.
expect 2 env PATH="$TMP/no-wp" bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
expect 2 env PATH="$TMP/no-wp" bash "$REPO/presswarden" baseline create "$ROOT"; intact
# A genuinely file-only baseline still works without either WP-CLI or PHP.
expect 0 env PATH="$TMP/no-wp" PRESSWARDEN_STATE_DIR="$TMP/file-only" bash "$REPO/presswarden" baseline create "$ROOT"
expect 0 env PATH="$TMP/no-wp" PRESSWARDEN_STATE_DIR="$TMP/file-only" bash "$REPO/presswarden" changes "$ROOT"
# Scope changes and stale discovery cannot become wholesale removals/additions.
make_site "$ROOT/new.com/public_html"
expect 2 bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
rm -rf "$ROOT/new.com"
mv "$ROOT/two.com" "$TMP/missing-site"
expect 2 bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
mv "$TMP/missing-site" "$ROOT/two.com"
expect 2 env PRESSWARDEN_EXCLUDE=two.com bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
expect 2 env PRESSWARDEN_DISCOVERY_DEPTH=9 bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
# Hash and mutation errors affect the whole capture; not a trustworthy partial diff.
expect 2 bash -c '. "$REPO/lib/baseline.sh"; _pw_sha256(){ case "$1" in *demo.php) return 2;; *) sha256sum < "$1" | awk "{print \$1}";; esac; }; pw_baseline_create'
intact
expect 2 bash -c '. "$REPO/lib/baseline.sh"; _pw_sha256(){ sha256sum < "$1" | awk "{print \$1}"; case "$1" in *demo.php) printf "modified while hashing\n" >> "$1";; esac; }; pw_baseline_diff'
no_delta; intact
printf '<?php // BASELINE_PRIVATE_SOURCE_SENTINEL\n' > "$SITE/wp-content/plugins/demo/demo.php"
printf '<?php // BASELINE_PRIVATE_SOURCE_SENTINEL\n' > "$ROOT/two.com/public_html/wp-content/plugins/demo/demo.php"
# Traversal diagnostics are not leaked; failed discoveries are not cached as complete.
REAL_FIND=$(command -v find); export REAL_FIND
cat > "$TMP/bin/find" <<'FIND'
#!/usr/bin/env bash
"$REAL_FIND" "$@"
printf 'BASELINE_PRIVATE_ERROR_SENTINEL\n' >&2
exit 1
FIND
chmod +x "$TMP/bin/find"
expect 2 bash "$REPO/presswarden" baseline create "$ROOT"
rm "$TMP/bin/find"; intact
# BSD-style stat fallback preserves the same file identities.
REAL_STAT=$(command -v stat); export REAL_STAT
cat > "$TMP/bin/stat" <<'STAT'
#!/usr/bin/env bash
if [ "${2:-}" = '%d:%i:%s:%Y:%Z' ]; then exit 1; fi
if [ "${1:-}" = -f ] && [ "${2:-}" = '%d:%i:%z:%m:%c' ]; then exec "$REAL_STAT" -c '%d:%i:%s:%Y:%Z' -- "$3"; fi
exec "$REAL_STAT" "$@"
STAT
chmod +x "$TMP/bin/stat"
expect 0 bash "$REPO/presswarden" changes "$ROOT"
rm "$TMP/bin/stat"
expect 2 bash "$REPO/presswarden" baseline create "$ROOT" unexpected; intact
expect 2 bash "$REPO/presswarden" changes "$ROOT" unexpected; intact
# Unsafe delimiter characters are refused instead of dropping a security file.
printf 'data' > "$SITE/wp-content/plugins/demo/line"$'\n'"break.php"
expect 2 bash "$REPO/presswarden" changes "$ROOT"; no_delta; intact
rm "$SITE/wp-content/plugins/demo/line"$'\n'"break.php"
printf 'data' > "$SITE/wp-content/plugins/demo/tab"$'\t'"break.php"
expect 2 bash "$REPO/presswarden" baseline create "$ROOT"; intact
rm "$SITE/wp-content/plugins/demo/tab"$'\t'"break.php"
# Tampered/malformed or legacy snapshots cannot silently enter the comparator.
printf 'tamper\n' >> "$CURRENT/manifest.tsv"
expect 2 bash "$REPO/presswarden" changes "$ROOT"; no_delta
cp "$TMP/reference/manifest.tsv" "$CURRENT/manifest.tsv"
rm "$CURRENT/coverage.tsv"
expect 2 bash "$REPO/presswarden" baseline status "$ROOT"
expect 2 bash "$REPO/checks/baseline-changes.sh"; no_delta
# Explicit recreation preserves legacy bytes; no automatic migration.
cp -a "$CURRENT" "$TMP/legacy"
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
legacy=$(find "$SCOPE/history" -type f -name manifest.tsv | head -n 1)
cmp "$TMP/legacy/manifest.tsv" "$legacy"
[ ! -e "$(dirname "$legacy")/coverage.tsv" ]
expect 0 bash "$REPO/presswarden" changes "$ROOT"
# Nested ownership, absolute exclusions with find metacharacters, and backslashes.
make_site "$SITE/staging[one]"; make_site "$SITE/excluded[two]"
printf 'data' > "$SITE/wp-content/plugins/demo/a back\\slash.php"
export PRESSWARDEN_EXCLUDE="one.com/excluded[two]"
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
grep -q $'^F\tone.com/staging\[one\]\twp-load.php\t' "$CURRENT/manifest.tsv"
! grep -q $'^F\tone.com\tstaging' "$CURRENT/manifest.tsv"
! grep -q 'excluded\[two\]' "$CURRENT/manifest.tsv"
grep -Fq 'a back\slash.php' "$CURRENT/manifest.tsv"
expect 0 bash "$REPO/presswarden" changes "$ROOT"
# A deliberately held lock prevents every cooperating reader/writer.
mkdir "$SCOPE/.baseline.lock"
expect 2 bash "$REPO/presswarden" baseline create "$ROOT"
expect 2 bash "$REPO/presswarden" baseline status "$ROOT"
expect 2 bash "$REPO/presswarden" changes "$ROOT"
expect 2 bash "$REPO/presswarden" correlate "$ROOT"
rmdir "$SCOPE/.baseline.lock"
# Baseline source-safety: no file content captured; no control-character metadata.
! grep -R -q 'BASELINE_PRIVATE_.*SENTINEL' "$SCOPE"
[ "$(stat -c %a "$CURRENT/manifest.tsv")" = 600 ]
[ "$(stat -c %a "$CURRENT")" = 700 ]
[ -z "$(find "$SCOPE" -maxdepth 1 -name '.work.*' -print)" ]
printf 'Baseline coverage: %s runtime assertions passed.\n' "$n"
