#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-intel-security.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

# Authenticated integrations must not put API credentials in curl/wget argv.
if grep -nE 'curl[^\n]*[[:space:]]-H[[:space:]]+.*(PSKey|Authorization|\$key|\$auth)|wget[^\n]*--header=.*(PSKey|Authorization|\$key|\$auth)' \
  "$ROOTDIR/lib/intel.sh" "$ROOTDIR/checks/wp-patchstack-intel.sh"; then
  printf 'authenticated threat-intel secret found in external process argv construction\n' >&2
  exit 1
fi
grep -q -- '--config -' "$ROOTDIR/lib/intel.sh"
grep -q -- '--config -' "$ROOTDIR/checks/wp-patchstack-intel.sh"
grep -q '_pw_intel_fetch_php_auth' "$ROOTDIR/lib/intel.sh"
grep -q 'ATTRIBUTION' "$ROOTDIR/checks/wp-wordfence-intel.sh"

# Dynamic proof for the shared Wordfence/feed fetch helper: fake curl records
# argv and stdin. The token must be present in stdin config but absent from argv.
cat > "$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$PW_TEST_ARGS"
cat > "$PW_TEST_STDIN"
out=''; prev=''
for a in "$@"; do
  if [ "$prev" = '-o' ]; then out="$a"; fi
  prev="$a"
done
[ -n "$out" ] || exit 9
printf '{"ok":true}\n' > "$out"
SH
chmod +x "$TMP/bin/curl"

export PRESSWARDEN_DIR="$ROOTDIR"
# shellcheck disable=SC1091
. "$ROOTDIR/lib/intel.sh"
export PW_TEST_ARGS="$TMP/args" PW_TEST_STDIN="$TMP/stdin"
secret='PW_TEST_BEARER_9f4d2c'
PATH="$TMP/bin:$PATH" _pw_intel_fetch 'https://example.invalid/feed' "$TMP/out.json" "Authorization: Bearer $secret"

grep -q 'Authorization: Bearer PW_TEST_BEARER_9f4d2c' "$TMP/stdin"
if grep -q "$secret" "$TMP/args"; then
  printf 'Bearer credential leaked into curl argv\n' >&2
  exit 1
fi
expected_version=$(tr -d '[:space:]' < "$ROOTDIR/VERSION")
grep -q "PressWarden/$expected_version Threat Intelligence" "$TMP/args"
[ -s "$TMP/out.json" ]

# `_pw_intel_age` must work on BSD/macOS-style stat implementations too. This
# shim deliberately rejects GNU `stat -c` and accepts only `stat -f %m`.
cat > "$TMP/bin/stat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = '-c' ]; then exit 1; fi
if [ "${1:-}" = '-f' ] && [ "${2:-}" = '%m' ] && [ -n "${3:-}" ]; then
  exec /usr/bin/stat -c %Y "$3"
fi
exit 2
SH
chmod +x "$TMP/bin/stat"
touch "$TMP/age-fixture"
age=$(PATH="$TMP/bin:$PATH" _pw_intel_age "$TMP/age-fixture")
case "$age" in unknown|never) printf 'BSD stat fallback did not produce cache age\n' >&2; exit 1 ;; esac

printf 'PressWarden intel credential + portability test: PASS\n'
