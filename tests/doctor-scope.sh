#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-doctor-scope.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/app" "$TMP/site/wp-admin" "$TMP/site/wp-content" "$TMP/site/wp-includes"
cp -a "$REPO/." "$TMP/app/"; rm -rf "$TMP/app/.git"
: > "$TMP/site/wp-load.php"; : > "$TMP/site/wp-settings.php"
printf '<?php $wp_version="7.1";\n' > "$TMP/site/wp-includes/version.php"
: > "$TMP/app/.presswarden-portable"
chmod +x "$TMP/app/presswarden" "$TMP/app"/checks/*.sh "$TMP/app"/suites/*.sh
mkdir -p "$TMP/app/var/quarantine" "$TMP/app/var/reports"
printf 'if broken (\n' > "$TMP/app/var/quarantine/untrusted.sh"
printf 'if broken (\n' > "$TMP/app/var/reports/snippet.sh"
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 "$TMP/app/presswarden" doctor "$TMP/site" > "$TMP/good.out" 2>&1
! grep -qE 'untrusted.sh|snippet.sh|INCOMPLETE' "$TMP/good.out"
grep -q 'shell entrypoint(s) parsed successfully' "$TMP/good.out"

# Configured optional integrations must not be called ready when a required
# executable is absent. The doctor must never invoke either mock provider.
mkdir -p "$TMP/bin"
for provider in wp wpscan yara; do
  printf '#!/usr/bin/env bash\nprintf "provider was executed\\n" >&2\nexit 99\n' > "$TMP/bin/$provider"
  chmod +x "$TMP/bin/$provider"
done
cat > "$TMP/hide-provider.sh" <<'SH'
command() {
  if [ "$#" -eq 2 ] && [ "$1" = -v ] && [ "$2" = "${PRESS_TEST_HIDE_COMMAND:-}" ]; then return 1; fi
  builtin command "$@"
}
SH
set +e
PATH="$TMP/bin:$PATH" BASH_ENV="$TMP/hide-provider.sh" PRESS_TEST_HIDE_COMMAND=wpscan \
WPSCAN_API_TOKEN=fixture-token-never-display PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 \
  "$TMP/app/presswarden" doctor --target "$TMP/site" > "$TMP/wpscan-missing.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$TMP/wpscan-missing.out"; echo "Expected configured optional-provider review 1; got $rc"; exit 1; }
grep -q 'configured but missing: wpscan' "$TMP/wpscan-missing.out"
! grep -qE 'fixture-token-never-display|provider was executed' "$TMP/wpscan-missing.out"

printf 'rule benign { condition: false }\n' > "$TMP/rules.yar"
set +e
PATH="$TMP/bin:$PATH" BASH_ENV="$TMP/hide-provider.sh" PRESS_TEST_HIDE_COMMAND=timeout \
WPSCAN_API_TOKEN= PRESSWARDEN_YARA_RULES="$TMP/rules.yar" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 \
  "$TMP/app/presswarden" doctor "$TMP/site" > "$TMP/yara-missing.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$TMP/yara-missing.out"; echo "Expected configured optional-provider review 1; got $rc"; exit 1; }
grep -q 'configured check needs GNU timeout' "$TMP/yara-missing.out"
! grep -q 'provider was executed' "$TMP/yara-missing.out"

PATH="$TMP/bin:$PATH" WPSCAN_API_TOKEN=fixture-token-never-display \
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 \
  "$TMP/app/presswarden" doctor "$TMP/site" > "$TMP/provider-present.out" 2>&1
grep -q 'API access/quota are checked only when scanning' "$TMP/provider-present.out"
! grep -qE 'fixture-token-never-display|provider was executed' "$TMP/provider-present.out"

printf 'if broken (\n' > "$TMP/app/lib/broken.sh"
set +e
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 "$TMP/app/presswarden" doctor "$TMP/site" > "$TMP/bad.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$TMP/bad.out"; echo "Expected doctor dependency/syntax failure 2; got $rc"; exit 1; }
grep -q INCOMPLETE "$TMP/bad.out"
echo 'PressWarden doctor scope: PASS'
