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
printf 'if broken (\n' > "$TMP/app/lib/broken.sh"
set +e
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_NOCOLOR=1 "$TMP/app/presswarden" doctor "$TMP/site" > "$TMP/bad.out" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$TMP/bad.out"; echo "Expected doctor dependency/syntax failure 2; got $rc"; exit 1; }
grep -q INCOMPLETE "$TMP/bad.out"
echo 'PressWarden doctor scope: PASS'
