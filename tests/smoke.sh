#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-smoke.$$"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/sites/example.com/public_html/wp-admin" "$TMP/sites/example.com/public_html/wp-content" "$TMP/sites/example.com/public_html/wp-includes"
touch "$TMP/sites/example.com/public_html/wp-settings.php" "$TMP/sites/example.com/public_html/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$TMP/sites/example.com/public_html/wp-includes/version.php"
for f in "$ROOTDIR/presswarden" "$ROOTDIR/install.sh" "$ROOTDIR/uninstall.sh" "$ROOTDIR"/lib/*.sh "$ROOTDIR"/checks/*.sh "$ROOTDIR"/suites/*.sh; do bash -n "$f"; done
out=$(PRESSWARDEN_NOCOLOR=1 "$ROOTDIR/presswarden" doctor "$TMP/sites" 2>&1 || true)
printf '%s\n' "$out" | grep -q '1 WordPress install(s)'
printf '%s\n' "$out" | grep -q 'example.com'
if grep -R -nE '<[[:space:]]*<\(|>[[:space:]]*>\(' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" >/dev/null 2>&1; then
  printf 'runtime process substitution found\n' >&2; exit 1
fi
printf 'PressWarden smoke test: PASS\n'
