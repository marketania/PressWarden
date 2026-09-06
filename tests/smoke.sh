#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-smoke.$$"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/sites/example.com/public_html/wp-admin" "$TMP/sites/example.com/public_html/wp-content" "$TMP/sites/example.com/public_html/wp-includes"
touch "$TMP/sites/example.com/public_html/wp-settings.php" "$TMP/sites/example.com/public_html/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$TMP/sites/example.com/public_html/wp-includes/version.php"

for f in "$ROOTDIR/presswarden" "$ROOTDIR/install.sh" "$ROOTDIR/uninstall.sh" "$ROOTDIR"/lib/*.sh "$ROOTDIR"/checks/*.sh "$ROOTDIR"/suites/*.sh; do bash -n "$f"; done

# Test discovery structurally rather than depending on formatted doctor output.
ROOT="$TMP/sites" \
PRESSWARDEN_CONFIG_FILE="$TMP/no-config" \
PRESSWARDEN_STATE_DIR="$TMP/state" \
PRESSWARDEN_CACHE_DIR="$TMP/cache" \
PRESSWARDEN_NOCOLOR=1 \
bash -c '
  set -euo pipefail
  . "$1/lib/_lib.sh"
  [ "${#SCAN_ROOTS[@]}" -eq 1 ]
  [ "$(site_label_from_root "${SCAN_ROOTS[0]}")" = "example.com" ]
  [ "$PRESSWARDEN_VERSION" = "1.0.2" ]
' _ "$ROOTDIR"

# Exported one-shot values must override persistent config values.
cat > "$TMP/config" <<'EOF'
PRESSWARDEN_UPLOADS_DEEP=0
EOF
cfg=$(PRESSWARDEN_CONFIG_FILE="$TMP/config" PRESSWARDEN_UPLOADS_DEEP=1 "$ROOTDIR/presswarden" config)
printf '%s\n' "$cfg" | grep -qE 'Deep upload scan:[[:space:]]+1$'

# CLI version and fleet-lock aliases must stay discoverable.
[ "$($ROOTDIR/presswarden --version)" = "PressWarden 1.0.2" ]
help=$($ROOTDIR/presswarden help)
printf '%s\n' "$help" | grep -q 'presswarden lock \[path\]'
printf '%s\n' "$help" | grep -q 'presswarden unlock \[path\]'
printf '%s\n' "$help" | grep -q 'presswarden lock-status \[path\]'

if grep -R -nE '<[[:space:]]*<\(|>[[:space:]]*>\(' "$ROOTDIR/checks" "$ROOTDIR/lib" "$ROOTDIR/suites" >/dev/null 2>&1; then
  printf 'runtime process substitution found\n' >&2; exit 1
fi
printf 'PressWarden smoke test: PASS\n'
