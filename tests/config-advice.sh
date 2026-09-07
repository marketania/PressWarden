#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-config-advice.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/app/config" "$TMP/app/lib"
cp "$REPO/presswarden" "$REPO/VERSION" "$TMP/app/"
cp "$REPO/lib/config-options.php" "$TMP/app/lib/"
: > "$TMP/app/.presswarden-portable"
cat > "$TMP/app/config/config.example" <<'EOF'
PRESSWARDEN_EXISTING=1
PRESSWARDEN_NEW=0
WPSCAN_API_TOKEN=""
# PRESSWARDEN_COMMENT_ONLY=1
EOF
cat > "$TMP/app/config/config" <<EOF
export PRESSWARDEN_EXISTING=0
WPSCAN_API_TOKEN='private-value-never-print'
touch '$TMP/executed'
PRESSWARDEN_CUSTOM='private-extra'
this is deliberately not valid shell (
EOF
chmod 600 "$TMP/app/config/config"
before=$(sha256sum "$TMP/app/config/config")
"$TMP/app/presswarden" config-new > "$TMP/out"
grep -q '^  PRESSWARDEN_NEW$' "$TMP/out"
! grep -qE 'private-value|private-extra|  PRESSWARDEN_EXISTING|  PRESSWARDEN_COMMENT_ONLY|  WPSCAN_API_TOKEN' "$TMP/out"
[ ! -e "$TMP/executed" ]
[ "$(sha256sum "$TMP/app/config/config")" = "$before" ]
[ "$(stat -c %a "$TMP/app/config/config")" = 600 ]
cp "$TMP/app/config/config.example" "$TMP/saved"
PRESSWARDEN_CONFIG_FILE="$TMP/saved" "$TMP/app/presswarden" config-new > "$TMP/all"
grep -q 'No additional template options' "$TMP/all"
PRESSWARDEN_CONFIG_FILE="$TMP/missing" "$TMP/app/presswarden" config-new > "$TMP/missing.out"
grep -q '3 template option(s)' "$TMP/missing.out"
[ ! -e "$TMP/missing" ]
# Comparison failures cannot look like an empty/successful configuration.
set +e
PRESSWARDEN_CONFIG_FILE="$TMP" "$TMP/app/presswarden" config-new > "$TMP/invalid" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'Configuration comparison failed' "$TMP/invalid"
echo 'PressWarden read-only config advice: PASS'
