#!/usr/bin/env bash
# A terminal scan offers the separate remediate files workflow only after the
# whole scan finished, defaults to No, and never offers without a terminal.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
command -v script >/dev/null 2>&1 || { printf 'SKIP: util-linux script is unavailable\n'; exit 0; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-remediation-offer.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cp -R "$REPO" "$TMP/repo"; rm -rf "$TMP/repo/.git"
SITE="$TMP/fleet/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content" "$SITE/wp-includes" "$TMP/home"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
# Stub suites: the scan records one remediable section; remediation only reports its mode.
printf '#!/usr/bin/env bash\necho SCAN_DONE\n[ -z "${_PW_REMEDIATION_OFFER_FILE:-}" ] || echo sensitive-files >> "$_PW_REMEDIATION_OFFER_FILE"\nexit "${STUB_RC:-0}"\n' > "$TMP/repo/suites/fast.sh"
printf '#!/usr/bin/env bash\necho "REMEDIATE_STARTED explicit=$_PW_EXPLICIT_REMEDIATION"\n' > "$TMP/repo/suites/remediate-files.sh"
export PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_NOCOLOR=1 HOME="$TMP/home" ROOT="$TMP/fleet"
run_tty() { printf '%s\n' "$1" | script -qec "bash $TMP/repo/presswarden fast $SITE" /dev/null > "$2" 2>&1 || true; }
run_tty n "$TMP/no.out"
grep -q SCAN_DONE "$TMP/no.out"; grep -q 'Remediate now? \[y/N\]' "$TMP/no.out"
grep -q 'Skipped. No files changed.' "$TMP/no.out"; ! grep -q REMEDIATE_STARTED "$TMP/no.out"
run_tty '' "$TMP/default.out"
! grep -q REMEDIATE_STARTED "$TMP/default.out"
run_tty y "$TMP/yes.out"
grep -q 'REMEDIATE_STARTED explicit=1' "$TMP/yes.out"
# Without a terminal or with INTERACTIVE=0 there is no offer and the scan exit code is kept.
set +e; STUB_RC=1 bash "$TMP/repo/presswarden" fast "$SITE" < /dev/null > "$TMP/pipe.out" 2>&1; rc=$?; set -e
[ "$rc" -eq 1 ]; grep -q SCAN_DONE "$TMP/pipe.out"; ! grep -q 'Remediate now' "$TMP/pipe.out"
printf 'y\n' | PRESSWARDEN_INTERACTIVE=0 script -qec "bash $TMP/repo/presswarden fast $SITE" /dev/null > "$TMP/off.out" 2>&1 || true
grep -q SCAN_DONE "$TMP/off.out"; ! grep -q 'Remediate now' "$TMP/off.out"; ! grep -q REMEDIATE_STARTED "$TMP/off.out"
# An inherited offer path is ignored.
printf 'y\n' | _PW_REMEDIATION_OFFER_FILE="$TMP/planted" script -qec "bash $TMP/repo/presswarden fast $SITE < /dev/null" /dev/null > "$TMP/planted.out" 2>&1 || true
[ ! -e "$TMP/planted" ]
printf 'Post-scan remediation offer: PASS\n'
