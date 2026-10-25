#!/usr/bin/env bash
# A terminal scan asks right after each remediable section with findings
# (default No). Without a terminal, or with INTERACTIVE=0, it only names the command.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
command -v script >/dev/null 2>&1 || { printf 'SKIP: util-linux script is unavailable\n'; exit 0; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-step-prompt.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cp -R "$REPO" "$TMP/repo"; rm -rf "$TMP/repo/.git"
SITE="$TMP/fleet/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content" "$SITE/wp-includes" "$TMP/home"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
# Stub suite: one remediable section (sensitive-files) and one other check, each with a finding.
cat > "$TMP/repo/suites/fast.sh" <<'STUB'
#!/usr/bin/env bash
export _PW_EXPLICIT_REMEDIATION=0
. "$PRESSWARDEN_DIR/lib/_lib.sh"
for check in sensitive-files wp-plugins; do
  NAME=$check; pw_report_init "$check"
  printf '%s\n' "$PW_TEST_SITE/.env" > "$TMP_LIST"
  echo "SECTION $check"
  _prompt_file_action "$TMP_LIST" issue
done
echo SCAN_DONE
STUB
export PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_NOCOLOR=1 HOME="$TMP/home" ROOT="$TMP/fleet" PW_TEST_SITE="$SITE" TMP_LIST="$TMP/list"
run_tty() { printf '%s\n' "$1" | script -qec "bash $TMP/repo/presswarden fast $SITE" /dev/null > "$2" 2>&1 || true; }
printf 'SECRET=1\n' > "$SITE/.env"
run_tty '' "$TMP/default.out"
grep -q 'Remediate now?' "$TMP/default.out"; grep -q 'SKIPPED' "$TMP/default.out"; [ -f "$SITE/.env" ]
# Exactly one prompt: the non-remediable check never asks.
[ "$(grep -c 'Remediate now?' "$TMP/default.out")" -eq 1 ]; grep -q SCAN_DONE "$TMP/default.out"
run_tty n "$TMP/no.out"; [ -f "$SITE/.env" ]
run_tty y "$TMP/yes.out"
grep -q 'QUARANTINED' "$TMP/yes.out"; [ ! -e "$SITE/.env" ]; grep -q SCAN_DONE "$TMP/yes.out"
# The prompt comes right after its section, before the next one starts.
awk '/SECTION sensitive-files/{a=NR} /Remediate now\?/{b=NR} /SECTION wp-plugins/{c=NR} END{exit !(a<b && b<c)}' "$TMP/yes.out"
find "$TMP/state/quarantine" -name 'case-*' -maxdepth 1 | grep -q .
# Without a terminal or with INTERACTIVE=0: hint only, nothing changes.
printf 'SECRET=1\n' > "$SITE/.env"
bash "$TMP/repo/presswarden" fast "$SITE" < /dev/null > "$TMP/pipe.out" 2>&1 || true
! grep -q 'Remediate now?' "$TMP/pipe.out"; grep -q 'remediate files' "$TMP/pipe.out"; [ -f "$SITE/.env" ]
printf 'y\n' | PRESSWARDEN_INTERACTIVE=0 script -qec "bash $TMP/repo/presswarden fast $SITE" /dev/null > "$TMP/off.out" 2>&1 || true
! grep -q 'Remediate now?' "$TMP/off.out"; [ -f "$SITE/.env" ]
# An inherited step-prompt flag without a terminal is ignored.
_PW_SCAN_STEP_REMEDIATION=1 bash "$TMP/repo/presswarden" fast "$SITE" < /dev/null > "$TMP/inherit.out" 2>&1 || true
! grep -q 'Remediate now?' "$TMP/inherit.out"; [ -f "$SITE/.env" ]
printf 'Per-section scan remediation prompt: PASS\n'
