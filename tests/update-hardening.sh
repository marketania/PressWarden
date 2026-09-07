#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-update-safety.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
INSTALL="$TMP/PressWarden"; SRC="$TMP/source"
mkdir -p "$INSTALL" "$SRC"
cp -a "$REPO/." "$INSTALL/"; cp -a "$REPO/." "$SRC/"
rm -rf "$INSTALL/.git" "$SRC/.git"
: > "$INSTALL/.presswarden-portable"
printf 'PRESSWARDEN_INTERACTIVE=0\n' > "$INSTALL/config/config"
chmod 600 "$INSTALL/config/config"
mkdir -p "$INSTALL/var/quarantine"
printf 'private evidence\n' > "$INSTALL/var/quarantine/keep"
printf '9.9.9-test\n' > "$SRC/VERSION"
cat >> "$SRC/lib/intel.sh" <<'EOF'
pw_intel_update() { return 0; }
EOF
tar -czf "$TMP/good.tar.gz" -C "$TMP" source
old=$(cat "$INSTALL/VERSION"); cfg=$(sha256sum "$INSTALL/config/config")
check_private() {
  [ "$(cat "$INSTALL/VERSION")" = "$old" ]
  [ "$(sha256sum "$INSTALL/config/config")" = "$cfg" ]
  grep -qx 'private evidence' "$INSTALL/var/quarantine/keep"
}
expect_fail() {
  local label=$1 expected=$2 rc; shift 2
  set +e
  "$@" > "$TMP/$label.log" 2>&1; rc=$?
  set -e
  [ "$rc" -eq "$expected" ] || { cat "$TMP/$label.log" >&2; echo "$label: expected $expected, got $rc" >&2; exit 1; }
  check_private
}
# Locks must fail closed, never steal an existing/stale lock or its workspace.
mkdir "$INSTALL/.presswarden-update.lock"
printf 'other-owner\n' > "$INSTALL/.presswarden-update.lock/pid"
expect_fail lock 2 env PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update
grep -qx other-owner "$INSTALL/.presswarden-update.lock/pid"
expect_fail scanblocked 2 "$INSTALL/presswarden" fast "$TMP"
grep -q 'Scans are blocked' "$TMP/scanblocked.log"
rm -rf "$INSTALL/.presswarden-update.lock"
# Protect custom state paths and symlink aliases to managed program directories.
expect_fail overlap 2 env PRESSWARDEN_STATE_DIR="$INSTALL/lib/private-state" PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update
ln -s "$INSTALL/lib" "$TMP/alias"
expect_fail alias 2 env PRESSWARDEN_CACHE_DIR="$TMP/alias/cache" PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update
mv "$INSTALL/config" "$TMP/private-config"; ln -s "$TMP/private-config" "$INSTALL/config"
expect_fail linkedconfig 2 env PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update
rm "$INSTALL/config"; mv "$TMP/private-config" "$INSTALL/config"
# Missing required public template must be rejected before replacing any code.
mv "$SRC/config/config.example" "$TMP/template"
tar -czf "$TMP/missing.tar.gz" -C "$TMP" source
expect_fail missingtemplate 2 env PRESSWARDEN_UPDATE_ARCHIVE="$TMP/missing.tar.gz" "$INSTALL/presswarden" update
mv "$TMP/template" "$SRC/config/config.example"
# Distribution symlinks are rejected before extraction; private state is intact.
ln -s ../../outside "$SRC/lib/unsafe"
tar -czf "$TMP/linked.tar.gz" -C "$TMP" source
expect_fail symlink 2 env PRESSWARDEN_UPDATE_ARCHIVE="$TMP/linked.tar.gz" "$INSTALL/presswarden" update
rm "$SRC/lib/unsafe"
# Simulate a copy failure after mutation using the actual EXIT recovery path.
cat > "$TMP/failure.sh" <<'EOF'
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_UPDATE_ARCHIVE="$2"; export PRESSWARDEN_DIR PRESSWARDEN_UPDATE_ARCHIVE
. "$PRESSWARDEN_DIR/lib/update.sh"
_pw_update_replace_managed() { printf 'broken\n' > "$2/VERSION"; return 2; }
pw_update
EOF
expect_fail rollback 2 bash "$TMP/failure.sh" "$INSTALL" "$TMP/good.tar.gz"
grep -q 'Previous program restored' "$TMP/rollback.log"
[ ! -e "$INSTALL/.presswarden-update.lock" ]
# Catchable interruption after mutation must restore code and preserve exit code.
sed 's/return 2; }/kill -TERM "$BASHPID"; return 2; }/' "$TMP/failure.sh" > "$TMP/signal.sh"
expect_fail interrupted 143 bash "$TMP/signal.sh" "$INSTALL" "$TMP/good.tar.gz"
grep -q 'Previous program restored' "$TMP/interrupted.log"
# If restore fails, the only good backup AND recovery lock must remain.
sed '/^pw_update$/i _pw_update_restore_managed() { return 2; }' "$TMP/failure.sh" > "$TMP/failed-rollback.sh"
set +e
bash "$TMP/failed-rollback.sh" "$INSTALL" "$TMP/good.tar.gz" > "$TMP/recovery.log" 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ]; grep -q 'ROLLBACK INCOMPLETE' "$TMP/recovery.log"
workspace=$(cat "$INSTALL/.presswarden-update.lock/workspace")
[ "$(cat "$workspace/backup/VERSION")" = "$old" ]; [ -f "$workspace/backup/.complete" ]
[ "$(sha256sum "$INSTALL/config/config")" = "$cfg" ]
# Restore the intentionally damaged fixture for the remaining test cases.
cp "$workspace/backup/VERSION" "$INSTALL/VERSION"
rm -rf "$INSTALL/.presswarden-update.lock" "$workspace"
# Hooks/umask in a calling shell are not overwritten by updater-local traps.
PRESSWARDEN_DIR="$INSTALL" PRESSWARDEN_UPDATE_ARCHIVE="$TMP/missing.tar.gz" bash -c '
  . "$1/lib/update.sh"
  trap ": caller trap" EXIT
  before=$(trap -p EXIT); mask=$(umask)
  pw_update >/dev/null 2>&1 || :
  [ "$(trap -p EXIT)" = "$before" ] && [ "$(umask)" = "$mask" ]
' _ "$INSTALL"
# Two live updaters must not interleave changes. The first owns the lock while
# fetching; the second fails without touching its recovery workspace.
cat > "$TMP/first.sh" <<'EOF'
set -uo pipefail
PRESSWARDEN_DIR="$1"; PRESSWARDEN_UPDATE_ARCHIVE="$2"; TEST_SYNC="$3"
. "$PRESSWARDEN_DIR/lib/update.sh"
_pw_update_fetch_archive() {
  : > "$TEST_SYNC.ready"
  local attempts=0
  while [ ! -f "$TEST_SYNC.go" ]; do
    attempts=$((attempts+1)); [ "$attempts" -lt 200 ] || return 2
    sleep 0.05
  done
  cp "$PRESSWARDEN_UPDATE_ARCHIVE" "$1"
}
pw_update
EOF
bash "$TMP/first.sh" "$INSTALL" "$TMP/good.tar.gz" "$TMP/sync" > "$TMP/first.log" 2>&1 &
first=$!; attempts=0
while [ ! -f "$TMP/sync.ready" ]; do
  attempts=$((attempts+1)); [ "$attempts" -lt 200 ] || { cat "$TMP/first.log"; exit 1; }
  sleep 0.05
done
expect_fail concurrent 2 env PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update
: > "$TMP/sync.go"; wait "$first"
[ ! -e "$INSTALL/.presswarden-update.lock" ]
# No symlink/hardlink or TAR_OPTIONS hook may execute during extraction.
TAR_OPTIONS="--checkpoint=1 --checkpoint-action=exec=touch $TMP/unwanted" \
  PRESSWARDEN_UPDATE_ARCHIVE="$TMP/good.tar.gz" "$INSTALL/presswarden" update > "$TMP/success.log" 2>&1
[ ! -e "$TMP/unwanted" ]; [ ! -e "$INSTALL/.presswarden-update.lock" ]
[ "$(cat "$INSTALL/VERSION")" = '9.9.9-test' ]
[ "$(sha256sum "$INSTALL/config/config")" = "$cfg" ]
if find "$INSTALL" -maxdepth 1 -type d -name '.presswarden-update.*' | grep -q .; then echo 'update workspace leak' >&2; exit 1; fi
printf 'PressWarden update hardening: PASS\n'
