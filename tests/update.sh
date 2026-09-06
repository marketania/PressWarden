#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/presswarden-update-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
INSTALL="$TMP/PressWarden"
SRC="$TMP/update-source"
BIN="$TMP/bin"
ARCHIVE="$TMP/update.tar.gz"
BAD_ARCHIVE="$TMP/bad-update.tar.gz"
mkdir -p "$INSTALL" "$SRC" "$BIN"

cp -a "$REPO/." "$INSTALL/"
cp -a "$REPO/." "$SRC/"
rm -rf "$INSTALL/.git" "$SRC/.git"
: > "$INSTALL/.presswarden-portable"

# Private/local state that the updater must never replace, remove, merge, or
# rewrite. Include unique content so preservation is easy to prove.
mkdir -p "$INSTALL/config" "$INSTALL/var/reports" "$INSTALL/var/quarantine/case-1" \
  "$INSTALL/var/baselines/fleet/current" "$INSTALL/var/cache" "$INSTALL/var/intel"
printf '%s\n' 'PRESSWARDEN_INTERACTIVE=0' 'PRIVATE_UPDATE_TEST_TOKEN=keep-me' > "$INSTALL/config/config"
printf '%s\n' 'local config companion' > "$INSTALL/config/local-note.txt"
printf '%s\n' 'historical report must survive' > "$INSTALL/var/reports/scan-20260906.log"
printf '%s\n' 'quarantined evidence must survive' > "$INSTALL/var/quarantine/case-1/evidence.php"
printf '%s\n' 'baseline must survive' > "$INSTALL/var/baselines/fleet/current/manifest.tsv"
printf '%s\n' 'cache must survive' > "$INSTALL/var/cache/discovery.tsv"
printf '%s\n' 'intel cache must survive' > "$INSTALL/var/intel/kev.json"

# Simulate an obsolete program file from an older release. Replacing the
# managed checks directory should remove it rather than leaving stale code.
printf '%s\n' '#!/usr/bin/env bash' 'echo obsolete' > "$INSTALL/checks/obsolete-check.sh"
chmod +x "$INSTALL/checks/obsolete-check.sh"

# Build a synthetic newer release. Deliberately include hostile/private paths
# in the archive to prove the updater ignores them and copies only managed code.
printf '%s\n' '9.9.9-test' > "$SRC/VERSION"
printf '\n<!-- update-test-release -->\n' >> "$SRC/README.md"
mkdir -p "$SRC/config" "$SRC/var/reports" "$SRC/var/quarantine"
printf '%s\n' 'PRIVATE_UPDATE_TEST_TOKEN=overwrite-attempt' > "$SRC/config/config"
printf '%s\n' 'should never replace local reports' > "$SRC/var/reports/scan-20260906.log"
printf '%s\n' 'should never replace quarantine' > "$SRC/var/quarantine/evidence.php"
rm -f "$SRC/checks/obsolete-check.sh"

tar -czf "$ARCHIVE" -C "$TMP" "$(basename "$SRC")"
ln -s "$INSTALL/presswarden" "$BIN/presswarden"

before_config=$(sha256sum "$INSTALL/config/config" | awk '{print $1}')
before_note=$(sha256sum "$INSTALL/config/local-note.txt" | awk '{print $1}')
before_report=$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')
before_quarantine=$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')
before_baseline=$(sha256sum "$INSTALL/var/baselines/fleet/current/manifest.tsv" | awk '{print $1}')
before_cache=$(sha256sum "$INSTALL/var/cache/discovery.tsv" | awk '{print $1}')
before_intel=$(sha256sum "$INSTALL/var/intel/kev.json" | awk '{print $1}')

out="$TMP/update.out"
PRESSWARDEN_UPDATE_ARCHIVE="$ARCHIVE" "$BIN/presswarden" update > "$out" 2>&1

grep -q 'PressWarden updated: 1.1.0 → 9.9.9-test' "$out"
grep -q 'Preserved: config/config and all runtime state' "$out"
[ "$(tr -d '[:space:]' < "$INSTALL/VERSION")" = '9.9.9-test' ]
grep -q 'update-test-release' "$INSTALL/README.md"
[ ! -e "$INSTALL/checks/obsolete-check.sh" ]
[ -f "$INSTALL/.presswarden-portable" ]
[ "$(sha256sum "$INSTALL/config/config" | awk '{print $1}')" = "$before_config" ]
[ "$(sha256sum "$INSTALL/config/local-note.txt" | awk '{print $1}')" = "$before_note" ]
[ "$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')" = "$before_report" ]
[ "$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')" = "$before_quarantine" ]
[ "$(sha256sum "$INSTALL/var/baselines/fleet/current/manifest.tsv" | awk '{print $1}')" = "$before_baseline" ]
[ "$(sha256sum "$INSTALL/var/cache/discovery.tsv" | awk '{print $1}')" = "$before_cache" ]
[ "$(sha256sum "$INSTALL/var/intel/kev.json" | awk '{print $1}')" = "$before_intel" ]
grep -q 'PRIVATE_UPDATE_TEST_TOKEN=keep-me' "$INSTALL/config/config"
grep -q 'historical report must survive' "$INSTALL/var/reports/scan-20260906.log"
grep -q 'quarantined evidence must survive' "$INSTALL/var/quarantine/case-1/evidence.php"

# The updated CLI must still resolve correctly through a symlink.
"$BIN/presswarden" --version | grep -q '^PressWarden 9.9.9-test$'

# A malformed future archive must fail validation before modifying installed
# code or any private state.
BAD="$TMP/bad-source"
cp -a "$SRC" "$BAD"
rm -f "$BAD/VERSION"
tar -czf "$BAD_ARCHIVE" -C "$TMP" "$(basename "$BAD")"
set +e
PRESSWARDEN_UPDATE_ARCHIVE="$BAD_ARCHIVE" "$BIN/presswarden" update > "$TMP/bad.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$TMP/bad.out" >&2; echo "Expected invalid update to exit 2, got $rc" >&2; exit 1; }
grep -q 'Update validation failed: VERSION is missing' "$TMP/bad.out"
[ "$(tr -d '[:space:]' < "$INSTALL/VERSION")" = '9.9.9-test' ]
[ "$(sha256sum "$INSTALL/config/config" | awk '{print $1}')" = "$before_config" ]
[ "$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')" = "$before_report" ]
[ "$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')" = "$before_quarantine" ]

echo 'PressWarden update preservation test: PASS'
