#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/presswarden-update-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
INSTALL="$TMP/PressWarden"
SRC="$TMP/update-source"
BIN="$TMP/bin"
ARCHIVE="$TMP/update.tar.gz"
FAIL_ARCHIVE="$TMP/update-intel-fail.tar.gz"
SAME_ARCHIVE="$TMP/update-same-version.tar.gz"
BAD_ARCHIVE="$TMP/bad-update.tar.gz"
CURRENT_VERSION="$(tr -d '[:space:]' < "$REPO/VERSION")"
mkdir -p "$INSTALL" "$SRC" "$BIN"

cp -a "$REPO/." "$INSTALL/"
cp -a "$REPO/." "$SRC/"
rm -rf "$INSTALL/.git" "$SRC/.git"
: > "$INSTALL/.presswarden-portable"

# Private/local state that the code updater must never replace, remove, merge,
# or rewrite. Intel refresh runs afterward and may update provider caches, so an
# unrelated local intel-state file is used to prove the directory is preserved.
mkdir -p "$INSTALL/config" "$INSTALL/var/reports" "$INSTALL/var/quarantine/case-1" \
  "$INSTALL/var/baselines/fleet/current" "$INSTALL/var/cache" "$INSTALL/var/intel"
printf '%s\n' 'PRESSWARDEN_INTERACTIVE=0' 'PRIVATE_UPDATE_TEST_TOKEN=keep-me' > "$INSTALL/config/config"
printf '%s\n' 'local config companion' > "$INSTALL/config/local-note.txt"
printf '%s\n' 'historical report must survive' > "$INSTALL/var/reports/scan-20260906.log"
printf '%s\n' 'quarantined evidence must survive' > "$INSTALL/var/quarantine/case-1/evidence.php"
printf '%s\n' 'baseline must survive' > "$INSTALL/var/baselines/fleet/current/manifest.tsv"
printf '%s\n' 'cache must survive' > "$INSTALL/var/cache/discovery.tsv"
printf '%s\n' 'local intel state must survive' > "$INSTALL/var/intel/local-note.txt"

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

# Override only the synthetic release's intel updater so CI never requires
# network access and can prove the newly-installed intel implementation runs.
cat >> "$SRC/lib/intel.sh" <<'EOF'

pw_intel_update() {
  mkdir -p "$PRESSWARDEN_DIR/var/intel"
  printf '%s\n' 'synthetic intel refresh succeeded' >> "$PRESSWARDEN_DIR/var/intel/update-test.log"
  return 0
}
EOF

tar -czf "$ARCHIVE" -C "$TMP" "$(basename "$SRC")"
ln -s "$INSTALL/presswarden" "$BIN/presswarden"

before_config=$(sha256sum "$INSTALL/config/config" | awk '{print $1}')
before_note=$(sha256sum "$INSTALL/config/local-note.txt" | awk '{print $1}')
before_report=$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')
before_quarantine=$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')
before_baseline=$(sha256sum "$INSTALL/var/baselines/fleet/current/manifest.tsv" | awk '{print $1}')
before_cache=$(sha256sum "$INSTALL/var/cache/discovery.tsv" | awk '{print $1}')
before_intel_note=$(sha256sum "$INSTALL/var/intel/local-note.txt" | awk '{print $1}')

out="$TMP/update.out"
PRESSWARDEN_UPDATE_ARCHIVE="$ARCHIVE" "$BIN/presswarden" update > "$out" 2>&1

grep -q "PressWarden updated: $CURRENT_VERSION → 9.9.9-test" "$out"
grep -q 'Preserved: config/config, reports, quarantine, baselines, cache, and existing intel state' "$out"
grep -q 'Refreshing threat intelligence with PressWarden v9.9.9-test' "$out"
grep -q 'Threat intelligence refreshed' "$out"
grep -q 'synthetic intel refresh succeeded' "$INSTALL/var/intel/update-test.log"
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
[ "$(sha256sum "$INSTALL/var/intel/local-note.txt" | awk '{print $1}')" = "$before_intel_note" ]
grep -q 'PRIVATE_UPDATE_TEST_TOKEN=keep-me' "$INSTALL/config/config"
grep -q 'historical report must survive' "$INSTALL/var/reports/scan-20260906.log"
grep -q 'quarantined evidence must survive' "$INSTALL/var/quarantine/case-1/evidence.php"

# The updated CLI must still resolve correctly through a symlink.
"$BIN/presswarden" --version | grep -q '^PressWarden 9.9.9-test$'

# Intel/network failure is a partial maintenance failure, not a reason to roll
# back a valid program update. Existing caches/state remain available and the
# command returns 1 so automation can notice the incomplete refresh.
FAIL="$TMP/update-intel-fail-source"
cp -a "$SRC" "$FAIL"
printf '%s\n' '9.9.10-test' > "$FAIL/VERSION"
cat >> "$FAIL/lib/intel.sh" <<'EOF'

pw_intel_update() {
  printf '%s\n' 'synthetic intel refresh failed'
  return 1
}
EOF

tar -czf "$FAIL_ARCHIVE" -C "$TMP" "$(basename "$FAIL")"
set +e
PRESSWARDEN_UPDATE_ARCHIVE="$FAIL_ARCHIVE" "$BIN/presswarden" update > "$TMP/intel-fail.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$TMP/intel-fail.out" >&2; echo "Expected intel refresh failure to exit 1, got $rc" >&2; exit 1; }
grep -q 'PressWarden updated: 9.9.9-test → 9.9.10-test' "$TMP/intel-fail.out"
grep -q 'program update succeeded, but one or more threat-intelligence feeds did not refresh' "$TMP/intel-fail.out"
[ "$(tr -d '[:space:]' < "$INSTALL/VERSION")" = '9.9.10-test' ]
[ "$(sha256sum "$INSTALL/config/config" | awk '{print $1}')" = "$before_config" ]
[ "$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')" = "$before_report" ]
[ "$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')" = "$before_quarantine" ]
[ "$(sha256sum "$INSTALL/var/baselines/fleet/current/manifest.tsv" | awk '{print $1}')" = "$before_baseline" ]
[ "$(sha256sum "$INSTALL/var/intel/local-note.txt" | awk '{print $1}')" = "$before_intel_note" ]

# Main can legitimately advance without a VERSION bump. A same-version refresh
# should say exactly that instead of presenting a misleading X → X upgrade.
SAME="$TMP/update-same-version-source"
cp -a "$FAIL" "$SAME"
cat >> "$SAME/lib/intel.sh" <<'EOF'

pw_intel_update() {
  printf '%s\n' 'synthetic same-version intel refresh succeeded'
  return 0
}
EOF

tar -czf "$SAME_ARCHIVE" -C "$TMP" "$(basename "$SAME")"
PRESSWARDEN_UPDATE_ARCHIVE="$SAME_ARCHIVE" "$BIN/presswarden" update > "$TMP/same.out" 2>&1
grep -q 'PressWarden code refreshed: v9.9.10-test (marketania/PressWarden @ main)' "$TMP/same.out"
if grep -q '9.9.10-test → 9.9.10-test' "$TMP/same.out"; then
  cat "$TMP/same.out" >&2
  printf 'same-version refresh was presented as a version upgrade\n' >&2
  exit 1
fi
grep -q 'Threat intelligence refreshed' "$TMP/same.out"
[ "$(sha256sum "$INSTALL/config/config" | awk '{print $1}')" = "$before_config" ]
[ "$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')" = "$before_quarantine" ]

# A malformed future archive must fail validation before modifying installed
# code or any private state.
BAD="$TMP/bad-source"
cp -a "$SAME" "$BAD"
rm -f "$BAD/VERSION"
tar -czf "$BAD_ARCHIVE" -C "$TMP" "$(basename "$BAD")"
set +e
PRESSWARDEN_UPDATE_ARCHIVE="$BAD_ARCHIVE" "$BIN/presswarden" update > "$TMP/bad.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { cat "$TMP/bad.out" >&2; echo "Expected invalid update to exit 2, got $rc" >&2; exit 1; }
grep -q 'Update validation failed: VERSION is missing' "$TMP/bad.out"
[ "$(tr -d '[:space:]' < "$INSTALL/VERSION")" = '9.9.10-test' ]
[ "$(sha256sum "$INSTALL/config/config" | awk '{print $1}')" = "$before_config" ]
[ "$(sha256sum "$INSTALL/var/reports/scan-20260906.log" | awk '{print $1}')" = "$before_report" ]
[ "$(sha256sum "$INSTALL/var/quarantine/case-1/evidence.php" | awk '{print $1}')" = "$before_quarantine" ]

echo 'PressWarden update + intel refresh test: PASS'
