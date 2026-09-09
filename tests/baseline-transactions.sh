#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
TMP=$(mktemp -d); trap 'rm -rf -- "$TMP"' EXIT
export ROOT="$TMP/fleet" HOME="$TMP/home" PRESSWARDEN_CONFIG_FILE="$TMP/no-config"
export PRESSWARDEN_STATE_DIR="$TMP/state" PRESSWARDEN_CACHE_DIR="$TMP/cache"
export PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1
export REPO TMP
mkdir -p "$ROOT/site/wp-admin" "$ROOT/site/wp-includes" "$ROOT/site/wp-content" "$HOME" "$TMP/bin"
printf '<?php $wp_version="6.8.2";\n' > "$ROOT/site/wp-includes/version.php"
printf '<?php // settings\n' > "$ROOT/site/wp-settings.php"
printf '<?php // load\n' > "$ROOT/site/wp-load.php"
cat > "$TMP/bin/wp" <<'WP'
#!/usr/bin/env bash
if [ "${PW_TEST_HOLD:-0}" = 1 ] && [ "$1" = plugin ]; then
  touch "$TMP/ready"
  for ((i=0;i<200;i++)); do [ ! -f "$TMP/release" ] || break; sleep 0.05; done
fi
case "$1" in
 plugin|theme) printf 'name,status,version\n';;
 user) printf 'user_login\n';;
 cron) printf 'hook,recurrence\n';;
esac
WP
chmod +x "$TMP/bin/wp"; export PATH="$TMP/bin:$PATH"
expect() { local wanted="$1" rc=0; shift; "$@" > "$TMP/out" 2>&1 || rc=$?; [ "$rc" -eq "$wanted" ] || { cat "$TMP/out"; echo "Expected $wanted got $rc"; exit 1; }; }
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
CURRENT=$(find "$PRESSWARDEN_STATE_DIR" -type d -name current); SCOPE=${CURRENT%/current}; export CURRENT SCOPE
cp -a "$CURRENT" "$TMP/reference"
intact() { for f in manifest meta scope coverage; do cmp "$TMP/reference/$f.tsv" "$CURRENT/$f.tsv"; done; }
# A real in-flight capture holds the lock: no reader/writer sees a mixed generation.
PW_TEST_HOLD=1 bash "$REPO/presswarden" baseline create "$ROOT" > "$TMP/held.out" 2>&1 & pid=$!
for ((i=0;i<200;i++)); do [ ! -f "$TMP/ready" ] || break; sleep 0.05; done
[ -f "$TMP/ready" ]
expect 2 bash "$REPO/presswarden" baseline create "$ROOT"
expect 2 bash "$REPO/presswarden" changes "$ROOT"
expect 2 bash "$REPO/presswarden" baseline status "$ROOT"
touch "$TMP/release"; wait "$pid"
[ ! -e "$SCOPE/.baseline.lock" ]
# Snapshot created_at may differ; preserve a fresh reference for failure assertions.
rm -rf "$TMP/reference"; cp -a "$CURRENT" "$TMP/reference"
# Refuse unsafe snapshot/ancestor destinations, without altering their referents.
mv "$CURRENT" "$TMP/link-target"; ln -s "$TMP/link-target" "$CURRENT"
expect 2 bash "$REPO/presswarden" baseline create "$ROOT"
cmp "$TMP/reference/manifest.tsv" "$TMP/link-target/manifest.tsv"
rm "$CURRENT"; mv "$TMP/link-target" "$CURRENT"
# Failure between moving the old generation and publishing the new one restores old.
expect 2 bash -c '
 . "$REPO/lib/baseline.sh"
 mv(){ case "$2" in */capture) return 1;; esac; command mv "$@"; }
 pw_baseline_create'
intact; [ ! -e "$SCOPE/.baseline.lock" ]
# If restoration also fails, retain the last good snapshot and the lock/workspace.
expect 2 bash -c '
 . "$REPO/lib/baseline.sh"
 mv(){ case "$2" in */capture|*/snapshot) return 1;; esac; command mv "$@"; }
 pw_baseline_create'
[ -d "$SCOPE/.baseline.lock" ]; [ ! -e "$CURRENT" ]
[ -n "$(find "$SCOPE" -maxdepth 1 -name '.work.*' -print)" ]
old=$(find "$SCOPE/history" -name meta.tsv -type f | while IFS= read -r f; do
  cmp -s "$TMP/reference/meta.tsv" "$f" && printf '%s\n' "${f%/meta.tsv}" || true
done | tail -n 1)
[ -n "$old" ]; cmp "$TMP/reference/manifest.tsv" "$old/manifest.tsv"
expect 2 bash "$REPO/presswarden" changes "$ROOT"
# Test-only manual recovery. Runtime code never automatically clears stale locks.
cp -a "$old" "$CURRENT"; rmdir "$SCOPE/.baseline.lock"
find "$SCOPE" -maxdepth 1 -type d -name '.work.*' -exec rm -rf -- '{}' +
intact
# Catchable interruption immediately after archiving restores the previous snapshot.
expect 2 bash -c '
 . "$REPO/lib/baseline.sh"
 mv(){ command mv "$@" || return; case "$2" in */current) kill -TERM "$BASHPID";; esac; }
 pw_baseline_create'
intact; [ ! -e "$SCOPE/.baseline.lock" ]
# Same-second snapshots and change reports never clobber one another.
cat > "$TMP/bin/date" <<'DATE'
#!/usr/bin/env bash
case "$*" in *%Y%m%dT%H%M%SZ*) printf '20260101T010101Z\n';; *) /bin/date "$@";; esac
DATE
chmod +x "$TMP/bin/date"
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
expect 0 bash "$REPO/presswarden" baseline create "$ROOT"
[ "$(find "$SCOPE/history" -maxdepth 1 -name 'snapshot-20260101T010101Z.*' | wc -l)" -eq 2 ]
printf '<?php // intentional change\n' > "$ROOT/site/new.php"
expect 1 bash "$REPO/presswarden" changes "$ROOT"
expect 1 bash "$REPO/presswarden" changes "$ROOT"
[ "$(find "$PRESSWARDEN_STATE_DIR/reports" -name 'baseline-changes-20260101T010101Z.*.tsv' | wc -l)" -eq 2 ]
# No-replace report publication failure must propagate without rebasing.
cp -a "$CURRENT" "$TMP/before-report-failure"
expect 2 bash -c '. "$REPO/lib/baseline.sh"; ln(){ return 1; }; pw_baseline_diff'
cmp "$TMP/before-report-failure/manifest.tsv" "$CURRENT/manifest.tsv"
[ ! -e "$SCOPE/.baseline.lock" ]
# Scoped subshell permissions must not change a caller's umask.
expect 0 bash -c '. "$REPO/lib/baseline.sh"; umask 0022; pw_baseline_create; [ "$(umask)" = 0022 ]'
printf 'Baseline transactions: concurrency, activation/rollback failure, interruption, history, reports and umask passed.\n'
