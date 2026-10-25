#!/usr/bin/env bash
# Manual quarantine retention: preview by default, only complete verified cases,
# exact approved set, typed terminal confirmation and post-removal verification.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/presswarden-quarantine-prune.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SITE="$TMP/fleet/example.com/public_html"
mkdir -p "$SITE/wp-admin" "$SITE/wp-content" "$SITE/wp-includes" "$TMP/home"
printf '<?php $wp_version="7.1";\n' > "$SITE/wp-includes/version.php"
touch "$SITE/wp-load.php" "$SITE/wp-settings.php"
export ROOT="$TMP/fleet" PRESSWARDEN_CONFIG_FILE="$TMP/no-config" PRESSWARDEN_STATE_DIR="$TMP/state"
export PRESSWARDEN_CACHE_DIR="$TMP/cache" PRESSWARDEN_DISCOVERY_CACHE_TTL=0 PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 HOME="$TMP/home"
export PW_TEST_REPO="$REPO" PW_TEST_SITE="$SITE"
cat > "$TMP/approved.sh" <<'STUB'
set -uo pipefail
. "$PW_TEST_REPO/lib/_lib.sh"
pw_report_init quarantine-prune-test
printf '%s\n' "$PW_TEST_SITE/$1" > "$2"
_quarantine_delete "$2"
STUB
Q="$TMP/state/quarantine"
for i in 1 2; do
  printf 'evidence %s\n' "$i" > "$SITE/old-$i.env"
  bash "$TMP/approved.sh" "old-$i.env" "$TMP/list-$i" > "$TMP/action-$i.out" 2>&1
  sleep 1
done
case1=$(sed -n 's/^    Quarantine case: //p' "$TMP/action-1.out")
case2=$(sed -n 's/^    Quarantine case: //p' "$TMP/action-2.out")
[ -n "$case1" ] && [ -n "$case2" ] && [ "$case1" != "$case2" ]

# CLI argument validation and fresh cases are never eligible.
for bad in '' --older-than=0 --older-than=abc '--older-than=30 --force'; do
  # shellcheck disable=SC2086 # intentional word splitting of test arguments
  set +e; bash "$REPO/presswarden" quarantine prune $bad > "$TMP/bad.out" 2>&1; rc=$?; set -e
  [ "$rc" -eq 2 ]
done
bash "$REPO/presswarden" quarantine prune --older-than=30 > "$TMP/preview.out"
grep -q 'Eligible: 0 case(s)' "$TMP/preview.out"
[ -d "$Q/$case1" ] && [ -d "$Q/$case2" ]

# Library level with a fixed clock: a tampered case is kept, a verified one is eligible.
printf 'tampered' > "$Q/$case2/objects/00001.bin"
cat > "$TMP/prune.php" <<'PHP'
<?php
require $argv[1].'/lib/quarantine.php';
$q = new PressWardenQuarantine(); $root = $argv[2]; $future = time() + 40 * 86400;
$r = $q->pruneCandidates($root, 30, $future);
if (array_keys($r['eligible']) !== [$argv[3]]) { fwrite(STDERR, "eligible mismatch\n"); exit(1); }
if (strpos($r['kept'][$argv[4]] ?? '', 'verification failed') !== 0) { fwrite(STDERR, "tampered case not kept\n"); exit(1); }
// A stale or widened approval is refused before anything is removed.
foreach ([[$argv[4]], [$argv[3], $argv[4]], []] as $bad) {
  try { $q->prune($root, 30, $bad, $future); fwrite(STDERR, "stale approval accepted\n"); exit(1); }
  catch (PressWardenQuarantineError $e) {}
}
if (!is_dir($root.'/'.$argv[3])) { fwrite(STDERR, "case removed by refused approval\n"); exit(1); }
ob_start(); $out = $q->prune($root, 30, [$argv[3]], $future); ob_end_clean();
if ($out['removed'] !== 1 || file_exists($root.'/'.$argv[3]) || file_exists($root.'/.pruning-'.$argv[3])) { fwrite(STDERR, "prune failed\n"); exit(1); }
if (!is_dir($root.'/'.$argv[4])) { fwrite(STDERR, "kept case removed\n"); exit(1); }
$log = file_get_contents($root.'/prune-log.tsv');
if (strpos($log, $argv[3]."\t") === false || (fileperms($root.'/prune-log.tsv') & 0077)) { fwrite(STDERR, "prune log\n"); exit(1); }
PHP
php "$TMP/prune.php" "$REPO" "$Q" "$case1" "$case2" > /dev/null
bash "$REPO/presswarden" quarantine list > "$TMP/list.out"
! grep -q "$case1" "$TMP/list.out"; grep -q "$case2" "$TMP/list.out"

# --apply never runs without a terminal, even with eligible cases (none here) or INTERACTIVE=0.
bash "$REPO/presswarden" quarantine prune --older-than=30 --apply < /dev/null > "$TMP/apply.out" 2>&1
grep -q 'Eligible: 0 case(s)' "$TMP/apply.out"
[ -d "$Q/$case2" ]
printf 'Quarantine retention preview, verification gate, exact approval and logging: PASS\n'
