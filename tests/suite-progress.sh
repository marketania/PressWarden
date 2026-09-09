#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/site/wp-admin" "$T/site/wp-content" "$T/site/wp-includes"
touch "$T/site/wp-load.php" "$T/site/wp-settings.php"
export ROOT="$T/site" PRESSWARDEN_DIR="$REPO" PRESSWARDEN_CONFIG_FILE="$T/no-config" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache" PRESSWARDEN_NOCOLOR=1
export PW_SUITE_CURRENT=9 PW_SUITE_TOTAL=20 PW_SUITE_COMPLETED=8 PW_SUITE_PERCENT=40
. "$REPO/lib/_lib.sh"
NAME=test-progress; DESC=test; SCAN_DOES=test; SCAN_WHY=test
banner > "$T/out"
grep -q 'PROGRESS.*40% suite complete.*step 9/20' "$T/out"
grep -q 'suite %s%% complete' "$REPO/lib/_runner.sh"
printf 'Every suite step receives exact completed-check percentage in RUN/banner context: PASS\n'
