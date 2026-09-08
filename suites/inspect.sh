#!/usr/bin/env bash
# Focused rechecks reuse the existing read-only intelligence checks unchanged.
case "${1:-}" in
  php) CHECKS='php-threat-intel'; RUN_NAME=inspect-php; scope='PHP callable / credential / admin-payload intelligence' ;;
  js) CHECKS='js-threat-intel'; RUN_NAME=inspect-js; scope='JavaScript and inline HTML intelligence' ;;
  db) CHECKS='wp-db-malware'; RUN_NAME=inspect-db; scope='targeted database-stored threat intelligence' ;;
  *) printf 'Usage: ./presswarden inspect php|js|db [directory]\n' >&2; exit 2 ;;
esac
[ "$#" -eq 1 ] || { printf 'Unexpected inspect arguments.\n' >&2; exit 2; }
RUN_DESC="focused read-only recheck • $scope"
RUN_DOES="Runs only $CHECKS on discovered sites with the usual exclusions, limits, findings and JSON summary."
RUN_WHY='Use to investigate one area or retest a fix; not a replacement for fast/full/incident coverage. Database mode still bootstraps WordPress through WP-CLI.'
PRESSWARDEN_INTERACTIVE=0; export PRESSWARDEN_INTERACTIVE
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_runner.sh"
run_all
