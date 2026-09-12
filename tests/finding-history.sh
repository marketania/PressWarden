#!/usr/bin/env bash
set -euo pipefail
if [ -n "${PWFH_REPO:-}" ]; then
  PHPH="$PWFH_REPO/lib/finding-history.php"
  PWFH_HELPER_SH="$PWFH_REPO/lib/finding-history.sh"
else
  PHPH=/tmp/finding-history.php
  PWFH_HELPER_SH=/tmp/finding-history.sh
fi
export PWFH_HELPER_SH
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
runs="$T/runs"; hist="$T/history"; site="$T/site"
mkdir -p "$runs" "$site"
printf '<?php echo 1;\n' > "$site/a.php"
fp=$(php -r '$b=["root"=>$argv[1],"discovery_depth"=>8,"scan_roots"=>[$argv[1]],"target_exclusions"=>[]]; echo hash("sha256",json_encode($b,JSON_UNESCAPED_SLASHES));' "$site")
mk_run() {
  id=$1 status=$2 checkstatus=$3 findings=$4 discovery=${5:-complete} epoch=${6:-100} version=${7:-1.1.19}
  d="$runs/$id"; mkdir -p "$d"
  cat > "$d/state.json" <<EOF
{"tool":"PressWarden","run_id":"$id","suite":"fast","version":"$version","started_epoch":$epoch,"status":"$status","discovery_status":"$discovery","results":{"check1":{"check":"check1","status":"$checkstatus","findings":$findings}}}
EOF
  cat > "$d/scope.json" <<EOF
{"format":1,"tool":"PressWarden","root":"$site","discovery_depth":8,"scan_roots":["$site"],"target_exclusions":[],"fingerprint":"$fp"}
EOF
  printf '%s\texample.com\n' "$site" > "$T/map.tsv"
  php "$PHPH" init "$d" "$T/map.tsv"
}
cap_file(){ id=$1; printf '%s\n' "$site/a.php" > "$T/findings"; php "$PHPH" capture "$runs/$id" check1 'PW-PHP-004 • callable' issue "$T/findings"; }
final(){ php "$PHPH" finalize "$runs" "$hist" "$1" > "$T/$1.out"; }
count(){ php -r '$j=json_decode(file_get_contents($argv[1]),true); echo $j["counts"][$argv[2]];' "$runs/$1/history.json" "$2"; }

mk_run r1 COMPLETED findings 1 complete 1900000100; cap_file r1; final r1
[ "$(count r1 NEW)" = 1 ]
[ "$(stat -c %a "$runs/r1/history.json")" = 600 ]
[ "$(stat -c %a "$runs/r1/observations")" = 700 ]
[ "$(stat -c %a "$hist/index")" = 700 ]
mk_run r2 COMPLETED findings 1 complete 1900000200; cap_file r2; final r2
[ "$(count r2 RECURRING)" = 1 ]
printf '<?php echo 2;\n' > "$site/a.php"
mk_run r3 COMPLETED findings 1 complete 1900000300; cap_file r3; final r3
[ "$(count r3 CHANGED)" = 1 ]
mk_run r4 COMPLETED skipped 0 complete 1900000400; final r4
[ "$(count r4 NOT_RECHECKED)" = 1 ]
mk_run r5 COMPLETED clean 0 complete 1900000500; final r5
[ "$(count r5 RESOLVED)" = 1 ]

# Incomplete discovery cannot resolve an active finding.
printf '<?php echo 3;\n' > "$site/a.php"
mk_run r6 COMPLETED findings 1 complete 1900000600; cap_file r6; final r6
mk_run r7 INCOMPLETE clean 0 incomplete 1900000700; final r7
[ "$(count r7 NOT_RECHECKED)" = 1 ]
[ "$(count r7 RESOLVED)" = 0 ]

# Generic evidence is represented only by a digest, never raw text.
mk_run r8 COMPLETED findings 1 complete 1900000800
printf 'credential=secret-value\n' > "$T/findings"
php "$PHPH" capture "$runs/r8" check1 'custom evidence' review "$T/findings"
final r8
! grep -q 'secret-value' "$runs/r8/history.json"

# Controlled DB locators retain site + row identity without raw values.
mk_run r9 COMPLETED findings 1 complete 1900000900
printf '%s [PW-DB-001; option row 42]\n' "$site" > "$T/findings"
php "$PHPH" capture "$runs/r9" check1 'PW-DB-001 • stored database evidence' issue "$T/findings"
final r9
grep -q 'db:option:42' "$runs/r9/history.json"
grep -q 'example.com' "$runs/r9/history.json"

# Carried completed checks copy observations into a new continuation run.
mk_run parent INTERRUPTED findings 1 complete 1900001000
printf '%s\n' "$site/a.php" > "$T/findings"
php "$PHPH" capture "$runs/parent" check1 'PW-PHP-004 • callable' issue "$T/findings"
mk_run child COMPLETED findings 1 complete 1900001100
php "$PHPH" carry "$runs" parent child check1
final child
[ "$(count child NEW)" = 1 ] || [ "$(count child RECURRING)" = 1 ]

php "$PHPH" show "$runs" r3 | grep -q CHANGED

# A scanner-version transition can carry known identities but cannot resolve
# an absent finding until it has been rechecked again under the new version.
printf '<?php echo 4;\n' > "$site/a.php"
mk_run v1 COMPLETED findings 1 complete 1900001000 1.1.19; cap_file v1; final v1
mk_run v2 INCOMPLETE clean 0 complete 1900001100 1.1.20; final v2
[ "$(count v2 NOT_RECHECKED)" = 1 ]
[ "$(count v2 RESOLVED)" = 0 ]
grep -q 'VERSION_CHANGED' "$runs/v2/history.json"
mk_run v3 COMPLETED clean 0 complete 1900001200 1.1.20; final v3
[ "$(count v3 RESOLVED)" = 1 ]
printf '<?php echo 5;\n' > "$site/a.php"
mk_run v4 COMPLETED findings 1 complete 1900001250 1.1.20; cap_file v4; final v4
[ "$(count v4 NEW)" = 1 ]

# A per-check capture mismatch never advances comparison state and cannot
# manufacture a resolution.
mk_run mismatch COMPLETED findings 2 complete 1900001300
cap_file mismatch
set +e
final mismatch
mismatch_rc=$?
set -e
[ "$mismatch_rc" -eq 2 ]
grep -q '"capture_integrity": false' "$runs/mismatch/history.json"
grep -R -q '"run_id": "v4"' "$hist/index"

# An overlapping older run can observe findings but cannot resolve an unmatched prior one.
mk_run overlap COMPLETED clean 0 complete 1 1.1.20
final overlap
[ "$(count overlap NOT_RECHECKED)" -ge 1 ]
[ "$(count overlap RESOLVED)" = 0 ]
grep -q 'OVERLAPPING_RUNS' "$runs/overlap/history.json"

# Unsafe unexpected observation entries fail closed and never produce a history report.
mk_run unsafe COMPLETED clean 0 complete 1900001400 1.1.20
ln -s /etc/passwd "$runs/unsafe/observations/obs-deadbeefdeadbeefdeadbeef.json"
set +e
php "$PHPH" finalize "$runs" "$hist" unsafe >/dev/null 2>&1
unsafe_rc=$?
set -e
[ "$unsafe_rc" -eq 2 ]
[ ! -e "$runs/unsafe/history.json" ]

# Inherited suite context must survive a check sourcing the history helper.
PW_HISTORY_ACTIVE=1 PW_HISTORY_RUN_DIR=/private/run PW_HISTORY_RUN_ID=test-run \
  bash -c '. "$PWFH_HELPER_SH"; [ "$PW_HISTORY_ACTIVE" = 1 ] && [ "$PW_HISTORY_RUN_DIR" = /private/run ] && [ "$PW_HISTORY_RUN_ID" = test-run ]'

# The shared report() path must invoke history capture for ALERT/REVIEW findings
# before remediation; INFO findings remain outside structured security history.
hook="$T/hook"
PW_HISTORY_ACTIVE=1
pw_history_capture(){ printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" > "$hook"; }
_save_details(){ return 0; }
compact_line(){ printf '%s' "$1"; }
human_time(){ printf '0s'; }
tmpf(){ mktemp; }
_prompt_file_action(){ return 0; }
B=''; R=''; Y=''; C=''; G=''; X=''; D=''; BL=''; M=''; PRESSWARDEN_MAX=60; PRESSWARDEN_INTERACTIVE=0
MANUAL_EXCLUDED_ROOTS=(); CURRENT_SECTION='PW-PHP-004 • callable'; NAME=php-threat-intel; TOTAL=0; ALERTS=0; REVIEWS=0; SECN=1; SEC_T0=$(date +%s); PW_REPORT_FAILED=0; PW_REMEDIATION_FAILED=0; PW_CHECK_INCOMPLETE=0
ROOT="$site"
if [ -n "${PWFH_REPO:-}" ]; then
  # shellcheck source=/dev/null
  . "$PWFH_REPO/lib/remediation.sh"
  printf '%s\n' "$site/a.php" > "$T/report-findings"
report "$T/report-findings" issue '' noaction >/dev/null
  grep -q $'issue\tPW-PHP-004 • callable\tphp-threat-intel' "$hook"
fi

printf 'finding history synthetic PASS\n'
