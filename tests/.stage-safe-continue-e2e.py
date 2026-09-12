#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).resolve().parent/'run-continuation.sh'
s=p.read_text()
anchor="printf 'Safe continuation scope, replay and refusal semantics: PASS\\n'\n"
if anchor not in s: raise SystemExit('continuation test footer missing')
extra=r'''
# End-to-end shared runner: completed prefix is carried, not executed again;
# first unfinished check runs and the combined summary preserves parent findings.
E2E="$TMP/e2e"; mkdir -p "$E2E/repo/lib" "$E2E/repo/checks" "$E2E/reports" "$E2E/state" "$E2E/root/site/wp-admin" "$E2E/root/site/wp-content"
cp "$REPO/lib/_runner.sh" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/suite-summary.php" \
   "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$REPO/lib/run-continuation.sh" "$REPO/lib/run-continuation.php" "$E2E/repo/lib/"
cat > "$E2E/repo/lib/_lib.sh" <<'EOF'
PRESSWARDEN_DIR="$PW_E2E_REPO"; ROOT="$PW_E2E_ROOT"; REPORTS="$PW_E2E_REPORTS"; PRESSWARDEN_STATE_DIR="$PW_E2E_STATE"
PRESSWARDEN_VERSION=1.1.17; PRESSWARDEN_DISCOVERY_DEPTH=8; PRESSWARDEN_INTERACTIVE=0; PRESSWARDEN_OUTPUT_JSON=1
B=''; C=''; X=''; D=''; Y=''; G=''; R=''; BL=''; W=60; T0=$(date +%s)
SCAN_ROOTS=("$ROOT/site"); NESTED_SITES=(); MANUAL_EXCLUDED_DOMAINS=(); PW_DISCOVERY_FAILED=0
count_sites(){ echo 1; }; count_domains(){ echo 1; }; nested_sites_summary(){ :; }; manual_exclusions_summary(){ :; }
_meta_field(){ :; }; _repeat(){ :; }; _rule(){ echo '---'; }; human_time(){ printf '%ss' "$1"; }; tmpf(){ mktemp; }; die(){ echo "$1" >&2; exit 2; }
. "$PRESSWARDEN_DIR/lib/reports.sh"
EOF
cat > "$E2E/repo/checks/one.sh" <<'EOF'
echo executed-one > "$PW_E2E_ONE_MARKER"
echo 'findings: 9'; exit 1
EOF
cat > "$E2E/repo/checks/two.sh" <<'EOF'
echo executed-two > "$PW_E2E_TWO_MARKER"
echo 'findings: 0'; exit 0
EOF
PARENT='fast-20260911-220000.E2E001'; E2ERUNS="$E2E/state/runs"; E2ESCOPE="$E2E/scope.tsv"
printf 'ROOT\t%s\nDEPTH\t8\nSITE\t%s\n' "$E2E/root" "$E2E/root/site" > "$E2ESCOPE"
php "$STATE" init "$E2ERUNS" "$PARENT" fast 1.1.17 "$E2E/root" 1 1 2 complete 12345 'one two' "$E2E/parent.log" 1789160100
php "$CONT" capture "$E2ERUNS/$PARENT" "$E2ESCOPE"
php "$STATE" step "$E2ERUNS/$PARENT/state.json" 1 2 one
php "$STATE" result "$E2ERUNS/$PARENT/state.json" one findings 2 4
php "$STATE" step "$E2ERUNS/$PARENT/state.json" 2 2 two
php "$STATE" interrupt "$E2ERUNS/$PARENT/state.json" HUP 129 two
set +e
PW_E2E_REPO="$E2E/repo" PW_E2E_ROOT="$E2E/root" PW_E2E_REPORTS="$E2E/reports" PW_E2E_STATE="$E2E/state" \
PW_E2E_ONE_MARKER="$E2E/one-ran" PW_E2E_TWO_MARKER="$E2E/two-ran" PRESSWARDEN_CONTINUE_FROM="$PARENT" \
bash -c 'RUN_NAME=fast; RUN_DESC=test; RUN_DOES=test; RUN_WHY=test; CHECKS="one two"; . "$1/lib/_runner.sh"; run_all' _ "$E2E/repo" > "$E2E/out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
[ ! -e "$E2E/one-ran" ]
[ -e "$E2E/two-ran" ]
grep -q '▶ CARRY.*one' "$E2E/out"
grep -q '▶ RUN.*two' "$E2E/out"
LATEST=$(cat "$E2E/state/runs/latest")
[ "$LATEST" != "$PARENT" ]
[ -f "$E2E/state/runs/$LATEST/scope.json" ]
grep -q '"continued_from": "'"$PARENT"'"' "$E2E/reports/fast-latest-summary.json"
grep -q '"checks_carried": 1' "$E2E/reports/fast-latest-summary.json"
grep -q '"total_findings": 2' "$E2E/reports/fast-latest-summary.json"
'''
p.write_text(s.replace(anchor, extra+"\n"+anchor,1))
