#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parent / 'runtime-reliability.sh'
s = p.read_text()
old = 'cp "$REPO/lib/_runner.sh" "$REPO/lib/suite-summary.php" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$TMP/repo/lib/"\n'
new = 'cp "$REPO/lib/_runner.sh" "$REPO/lib/suite-summary.php" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$TMP/repo/lib/"\n'
if old not in s:
    raise SystemExit('runtime fixture copy anchor not found')
s = s.replace(old, new, 1)
old = 'REPORTS="$PW_TEST_REPORTS"; PRESSWARDEN_VERSION=test; T0=$(date +%s)\n'
new = 'REPORTS="$PW_TEST_REPORTS"; PRESSWARDEN_STATE_DIR="$PW_TEST_STATE"; PRESSWARDEN_VERSION=test; T0=$(date +%s)\n'
if old not in s:
    raise SystemExit('runtime fixture state anchor not found')
s = s.replace(old, new, 1)
old = 'PW_TEST_REPO="$TMP/repo" PW_TEST_REPORTS="$TMP/reports" PRESSWARDEN_INTERACTIVE=0 \\\n'
new = 'PW_TEST_REPO="$TMP/repo" PW_TEST_REPORTS="$TMP/reports" PW_TEST_STATE="$TMP/state" PRESSWARDEN_INTERACTIVE=0 \\\n'
if old not in s:
    raise SystemExit('runtime fixture env anchor not found')
s = s.replace(old, new, 1)
p.write_text(s)
