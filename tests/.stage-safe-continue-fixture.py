#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).resolve().parent/'runtime-reliability.sh'
s=p.read_text()
old='cp "$REPO/lib/_runner.sh" "$REPO/lib/suite-summary.php" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$TMP/repo/lib/"'
new='cp "$REPO/lib/_runner.sh" "$REPO/lib/suite-summary.php" "$REPO/lib/reports.sh" "$REPO/lib/report-json.php" "$REPO/lib/run-state.sh" "$REPO/lib/run-state.php" "$REPO/lib/run-continuation.sh" "$REPO/lib/run-continuation.php" "$TMP/repo/lib/"'
if old not in s: raise SystemExit('runtime fixture copy anchor missing')
p.write_text(s.replace(old,new,1))
