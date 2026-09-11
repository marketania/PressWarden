#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]

# 1) Contextualize the whole-selection apply revalidation without weakening it.
p = root / 'lib/quarantine.php'
s = p.read_text()
old = """        // Never trust a saved plan as current state. Whole-selection precheck.\n        if ($this->plan($policy, $targets)['items'] !== $plan['items']) $this->fail('source changed since approval snapshot');\n"""
new = """        // Never trust a saved plan as current state. Whole-selection precheck.\n        // The snapshot intentionally predates interactive approval so approval remains\n        // bound to the exact bytes that produced the finding. If a target changes or\n        // disappears while the operator is deciding, refuse the entire batch rather\n        // than deleting content that was not part of the approved snapshot.\n        try {\n            $current = $this->plan($policy, $targets);\n        } catch (PressWardenQuarantineError $e) {\n            $this->fail('approved selection revalidation failed: '.$e->getMessage());\n        }\n        if ($current['items'] !== $plan['items']) $this->fail('approved selection changed since snapshot');\n"""
if old not in s:
    raise SystemExit('quarantine.php apply precheck anchor not found')
s = s.replace(old, new, 1)
p.write_text(s)

# 2) Give stale-before-removal failures specific guidance while keeping generic
# guidance for failures after evidence creation/removal may have started.
p = root / 'lib/quarantine-cli.php'
s = p.read_text()
old = """    if ($e instanceof PressWardenQuarantineError) fwrite(STDERR, \"Quarantine safeguard: \".$e->getMessage().\".\\n\");\n    fwrite(STDERR, \"INCOMPLETE: quarantine operation refused or failed. Existing evidence was retained; inspect permissions, paths, limits and docs/QUARANTINE.md.\\n\");\n"""
new = """    if ($e instanceof PressWardenQuarantineError) {\n        $reason = $e->getMessage();\n        fwrite(STDERR, \"Quarantine safeguard: \".$reason.\".\\n\");\n        if (strpos($reason, 'approved selection revalidation failed:') === 0\n            || $reason === 'approved selection changed since snapshot') {\n            fwrite(STDERR, \"INCOMPLETE: selected content changed or became unavailable after the approval snapshot. No removal started; rerun the current check to refresh the action list.\\n\");\n            exit(2);\n        }\n    }\n    fwrite(STDERR, \"INCOMPLETE: quarantine operation refused or failed. Existing evidence was retained; inspect permissions, paths, limits and docs/QUARANTINE.md.\\n\");\n"""
if old not in s:
    raise SystemExit('quarantine-cli.php catch anchor not found')
s = s.replace(old, new, 1)
p.write_text(s)

# 3) Avoid printing a second generic shell failure when the PHP helper already
# emitted the controlled safeguard + INCOMPLETE explanation.
p = root / 'lib/quarantine.sh'
s = p.read_text()
old = """_pw_quarantine_failure() {\n  PW_REMEDIATION_FAILED=1\n  printf 'INCOMPLETE: quarantine action did not complete; existing evidence is retained.\\n' >&2\n  return 2\n}\n"""
new = """_pw_quarantine_failure() {\n  PW_REMEDIATION_FAILED=1\n  printf 'INCOMPLETE: quarantine action did not complete; existing evidence is retained.\\n' >&2\n  return 2\n}\n_pw_quarantine_mark_failed() {\n  # The PHP helper already emitted a controlled safeguard and INCOMPLETE line.\n  # Mark the check incomplete without duplicating a third generic message.\n  PW_REMEDIATION_FAILED=1\n  return 2\n}\n"""
if old not in s:
    raise SystemExit('quarantine.sh failure helper anchor not found')
s = s.replace(old, new, 1)
old = """  if ! php \"$PRESSWARDEN_DIR/lib/quarantine-cli.php\" --prepare \"$PW_Q_WORK/context\" \"$PW_Q_WORK/plan.json\"; then\n    _pw_quarantine_discard_plan; _pw_quarantine_failure; return 2\n  fi\n"""
new = """  if ! php \"$PRESSWARDEN_DIR/lib/quarantine-cli.php\" --prepare \"$PW_Q_WORK/context\" \"$PW_Q_WORK/plan.json\"; then\n    _pw_quarantine_discard_plan; _pw_quarantine_mark_failed; return 2\n  fi\n"""
if old not in s:
    raise SystemExit('quarantine.sh prepare failure anchor not found')
s = s.replace(old, new, 1)
old = """  local list=\"$1\" plan=\"${2:-}\" mode=\"${3:-generic}\" own_plan=0 out rc kind caseid original extra removed=0 completed=0 expected_case=''\n"""
new = """  local list=\"$1\" plan=\"${2:-}\" mode=\"${3:-generic}\" own_plan=0 out rc helper_rc kind caseid original extra removed=0 completed=0 expected_case=''\n"""
if old not in s:
    raise SystemExit('quarantine.sh local anchor not found')
s = s.replace(old, new, 1)
old = """  php \"$PRESSWARDEN_DIR/lib/quarantine-cli.php\" --apply \"$plan\" > \"$out\"; rc=$?\n"""
new = """  php \"$PRESSWARDEN_DIR/lib/quarantine-cli.php\" --apply \"$plan\" > \"$out\"; helper_rc=$?; rc=$helper_rc\n"""
if old not in s:
    raise SystemExit('quarantine.sh apply anchor not found')
s = s.replace(old, new, 1)
old = """  [ \"$rc\" -eq 0 ] && [ \"$completed\" -eq 1 ] && [ \"$removed\" -gt 0 ] || { _pw_quarantine_failure; return 2; }\n"""
new = """  if ! { [ \"$rc\" -eq 0 ] && [ \"$completed\" -eq 1 ] && [ \"$removed\" -gt 0 ]; }; then\n    if [ \"${helper_rc:-0}\" -ne 0 ]; then _pw_quarantine_mark_failed; else _pw_quarantine_failure; fi\n    return 2\n  fi\n"""
if old not in s:
    raise SystemExit('quarantine.sh final failure anchor not found')
s = s.replace(old, new, 1)
p.write_text(s)

# 4) Make the operator-facing action line describe the actual sequence.
p = root / 'lib/remediation.sh'
s = p.read_text()
old = """        printf '    %sℹ%s  backing up to quarantine before removal...\\n' \"$C\" \"$X\"\n"""
new = """        printf '    %sℹ%s  revalidating approved snapshot, then backing up before removal...\\n' \"$C\" \"$X\"\n"""
if old not in s:
    raise SystemExit('remediation action message anchor not found')
s = s.replace(old, new, 1)
p.write_text(s)

# 5) Regression: a target that disappears after prepare must fail before any
# removal/case creation, with one specific explanation and no duplicate shell line.
p = root / 'tests/quarantine-runtime.sh'
s = p.read_text()
anchor = """[ \"$rc\" -eq 2 ]; [ \"$(cat \"$SITE/changed.php\")\" = 'new state' ]; grep -q INCOMPLETE \"$TMP/changed.out\"\n"""
insert = anchor + """grep -q 'approved selection changed since snapshot' \"$TMP/changed.out\"\ngrep -q 'No removal started; rerun the current check to refresh the action list' \"$TMP/changed.out\"\n! grep -q 'quarantine action did not complete' \"$TMP/changed.out\"\n# A target can also disappear while the operator is deciding. The exact approved\n# batch is then stale, so nothing else in that batch may be removed.\ncat > \"$TMP/missing.sh\" <<'STUB'\nset -uo pipefail\n. \"$PW_TEST_REPO/lib/_lib.sh\"\npw_report_init missing\nprintf '%s\\n' \"$PW_TEST_SITE/missing-a.php\" \"$PW_TEST_SITE/missing-b.php\" > \"$1\"\n_pw_quarantine_prepare \"$1\" || exit 9\nrm -f \"$PW_TEST_SITE/missing-a.php\"\n_quarantine_delete \"$1\" \"$PW_Q_WORK/plan.json\"; rc=$?\n_pw_quarantine_discard_plan\n[ \"$rc\" -eq 2 ] && [ \"$PW_REMEDIATION_FAILED\" -eq 1 ] || exit 9\nfinish\nSTUB\nprintf 'gone before approval completes\\n' > \"$SITE/missing-a.php\"\nprintf 'must remain untouched\\n' > \"$SITE/missing-b.php\"\nbefore_cases=$(find \"$TMP/state/quarantine\" -mindepth 1 -maxdepth 1 -type d -name 'case-*' 2>/dev/null | wc -l)\nset +e; bash \"$TMP/missing.sh\" \"$TMP/missing-list\" > \"$TMP/missing.out\" 2>&1; rc=$?; set -e\nafter_cases=$(find \"$TMP/state/quarantine\" -mindepth 1 -maxdepth 1 -type d -name 'case-*' 2>/dev/null | wc -l)\n[ \"$rc\" -eq 2 ]; [ -f \"$SITE/missing-b.php\" ]; [ \"$before_cases\" -eq \"$after_cases\" ]\ngrep -q 'approved selection revalidation failed: unreadable or missing path' \"$TMP/missing.out\"\ngrep -q 'No removal started; rerun the current check to refresh the action list' \"$TMP/missing.out\"\n! grep -q 'quarantine action did not complete' \"$TMP/missing.out\"\n"""
if anchor not in s:
    raise SystemExit('quarantine-runtime changed regression anchor not found')
s = s.replace(anchor, insert, 1)
p.write_text(s)

# 6) Version/changelog.
p = root / 'VERSION'
p.write_text('1.1.15\n')
p = root / 'CHANGELOG.md'
s = p.read_text()
marker = '# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n'
entry = """## 1.1.15 — 2026-09-11\n\nQuarantine stale-selection diagnostics and operator clarity.\n\n- Preserve the exact-content approval guarantee: quarantine snapshots still bind interactive approval to the bytes that produced the finding, and any target that changes or disappears before removal still refuses the whole batch.\n- Contextualize the pre-removal whole-selection revalidation so missing/unreadable targets are reported as an approved-selection change rather than an unexplained generic quarantine failure.\n- State explicitly when the stale-selection failure happens before any removal starts and tell the operator to rerun the current check to refresh findings/action scope.\n- Remove the redundant third shell-level INCOMPLETE line when the PHP quarantine helper already emitted controlled failure diagnostics.\n- Add runtime regressions for changed content and a target disappearing after the approval snapshot; verify an unchanged sibling remains untouched and no quarantine case is created for the refused stale batch.\n\n"""
if marker not in s:
    raise SystemExit('CHANGELOG marker not found')
s = s.replace(marker, marker + entry, 1)
p.write_text(s)
