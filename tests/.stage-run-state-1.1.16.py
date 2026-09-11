#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]

def replace_once(path, old, new):
    p = root / path
    s = p.read_text()
    if old not in s:
        raise SystemExit(f'anchor not found: {path}: {old[:80]!r}')
    p.write_text(s.replace(old, new, 1))

# run-state helper: querying history before the first run is normal, and epochs
# should not inherit the 2038 signed-32-bit boundary on 64-bit PHP hosts.
replace_once('lib/run-state.php',
"""function pwrs_show($runs, $id = '') {
    $runs = pwrs_plain_dir($runs, false);
""",
"""function pwrs_show($runs, $id = '') {
    $runsRaw = rtrim(pwrs_text($runs, false, 8192), '/');
    if ($runsRaw === '') $runsRaw = '/';
    if (!file_exists($runsRaw) && !is_link($runsRaw)) {
        fwrite(STDOUT, "No recorded PressWarden suite runs.\\n");
        return 0;
    }
    $runs = pwrs_plain_dir($runsRaw, false);
""")
replace_once('lib/run-state.php',
"""$report = pwrs_text($argv[13], true, 8192); $startedEpoch = pwrs_uint($argv[14], 2147483647);""",
"""$report = pwrs_text($argv[13], true, 8192); $startedEpoch = pwrs_uint($argv[14], 4102444800);""")

# Shared suite runner: record the selected plan, active check, each result and
# final suite state. The scan continues if run-state persistence itself fails,
# but final coverage becomes INCOMPLETE.
replace_once('lib/_runner.sh',
""". "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
SUITE_DISCOVERY_INCOMPLETE="${PW_DISCOVERY_FAILED:-0}"
""",
""". "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
. "$(dirname "${BASH_SOURCE[0]}")/run-state.sh"
SUITE_DISCOVERY_INCOMPLETE="${PW_DISCOVERY_FAILED:-0}"
""")
replace_once('lib/_runner.sh',
"""    export PW_SUITE_CURRENT="$current_check" PW_SUITE_TOTAL="$total_checks" PW_SUITE_COMPLETED="$completed_before" PW_SUITE_PERCENT="$suite_percent"
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
""",
"""    export PW_SUITE_CURRENT="$current_check" PW_SUITE_TOTAL="$total_checks" PW_SUITE_COMPLETED="$completed_before" PW_SUITE_PERCENT="$suite_percent"
    pw_run_state_step "$current_check" "$total_checks" "$c" || true
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
""")
replace_once('lib/_runner.sh',
"""      printf '%s|0|skipped|0\\n' "$c" >> "$RES" || return 2; continue
""",
"""      printf '%s|0|skipped|0\\n' "$c" >> "$RES" || return 2
      pw_run_state_result "$c" skipped 0 0 || true
      continue
""")
# The same line occurs for the second interactive skip branch; replace it again.
replace_once('lib/_runner.sh',
"""      printf '%s|0|skipped|0\\n' "$c" >> "$RES" || return 2; continue
""",
"""      printf '%s|0|skipped|0\\n' "$c" >> "$RES" || return 2
      pw_run_state_result "$c" skipped 0 0 || true
      continue
""")
replace_once('lib/_runner.sh',
"""      printf '%s|-|missing|0\\n' "$c" >> "$RES" || return 2; continue
""",
"""      printf '%s|-|missing|0\\n' "$c" >> "$RES" || return 2
      pw_run_state_result "$c" missing - 0 || true
      continue
""")
replace_once('lib/_runner.sh',
"""    case "$rc" in
      0) printf '%s|%s|clean|%s\\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2 ;;
      1) printf '%s|%s|findings|%s\\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2 ;;
      *) printf '%s|%s|ERROR rc=%s|%s\\n' "$c" "${n:--}" "$rc" "$elapsed" >> "$RES" || return 2 ;;
    esac
""",
"""    case "$rc" in
      0)
        printf '%s|%s|clean|%s\\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2
        pw_run_state_result "$c" clean "${n:-0}" "$elapsed" || true
        ;;
      1)
        printf '%s|%s|findings|%s\\n' "$c" "${n:-0}" "$elapsed" >> "$RES" || return 2
        pw_run_state_result "$c" findings "${n:-0}" "$elapsed" || true
        ;;
      *)
        printf '%s|%s|ERROR rc=%s|%s\\n' "$c" "${n:--}" "$rc" "$elapsed" >> "$RES" || return 2
        pw_run_state_result "$c" error "${n:--}" "$elapsed" || true
        ;;
    esac
""")
replace_once('lib/_runner.sh',
"""run_all() {
  pw_report_init "$NAME" || return 2
  local json rc json_written=0
  local -a pipeline_status
  RES=$(tmpf) || { pw_report_remove_empty; return 2; }
""",
"""run_all() {
  pw_report_init "$NAME" || return 2
  local json rc json_written=0 total_checks state_status
  local -a pipeline_status
  total_checks=$(printf '%s\\n' $CHECKS | sort -u | grep -c .)
  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true
  RES=$(tmpf) || { pw_report_remove_empty; return 2; }
""")
replace_once('lib/_runner.sh',
"""  rm -f "$RES"
  pw_report_remove_empty
  printf '%ssummary log:%s %s\\n' "$D" "$X" "$LOG"
  [ "$json_written" -eq 1 ] && printf '%sJSON summary:%s %s\\n' "$D" "$X" "$json"
  return "$rc"
}
""",
"""  rm -f "$RES"
  pw_report_remove_empty
  [ "${PW_RUN_STATE_FAILED:-0}" -eq 0 ] || rc=2
  state_status=COMPLETED
  [ "$rc" -eq 2 ] && state_status=INCOMPLETE
  [ "$rc" -le 2 ] || state_status=FAILED
  if ! pw_run_state_finish "$state_status" "$rc"; then rc=2; fi
  printf '%ssummary log:%s %s\\n' "$D" "$X" "$LOG"
  [ "$json_written" -eq 1 ] && printf '%sJSON summary:%s %s\\n' "$D" "$X" "$json"
  [ "${PW_RUN_STATE_ACTIVE:-0}" -eq 1 ] && printf '%srun state:%s %s\\n' "$D" "$X" "$PW_RUN_STATE_FILE"
  return "$rc"
}
""")

# CLI: read-only last-run / run-status commands and visibility in config/help.
replace_once('presswarden',
"""  ./presswarden doctor [target]        Dependencies, config, integrations, discovery
  ./presswarden lock [target]          Lock WordPress file modifications across discovered sites
""",
"""  ./presswarden doctor [target]        Dependencies, config, integrations, discovery
  ./presswarden last-run               Show the most recently started suite run state
  ./presswarden run-status [RUN_ID]    Show latest or a specific suite run state
  ./presswarden lock [target]          Lock WordPress file modifications across discovered sites
""")
replace_once('presswarden',
"""  printf 'Baseline directory: %s\\n' "$baseline"
}
""",
"""  printf 'Baseline directory: %s\\n' "$baseline"
  printf 'Run-state directory:%s %s\\n' ' ' "$state/runs"
}
""")
replace_once('presswarden',
"""  config) show_config ;;
  sites)
""",
"""  config) show_config ;;
  last-run|run-status)
    if [ "$cmd" = last-run ]; then
      [ "$#" -eq 0 ] || { printf 'Usage: ./presswarden last-run\\n' >&2; exit 2; }
      run_id=''
    else
      [ "$#" -le 1 ] || { printf 'Usage: ./presswarden run-status [RUN_ID]\\n' >&2; exit 2; }
      run_id="${1:-}"
    fi
    command -v php >/dev/null 2>&1 || { printf 'Run-status inspection requires PHP CLI.\\n' >&2; exit 2; }
    if [ "$PRESSWARDEN_PORTABLE" = 1 ]; then
      state="${PRESSWARDEN_STATE_DIR:-$PRESSWARDEN_DIR/var}"
    else
      state="${PRESSWARDEN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/presswarden}"
    fi
    exec php "$PRESSWARDEN_DIR/lib/run-state.php" show "$state/runs" "$run_id"
    ;;
  sites)
""")

# README public surface.
replace_once('README.md', 'version-1.1.15-2ea44f', 'version-1.1.16-2ea44f')
replace_once('README.md',
"""- 📊 **Human-readable and JSON reports**
""",
"""- 📊 **Human-readable and JSON reports**
- 🧾 **Persistent suite run state** so interrupted SSH scans are not mistaken for completed audits
""")
replace_once('README.md',
"""| `./presswarden wp-settings example.com` | WordPress policy, updates, cron, recovery, environment, debug, and config posture |
""",
"""| `./presswarden wp-settings example.com` | WordPress policy, updates, cron, recovery, environment, debug, and config posture |
| `./presswarden last-run` | See whether the latest suite completed, was incomplete, or was interrupted and where it stopped |
""")
replace_once('README.md',
"""Long PHP/JavaScript checks now show a live file percentage; database inspection shows sites processed. The terminal line stays separate from saved reports. Disable with `PRESSWARDEN_PROGRESS=0`. See [progress details](docs/PROGRESS.md).

---
""",
"""Long PHP/JavaScript checks now show a live file percentage; database inspection shows sites processed. The terminal line stays separate from saved reports. Disable with `PRESSWARDEN_PROGRESS=0`. See [progress details](docs/PROGRESS.md).

## Interrupted scans and last-run status

Suite runs now maintain a small private atomic state record while they execute. If SSH closes or the suite receives `HUP`, `INT`, or `TERM`, the latest run is marked `INTERRUPTED` with the active check instead of being left ambiguous.

```bash
./presswarden last-run
./presswarden run-status RUN_ID
```

A catchable interruption retains partial validated reports but never becomes a completed audit. `SIGKILL` cannot be trapped; when process liveness is available, `run-status` identifies a stale `RUNNING` record as an interrupted/abandoned run rather than inventing completion. Automatic resume is intentionally not provided yet. See [suite run-state details](docs/RUN-STATE.md).

---
""")

# Version and changelog.
(root / 'VERSION').write_text('1.1.16\n')
p = root / 'CHANGELOG.md'
s = p.read_text()
marker = '# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n'
entry = """## 1.1.16 — 2026-09-11

Resilient suite run state and interruption visibility.

- Add a private atomic per-suite run-state journal keyed by the existing unique report run ID. Track the selected checks, active step, per-check result/finding count, discovery completeness, site counts, report path, timestamps, signal and final exit state without storing WordPress secrets or payload contents.
- Catch `HUP`, `INT` and `TERM` in the shared suite runner and record `INTERRUPTED` with the active check before exiting. Unexpected shell exits are recorded as `FAILED`; normal finished suites record `COMPLETED` or `INCOMPLETE`. A run-state write failure lets validated checks continue but forces the suite verdict INCOMPLETE.
- Add read-only `last-run` and `run-status [RUN_ID]` commands that do not discover sites or bootstrap WordPress. A stale RUNNING record can report that its recorded PID is no longer present when PHP POSIX support is available; uncatchable SIGKILL is never falsely described as a clean completion.
- Keep run history bounded to allowlisted operational metadata with private run directories, 0600 atomic JSON publication, safe run IDs, symlink/non-regular refusal and a private atomic `latest` pointer. Historical run IDs are never overwritten.
- Deliberately do not add automatic resume yet: replaying partially completed suites safely requires stronger version/scope/exclusion/check-plan compatibility guarantees, especially around stateful or destructive operations.
- Add interruption, unexpected-exit, completed-run, malformed-state, symlink, privacy and PHP 7.4 regressions. Existing malware thresholds, quarantine semantics, baseline transactions, updater recovery, website targeting and shared-host portability remain unchanged.

"""
if marker not in s:
    raise SystemExit('CHANGELOG marker not found')
p.write_text(s.replace(marker, marker + entry, 1))
