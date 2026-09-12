#!/usr/bin/env python3
from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]

def rep(path, old, new):
    p=root/path; s=p.read_text()
    if old not in s: raise SystemExit(f'anchor missing: {path}: {old[:90]!r}')
    p.write_text(s.replace(old,new,1))

def sub(path, pattern, repl):
    p=root/path; s=p.read_text(); n=re.subn(pattern,repl,s,count=1,flags=re.S)
    if n[1]!=1: raise SystemExit(f'pattern missing: {path}: {pattern[:90]!r}')
    p.write_text(n[0])

# Finish the dedicated continuation helper verify path.
sub(Path('lib/run-continuation.php'), r"    if\(\$cmd==='verify'\)\{.*?\n    \}\n    pwc_fail\('unknown continuation command'\);", """    if($cmd==='verify'){
        if($argc!==9)pwc_fail('invalid verify arguments');
        $p=pwc_plan_data($argv[2],$argv[3],$argv[4]);
        $suite=pwc_text($argv[5],false,96); if($suite!==$p['suite'])pwc_fail('suite changed since interrupted run');
        $rawChecks=trim(pwc_text($argv[6],false,16384)); $currentChecks=$rawChecks===''?[]:preg_split('/[[:space:]]+/',$rawChecks);
        if($currentChecks!==$p['checks'])pwc_fail('check plan changed since interrupted run');
        $scope=pwc_scope_from_tsv($argv[7]);
        if(!hash_equals((string)$p['scope']['fingerprint'],(string)$scope['fingerprint']))pwc_fail('site scope changed since interrupted run; rerun the suite for trustworthy coverage');
        pwc_write_carry($argv[8],$p['carry']);
        echo "START\\t",$p['start'],"\\nCARRY\\t",count($p['carry']),"\\n";
        exit(0);
    }
    pwc_fail('unknown continuation command');""")

# Shared runner: continuation is validated after fresh discovery, completed-prefix
# results are carried transparently, and every new run captures continuation scope.
rep('lib/_runner.sh',
'''. "$(dirname "${BASH_SOURCE[0]}")/run-state.sh"
SUITE_DISCOVERY_INCOMPLETE="${PW_DISCOVERY_FAILED:-0}"
''',
'''. "$(dirname "${BASH_SOURCE[0]}")/run-state.sh"
. "$(dirname "${BASH_SOURCE[0]}")/run-continuation.sh"
SUITE_DISCOVERY_INCOMPLETE="${PW_DISCOVERY_FAILED:-0}"
''')
rep('lib/_runner.sh',
'''  local c rc n out seen="" start elapsed force="" total_checks=0 current_check=0 check_path completed_before suite_percent discovery_incomplete="${SUITE_DISCOVERY_INCOMPLETE:-0}"
''',
'''  local c rc n out seen="" start elapsed force="" total_checks=0 current_check=0 check_path completed_before suite_percent discovery_incomplete="${SUITE_DISCOVERY_INCOMPLETE:-0}" carried carry_check carry_n carry_st carry_tm
''')
rep('lib/_runner.sh',
'''  _meta_field 10 "WHY" "$SUITE_WHY"
  printf '  %s%-10s%s %s\\n' "$D" "ROOT" "$X" "$ROOT"
''',
'''  _meta_field 10 "WHY" "$SUITE_WHY"
  [ -z "${PRESSWARDEN_CONTINUE_FROM:-}" ] || _meta_field 10 "CONTINUE" "from ${PRESSWARDEN_CONTINUE_FROM} • carried ${PW_CONTINUE_CARRIED:-0} completed check(s) • rerun starts at ${PW_CONTINUE_START:-unknown}"
  printf '  %s%-10s%s %s\\n' "$D" "ROOT" "$X" "$ROOT"
''')
rep('lib/_runner.sh',
'''    pw_run_state_step "$current_check" "$total_checks" "$c" || true
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
''',
'''    pw_run_state_step "$current_check" "$total_checks" "$c" || true
    if carried=$(pw_continue_carried_row "$c" 2>/dev/null); then
      IFS=$'\\t' read -r carry_check carry_n carry_st carry_tm <<< "$carried"
      printf '\\n%s%s▶ CARRY%s %s[%s/%s]%s  %s%s%s  %s(completed in parent run • suite %s%% complete)%s\\n' "$B" "$C" "$X" "$B" "$current_check" "$total_checks" "$X" "$B" "$c" "$X" "$D" "$suite_percent" "$X"
      printf '%s|%s|%s|%s\\n' "$c" "$carry_n" "$carry_st" "$carry_tm" >> "$RES" || return 2
      pw_run_state_result "$c" "$carry_st" "$carry_n" "$carry_tm" || true
      continue
    fi
    if [ "$c" = "wp-access" ] && ! admin_check_wanted; then
''')
rep('lib/_runner.sh',
'''run_all() {
  pw_report_init "$NAME" || return 2
  local json rc json_written=0 total_checks state_status
  local -a pipeline_status
  total_checks=$(printf '%s\\n' $CHECKS | sort -u | grep -c .)
''',
'''run_all() {
  local json rc json_written=0 total_checks state_status
  local -a pipeline_status
  if ! pw_continue_prepare "$NAME" "$CHECKS"; then return 2; fi
  if ! pw_report_init "$NAME"; then pw_continue_cleanup; return 2; fi
  total_checks=$(printf '%s\\n' $CHECKS | sort -u | grep -c .)
''')
rep('lib/_runner.sh',
'''  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true
  RES=$(tmpf) || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_report_remove_empty; return 2; }
''',
'''  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true
  if ! pw_continue_capture_scope; then _pw_run_state_warn; fi
  RES=$(tmpf) || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_continue_cleanup; pw_report_remove_empty; return 2; }
''')
rep('lib/_runner.sh',
'''    if ! php "$PRESSWARDEN_DIR/lib/suite-summary.php" "$RES" "$json" "$NAME" "$PRESSWARDEN_VERSION" "$ROOT" "$(count_sites)" "$(count_domains)" "$rc" "$LOG" "${SUITE_DISCOVERY_INCOMPLETE:-0}"; then
''',
'''    if ! php "$PRESSWARDEN_DIR/lib/suite-summary.php" "$RES" "$json" "$NAME" "$PRESSWARDEN_VERSION" "$ROOT" "$(count_sites)" "$(count_domains)" "$rc" "$LOG" "${SUITE_DISCOVERY_INCOMPLETE:-0}" "${PRESSWARDEN_CONTINUE_FROM:-}" "${PW_CONTINUE_CARRIED:-0}"; then
''')
rep('lib/_runner.sh',
'''  rm -f "$PW_RUN_STATE_ERROR_FILE"
  return "$rc"
}
''',
'''  rm -f "$PW_RUN_STATE_ERROR_FILE"
  pw_continue_cleanup
  return "$rc"
}
''')

# JSON summaries are explicit about carried evidence.
rep('lib/suite-summary.php',
'''if ($argc !== 11) { fwrite(STDERR, "Invalid suite summary arguments\\n"); exit(2); }
[$res, $out, $suite, $version, $root, $sites, $domains, $rc, $log, $discovery] = array_slice($argv, 1);
''',
'''if ($argc !== 11 && $argc !== 13) { fwrite(STDERR, "Invalid suite summary arguments\\n"); exit(2); }
[$res, $out, $suite, $version, $root, $sites, $domains, $rc, $log, $discovery] = array_slice($argv, 1, 10);
$continuedFrom = $argc === 13 ? (string)$argv[11] : '';
$checksCarried = $argc === 13 ? (int)$argv[12] : 0;
''')
rep('lib/suite-summary.php',
'''    'discovery_status'=>$discoveryIncomplete ? 'incomplete' : 'complete', 'checks'=>$checks];
''',
'''    'discovery_status'=>$discoveryIncomplete ? 'incomplete' : 'complete', 'checks'=>$checks];
if ($continuedFrom !== '') { $data['continued_from']=$continuedFrom; $data['checks_carried']=$checksCarried; }
''')

# CLI: continue latest or named interrupted run, restoring its narrow exclusions/depth.
rep('presswarden',
'''  ./presswarden last-run               Show the most recently started suite run state
  ./presswarden run-status [RUN_ID]    Show latest or a specific suite run state
''',
'''  ./presswarden last-run               Show the most recently started suite run state
  ./presswarden run-status [RUN_ID]    Show latest or a specific suite run state
  ./presswarden continue [RUN_ID]      Safely continue an interrupted suite from its first unfinished check
''')
rep('presswarden',
'''  last-run|run-status)
''',
'''  continue|resume)
    [ "$#" -le 1 ] || { printf 'Usage: ./presswarden continue [RUN_ID]\\n' >&2; exit 2; }
    command -v php >/dev/null 2>&1 || { printf 'Safe continuation requires PHP CLI.\\n' >&2; exit 2; }
    if [ "$PRESSWARDEN_PORTABLE" = 1 ]; then state="${PRESSWARDEN_STATE_DIR:-$PRESSWARDEN_DIR/var}"; else state="${PRESSWARDEN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/presswarden}"; fi
    plan=$(php "$PRESSWARDEN_DIR/lib/run-continuation.php" plan "$state/runs" "${1:-latest}" "$VERSION") || exit 2
    parent=''; suite=''; root=''; depth=''; start=''; index=''; total=''; carried=''; _PW_TARGET_EXCLUSIONS=''
    while IFS=$'\\t' read -r key value; do
      case "$key" in
        RUN) parent="$value" ;; SUITE) suite="$value" ;; ROOT) root="$value" ;; DEPTH) depth="$value" ;;
        START) start="$value" ;; INDEX) index="$value" ;; TOTAL) total="$value" ;; CARRY) carried="$value" ;;
        EXCLUDE) _PW_TARGET_EXCLUSIONS+="$value"$'\\n' ;;
      esac
    done <<< "$plan"
    [ -n "$parent" ] && [ -n "$suite" ] && [ -n "$root" ] && [ -n "$start" ] || { printf 'INCOMPLETE: continuation plan is invalid.\\n' >&2; exit 2; }
    ROOT="$root"; PRESSWARDEN_DISCOVERY_DEPTH="$depth"; PRESSWARDEN_CONTINUE_FROM="$parent"
    export ROOT PRESSWARDEN_DIR PRESSWARDEN_DISCOVERY_DEPTH PRESSWARDEN_CONTINUE_FROM _PW_TARGET_EXCLUSIONS
    printf 'Continuing %s run %s from [%s/%s] %s; carrying %s completed check(s).\\n' "$suite" "$parent" "$index" "$total" "$start" "$carried" >&2
    case "$suite" in
      fast|full|incident|db) exec bash "$PRESSWARDEN_DIR/suites/$suite.sh" ;;
      intel) exec bash "$PRESSWARDEN_DIR/suites/intel.sh" ;;
      inspect-php) exec bash "$PRESSWARDEN_DIR/suites/inspect.sh" php ;;
      inspect-js) exec bash "$PRESSWARDEN_DIR/suites/inspect.sh" js ;;
      inspect-db) exec bash "$PRESSWARDEN_DIR/suites/inspect.sh" db ;;
      inspect-runtime) exec bash "$PRESSWARDEN_DIR/suites/inspect.sh" runtime ;;
      *) printf 'INCOMPLETE: suite is not continuation-enabled.\\n' >&2; exit 2 ;;
    esac
    ;;
  last-run|run-status)
''')

# Version/docs.
(root/'VERSION').write_text('1.1.17\n')
rep('README.md','version-1.1.16-2ea44f','version-1.1.17-2ea44f')
rep('README.md',
'''| `./presswarden last-run` | See whether the latest suite completed, was incomplete, or was interrupted and where it stopped |
''',
'''| `./presswarden last-run` | See whether the latest suite completed, was incomplete, or was interrupted and where it stopped |
| `./presswarden continue` | Safely continue an interrupted/failed suite from its first unfinished check after scope/version verification |
''')
rep('README.md',
'''Automatic resume is intentionally not provided yet. See [suite run-state details](docs/RUN-STATE.md).
''',
'''Safe continuation is available with `./presswarden continue [RUN_ID]`. It carries only a completed prefix from the same PressWarden version and exact rediscovered scope, reruns the interrupted check from the beginning, and starts a new linked audit summary. Runs created before 1.1.17 do not contain the required scope snapshot. Automatic database maintenance is never replayed if it was the interrupted check. See [safe continuation](docs/CONTINUATION.md) and [suite run-state details](docs/RUN-STATE.md).
''')

p=root/'CHANGELOG.md'; s=p.read_text(); marker='# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n'
entry='''## 1.1.17 — 2026-09-11\n\nSafe continuation of interrupted suite scans.\n\n- Add `continue [RUN_ID]` with `resume` as a compatibility alias. A continuation starts a new run, carries only the parent's completed clean/findings/skipped prefix, reruns the first unfinished check from the beginning, and executes the remaining original plan.\n- Capture a private exact scope snapshot for every new suite run: selected WordPress roots, target-specific exclusions, root and discovery depth. Continuation fresh-discovers sites and refuses when the PressWarden version, suite, check plan, or scope differs. Pre-1.1.17 runs intentionally cannot be continued because they lack this compatibility evidence.\n- Preserve prior findings in the combined continuation summary and expose `continued_from` / `checks_carried` in JSON. Carried checks are visibly labeled in the terminal and are not re-executed.\n- Refuse continuation when the interrupted step is `wp-db-maintenance`, because that check performs automatic database writes and an interrupted write-capable step must not be blindly replayed. Other interrupted checks are rerun from current live state; any interactive remediation requires fresh confirmation/revalidation.\n- Allow continuation only for INTERRUPTED/FAILED or provably abandoned RUNNING records. Completed or ordinary incomplete runs are not treated as resumable.\n- Add scope mismatch, version/check-plan mismatch, old-run refusal, DB-maintenance refusal, privacy and PHP 7.4 regressions. No malware thresholds, quarantine guarantees, baseline semantics or updater behavior are weakened.\n\n'''
if marker not in s: raise SystemExit('changelog marker missing')
p.write_text(s.replace(marker,marker+entry,1))

# Existing run-state CI gains continuation coverage.
rep('.github/workflows/run-state-quality.yml',
'''          bash tests/run-state.sh
          bash tests/runtime-reliability.sh
          bash tests/suite-progress.sh
''',
'''          bash tests/run-state.sh
          bash tests/run-continuation.sh
          bash tests/runtime-reliability.sh
          bash tests/suite-progress.sh
''')
rep('.github/workflows/run-state-quality.yml',
'''          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli php -l lib/run-state.php >/dev/null
          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli bash tests/run-state.sh
''',
'''          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli php -l lib/run-state.php >/dev/null
          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli php -l lib/run-continuation.php >/dev/null
          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli bash tests/run-state.sh
          docker run --rm -v "$PWD:/work" -w /work php:7.4-cli bash tests/run-continuation.sh
''')
