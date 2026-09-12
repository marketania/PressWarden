#!/usr/bin/env python3
from pathlib import Path
import base64, gzip
root=Path(__file__).resolve().parents[1]
import json
PAYLOADS=json.loads((root/'tests/.stage-finding-history-payloads.json').read_text())
for rel,data in PAYLOADS.items():
    data = data + ('=' * (-len(data) % 4))
    p=root/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(gzip.decompress(base64.b64decode(data)))

def replace_once(rel, old, new):
    p=root/rel; s=p.read_text()
    if old not in s: raise SystemExit(f'anchor not found: {rel}: {old[:100]!r}')
    p.write_text(s.replace(old,new,1))

replace_once('lib/_lib.sh',
'# shellcheck source=lib/ui.sh\n. "$_PRESSWARDEN_LIB_DIR/ui.sh"\n# shellcheck source=lib/quarantine.sh\n',
'# shellcheck source=lib/ui.sh\n. "$_PRESSWARDEN_LIB_DIR/ui.sh"\n# shellcheck source=lib/finding-history.sh\n. "$_PRESSWARDEN_LIB_DIR/finding-history.sh"\n# shellcheck source=lib/quarantine.sh\n')

replace_once('lib/remediation.sh',
'  if [ "$n" -eq 0 ]; then\n    printf \'    %s%s✓ CLEAN%s  %s%s%s  %s(%s)%s\\n\' \\\n      "$B" "$G" "$X" "$D" "$clean_msg" "$X" "$D" "$(human_time "$elapsed")" "$X"\n    rm -f "$f"; return 0\n  fi\n\n  if ! _save_details "$f" "$sev"; then pw_report_failure; fi\n',
'  if [ "$n" -eq 0 ]; then\n    printf \'    %s%s✓ CLEAN%s  %s%s%s  %s(%s)%s\\n\' \\\n      "$B" "$G" "$X" "$D" "$clean_msg" "$X" "$D" "$(human_time "$elapsed")" "$X"\n    rm -f "$f"; return 0\n  fi\n\n  pw_history_capture "$f" "$sev" "${CURRENT_SECTION:-$NAME}" "$NAME" || true\n  if ! _save_details "$f" "$sev"; then pw_report_failure; fi\n')

replace_once('lib/_runner.sh',
'  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true\n  if ! pw_continue_capture_scope; then _pw_run_state_warn; fi\n  RES=$(tmpf) || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_continue_cleanup; pw_report_remove_empty; return 2; }\n',
'  pw_run_state_init "$NAME" "$total_checks" "$CHECKS" || true\n  if ! pw_continue_capture_scope; then _pw_run_state_warn; fi\n  pw_history_init || true\n  RES=$(tmpf) || { rm -f "$PW_RUN_STATE_ERROR_FILE"; pw_continue_cleanup; pw_report_remove_empty; return 2; }\n')
replace_once('lib/_runner.sh',
'      printf \'%s|%s|%s|%s\\n\' "$c" "$carry_n" "$carry_st" "$carry_tm" >> "$RES" || return 2\n      pw_run_state_result "$c" "$carry_st" "$carry_n" "$carry_tm" || true\n      continue\n',
'      printf \'%s|%s|%s|%s\\n\' "$c" "$carry_n" "$carry_st" "$carry_tm" >> "$RES" || return 2\n      pw_history_carry_check "${PRESSWARDEN_CONTINUE_FROM:-}" "$c" || true\n      pw_run_state_result "$c" "$carry_st" "$carry_n" "$carry_tm" || true\n      continue\n')
replace_once('lib/_runner.sh',
'  if ! pw_run_state_finish "$state_status" "$rc"; then rc=2; fi\n  printf \'%ssummary log:%s %s\\n\' "$D" "$X" "$LOG"\n',
'  if ! pw_run_state_finish "$state_status" "$rc"; then rc=2; fi\n  pw_history_finalize || true\n  printf \'%ssummary log:%s %s\\n\' "$D" "$X" "$LOG"\n')

replace_once('tests/runtime-reliability.sh',
'. "$PW_TEST_REPO/lib/reports.sh"\nEOF\n',
'. "$PW_TEST_REPO/lib/reports.sh"\npw_history_init() { :; }\npw_history_carry_check() { :; }\npw_history_finalize() { :; }\nEOF\n')

replace_once('presswarden',
'  ./presswarden run-status [RUN_ID]    Show latest or a specific suite run state\n  ./presswarden continue [RUN_ID]      Safely continue an interrupted suite from its first unfinished check\n',
'  ./presswarden run-status [RUN_ID]    Show latest or a specific suite run state\n  ./presswarden history [RUN_ID]       Show NEW/RECURRING/CHANGED/RESOLVED/NOT RECHECKED findings\n  ./presswarden continue [RUN_ID]      Safely continue an interrupted suite from its first unfinished check\n')
replace_once('presswarden',
'  sites)\n    [ "$#" -le 1 ] || { printf \'Usage: ./presswarden sites [directory]\\n\' >&2; exit 2; }\n',
'  history)\n    [ "$#" -le 1 ] || { printf \'Usage: ./presswarden history [RUN_ID]\\n\' >&2; exit 2; }\n    run_id="${1:-}"\n    command -v php >/dev/null 2>&1 || { printf \'Finding-history inspection requires PHP CLI.\\n\' >&2; exit 2; }\n    if [ "$PRESSWARDEN_PORTABLE" = 1 ]; then\n      state="${PRESSWARDEN_STATE_DIR:-$PRESSWARDEN_DIR/var}"\n    else\n      state="${PRESSWARDEN_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/presswarden}"\n    fi\n    exec php "$PRESSWARDEN_DIR/lib/finding-history.php" show "$state/runs" "$run_id"\n    ;;\n  sites)\n    [ "$#" -le 1 ] || { printf \'Usage: ./presswarden sites [directory]\\n\' >&2; exit 2; }\n')

(root/'VERSION').write_text('1.1.19\n')
replace_once('README.md','version-1.1.18-2ea44f','version-1.1.19-2ea44f')
replace_once('README.md',
'- 🧾 **Persistent suite run state** so interrupted SSH scans are not mistaken for completed audits\n',
'- 🧾 **Persistent suite run state** so interrupted SSH scans are not mistaken for completed audits\n- 🧭 **Structured finding history** with NEW, RECURRING, CHANGED, RESOLVED, and fail-closed NOT RECHECKED states\n')
replace_once('README.md',
'| `./presswarden continue` | Safely continue an interrupted/failed suite from its first unfinished check after scope/version verification |\n',
'| `./presswarden continue` | Safely continue an interrupted/failed suite from its first unfinished check after scope/version verification |\n| `./presswarden history` | Compare the latest finalized suite findings with the previous trustworthy same-scope history snapshot |\n')
anchor='A catchable interruption retains partial validated reports but never becomes a completed audit. `SIGKILL` cannot be trapped; when process liveness is available, `run-status` identifies a stale `RUNNING` record as an interrupted/abandoned run rather than inventing completion. Safe continuation is available with `./presswarden continue [RUN_ID]`. It carries only a completed prefix from the same PressWarden version and exact rediscovered scope, reruns the interrupted check from the beginning, and starts a new linked audit summary. Runs created before 1.1.17 do not contain the required scope snapshot. Automatic database maintenance is never replayed if it was the interrupted check. See [safe continuation](docs/CONTINUATION.md) and [suite run-state details](docs/RUN-STATE.md).\n\n---\n'
new='A catchable interruption retains partial validated reports but never becomes a completed audit. `SIGKILL` cannot be trapped; when process liveness is available, `run-status` identifies a stale `RUNNING` record as an interrupted/abandoned run rather than inventing completion. Safe continuation is available with `./presswarden continue [RUN_ID]`. It carries only a completed prefix from the same PressWarden version and exact rediscovered scope, reruns the interrupted check from the beginning, and starts a new linked audit summary. Runs created before 1.1.17 do not contain the required scope snapshot. Automatic database maintenance is never replayed if it was the interrupted check. See [safe continuation](docs/CONTINUATION.md) and [suite run-state details](docs/RUN-STATE.md).\n\n## Finding history\n\nFinalized suite runs now correlate structured security findings with the previous trustworthy same-suite/same-scope snapshot:\n\n```bash\n./presswarden history\n./presswarden history RUN_ID\n```\n\nHistory labels observations as **NEW**, **RECURRING**, **CHANGED**, **RESOLVED**, or **NOT RECHECKED**. These describe PressWarden observations, not compromise or remediation timestamps. A missing prior finding becomes RESOLVED only after complete discovery, internally complete history capture, a successful recheck of its owning check, non-overlapping runs, and a comparable scanner version. Otherwise it remains NOT RECHECKED. Interrupted runs never publish resolution history; continuation carries already-completed observation records into the new linked run. See [finding-history semantics](docs/FINDING-HISTORY.md).\n\n---\n'
replace_once('README.md',anchor,new)

p=root/'CHANGELOG.md'; s=p.read_text(); marker='# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n'
entry='## 1.1.19 — 2026-09-12\n\nStructured finding history with fail-closed resolution semantics.\n\n- Add per-suite structured observation history with NEW, RECURRING, CHANGED, RESOLVED and NOT RECHECKED states. These are scan-observation states, not compromise/remediation timestamps or attacker attribution.\n- Capture issue/review findings centrally before remediation using stable check/rule/site/relative-path identities where possible, bounded fingerprints, controlled database row locators, and digests for generic evidence. Raw generic evidence, database values, credentials, salts and payload bodies are not stored in history reports.\n- Permit RESOLVED only after trustworthy comparable coverage: same suite/scope stream, complete discovery, internally complete finding capture, successful owning-check recheck, non-overlapping runs, and comparable PressWarden version. Skipped/failed/missing checks, capture mismatch, version transition, overlap or incomplete discovery produce NOT RECHECKED instead.\n- Keep prior NOT RECHECKED findings active so a partial run cannot make evidence disappear. History capture-count mismatches fail closed and do not advance the comparison pointer.\n- Integrate safe continuation by copying structured observations for carried completed checks into the new child run. Interrupted/running runs never publish resolution history or advance finalized comparison state.\n- Add read-only `history [RUN_ID]`, private no-replace per-run history JSON, an atomic per-suite/scope pointer serialized with PHP flock, resource bounds, symlink/non-regular refusal and PHP 7.4 regressions.\n- Preserve malware thresholds, verified quarantine, complete-or-refuse baselines, safe continuation, transactional wp-config mutations, updater recovery and shared-host portability.\n\n'
if marker not in s: raise SystemExit('changelog marker missing')
p.write_text(s.replace(marker,marker+entry,1))
