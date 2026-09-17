from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path, old, new):
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:80]!r}")
    write(path, text.replace(old, new, 1))


def replace_section(path, start, end, new):
    text = read(path)
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"{path}: start marker not found: {start!r}")
    j = text.find(end, i + len(start))
    if j < 0:
        raise SystemExit(f"{path}: end marker not found: {end!r}")
    write(path, text[:i] + new + text[j:])


# ---------------------------------------------------------------------------
# PressWarden CLI: normalize LiteSpeed targets before the lower-level command
# parser sees them, and keep syntax errors concise/actionable.
# ---------------------------------------------------------------------------
replace_once(
    "presswarden",
    "  ./presswarden litespeed-db status [target]    Show LiteSpeed database cleanup availability\n"
    "  ./presswarden litespeed-db optimize [target]  Run LiteSpeed Cache optimize_all cleanup\n"
    "  ./presswarden litespeed AREA ACTION ... --target SITE  Full LiteSpeed Cache CLI management\n",
    "  ./presswarden litespeed-db status [target|--target target]    Show verified LiteSpeed database status\n"
    "  ./presswarden litespeed-db optimize [target|--target target]  Run verified LiteSpeed database maintenance\n"
    "  ./presswarden litespeed AREA ACTION ... [target|--target target]  Full LiteSpeed Cache CLI management\n",
)

new_litespeed = r'''  litespeed)
    ls_target=''
    ls_args=()
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --target|--site)
          [ "$#" -ge 2 ] || { printf '%s requires a website, directory, or all.\n' "$1" >&2; exit 2; }
          [ -z "$ls_target" ] || { printf 'LiteSpeed target was supplied more than once. Use one positional target or one --target/--site value.\n' >&2; exit 2; }
          ls_target="$2"; shift 2 ;;
        --target=*|--site=*)
          [ -z "$ls_target" ] || { printf 'LiteSpeed target was supplied more than once. Use one positional target or one --target/--site value.\n' >&2; exit 2; }
          ls_target=${1#*=}; [ -n "$ls_target" ] || { printf 'LiteSpeed target cannot be empty.\n' >&2; exit 2; }; shift ;;
        *) ls_args+=("$1"); shift ;;
      esac
    done

    # LiteSpeed database actions have no ordinary positional operands after the
    # action name (only optional --blog=ID), so PressWarden can safely accept the
    # same positional website target used by the rest of the CLI.
    if [ "${ls_args[0]:-}" = database ] || [ "${ls_args[0]:-}" = db ]; then
      ls_db_area="${ls_args[0]}"
      ls_db_action="${ls_args[1]:-status}"
      ls_db_known=0
      case "$ls_db_action" in
        status|clear-posts|clear_posts|clear-comments|clear_comments|clear-trackbacks|clear_trackbacks|clear-transients|clear_transients|optimize-tables|optimize_tables|optimize-all|optimize_all|optimize) ls_db_known=1 ;;
      esac

      # `presswarden litespeed database example.com` means status for that site.
      if [ "$ls_db_known" -eq 0 ] && [ -z "$ls_target" ]; then
        case "$ls_db_action" in
          all|*.*|*/*|.|..|~/*)
            ls_target="$ls_db_action"
            ls_db_action=status
            ls_args=("$ls_db_area" "$ls_db_action")
            ls_db_known=1
            ;;
        esac
      fi

      if [ "$ls_db_known" -eq 1 ]; then
        ls_db_rest=()
        ls_i=2
        while [ "$ls_i" -lt "${#ls_args[@]}" ]; do
          ls_arg="${ls_args[$ls_i]}"
          case "$ls_arg" in
            --blog=*) ls_db_rest+=("$ls_arg") ;;
            --all|--*.*|--*/*)
              ls_bad_target=${ls_arg#--}
              printf 'Invalid PressWarden target syntax: %s\n' "$ls_arg" >&2
              printf 'Use one of these instead:\n' >&2
              printf '  ./presswarden litespeed database %s %s\n' "$ls_db_action" "$ls_bad_target" >&2
              printf '  ./presswarden litespeed database %s --target %s\n' "$ls_db_action" "$ls_bad_target" >&2
              exit 2
              ;;
            --*) ls_db_rest+=("$ls_arg") ;;
            *)
              [ -z "$ls_target" ] || { printf 'LiteSpeed database target was supplied more than once. Use one website/directory/all target.\n' >&2; exit 2; }
              ls_target="$ls_arg"
              ;;
          esac
          ls_i=$((ls_i+1))
        done
        ls_args=("$ls_db_area" "$ls_db_action" "${ls_db_rest[@]}")
      fi
    fi

    if [ -n "$ls_target" ]; then select_target "$ls_target" || exit 2; else select_target || exit 2; fi
    exec bash "$PRESSWARDEN_DIR/checks/litespeed.sh" "${ls_args[@]}"
    ;;
'''
replace_section("presswarden", "  litespeed)\n", "  litespeed-db)\n", new_litespeed)

new_litespeed_db = r'''  litespeed-db)
    action="${1:-status}"; [ "$#" -gt 0 ] && shift || true
    case "$action" in
      status|optimize) : ;;
      optimize-all|optimize_all) action=optimize ;;
      *) printf 'PressWarden LiteSpeed DB action must be status or optimize.\n' >&2; printf 'Examples:\n  ./presswarden litespeed-db status example.com\n  ./presswarden litespeed-db optimize example.com\n' >&2; exit 2 ;;
    esac
    lsdb_target=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --target|--site)
          [ "$#" -ge 2 ] || { printf '%s requires a website, directory, or all.\n' "$1" >&2; exit 2; }
          [ -z "$lsdb_target" ] || { printf 'LiteSpeed DB target was supplied more than once.\n' >&2; exit 2; }
          lsdb_target="$2"; shift 2 ;;
        --target=*|--site=*)
          [ -z "$lsdb_target" ] || { printf 'LiteSpeed DB target was supplied more than once.\n' >&2; exit 2; }
          lsdb_target=${1#*=}; [ -n "$lsdb_target" ] || { printf 'LiteSpeed DB target cannot be empty.\n' >&2; exit 2; }; shift ;;
        --all|--*.*|--*/*)
          lsdb_bad=${1#--}
          printf 'Invalid PressWarden target syntax: %s\n' "$1" >&2
          printf 'Use one of these instead:\n' >&2
          printf '  ./presswarden litespeed-db %s %s\n' "$action" "$lsdb_bad" >&2
          printf '  ./presswarden litespeed-db %s --target %s\n' "$action" "$lsdb_bad" >&2
          exit 2
          ;;
        --*)
          printf 'Unknown PressWarden litespeed-db option: %s\n' "$1" >&2
          printf 'Use a positional target or --target SITE. Example: ./presswarden litespeed-db %s example.com\n' "$action" >&2
          exit 2
          ;;
        *)
          [ -z "$lsdb_target" ] || { printf 'LiteSpeed DB target was supplied more than once. Use one website, directory, or all.\n' >&2; exit 2; }
          lsdb_target="$1"; shift ;;
      esac
    done
    select_target "$lsdb_target" || exit 2
    exec bash "$PRESSWARDEN_DIR/checks/litespeed-db.sh" "$action"
    ;;
'''
replace_section("presswarden", "  litespeed-db)\n", "  intel)\n", new_litespeed_db)

replace_once(
    "presswarden",
    "  *) printf 'Unknown command: %s\\n\\n' \"$cmd\" >&2; usage >&2; exit 2 ;;\n",
    r'''  database|litespeed-database)
    hint_target=''
    hint_action="${1:-status}"
    for hint_arg in "$@"; do
      case "$hint_arg" in
        --target=*|--site=*) hint_target=${hint_arg#*=} ;;
        --all|--*.*|--*/*) hint_target=${hint_arg#--} ;;
        all|*.*|*/*|.|..|~/*) hint_target="$hint_arg" ;;
      esac
    done
    printf 'PressWarden has no top-level "%s" command.\n' "$cmd" >&2
    printf 'Use PressWarden syntax instead:\n' >&2
    if [ "$hint_action" = status ]; then
      if [ -n "$hint_target" ]; then
        printf '  ./presswarden litespeed-db status %s\n' "$hint_target" >&2
        printf '  ./presswarden litespeed database status --target %s\n' "$hint_target" >&2
      else
        printf '  ./presswarden litespeed-db status [website|directory|all]\n' >&2
        printf '  ./presswarden litespeed database status --target SITE\n' >&2
      fi
    else
      if [ -n "$hint_target" ]; then
        printf '  ./presswarden litespeed-db optimize %s\n' "$hint_target" >&2
        printf '  ./presswarden litespeed database optimize-all --target %s\n' "$hint_target" >&2
        printf '  ./presswarden db %s    # full PressWarden DB security + maintenance suite\n' "$hint_target" >&2
      else
        printf '  ./presswarden litespeed-db optimize [website|directory|all]\n' >&2
        printf '  ./presswarden litespeed database optimize-all --target SITE\n' >&2
        printf '  ./presswarden db [website|directory|all]\n' >&2
      fi
    fi
    exit 2
    ;;
  *)
    printf 'Unknown PressWarden command: %s\n' "$cmd" >&2
    printf 'Run ./presswarden help to see valid PressWarden inputs.\n' >&2
    exit 2
    ;;
''',
)

# Keep lower-level LiteSpeed parse errors concise. Explicit `litespeed help`
# remains the place for the full command matrix.
replace_once(
    "checks/litespeed.sh",
    "fail_usage() { printf '%s\\n\\n' \"$1\" >&2; usage >&2; exit 2; }\n",
    "fail_usage() { printf 'PressWarden LiteSpeed input error: %s\\n' \"$1\" >&2; printf 'Run ./presswarden litespeed help for the full command list.\\n' >&2; exit 2; }\n",
)
replace_once(
    "checks/litespeed.sh",
    "  [ \"$#\" -le 1 ] || fail_usage 'Database action accepts only optional --blog=ID.'\n",
    "  [ \"$#\" -le 1 ] || fail_usage 'Database action accepts only optional --blog=ID after PressWarden target parsing. Select a website with a positional target or --target SITE.'\n",
)

# ---------------------------------------------------------------------------
# Verified LiteSpeed DB: make fleet runs streaming and remove redundant WP-CLI
# bootstraps from every active-site preflight.
# ---------------------------------------------------------------------------
replace_section(
    "checks/litespeed-db.sh",
    "_lscwp_commands_available() {\n",
    "_multisite_blog_ids() {\n",
    r'''_lscwp_commands_available() {
  local site="$1"
  # One family-level probe is enough. The previous implementation requested
  # help for five subcommands per site, causing hundreds of redundant WordPress
  # bootstraps before a fleet run could begin changing the first database.
  (cd "$site" 2>/dev/null && PAGER=cat WP_CLI_PAGER=cat wp help litespeed-database >/dev/null 2>&1)
}

''',
)

replace_section(
    "checks/litespeed-db.sh",
    "_preflight_site() {\n",
    "_confirm_optimize() {\n",
    r'''_preflight_site() {
  local site="$1" ids count
  # Active sites take the fast path: one plugin-active check, one LiteSpeed
  # database-family probe, and multisite detection. Only failures need the
  # extra bootstrap/install calls required to distinguish unavailable states.
  if ! _lscwp_active "$site"; then
    if ! _wp_bootstrap_ok "$site"; then printf 'ERROR\tWordPress/WP-CLI bootstrap failed\n'; return 0; fi
    if ! _lscwp_installed "$site"; then printf 'SKIP\tLiteSpeed Cache is not installed\n'; return 0; fi
    printf 'SKIP\tLiteSpeed Cache is installed but inactive\n'
    return 0
  fi
  if ! _lscwp_commands_available "$site"; then printf 'ERROR\tLiteSpeed database command family is unavailable\n'; return 0; fi
  if _is_multisite "$site"; then
    ids=$(_multisite_blog_ids "$site") || { printf 'ERROR\tmultisite blog-ID inventory failed; no cleanup will be attempted\n'; return 0; }
    count=$(printf '%s\n' "$ids" | awk 'NF { n++ } END { print n+0 }')
    printf 'READY\tmultisite detected; %s validated blog(s)\n' "$count"
  else
    printf 'READY\tLiteSpeed database commands available\n'
  fi
}

''',
)

replace_once(
    "checks/litespeed-db.sh",
    "    printf '\\n  Run verified LiteSpeed database maintenance for %s eligible WordPress installation(s) under %s? [y/N]: ' \"$count\" \"$ROOT\" > /dev/tty\n",
    "    printf '\\n  Run verified LiteSpeed database maintenance across up to %s discovered WordPress installation(s) under %s? Ineligible sites will be skipped. [y/N]: ' \"$count\" \"$ROOT\" > /dev/tty\n",
)

new_optimize = r'''_optimize() {
  local site label row state detail is_multi idx=0 total log retrylog
  local ready=0 unavailable=0 preflight_failed=0 verified=0 already=0 unverified=0 failed=0
  local pair_n=0 pair_before=0 pair_after=0
  local tr=0 to=0 ta=0 tt=0 ts=0 tc=0 tk=0 te=0 tx=0 tb=0
  local dr do_ da dt ds dc dk de dx db
  require_wp; discover_sites; total=${#WP_SITES[@]}
  trap _lsdb_interrupt INT TERM; LSDB_PHASE=preflight
  printf 'LiteSpeed verified database maintenance — %s discovered WordPress installation(s)\n' "$total"
  printf 'Verification: LiteSpeed dashboard counters BEFORE → documented cleanup commands → counters AFTER.\n'
  printf 'Execution: streaming per installation; each site is preflighted and processed immediately.\n'
  if [ "$SUITE_MODE" = 1 ]; then printf 'Mode: DB maintenance suite (before native SQL table maintenance).\n'; fi
  printf '\n'

  _confirm_optimize "$total" || { trap - INT TERM; LSDB_PHASE=''; return 1; }

  # Once fleet processing begins, earlier installations may already have been
  # changed while a later installation is being preflighted. Treat any
  # interruption as an interrupted maintenance pass, never as a no-change event.
  LSDB_PHASE=optimize
  printf '\nProcessing verified LiteSpeed database maintenance sequentially...\n\n'
  for site in "${WP_SITES[@]}"; do
    idx=$((idx+1)); label=$(site_label_from_root "$site")
    printf '[%3d/%3d] %s\n' "$idx" "$total" "$label"

    row=$(_preflight_site "$site"); IFS=$'\t' read -r state detail <<< "$row"
    case "$state" in
      SKIP)
        unavailable=$((unavailable+1))
        printf '    PRECHECK\n      - UNAVAILABLE  %s\n' "$detail"
        printf '    RESULT\n      - SKIPPED  Native PressWarden DB maintenance can still run independently.\n\n'
        continue
        ;;
      ERROR)
        preflight_failed=$((preflight_failed+1))
        printf '    PRECHECK\n      ✖ ERROR  %s\n' "$detail"
        printf '    RESULT\n      ✖ FAILED  LiteSpeed database maintenance did not start for this installation.\n\n'
        continue
        ;;
      READY)
        ready=$((ready+1))
        printf '    PRECHECK\n      ✓ %s\n' "$detail"
        ;;
      *)
        preflight_failed=$((preflight_failed+1))
        printf '    PRECHECK\n      ✖ ERROR  unexpected preflight state\n'
        printf '    RESULT\n      ✖ FAILED  LiteSpeed database maintenance did not start for this installation.\n\n'
        continue
        ;;
    esac

    is_multi=0; [[ "$detail" == multisite* ]] && is_multi=1
    if ! _capture_install_state "$site" "$is_multi"; then
      failed=$((failed+1)); printf '    BEFORE\n      ✖ ERROR  Could not read LiteSpeed dashboard counters. Database was not changed.\n\n'; continue
    fi
    _save_before; _print_state 'BEFORE'
    if ! _state_pending; then
      already=$((already+1)); printf '    RESULT\n      ✓ ALREADY OPTIMIZED  No LiteSpeed database cleanup was required.\n\n'
      if _is_uint "$B_SIZE"; then pair_n=$((pair_n+1)); pair_before=$((pair_before+B_SIZE)); pair_after=$((pair_after+B_SIZE)); fi
      continue
    fi

    log=$(tmpf); : > "$log"; LS_ACTION_TOTAL=0; LS_ACTION_OK=0; LS_ACTION_FAILURES=0; LS_ACTION_BLOGS_DONE=0
    _run_actions "$site" "$is_multi" "$log" all || true
    _print_action_log "$log" 'OPTIMIZING'

    if ! _capture_install_state "$site" "$is_multi"; then
      if [ "$LS_ACTION_FAILURES" -gt 0 ]; then failed=$((failed+1)); printf '    RESULT\n      ✖ FAILED  One or more LiteSpeed commands failed and post-maintenance state could not be verified.\n\n'
      else unverified=$((unverified+1)); printf '    RESULT\n      ⚠ UNVERIFIED  Commands completed, but LiteSpeed database state could not be read afterward.\n\n'; fi
      rm -f "$log"; continue
    fi

    # One bounded targeted pass handles residual counters such as orphaned post
    # meta created by deleting drafts/trash during the first post-data pass.
    if [ "$LS_ACTION_FAILURES" -eq 0 ] && _state_pending; then
      retrylog=$(tmpf); : > "$retrylog"
      _run_actions "$site" "$is_multi" "$retrylog" residual || true
      _print_action_log "$retrylog" 'VERIFYING RESIDUALS'
      rm -f "$retrylog"
      _capture_install_state "$site" "$is_multi" || {
        unverified=$((unverified+1)); printf '    RESULT\n      ⚠ UNVERIFIED  Residual cleanup ran, but final LiteSpeed counters could not be read.\n\n'; rm -f "$log"; continue; }
    fi

    _print_state 'AFTER'
    dr=$(_removed "$B_REV" "$LS_REV"); do_=$(_removed "$B_ORPH" "$LS_ORPH"); da=$(_removed "$B_AUTO" "$LS_AUTO"); dt=$(_removed "$B_TRASH_POST" "$LS_TRASH_POST")
    ds=$(_removed "$B_SPAM" "$LS_SPAM"); dc=$(_removed "$B_TRASH_COMMENT" "$LS_TRASH_COMMENT"); dk=$(_removed "$B_TRACK" "$LS_TRACK")
    de=$(_removed "$B_EXPIRED" "$LS_EXPIRED"); dx=$(_removed "$B_TRANSIENTS" "$LS_TRANSIENTS"); db=$(_removed "$B_TABLES" "$LS_TABLES")
    tr=$((tr+dr)); to=$((to+do_)); ta=$((ta+da)); tt=$((tt+dt)); ts=$((ts+ds)); tc=$((tc+dc)); tk=$((tk+dk)); te=$((te+de)); tx=$((tx+dx)); tb=$((tb+db))
    if _is_uint "$B_SIZE" && _is_uint "$LS_SIZE"; then pair_n=$((pair_n+1)); pair_before=$((pair_before+B_SIZE)); pair_after=$((pair_after+LS_SIZE)); fi

    printf '    CHANGES\n'
    printf '      %-30s %10s\n' 'Post revisions removed:' "$dr"
    printf '      %-30s %10s\n' 'Orphaned post meta removed:' "$do_"
    printf '      %-30s %10s\n' 'Auto drafts removed:' "$da"
    printf '      %-30s %10s\n' 'Trashed posts removed:' "$dt"
    printf '      %-30s %10s\n' 'Spam comments removed:' "$ds"
    printf '      %-30s %10s\n' 'Trashed comments removed:' "$dc"
    printf '      %-30s %10s\n' 'Trackbacks/Pingbacks removed:' "$dk"
    printf '      %-30s %10s\n' 'Expired transient timers removed:' "$de"
    printf '      %-30s %10s\n' 'Transient rows removed:' "$dx"
    printf '      %-30s %10s\n' 'Tables optimized:' "$db"
    if _is_uint "$B_SIZE" && _is_uint "$LS_SIZE"; then
      printf '      %-30s %s → %s' 'Database size:' "$(_format_bytes "$B_SIZE")" "$(_format_bytes "$LS_SIZE")"
      if [ "$B_SIZE" -gt "$LS_SIZE" ]; then printf ' • reduction %s' "$(_format_bytes $((B_SIZE-LS_SIZE)))"; elif [ "$B_SIZE" -lt "$LS_SIZE" ]; then printf ' • increase %s' "$(_format_bytes $((LS_SIZE-B_SIZE)))"; else printf ' • no allocation change'; fi
      printf '\n'
    fi

    if [ "$LS_ACTION_FAILURES" -gt 0 ]; then
      failed=$((failed+1)); printf '    RESULT\n      ✖ FAILED  %s LiteSpeed command(s) failed; final counters are shown above.\n\n' "$LS_ACTION_FAILURES"
    elif _state_pending; then
      unverified=$((unverified+1)); printf '    RESULT\n      ⚠ UNVERIFIED  Commands completed, but one or more LiteSpeed dashboard counters remain non-zero.\n      The site is not reported as optimized because the resulting database state was not fully confirmed.\n\n'
    else
      verified=$((verified+1)); printf '    RESULT\n      ✓ VERIFIED  LiteSpeed database maintenance confirmed; all dashboard counters are zero.\n\n'
    fi
    rm -f "$log"
  done

  trap - INT TERM; LSDB_PHASE=''
  failed=$((failed+preflight_failed))
  printf 'LiteSpeed Database Maintenance Summary\n\n'
  printf '  Websites checked:          %8s\n' "$total"
  printf '  Eligible processed:        %8s\n' "$ready"
  printf '  Optimized + verified:      %8s\n' "$verified"
  printf '  Already optimized:         %8s\n' "$already"
  printf '  LiteSpeed unavailable:     %8s\n' "$unavailable"
  printf '  Unverified:                %8s\n' "$unverified"
  printf '  Failed:                    %8s\n' "$failed"
  if [ "$pair_n" -gt 0 ]; then
    printf '\n  Database before:            %8s\n' "$(_format_bytes "$pair_before")"
    printf '  Database after:             %8s\n' "$(_format_bytes "$pair_after")"
    if [ "$pair_before" -gt "$pair_after" ]; then printf '  Reported reduction:         %8s\n' "$(_format_bytes $((pair_before-pair_after)))"; elif [ "$pair_before" -lt "$pair_after" ]; then printf '  Reported increase:          %8s\n' "$(_format_bytes $((pair_after-pair_before)))"; else printf '  Reported allocation change: %8s\n' '0 B'; fi
    printf '  Size pairs measured:        %8s\n' "$pair_n"
  fi
  printf '\n  Post revisions removed:     %8s\n' "$tr"
  printf '  Orphaned post meta removed: %8s\n' "$to"
  printf '  Auto drafts removed:        %8s\n' "$ta"
  printf '  Trashed posts removed:      %8s\n' "$tt"
  printf '  Spam comments removed:      %8s\n' "$ts"
  printf '  Trashed comments removed:   %8s\n' "$tc"
  printf '  Trackbacks/Pingbacks:       %8s\n' "$tk"
  printf '  Expired transient timers:   %8s\n' "$te"
  printf '  Transient rows removed:     %8s\n' "$tx"
  printf '  Tables optimized:           %8s\n' "$tb"
  printf '\nNote: expired-transient timers are a subset of transient rows, so those two removal figures overlap and must not be added together.\n'
  printf 'Database size is allocation telemetry only; verification is based on LiteSpeed dashboard counters, not size reduction.\n'
  [ "$failed" -eq 0 ] && [ "$unverified" -eq 0 ] || return 2
}

'''
replace_section("checks/litespeed-db.sh", "_optimize() {\n", "case \"$ACTION\" in\n", new_optimize)

# ---------------------------------------------------------------------------
# Regression coverage: fleet execution must actually reach maintenance, avoid
# five help probes/site, and CLI mistakes must receive PressWarden corrections.
# ---------------------------------------------------------------------------
replace_once(
    "tests/litespeed-db.sh",
    "  help)\n    [ \"${2:-}\" = litespeed-database ] || exit 93\n    case \"${3:-}\" in clear_posts|clear_comments|clear_trackbacks|clear_transients|optimize_tables) : ;; *) exit 93 ;; esac\n    [ -f \"$p/.litespeed-active\" ] || exit 94\n    [ ! -f \"$p/.no-litespeed-command\" ] || exit 95\n    ;;\n",
    "  help)\n    [ \"${2:-}\" = litespeed-database ] || exit 93\n    printf '%s\\n' \"${3:-family}\" >> \"$p/.help-calls\"\n    case \"${3:-}\" in ''|clear_posts|clear_comments|clear_trackbacks|clear_transients|optimize_tables) : ;; *) exit 93 ;; esac\n    [ -f \"$p/.litespeed-active\" ] || exit 94\n    [ ! -f \"$p/.no-litespeed-command\" ] || exit 95\n    ;;\n",
)

fleet_test_anchor = "grep -q 'broken.com' \"$T/status\"; grep -q 'ERROR.*bootstrap failed' \"$T/status\"\n\n"
fleet_test = r'''# Fleet optimization must begin maintaining eligible sites immediately instead
# of running a five-subcommand help preflight across the whole fleet first.
rm -f "$T/sites/example.com/public_html/.actions" "$T/sites/example.com/public_html/.help-calls"
set +e
run litespeed-db optimize all > "$T/fleet-optimize" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]  # broken.com remains an honest fleet error
[ -s "$T/sites/example.com/public_html/.actions" ]
grep -q 'Execution: streaming per installation' "$T/fleet-optimize"
grep -q 'example.com' "$T/fleet-optimize"
grep -q '✓ VERIFIED' "$T/fleet-optimize"
grep -q 'other.com' "$T/fleet-optimize"; grep -q 'UNAVAILABLE.*not installed' "$T/fleet-optimize"
grep -q 'broken.com' "$T/fleet-optimize"; grep -q 'ERROR.*bootstrap failed' "$T/fleet-optimize"
grep -q 'Optimized + verified:.*1' "$T/fleet-optimize"
grep -q 'LiteSpeed unavailable:.*1' "$T/fleet-optimize"
grep -q 'Failed:.*1' "$T/fleet-optimize"
help_calls=$(wc -l < "$T/sites/example.com/public_html/.help-calls" 2>/dev/null || printf '0')
[ "${help_calls:-0}" -le 1 ] || { echo "fleet preflight used too many LiteSpeed help probes: $help_calls" >&2; exit 1; }
! grep -q 'Preflight complete:' "$T/fleet-optimize"

# Dedicated command accepts --target, while a mistaken --hostname receives a
# PressWarden correction instead of falling through to site/WP-CLI errors.
run litespeed-db status --target example.com > "$T/status-target" 2>&1
grep -q 'example.com' "$T/status-target"
set +e
run litespeed-db optimize --example.com > "$T/bad-target" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'Invalid PressWarden target syntax: --example.com' "$T/bad-target"
grep -q './presswarden litespeed-db optimize example.com' "$T/bad-target"
! grep -q 'Website not found' "$T/bad-target"

'''
replace_once("tests/litespeed-db.sh", fleet_test_anchor, fleet_test_anchor + fleet_test)

replace_once(
    "tests/litespeed-db.sh",
    "grep -q 'required LiteSpeed database commands are unavailable' \"$T/unavailable\"\n",
    "grep -q 'LiteSpeed database command family is unavailable' \"$T/unavailable\"\n",
)

replace_once(
    "tests/litespeed-full-cli.sh",
    "run_check(){ ROOT=\"$T/sites\" PRESSWARDEN_DIR=\"$REPO\" bash \"$REPO/checks/litespeed.sh\" \"$@\"; }\n",
    "run_check(){ ROOT=\"$T/sites\" PRESSWARDEN_DIR=\"$REPO\" bash \"$REPO/checks/litespeed.sh\" \"$@\"; }\nrun_cli(){ bash \"$REPO/presswarden\" \"$@\"; }\n",
)

cli_tests = r'''
# Top-level PressWarden accepts a positional target for LiteSpeed database
# actions, preserves explicit --target, and gives concise corrections for the
# common mistaken `--hostname` and top-level `database` forms.
rm -f "$T/sites/example.com/public_html/.last-command" "$T/sites/other.com/public_html/.last-command"
run_cli litespeed database optimize-all example.com > "$T/cli-positional" 2>&1
grep -q 'litespeed-database optimize_all' "$T/sites/example.com/public_html/.last-command"
[ ! -f "$T/sites/other.com/public_html/.last-command" ]
rm -f "$T/sites/example.com/public_html/.last-command"
run_cli litespeed database optimize-all --target example.com > "$T/cli-target" 2>&1
grep -q 'litespeed-database optimize_all' "$T/sites/example.com/public_html/.last-command"

set +e
run_cli litespeed database optimize-all --example.com > "$T/cli-bad-target" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'Invalid PressWarden target syntax: --example.com' "$T/cli-bad-target"
grep -q 'litespeed database optimize-all --target example.com' "$T/cli-bad-target"
! grep -q 'Areas and actions:' "$T/cli-bad-target"

set +e
run_cli database optimize-all --example.com > "$T/cli-top-database" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'PressWarden has no top-level "database" command' "$T/cli-top-database"
grep -q 'litespeed-db optimize example.com' "$T/cli-top-database"
! grep -q 'PressWarden v' "$T/cli-top-database"
'''
replace_once(
    "tests/litespeed-full-cli.sh",
    "\nprintf 'Full LiteSpeed CLI management: all documented families/subcommands, redaction, backups, guards and DB invocation PASS\\n'\n",
    cli_tests + "\nprintf 'Full LiteSpeed CLI management: all documented families/subcommands, PressWarden targeting/corrections, redaction, backups, guards and DB invocation PASS\\n'\n",
)

# Documentation/version bookkeeping.
write("VERSION", "1.1.24\n")
replace_once(
    "README.md",
    "![Version](https://img.shields.io/badge/version-1.1.22-2ea44f)",
    "![Version](https://img.shields.io/badge/version-1.1.24-2ea44f)",
)

changelog_insert = r'''## 1.1.24 — 2026-09-17

LiteSpeed fleet throughput and PressWarden-native CLI guidance.

- Change verified LiteSpeed fleet optimization from a whole-fleet preflight followed by execution to streaming per-installation processing, so the first eligible database is measured and maintained immediately after one fleet confirmation.
- Reduce active-site LiteSpeed DB preflight from nine WordPress/WP-CLI bootstraps to three by checking plugin-active state first and probing the database command family once instead of requesting help for five subcommands on every website.
- Preserve full before/after dashboard-counter verification, residual cleanup, multisite coverage, allocation telemetry, and fail-closed VERIFIED/UNVERIFIED/FAILED semantics while making large shared-host fleets practical.
- Accept normal PressWarden positional targets for umbrella LiteSpeed database commands, e.g. `presswarden litespeed database optimize-all example.com`, while continuing to support `--target`/`--site`.
- Add `--target`/`--site` support and `optimize-all` aliasing to the focused `litespeed-db` command. Mistaken forms such as `--example.com` now receive an exact corrected PressWarden command instead of generic site or lower-level usage output.
- Add concise guidance for accidental top-level `database`/`litespeed-database` commands and stop dumping the full command matrix for ordinary LiteSpeed input errors.
- Add fleet-execution and CLI-correction regressions.

## 1.1.23 — 2026-09-16

Verified LiteSpeed database maintenance.

- Replace exit-code-only success with before/after verification using `LiteSpeed\\DB_Optm::db_count()`, the same counters displayed by LiteSpeed Cache > Database > Manage.
- Run documented post/comment/trackback/transient/table command groups separately, perform one bounded residual cleanup pass, and report ALREADY OPTIMIZED, VERIFIED, UNVERIFIED, or FAILED from measured state.
- Aggregate real counter reductions and database-allocation telemetry across single-site and validated multisite installs while keeping size changes informational only.
- Keep verified LiteSpeed cleanup inside the `db` and `full` suites before native SQL maintenance.

'''
replace_once(
    "CHANGELOG.md",
    "# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n",
    "# Changelog\n\nAll notable changes to PressWarden are documented here.\n\n" + changelog_insert,
)

replace_once(
    "docs/LITESPEED-DATABASE.md",
    "`target` follows normal PressWarden targeting: a website name, nested website name, directory, `all`, or the configured fleet when omitted.\n\n",
    "`target` follows normal PressWarden targeting: a website name, nested website name, directory, `all`, or the configured fleet when omitted. The focused command also accepts `--target SITE` / `--site SITE`.\n\n"
    "For the umbrella LiteSpeed database interface, both of these are valid PressWarden forms:\n\n"
    "```bash\npresswarden litespeed database optimize-all example.com\npresswarden litespeed database optimize-all --target example.com\n```\n\n"
    "Do not prefix a website itself with `--` (for example `--example.com`). PressWarden detects that common mistake and prints the corrected command instead of forwarding it to the lower-level parser.\n\n"
    "## Fleet execution\n\n"
    "Fleet maintenance is streaming. After one fleet confirmation, PressWarden preflights, measures, maintains, and verifies each discovered installation immediately before moving to the next one. It does not wait for an expensive whole-fleet preflight before the first database is changed.\n\n"
    "Active-site preflight also probes the LiteSpeed database command family once instead of requesting help for every cleanup subcommand. This substantially reduces redundant WordPress bootstraps on large shared-host fleets while preserving per-site errors and final verification.\n\n",
)

# Remove this one-shot patch helper from the implementation commit.
Path(__file__).unlink()
print("Applied PressWarden 1.1.24 LiteSpeed fleet/CLI fixes.")
