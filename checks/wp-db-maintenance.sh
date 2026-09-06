#!/usr/bin/env bash
# wp-db-maintenance — WordPress database check/conditional repair/optimize/verify.
# Uses WordPress's existing $wpdb connection directly; does NOT require proc_open/proc_close
# and does NOT invoke mysqlcheck or the external mysql client.
NAME=wp-db-maintenance; DESC="database check, conditional repair, optimize, verify — native SQL mode"
SCAN_DOES="Checks database tables through WordPress's existing database connection, repairs only genuine CHECK TABLE failures, optimizes tables, and performs a final verification. Storage engines that do not implement CHECK TABLE are reported informationally instead of treated as corruption."
SCAN_WHY="This avoids WP-CLI's external mysqlcheck dependency and distinguishes unsupported maintenance operations from actual table-health failures."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

_human_bytes() { local b="${1:-0}"; case "$b" in ''|*[!0-9]*) printf 'n/a'; return ;; esac; if [ "$b" -ge 1073741824 ]; then awk -v b="$b" 'BEGIN{printf "%.2f GB", b/1073741824}'; elif [ "$b" -ge 1048576 ]; then awk -v b="$b" 'BEGIN{printf "%.2f MB", b/1048576}'; elif [ "$b" -ge 1024 ]; then awk -v b="$b" 'BEGIN{printf "%.2f KB", b/1024}'; else printf '%s B' "$b"; fi; }

_make_db_helper() {
  local f="$1"
  cat > "$f" <<'PRESSWARDEN_DB_PHP'
<?php
global $wpdb;
$action = getenv('PRESSWARDEN_DB_ACTION');
if (!$action) { fwrite(STDERR, "PRESSWARDEN_DB_ERROR\tmissing action\n"); exit(30); }
function pw_ident($name) { return '`' . str_replace('`', '``', $name) . '`'; }
function pw_clean_msg($value) { $value = preg_replace('/[\r\n\t]+/', ' ', (string)$value); return trim($value); }
function pw_tables($wpdb) { $wpdb->last_error=''; $tables=$wpdb->get_col('SHOW TABLES'); if(!is_array($tables)||$wpdb->last_error){fwrite(STDERR,"PRESSWARDEN_DB_ERROR\tSHOW TABLES failed: ".pw_clean_msg($wpdb->last_error)."\n");exit(31);} return array_values(array_filter($tables,'strlen')); }
function pw_check_unsupported($text) {
    $text = strtolower((string)$text);
    return strpos($text, "doesn't support check") !== false || strpos($text, 'does not support check') !== false || strpos($text, 'not support check') !== false;
}
function pw_check_one($wpdb,$table){
    $wpdb->last_error='';
    $rows=$wpdb->get_results('CHECK TABLE '.pw_ident($table),ARRAY_A);
    if($wpdb->last_error)return ['bad',pw_clean_msg($wpdb->last_error)];
    if(!is_array($rows)||!$rows)return ['bad','CHECK TABLE returned no status'];
    $ok=false;$unsupported=false;$problems=[];$details=[];
    foreach($rows as $row){
        $type=strtolower((string)($row['Msg_type']??$row['msg_type']??''));
        $text=(string)($row['Msg_text']??$row['msg_text']??'');
        $clean=pw_clean_msg($text);
        if($type==='status' && in_array(strtolower(trim($text)),['ok','table is already up to date'],true)){$ok=true;continue;}
        if(pw_check_unsupported($text)){$unsupported=true;$details[]=$clean;continue;}
        if($type==='error'){$problems[]=$clean?:'database reported an error';continue;}
        if($clean!=='')$details[]=$type.': '.$clean;
    }
    if($problems)return ['bad',pw_clean_msg(implode(' | ',$problems))];
    if($ok)return ['ok','OK'];
    if($unsupported)return ['unsupported',pw_clean_msg(implode(' | ',array_unique($details)))?:'storage engine does not support CHECK TABLE'];
    return ['bad',pw_clean_msg(implode(' | ',$details))?:'CHECK TABLE did not return a healthy status'];
}
function pw_sql_result_has_error($rows){if(!is_array($rows))return true;foreach($rows as $row){$type=strtolower((string)($row['Msg_type']??$row['msg_type']??''));if($type==='error')return true;}return false;}
$tables=pw_tables($wpdb);
if($action==='size'){$wpdb->last_error='';$size=$wpdb->get_var("SELECT COALESCE(SUM(data_length + index_length),0) FROM information_schema.tables WHERE table_schema = DATABASE()");if($wpdb->last_error){fwrite(STDERR,"PRESSWARDEN_DB_ERROR\tsize query failed: ".pw_clean_msg($wpdb->last_error)."\n");exit(32);}echo preg_replace('/[^0-9]/','',(string)$size),"\n";exit(0);}
if($action==='check'){$bad=0;foreach($tables as $table){[$state,$msg]=pw_check_one($wpdb,$table);if($state==='bad'){$bad++;echo "BAD\t",pw_clean_msg($table),"\t",pw_clean_msg($msg),"\n";}elseif($state==='unsupported'){echo "SKIP\t",pw_clean_msg($table),"\t",pw_clean_msg($msg),"\n";}}exit($bad?10:0);}
if($action==='repair'){$unresolved=0;foreach($tables as $table){[$state,$before]=pw_check_one($wpdb,$table);if($state!=='bad')continue;$wpdb->last_error='';$rows=$wpdb->get_results('REPAIR TABLE '.pw_ident($table),ARRAY_A);$err=$wpdb->last_error;[$after_state,$after]=pw_check_one($wpdb,$table);if($after_state==='ok')echo "REPAIRED\t",pw_clean_msg($table),"\n";else{$unresolved++;$detail=$err?:$after;if(!$detail&&pw_sql_result_has_error($rows))$detail='REPAIR TABLE reported an error';echo "UNRESOLVED\t",pw_clean_msg($table),"\t",pw_clean_msg($detail?:$before),"\n";}}exit($unresolved?10:0);}
if($action==='optimize'){$failed=0;foreach($tables as $table){$wpdb->last_error='';$rows=$wpdb->get_results('OPTIMIZE TABLE '.pw_ident($table),ARRAY_A);$err=$wpdb->last_error;if($err||pw_sql_result_has_error($rows)){$failed++;echo "OPTFAIL\t",pw_clean_msg($table),"\t",pw_clean_msg($err?:'OPTIMIZE TABLE reported an error'),"\n";}}exit($failed?10:0);}
fwrite(STDERR,"PRESSWARDEN_DB_ERROR\tunknown action\n");exit(33);
PRESSWARDEN_DB_PHP
}
_db_native() { local s="$1" action="$2" helper="$3"; PRESSWARDEN_DB_ACTION="$action" wpq "$s" eval-file "$helper"; }
_db_size_bytes() { local s="$1" helper="$2" out; out=$(_db_native "$s" size "$helper" 2>/dev/null) || return 1; printf '%s\n' "$out" | grep -E '^[0-9]+$' | tail -n 1; }
_show_db_problems() { local out="$1"; printf '%s\n' "$out" | grep -E '^(BAD|UNRESOLVED|OPTFAIL|PRESSWARDEN_DB_ERROR)[[:space:]]' | head -12 | sed -E 's/^(BAD|UNRESOLVED|OPTFAIL|PRESSWARDEN_DB_ERROR)[[:space:]]+/          /; s/[[:space:]]+/ › /' || true; }
_show_db_skips() { local out="$1"; printf '%s\n' "$out" | grep -E '^SKIP[[:space:]]' | head -12 | sed -E 's/^SKIP[[:space:]]+/          /; s/[[:space:]]+/ › /' || true; }
_db_skip_count() { local out="$1" n; n=$(printf '%s\n' "$out" | grep -cE '^SKIP[[:space:]]' 2>/dev/null || true); printf '%s' "${n:-0}"; }

main() {
  require_wp; banner; discover_sites
  local s d out rc before after repaired optimize_failed final_failed runtime_failed repaired_n=0 optimized_n=0 failed_n=0 runtime_failed_n=0 unsupported_n=0 helper skip_n
  helper=$(tmpf); _make_db_helper "$helper"
  sec "Database maintenance" "${#WP_SITES[@]} sites • automatic • native SQL • proc_open not required"
  note "workflow: CHECK TABLE → REPAIR genuine failures only → OPTIMIZE TABLE → FINAL CHECK"
  note "A storage engine that does not implement CHECK TABLE is skipped informationally; unsupported CHECK is not database corruption."
  note "Restricted hosting may keep proc_open/proc_close disabled; this maintenance path does not use them."
  for s in "${WP_SITES[@]}"; do
    d=$(site_domain "$s"); repaired=0; optimize_failed=0; final_failed=0; runtime_failed=0; before=$(_db_size_bytes "$s" "$helper" 2>/dev/null || true)
    printf '\n    %s%s%s%s\n' "$B" "$M" "$d" "$X"
    out=$(_db_native "$s" check "$helper" 2>&1); rc=$?; skip_n=$(_db_skip_count "$out"); unsupported_n=$((unsupported_n+skip_n))
    if [ "$rc" -eq 0 ]; then
      if [ "$skip_n" -gt 0 ]; then printf '      %s✓ CHECK%s      supported tables healthy\n' "$G" "$X"; printf '      %sℹ SKIPPED%s    %s table(s) use a storage engine without CHECK TABLE support\n' "$C" "$X" "$skip_n"; _show_db_skips "$out"; else printf '      %s✓ CHECK%s      healthy\n' "$G" "$X"; fi
    elif [ "$rc" -eq 10 ]; then
      printf '      %s⚠ CHECK%s      genuine table problem detected — attempting SQL repair automatically\n' "$Y" "$X"; _show_db_problems "$out"
      [ "$skip_n" -gt 0 ] && { printf '      %sℹ SKIPPED%s    %s unrelated unsupported CHECK operation(s)\n' "$C" "$X" "$skip_n"; _show_db_skips "$out"; }
      out=$(_db_native "$s" repair "$helper" 2>&1); rc=$?
      if [ "$rc" -eq 0 ]; then repaired=1; repaired_n=$((repaired_n+1)); printf '      %s✓ REPAIR%s     completed for affected table(s)\n' "$G" "$X"
      elif [ "$rc" -eq 10 ]; then printf '      %s⚠ REPAIR%s     one or more genuinely unhealthy tables could not be automatically repaired\n' "$Y" "$X"; _show_db_problems "$out"
      else runtime_failed=1; printf '      %s⚠ ENGINE%s     repair could not run; tooling/bootstrap error, not proof of DB corruption\n' "$Y" "$X"; printf '%s\n' "$out" | grep -v '^$' | head -8 | sed 's/^/          /'; fi
    else runtime_failed=1; printf '      %s⚠ ENGINE%s     CHECK could not run; tooling/bootstrap error, not proof of DB corruption\n' "$Y" "$X"; printf '%s\n' "$out" | grep -v '^$' | head -8 | sed 's/^/          /'; fi
    if [ "$runtime_failed" -eq 0 ]; then out=$(_db_native "$s" optimize "$helper" 2>&1); rc=$?; if [ "$rc" -eq 0 ]; then optimized_n=$((optimized_n+1)); printf '      %s✓ OPTIMIZE%s   completed\n' "$G" "$X"; elif [ "$rc" -eq 10 ]; then optimize_failed=1; printf '      %s⚠ OPTIMIZE%s   one or more tables returned an optimization error\n' "$Y" "$X"; _show_db_problems "$out"; else runtime_failed=1; printf '      %s⚠ ENGINE%s     OPTIMIZE could not run; tooling/bootstrap error\n' "$Y" "$X"; fi; fi
    if [ "$runtime_failed" -eq 0 ]; then
      out=$(_db_native "$s" check "$helper" 2>&1); rc=$?; skip_n=$(_db_skip_count "$out")
      if [ "$rc" -eq 0 ]; then
        if [ "$skip_n" -gt 0 ]; then printf '      %s✓ VERIFY%s     supported tables healthy after maintenance  %s• %s unsupported check(s) skipped%s\n' "$G" "$X" "$D" "$skip_n" "$X"; else printf '      %s✓ VERIFY%s     healthy after maintenance\n' "$G" "$X"; fi
      elif [ "$rc" -eq 10 ]; then final_failed=1; failed_n=$((failed_n+1)); printf '      %s✖ VERIFY%s     a supported table still reports an actual problem\n' "$R" "$X"; _show_db_problems "$out"; [ "$skip_n" -gt 0 ] && _show_db_skips "$out"
      else runtime_failed=1; printf '      %s⚠ ENGINE%s     final verification could not run; DB health is unknown\n' "$Y" "$X"; fi
    fi
    after=$(_db_size_bytes "$s" "$helper" 2>/dev/null || true); if [ -n "$before" ] && [ -n "$after" ]; then printf '      %sℹ SIZE%s       %s → %s' "$C" "$X" "$(_human_bytes "$before")" "$(_human_bytes "$after")"; [ "$before" -gt "$after" ] 2>/dev/null && printf '  %s(saved %s)%s' "$D" "$(_human_bytes $((before-after)))" "$X"; printf '\n'; fi
    if [ "$runtime_failed" -eq 1 ]; then runtime_failed_n=$((runtime_failed_n+1)); flag "$d" "database maintenance engine could not complete; database health not classified"; elif [ "$final_failed" -eq 1 ]; then issue "$d" "supported database table(s) remain unhealthy after maintenance"; elif [ "$optimize_failed" -eq 1 ]; then flag "$d" "supported tables verify clean, but one or more tables could not be optimized"; elif [ "$repaired" -eq 1 ]; then printf '      %s%s✓ RESULT%s    repaired + optimized + verified\n' "$B" "$G" "$X"; else printf '      %s%s✓ RESULT%s    healthy + optimized + verified\n' "$B" "$G" "$X"; fi
  done
  printf '\n    %sSUMMARY%s  repaired: %s%s%s  • optimized: %s%s%s  • unresolved: %s%s%s  • unsupported checks: %s%s%s  • runtime errors: %s%s%s\n' "$B$C" "$X" "$B" "$repaired_n" "$X" "$B" "$optimized_n" "$X" "$B" "$failed_n" "$X" "$B" "$unsupported_n" "$X" "$B" "$runtime_failed_n" "$X"
  note "Unsupported CHECK TABLE operations are informational and are not counted as unhealthy tables."
  note "This script never runs wp db clean, reset, drop, import, or other destructive database commands."
  rm -f "$helper"; finish
}
run_logged wp-db-maintenance
