from pathlib import Path
import os, subprocess
ROOT=Path.cwd()
OURS='2cbb73bd408f2aa1fad2a4c0c5da8f8864e3b8ed'
MAIN='3abee36f7879dbd5dc41701a6d6826bd70189c24'
def read(ref,path):
    local=os.getenv('PW_RECONCILE_'+('OURS' if ref==OURS else 'MAIN'))
    return (Path(local)/path).read_text() if local else subprocess.check_output(['git','show',ref+':'+path],text=True)
def write(path,text):
    p=ROOT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
def rep(s,a,b):
    assert a in s,a[:100]
    return s.replace(a,b)
# Keep concurrent continuation protection and its regression/documentation changes.
for f in ['lib/run-continuation.php','tests/run-continuation.sh','docs/CONTINUATION.md','docs/DATABASE-SCANNING.md']:
    write(f,read(MAIN,f))
# All other previously tested source changes remain; no main-only source changes are dropped.
write('VERSION','1.1.23\n')
s=read(OURS,'CHANGELOG.md'); new=s.split('## 1.1.22',1)[1].split('## 1.1.21',1)[0]
new='## 1.1.23'+new
new=new.replace('Keep integrated multisite cleanup explicitly skipped instead of claiming default-blog cleanup covers a network.', 'Preserve validated multisite enumeration from 1.1.22 and revalidate every blog before dispatch.')
# Keep the complete concurrent 1.1.22 release history rather than overwrite it.
m=read(MAIN,'CHANGELOG.md'); at=m.index('## 1.1.22');write('CHANGELOG.md',m[:at]+new+m[at:])
s=read(OURS,'README.md').replace('version-1.1.22','version-1.1.23')
s=s.replace('Automatic database maintenance is never replayed', 'Automatic LiteSpeed or native database maintenance is never replayed')
write('README.md',s)
# Preserve explicit legacy opt-out in integrated maintenance.
s=read(OURS,'checks/wp-db-maintenance.sh')
s=rep(s,"  PW_DB_LS_ENABLED=0",'''  # The 1.1.22 opt-out remains authoritative for integrated maintenance.
  case "${PRESSWARDEN_LITESPEED_DB_MAINTENANCE:-}" in
    0|false|FALSE|no|NO|off|OFF) policy=off ;;
  esac
  PW_DB_LS_ENABLED=0''')
s=rep(s,'if [ "$state" = READY ] && [[ "$detail" != multisite* ]]; then','if [ "$state" = READY ]; then')
s=rep(s,'pw_lsdb_run "$s" optimize_all > "$lsout" 2>&1; rc=$?; elapsed=$((SECONDS-started))','pw_lsdb_run_all "$s" "$lsout"; rc=$?; elapsed=$((SECONDS-started))')
s=rep(s,"            printf '      ✓ LITESPEED DB OPTIMIZED • %ss • native OPTIMIZE not repeated\\n' \"$elapsed\"", "            printf '      ✓ LITESPEED DB OPTIMIZED • %ss • %s/%s blog scopes • native OPTIMIZE not repeated\\n' \"$elapsed\" \"$LSDB_RUN_BLOG_DONE\" \"$LSDB_RUN_BLOG_TOTAL\"")
s=rep(s,"        elif [ \"$state\" = READY ]; then\n          printf '      - LITESPEED SKIP • multisite needs an explicit --blog=ID; native network-table maintenance retained\\n'\n",'')
write('checks/wp-db-maintenance.sh',s)
# Shared adapter retains whole-network cleanup from concurrent main, with strict validation.
s=read(OURS,'lib/litespeed-db.sh')
s=rep(s,'local site="$1" action="${2:-optimize_all}"\n  if !', 'local site="$1" action="${2:-optimize_all}" ids count\n  if !')
s=rep(s,"    printf 'READY\\tmultisite detected; LiteSpeed without blog <id> targets its default blog\\n'",'''    ids=$(pw_lsdb_blog_ids "$site") || { printf 'ERROR\\tmultisite blog-ID inventory failed; no cleanup will be attempted\\n'; return 0; }
    count=$(printf '%s\\n' "$ids" | awk 'NF {n++} END {print n+0}')
    printf 'READY\\tmultisite detected; %s validated blog(s) will be cleaned\\n' "$count"''')
s+='''
# Validate the entire active-blog inventory before the first mutation. A blog is
# validated again by pw_lsdb_run immediately before its individual cleanup.
pw_lsdb_blog_ids() {
  local site="$1" raw id seen='|' result='' count=0
  raw=$(pw_lsdb_builtin "$site" site list --field=blog_id --deleted=0 --archived=0 --spam=0 2>/dev/null) || return 1
  while IFS= read -r id; do
    [[ "$id" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    [[ "$seen" != *"|$id|"* ]] || continue
    pw_lsdb_validate_blog "$site" "$id" || return 1
    seen+="$id|"; result+="$id"$'\\n'; count=$((count+1))
    [ "$count" -le 10000 ] || return 1
  done <<< "$raw"
  [ "$count" -gt 0 ] || return 1
  printf '%s' "$result"
}
'''
m=read(MAIN,'checks/litespeed-db.sh'); runner=m[m.index('# Result globals for one installation.'):m.index("LSDB_PHASE=''")]
runner=rep(runner,'_run_site_optimization() {','pw_lsdb_run_all() {')
runner=rep(runner,'local site="$1" multisite="$2" out="$3" ids blog rc','local site="$1" out="$2" ids blog rc multisite=0\n  pw_lsdb_is_multisite "$site" && multisite=1')
runner=runner.replace('_multisite_blog_ids "$site"','pw_lsdb_blog_ids "$site"')
runner=rep(runner,'(cd "$site" && wp litespeed-database optimize_all blog "$blog")','pw_lsdb_run "$site" optimize_all blog "$blog"')
runner=rep(runner,'(cd "$site" && wp litespeed-database optimize_all)','pw_lsdb_run "$site" optimize_all')
s+=runner;write('lib/litespeed-db.sh',s)
# Retain concurrent standalone/multisite/suite-mode semantics; use the shared native telemetry.
s=m
start=s.index('# Built-in WP-CLI commands');end=s.index('_confirm_optimize()')
s=s[:start]+'''# Shared command contract and native-connection allocation measurements.
. "$PRESSWARDEN_DIR/lib/litespeed-db.sh"
_preflight_site() { pw_lsdb_preflight "$@"; }
_db_size_bytes() { pw_lsdb_size_bytes "$@"; }
_format_bytes() { pw_lsdb_format_bytes "$@"; }
_show_command_output() { pw_lsdb_show_output "$@"; }

'''+s[end:]
start=s.index('# Result globals for one installation.');end=s.index("LSDB_PHASE=''")
s=s[:start]+'''_run_site_optimization() { pw_lsdb_run_all "$1" "$3"; }

'''+s[end:]
s=s.replace('no databases were changed.', 'no LiteSpeed cleanup was started.')
s=s.replace('installations and multisite blogs already completed remain optimized.', 'completed sites/blogs remain optimized; the current blog may be partially cleaned. No rollback is implied.')
s=s.replace('    row=$(_preflight_site "$site")','    printf "  Preflight [%s/%s] %s ...\\n" "$idx" "$total" "$label"\n    row=$(_preflight_site "$site")')
s=s.replace('    before=$(_db_size_bytes "$site" 2>/dev/null || true)\n    out=$(tmpf)', '    printf "  Optimizing [%s/%s] %s ...\\n" "$exec_idx" "$exec_total" "$label"\n    before=\'\'; after=\'\'\n    [ "$is_multi" = 1 ] || before=$(_db_size_bytes "$site" 2>/dev/null || true)\n    out=$(tmpf) || return 2')
s=s.replace('      after=$(_db_size_bytes "$site" 2>/dev/null || true)','      [ "$is_multi" = 1 ] || after=$(_db_size_bytes "$site" 2>/dev/null || true)')
s=s.replace("  printf '\\nLiteSpeed database optimization complete.\\n'", '''  if [ "$preflight_failed" -eq 0 ] && [ "$failed" -eq 0 ]; then
    printf '\\nLiteSpeed database optimization complete.\\n'
  else
    printf '\\nLiteSpeed database optimization INCOMPLETE; see failed sites above.\\n'
  fi''')
write('checks/litespeed-db.sh',s)
# Documentation on the reconciled safety/compatibility behavior.
s=read(OURS,'docs/LITESPEED-DATABASE.md')
s += '''\n## Compatibility with 1.1.22\n\nThe `PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0` suite opt-out remains supported. In 1.1.23 the cleanup runs inside native maintenance after table health checks, rather than as a separate preceding suite step. `PRESSWARDEN_DB_LITESPEED=ask|on|off` controls consent; `ask` is the default. An explicit legacy opt-out overrides this policy.\n\nWhole-network cleanup from 1.1.22 is retained: active blog IDs are enumerated and fully validated before the first cleanup, then revalidated before each `optimize_all blog ID`. Partial failures report the completed/failed blog scope; no network-wide success is claimed. Integrated cleanup uses the same path. Allocation statistics remain omitted for multisite.\n'''
s=s.replace('Multisite is skipped during integrated cleanup; use the explicit blog-targeted command below instead.', 'Multisite uses validated active-blog enumeration; explicit blog targeting is also available.')
write('docs/LITESPEED-DATABASE.md',s)
s=read(OURS,'docs/LITESPEED.md');s+='\nSince 1.1.23, default database optimization delegates to the shared runner, including validated active-blog enumeration for multisite. The old suite opt-out is preserved.\n';write('docs/LITESPEED.md',s)
s=read(OURS,'config/config.example');s+='\n# Compatibility: an explicit PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0 still disables integrated LiteSpeed cleanup.\n';write('config/config.example',s)
# Preserve concurrent multisite/suite-mode tests, extend their fake WP CLI for native telemetry/validation.
s=read(MAIN,'tests/litespeed-db.sh')
s=rep(s,'  db)\n', '''  eval-file)
    case "${2:-}" in
      */lib/db-size.php)
        [ ! -f "$p/.size-fail" ] || exit 31
        if [ -f "$p/.optimized" ]; then printf 'PWDBSIZE1\\t900000\\n'; else printf 'PWDBSIZE1\\t1000000\\n'; fi ;;
      */lib/db-blog.php) [[ "${3:-}" =~ ^[1-9][0-9]*$ ]] && printf 'PWDBBLOG1\\t%s\\n' "$3" ;;
      *) exit 88 ;;
    esac ;;
  db)
''')
# Existing literal checks remain aligned with retained main behavior.
write('tests/litespeed-db.sh',s)
# Keep strengthened umbrella tests from our review; active network inventory needs a fake.
s=read(OURS,'tests/litespeed-full-cli.sh')
# No changes needed: the database status is tested on single sites; explicit blog uses its own validator.
write('tests/litespeed-full-cli.sh',s)
s=read(OURS,'tests/db-maintenance-runtime.sh')
s=rep(s,'  eval-file)\n', '''  site) printf '1\\n2\\n' ;;
  eval-file)
    if [[ "${args[1]}" == */db-blog.php ]]; then printf 'PWDBBLOG1\\t%s\\n' "${args[2]}"; exit 0; fi
''')
s=s.replace("grep -q 'multisite needs an explicit' \"$T/out\"", "grep -q '2/2 blog scopes' \"$T/out\"")
write('tests/db-maintenance-runtime.sh',s)
print('Reconciled source from exact main and tested feature snapshots.')
s=(ROOT/'tests/db-maintenance-runtime.sh').read_text().replace('for mode in absent inactive multisite; do','for mode in absent inactive; do')
s=s.replace('run_case missingcli on 2', '''run_case multisite on 0
[ "$(grep -c '^litespeed$' "$site/.trace")" = 2 ]
! grep -q '^optimize$' "$site/.trace"
grep -q '2/2 blog scopes' "$T/out"
PRESSWARDEN_LITESPEED_DB_MAINTENANCE=0 run_case clean on 0
! grep -q '^litespeed$' "$site/.trace"; grep -q '^optimize$' "$site/.trace"
run_case missingcli on 2''')
write('tests/db-maintenance-runtime.sh',s)
s=(ROOT/'tests/litespeed-db.sh').read_text().replace('grep -q \'Measured database size (1 installation(s))\' "$T/multisite-optimize"','! grep -q \'Measured database size\' "$T/multisite-optimize"\ngrep -q \'database size unavailable\' "$T/multisite-optimize"')
s=s.replace("grep -q 'CHECKS=.*litespeed-db wp-db-maintenance'", "grep -q 'CHECKS=.*wp-db-maintenance'")
s=s.replace("grep -q 'PW_LITESPEED_DB_SUITE=1'", "! grep -q 'CHECKS=.*litespeed-db wp-db-maintenance'")
write('tests/litespeed-db.sh',s)
s=(ROOT/'docs/LITESPEED-DATABASE.md').read_text().replace('Integrated DB maintenance (1.1.22+)', 'Integrated DB maintenance (1.1.23+)')
s=s.replace('Integrated DB maintenance skips LiteSpeed content cleanup for multisite rather than pretending one default-blog invocation cleans the network. Native network-prefixed table maintenance remains available. The standalone default-blog optimizer retains a prominent multisite warning and omits network-size savings.', 'Integrated and standalone optimization enumerate active multisite blogs, validate the entire list before any cleanup, and pass each blog ID explicitly to LiteSpeed. A partial failure is not network-wide success. Native maintenance uses the network base prefix; allocation statistics are omitted for multisite.')
write('docs/LITESPEED-DATABASE.md',s)
s=(ROOT/'README.md').read_text().replace('Integrated cleanup skips multisite; explicit blog actions validate a real active blog before dispatch.', 'Integrated and standalone cleanup validate the complete active multisite blog list before cleanup, then revalidate each blog before dispatch. Explicit single-blog actions remain available.')
write('README.md',s)
