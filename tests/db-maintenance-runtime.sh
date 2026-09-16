#!/usr/bin/env bash
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sites/example.com/public_html" "$T/sites/other.com/public_html"
for s in example.com other.com; do
  p="$T/sites/$s/public_html"; mkdir -p "$p/wp-admin" "$p/wp-includes" "$p/wp-content"
  touch "$p/wp-load.php" "$p/wp-settings.php"
  printf '<?php $wp_version="7.1";\n' > "$p/wp-includes/version.php"
  printf '<?php\n' > "$p/wp-config.php"
done
cat > "$T/bin/wp" <<'WP'
#!/usr/bin/env bash
set -euo pipefail
original=("$@"); args=(); p=''
for a in "$@"; do
  case "$a" in --path=*) p=${a#--path=} ;; --skip-plugins|--skip-themes|--skip-packages|--no-color) ;; *) args+=("$a") ;; esac
done
set -- "${args[@]}"; p=${p:-$PWD}
mode=$(cat "$p/.case" 2>/dev/null || echo clean)
case "$1" in
  core) if [ "${3:-}" = --network ]; then [ "$mode" = multisite ]; else exit 0; fi ;;
  plugin)
    case "$2" in is-installed) [ "$mode" != absent ] ;; is-active) [ "$mode" != inactive ] ;; *) exit 90 ;; esac ;;
  help)
    [ "$2" = litespeed-database ] && [ "${3:-}" = optimize_all ] && [ "$mode" != missingcli ] ;;
  eval-file)
    case "${2##*/}" in
      db-size.php) printf 'PWDBSIZE1\t1000000\n' ;;
      db-maintenance.php)
        a=${PRESSWARDEN_DB_ACTION:?}; printf '%s\n' "$a" >> "$p/.trace"
        [ "$mode" != bootstrap ] || { echo 'DB_PASSWORD=secret-sentinel'; exit 31; }
        [ "$mode" != malformed ] || exit 0
        rc=0
        if [ "$a" = check ] && { [ "$mode" = unrepaired ] || { [ "$mode" = repairable ] && [ ! -f "$p/.repaired" ]; }; }; then
          printf 'PWDBM1\tBAD\twp_posts\ttable error\n'; rc=10
        elif [ "$a" = repair ]; then
          if [ "$mode" = unrepaired ]; then printf 'PWDBM1\tUNRESOLVED\twp_posts\ttable error\n'; rc=10
          else touch "$p/.repaired"; printf 'PWDBM1\tREPAIRED\twp_posts\tOK\n'; fi
        elif [ "$a" = optimize ]; then
          if [ "$mode" = optfail ]; then printf 'PWDBM1\tOPTFAIL\twp_posts\tno success status\n'; rc=10
          else printf 'PWDBM1\tOPTIMIZED\twp_posts\tOK\n'; fi
        fi
        printf 'PWDBM1\tDONE\t%s\t1\n' "$a"; exit "$rc"
        ;;
      *) exit 91 ;;
    esac ;;
  litespeed-database)
    for a in "${original[@]}"; do case "$a" in --*) exit 92 ;; esac; done
    [ "$2" = optimize_all ] || exit 93
    echo litespeed >> "$p/.trace"
    [ "$mode" != lsfail ] || { echo 'Error: secret=never-print-me'; exit 41; }
    echo 'Success: LiteSpeed database optimized.' ;;
  db) echo 'external mysql utility invoked'; exit 94 ;;
  *) exit 95 ;;
esac
WP
chmod +x "$T/bin/wp"
export PATH="$T/bin:$PATH" PRESSWARDEN_DIR="$REPO" PRESSWARDEN_SCAN_ROOT="$T/sites"
export PRESSWARDEN_CONFIG_FILE="$T/no-config" PRESSWARDEN_STATE_DIR="$T/state" PRESSWARDEN_CACHE_DIR="$T/cache"
export PRESSWARDEN_INTERACTIVE=0 PRESSWARDEN_NOCOLOR=1 PRESSWARDEN_PROGRESS=0
site="$T/sites/example.com/public_html"
run_case() {
  local mode="$1" policy="$2" expected="$3" rc
  echo "$mode" > "$site/.case"; rm -f "$site/.trace" "$site/.repaired"
  set +e
  ROOT="$site" PRESSWARDEN_DB_LITESPEED="$policy" bash "$REPO/checks/wp-db-maintenance.sh" > "$T/out" 2>&1
  rc=$?
  set -e
  [ "$rc" = "$expected" ] || { cat "$T/out"; echo "$mode:$policy expected $expected, got $rc" >&2; exit 1; }
  ! grep -qE 'secret-sentinel|never-print-me|external mysql' "$T/out"
  if [ "$expected" = 2 ]; then grep -q INCOMPLETE "$T/out"; ! grep -q '^  CLEAN' "$T/out"; fi
}
run_case clean ask 0
! grep -q litespeed "$site/.trace"; grep -q optimize "$site/.trace"
run_case clean off 0
! grep -q litespeed "$site/.trace"
run_case clean on 0
[ "$(grep -c '^litespeed$' "$site/.trace")" = 1 ]
! grep -q '^optimize$' "$site/.trace"
[ "$(grep -c '^check$' "$site/.trace")" = 2 ]
grep -q 'LITESPEED DB OPTIMIZED' "$T/out"
for mode in absent inactive multisite; do
  run_case "$mode" on 0; ! grep -q litespeed "$site/.trace"; grep -q optimize "$site/.trace"
  grep -q 'LITESPEED SKIP' "$T/out"
done
run_case missingcli on 2
grep -q '^optimize$' "$site/.trace"; ! grep -q '^litespeed$' "$site/.trace"
run_case lsfail on 2
grep -q '^litespeed$' "$site/.trace"; ! grep -q '^optimize$' "$site/.trace"
run_case bootstrap on 2
! grep -Eq '^(litespeed|repair|optimize)$' "$site/.trace"
run_case malformed on 2
! grep -Eq '^(litespeed|repair|optimize)$' "$site/.trace"
run_case unrepaired on 1
grep -q '^repair$' "$site/.trace"; ! grep -Eq '^(litespeed|optimize)$' "$site/.trace"
run_case repairable on 0
grep -q '^repair$' "$site/.trace"; grep -q '^litespeed$' "$site/.trace"
run_case optfail off 2
run_case clean invalid 2
[ ! -f "$site/.trace" ]

# Mixed fleet: one failure must not hide later successful independent sites.
echo lsfail > "$site/.case"; echo clean > "$T/sites/other.com/public_html/.case"
set +e
ROOT="$T/sites" PRESSWARDEN_DB_LITESPEED=on bash "$REPO/checks/wp-db-maintenance.sh" > "$T/fleet" 2>&1
rc=$?; set -e
[ "$rc" = 2 ]; grep -q 'LITESPEED  optimized: 1.*failed: 1' "$T/fleet"
! grep -R -q 'secret-sentinel\|never-print-me' "$T/state/reports"
# Only DB and Full include maintenance; evidence-only suites stay non-cleaning.
grep -q wp-db-maintenance "$REPO/suites/db.sh"
grep -q wp-db-maintenance "$REPO/suites/full.sh"
! grep -Eq 'wp-db-maintenance|litespeed-db' "$REPO/suites/fast.sh" "$REPO/suites/incident.sh"
# A real terminal must prompt once; declining retains native optimization.
echo clean > "$site/.case"
python3 - "$REPO" "$site" <<'PYTERM'
import errno, os, pty, select, signal, sys, time
from pathlib import Path
repo, site = sys.argv[1:]
for answer in (b'n\n', b'y\n'):
    trace = Path(site, '.trace'); trace.unlink(missing_ok=True)
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ, ROOT=site, PRESSWARDEN_INTERACTIVE='1', PRESSWARDEN_DB_LITESPEED='ask')
        os.execvpe('bash', ['bash', repo+'/checks/wp-db-maintenance.sh'], env)
    output = b''; replied = False; deadline = time.monotonic()+20
    try:
        while time.monotonic() < deadline:
            if not select.select([fd], [], [], .1)[0]:
                continue
            try: chunk = os.read(fd, 65536)
            except OSError as e:
                if e.errno == errno.EIO: break
                raise
            if not chunk: break
            output += chunk
            if b'[y/N]:' in output and not replied:
                os.write(fd, answer); replied = True
        else:
            os.killpg(pid, signal.SIGKILL)
            raise AssertionError('interactive maintenance timeout')
    finally:
        os.close(fd)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors='replace')
    assert replied and output.count(b'[y/N]:') == 1
    actions = trace.read_text().splitlines()
    if answer.startswith(b'y'):
        assert actions.count('litespeed') == 1 and 'optimize' not in actions
    else:
        assert 'litespeed' not in actions and actions.count('optimize') == 1
print('Interactive cleanup consent: yes/no terminal cases PASS')
PYTERM
printf 'Native/LiteSpeed maintenance integration, consent, failures, no duplicate optimization and privacy: PASS\n'
