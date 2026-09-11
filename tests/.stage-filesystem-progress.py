#!/usr/bin/env python3
from pathlib import Path

full = r'''#!/usr/bin/env bash
# filesystem-security-full — exhaustive recursive permission/symlink audit; FULL suite only
NAME=filesystem-security-full; DESC="FULL recursive filesystem permissions + symlink containment"
SCAN_DOES="Recursively checks every WordPress file and directory for world-writable permissions and unsafe symlink targets."
SCAN_WHY="The exhaustive pass finds deeply nested permission weaknesses that the targeted FAST scan intentionally skips."
. "$(cd "$(dirname "$0")/.." && pwd)/lib/_lib.sh"

main() {
  banner
  local L s f mode modes target owner CAND tmp failures label failed_n
  local tree_total tree_done percent world_failed=0 symlink_failed=0

  sec "World-writable files and directories" "FULL recursive scan • mode other-write bit set"
  L=$(tmpf); failures=$(tmpf); : > "$L"; : > "$failures"
  tree_total=${#TREE_ROOTS[@]}; tree_done=0
  pw_progress_init
  pw_progress_draw "World-writable: 0% | 0/$tree_total trees processed" 1
  for s in "${TREE_ROOTS[@]}"; do
    label=$(site_label_from_root "$s")
    percent=0; [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
    pw_progress_draw "World-writable: $percent% | $tree_done/$tree_total trees processed | scanning $label" 1
    tmp=$(tmpf); : > "$tmp"
    if ! find "$s" -xdev \( -type f -o -type d \) -perm -0002 \
      -not -path '*/.private/*' -print > "$tmp" 2>/dev/null; then
      world_failed=1
      printf '%s\n' "$label" >> "$failures"
    fi
    cat "$tmp" >> "$L" || world_failed=1
    rm -f "$tmp"
    tree_done=$((tree_done+1)); percent=0
    [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
  done
  if [ "$world_failed" -ne 0 ]; then
    pw_progress_draw "World-writable: INCOMPLETE | $tree_done/$tree_total trees attempted" 1
  else
    pw_progress_draw "World-writable: 100% | $tree_done/$tree_total trees processed" 1
  fi
  pw_progress_end
  sort -u "$L" -o "$L"
  if [ "$world_failed" -ne 0 ]; then
    PW_CHECK_INCOMPLETE=1
    if [ -s "$L" ]; then
      report "$L" issue "" noaction
    else
      rm -f "$L"
      printf '    %s⚠ INCOMPLETE%s  no world-writable items found in successfully traversed portions\n' "$Y" "$X"
    fi
    failed_n=$(sort -u "$failures" | grep -c . 2>/dev/null || true); failed_n=${failed_n:-0}
    printf '    Recursive permission traversal failed for %s WordPress tree(s); validated findings are retained.\n' "$failed_n"
  else
    report "$L" issue "no world-writable files/directories anywhere in WordPress trees" noaction
  fi
  rm -f "$failures"
  note "Permission findings are configuration posture only; PressWarden never offers generic delete/quarantine for them."

  sec "wp-config.php permission posture" "inventory; group/other WRITE is an alert"
  L=$(tmpf); modes=$(tmpf); : > "$L"; : > "$modes"
  for s in "${SCAN_ROOTS[@]}"; do
    f="$s/wp-config.php"; [ -f "$f" ] || continue
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo unknown)
    printf '%s|%s\n' "$mode" "$(site_domain "$s")" >> "$modes"
    case "$mode" in
      *[2367][0-7]|*[0-7][2367]) printf '%s mode=%s (group/other writable)\n' "$f" "$mode" >> "$L" ;;
    esac
  done
  report "$L" issue "no wp-config.php file is group/other writable" noaction
  printf '    %sℹ MODES%s  ' "$C" "$X"
  cut -d'|' -f1 "$modes" | sort | uniq -c | awk '{printf "%s=%s site(s)  ",$2,$1} END{print ""}'
  note "Mode inventory is informational; shared-host ownership models vary, so read-only differences are not auto-flagged."
  rm -f "$modes"

  sec "Symlinks escaping a WordPress site root" "FULL recursive scan"
  L=$(tmpf); failures=$(tmpf); : > "$L"; : > "$failures"
  tree_total=${#TREE_ROOTS[@]}; tree_done=0
  pw_progress_init
  pw_progress_draw "Symlinks: 0% | 0/$tree_total trees processed" 1
  for s in "${TREE_ROOTS[@]}"; do
    label=$(site_label_from_root "$s")
    percent=0; [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
    pw_progress_draw "Symlinks: $percent% | $tree_done/$tree_total trees processed | scanning $label" 1
    CAND=$(tmpf); : > "$CAND"
    if ! find "$s" -xdev -type l -not -path '*/.private/*' -print > "$CAND" 2>/dev/null; then
      symlink_failed=1
      printf '%s\n' "$label" >> "$failures"
    fi
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      target=$(readlink -f "$f" 2>/dev/null || true); [ -n "$target" ] || continue
      owner=$(_site_root_for_path "$f" 2>/dev/null || true); [ -n "$owner" ] || owner="$s"
      case "$target" in "$owner"|"$owner"/*) : ;; *) printf '%s -> %s\n' "$f" "$target" ;; esac
    done < "$CAND" >> "$L"
    rm -f "$CAND"
    tree_done=$((tree_done+1)); percent=0
    [ "$tree_total" -gt 0 ] && percent=$((tree_done*100/tree_total))
  done
  if [ "$symlink_failed" -ne 0 ]; then
    pw_progress_draw "Symlinks: INCOMPLETE | $tree_done/$tree_total trees attempted" 1
  else
    pw_progress_draw "Symlinks: 100% | $tree_done/$tree_total trees processed" 1
  fi
  pw_progress_end
  sort -u "$L" -o "$L"
  if [ "$symlink_failed" -ne 0 ]; then
    PW_CHECK_INCOMPLETE=1
    if [ -s "$L" ]; then
      report "$L" review "" noaction
    else
      rm -f "$L"
      printf '    %s⚠ INCOMPLETE%s  no escaping symlinks found in successfully traversed portions\n' "$Y" "$X"
    fi
    failed_n=$(sort -u "$failures" | grep -c . 2>/dev/null || true); failed_n=${failed_n:-0}
    printf '    Recursive symlink traversal failed for %s WordPress tree(s); validated findings are retained.\n' "$failed_n"
  else
    report "$L" review "no symlink escapes detected anywhere in WordPress trees" noaction
  fi
  rm -f "$failures"

  finish
}
run_logged filesystem-security-full
'''
Path('checks/filesystem-security-full.sh').write_text(full)

p = Path('checks/filesystem-security.sh')
s = p.read_text()
for old, new in [
    ('report "$L" issue "no world-writable high-risk paths"', 'report "$L" issue "no world-writable high-risk paths" noaction'),
    ('report "$L" issue "no wp-config.php file is group/other writable"', 'report "$L" issue "no wp-config.php file is group/other writable" noaction'),
    ('report "$L" review "no escaping symlinks in targeted high-risk paths"', 'report "$L" review "no escaping symlinks in targeted high-risk paths" noaction'),
]:
    assert old in s, old
    s = s.replace(old, new, 1)
p.write_text(s)

p = Path('lib/remediation.sh')
s = p.read_text()
old = '''  [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] || return 2\n  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || return 0\n'''
new = '''  [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] || return 2\n  [ "${PW_CHECK_INCOMPLETE:-0}" -eq 0 ] || return 2\n  [ "$PRESSWARDEN_INTERACTIVE" != 0 ] || return 0\n'''
assert old in s; s = s.replace(old, new, 1)
old = '''  if [ "${PW_REPORT_FAILED:-0}" -ne 0 ] || [ "${PW_REMEDIATION_FAILED:-0}" -ne 0 ] || [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ]; then col="$Y"; status='INCOMPLETE'\n'''
new = '''  if [ "${PW_REPORT_FAILED:-0}" -ne 0 ] || [ "${PW_REMEDIATION_FAILED:-0}" -ne 0 ] || [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ] || [ "${PW_CHECK_INCOMPLETE:-0}" -ne 0 ]; then col="$Y"; status='INCOMPLETE'\n'''
assert old in s; s = s.replace(old, new, 1)
old = '''  if [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ]; then\n    printf '  Discovery coverage is INCOMPLETE; results above cover validated sites only.\\n'\n  fi\n  _rule\n'''
new = '''  if [ "${PW_DISCOVERY_FAILED:-0}" -ne 0 ]; then\n    printf '  Discovery coverage is INCOMPLETE; results above cover validated sites only.\\n'\n  fi\n  if [ "${PW_CHECK_INCOMPLETE:-0}" -ne 0 ]; then\n    printf '  Check coverage is INCOMPLETE; successful findings above are retained.\\n'\n  fi\n  _rule\n'''
assert old in s; s = s.replace(old, new, 1)
old = '''  [ "${PW_REPORT_FAILED:-0}" -eq 0 ] && [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] && [ "${PW_DISCOVERY_FAILED:-0}" -eq 0 ] || return 2\n'''
new = '''  [ "${PW_REPORT_FAILED:-0}" -eq 0 ] && [ "${PW_REMEDIATION_FAILED:-0}" -eq 0 ] && [ "${PW_DISCOVERY_FAILED:-0}" -eq 0 ] && [ "${PW_CHECK_INCOMPLETE:-0}" -eq 0 ] || return 2\n'''
assert old in s; s = s.replace(old, new, 1)
p.write_text(s)

Path('tests/filesystem-progress.py').write_text(r'''#!/usr/bin/env python3
"""PTY regressions for FULL recursive filesystem progress and fail-closed traversal."""
import errno, fcntl, os, select, signal, struct, subprocess, tempfile, termios, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
checks = 0
def expect(ok, msg):
    global checks
    assert ok, msg
    checks += 1

def terminal(args, env, timeout=20):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 100, 0, 0))
    def setup():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                            env=env, preexec_fn=setup, close_fds=True)
    os.close(slave); out=bytearray(); deadline=time.monotonic()+timeout
    try:
        while True:
            if time.monotonic()>deadline: raise AssertionError('filesystem progress fixture timed out')
            ready,_,_=select.select([master],[],[],0.1)
            if ready:
                try: chunk=os.read(master,65536)
                except OSError as e:
                    if e.errno==errno.EIO: break
                    raise
                if not chunk: break
                out.extend(chunk)
            elif proc.poll() is not None: break
        return proc.wait(timeout=5), out.decode('utf-8', errors='replace')
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=5)
        os.close(master)

with tempfile.TemporaryDirectory(prefix='presswarden-fs-progress-') as td:
    base=Path(td); root=base/'sites'; site=root/'example.invalid'/'public_html'
    for d in ['wp-admin','wp-includes','wp-content']: (site/d).mkdir(parents=True, exist_ok=True)
    (site/'wp-load.php').write_text('<?php // fixture\n')
    (site/'wp-settings.php').write_text('<?php // fixture\n')
    (site/'wp-includes'/'version.php').write_text('<?php $wp_version="7.1";\n')
    world=site/'wp-content'/'world-writable.php'; world.write_text('<?php // permission fixture\n'); world.chmod(0o666)
    bindir=base/'bin'; bindir.mkdir()
    env=dict(os.environ, HOME=str(base/'home'), TERM='xterm', PRESSWARDEN_NOCOLOR='1',
             PRESSWARDEN_CONFIG_FILE=str(base/'no-config'), PRESSWARDEN_STATE_DIR=str(base/'state'),
             PRESSWARDEN_CACHE_DIR=str(base/'cache'), PRESSWARDEN_SCAN_ROOT=str(root), ROOT=str(root),
             PRESSWARDEN_PROGRESS='auto', PRESSWARDEN_INTERACTIVE='1', PATH=str(bindir)+':'+os.environ['PATH'])
    (base/'home').mkdir()

    reports=base/'reports-ok'; e=dict(env, REPORTS=str(reports))
    rc,out=terminal(['bash',str(REPO/'checks/filesystem-security-full.sh')],e)
    expect(rc==1,out)
    expect('World-writable: 0% | 0/1 trees processed' in out,out)
    expect('World-writable: 0% | 0/1 trees processed | scanning example.invalid' in out,out)
    expect('World-writable: 100% | 1/1 trees processed' in out,out)
    expect('Symlinks: 100% | 1/1 trees processed' in out,out)
    expect('ACTION' not in out,'permission/symlink posture offered destructive remediation')
    logs=list(reports.glob('filesystem-security-full-*.log')); expect(bool(logs),'filesystem report missing')
    for log in logs:
        b=log.read_bytes()
        expect(b'World-writable:' not in b and b'Symlinks:' not in b and b'\r' not in b,
               'progress leaked into saved report: '+log.name)

    # Fail only the recursive permission traversal after allowing discovery to complete.
    fw=bindir/'find'
    fw.write_text('#!/usr/bin/env bash\n/usr/bin/find "$@"\nrc=$?\nfor a in "$@"; do [ "$a" != "-perm" ] || exit 1; done\nexit "$rc"\n')
    fw.chmod(0o700)
    reports2=base/'reports-failed'; e2=dict(env, REPORTS=str(reports2), PRESSWARDEN_DISCOVERY_REFRESH='1')
    rc,out=terminal(['bash',str(REPO/'checks/filesystem-security-full.sh')],e2)
    expect(rc==2,out)
    expect('World-writable: INCOMPLETE | 1/1 trees attempted' in out,out)
    expect('World-writable: 100%' not in out,out)
    expect('INCOMPLETE  filesystem-security-full' in out,out)
    expect('CLEAN  filesystem-security-full' not in out,out)
    expect('Check coverage is INCOMPLETE' in out,out)
    expect('ACTION' not in out,'incomplete posture scan offered destructive remediation')

print(f'Filesystem recursive progress: {checks} assertions passed')
''')

p=Path('.github/workflows/progress-quality.yml'); s=p.read_text()
marker='''      - name: Real terminal rendering, safe counts and report isolation\n        run: python3 tests/progress-terminal.py\n'''
add=marker+'''      - name: Recursive filesystem progress and traversal failures\n        run: python3 tests/filesystem-progress.py\n'''
assert marker in s; p.write_text(s.replace(marker,add,1))

p=Path('.github/workflows/ci.yml'); s=p.read_text()
marker='''      - name: Host-agnostic discovery smoke test\n        shell: bash\n        run: bash tests/smoke.sh\n'''
if 'Discovery completeness and cache boundaries' not in s:
    add=marker+'''\n      - name: Discovery completeness and cache boundaries\n        shell: bash\n        run: bash tests/discovery-reliability.sh\n'''
    assert marker in s; s=s.replace(marker,add,1)
p.write_text(s)

p=Path('CHANGELOG.md'); s=p.read_text()
marker='- Add regressions for traversal returning partial candidates, direct-check/suite false-clean prevention, out-of-root cache poisoning, symlinked cache files, oversized cache input, private permissions, and existing runtime behavior. No malware rules, target semantics, remediation, quarantine, baseline, or WordPress policy thresholds changed.\n'
if 'measured per-WordPress-tree progress' not in s:
    add=marker+'- Add measured per-WordPress-tree progress to FULL recursive world-writable and symlink scans. Recursive traversal failures retain completed findings but make the check INCOMPLETE instead of allowing a false clean result.\n- Treat permission and symlink posture findings as read-only in FAST/FULL filesystem checks; they no longer offer generic delete/quarantine remediation.\n'
    assert marker in s; s=s.replace(marker,add,1)
p.write_text(s)
