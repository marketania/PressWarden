#!/usr/bin/env python3
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
