#!/usr/bin/env python3
"""Exercise the real check with a recording, inert YARA adapter; never malware."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class YaraBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='press-yara-boundary-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.site = self.base / 'fleet/example.test/public_html'
        self.make_site(self.site)
        self.bin = self.base / 'bin'; self.bin.mkdir()
        self.rules = self.base / 'rules.yar'; self.rules.write_text('rule Fixture { condition: false }\n')
        self.env = {'PATH': str(self.bin)+':/usr/local/bin:/usr/bin:/bin', 'HOME':str(self.base),
                    'ROOT':str(self.base/'fleet'), 'LANG':'C.UTF-8',
                    'PRESSWARDEN_CONFIG_FILE':str(self.base/'absent'),
                    'PRESSWARDEN_STATE_DIR':str(self.base/'state'),
                    'PRESSWARDEN_CACHE_DIR':str(self.base/'cache'),
                    'PRESSWARDEN_NOCOLOR':'1', 'PRESSWARDEN_PROGRESS':'0',
                    'PRESSWARDEN_INTERACTIVE':'0','PRESSWARDEN_YARA_RULES':str(self.rules),
                    'YARA_CALLS':str(self.base/'calls.jsonl'),'YARA_MODE':'clean'}
        adapter = self.bin/'yara'
        adapter.write_text(r'''#!/usr/bin/env python3
import json, os, sys, time
mode=os.environ['YARA_MODE']
if sys.argv[1:]==['--help']:
    print('--no-follow-symlinks' if mode!='legacy' else 'legacy help')
    sys.exit(0)
with open(os.environ['YARA_CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\n')
target=sys.argv[-1]
if mode=='timeout': time.sleep(20)
if mode in ('match','partial'): print('Fixture '+target+'/inert.php',flush=True)
if mode=='escape': print('Fixture '+target+'/bad\x1b[2J.php',flush=True)
if mode in ('fail','partial'): print('fixture engine failure',file=sys.stderr);sys.exit(7)
if mode=='warning': print('fixture read warning',file=sys.stderr)
if mode=='malformed': print('not-a-rule nor-a-scoped-path')
''')
        adapter.chmod(0o755)

    def make_site(self, site):
        for directory in ('wp-admin','wp-content','wp-includes'):
            (site/directory).mkdir(parents=True,exist_ok=True)
        for name in ('wp-load.php','wp-settings.php'):(site/name).write_text('<?php\n')
        (site/'wp-includes/version.php').write_text('<?php $wp_version="7.1";\n')
        (site/'inert.php').write_text('<?php // benign fixture\n')

    def run_check(self, mode):
        self.env['YARA_MODE']=mode
        result=subprocess.run(['bash',str(ROOT/'checks/external-yara.sh')],env=self.env,
                              text=True,capture_output=True,timeout=15)
        self.assertEqual((self.site/'inert.php').read_text(),'<?php // benign fixture\n')
        return result

    def calls(self):
        path=self.base/'calls.jsonl'
        return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []

    def test_failure_is_incomplete_not_clean(self):
        r=self.run_check('fail');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn('INCOMPLETE',r.stdout);self.assertNotIn('CLEAN',r.stdout)

    def test_successful_empty_scan_is_scoped_success(self):
        r=self.run_check('clean');self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(len(self.calls()),1)
        self.assertIn('--no-follow-symlinks',self.calls()[0])
        self.assertIn('no external YARA rule matches',r.stdout)

    def test_matches_are_review_not_automatic_remediation(self):
        r=self.run_check('match');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertIn('Fixture',r.stdout);self.assertIn('REVIEW',r.stdout)

    def test_partial_findings_survive_engine_error(self):
        r=self.run_check('partial');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn('external YARA match',r.stdout);self.assertIn('INCOMPLETE',r.stdout)

    def test_excluded_nested_site_is_never_passed_to_recursive_scanner(self):
        self.make_site(self.site/'private')
        self.env['PRESSWARDEN_EXCLUDE']='example.test/private'
        r=self.run_check('clean');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertEqual(self.calls(),[]);self.assertNotIn('CLEAN',r.stdout)

    def test_legacy_engine_is_refused_before_scan(self):
        r=self.run_check('legacy');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertEqual(self.calls(),[])

    def test_invalid_timeout_never_invokes_scanner(self):
        for value in ('0','-1','1;false','99999999'):
            self.env['PRESSWARDEN_YARA_TIMEOUT']=value
            r=self.run_check('clean');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
            self.assertEqual(self.calls(),[])

    def test_real_process_timeout_is_incomplete(self):
        self.env['PRESSWARDEN_YARA_TIMEOUT']='1'
        r=self.run_check('timeout');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertNotIn('CLEAN',r.stdout)

    def test_scanner_stderr_cannot_be_presented_as_clean(self):
        r=self.run_check('warning');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertNotIn('CLEAN',r.stdout)

    def test_control_characters_are_not_terminal_commands(self):
        r=self.run_check('escape');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertNotIn('\x1b',r.stdout+r.stderr)

    def test_invalid_output_is_incomplete(self):
        r=self.run_check('malformed');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertNotIn('CLEAN',r.stdout)

    def test_unconfigured_is_explicit_skip_without_clean_claim(self):
        self.env.pop('PRESSWARDEN_YARA_RULES')
        r=self.run_check('clean');self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('SKIPPED',r.stdout);self.assertNotIn('CLEAN',r.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
