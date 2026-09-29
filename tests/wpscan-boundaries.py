#!/usr/bin/env python3
"""Real check subprocesses; inert recording tools, no HTTP or WordPress execution."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class WPScanBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='press-wpscan-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.site = self.base/'fleet/example.test/public_html'
        for name in ('wp-admin','wp-content','wp-includes'):
            (self.site/name).mkdir(parents=True, exist_ok=True)
        for name in ('wp-load.php','wp-settings.php'):
            (self.site/name).write_text('<?php // inert fixture\n')
        (self.site/'wp-includes/version.php').write_text('<?php $wp_version="7.1";\n')
        self.bin = self.base/'bin'; self.bin.mkdir()
        self.env = {'PATH': str(self.bin)+':/usr/local/bin:/usr/bin:/bin', 'HOME':str(self.base),
                    'LANG':'C.UTF-8', 'ROOT':str(self.base/'fleet'),
                    'PRESSWARDEN_CONFIG_FILE':str(self.base/'absent'),
                    'PRESSWARDEN_STATE_DIR':str(self.base/'state'),
                    'PRESSWARDEN_CACHE_DIR':str(self.base/'cache'),
                    'PRESSWARDEN_NOCOLOR':'1', 'PRESSWARDEN_PROGRESS':'0',
                    'PRESSWARDEN_INTERACTIVE':'0', 'PRESSWARDEN_WPSCAN_TIMEOUT':'3',
                    'WPSCAN_API_TOKEN':'test-secret-not-a-real-token-7482',
                    'CALLS':str(self.base/'calls'), 'WP_MODE':'ok', 'SCAN_MODE':'clean'}
        (self.bin/'wp').write_text(r'''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'wp','args':sys.argv[1:]})+'\n')
mode=os.environ['WP_MODE']
if mode=='fail': print('bootstrap failed '+os.environ['WPSCAN_API_TOKEN'],file=sys.stderr);sys.exit(7)
if mode=='warning': print('warning '+os.environ['WPSCAN_API_TOKEN'],file=sys.stderr)
print(os.environ.get('HOME_URL','https://example.test/'))
''')
        (self.bin/'wpscan').write_text(r'''#!/usr/bin/env python3
import json,os,sys,time
mode=os.environ['SCAN_MODE']
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':'wpscan','args':args,'cwd':os.getcwd()})+'\n')
if mode=='timeout':time.sleep(20)
if mode=='malformed':print('No Known Vulnerabilities Detected');sys.exit(0)
if mode=='empty':sys.exit(0)
url=args[args.index('--url')+1]
r={'target_url':url,'start_time':1700000000,'stop_time':1700000002,
   'version':{'number':'7.1','vulnerabilities':[]},'main_theme':None,
   'plugins':{},'themes':{},'vuln_api':{'plan':'fixture','requests_done_during_scan':1,'requests_remaining':10}}
v={'title':'Fixture known vulnerability','uuid':'11111111-1111-4111-8111-111111111111','fixed_in':'2.0','references':{}}
if mode in ('finding','vulnerable-exit','partial','escape','unicode','quota-findings'):
    if mode=='unicode':v['title']='Fixture café Straße العربية\u202e'
    if mode=='escape':v['title']='Fixture\x1b[2J vulnerability '+os.environ['WPSCAN_API_TOKEN']
    r['plugins']={'fixture':{'slug':'fixture','version':{'number':'1.0'},'vulnerabilities':[v]}}
if mode in ('quota','quota-findings'):r['vuln_api']={'http_error':'429 '+os.environ['WPSCAN_API_TOKEN']}
if mode=='zero-quota':r['vuln_api']['requests_remaining']=0
if mode=='no-api':r.pop('vuln_api')
if mode=='no-stop':r.pop('stop_time')
if mode=='wrong-target':r['target_url']='https://other.invalid/'
if mode=='unknown-version':r['version']=None
if mode=='wrong-schema':r['plugins']=[]
if mode=='aborted':r['scan_aborted']='connection failed '+os.environ['WPSCAN_API_TOKEN']
if mode=='oversized':r['irrelevant']='x'*(9*1024*1024)
if mode=='stderr':print('sensitive diagnostic '+os.environ['WPSCAN_API_TOKEN'],file=sys.stderr)
print(json.dumps(r),flush=True)
if mode=='partial':sys.exit(4)
if mode in ('vulnerable-exit','unexplained-exit'):sys.exit(5)
''')
        for p in self.bin.iterdir():p.chmod(0o755)

    def run_check(self, mode='clean'):
        self.env['SCAN_MODE']=mode
        return subprocess.run(['bash',str(ROOT/'checks/wp-vulnerabilities.sh')],env=self.env,
                              capture_output=True,text=True,timeout=15,cwd=self.site)

    def calls(self, tool='wpscan'):
        p=self.base/'calls'
        return [json.loads(x) for x in p.read_text().splitlines() if json.loads(x)['tool']==tool] if p.exists() else []

    def assert_incomplete(self,r):
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn('INCOMPLETE',r.stdout+r.stderr)
        self.assertNotIn('CLEAN',r.stdout+r.stderr)
        self.assertNotIn(self.env['WPSCAN_API_TOKEN'],r.stdout+r.stderr)

    def test_valid_json_no_records_is_scoped_success(self):
        r=self.run_check();self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        args=self.calls()[0]['args']
        self.assertEqual(args[args.index('--format')+1],'json')
        self.assertNotIn(self.env['WPSCAN_API_TOKEN'],' '.join(args))
        self.assertIn('passive',r.stdout)
        self.assertNotEqual(Path(self.calls()[0]['cwd']),self.site)

    def test_real_vulnerability_records_produce_review(self):
        r=self.run_check('finding');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertIn('Fixture known vulnerability',r.stdout)

    def test_upstream_vulnerability_exit_is_review_not_error(self):
        r=self.run_check('vulnerable-exit');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertIn('Fixture known vulnerability',r.stdout);self.assertNotIn('INCOMPLETE',r.stdout)
        self.assert_incomplete(self.run_check('unexplained-exit'))

    def test_partial_findings_survive_nonzero_exit(self):
        r=self.run_check('partial');self.assert_incomplete(r)
        self.assertIn('Fixture known vulnerability',r.stdout)

    def test_quota_failure_retains_findings_but_is_incomplete(self):
        r=self.run_check('quota-findings');self.assert_incomplete(r)
        self.assertIn('Fixture known vulnerability',r.stdout)

    def test_api_failure_or_exhaustion_never_clean(self):
        for mode in ('quota','zero-quota','no-api'):
            with self.subTest(mode=mode):self.assert_incomplete(self.run_check(mode))

    def test_malformed_empty_or_wrong_schema_never_clean(self):
        for mode in ('malformed','empty','wrong-schema','no-stop','aborted','unknown-version'):
            with self.subTest(mode=mode):self.assert_incomplete(self.run_check(mode))

    def test_provider_target_must_match(self):
        self.assert_incomplete(self.run_check('wrong-target'))

    def test_failed_bootstrap_never_guesses_url(self):
        self.env['WP_MODE']='fail';self.assert_incomplete(self.run_check())
        self.assertEqual(self.calls(),[])

    def test_bootstrap_diagnostics_never_become_url(self):
        self.env['WP_MODE']='warning';self.assert_incomplete(self.run_check())
        self.assertEqual(self.calls(),[])

    def test_invalid_home_urls_never_reach_scanner(self):
        for value in ('', 'file:///etc/passwd','https://user:secret@example.test/',
                      'https://example.test/\nhttps://other.invalid/', 'https://example.test/?token=secret'):
            with self.subTest(value=value):
                self.env['HOME_URL']=value;self.assert_incomplete(self.run_check())
                self.assertEqual(self.calls(),[])

    def test_provider_diagnostics_and_controls_are_not_disclosed(self):
        r=self.run_check('escape');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertNotIn('\x1b',r.stdout+r.stderr)
        self.assertNotIn(self.env['WPSCAN_API_TOKEN'],r.stdout+r.stderr)
        self.assert_incomplete(self.run_check('stderr'))

    def test_unicode_text_is_preserved_without_bidi_controls(self):
        r=self.run_check('unicode');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertIn('café Straße العربية',r.stdout);self.assertNotIn('\u202e',r.stdout)

    def test_real_timeout_is_incomplete(self):
        self.env['PRESSWARDEN_WPSCAN_TIMEOUT']='1';self.assert_incomplete(self.run_check('timeout'))

    def test_invalid_timeout_is_rejected_before_bootstrap(self):
        for value in ('0','-1','1;false','9999999999'):
            self.env['PRESSWARDEN_WPSCAN_TIMEOUT']=value
            self.assert_incomplete(self.run_check());self.assertEqual(self.calls('wp'),[])

    def test_unconfigured_optional_check_does_not_bootstrap(self):
        self.env['WPSCAN_API_TOKEN']=''
        r=self.run_check();self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('SKIPPED',r.stdout);self.assertNotIn('CLEAN',r.stdout)
        self.assertEqual(self.calls('wp'),[]);self.assertEqual(self.calls(),[])

    def test_configured_missing_scanner_is_incomplete(self):
        (self.bin/'wpscan').unlink();self.assert_incomplete(self.run_check())
        self.assertEqual(self.calls('wp'),[])

    def test_large_provider_output_is_bounded_and_incomplete(self):
        self.assert_incomplete(self.run_check('oversized'))

if __name__=='__main__':unittest.main(verbosity=2)
