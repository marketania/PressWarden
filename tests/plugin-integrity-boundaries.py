#!/usr/bin/env python3
"""Real checksum-check routing with inert WP-CLI responses; no live WordPress."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class PluginIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='press-plugin-fixture-')
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
        site=self.base/'fleet/example.test/public_html';self.site=site
        for d in ['wp-admin','wp-content','wp-includes']:(site/d).mkdir(parents=True)
        for f in ['wp-settings.php','wp-load.php']:(site/f).write_text('<?php\n')
        (site/'wp-includes/version.php').write_text('<?php $wp_version="7.1";\n')
        bin=self.base/'bin';bin.mkdir();wp=bin/'wp'
        wp.write_text(r'''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:];mode=os.environ['FIXTURE_MODE']
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps(args)+'\n')
if args[:2]==['plugin','list']:
    if mode=='inventory-error':sys.exit(7)
    if mode=='invalid-inventory':print('{}');sys.exit(0)
    name='--require=/tmp/not-code.php' if mode=='unsafe-name' else 'demo'
    rows=[dict(name=name,status='active',version='1.0',title='Demo')]
    if any('wporg_status' in a for a in args):
        if mode=='metadata-error':sys.exit(8)
        rows[0]['wporg_status']='' if mode=='premium' else 'active'
    print(json.dumps(rows));sys.exit(0)
if args[:2]==['plugin','verify-checksums']:
    if mode=='empty-error':sys.exit(7)
    if mode=='malformed':print('{}');sys.exit(0)
    if mode=='warning':print('[]');print('Warning: Could not retrieve checksums; skipping.',file=sys.stderr);sys.exit(0)
    if mode in ['mismatch','metadata','control']:
        file='index.php' if mode=='mismatch' else ('.DS_Store' if mode=='metadata' else 'bad\x1b[2J.php')
        print(json.dumps([dict(plugin_name='demo',file=file,message='Checksum does not match' if mode=='mismatch' else 'File was added')]))
        print('Error: No plugins verified (1 failed).',file=sys.stderr);sys.exit(1)
    print('[]');sys.exit(0)
sys.exit(91)
''');wp.chmod(0o755)
        self.env={'PATH':str(bin)+':/usr/local/bin:/usr/bin:/bin','HOME':str(self.base),'ROOT':str(self.base/'fleet'),
                  'PRESSWARDEN_CONFIG_FILE':str(self.base/'absent'),'PRESSWARDEN_STATE_DIR':str(self.base/'state'),
                  'PRESSWARDEN_CACHE_DIR':str(self.base/'cache'),'PRESSWARDEN_NOCOLOR':'1',
                  'PRESSWARDEN_PROGRESS':'0','PRESSWARDEN_INTERACTIVE':'0','CALLS':str(self.base/'calls')}
    def run_check(self,mode):
        self.env['FIXTURE_MODE']=mode
        return subprocess.run(['bash',str(ROOT/'checks/wp-plugin-integrity.sh')],env=self.env,text=True,capture_output=True,timeout=15)
    def test_clean(self):
        r=self.run_check('clean');self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertIn('verified',r.stdout)
    def test_inventory_failure_is_not_a_malware_finding(self):
        r=self.run_check('inventory-error');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertIn('INCOMPLETE',r.stdout)
    def test_inventory_must_be_array(self):
        r=self.run_check('invalid-inventory');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_metadata_failure_is_not_no_eligible_plugins(self):
        r=self.run_check('metadata-error');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_unknown_vendor_is_coverage_gap(self):
        r=self.run_check('premium');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_option_like_plugin_name_never_becomes_wp_option(self):
        r=self.run_check('unsafe-name');self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        calls=[json.loads(x) for x in (self.base/'calls').read_text().splitlines()]
        self.assertFalse(any(a[:2]==['plugin','verify-checksums'] for a in calls))
    def test_engine_failure_is_incomplete(self):
        r=self.run_check('empty-error');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_object_is_not_empty_checksum_array(self):
        r=self.run_check('malformed');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_upstream_skip_warning_is_incomplete(self):
        r=self.run_check('warning');self.assertEqual(r.returncode,2,r.stdout+r.stderr);self.assertNotIn('CLEAN',r.stdout)
    def test_mismatch_remains_integrity_finding(self):
        r=self.run_check('mismatch');self.assertEqual(r.returncode,1,r.stdout+r.stderr);self.assertIn('mismatch',r.stdout)
    def test_metadata_filename_does_not_prove_harmless_content(self):
        r=self.run_check('metadata');self.assertEqual(r.returncode,1,r.stdout+r.stderr)
        self.assertNotIn('safe to delete',r.stdout);self.assertNotIn('harmless',r.stdout);self.assertIn('REVIEW',r.stdout)
    def test_untrusted_paths_are_display_data(self):
        r=self.run_check('control');self.assertEqual(r.returncode,1,r.stdout+r.stderr);self.assertNotIn('\x1b',r.stdout+r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
