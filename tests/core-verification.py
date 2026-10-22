#!/usr/bin/env python3
"""Static verifier regressions using inert files; no WP-CLI or network."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / 'lib/core-verification.php'

class CoreVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='press-core-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.site = self.base / 'site'
        (self.site / 'wp-admin').mkdir(parents=True)
        (self.site / 'wp-includes').mkdir()
        self.checksums = {}
        self.file('wp-admin/core.php', '<?php /* inert expected file */\n')
        self.file('wp-includes/version.php', '<?php $wp_version="7.1";\n')

    def file(self, name, text):
        p = self.site / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        self.checksums[name] = hashlib.md5(p.read_bytes()).hexdigest()
        return p

    def run_verifier(self, checksums=None, unprivileged=False):
        manifest = self.base / 'manifest.json'
        manifest.write_text(json.dumps({'checksums': self.checksums if checksums is None else checksums}))
        meta = self.base / 'meta.tsv'
        meta.write_text(f'1\t{self.site}\tfixture\t7.1\ten_US\t{manifest}\n')
        out = self.base / 'results'
        out.mkdir()
        kwargs = {}
        if unprivileged and os.geteuid() == 0:
            # Drop privilege only for this isolated read-only child process.
            self.base.chmod(0o755)
            out.chmod(0o777)
            kwargs.update(user=65534, group=65534, extra_groups=[])
        r = subprocess.run(['php', str(HELPER), str(meta), str(out)],
                           capture_output=True, timeout=20, **kwargs)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        return {p.suffix[1:]: p.read_text() for p in out.iterdir()}

    def test_clean_static_control_never_executes_php(self):
        marker = self.base / 'executed'
        self.file('wp-admin/core.php', f'<?php file_put_contents("{marker}", "bad");\n')
        result = self.run_verifier()
        self.assertEqual(result['status'], 'clean\n')
        self.assertFalse(marker.exists())

    def test_expected_symlink_cannot_be_clean(self):
        p = self.site / 'wp-admin/core.php'
        outside = self.base / 'outside.php'
        p.rename(outside)
        p.symlink_to(outside)
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_symlink_directory_cannot_hide_extra_files(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'inert.php').write_text('<?php /* inert */')
        (self.site / 'wp-admin/hidden').symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_linked_core_directory_is_incomplete(self):
        d = self.site / 'wp-admin'
        d.rename(self.base / 'linked-directory')
        d.symlink_to(self.base / 'linked-directory', target_is_directory=True)
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_unreadable_directory_is_not_clean(self):
        p = self.site / 'wp-admin/private'
        p.mkdir()
        p.chmod(0)
        try:
            self.assertEqual(self.run_verifier(unprivileged=True)['status'], 'error\n')
        finally:
            p.chmod(0o755)

    def test_special_entry_is_incomplete(self):
        os.mkfifo(self.site / 'wp-includes/inert.fifo')
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_hardlinked_file_is_incomplete(self):
        os.link(self.site / 'wp-admin/core.php', self.base / 'shared.php')
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_manifest_paths_cannot_escape(self):
        self.checksums['../outside'] = '0' * 32
        result = self.run_verifier()
        self.assertEqual(result['status'], 'error\n')
        self.assertEqual(result['bad'], '')

    def test_malformed_digest_is_rejected(self):
        self.checksums['wp-admin/core.php'] = 'not-md5'
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def test_terminal_controls_are_withheld(self):
        (self.site / 'wp-admin/bad\x1b[31m.php').write_text('inert')
        result = self.run_verifier()
        self.assertEqual(result['status'], 'error\n')
        self.assertNotIn('\x1b', result['details'])

    def test_mismatch_missing_and_extra_are_distinct(self):
        (self.site / 'wp-admin/core.php').write_text('changed')
        (self.site / 'wp-includes/version.php').unlink()
        (self.site / 'wp-admin/extra.php').write_text('inert')
        r = self.run_verifier()
        self.assertEqual(r['status'], 'alert\n')
        self.assertEqual(r['mismatch'], 'wp-admin/core.php\n')
        self.assertEqual(r['missing'], 'wp-includes/version.php\n')
        self.assertEqual(r['extra'], 'wp-admin/extra.php\n')

    def test_wp_content_prefix_does_not_skip_root_file(self):
        p = self.file('wp-content-custom.php', 'original')
        p.write_text('changed')
        self.assertEqual(self.run_verifier()['status'], 'alert\n')

    def test_oversized_file_is_incomplete(self):
        p = self.site / 'wp-admin/core.php'
        with p.open('wb') as f:
            f.truncate(67108865)
        self.assertEqual(self.run_verifier()['status'], 'error\n')

    def integrated_check(self, linked=False):
        for name in ['wp-settings.php','wp-load.php']:
            self.file(name, '<?php /* inert bootstrap; never execute */\n')
        (self.site/'wp-content').mkdir()
        for i in range(101):
            self.file(f'wp-includes/fixture-{i}.php', '<?php /* inert */\n')
        cache = self.base/'cache/core-checksums'
        cache.mkdir(parents=True)
        (cache/'7.1-en_US.json').write_text(json.dumps({'checksums':self.checksums}))
        bindir = self.base/'bin'
        bindir.mkdir()
        marker = self.base/'external-call'
        for name in ['curl','wget','wp']:
            script = bindir/name
            script.write_text('#!/bin/sh\nprintf called > "$TEST_EXTERNAL_CALL"\nexit 99\n')
            script.chmod(0o755)
        if linked:
            outside = self.base/'outside'
            outside.mkdir()
            (self.site/'wp-admin/linked').symlink_to(outside, target_is_directory=True)
        env = {'HOME':str(self.base), 'PATH':str(bindir)+':/usr/local/bin:/usr/bin:/bin',
               'ROOT':str(self.site), 'PRESSWARDEN_DIR':str(REPO),
               'PRESSWARDEN_CONFIG_FILE':str(self.base/'absent'),
               'PRESSWARDEN_STATE_DIR':str(self.base/'state'),
               'PRESSWARDEN_CACHE_DIR':str(self.base/'cache'),
               'PRESSWARDEN_INTERACTIVE':'0','PRESSWARDEN_NOCOLOR':'1',
               'PRESSWARDEN_PROGRESS':'0','TEST_EXTERNAL_CALL':str(marker)}
        r = subprocess.run(['bash',str(REPO/'checks/wp-core.sh')],env=env,
                           capture_output=True,text=True,timeout=30)
        self.assertFalse(marker.exists())
        return r

    def test_full_check_clean_without_bootstrap_or_network(self):
        r = self.integrated_check()
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('1/1 sites',r.stdout)

    def test_full_check_propagates_incomplete(self):
        r = self.integrated_check(linked=True)
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertNotIn('1/1 sites',r.stdout)
        self.assertIn('INCOMPLETE',r.stdout+r.stderr)

    def test_exclusive_result_publication(self):
        self.run_verifier()
        out = self.base / 'results'
        before = (out / '1.status').read_bytes()
        r = subprocess.run(['php',str(HELPER),str(self.base/'meta.tsv'),str(out)], capture_output=True, timeout=20)
        self.assertEqual(r.returncode,2)
        self.assertEqual((out/'1.status').read_bytes(),before)

if __name__ == '__main__':
    unittest.main(verbosity=2)
