#!/usr/bin/env python3
"""Exercise excluded finding projections as bytes, without WordPress or network."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('report_display_fixture', ROOT / 'tests/report-display.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
HARNESS = fixture.HARNESS.replace('MANUAL_EXCLUDED_ROOTS=()', 'MANUAL_EXCLUDED_ROOTS=("$WORK/excluded")')

class ExcludedEvidence(unittest.TestCase):
    def run_case(self, data, kind='file', cap='2', fail_log=False):
        t = tempfile.TemporaryDirectory(prefix='press-excluded-evidence-')
        self.addCleanup(t.cleanup)
        root = Path(t.name); source = root / 'input'
        if callable(data): data = data(root)
        if kind == 'hardlink':
            (root / 'outside').write_bytes(data); os.link(root / 'outside', source)
        elif kind == 'oversized':
            with source.open('wb') as f: f.truncate(128*1024*1024+1)
        else: source.write_bytes(data)
        before = source.stat()
        env = dict(os.environ, REPO=str(ROOT), WORK=str(root), CAP=cap,
                   FAIL_LOG=str(int(fail_log)), FAIL_RENDER='0')
        p = subprocess.Popen(['bash','-c', HARNESS], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try: out, err = p.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.communicate(); self.fail('Unbounded excluded-source processing')
        details = root / 'details.log'
        return p.returncode, out+err, source, details.read_bytes() if details.exists() else b'', before

    def test_nul_only_record_cannot_become_clean(self):
        rc, out, _, details, _ = self.run_case(b'\0\n')
        self.assertEqual(rc, 1, out); self.assertIn(b'\\x00', out)
        self.assertIn(b'\0\n', details); self.assertNotIn(b'CLEAN', out)

    def test_embedded_nul_and_no_final_newline_are_preserved(self):
        raw = b'finding\0evidence\xff\x1b[2J'
        rc, out, _, details, _ = self.run_case(raw)
        self.assertEqual(rc, 1, out); self.assertIn(raw, details)
        self.assertTrue(details.endswith(raw)); self.assertNotIn(b'\x1b', out)

    def test_hardlink_is_refused_before_projection(self):
        raw = b'one\n'; rc, out, src, details, st = self.run_case(raw, 'hardlink')
        self.assertEqual(rc, 2, out); self.assertEqual(src.stat().st_ino, st.st_ino)
        self.assertEqual(src.read_bytes(), raw); self.assertEqual(details, b'')
        self.assertNotIn(b'ACTION_OFFERED', out)

    def test_oversized_input_refused_before_line_processing(self):
        rc, out, src, details, st = self.run_case(b'', 'oversized')
        self.assertEqual(rc, 2, out); self.assertEqual(src.stat().st_size, st.st_size)
        self.assertEqual(src.stat().st_ino, st.st_ino); self.assertEqual(details, b'')

    def test_invalid_cap_does_not_rewrite_source(self):
        raw = b'keep\0original-no-newline'
        rc, out, src, _, st = self.run_case(raw, cap='bad')
        self.assertEqual(rc, 2, out); self.assertEqual(src.read_bytes(), raw)
        self.assertEqual(src.stat().st_ino, st.st_ino)

    def test_log_failure_retains_original_including_excluded_records(self):
        def raw(root): return str(root / 'excluded/file.php').encode()+b'\nkeep\0original'
        rc, out, src, _, st = self.run_case(raw, fail_log=True)
        self.assertEqual(rc, 2, out); self.assertEqual(src.read_bytes(), raw(src.parent))
        self.assertEqual(src.stat().st_ino, st.st_ino); self.assertNotIn(b'ACTION_OFFERED', out)

    def test_excluded_path_boundary_and_visible_counts(self):
        def raw(root):
            return (str(root/'excluded/file.php')+'\n'+str(root/'excluded')+'\n'+
                    str(root/'excluded-neighbor/keep.php')+'\nlast').encode()
        rc, out, src, details, _ = self.run_case(raw)
        self.assertEqual(rc, 1, out)
        self.assertNotIn(str(src.parent/'excluded/file.php').encode(), details)
        self.assertIn(b'excluded-neighbor/keep.php', details); self.assertTrue(details.endswith(b'last'))
        self.assertIn(b'findings: 2', out)

    def test_excluded_long_record_cannot_leak_its_continuation(self):
        def raw(root): return str(root/'excluded/file.php').encode()+b':' + b'A'*90000+b'\0tail\nallowed'
        rc, out, _, details, _ = self.run_case(raw)
        self.assertEqual(rc, 1, out); self.assertNotIn(b'A'*64, details)
        self.assertTrue(details.endswith(b'allowed')); self.assertIn(b'findings: 1', out)

    def test_all_excluded_is_clean_for_this_projection(self):
        rc, out, _, details, _ = self.run_case(lambda r: str(r/'excluded/file').encode())
        self.assertEqual(rc, 0, out); self.assertIn(b'CLEAN', out); self.assertEqual(details, b'')

if __name__ == '__main__': unittest.main(verbosity=2)
