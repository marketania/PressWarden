#!/usr/bin/env python3
"""Exercise actual report functions with inert bytes; never bootstrap WordPress."""
from pathlib import Path
import os
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
set -uo pipefail
. "$REPO/lib/reports.sh"
. "$REPO/lib/ui.sh"
. "$REPO/lib/remediation.sh"
B=''; D=''; R=''; G=''; Y=''; X=''; C=''; BL=''; M=''; NAME=display
ROOT="$WORK"; SCAN_ROOTS=(); MANUAL_EXCLUDED_ROOTS=()
SECN=1; CURRENT_SECTION=fixture; SEC_T0=$(date +%s); T0=$SEC_T0
TOTAL=0; ALERTS=0; REVIEWS=0; DELETED=0; PROTECTED_SKIPPED=0
PRESSWARDEN_MAX="${CAP:-2}"; PRESSWARDEN_INTERACTIVE=1
DETAIL_LOG="$WORK/details.log"; LOG="$WORK/console.log"
_rule(){ :; }; human_time(){ printf '0s'; }
tmpf(){ mktemp "$WORK/tmp.XXXXXX"; }
pw_history_capture(){ :; }
_prompt_file_action(){ printf 'ACTION_OFFERED\n'; }
if [ "${FAIL_LOG:-0}" = 1 ]; then DETAIL_LOG="$WORK/log-directory"; mkdir "$DETAIL_LOG"; fi
[ "${FAIL_RENDER:-0}" != 1 ] || _PW_REPORT_DISPLAY_HELPER="$WORK/not-installed.php"
report "$WORK/input" issue 'no fixture findings'
finish
'''


class ReportDisplay(unittest.TestCase):
    def run_report(self, data=b'', kind='file', cap=2, fail_log=False, fail_render=False):
        tmp = tempfile.TemporaryDirectory(prefix='press-report-display-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        source = root / 'input'
        if kind == 'file':
            source.write_bytes(data)
        elif kind == 'link':
            (root / 'outside').write_bytes(data)
            source.symlink_to(root / 'outside')
        elif kind == 'hardlink':
            (root / 'outside').write_bytes(data)
            os.link(root / 'outside', source)
        elif kind == 'unreadable':
            source.write_bytes(data)
            source.chmod(0)
        elif kind == 'oversized':
            with source.open('wb') as f:
                f.truncate(128 * 1024 * 1024 + 1)
        elif kind == 'fifo':
            os.mkfifo(source)
        elif kind == 'directory':
            source.mkdir()
        elif kind != 'missing':
            raise AssertionError(kind)
        env = dict(os.environ, REPO=str(ROOT), WORK=str(root), CAP=str(cap), FAIL_LOG=str(int(fail_log)), FAIL_RENDER=str(int(fail_render)))
        process = subprocess.Popen(['bash', '-c', HARNESS], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        details = (root / 'details.log').read_bytes() if (root / 'details.log').exists() else b''
        return result, details, source

    def test_terminal_sequences_are_inert_but_evidence_is_exact(self):
        original = b'file.php:12:payload\x1b[2J\x1b]52;c;SGVsbG8=\x07\r\b\n'
        result, details, _ = self.run_report(original)
        self.assertEqual(result.returncode, 1, result.stderr)
        for control in (b'\x1b', b'\x07', b'\r', b'\b'):
            self.assertNotIn(control, result.stdout + result.stderr)
        self.assertIn(b'\\x1B', result.stdout)
        self.assertIn(original, details)

    def test_unicode_preserved_and_direction_controls_escaped(self):
        text = 'مرحبا café 東京'
        result, details, _ = self.run_report((text + '\u202e\u2066\u009b\n').encode())
        self.assertEqual(result.returncode, 1)
        self.assertIn(text.encode(), result.stdout)
        for unsafe in ('\u202e', '\u2066', '\u009b'):
            self.assertNotIn(unsafe.encode(), result.stdout)
            self.assertIn(unsafe.encode(), details)

    def test_invalid_utf8_uses_visible_byte_escapes(self):
        result, details, _ = self.run_report(b'file: \xff\x9b\x1b\n')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b'\xff', result.stdout)
        self.assertNotIn(b'\x9b', result.stdout)
        self.assertIn(b'\\xFF', result.stdout)
        self.assertIn(b'\xff\x9b\x1b', details)

    def test_nonexistent_evidence_cannot_be_clean(self):
        result, _, _ = self.run_report(kind='missing')
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'INCOMPLETE', result.stdout + result.stderr)
        self.assertNotIn(b'CLEAN', result.stdout)
        self.assertNotIn(b'ACTION_OFFERED', result.stdout)

    def test_nonregular_sources_refused_without_consuming_or_deleting(self):
        for kind in ('link', 'hardlink', 'directory', 'fifo', 'oversized'):
            with self.subTest(kind=kind):
                result, details, source = self.run_report(b'outside evidence\n', kind)
                self.assertEqual(result.returncode, 2)
                self.assertTrue(source.exists())
                self.assertEqual(details, b'')
                self.assertNotIn(b'CLEAN', result.stdout)
                if kind == 'link':
                    self.assertTrue(source.is_symlink())
                    self.assertEqual(source.read_bytes(), b'outside evidence\n')

    @unittest.skipIf(os.geteuid() == 0, 'read permissions require a non-root fixture')
    def test_unreadable_source_is_incomplete(self):
        result, details, source = self.run_report(b'private finding', kind='unreadable')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(details, b'')
        self.assertTrue(source.exists())

    def test_renderer_failure_cannot_claim_clean(self):
        result, details, source = self.run_report(b'unsafe\x1b[2J\n', fail_render=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'CLEAN', result.stdout)
        self.assertNotIn(b'\x1b', result.stdout + result.stderr)
        self.assertTrue(source.exists())

    def test_invalid_display_cap_refuses_without_discarding_source(self):
        for cap in ('-1', 'bad', '01', '10001'):
            with self.subTest(cap=cap):
                result, details, source = self.run_report(b'finding\n', cap=cap)
                self.assertEqual(result.returncode, 2)
                self.assertTrue(source.exists())
                self.assertNotIn(b'CLEAN', result.stdout)

    def test_log_failure_retains_original_and_disables_actions(self):
        data = b'A' * 100_000 + b'\x1b[2J\n'
        result, details, source = self.run_report(data, fail_log=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(source.read_bytes(), data)
        self.assertNotIn(b'original in findings log', result.stdout)
        self.assertNotIn(b'ACTION_OFFERED', result.stdout)
        self.assertNotIn(b'\x1b', result.stdout + result.stderr)

    def test_real_empty_evidence_remains_clean(self):
        result, _, _ = self.run_report(b'\n\n')
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'CLEAN', result.stdout)

    def test_last_record_without_newline_is_displayed_and_counted(self):
        result, details, _ = self.run_report(b'last-finding-no-newline')
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'last-finding-no-newline', result.stdout)
        self.assertIn(b'findings: 1', result.stdout)
        self.assertIn(b'last-finding-no-newline', details)

    def test_display_is_bounded_without_truncating_evidence(self):
        original = b'A' * 100_000 + b'\x1b[2J\n'
        result, details, _ = self.run_report(original)
        self.assertEqual(result.returncode, 1)
        self.assertLess(len(result.stdout), 7000)
        self.assertIn(b'display truncated', result.stdout)
        self.assertIn(original, details)

    def test_line_cap_and_count_preserved(self):
        result, details, _ = self.run_report(b'one\ntwo\nthree\n', cap=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'one', result.stdout)
        self.assertIn(b'two', result.stdout)
        self.assertNotIn(b'three', result.stdout)
        self.assertIn(b'findings: 3', result.stdout)
        self.assertIn(b'1 more hidden', result.stdout)
        self.assertIn(b'one\ntwo\nthree\n', details)


if __name__ == '__main__':
    unittest.main(verbosity=2)
