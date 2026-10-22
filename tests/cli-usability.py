#!/usr/bin/env python3
"""Exercise public routing, target isolation and terminal color with inert sites."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CliUsability(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='presswarden-cli-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.app = self.base / 'app'
        self.app.mkdir()
        for name in ['presswarden', 'VERSION']:
            shutil.copy2(ROOT / name, self.app / name)
        for name in ['lib', 'config']:
            shutil.copytree(ROOT / name, self.app / name)
        (self.app / 'suites').mkdir()
        (self.app / 'checks').mkdir()
        stub = '''#!/usr/bin/env bash
. "$PRESSWARDEN_DIR/lib/_lib.sh"
printf 'SUITE=%s KIND=%s ROOT=%s REMEDIATE=%s\\n' "${0##*/}" "${1:-}" "$ROOT" "${_PW_EXPLICIT_REMEDIATION:-unset}"
for site in "${SCAN_ROOTS[@]}"; do printf 'SITE=%s\\n' "$site"; done
printf '%sCOLOR%s\\n' "$C" "$X"
exit "${CLI_TEST_EXIT:-0}"
'''
        for suite in ['fast', 'full', 'incident', 'db', 'inspect', 'intel']:
            (self.app / 'suites' / (suite + '.sh')).write_text(stub)
        (self.app / 'checks/doctor.sh').write_text(stub)
        (self.app / 'lib/update.sh').write_text('pw_update() { touch "$CLI_TEST_MUTATION"; }\n')
        (self.app / 'lib/intel.sh').write_text(
            'pw_intel_update() { touch "$CLI_TEST_MUTATION"; }\n'
            'pw_intel_status() { printf "FEED STATUS\\n"; }\n')
        self.fleet = self.base / 'sites'
        self.alpha = self.fleet / 'alpha.example/public_html'
        self.beta = self.fleet / 'beta.example/public_html'
        self.child = self.alpha / 'shop'
        for site in [self.alpha, self.beta, self.child]:
            for name in ['wp-admin', 'wp-content', 'wp-includes']:
                (site / name).mkdir(parents=True, exist_ok=True)
            for name in ['wp-settings.php', 'wp-load.php']:
                (site / name).write_text('<?php // inert fixture\n')
            (site / 'wp-includes/version.php').write_text('<?php $wp_version="7.1";\n')
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith('PRESSWARDEN_') or key == 'NO_COLOR':
                del self.env[key]
        self.env.update(HOME=str(self.base), TERM='xterm',
                        PRESSWARDEN_CONFIG_FILE=str(self.base / 'absent-config'),
                        PRESSWARDEN_SCAN_ROOT=str(self.fleet),
                        PRESSWARDEN_STATE_DIR=str(self.base / 'state'),
                        PRESSWARDEN_CACHE_DIR=str(self.base / 'cache'),
                        PRESSWARDEN_INTERACTIVE='0', PRESSWARDEN_PROGRESS='0',
                        CLI_TEST_MUTATION=str(self.base / 'mutated'))

    def run_cli(self, *args, env=None):
        return subprocess.run(['bash', str(self.app / 'presswarden'), *args],
                              env=self.env if env is None else env,
                              capture_output=True, text=True, timeout=20)

    def assert_refused(self, *args):
        result = self.run_cli(*args)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn('SUITE=', result.stdout)
        self.assertNotIn('SITE=', result.stdout)
        self.assertFalse((self.base / 'mutated').exists())

    def test_modes_route_to_existing_read_only_suites(self):
        modes = [([], 'fast', ''), (['--full'], 'full', ''), (['--deep'], 'full', ''),
                 (['--incident'], 'incident', ''), (['-db'], 'db', ''),
                 (['--db'], 'db', ''), (['--php'], 'inspect', 'php'),
                 (['--js'], 'inspect', 'js'), (['--runtime'], 'inspect', 'runtime')]
        for options, suite, kind in modes:
            with self.subTest(mode=options):
                result = self.run_cli('scan', *options, '--target', 'alpha.example')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'SUITE={suite}.sh KIND={kind} ROOT={self.alpha} REMEDIATE=0', result.stdout)
                self.assertIn('SITE=' + str(self.child), result.stdout)
                self.assertNotIn('SITE=' + str(self.beta), result.stdout)

    def test_target_position_and_legacy_verbs_keep_scope(self):
        cases = [('scan', 'alpha.example', '--full'),
                 ('scan', '--target=alpha.example', '-db'),
                 ('scan', '--php', '--', str(self.alpha)),
                 ('fast', '--target', 'alpha.example'),
                 ('full', 'alpha.example'),
                 ('db', '--target=alpha.example'),
                 ('inspect', 'js', '--target', 'alpha.example'),
                 ('doctor', '--target', 'alpha.example')]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('ROOT=' + str(self.alpha), result.stdout)
                self.assertNotIn('SITE=' + str(self.beta), result.stdout)

    def test_invalid_modes_targets_and_duplicates_fail_before_dispatch(self):
        cases = [('scan', '--full', '--php'), ('scan', '-logs'), ('scan', '--execute'),
                 ('scan', ''), ('scan', '--target'), ('scan', '--target', ''),
                 ('scan', '--target='), ('scan', '--target', '--full'),
                 ('scan', '--target', 'alpha.example', 'beta.example'),
                 ('scan', 'alpha.example', '--target', 'beta.example'),
                 ('scan', '--target=alpha.example', '--target=beta.example'),
                 ('scan', '--', '--target=all'), ('scan', '--target=--target=all'),
                 ('scan', '--target', 'full'), ('scan', '--target', 'update'),
                 ('scan', '--target', 'absent.example'), ('scan', 'alpha.example/../beta.example'),
                 ('scan', '--color=invalid'), ('scan', '--color'),
                 ('full', '--unknown'), ('inspect', 'js', '--unknown')]
        for args in cases:
            with self.subTest(args=args):
                self.assert_refused(*args)

    def test_narrowing_retains_nested_exclusions_and_refuses_excluded_site(self):
        self.env['PRESSWARDEN_EXCLUDE'] = 'alpha.example/shop'
        result = self.run_cli('scan', '-db', '--target', 'alpha.example')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('SITE=' + str(self.alpha) + '\n', result.stdout)
        self.assertNotIn('SITE=' + str(self.child), result.stdout)
        self.assert_refused('scan', '--target', 'alpha.example/shop')

    def test_symlinks_and_duplicate_names_never_expand_to_fleet(self):
        link = self.base / 'linked'
        link.symlink_to(self.alpha, target_is_directory=True)
        self.assert_refused('scan', '--target', str(link))
        shutil.copytree(self.alpha, self.fleet / 'other/alpha.example/public_html')
        self.assert_refused('scan', '--target', 'alpha.example')

    def test_default_and_explicit_fleet_are_supported(self):
        for args in [('scan',), ('scan', '--db', 'all')]:
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('SITE=' + str(self.alpha), result.stdout)
            self.assertIn('SITE=' + str(self.beta), result.stdout)

    def test_exit_codes_and_disabled_remediation_survive_routing(self):
        for code in [0, 1, 2]:
            result = self.run_cli('scan', '--php', 'alpha.example',
                                  env=dict(self.env, CLI_TEST_EXIT=str(code), _PW_EXPLICIT_REMEDIATION='1'))
            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
            self.assertIn('REMEDIATE=0', result.stdout)

    def test_help_and_invalid_arguments_cannot_update_anything(self):
        for args in [('update', '--help'), ('update', '-h'), ('help', 'update'),
                     ('intel', '--help'), ('config-new', '--help'), ('help', 'cleanup')]:
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((self.base / 'mutated').exists())
        for args in [('update', '--unknown'), ('update', 'alpha.example'),
                     ('intel', 'update', 'alpha.example'), ('intel', 'status', 'extra'),
                     ('intel', '--target', 'update'), ('remediate', '--target', 'core'),
                     ('config', 'alpha.example'), ('version', 'extra'),
                     ('help', 'scan', 'extra'), ('help', 'unknown'), ('config-new', 'extra')]:
            self.assert_refused(*args)

    def test_short_help_topics_and_legacy_reference(self):
        brief = self.run_cli('help')
        full = self.run_cli('help', 'all')
        self.assertEqual(brief.returncode, 0)
        self.assertLess(len(brief.stdout.splitlines()), len(full.stdout.splitlines()))
        self.assertIn('help all', brief.stdout)
        self.assertIn('./presswarden fast [target]', full.stdout)
        self.assertIn('--target', self.run_cli('help', 'scan').stdout)
        self.assertIn('INCOMPLETE', self.run_cli('help', 'reports').stdout.upper())

    def test_color_respects_no_color_and_redirected_stdout(self):
        result = self.run_cli('help')
        self.assertNotIn('\x1b', result.stdout)
        result = self.run_cli('--color=always', 'help')
        self.assertIn('\x1b[', result.stdout)
        for env in [dict(self.env, NO_COLOR='1'), dict(self.env, PRESSWARDEN_NOCOLOR='1')]:
            result = self.run_cli('help', '--color=always', env=env)
            self.assertNotIn('\x1b', result.stdout)
        result = self.run_cli('help', '--color=never')
        self.assertNotIn('\x1b', result.stdout)
        result = self.run_cli('help', env=dict(self.env, PRESSWARDEN_FORCE_COLOR='0'))
        self.assertNotIn('\x1b', result.stdout)
        result = self.run_cli('scan', '--php', 'alpha.example', '--color=always')
        self.assertIn('\x1b[', result.stdout)
        master, slave = os.openpty()
        try:
            result = subprocess.run(['bash', str(self.app / 'presswarden'), 'scan', '--php', 'alpha.example'],
                                    env=self.env, stdout=subprocess.PIPE, stderr=slave, timeout=20)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn(b'\x1b', result.stdout, 'stderr TTY contaminated redirected stdout')
        finally:
            os.close(master)
            os.close(slave)

    def test_auto_color_uses_actual_stdout_terminal(self):
        master, slave = os.openpty()
        try:
            result = subprocess.run(['bash', str(self.app / 'presswarden'), 'help'],
                                    env=self.env, stdout=slave, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = os.read(master, 65536)
            self.assertIn(b'\x1b[', output)
        finally:
            os.close(master)
            os.close(slave)

    def test_incomplete_distribution_is_rejected_before_install_or_update(self):
        for name in ['install.sh', 'uninstall.sh', 'PRODUCT']:
            shutil.copy2(ROOT / name, self.app / name)
        (self.app / 'tests').mkdir()
        (self.app / 'lib/cli.sh').unlink()
        result = subprocess.run(['bash', str(ROOT / 'install.sh')],
                                env=dict(self.env, PRESSWARDEN_INSTALL_SOURCE=str(self.app),
                                         PRESSWARDEN_INSTALL_PREFIX=str(self.base / 'installation')),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('lib/cli.sh', result.stderr)
        self.assertFalse((self.base / 'installation').exists())
        result = subprocess.run(['bash', '-c', '. "$1/lib/update.sh"; _pw_update_validate_source "$2"',
                                 '_', str(ROOT), str(self.app)], env=self.env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('lib/cli.sh', result.stderr)

    def test_status_alias_reads_the_same_saved_run_state(self):
        status = self.run_cli('status')
        old = self.run_cli('run-status')
        self.assertEqual((status.returncode, status.stdout, status.stderr),
                         (old.returncode, old.stdout, old.stderr))

    def test_presentation_flags_cannot_replace_a_missing_named_target(self):
        for color in ['--color=always', '--color=never', '--no-color']:
            with self.subTest(color=color):
                self.assert_refused('scan', '--target', color, 'all')
                self.assert_refused('doctor', '--target', color, 'all')
        result = self.run_cli('scan', '--color=never', '--target', 'alpha.example')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ROOT=' + str(self.alpha), result.stdout)
        self.assertNotIn('SITE=' + str(self.beta), result.stdout)

    def test_invalid_config_is_refused_before_any_partial_execution(self):
        config = self.base / 'invalid-config'
        sentinel = self.base / 'config-executed'
        config.write_text('touch "' + str(sentinel) + '"\n'
                          'WPSCAN_API_TOKEN="fixture-value-never-display"\n'
                          'PRESSWARDEN_EXCLUDE="unterminated\n')
        env = dict(self.env, PRESSWARDEN_CONFIG_FILE=str(config))
        for args in [('scan', '--php'), ('scan', '--php', str(self.alpha)),
                     ('scan', '--php', 'alpha.example'), ('config',)]:
            with self.subTest(args=args):
                result = self.run_cli(*args, env=env)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('Invalid shell configuration', result.stderr)
                self.assertNotIn('fixture-value-never-display', result.stdout + result.stderr)
                self.assertNotIn('SUITE=', result.stdout)
                self.assertFalse(sentinel.exists())
        result = subprocess.run(['bash', '-c', '. "$1/lib/env-discovery.sh"', '_', str(self.app)],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('Invalid shell configuration', result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertFalse((self.base / 'state').exists())
        advice = self.run_cli('config-new', env=env)
        self.assertEqual(advice.returncode, 0, advice.stdout + advice.stderr)
        self.assertFalse(sentinel.exists())
        self.assertNotIn('fixture-value-never-display', advice.stdout + advice.stderr)

    def test_config_propagates_root_failure_and_shows_effective_report_path(self):
        linked = self.base / 'linked-root'
        linked.symlink_to(self.fleet, target_is_directory=True)
        for root in [linked, str(self.base / 'invalid') + '\nroot']:
            with self.subTest(root=root):
                result = self.run_cli('config', env=dict(self.env, PRESSWARDEN_SCAN_ROOT=str(root)))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn('Scan root:', result.stdout)
        custom = self.base / 'private-reports'
        result = self.run_cli('config', env=dict(self.env, PRESSWARDEN_REPORTS_DIR=str(custom)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Reports directory:  ' + str(custom), result.stdout)
        self.assertFalse(custom.exists())

    def test_exported_values_keep_multiline_scope_and_override_saved_config(self):
        config = self.base / 'saved-config'
        config.write_text('PRESSWARDEN_SCAN_ROOT="' + str(self.beta) + '"\n'
                          'PRESSWARDEN_EXCLUDE="alpha.example"\n')
        env = dict(self.env, PRESSWARDEN_CONFIG_FILE=str(config),
                   PRESSWARDEN_EXCLUDE='alpha.example/shop\nbeta.example')
        result = self.run_cli('scan', '--php', env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ROOT=' + str(self.fleet), result.stdout)
        self.assertIn('SITE=' + str(self.alpha) + '\n', result.stdout)
        self.assertNotIn('SITE=' + str(self.child), result.stdout)
        self.assertNotIn('SITE=' + str(self.beta), result.stdout)
        loader = '. "$1/lib/env-discovery.sh"; printf "SITE=%s\\n" "${SCAN_ROOTS[@]}"'
        result = subprocess.run(['bash', '-c', loader, '_', str(self.app)],
                                env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'SITE=' + str(self.alpha) + '\n')
        invalid = dict(env, PRESSWARDEN_SCAN_ROOT=str(self.fleet) + '\ninvalid')
        result = self.run_cli('scan', '--php', env=invalid)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('control character in target', result.stderr)
        self.assertNotIn('SUITE=', result.stdout)
        result = subprocess.run(['bash', '-c', loader, '_', str(self.app)],
                                env=invalid, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn('SITE=', result.stdout)

    def test_unusable_config_never_becomes_default_fleet_configuration(self):
        dangling = self.base / 'dangling-config'
        dangling.symlink_to(self.base / 'absent-config-target')
        failing = self.base / 'failing-config'
        failing.write_text('return 7\n')
        readonly = self.base / 'readonly-scope-config'
        readonly.write_text('readonly PRESSWARDEN_SCAN_ROOT="' + str(self.beta) + '"\n')
        cases = [self.base, dangling, failing, readonly]
        if os.geteuid() != 0:
            unreadable = self.base / 'unreadable-config'
            unreadable.write_text('PRESSWARDEN_EXCLUDE="alpha.example"\n')
            unreadable.chmod(0)
            cases.append(unreadable)
        for config in cases:
            with self.subTest(config=config):
                env = dict(self.env, PRESSWARDEN_CONFIG_FILE=str(config))
                result = self.run_cli('scan', '--php', env=env)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('Configuration', result.stderr)
                self.assertNotIn('SUITE=', result.stdout)
                result = subprocess.run(['bash', '-c', '. "$1/lib/env-discovery.sh"', '_', str(self.app)],
                                        env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('Configuration', result.stderr)
        self.assertFalse((self.base / 'state').exists())

    def test_new_install_reports_have_a_clear_nonmutating_empty_state(self):
        for args in [('status',), ('status', 'latest'), ('history',), ('history', 'latest')]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('No recorded PressWarden suite runs', result.stdout)
        self.assertFalse((self.base / 'state').exists())
        runs = self.base / 'state/runs'
        runs.mkdir(parents=True)
        result = self.run_cli('history')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('No recorded PressWarden suite runs', result.stdout)
        self.assertEqual(list(runs.iterdir()), [])

    def test_explicit_empty_invalid_or_missing_run_ids_are_errors(self):
        for command in ['status', 'run-status', 'history', 'continue', 'resume']:
            for run_id in ['', '../invalid', 'missing-run']:
                with self.subTest(command=command, run_id=run_id):
                    result = self.run_cli(command, run_id)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertNotIn('SUITE=', result.stdout)
        self.assertFalse((self.base / 'state').exists())

    def test_empty_history_does_not_hide_unsafe_run_storage(self):
        runs = self.base / 'state/runs'
        runs.parent.mkdir()
        runs.symlink_to(self.base / 'absent-runs', target_is_directory=True)
        self.assertEqual(self.run_cli('history').returncode, 2)
        runs.unlink()
        runs.mkdir()
        (runs / 'latest').symlink_to(self.base / 'absent-pointer')
        self.assertEqual(self.run_cli('history').returncode, 2)

    def test_older_self_contained_source_does_not_require_unused_cli_helper(self):
        for name in ['install.sh', 'uninstall.sh', 'PRODUCT']:
            shutil.copy2(ROOT / name, self.app / name)
        (self.app / 'tests').mkdir()
        (self.app / 'lib/cli.sh').unlink()
        (self.app / 'presswarden').write_text('#!/usr/bin/env bash\nprintf "legacy fixture\\n"\n')
        (self.app / 'lib/env-discovery.sh').write_text('#!/usr/bin/env bash\n# self-contained fixture\n')
        result = subprocess.run(['bash', '-c', '. "$1/lib/update.sh"; _pw_update_validate_source "$2"',
                                 '_', str(ROOT), str(self.app)], env=self.env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        destination = self.base / 'installation'
        result = subprocess.run(['bash', str(ROOT / 'install.sh')],
                                env=dict(self.env, PRESSWARDEN_INSTALL_SOURCE=str(self.app),
                                         PRESSWARDEN_INSTALL_PREFIX=str(destination)),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((destination / 'presswarden').read_text(),
                         (self.app / 'presswarden').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
