#!/usr/bin/env python3
"""Synthetic regressions for check_test_id_map.py; never runs cargo."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('check_test_id_map.py').resolve()
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('check_test_id_map', SCRIPT)
idmap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = idmap
spec.loader.exec_module(idmap)

GIT_ENV = {
    **os.environ,
    'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
}
RUNNER = SCRIPT.with_name('ci_runtime_tests.py').read_text(encoding='utf-8')
HEADER = 'target\told_test\tnew_test\n'
LIB = 'crates/demo/src/lib.rs'


class Repo:
    def __init__(self, test):
        temp = tempfile.TemporaryDirectory()
        test.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git('init', '-q', '-b', 'main')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, env=GIT_ENV,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def commit(self, files):
        for name, text in files.items():
            path = self.root / name
            if text is None:
                path.unlink(missing_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        self.git('add', '-A')
        self.git('commit', '-q', '--allow-empty', '-m', 'step')
        return self.git('rev-parse', 'HEAD')


def tests_file(*names):
    return ''.join(f'#[test]\nfn {name}() {{}}\n\n' for name in names)


class TestIdMapTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo(self)
        self.base = self.repo.commit({
            'scripts/ci_runtime_tests.py': RUNNER,
            'scripts/test_id_renames.tsv': HEADER,
            'crates/demo/Cargo.toml': '[package]\nname = "demo"\n',
            LIB: 'mod snapshots;\n',
            'crates/demo/src/snapshots.rs': '#[cfg(test)]\nmod tests {\n    mod scan_tests;\n}\n',
            'crates/demo/src/snapshots/tests/scan_tests.rs': tests_file('reads_lines', 'skips_blank'),
            'crates/demo/src/snapshots/money_tests.rs': tests_file('charges_once'),
        })

    def reset(self):
        """Put the working tree back to the base commit before the next head."""
        self.repo.git('read-tree', '-u', '--reset', self.base)

    def run_check(self, head, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = idmap.main(['--repo', str(self.repo.root), '--base', self.base, '--head', head, *extra])
        return status, out.getvalue() + err.getvalue()

    def moved(self, rows=''):
        return {
            'crates/demo/src/snapshots.rs': '#[cfg(test)]\nmod tests;\n',
            'crates/demo/src/snapshots/tests.rs': 'mod scan;\n',
            'crates/demo/src/snapshots/tests/scan_tests.rs': None,
            'crates/demo/src/snapshots/tests/scan.rs': tests_file('reads_lines', 'skips_blank'),
            'scripts/test_id_renames.tsv': HEADER + rows,
        }

    def test_static_ids_follow_mod_path_and_inline_modules(self):
        source = idmap.rst.GitSource(self.repo.root, self.base)
        self.addCleanup(source.close)
        self.assertEqual(idmap.test_ids(source, 'crates/demo')[LIB], {
            'snapshots::tests::scan_tests::reads_lines': 1,
            'snapshots::tests::scan_tests::skips_blank': 1,
        })

    def test_a_rename_needs_exactly_one_added_row(self):
        rows = (f'{LIB}\tsnapshots::tests::scan_tests::reads_lines\tsnapshots::tests::scan::reads_lines\n'
                f'{LIB}\tsnapshots::tests::scan_tests::skips_blank\tsnapshots::tests::scan::skips_blank\n')
        status, out = self.run_check(self.repo.commit(self.moved(rows)))
        self.assertEqual(status, 0, out)
        self.assertIn('2 tests at base, 2 at head, 2 renamed', out)
        self.reset()
        status, out = self.run_check(self.repo.commit(self.moved(rows.splitlines(True)[0])))
        self.assertEqual(status, 1)
        self.assertIn('test without a new ID: snapshots::tests::scan_tests::skips_blank', out)
        self.assertIn(f'{LIB}\tsnapshots::tests::scan_tests::skips_blank\tsnapshots::tests::scan::skips_blank', out)

    def test_wrong_rows_and_changed_test_sets_fail(self):
        wrong_leaf = f'{LIB}\tsnapshots::tests::scan_tests::reads_lines\tsnapshots::tests::scan::skips_blank\n'
        status, out = self.run_check(self.repo.commit(self.moved(wrong_leaf)))
        self.assertEqual(status, 1)
        self.assertIn('row renames the test function', out)
        self.reset()
        head = self.repo.commit({'crates/demo/src/snapshots/tests/scan_tests.rs':
                                 tests_file('reads_lines', 'skips_blank', 'extra')})
        status, out = self.run_check(head)
        self.assertEqual(status, 1)
        self.assertIn('2 tests at base, 3 at head', out)
        self.assertIn("only at head ['extra']", out)

    def test_existing_rows_may_not_change(self):
        row = f'{LIB}\ta::old\ta::new\n'
        self.base = self.repo.commit({'scripts/test_id_renames.tsv': HEADER + row})
        status, out = self.run_check(self.repo.commit({'scripts/test_id_renames.tsv': HEADER}))
        self.assertEqual(status, 1)
        self.assertIn('existing row removed or changed', out)

    def test_a_move_out_of_a_money_module_changes_the_never_retry_decision(self):
        rows = f'{LIB}\tsnapshots::tests::scan_tests::reads_lines\tsnapshots::tests::scan::reads_lines\n'
        head = self.repo.commit({
            'crates/demo/src/snapshots/tests/scan_tests.rs': tests_file('skips_blank'),
            'crates/demo/src/snapshots/tests/scan.rs': tests_file('reads_lines'),
            'crates/demo/src/snapshots.rs': '#[cfg(test)]\nmod tests {\n    mod scan_tests;\n    mod scan;\n}\n',
            'scripts/test_id_renames.tsv': HEADER + rows,
            'scripts/ci_runtime_tests.py': RUNNER.replace('"money_oracle",', '"money_oracle",\n    "scan",'),
        })
        status, out = self.run_check(head)
        self.assertEqual(status, 1)
        self.assertIn('never-retry changes for snapshots::tests::scan_tests::reads_lines -> '
                      'snapshots::tests::scan::reads_lines: False -> True', out)

    def test_report_mode_and_no_rust_change(self):
        head = self.repo.commit({'crates/demo/src/snapshots/money_tests.rs': None})
        status, out = self.run_check(head, '--report')
        self.assertEqual(status, 0)
        self.assertIn('report only', out)
        self.base = head
        status, out = self.run_check(self.repo.commit({'README.md': 'docs\n'}))
        self.assertEqual(status, 0)
        self.assertIn('nothing to compare', out)


if __name__ == '__main__':
    unittest.main()
