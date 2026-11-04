#!/usr/bin/env python3
"""Synthetic regressions for check_source_layout.py."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name('check_source_layout.py').resolve()
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('check_source_layout', SCRIPT)
layout = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = layout
spec.loader.exec_module(layout)

GIT_ENV = {
    **os.environ,
    'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
}
SRC = 'crates/ottto-service/src'
CLEAN = {
    'crates/ottto-service/Cargo.toml': '',
    f'{SRC}/lib.rs': 'pub mod snapshots;\n',
    f'{SRC}/snapshots.rs': '//! Snapshots.\n\nmod state_v2;\nmod wire;\nmod tests;\n',
    f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\n',
    f'{SRC}/snapshots/wire/frame.rs': '//! Frames.\n',
    f'{SRC}/snapshots/tests.rs': 'mod frame_tests;\n',
    f'{SRC}/snapshots/tests/frame_tests.rs': 'fn t() {}\n',
    f'{SRC}/snapshots/tests/fixtures/frame.json': '{}\n',
    f'{SRC}/snapshots/state_v2.rs': '//! State.\n\nmod sqlite;\n',
    f'{SRC}/snapshots/state_v2/sqlite.rs': '//! SQLite.\n',
    f'{SRC}/snapshots/state_v2/sqlite/migrations/0001_init.sql': 'select 1;\n',
    'scripts/source_layout_limits.tsv': '# path\tmax_lines\n',
    'scripts/source_layout_includes.tsv': '# file\tkind\tliteral\n',
}


class LayoutTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write(CLEAN)

    def write(self, files):
        for name, text in files.items():
            path = self.root / name
            if text is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, env=GIT_ENV,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def commit(self):
        if not (self.root / '.git').exists():
            self.git('init', '-q', '-b', 'main')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'step')
        return self.git('rev-parse', 'HEAD')

    def run_check(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = layout.main(['--root', str(self.root), *extra])
        return status, out.getvalue() + err.getvalue()

    def findings(self, *extra):
        status, out = self.run_check(*extra)
        lines = [line for line in out.splitlines() if line.count(': ') >= 2 and ': note: ' not in line]
        return status, [line.removeprefix('source-layout: ').replace(f'{SRC}/', '') for line in lines], out

    def test_a_clean_tree_reports_nothing_and_exits_zero(self):
        status, found, out = self.findings()
        self.assertEqual((status, found), (0, []), out)
        self.assertIn('size 0, tree 0, budget 0, path-include 0, names 0, header 0, stutter 0', out)
        self.assertIn('report only', out)

    def test_size_needs_a_row_and_the_ceilings_only_fall(self):
        big = '//! Big.\n' + 'fn f() {}\n' * 20
        self.write({f'{SRC}/snapshots/wire/frame.rs': big})
        with mock.patch.object(layout, 'MAX_LINES', 10), mock.patch.object(layout, 'NOTE_LINES', 5):
            _, found, _ = self.findings()
            self.assertEqual(found, [('size: snapshots/wire/frame.rs: 21 lines, over 10 and not in '
                                      'scripts/source_layout_limits.tsv')])
            self.write({'scripts/source_layout_limits.tsv': f'{SRC}/snapshots/wire/frame.rs\t21\n'})
            base = self.commit()
            _, found, _ = self.findings('--base', base)
            self.assertEqual(found, [])
            self.write({'scripts/source_layout_limits.tsv': f'{SRC}/snapshots/wire/frame.rs\t30\n'})
            _, found, _ = self.findings('--base', base)
            self.assertIn('size: snapshots/wire/frame.rs: ceiling rose from 21 to 30', found)
            self.write({f'{SRC}/snapshots/wire/frame.rs': big + 'fn g() {}\n' * 10})
            _, found, _ = self.findings('--base', base)
            self.assertIn('size: snapshots/wire/frame.rs: 31 lines, over its ceiling of 30 in '
                          'scripts/source_layout_limits.tsv', found)

    def test_tree_rules(self):
        self.write({
            f'{SRC}/snapshots/stray.rs': '//! Stray.\n',
            f'{SRC}/snapshots/orphan/inner.rs': '//! Inner.\n',
            f'{SRC}/snapshots/notes.txt': 'x\n',
            f'{SRC}/snapshots/wire/frame/mod.rs': '//! Old style.\n',
        })
        _, found, _ = self.findings()
        self.assertEqual(sorted(f for f in found if f.startswith('tree')), [
            'tree: snapshots/notes.txt: not a .rs file outside tests/fixtures/ and state_v2/sqlite/migrations/*.sql',
            'tree: snapshots/orphan/inner.rs: not reachable by mod from the crate root',
            'tree: snapshots/orphan: module directory without orphan.rs',
            'tree: snapshots/stray.rs: not reachable by mod from the crate root',
            'tree: snapshots/wire/frame/mod.rs: mod.rs; name the module file after its directory',
            'tree: snapshots/wire/frame/mod.rs: not reachable by mod from the crate root',
        ])

    def test_budget_rules(self):
        files = {f'{SRC}/snapshots/wire/f{i:02}.rs': '//! F.\n' for i in range(25)}
        files[f'{SRC}/snapshots/wire.rs'] = '//! Wire.\n\nmod frame;\n' + ''.join(f'mod f{i:02};\n' for i in range(25))
        files[f'{SRC}/snapshots/wire/frame.rs'] = '//! Frames.\n\nmod a;\n'
        files[f'{SRC}/snapshots/wire/frame/a.rs'] = '//! A.\n\nmod b;\n'
        files[f'{SRC}/snapshots/wire/frame/a/b.rs'] = '//! B.\n'
        self.write(files)
        _, found, _ = self.findings()
        self.assertEqual([f for f in found if f.startswith('budget')], [
            'budget: snapshots/wire: 27 entries, over 25',
            'budget: snapshots/wire/frame/a/b.rs: module depth 4, over 3',
        ])

    def test_path_and_include_need_a_row_and_the_list_only_shrinks(self):
        root = CLEAN[f'{SRC}/snapshots.rs'] + '#[path = "snapshots/extra.rs"]\nmod extra;\n'
        self.write({f'{SRC}/snapshots.rs': root, f'{SRC}/snapshots/extra.rs': '//! Extra.\n'})
        _, found, _ = self.findings()
        self.assertEqual(found, [('path-include: snapshots.rs: #[path] "snapshots/extra.rs" is not in '
                                  'scripts/source_layout_includes.tsv')])
        self.write({'scripts/source_layout_includes.tsv': f'{SRC}/snapshots.rs\tpath\tsnapshots/extra.rs\n'})
        base = self.commit()
        _, found, _ = self.findings('--base', base)
        self.assertEqual(found, [])
        self.write({'scripts/source_layout_includes.tsv': f'{SRC}/snapshots.rs\tpath\tsnapshots/extra.rs\n'
                                                          f'{SRC}/snapshots.rs\tinclude\tsnapshots/other.rs\n'})
        _, found, _ = self.findings('--base', base)
        self.assertEqual(found, ['path-include: scripts/source_layout_includes.tsv: 2 rows, up from 1 at base',
                                 ('path-include: snapshots.rs: row "snapshots/other.rs" in '
                                  'scripts/source_layout_includes.tsv is new, not a relocated row')])
        # Swapping a row for a new include keeps the count but is still new.
        self.write({'scripts/source_layout_includes.tsv': f'{SRC}/snapshots.rs\tinclude\tsnapshots/other.rs\n'})
        _, found, _ = self.findings('--base', base)
        self.assertIn('path-include: snapshots.rs: row "snapshots/other.rs" in '
                      'scripts/source_layout_includes.tsv is new, not a relocated row', found)
        # A row whose include moved with its file is a relocation.
        self.write({f'{SRC}/snapshots.rs': CLEAN[f'{SRC}/snapshots.rs'] + 'mod wire_moved;\n',
                    f'{SRC}/snapshots/wire_moved.rs': '//! Moved.\n\n#[path = "inner/extra.rs"]\nmod extra;\n',
                    f'{SRC}/snapshots/wire_moved/inner/extra.rs': '//! Extra.\n',
                    f'{SRC}/snapshots/extra.rs': None,
                    'scripts/source_layout_includes.tsv': f'{SRC}/snapshots/wire_moved.rs\tpath\tinner/extra.rs\n'})
        _, found, _ = self.findings('--base', base)
        self.assertEqual([f for f in found if f.startswith('path-include')], [])

    def test_name_header_and_stutter_rules(self):
        self.write({
            f'{SRC}/snapshots.rs': CLEAN[f'{SRC}/snapshots.rs'] + 'mod shared_value;\nmod e2_retry;\nmod safe_read;\n',
            f'{SRC}/snapshots/shared_value.rs': '//! Shared.\n',
            f'{SRC}/snapshots/e2_retry.rs': '//! Coded.\n',
            f'{SRC}/snapshots/safe_read.rs': '// No module doc.\nfn f() {}\n',
            f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\nmod wire_codec;\nmod kinds_misc;\n',
            f'{SRC}/snapshots/wire/wire_codec.rs': '//! Codec.\n',
            f'{SRC}/snapshots/wire/kinds_misc.rs': '//! Allowed.\n',
        })
        _, found, _ = self.findings()
        self.assertEqual(sorted(found), [
            'header: snapshots/safe_read.rs: no //! module doc at the top',
            'names: snapshots/e2_retry.rs: coded stem e2',
            'names: snapshots/shared_value.rs: generic stem shared',
            'stutter: snapshots/wire/wire_codec.rs: name starts with its directory name wire',
        ])

    def test_enforce_fails_only_on_named_rules(self):
        self.write({f'{SRC}/snapshots/wire/frame.rs': 'fn f() {}\n'})
        status, out = self.run_check('--enforce', 'size,names')
        self.assertEqual(status, 0, out)
        status, out = self.run_check('--enforce', 'header')
        self.assertEqual(status, 1, out)
        self.assertIn('enforced rules with findings: header', out)
        status, out = self.run_check('--enforce', 'sizes')
        self.assertEqual(status, 2)


if __name__ == '__main__':
    unittest.main()
