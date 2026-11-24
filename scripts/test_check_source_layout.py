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
    f'{SRC}/lib.rs': '//! Demo.\n\npub mod snapshots;\n',
    f'{SRC}/snapshots.rs': '//! Snapshots.\n\nmod state_v2;\nmod wire;\nmod tests;\n',
    f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\n',
    f'{SRC}/snapshots/wire/frame.rs': '//! Frames.\n',
    f'{SRC}/snapshots/tests.rs': 'mod frame;\n\n#[test]\nfn hub() {}\n',
    f'{SRC}/snapshots/tests/frame.rs': '#[test]\nfn t() {}\n',
    f'{SRC}/snapshots/tests/fixtures/frame.json': '{}\n',
    f'{SRC}/snapshots/state_v2.rs': '//! State.\n\nmod sqlite;\n',
    f'{SRC}/snapshots/state_v2/sqlite.rs': '//! SQLite.\n',
    f'{SRC}/snapshots/state_v2/sqlite/migrations/0001_init.sql': 'select 1;\n',
    'scripts/source_layout_limits.tsv': '# path\tmax_lines\n',
    'scripts/source_layout_includes.tsv': '# file\tkind\tliteral\n',
    'scripts/source_layout_flat.tsv': '# directory\tmax_rs_files\n',
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
        # The `enforced: <rules>` and `enforced rules with findings: <rules>` status lines are not findings.
        lines = [line for line in out.splitlines() if line.count(': ') >= 2 and ': note: ' not in line
                 and not line.startswith('source-layout: enforced')]
        return status, [line.removeprefix('source-layout: ').replace(f'{SRC}/', '') for line in lines], out

    def test_a_clean_tree_reports_nothing_and_exits_zero(self):
        status, found, out = self.findings()
        self.assertEqual((status, found), (0, []), out)
        self.assertIn('size 0, tree 0, budget 0, path-include 0, names 0, header 0, stutter 0, tests 0, '
                      'isolation 0, test-stem 0, flat 0', out)
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
        # Three directories below snapshots/ (like sources/claude/census/x.rs) is within budget.
        files[f'{SRC}/snapshots/wire/frame/a/b.rs'] = '//! B.\n\nmod c;\n'
        files[f'{SRC}/snapshots/wire/frame/a/b/c.rs'] = '//! C.\n'
        self.write(files)
        _, found, _ = self.findings()
        self.assertEqual([f for f in found if f.startswith('budget')], [
            'budget: snapshots/wire: 27 entries, over 25',
            'budget: snapshots/wire/frame/a/b/c.rs: module depth 4, over 3',
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

    def test_tests_only_in_tests_rs_or_a_tests_dir(self):
        self.write({
            f'{SRC}/snapshots/wire.rs': ('//! Wire.\n\nmod frame;\nmod tests;\n\n'
                                         '#[cfg(test)]\nmod inline {\n    #[test]\n    fn a() {}\n\n'
                                         '    #[tokio::test]\n    async fn b() {}\n}\n'),
            # Comments, strings and `#[cfg(test)]` are not tests.
            f'{SRC}/snapshots/wire/frame.rs': ('//! Frames.\n\n// #[test]\nconst S: &str = "#[test]";\n\n'
                                               '#[cfg(test)]\nmod tests;\n'),
            f'{SRC}/snapshots/wire/frame/tests.rs': '#[test]\nfn c() {}\n',
            f'{SRC}/snapshots/wire/tests.rs': '#[test]\nfn d() {}\n',
        })
        _, found, _ = self.findings()
        self.assertEqual([f for f in found if f.startswith('tests')], [
            'tests: snapshots/wire.rs: 2 #[test] outside tests.rs, tests/ and an inline mod tests',
        ])

    def test_a_files_own_inline_mod_tests_is_not_a_finding(self):
        self.write({f'{SRC}/snapshots/wire/frame.rs': ('//! Frames.\n\nfn f() {}\n\n#[cfg(test)]\nmod tests {\n'
                                                       '    #[test]\n    fn a() {}\n}\n')})
        _, found, _ = self.findings()
        self.assertEqual(found, [])

    def test_the_whole_crate_is_in_scope(self):
        self.write({
            f'{SRC}/lib.rs': '//! Demo.\n\npub mod snapshots;\nmod relay;\nmod e2_probe;\n',
            f'{SRC}/relay.rs': 'mod sender_tests;\n',
            f'{SRC}/relay/sender_tests.rs': '#[test]\nfn t() {}\n',
            f'{SRC}/relay/legacy/mod.rs': '//! Old style.\n',
            f'{SRC}/e2_probe.rs': '//! Coded.\n',
            f'{SRC}/shim.c': 'int x;\n',
            f'{SRC}/relay/notes.txt': 'x\n',
        })
        _, found, _ = self.findings()
        self.assertEqual(sorted(found), [
            'header: relay.rs: no //! module doc at the top',
            'names: e2_probe.rs: coded stem e2',
            'test-stem: relay/sender_tests.rs: stem ends in _tests; use tests.rs or tests/<topic>.rs',
            'tests: relay/sender_tests.rs: 1 #[test] outside tests.rs, tests/ and an inline mod tests',
            'tree: relay/legacy/mod.rs: mod.rs; name the module file after its directory',
            'tree: relay/legacy/mod.rs: not reachable by mod from the crate root',
            'tree: relay/legacy: module directory without legacy.rs',
            'tree: relay/notes.txt: not a .rs file outside tests/fixtures/ and state_v2/sqlite/migrations/*.sql',
        ])

    def test_isolation_keeps_each_source_to_its_own_paths(self):
        self.write({
            f'{SRC}/snapshots.rs': CLEAN[f'{SRC}/snapshots.rs'] + 'mod sources;\nmod scan;\n',
            f'{SRC}/snapshots/sources.rs': '//! Sources.\n\nmod claude;\nmod codex;\n',
            f'{SRC}/snapshots/sources/claude.rs': ('//! Claude.\n\nmod census;\n\n'
                                                  'use crate::snapshots::sources::codex::Line;\n'),
            # Its own source, comments and strings are fine.
            f'{SRC}/snapshots/sources/claude/census.rs': ('//! Census.\n\n'
                                                         'use crate::snapshots::sources::claude::Row;\n'
                                                         '// sources::codex::Line\nconst S: &str = "sources::pi";\n'),
            f'{SRC}/snapshots/sources/codex.rs': ('//! Codex.\n\nfn f() {\n    sources::claude::row();\n'
                                                 '    sources::pi::row();\n    sources::claude::other();\n}\n'),
            # Outside a source dir any source may be named.
            f'{SRC}/snapshots/scan.rs': '//! Scan.\n\nuse super::sources::codex::Line;\n',
        })
        _, found, _ = self.findings()
        self.assertEqual([f for f in found if f.startswith('isolation')], [
            'isolation: snapshots/sources/claude.rs: names sources::codex on line(s) 5',
            'isolation: snapshots/sources/codex.rs: names sources::claude on line(s) 4, 6',
            'isolation: snapshots/sources/codex.rs: names sources::pi on line(s) 5',
        ])

    def test_test_stem_flags_files_ending_in_tests(self):
        self.write({
            f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\nmod frame_tests;\n',
            f'{SRC}/snapshots/wire/frame_tests.rs': 'fn t() {}\n',
        })
        _, found, _ = self.findings()
        self.assertEqual([f for f in found if f.startswith('test-stem')], [
            'test-stem: snapshots/wire/frame_tests.rs: stem ends in _tests; use tests.rs or tests/<topic>.rs',
        ])
        # Under a tests/ directory the stem is fine: the folder is what keeps tests apart.
        self.write({f'{SRC}/snapshots/wire/frame_tests.rs': None,
                    f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\n',
                    f'{SRC}/snapshots/tests.rs': 'mod frame;\nmod frame_tests;\n\n#[test]\nfn hub() {}\n',
                    f'{SRC}/snapshots/tests/frame_tests.rs': '#[test]\nfn t() {}\n'})
        _, found, _ = self.findings()
        self.assertEqual(found, [])

    def test_flat_ceilings_hold_and_only_fall(self):
        directory = f'{SRC}/snapshots'
        table = 'scripts/source_layout_flat.tsv'
        self.write({table: f'{directory}\t3\n'})
        base = self.commit()
        status, found, out = self.findings('--enforce', 'flat', '--base', base)
        self.assertEqual((status, found), (0, []), out)
        # A file in a child folder does not count; a file directly in the directory does.
        self.write({f'{SRC}/snapshots/wire/extra.rs': '//! Extra.\n',
                    f'{SRC}/snapshots/wire.rs': '//! Wire.\n\nmod frame;\nmod extra;\n'})
        self.assertEqual(self.findings('--enforce', 'flat', '--base', base)[:2], (0, []))
        self.write({f'{SRC}/snapshots/extra.rs': '//! Extra.\n',
                    f'{SRC}/snapshots.rs': CLEAN[f'{SRC}/snapshots.rs'] + 'mod extra;\n'})
        status, found, out = self.findings('--base', base)
        self.assertEqual(status, 0, out)
        self.assertEqual(found, [f'flat: snapshots: 4 .rs files directly in it, over its ceiling of 3 in {table}; '
                                 'put a new file in the folder of its feature'])
        self.assertEqual(self.run_check('--enforce', 'flat', '--base', base)[0], 1)
        self.write({table: f'{directory}\t4\n'})
        status, found, _ = self.findings('--enforce', 'flat', '--base', base)
        self.assertEqual((status, found), (1, ['flat: snapshots: ceiling rose from 3 to 4']))
        self.write({table: '# directory\tmax_rs_files\n'})
        status, found, _ = self.findings('--enforce', 'flat', '--base', base)
        self.assertEqual((status, found), (1, [f'flat: snapshots: its row is gone from {table}']))
        # Fewer files than the ceiling is a note; the row may fall.
        self.write({table: f'{directory}\t3\n', f'{SRC}/snapshots/extra.rs': None,
                    f'{SRC}/snapshots.rs': CLEAN[f'{SRC}/snapshots.rs']})
        self.commit()
        self.write({table: f'{directory}\t5\n'})
        base = self.commit()
        self.write({table: f'{directory}\t3\n'})
        self.assertEqual(self.findings('--enforce', 'flat', '--base', base)[:2], (0, []))

    def test_enforce_fails_only_on_named_rules(self):
        self.write({f'{SRC}/snapshots/wire/frame.rs': 'fn f() {}\n'})
        status, out = self.run_check('--enforce', 'size,names')
        self.assertEqual(status, 0, out)
        status, out = self.run_check('--enforce', 'header')
        self.assertEqual(status, 1, out)
        self.assertIn('enforced rules with findings: header', out)
        status, out = self.run_check('--enforce', 'sizes')
        self.assertEqual(status, 2)

    def test_new_production_file_line_ceiling_and_warning(self):
        base = self.commit()
        for lines in (1400, 1500, 1501, 2000, 3000, 3001, 3100):
            with self.subTest(lines=lines):
                # Also cover additions outside the snapshots report's scope.
                path = f'crates/demo/src/file_{lines}.rs'
                self.write({path: '//! Module.\n' + '// Line.\n' * (lines - 1)})
                self.commit()
                status, out = self.run_check('--enforce-new', '--base', base)
                self.assertEqual(status, 1 if lines > 3000 else 0, out)
                if 1500 < lines <= 3000:
                    self.assertIn(f'warning: {path}: new file: {lines} lines, over 1500', out)
                elif lines <= 1500:
                    self.assertNotIn(f'warning: {path}:', out)
                else:
                    self.assertIn(f'size: {path}: new file: {lines} lines, over 3000', out)

    def test_new_file_cannot_use_a_limits_row_to_exempt_it(self):
        base = self.commit()
        path = f'{SRC}/snapshots/large.rs'
        self.write({path: '//! Module.\n' * 3100,
                    'scripts/source_layout_limits.tsv': f'{path}\t4000\n'})
        self.commit()
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 1, out)
        self.assertIn(f'{path}: new file: 3100 lines, over 3000', out)

    def test_existing_large_file_stays_report_only(self):
        path = f'{SRC}/snapshots/wire/frame.rs'
        self.write({path: '//! Module.\n' * 3100})
        base = self.commit()
        self.write({path: '//! Module.\n' * 3200})
        self.commit()
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 0, out)
        self.assertIn(f'size: {path}: 3200 lines, over 3000', out)

    def test_exact_move_of_large_file_stays_report_only(self):
        old, moved = 'crates/demo/src/large.rs', f'{SRC}/snapshots/large.rs'
        text = '//! Module.\n' * 3100
        self.write({old: text})
        base = self.commit()
        self.write({old: None, moved: text})
        self.commit()
        self.assertIn('R100', self.git('diff', '--find-renames=100%', '--name-status', base, 'HEAD'))
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 0, out)
        self.assertIn(f'size: {moved}: 3100 lines, over 3000', out)

    def test_new_test_files_are_excluded_from_the_ceiling(self):
        base = self.commit()
        paths = [f'{SRC}/snapshots/large_tests.rs', f'{SRC}/snapshots/wire/tests.rs',
                 f'{SRC}/snapshots/tests/large.rs', 'crates/demo/tests/large.rs']
        self.write({path: f'//! {path}.\n' * 3100 for path in paths})
        self.commit()
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 0, out)
        self.assertNotIn('new file:', out)

    def test_an_added_mod_rs_or_headerless_production_file_fails(self):
        # Existing files that break the same rules stay report-only.
        self.write({f'{SRC}/snapshots/wire/frame.rs': 'fn f() {}\n',
                    f'{SRC}/snapshots/state_v2/mod.rs': '//! Old style.\n'})
        base = self.commit()
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 0, out)
        for name, path, text, message in (
            ('mod.rs', f'{SRC}/snapshots/wire/codec/mod.rs', '//! Codec.\n', 'mod.rs; name the module file'),
            ('no module doc', f'{SRC}/snapshots/wire/codec.rs', 'fn f() {}\n', 'no //! module doc at the top'),
        ):
            with self.subTest(name):
                self.write({path: text})
                self.commit()
                status, out = self.run_check('--enforce-new', '--base', base)
                self.assertEqual(status, 1, out)
                self.assertIn(f'{path}: {message}', out)
                self.assertIn('added files break the rules for new files', out)
                self.git('rm', '-q', path)
                self.commit()
        # A test file needs no module doc, and a good new file passes.
        self.write({f'{SRC}/snapshots/wire/tests.rs': '#[test]\nfn t() {}\n',
                    f'{SRC}/snapshots/wire/codec.rs': '//! Codec.\n'})
        self.commit()
        status, out = self.run_check('--enforce-new', '--base', base)
        self.assertEqual(status, 0, out)

    def test_new_file_enforcement_requires_a_valid_base(self):
        self.commit()
        for extra in ((), ('--base', 'missing-ref')):
            with self.subTest(extra=extra):
                status, out = self.run_check('--enforce-new', *extra)
                self.assertEqual(status, 2, out)


if __name__ == '__main__':
    unittest.main()
