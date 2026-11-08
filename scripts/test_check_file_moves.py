#!/usr/bin/env python3
"""Synthetic regressions for check_file_moves.py: accepted shapes and near misses that must fail."""
import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('check_file_moves.py').resolve()
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('check_file_moves', SCRIPT)
fm = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fm
spec.loader.exec_module(fm)

GIT_ENV = {
    **os.environ,
    'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
}
SRC = 'crates/demo/src/'


def code(text):
    return textwrap.dedent(text).lstrip('\n')


class Repo:
    """A throwaway git repository holding one crate under crates/demo."""

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
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        self.git('add', '-A')
        self.git('commit', '-q', '--allow-empty', '-m', 'step')
        return self.git('rev-parse', 'HEAD')


CARGO = '[package]\nname = "demo"\nedition = "2021"\n\n[dependencies]\nserde = "1"\n'
OLD = code('''
    use crate::snapshots::dest::here;

    pub(crate) fn f() -> u8 {
        here() + 1
    }

    #[cfg(test)]
    mod tests;
''')
OLD_TESTS = code('''
    use super::*;

    #[test]
    fn f_is_one() {
        assert_eq!(f(), 1);
    }
''')
CALLER = code('''
    pub(crate) fn call() -> u8 {
        super::old::f()
    }
''')


def files(**overrides):
    """The base crate: snapshots::{dest, old (+ old::tests), caller}, with `overrides` by short path."""
    tree = {
        'crates/demo/Cargo.toml': CARGO,
        SRC + 'lib.rs': 'mod snapshots;\n',
        SRC + 'snapshots.rs': 'mod caller;\nmod dest;\nmod old;\n',
        SRC + 'snapshots/dest.rs': 'pub(crate) fn here() -> u8 {\n    0\n}\n',
        SRC + 'snapshots/old.rs': OLD,
        SRC + 'snapshots/old/tests.rs': OLD_TESTS,
        SRC + 'snapshots/caller.rs': CALLER,
    }
    for name, text in overrides.items():
        tree[SRC + name] = text
        if text is None:
            del tree[SRC + name]
    return tree


def moved(tree, mapping):
    """Head files: `mapping` old short path -> new short path, bytes unchanged."""
    out = {}
    for old, new in mapping.items():
        out[SRC + new] = tree[SRC + old]
        out[SRC + old] = None
    return out


BASIC_MOVE = {'snapshots/old.rs': 'snapshots/dest/old.rs', 'snapshots/old/tests.rs': 'snapshots/dest/old/tests.rs'}
ALIAS_PARENT = 'mod caller;\nmod dest;\npub(crate) use crate::snapshots::dest::old;\n'
DEST_WITH_OLD = 'pub(crate) fn here() -> u8 {\n    0\n}\n\npub(crate) mod old;\n'


class Base(unittest.TestCase):
    def run_check(self, base, head, mode='move'):
        repo = Repo(self)
        first = repo.commit(base)
        second = repo.commit(head)
        check = fm.check_move if mode == 'move' else fm.check_absolutize
        return check(repo.root, first, second)

    def accept(self, base, head, mode='move'):
        result = self.run_check(base, head, mode)
        self.assertEqual(result.problems, [], '\n'.join(result.lines + result.notes))
        return result

    def reject(self, base, head, needle, mode='move'):
        result = self.run_check(base, head, mode)
        self.assertTrue(result.problems, 'expected a failure:\n' + '\n'.join(result.lines + result.notes))
        self.assertTrue(any(needle in problem for problem in result.problems),
                        f'no problem mentions {needle!r}:\n' + '\n'.join(result.problems))
        return result


class MoveAccepts(Base):
    def test_subtree_move_with_absolute_alias(self):
        base = files()
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        result = self.accept(base, head)
        self.assertTrue(any('crate::snapshots::old -> crate::snapshots::dest::old (alias)' in line
                            for line in result.lines), result.lines)
        self.assertTrue(any('visibility `private` -> `pub(crate)`' in note for note in result.notes), result.notes)

    def test_rename_with_relative_as_alias(self):
        base = files()
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/renamed.rs',
                            'snapshots/old/tests.rs': 'snapshots/dest/renamed/tests.rs'})
        head |= {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\npub(crate) use dest::renamed as old;\n',
                 SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('mod old;', 'mod renamed;')}
        self.accept(base, head)

    def test_move_without_alias_when_nothing_names_it(self):
        base = files(**{'snapshots/caller.rs': 'pub(crate) fn call() -> u8 {\n    7\n}\n'})
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\n',
                                          SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod', 'mod')}
        self.accept(base, head)

    def test_new_parent_globbing_the_old_parent(self):
        dest = 'use super::*;\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'snapshots/dest.rs': dest})
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT,
                                          SRC + 'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'}
        self.accept(base, head)

    def test_inline_modules_and_an_unread_data_file_move_inside_the_subtree(self):
        old = OLD + code('''

            mod inner {
                pub(super) fn g() -> u8 {
                    super::f()
                }
            }
        ''')
        base = files(**{'snapshots/old.rs': old, 'snapshots/old/notes.txt': 'n\n'})
        head = moved(base, BASIC_MOVE | {'snapshots/old/notes.txt': 'snapshots/dest/old/notes.txt'})
        head |= {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        result = self.accept(base, head)
        self.assertTrue(any('1 data files' in line for line in result.lines), result.lines)

    def test_layout_tsv_rides_along(self):
        base = files() | {'scripts/source_layout_limits.tsv': 'path\tlines\n',
                          'scripts/test_id_renames.tsv': 'old\tnew\n'}
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD,
                                          'scripts/source_layout_limits.tsv': 'path\tlines\nx\t1\n',
                                          'scripts/test_id_renames.tsv': 'old\tnew\na\tb\n'}
        result = self.accept(base, head)
        self.assertTrue(any('layout TSV files' in line for line in result.lines))

    def test_same_textual_macro_at_both_declaration_points(self):
        parent = 'macro_rules! m {\n    () => {\n        1\n    };\n}\n\nmod caller;\nmod dest;\nmod old;\n'
        old = OLD.replace('here() + 1', 'here() + m!()')
        base = files(**{'snapshots.rs': parent, 'snapshots/old.rs': old})
        head = moved(base, BASIC_MOVE)
        head |= {SRC + 'snapshots.rs': parent.replace('mod old;\n', 'pub(crate) use crate::snapshots::dest::old;\n'),
                 SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        self.accept(base, head)

    def test_nested_shape_root_gains_mod_for_another_moved_root(self):
        # model -> usage/model.rs gaining `mod upload;`; upload_state -> usage/model/upload.rs; tests follow.
        model = 'pub(crate) fn evidence() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests;\n'
        base = {
            'crates/demo/Cargo.toml': CARGO,
            SRC + 'lib.rs': 'mod snapshots;\n',
            SRC + 'snapshots.rs': 'mod model;\nmod upload_state;\nmod usage;\n',
            SRC + 'snapshots/usage.rs': 'pub(crate) fn total() -> u8 {\n    2\n}\n',
            SRC + 'snapshots/model.rs': model,
            SRC + 'snapshots/model/tests.rs': 'use super::*;\n\n#[test]\nfn one() {\n    assert_eq!(evidence(), 1);\n}\n',
            SRC + 'snapshots/upload_state.rs': 'pub(crate) fn prepare() -> u8 {\n    crate::snapshots::model::evidence()\n}\n',
        }
        head = moved(base, {'snapshots/model/tests.rs': 'snapshots/usage/model/tests.rs',
                            'snapshots/upload_state.rs': 'snapshots/usage/model/upload.rs'})
        head |= {
            SRC + 'snapshots/model.rs': None,
            SRC + 'snapshots/usage/model.rs': model + '\npub(crate) mod upload;\n',
            SRC + 'snapshots.rs': ('pub(crate) use crate::snapshots::usage::model;\n'
                                   'pub(crate) use crate::snapshots::usage::model::upload as upload_state;\n'
                                   'mod usage;\n'),
            SRC + 'snapshots/usage.rs': 'pub(crate) fn total() -> u8 {\n    2\n}\n\npub(crate) mod model;\n',
        }
        result = self.accept(base, head)
        self.assertTrue(any('after removing `mod upload;`' in line for line in result.lines), result.lines)


    def test_std_test_serial_and_thiserror_attributes(self):
        tests = OLD_TESTS + code('''

            #[test]
            #[ignore]
            fn slow() {}

            #[test]
            #[should_panic(expected = "boom")]
            fn boom() {
                panic!("boom");
            }

            #[test]
            #[serial]
            fn serial_one() {}

            #[test]
            #[serial_test::serial]
            fn serial_two() {}
        ''')
        error = code('''

            #[derive(Debug, thiserror::Error)]
            pub(crate) enum Failure {
                #[error("bad value {0}")]
                Bad(u8),
                #[error(transparent)]
                Io(#[from] std::io::Error),
            }
        ''')
        base = files(**{'snapshots/old.rs': OLD + error, 'snapshots/old/tests.rs': tests})
        base['crates/demo/Cargo.toml'] = CARGO + 'serial_test = "3"\nthiserror = "2"\n'
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        self.accept(base, head)

    def test_relative_transcriber_heads_invoked_inside_the_subtree(self):
        extra = code('''

            mod ffi {
                pub(crate) fn x() -> u8 {
                    2
                }
            }

            fn y() -> u8 {
                3
            }

            macro_rules! local {
                () => {
                    ffi::x() + self::y()
                };
            }

            pub(crate) fn g() -> u8 {
                local!()
            }
        ''')
        child = 'macro_rules! via_child {\n    () => {\n        ffi::x()\n    };\n}\n\npub(crate) use via_child;\n'
        old = OLD + extra + '\nmod child;\n\npub(crate) fn h() -> u8 {\n    child::via_child!()\n}\n'
        base = files(**{'snapshots/old.rs': old, 'snapshots/old/child.rs': child})
        head = moved(base, BASIC_MOVE | {'snapshots/old/child.rs': 'snapshots/dest/old/child.rs'})
        head |= {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        self.accept(base, head)

class MoveRejects(Base):
    def basic_head(self, base, **extra):
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        return head | {SRC + name: text for name, text in extra.items()}

    def test_escaping_super(self):
        base = files(**{'snapshots/old.rs': OLD.replace('here() + 1', 'super::dest::here() + 1')})
        self.reject(base, self.basic_head(base), 'reaches above moved')

    def test_spaced_and_commented_super(self):
        for spelled in ('super :: dest::here()', 'super/*x*/::dest::here()', 'self::super::dest::here()'):
            with self.subTest(spelled=spelled):
                base = files(**{'snapshots/old.rs': OLD.replace('here() + 1', f'{spelled} + 1')})
                self.reject(base, self.basic_head(base), 'reaches above moved')

    def test_super_in_inline_tests_reaching_out(self):
        old = OLD + '\n#[cfg(test)]\nmod more {\n    fn g() -> u8 {\n        super::super::dest::here()\n    }\n}\n'
        base = files(**{'snapshots/old.rs': old})
        self.reject(base, self.basic_head(base), 'reaches above moved')

    def test_macro_generated_path(self):
        old = OLD + '\nwrap! {\n    mod fake {\n        fn g() -> u8 {\n            super::super::dest::here()\n        }\n    }\n}\n'
        base = files(**{'snapshots/old.rs': old})
        self.reject(base, self.basic_head(base), 'reaches above moved')
        old = OLD + '\npub(crate) fn s() -> &\'static str {\n    stringify!(super::x)\n}\n'
        base = files(**{'snapshots/old.rs': old})
        self.reject(base, self.basic_head(base), 'reaches above moved')

    def test_path_attribute_inside_moved_file(self):
        old = OLD.replace('mod tests;', '#[path = "tests.rs"]\nmod tests;')
        base = files(**{'snapshots/old.rs': old, 'snapshots/tests.rs': OLD_TESTS, 'snapshots/old/tests.rs': None})
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/old.rs', 'snapshots/tests.rs': 'snapshots/dest/tests.rs'})
        head |= {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        self.reject(base, head, '#[path]')

    def test_include_pointing_outside_the_subtree(self):
        old = OLD + '\nconst DATA: &str = include_str!("data.txt");\n'
        base = files(**{'snapshots/old.rs': old, 'snapshots/data.txt': 'x\n'})
        self.reject(base, self.basic_head(base), 'its relative path would name another file')
        old = OLD + '\nconst DATA: &str = include_str!(concat!("da", "ta.txt"));\n'
        base = files(**{'snapshots/old.rs': old, 'snapshots/data.txt': 'x\n'})
        self.reject(base, self.basic_head(base), 'without one plain string literal')

    def test_edited_rename(self):
        base = files()
        head = self.basic_head(base, **{'snapshots/dest/old.rs': OLD.replace('+ 1', '+ 2')})
        self.reject(base, head, 'has no exact move')

    def test_item_swap_between_moved_and_decoy(self):
        base = files(**{'snapshots/decoy.rs': 'fn local() -> u8 {\n    2\n}\n',
                        'snapshots.rs': 'mod caller;\nmod decoy;\nmod dest;\nmod old;\n',
                        'snapshots/old.rs': OLD + '\nfn local() -> u8 {\n    1\n}\n'})
        head = self.basic_head(base, **{
            'snapshots/dest/old.rs': OLD + '\nfn local() -> u8 {\n    2\n}\n',
            'snapshots/decoy.rs': 'fn local() -> u8 {\n    1\n}\n',
            'snapshots.rs': 'mod caller;\nmod decoy;\nmod dest;\npub(crate) use crate::snapshots::dest::old;\n'})
        self.reject(base, head, 'has no exact move')

    def test_exact_exchange_of_two_files(self):
        a = 'pub(crate) fn v() -> u8 {\n    1\n}\n' + ''.join(f'fn pad_a{i}() {{}}\n' for i in range(40))
        b = 'pub(crate) fn v() -> u8 {\n    2\n}\n' + ''.join(f'fn pad_b{i}() {{}}\n' for i in range(40))
        base = files(**{'snapshots/a.rs': a, 'snapshots/b.rs': b,
                        'snapshots.rs': 'mod a;\nmod b;\nmod caller;\nmod dest;\nmod old;\n'})
        head = {SRC + 'snapshots/a.rs': b, SRC + 'snapshots/b.rs': a}
        self.reject(base, head, 'edited, but nothing moved')

    def test_permutation_through_moves(self):
        a = 'pub(crate) fn v() -> u8 {\n    1\n}\n'
        b = 'pub(crate) fn v() -> u8 {\n    2\n}\n'
        base = files(**{'snapshots/a.rs': a, 'snapshots/b.rs': b,
                        'snapshots.rs': 'mod a;\nmod b;\nmod caller;\nmod dest;\nmod old;\n'})
        # a.rs -> dest/b.rs and b.rs -> dest/a.rs, with aliases that swap the names.
        head = moved(base, {'snapshots/a.rs': 'snapshots/dest/b.rs', 'snapshots/b.rs': 'snapshots/dest/a.rs'})
        head |= {SRC + 'snapshots.rs': ('pub(crate) use crate::snapshots::dest::b as b;\n'
                                        'pub(crate) use crate::snapshots::dest::a as a;\nmod caller;\nmod dest;\nmod old;\n'),
                 SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('mod old;', 'mod a;\npub(crate) mod b;')}
        self.reject(base, head, 'not moved')

    def test_copy_with_source_kept(self):
        upload = 'pub(crate) struct T;\n' + ''.join(f'fn pad{i}() {{}}\n' for i in range(40))
        base = files(**{'snapshots/upload.rs': upload,
                        'snapshots.rs': 'mod caller;\nmod dest;\nmod old;\nmod upload;\n'})
        head = {SRC + 'snapshots/upload/nested.rs': upload,
                SRC + 'snapshots/upload.rs': 'pub(crate) mod nested;\n' + upload.replace('struct T', 'struct U')}
        self.reject(base, head, 'is not an exact move')

    def test_alias_to_a_different_module(self):
        base = files(**{'snapshots.rs': 'mod caller;\nmod dest;\nmod old;\nmod y;\n',
                        'snapshots/y.rs': 'pub(crate) fn f() -> u8 {\n    9\n}\n'})
        head = self.basic_head(base, **{'snapshots.rs': 'mod caller;\nmod dest;\nuse self::y as old;\nmod y;\n'})
        self.reject(base, head, 'not moved')

    def test_alias_through_a_use_binding(self):
        base = files(**{'snapshots.rs': 'mod caller;\nmod dest;\nmod old;\nuse dest as d;\n'})
        head = self.basic_head(base, **{'snapshots.rs': 'mod caller;\nmod dest;\npub(crate) use d::old;\nuse dest as d;\n'})
        self.reject(base, head, 'alias path')

    def test_alias_with_cfg_split_segment(self):
        base = files(**{'snapshots.rs': 'mod caller;\n#[cfg(not(test))]\nuse other as dest;\n#[cfg(test)]\nmod dest;\nmod old;\n'})
        head = self.basic_head(base, **{
            'snapshots.rs': ('mod caller;\n#[cfg(not(test))]\nuse other as dest;\n#[cfg(test)]\nmod dest;\n'
                             'pub(crate) use dest::old;\n')})
        self.reject(base, head, 'alias path')

    def test_alias_visibility_and_braces(self):
        base = files()
        head = self.basic_head(base, **{'snapshots.rs': 'mod caller;\nmod dest;\npub use crate::snapshots::dest::old;\n'})
        self.reject(base, head, 'alias visibility')
        head = self.basic_head(base, **{'snapshots.rs': 'mod caller;\nmod dest;\npub(crate) use crate::snapshots::dest::{old};\n'})
        self.reject(base, head, 'one plain')

    def test_new_parent_glob_could_bind_the_name(self):
        fallback = 'pub(crate) mod old {\n    pub(crate) fn f() -> u8 {\n        5\n    }\n}\n'
        dest = 'use crate::fallback::*;\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'lib.rs': 'mod fallback;\nmod snapshots;\n', 'fallback.rs': fallback, 'snapshots/dest.rs': dest})
        head = self.basic_head(base, **{'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'})
        self.reject(base, head, 'may bind the new name')

    def test_old_name_without_alias_under_old_parent_glob(self):
        parent = 'use crate::fallback::*;\nmod caller;\nmod dest;\nmod old;\n'
        base = files(**{'lib.rs': 'mod fallback;\nmod snapshots;\n', 'fallback.rs': 'pub(crate) mod old {}\n',
                        'snapshots.rs': parent, 'snapshots/caller.rs': 'pub(crate) fn call() -> u8 {\n    7\n}\n'})
        head = moved(base, BASIC_MOVE) | {
            SRC + 'snapshots.rs': parent.replace('mod old;\n', ''),
            SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod', 'mod')}
        self.reject(base, head, 'needs an alias')

    def test_declaration_retarget_without_moves(self):
        base = {'crates/demo/Cargo.toml': CARGO,
                SRC + 'lib.rs': 'mod a;\nmod b;\nmod caller;\n',
                SRC + 'a.rs': 'pub(crate) fn v() -> u8 {\n    1\n}\n',
                SRC + 'b.rs': 'pub(crate) fn v() -> u8 {\n    2\n}\n',
                SRC + 'caller.rs': 'pub(crate) fn f() -> u8 {\n    crate::a::v()\n}\n'}
        head = {SRC + 'lib.rs': '#[path = "b.rs"]\nmod a;\n#[path = "a.rs"]\nmod b;\nmod caller;\n'}
        self.reject(base, head, 'nothing moved')

    def test_multi_context_path_and_include(self):
        base = files(**{'lib.rs': 'mod other;\nmod snapshots;\n',
                        'other.rs': '#[path = "snapshots/old.rs"]\nmod old;\n'})
        head = self.basic_head(base, **{'other.rs': '#[path = "snapshots/dest/old.rs"]\nmod old;\n'})
        self.reject(base, head, 'module contexts')
        old = OLD + '\ninclude!("old/part.rs");\n'
        base = files(**{'snapshots/old.rs': old, 'snapshots/old/part.rs': 'fn part() {}\n',
                        'lib.rs': 'mod other;\nmod snapshots;\n', 'other.rs': 'include!("snapshots/old/part.rs");\n'})
        head = self.basic_head(base, **{'other.rs': 'include!("snapshots/dest/old/part.rs");\n'})
        head |= moved(base, {'snapshots/old/part.rs': 'snapshots/dest/old/part.rs'})
        self.reject(base, head, 'reached through include!')

    def test_glue_edits(self):
        base = files()
        head = self.basic_head(base, **{'snapshots/dest.rs': DEST_WITH_OLD.replace('0\n', '1\n')})
        self.reject(base, head, 'edited beyond mod items')
        head = self.basic_head(base, **{'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod old;',
                                                                                   '#[cfg(test)]\npub(crate) mod old;')})
        self.reject(base, head, 'attributes change')
        head = moved(base, BASIC_MOVE) | {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\n',
                                          SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod', 'pub mod')}
        self.reject(base, head, 'visibility')
        head = self.basic_head(base, **{'snapshots/caller.rs': CALLER.replace('f()', 'f() + 0')})
        self.reject(base, head, 'neither glue nor a layout TSV')
        head = self.basic_head(base, **{'snapshots.rs': ALIAS_PARENT + 'use std::fmt;\n'})
        self.reject(base, head, 'does not restore the old name')

    def test_subtree_file_left_behind(self):
        base = files()
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/old.rs'})
        head |= {SRC + 'snapshots.rs': ALIAS_PARENT, SRC + 'snapshots/dest.rs': DEST_WITH_OLD}
        self.reject(base, head, 'does not move')

    def test_name_shadows_an_extern_crate(self):
        base = files(**{'snapshots/caller.rs': 'pub(crate) fn call() -> u8 {\n    7\n}\n'})
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/serde.rs',
                            'snapshots/old/tests.rs': 'snapshots/dest/serde/tests.rs'})
        head |= {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\n',
                 SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod old', 'mod serde')}
        self.reject(base, head, 'extern crate, prelude (edition 2021) or primitive')

    def test_macro_expanded_import_in_new_parent(self):
        dest = ('macro_rules! imports {\n    () => {\n        use crate::fallback::*;\n    };\n}\n\nimports!();\n\n'
                'pub(crate) fn here() -> u8 {\n    0\n}\n')
        base = files(**{'lib.rs': 'mod fallback;\nmod snapshots;\n', 'fallback.rs': 'pub(crate) mod old {}\n',
                        'snapshots/dest.rs': dest})
        head = self.basic_head(base, **{'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'})
        self.reject(base, head, 'not on the item macro allowlist')

    def test_renamed_under_globbing_new_parent(self):
        dest = 'use super::*;\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'snapshots/dest.rs': dest})
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/renamed.rs',
                            'snapshots/old/tests.rs': 'snapshots/dest/renamed/tests.rs'})
        head |= {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\npub(crate) use dest::renamed as old;\n',
                 SRC + 'snapshots/dest.rs': dest + '\npub(crate) mod renamed;\n'}
        self.reject(base, head, 'renamed module under a new parent with glob imports')

    def test_textual_macro_differs(self):
        macro = 'macro_rules! m {{\n    () => {{\n        {}\n    }};\n}}\n\n'
        parent = macro.format(1) + 'mod caller;\nmod dest;\nmod old;\n'
        old = OLD.replace('here() + 1', 'here() + m!()')
        base = files(**{'snapshots.rs': parent, 'snapshots/old.rs': old,
                        'snapshots/dest.rs': macro.format(2) + 'pub(crate) fn here() -> u8 {\n    0\n}\n'})
        head = moved(base, BASIC_MOVE) | {
            SRC + 'snapshots.rs': parent.replace('mod old;\n', 'pub(crate) use crate::snapshots::dest::old;\n'),
            SRC + 'snapshots/dest.rs': macro.format(2) + DEST_WITH_OLD}
        self.reject(base, head, 'bare m!')

    def test_nested_shape_name_already_used(self):
        model = 'pub(crate) fn evidence() -> u8 {\n    upload()\n}\n\nfn upload() -> u8 {\n    1\n}\n'
        base = {'crates/demo/Cargo.toml': CARGO, SRC + 'lib.rs': 'mod snapshots;\n',
                SRC + 'snapshots.rs': 'mod model;\nmod upload_state;\nmod usage;\n',
                SRC + 'snapshots/usage.rs': '', SRC + 'snapshots/model.rs': model,
                SRC + 'snapshots/upload_state.rs': 'pub(crate) fn prepare() {}\n'}
        head = moved(base, {'snapshots/upload_state.rs': 'snapshots/usage/model/upload.rs'})
        head |= {SRC + 'snapshots/model.rs': None, SRC + 'snapshots/usage/model.rs': model + '\nmod upload;\n',
                 SRC + 'snapshots.rs': 'mod usage;\n', SRC + 'snapshots/usage.rs': 'mod model;\n'}
        self.reject(base, head, 'is not an exact move')

    def test_r1_shape_reuses_the_upload_state_path(self):
        # The planned R1: model -> usage/cache_observations.rs, whose old upload state moves to its child.
        model = 'pub(crate) fn evidence() -> u8 {\n    1\n}\n'
        upload = 'pub(crate) fn prepare() -> u8 {\n    crate::snapshots::cache_observations::evidence()\n}\n'
        base = {'crates/demo/Cargo.toml': CARGO, SRC + 'lib.rs': 'mod snapshots;\n',
                SRC + 'snapshots.rs': 'pub(crate) mod cache_observations;\nmod usage;\nuse usage::cache_observations::prepare;\n',
                SRC + 'snapshots/cache_observations.rs': model,
                SRC + 'snapshots/usage.rs': 'pub(super) mod cache_observations;\n',
                SRC + 'snapshots/usage/cache_observations.rs': upload}
        head = {SRC + 'snapshots/cache_observations.rs': None,
                SRC + 'snapshots/usage/cache_observations.rs': model + '\npub(crate) mod upload;\n',
                SRC + 'snapshots/usage/cache_observations/upload.rs': upload,
                SRC + 'snapshots.rs': ('pub(crate) use usage::cache_observations;\nmod usage;\n'
                                       'use usage::cache_observations::upload::prepare;\n'),
                SRC + 'snapshots/usage.rs': 'pub(crate) mod cache_observations;\n'}
        self.reject(base, head, 'is not an exact move')

    def test_blank_line_inside_a_literal(self):
        dest = 'pub(crate) const S: &str = "a\nb";\n'
        base = files(**{'snapshots/dest.rs': dest, 'snapshots/old.rs': OLD.replace(
            'use crate::snapshots::dest::here;\n', 'fn here() -> u8 {\n    0\n}\n')})
        head = self.basic_head(base, **{'snapshots/dest.rs': dest.replace('a\nb', 'a\n\nb') + 'pub(crate) mod old;\n'})
        self.reject(base, head, 'not whole `use` items')

    def test_data_file_outside_the_subtree_directory(self):
        base = files(**{'snapshots/notes.txt': 'n\n'})
        head = self.basic_head(base) | moved(base, {'snapshots/notes.txt': 'snapshots/dest/notes.txt'})
        self.reject(base, head, 'must keep its place inside a moved subtree')

    # One fixture per value-changing counterexample of the soundness review.

    def test_included_rust_part_escapes(self):
        old = OLD + '\ninclude!("old/part.inc");\n'
        part = 'pub(crate) fn g() -> u8 {\n    super::dest::here()\n}\n'
        base = files(**{'snapshots/old.rs': old, 'snapshots/old/part.inc': part})
        head = self.basic_head(base) | moved(base, {'snapshots/old/part.inc': 'snapshots/dest/old/part.inc'})
        self.reject(base, head, 'rule 1 (includes)')

    def test_macro_expansion_with_super(self):
        child = 'macro_rules! m {\n    () => {\n        super::dest::here()\n    };\n}\n'
        for decl, call, extra in (('#[macro_use]\nmod child;\n', 'm!()', ''),
                                  ('mod child;\n', 'child::m!()', 'pub(crate) use m;\n')):
            with self.subTest(decl=decl):
                old = OLD.replace('here() + 1', f'here() + {call}') + decl
                base = files(**{'snapshots/old.rs': old, 'snapshots/old/child.rs': child + extra})
                head = self.basic_head(base) | moved(base, {'snapshots/old/child.rs': 'snapshots/dest/old/child.rs'})
                self.reject(base, head, 'rule 2 (macros)')

    def test_super_in_a_moved_transcriber(self):
        for chain in ('super::dest::here()', 'super::super::snapshots::dest::here()'):
            with self.subTest(chain=chain):
                extra = f'\nmacro_rules! up {{\n    () => {{\n        {chain}\n    }};\n}}\n'
                base = files(**{'snapshots/old.rs': OLD + extra})
                self.reject(base, self.basic_head(base), 'has `super` in a transcriber')

    def test_derive_or_macro_generated_glob_in_new_parent(self):
        fallback = 'pub(crate) mod old {\n    pub(crate) fn f() -> u8 {\n        5\n    }\n}\n'
        dest = '#[derive(probe::Import)]\nstruct Marker;\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'lib.rs': 'mod fallback;\nmod snapshots;\n', 'fallback.rs': fallback, 'snapshots/dest.rs': dest})
        self.reject(base, self.basic_head(base, **{'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'}),
                    'may be a macro')
        lib = 'macro_rules! imports {\n    ($u:ident) => {\n        $u crate::fallback::*;\n    };\n}\n\nmod fallback;\nmod snapshots;\n'
        dest = 'imports!(use);\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'lib.rs': lib, 'fallback.rs': fallback, 'snapshots/dest.rs': dest})
        self.reject(base, self.basic_head(base, **{'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'}),
                    'rule 3 (item macros)')

    def test_moved_proc_macro_derive_and_attribute(self):
        for extra, needle in (('#[derive(probe::Read)]\npub(crate) struct Marker;\n', 'derive(probe::Read)'),
                              ('#[probe::location]\npub(crate) fn g() {}\n', 'probe::location'),
                              ('#[cfg_attr(all(), derive(Debug, probe::Read))]\npub(crate) struct M;\n', 'derive(probe::Read)')):
            with self.subTest(needle=needle):
                base = files(**{'snapshots/old.rs': OLD + '\n' + extra})
                self.reject(base, self.basic_head(base), needle)

    def test_attribute_literal_bytes(self):
        parent = 'mod caller;\nmod dest;\n#[cfg(flavor = "a  b")]\nmod old;\n'
        base = files(**{'snapshots.rs': parent})
        head = self.basic_head(base, **{
            'snapshots.rs': 'mod caller;\nmod dest;\n#[cfg(flavor = "a b")]\npub(crate) use crate::snapshots::dest::old;\n',
            'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod old;', '#[cfg(flavor = "a b")]\npub(crate) mod old;')})
        self.reject(base, head, 'rule 5 (attributes)')

    def test_facade_drops_the_cfg(self):
        base = files(**{'snapshots.rs': 'mod caller;\nmod dest;\n#[cfg(test)]\nmod old;\n'})
        head = self.basic_head(base, **{
            'snapshots/dest.rs': DEST_WITH_OLD.replace('pub(crate) mod old;', '#[cfg(test)]\npub(crate) mod old;')})
        self.reject(base, head, 'rule 6 (facade cfg)')

    def test_pub_in_names_a_moving_module(self):
        base = files(**{'snapshots/old.rs': OLD + '\npub(in crate::snapshots::old) fn g() {}\n'})
        self.reject(base, self.basic_head(base), 'rule 7 (location)')

    def test_location_and_reflection_values(self):
        for body in ('file!()', 'module_path!()', 'std::any::type_name::<u8>()', 'std::any::type_name_of_val(&1)'):
            with self.subTest(body=body):
                base = files(**{'snapshots/old.rs': OLD + f'\npub(crate) fn g() -> &\'static str {{\n    {body}\n}}\n'})
                self.reject(base, self.basic_head(base), 'rule 7 (location)')
        base = files(**{'snapshots/old.rs': OLD + '\n#[track_caller]\npub(crate) fn g() {}\n'})
        self.reject(base, self.basic_head(base), 'rule 7 (location)')

    def test_line_shift_in_a_glue_file(self):
        dest = 'pub(crate) fn here() -> u8 {\n    0\n}\n\npub(crate) fn at() -> u32 {\n    line!()\n}\n'
        base = files(**{'snapshots/dest.rs': dest})
        head = self.basic_head(base, **{'snapshots/dest.rs': 'pub(crate) mod old;\n\n' + dest})
        self.reject(base, head, 'rule 7 (location)')

    def test_unmoved_include_consumer(self):
        base = files(**{'snapshots/old/data.txt': 'x\n', 'snapshots.rs': 'mod caller;\nmod consumer;\nmod dest;\nmod old;\n',
                        'snapshots/consumer.rs': 'pub(crate) const DATA: &str = include_str!("old/data.txt");\n'})
        head = self.basic_head(base, **{'snapshots.rs': 'mod caller;\nmod consumer;\nmod dest;\n'
                                                        'pub(crate) use crate::snapshots::dest::old;\n'})
        head |= moved(base, {'snapshots/old/data.txt': 'snapshots/dest/old/data.txt'})
        self.reject(base, head, 'rule 1 (includes)')

    def test_macro_generated_include_and_path(self):
        for body in ('include!("snapshots/old.rs");', '#[path = "snapshots/old.rs"]\n        mod second;'):
            with self.subTest(body=body):
                lib = f'macro_rules! more {{\n    () => {{\n        {body}\n    }};\n}}\n\nmod snapshots;\n'
                base = files(**{'lib.rs': lib})
                self.reject(base, self.basic_head(base), 'rule 8 (hidden contexts)')
        base = files(**{'lib.rs': 'mod other;\nmod snapshots;\n', 'other/second.rs': '\n',
                        'other.rs': '#[cfg_attr(all(), path = "snapshots/old.rs")]\nmod second;\n'})
        self.reject(base, self.basic_head(base), 'rule 8 (hidden contexts)')

    def test_custom_cargo_target(self):
        cargo = CARGO + '\n[[bin]]\nname = "custom"\npath = "src/custom.rs"\n'
        base = files(**{'custom.rs': '#[path = "snapshots/old.rs"]\nmod old;\n\nfn main() {}\n'})
        base['crates/demo/Cargo.toml'] = cargo
        self.reject(base, self.basic_head(base), 'rule 8 (targets)')
        base = files()
        base['crates/demo/Cargo.toml'] = CARGO + '\n[[bin]]\nname = "ghost"\n'
        self.reject(base, self.basic_head(base), 'no path and no default file')

    def test_runtime_old_path_read(self):
        read = ('\npub(crate) fn source() -> String {\n    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), '
                '"/src/snapshots/old.rs")).unwrap()\n}\n')
        base = files(**{'snapshots/old.rs': OLD + read})
        self.reject(base, self.basic_head(base), 'rule 9 (old paths)')

    def test_glob_consumer_of_the_new_parent(self):
        fallback = 'pub(crate) mod old {\n    pub(crate) fn f() -> u8 {\n        5\n    }\n}\n'
        consumer = 'use crate::fallback::*;\nuse super::*;\n\npub(crate) fn g() -> u8 {\n    old::f()\n}\n'
        dest = 'mod consumer;\n\npub(crate) fn here() -> u8 {\n    0\n}\n'
        base = files(**{'lib.rs': 'mod fallback;\nmod snapshots;\n', 'fallback.rs': fallback,
                        'snapshots/dest.rs': dest, 'snapshots/dest/consumer.rs': consumer})
        self.reject(base, self.basic_head(base, **{'snapshots/dest.rs': dest + '\npub(crate) mod old;\n'}),
                    'rule 4 (glob consumers)')

    def test_edition_2024_prelude_name(self):
        base = files()
        base['crates/demo/Cargo.toml'] = CARGO.replace('2021', '2024')
        head = moved(base, {'snapshots/old.rs': 'snapshots/dest/Future.rs',
                            'snapshots/old/tests.rs': 'snapshots/dest/Future/tests.rs'})
        head |= {SRC + 'snapshots.rs': 'mod caller;\nmod dest;\npub(crate) use dest::Future as old;\n',
                 SRC + 'snapshots/dest.rs': DEST_WITH_OLD.replace('mod old;', 'mod Future;')}
        self.reject(base, head, 'prelude (edition 2024)')

    def test_includes_tsv_still_names_the_old_path(self):
        row = lambda path: f'# file\tkind\tliteral\n{SRC}{path}\tinclude\tx.rs\n'  # noqa: E731
        base = files() | {'scripts/source_layout_includes.tsv': row('snapshots/old.rs')}
        self.reject(base, self.basic_head(base), 'source_layout_includes.tsv still names')
        head = self.basic_head(base) | {'scripts/source_layout_includes.tsv': row('snapshots/dest/old.rs')}
        self.accept(base, head)


class AbsolutizeAccepts(Base):
    def test_super_chains_become_absolute(self):
        old = code('''
            use super::*;

            pub(super) fn f() -> u8 {
                super::dest::here()
            }

            pub(in super::super) fn g() -> u8 {
                1
            }

            #[cfg(test)]
            mod tests {
                use super::super::caller;

                #[test]
                fn t() {
                    assert_eq!(caller::call(), 1);
                }
            }
        ''')
        new = (old.replace('use super::*;', 'use crate::snapshots::*;')
               .replace('pub(super) fn f', 'pub(in crate::snapshots) fn f')
               .replace('super::dest::here()', 'crate::snapshots::dest::here()')
               .replace('pub(in super::super) fn g', 'pub(in crate) fn g')
               .replace('use super::super::caller;', 'use crate::snapshots::caller;'))
        base = files(**{'snapshots/old.rs': old})
        result = self.accept(base, {SRC + 'snapshots/old.rs': new}, mode='absolutize')
        self.assertIn('1 files, 5 absolutized paths', result.lines[0])


class AbsolutizeRejects(Base):
    def check_edit(self, old, new, needle, **extra):
        base = files(**{'snapshots/old.rs': old}, **extra)
        self.reject(base, {SRC + 'snapshots/old.rs': new}, needle, mode='absolutize')

    def test_wrong_target(self):
        self.check_edit('fn f() {\n    super::dest::here();\n}\n', 'fn f() {\n    crate::dest::here();\n}\n',
                        'expected `crate::snapshots`')

    def test_inside_macro_attribute_and_macro_rules(self):
        self.check_edit('fn f() {\n    m!(super::x);\n}\n', 'fn f() {\n    m!(crate::snapshots::x);\n}\n', 'inside m!')
        self.check_edit('#[cfg_attr(test, allow(super::x))]\nfn f() {}\n',
                        '#[cfg_attr(test, allow(crate::snapshots::x))]\nfn f() {}\n', 'inside attribute')
        self.check_edit('macro_rules! m {\n    () => {\n        super::x()\n    };\n}\n',
                        'macro_rules! m {\n    () => {\n        crate::snapshots::x()\n    };\n}\n', 'inside macro_rules!')

    def test_spaced_chain_and_other_edits(self):
        self.check_edit('fn f() {\n    super :: super :: x();\n}\n', 'fn f() {\n    crate::x();\n}\n', 'spaced')
        self.check_edit('fn f() {\n    super::x(1);\n}\n', 'fn f() {\n    crate::snapshots::x(2);\n}\n', 'edited beyond')
        self.check_edit('fn f() {\n    self::super::x();\n}\n', 'fn f() {\n    self::crate::snapshots::x();\n}\n',
                        'not at the start of a path')

    def test_unnameable_module_and_attribute_macro(self):
        self.check_edit('fn f() {\n    mod local {\n        fn g() {\n            super::x();\n        }\n    }\n}\n',
                        'fn f() {\n    mod local {\n        fn g() {\n            crate::snapshots::old::x();\n        }\n    }\n}\n',
                        'has no path')
        self.check_edit('#[tokio::test]\nasync fn f() {\n    super::x();\n}\n',
                        '#[tokio::test]\nasync fn f() {\n    crate::snapshots::x();\n}\n', 'may be a macro')

    def test_derive_observing_the_replaced_path(self):
        for attr in ('#[derive(probe::Observe)]', '#[cfg_attr(all(), derive(probe::Observe))]'):
            with self.subTest(attr=attr):
                old = f'{attr}\npub(crate) struct Marker {{\n    value: super::dest::Value,\n}}\n'
                self.check_edit(old, old.replace('super::dest', 'crate::snapshots::dest'), 'derive(probe::Observe)')

    def test_column_shift_after_a_replacement(self):
        old = 'fn f() -> u32 {\n    let _ = super::dest::here(); column!()\n}\n'
        self.check_edit(old, old.replace('super::dest', 'crate::snapshots::dest'), 'rule 7 (location)')

    def test_attribute_pattern_inside_macro_rules_is_fine(self):
        old = 'macro_rules! m {\n    ($(#[$a:meta])* $f:ident) => {};\n}\n\nfn f() {\n    super::x();\n}\n'
        base = files(**{'snapshots/old.rs': old})
        self.accept(base, {SRC + 'snapshots/old.rs': old.replace('super::x', 'crate::snapshots::x')}, mode='absolutize')

    def test_moves_and_multi_context_files(self):
        base = files()
        self.reject(base, moved(base, BASIC_MOVE), 'absolutize changes only edit', mode='absolutize')
        base = files(**{'lib.rs': 'mod other;\nmod snapshots;\n', 'other.rs': '#[path = "snapshots/caller.rs"]\nmod c;\n'})
        self.reject(base, {SRC + 'snapshots/caller.rs': CALLER.replace('super::old', 'crate::snapshots::old')},
                    'exactly one module context', mode='absolutize')


class Cli(Base):
    def test_exit_codes_and_report(self):
        repo = Repo(self)
        base = repo.commit(files())
        head = repo.commit(moved(files(), BASIC_MOVE) | {SRC + 'snapshots.rs': ALIAS_PARENT,
                                                         SRC + 'snapshots/dest.rs': DEST_WITH_OLD})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fm.main(['move', '--repo', str(repo.root), '--base', base, '--head', head]), 0)
        self.assertIn('file-move-only', out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fm.main(['absolutize', '--repo', str(repo.root), '--base', base, '--head', head]), 1)
            self.assertEqual(fm.main(['absolutize', '--repo', str(repo.root), '--base', base, '--head', head,
                                      '--report']), 0)


if __name__ == '__main__':
    unittest.main()
