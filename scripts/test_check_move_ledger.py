#!/usr/bin/env python3
"""Synthetic regressions for check_move_ledger.py and rust_source_tree.py."""
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

SCRIPT = Path(__file__).with_name('check_move_ledger.py').resolve()
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('check_move_ledger', SCRIPT)
ledger = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ledger
spec.loader.exec_module(ledger)
rst = ledger.rst

GIT_ENV = {
    **os.environ,
    'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
    'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid',
    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
}


def code(text):
    return textwrap.dedent(text).lstrip('\n')


class Repo:
    """A throwaway git repository holding one crate under crates/demo."""

    def __init__(self, test):
        temp = tempfile.TemporaryDirectory()
        test.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git('init', '-q', '-b', 'main')
        self.write({'crates/demo/Cargo.toml': '[package]\nname = "demo"\n'})

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, env=GIT_ENV,
                              stdout=subprocess.PIPE, text=True).stdout.strip()

    def write(self, files):
        for name, text in files.items():
            path = self.root / name
            if text is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')

    def commit(self, files):
        self.write(files)
        self.git('add', '-A')
        self.git('commit', '-q', '--allow-empty', '-m', 'step')
        return self.git('rev-parse', 'HEAD')


def src(name):
    return f'crates/demo/src/{name}'


def run(repo, base, head, *extra):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = ledger.main(['--repo', str(repo.root), '--base', base, '--head', head, *extra])
    return status, out.getvalue() + err.getvalue()


ROOT = code('''
    //! The demo snapshots root.

    use std::fmt;

    /// Formats one value.
    fn helper(value: u32) -> String {
        format!("{value}")
    }

    // Keeps the order.
    fn second() {}

    struct Holder {
        pub(crate) value: u32,
        inner: u32,
    }

    impl Holder {
        fn one(&self) -> u32 {
            self.value
        }

        fn two(&self) -> u32 {
            self.inner
        }
    }
''')


class LexerTests(unittest.TestCase):
    def items(self, text):
        return [(item.kind, item.name) for item in rst.Lexed(code(text)).items]

    def test_strings_raw_strings_chars_lifetimes_and_nested_comments_do_not_end_items(self):
        text = '''
            fn a<'x>(v: &'x str) -> char {
                let _ = r#"} " { "#;
                let _ = "}\\"{";
                let _ = b'}';
                /* outer /* } nested */ still { comment */
                '{'
            }
            const B: [u8; 2] = { [1, 2] };
            use x::{y, z};
            static C: &str = "a;b";
            struct T(u8);
            macro_rules! m { () => { pub fn hidden() {} }; }
            m!();
        '''
        self.assertEqual(self.items(text), [
            ('fn', 'a'), ('const', 'B'), ('use', 'use x::{y, z}'), ('static', 'C'),
            ('struct', 'T'), ('macro_rules', 'macro_rules! m'), ('macro', 'm!'),
        ])

    def test_leading_comments_attributes_and_same_line_comments_belong_to_the_item(self):
        text = code('''
            //! File docs.

            // Leading note.

            /// Docs.
            #[cfg(test)]
            fn a() {} // trailing note
            fn b() {}
            // Trailing file comment.
        ''')
        lexed = rst.Lexed(text)
        kinds = [(item.kind, text[item.start:item.end]) for item in lexed.items]
        self.assertEqual(kinds[0], ('inner-doc', '//! File docs.'))
        self.assertEqual(kinds[1], ('fn', '// Leading note.\n\n/// Docs.\n#[cfg(test)]\nfn a() {} // trailing note'))
        self.assertEqual(lexed.items[1].attrs, ['#[cfg(test)]'])
        self.assertEqual(kinds[2], ('fn', 'fn b() {}'))
        self.assertEqual(kinds[3], ('comment', '// Trailing file comment.'))

    def test_inline_modules_and_impls_keep_members(self):
        lexed = rst.Lexed(code('''
            mod tests {
                use super::*;
                fn t() {}
            }
            impl<T: Fn() -> u8> Foo<T> {
                pub fn get(&self) {}
            }
            mod decl;
        '''))
        tests, impl, decl = lexed.items
        self.assertEqual([m.kind for m in tests.members], ['use', 'fn'])
        self.assertEqual(impl.name, 'impl<T: Fn() -> u8> Foo<T>')
        self.assertEqual([(m.kind, m.name, m.depth) for m in impl.members], [('fn', 'get', 1)])
        self.assertEqual(decl.kind, 'mod-decl')

    def test_unterminated_input_is_an_error(self):
        for text in ('fn a() { "x }', 'fn a() { /* x }', 'fn a() { r#"x" }', 'fn a() {'):
            with self.assertRaises(rst.SourceError, msg=text):
                rst.Lexed(text)


class ModuleTreeTests(unittest.TestCase):
    def test_mod_path_and_include_resolve_like_rustc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {
                'c/Cargo.toml': '',
                'c/src/lib.rs': 'pub mod snapshots;\n',
                'c/src/snapshots.rs': code('''
                    mod plain;
                    #[path = "elsewhere.rs"]
                    mod moved;
                    #[cfg(test)]
                    mod tests {
                        mod inner;
                        include!("snapshots/included.rs");
                    }
                '''),
                'c/src/snapshots/plain.rs': 'mod child;\n',
                'c/src/snapshots/plain/child.rs': '',
                'c/src/elsewhere.rs': 'mod sub;\n',
                'c/src/sub.rs': '',
                'c/src/snapshots/tests/inner.rs': '',
                'c/src/snapshots/included.rs': 'mod beside;\n',
                'c/src/snapshots/beside.rs': '',
            }
            for name, text in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            tree = rst.crate_tree(rst.DirSource(root), 'c')
        modules = {path: '::'.join(found[0].module) for path, found in tree.contexts.items()}
        self.assertEqual(modules, {
            'c/src/lib.rs': 'crate',
            'c/src/snapshots.rs': 'crate::snapshots',
            'c/src/snapshots/plain.rs': 'crate::snapshots::plain',
            'c/src/snapshots/plain/child.rs': 'crate::snapshots::plain::child',
            'c/src/elsewhere.rs': 'crate::snapshots::moved',
            'c/src/sub.rs': 'crate::snapshots::moved::sub',
            'c/src/snapshots/tests/inner.rs': 'crate::snapshots::tests::inner',
            'c/src/snapshots/included.rs': 'crate::snapshots::tests',
            'c/src/snapshots/beside.rs': 'crate::snapshots::tests::beside',
        })
        self.assertEqual(tree.context('c/src/snapshots/included.rs').chain, frozenset({'#[cfg(test)]'}))
        self.assertTrue(all(link.target for link in tree.links))


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo(self)
        self.base = self.repo.commit({src('lib.rs'): 'pub mod snapshots;\n', src('snapshots.rs'): ROOT})

    def move(self, root, files=None, *extra):
        head = self.repo.commit({src('snapshots.rs'): root, **(files or {})})
        return run(self.repo, self.base, head, *extra)

    def test_a_pure_move_passes_and_prints_the_ledger(self):
        root = ROOT.replace(code('''
            /// Formats one value.
            fn helper(value: u32) -> String {
                format!("{value}")
            }

            // Keeps the order.
            fn second() {}
        '''), '').replace('use std::fmt;\n', 'use std::fmt;\n\nmod wire;\nuse wire::helper;\n')
        wire = code('''
            //! Wire helpers.

            /// Formats one value.
            pub(super) fn helper(value: u32) -> String {
                format!("{value}")
            }

            // Keeps the order.
            fn second() {}
        ''')
        status, out = self.move(root, {src('snapshots/wire.rs'): wire})
        self.assertEqual(status, 0, out)
        self.assertIn('crates/demo/src/snapshots.rs:5-11 fn helper .. fn second (2 items) -> '
                      'crates/demo/src/snapshots/wire.rs:3-9  [crate::snapshots -> crate::snapshots::wire]', out)
        self.assertIn('move-only', out)

    def test_a_changed_body_fails_with_a_diff(self):
        status, out = self.move(ROOT.replace('format!("{value}")', 'format!("{value:?}")'))
        self.assertEqual(status, 1)
        self.assertIn('changed: fn helper', out)
        self.assertIn('-    format!("{value}")', out)
        self.assertIn('+    format!("{value:?}")', out)

    def test_dropped_comment_and_duplicated_item_fail(self):
        status, out = self.move(ROOT.replace('// Keeps the order.\n', ''))
        self.assertEqual(status, 1)
        self.assertIn('fn second', out)
        status, out = self.move(ROOT + '\nfn second() {}\n')
        self.assertEqual(status, 1)
        self.assertIn('added or changed: fn second', out)

    def test_visibility_equivalence_and_widening(self):
        moved = code('''
            /// Formats one value.
            {vis}fn helper(value: u32) -> String {
                format!("{value}")
            }
        ''')
        root = ROOT.replace(moved.replace('{vis}', ''), '').replace('use std::fmt;\n', 'use std::fmt;\nmod a;\n')
        for vis, path, expect in (
            ('pub(super) ', 'a.rs', 0),
            ('pub(in crate::snapshots) ', 'a.rs', 0),
            ('pub(in crate::snapshots) ', 'a/b.rs', 0),
            ('pub(crate) ', 'a.rs', 1),
            ('pub ', 'a/b.rs', 1),
        ):
            with self.subTest(vis=vis, path=path):
                files = {src('snapshots/a.rs'): 'mod b;\n' if path == 'a/b.rs' else moved.replace('{vis}', vis)}
                if path == 'a/b.rs':
                    files[src('snapshots/a/b.rs')] = moved.replace('{vis}', vis)
                status, out = self.move(root, files)
                self.assertEqual(status, expect, out)
                if expect:
                    self.assertIn('widened: fn helper', out)
                self.repo.commit({src('snapshots/a/b.rs'): None} if path == 'a/b.rs' else {})
        status, out = self.move(root, {src('snapshots/a.rs'): moved.replace('{vis}', 'pub(crate) ')},
                                '--allow-widened', 'helper')
        self.assertEqual(status, 0, out)
        self.assertIn('[allowed]', out)

    def test_one_impl_split_across_files_and_order_inside_a_destination(self):
        impl_two = code('''
            impl Holder {
                fn two(&self) -> u32 {
                    self.inner
                }
            }
        ''')
        two = '\n    fn two(&self) -> u32 {\n        self.inner\n    }\n'
        self.assertIn(two, ROOT)
        root = ROOT.replace(two, '').replace('use std::fmt;\n', 'use std::fmt;\nmod extra;\n')
        status, out = self.move(root, {src('snapshots/extra.rs'): 'use super::Holder;\n\n' + impl_two})
        self.assertEqual(status, 0, out)
        self.assertIn('impl Holder :: fn two', out)
        swapped = ROOT.replace('// Keeps the order.\nfn second() {}\n', '').replace(
            '/// Formats one value.', '// Keeps the order.\nfn second() {}\n\n/// Formats one value.')
        status, out = self.move(swapped)
        self.assertEqual(status, 1)
        self.assertIn('order changed in crates/demo/src/snapshots.rs', out)

    def test_inline_module_becomes_a_file_with_its_cfg_and_indentation(self):
        base = self.repo.commit({src('snapshots.rs'): ROOT + code('''

            // Checks the formatter.
            #[cfg(test)]
            mod tests {
                use super::*;

                #[test]
                fn formats() {
                    let text = "line one
            line two";
                    assert_eq!(helper(1), "1");
                }
            }
        ''')})
        tests = code('''
            use super::*;

            #[test]
            fn formats() {
                let text = "line one
            line two";
                assert_eq!(helper(1), "1");
            }
        ''')
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n// Checks the formatter.\n#[cfg(test)]\nmod tests;\n',
                                 src('snapshots/tests.rs'): tests})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 0, out)
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n// Checks the formatter.\nmod tests;\n'})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 1)
        self.assertIn("module attributes changed for fn formats", out)
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n#[cfg(test)]\nmod tests;\n'})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 1)
        self.assertIn("removed or changed: comment before mod tests", out)

    def test_rustfmt_skip_on_an_outlined_module_is_formatting_only(self):
        base = self.repo.commit({src('snapshots.rs'): ROOT + code('''

            #[cfg(test)]
            mod tests {
                fn a() {}
            }
        ''')})
        tests = {src('snapshots/tests.rs'): 'fn a() {}\n'}
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n#[cfg(test)]\n#[ rustfmt :: skip ]\nmod tests;\n',
                                 **tests})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 0, out)
        self.assertIn('move-ledger: move-only', out)
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n#[cfg(test)]\n#[cfg(unix)]\nmod tests;\n'})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 1)
        self.assertIn('module attributes changed for fn a', out)
        head = self.repo.commit({src('snapshots.rs'): ROOT + '\n#[cfg(test)]\n#[rustfmt::skip]\nmod tests;\n',
                                 src('snapshots/tests.rs'): '#[rustfmt::skip]\nfn a() {}\n'})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 1)
        self.assertIn('changed: fn a', out)
        self.assertIn('+#[rustfmt::skip]', out)

    def test_include_str_paths_must_reach_the_same_bytes(self):
        reader = 'fn golden() -> &\'static str {\n    include_str!("../fixtures/a.json")\n}\n'
        base = self.repo.commit({src('snapshots.rs'): ROOT + reader, 'crates/demo/fixtures/a.json': '{}\n'})
        moved = {src('snapshots.rs'): ROOT + 'mod read;\n',
                 src('snapshots/read.rs'): reader.replace('../', '../../')}
        status, out = run(self.repo, base, self.repo.commit(moved))
        self.assertEqual(status, 0, out)
        moved[src('snapshots/read.rs')] = reader.replace('../fixtures/a.json', '../../fixtures/b.json')
        status, out = run(self.repo, base, self.repo.commit({**moved, 'crates/demo/fixtures/b.json': '[]\n'}))
        self.assertEqual(status, 1)
        self.assertIn('include_str target bytes differ', out)

    def test_a_subtree_that_moves_intact_keeps_pub_super(self):
        base = self.repo.commit({
            src('snapshots.rs'): ROOT + 'mod money;\n',
            src('snapshots/money.rs'): '//! Money.\n\nmod birth;\n\nfn total() {}\n',
            src('snapshots/money/birth.rs'): 'pub(super) fn born() {}\n',
        })
        head = self.repo.commit({
            src('snapshots.rs'): ROOT + 'mod sources;\n',
            src('snapshots/sources.rs'): 'mod money;\n',
            src('snapshots/sources/money.rs'): '//! Money.\n\nmod birth;\n\nfn total() {}\n',
            src('snapshots/sources/money/birth.rs'): 'pub(super) fn born() {}\n',
            src('snapshots/money.rs'): None, src('snapshots/money/birth.rs'): None,
        })
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 0, out)
        self.assertIn('[crate::snapshots::money::birth -> crate::snapshots::sources::money::birth]', out)

    LONG = code('''
        /// Checks both arguments.
        fn long_signature(first_argument: Option<&str>, second_argument: u64) -> bool {
            first_argument == Some("a b") && second_argument > 0
        }
    ''')
    WRAPPED = code('''
        /// Checks both arguments.
        pub(super) fn long_signature(
            first_argument: Option<&str>,
            second_argument: u64,
        ) -> bool {
            first_argument == Some("a b") && second_argument > 0
        }
    ''')

    def move_long(self, moved, original=LONG):
        files = {src('snapshots.rs'): ROOT + original}
        if (self.repo.root / src('snapshots/wide.rs')).exists():
            files[src('snapshots/wide.rs')] = None
        base = self.repo.commit(files)
        head = self.repo.commit({src('snapshots.rs'): ROOT + 'mod wide;\n', src('snapshots/wide.rs'): moved})
        return run(self.repo, base, head)

    def test_a_rustfmt_reflow_after_a_visibility_token_is_a_reflowed_move(self):
        status, out = self.move_long(self.WRAPPED)
        self.assertEqual(status, 0, out)
        self.assertIn(' 1 moved, 1 reflowed, 0 respelled, 0 widened, 0 problems', out)
        self.assertIn('reflowed fn long_signature (crates/demo/src/snapshots.rs:', out)
        self.assertIn('move-only', out)

    def test_a_reflow_that_hides_a_changed_identifier_or_literal_fails(self):
        for old, new in (('second_argument: u64,', 'second_arg: u64,'), ('Some("a b")', 'Some("a c")')):
            with self.subTest(new=new):
                status, out = self.move_long(self.WRAPPED.replace(old, new))
                self.assertEqual(status, 1, out)
                self.assertIn('changed: fn long_signature', out)
                self.assertIn(' 0 reflowed,', out)

    def test_whitespace_inside_a_string_literal_is_not_a_reflow(self):
        status, out = self.move_long(self.WRAPPED.replace('Some("a b")', 'Some("a  b")'))
        self.assertEqual(status, 1, out)
        self.assertIn('changed: fn long_signature', out)
        self.assertIn(' 0 reflowed,', out)

    def test_a_wrapped_fn_with_a_where_clause_is_reflowed_and_widening_still_fails(self):
        original = code('''
            fn applies_to_the_value<T>(value: T, check_value: impl Fn(&T) -> bool, label: &str) -> bool
            where
                T: Clone,
            {
                check_value(&value.clone()) && !label.is_empty()
            }
        ''')
        wrapped = code('''
            pub(super) fn applies_to_the_value<T>(
                value: T,
                check_value: impl Fn(&T) -> bool,
                label: &str,
            ) -> bool
            where
                T: Clone,
            {
                check_value(&value.clone()) && !label.is_empty()
            }
        ''')
        status, out = self.move_long(wrapped, original)
        self.assertEqual(status, 0, out)
        self.assertIn(' 1 moved, 1 reflowed, 0 respelled, 0 widened, 0 problems', out)
        status, out = self.move_long(wrapped.replace('T: Clone,', 'T: Clone'), original)
        self.assertEqual(status, 1, out)
        status, out = self.move_long(self.WRAPPED.replace('pub(super)', 'pub(crate)'))
        self.assertEqual(status, 1, out)
        self.assertIn('1 reflowed', out)
        self.assertIn('widened: fn long_signature', out)

    def test_reflow_rejects_tuples_macro_commas_joined_operators_and_other_items(self):
        for before, after in (
            # A one-element tuple, a comma-sensitive macro call and `& &` vs `&&` in a body.
            ('fn tuple() -> String {\n    format!("{:?}", (1u8))\n}\n',
             'pub(super) fn tuple() -> String {\n    format!("{:?}", (1u8,\n    ))\n}\n'),
            ('fn call() -> u8 {\n    m!(x)\n}\n', 'pub(super) fn call() -> u8 {\n    m!(x,\n    )\n}\n'),
            ('fn both(b: bool, mut g: impl FnMut() -> bool) -> bool {\n    b & &g()\n}\n',
             'pub(super) fn both(b: bool, mut g: impl FnMut() -> bool) -> bool {\n    b &&g()\n}\n'),
            # The same in a signature: punctuation jointness and a comma that is not the list's own.
            ('fn joined(x: & &u8) {}\n', 'pub(super) fn joined(\n    x: &&u8,\n) {}\n'),
            ('fn inner(x: (u8)) {}\n', 'pub(super) fn inner(\n    x: (u8,\n    ),\n) {}\n'),
            # A `pub` inside an attribute is not the item's visibility.
            ('#[cfg_attr(any(), dummy(pub))]\nfn f() {}\n', '#[cfg_attr(any(), dummy())]\npub fn f(\n) {}\n'),
            # A macro in the signature can see token boundaries the lexer does not keep.
            ('fn f(x: ty!("s"tag)) {}\n', 'pub(super) fn f(\n    x: ty!("s" tag),\n) {}\n'),
            ('fn f(x: ty!(1.0)) {}\n', 'pub(super) fn f(\n    x: ty!(1 . 0),\n) {}\n'),
            ('fn f(x: ty! /*c*/ ("s"tag)) {}\n', 'pub(super) fn f(\n    x: ty! /*c*/ ("s" tag),\n) {}\n'),
            ('fn f(x: ty /*c*/ !("s"tag)) {}\n', 'pub(super) fn f(\n    x: ty /*c*/ !("s" tag),\n) {}\n'),
            # A struct whose field visibilities trade places at the same text offsets.
            ('pub(crate) struct S {\n    pub(crate) a: u8,\n    b: u8,\n}\n',
             'pub(crate) struct S {a:u8,pub(crate) b:u8,}\n'),
        ):
            with self.subTest(after=after):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 1, out)
                self.assertIn(' 0 reflowed,', out)

    FIELDS = code('''
        /// Holds the scan state.
        #[derive(Debug, Default)]
        pub(crate) struct Index {
            /// Entries by path.
            entries: Vec<u32>,
            #[serde(default)]
            claude_usage_authority_quarantine_records_by_session: Option<Vec<u32>>,
            codex_counting_tombstones_by_session_identifier: Vec<u64>,
        }
    ''')
    WRAPPED_FIELDS = code('''
        /// Holds the scan state.
        #[derive(Debug, Default)]
        pub(crate) struct Index {
            /// Entries by path.
            pub(super) entries: Vec<u32>,
            #[serde(default)]
            pub(super) claude_usage_authority_quarantine_records_by_session:
                Option<Vec<u32>>,
            pub(super) codex_counting_tombstones_by_session_identifier:
                Vec<u64>,
        }
    ''')

    def test_struct_fields_wrapped_after_a_visibility_token_are_a_reflowed_move(self):
        table = 'pub(crate) struct Table {\n    map: HashMap<K, Vec<(A, B)>>,\n    call: Box<dyn Fn(A, B) -> C>,\n}\n'
        wrapped = ('pub(crate) struct Table {\n    {a} map:\n        HashMap<K, Vec<(A, B)>>,\n'
                   '    {b} call:\n        Box<dyn Fn(A, B) -> C>,\n}\n')
        for name, before, after, label in (
            ('long fields', self.FIELDS, self.WRAPPED_FIELDS, 'struct Index'),
            ('nested generic and closure type', table,
             wrapped.replace('{a}', 'pub(super)').replace('{b}', 'pub(super)'), 'struct Table'),
            ('pub(in original module)', table,
             wrapped.replace('{a}', 'pub(in crate::snapshots)').replace('{b}', 'pub(in crate::snapshots)'),
             'struct Table'),
            ('mixed scopes', table,
             wrapped.replace('{a}', 'pub(super)').replace('{b}', 'pub(in crate::snapshots)'), 'struct Table'),
        ):
            with self.subTest(name):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 0, out)
                self.assertIn(' 1 moved, 1 reflowed, 0 respelled, 0 widened, 0 problems', out)
                self.assertIn(f'reflowed {label} (crates/demo/src/snapshots.rs:', out)

    def test_struct_field_reflow_rejects_any_other_change(self):
        wrapped, fields = self.WRAPPED_FIELDS, self.FIELDS
        swapped = wrapped.replace(
            '    /// Entries by path.\n    pub(super) entries: Vec<u32>,\n', '').replace(
            '        Vec<u64>,\n', '        Vec<u64>,\n    /// Entries by path.\n    pub(super) entries: Vec<u32>,\n')
        self.assertNotEqual(swapped, wrapped)
        for name, before, after in (
            ('type', fields, wrapped.replace('        Vec<u64>,', '        Vec<u32>,')),
            ('name', fields, wrapped.replace('pub(super) entries:', 'pub(super) entry:')),
            ('order', fields, swapped),
            ('attribute', fields, wrapped.replace('#[serde(default)]', '#[serde(skip)]')),
            ('macro', fields.replace('Vec<u64>', 'ty!(u64)'), wrapped.replace('Vec<u64>', 'ty!(u64)')),
            ('attribute pub', fields.replace('#[serde(default)]', '#[cfg_attr(any(), dummy(pub))]'),
             wrapped.replace('#[serde(default)]', '#[cfg_attr(any(), dummy())]')),
            ('tuple', 'pub(crate) struct Pair(u32, u64);\n',
             'pub(crate) struct Pair(\n    pub(super) u32,\n    pub(super) u64,\n);\n'),
            ('doc comment', fields, wrapped.replace('/// Entries by path.', '/// Entries by name.')),
            ('serde string', fields.replace('#[serde(default)]', '#[serde(rename = "a")]'),
             wrapped.replace('#[serde(default)]', '#[serde(rename = "b")]')),
            ('unit struct', 'pub(crate) struct Marker;\n', 'pub(crate) struct\n    Marker;\n'),
        ):
            with self.subTest(name):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 1, out)
                self.assertIn(' 0 reflowed,', out)
        status, out = self.move_long(wrapped.replace('pub(super) entries', 'pub(crate) entries'), fields)
        self.assertEqual(status, 1, out)
        self.assertIn('1 reflowed', out)
        self.assertIn('widened: struct Index', out)

    def test_const_static_and_type_rewrapped_after_a_visibility_token_are_reflowed(self):
        for before, after in (
            ('const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);\n',
             'pub(super) const BUSY_TIMEOUT: std::time::Duration =\n    std::time::Duration::from_secs(5);\n'),
            ('/// Effort tiers.\nconst EFFORT_TIERS: &[&str] = &["low", "medium", "high", "xhigh", "max"];\n',
             '/// Effort tiers.\npub(in crate::snapshots) const EFFORT_TIERS: &[&str] =\n'
             '    &["low", "medium", "high", "xhigh", "max"];\n'),
            ('static SEEN: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());\n',
             'pub(super) static SEEN: std::sync::Mutex<Vec<u64>> =\n    std::sync::Mutex::new(Vec::new());\n'),
            ('type Ledger<R = crate::snapshots::Holder> = std::collections::BTreeMap<String, R>;\n',
             'pub(super) type Ledger<R = crate::snapshots::Holder> =\n    std::collections::BTreeMap<String, R>;\n'),
        ):
            with self.subTest(after=after):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 0, out)
                self.assertIn(' 1 moved, 1 reflowed, 0 respelled, 0 widened, 0 problems', out)

    def test_const_reflow_rejects_changed_tokens(self):
        for before, after in (
            # A changed literal, an added trailing comma, a macro call and a second visibility token.
            ('const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);\n',
             'pub(super) const BUSY_TIMEOUT: std::time::Duration =\n    std::time::Duration::from_secs(6);\n'),
            ('const TIERS: &[&str] = &["low", "max"];\n', 'pub(super) const TIERS: &[&str] =\n    &["low", "max",];\n'),
            ('const NAME: &str = concat!("a", "b");\n', 'pub(super) const NAME: &str =\n    concat!("a", "b");\n'),
            ('const N: u8 = { struct P { a: u8 } 1 };\n',
             'pub(super) const N: u8 =\n    { struct P { pub a: u8 } 1 };\n'),
            # A changed type and a changed cfg attribute.
            ('const LIMIT: u8 = 1;\n', 'pub(super) const LIMIT: u16 =\n    1;\n'),
            ('#[cfg(test)]\nconst LIMIT: u8 = 1;\n', '#[cfg(unix)]\npub(super) const LIMIT: u8 =\n    1;\n'),
        ):
            with self.subTest(after=after):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 1, out)
                self.assertIn(' 0 reflowed,', out)

    def test_a_number_literal_is_one_token_in_a_reflow(self):
        # A float, an exponent, hex, a suffixed integer and a suffixed float re-wrapped whole are reflowed.
        for value in ('1.0', '1e-3', '2.5E+10', '0x1F', '1_000u64', '1.0f32', '1.'):
            with self.subTest(value=value):
                status, out = self.move_long(f'pub(super) const VALUE: f64 =\n    {value};\n',
                                             f'const VALUE: f64 = {value};\n')
                self.assertEqual(status, 0, out)
                self.assertIn(' 1 moved, 1 reflowed,', out)
        # Whitespace inside a number literal changes its tokens: not a reflow.
        for before, after in (('1.0', '1 . 0'), ('1.0', '1 .0'), ('1e-3', '1e - 3'), ('1.0f32', '1. 0f32'),
                              ('1.5', '1 .5')):
            with self.subTest(after=after):
                status, out = self.move_long(f'pub(super) const VALUE: f64 =\n    {after};\n',
                                             f'const VALUE: f64 = {before};\n')
                self.assertEqual(status, 1, out)
                self.assertIn(' 0 reflowed,', out)
                self.assertIn('changed: const VALUE', out)

    MACRO = code('''
        macro_rules! scan_result {
            (pub struct $name:ident { $($field:ident: $ty:ty,)* }) => {
                pub struct $name { $($field: $ty,)* }
                impl $name {
                    fn empty() -> Self {
                        Self { $($field: Default::default(),)* }
                    }
                }
            };
        }
        scan_result! {
        pub struct Scan {
            count: u64,
        }
        }
    ''')

    def test_a_macro_rules_body_moves_byte_for_byte(self):
        status, out = self.move_long(self.MACRO, self.MACRO)
        self.assertEqual(status, 0, out)
        self.assertIn(' 2 moved, 0 reflowed, 0 respelled, 0 widened, 0 problems', out)
        # No visibility glue inside a macro body: a token on a generated fn, on a word a macro only
        # stringifies, or in the matcher, and a dropped one, all fail.
        stringified = code('''
            macro_rules! maker {
                () => { stringify!(fn empty) };
            }
            const TEXT: &str = maker!();
        ''')
        for name, before, after in (
            ('generated fn', self.MACRO, self.MACRO.replace('fn empty', 'pub(super) fn empty')),
            ('generated fn in crate::snapshots', self.MACRO,
             self.MACRO.replace('fn empty', 'pub(in crate::snapshots) fn empty')),
            ('stringified word', stringified, stringified.replace('(fn empty)', '(pub(super) fn empty)')),
            ('in the matcher', self.MACRO, self.MACRO.replace('(pub struct $name', '(pub(super) struct $name')),
            ('dropped token', self.MACRO, self.MACRO.replace('pub struct $name {', 'struct $name {')),
        ):
            with self.subTest(name):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 1, out)
                self.assertIn('changed: macro_rules macro_rules!', out)

    COIN = code('''
        //! Money totals.

        #[cfg(test)]
        mod tests;

        /// Adds the fee to the value.
        pub(crate) fn total(value: u32) -> u32 {
            value + crate::snapshots::money::fee()
        }

        fn fee() -> u32 {
            // One unit per call.
            1
        }

        impl crate::snapshots::Holder {
            fn doubled(&self) -> u32 {
                self.value * 2
            }
        }

        // Keeps the file long enough for git to see the rename.
        fn first() {}
        fn second() {}
        fn third() {}
    ''')
    COIN_TESTS = 'use super::*;\n\n#[test]\nfn adds() {\n    assert_eq!(super::total(1), 2);\n}\n'
    MONEY_FILES = ('snapshots/money.rs', 'snapshots/money/tests.rs', 'snapshots/sources.rs',
                   'snapshots/sources/coin.rs', 'snapshots/sources/coin/tests.rs', 'snapshots/sources/money.rs',
                   'snapshots/sources/money/tests.rs')

    def move_money(self, coin, tests=COIN_TESTS, alias='pub(crate) use sources::coin as money;\n', name='coin',
                   source=None):
        """Commit the money module (`source`, default COIN) at base, then `git mv` it to sources/<name>.rs
        holding `coin`, and its tests file holding `tests` (no tests module when None), with `alias` in the root."""
        reset = {src(path): None for path in self.MONEY_FILES if (self.repo.root / src(path)).exists()}
        self.repo.commit(reset)
        source = source or self.COIN
        if tests is None:
            source, coin = (text.replace('#[cfg(test)]\nmod tests;\n\n', '') for text in (source, coin))
        files = {src('snapshots.rs'): ROOT + 'mod money;\n', src('snapshots/money.rs'): source}
        if tests is not None:
            files[src('snapshots/money/tests.rs')] = self.COIN_TESTS
        base = self.repo.commit(files)
        (self.repo.root / src(f'snapshots/sources/{name}')).mkdir(parents=True, exist_ok=True)
        self.repo.git('mv', src('snapshots/money.rs'), src(f'snapshots/sources/{name}.rs'))
        head_files = {src('snapshots.rs'): ROOT + 'mod sources;\n' + alias,
                      src('snapshots/sources.rs'): f'pub(crate) mod {name};\n',
                      src(f'snapshots/sources/{name}.rs'): coin}
        if tests is not None:
            self.repo.git('mv', src('snapshots/money/tests.rs'), src(f'snapshots/sources/{name}/tests.rs'))
            head_files[src(f'snapshots/sources/{name}/tests.rs')] = tests
        return run(self.repo, base, self.repo.commit(head_files))

    def test_a_whole_file_git_mv_with_its_mod_decl_and_facade_alias_decomposes_into_moved_items(self):
        status, out = self.move_money(self.COIN)
        self.assertEqual(status, 0, out)
        self.assertIn(' 0 respelled, 0 widened, 0 problems', out)
        self.assertIn('file map: 2 exact renames of .rs files, 2 module moves, 1 facade aliases', out)
        self.assertIn('module crate::snapshots::money -> crate::snapshots::sources::coin', out)
        self.assertIn('facade alias crate::snapshots::money -> crate::snapshots::sources::coin', out)
        self.assertIn('crates/demo/src/snapshots/money.rs:6-25 fn total .. fn third (6 items) -> '
                      'crates/demo/src/snapshots/sources/coin.rs:6-25  '
                      '[crate::snapshots::money -> crate::snapshots::sources::coin]', out)
        self.assertIn('[crate::snapshots::money::tests -> crate::snapshots::sources::coin::tests]', out)
        self.assertIn('move-only', out)
        # Without `as` when the name stays the same.
        status, out = self.move_money(self.COIN, alias='pub(crate) use sources::money;\n', name='money')
        self.assertEqual(status, 0, out)
        self.assertIn('facade alias crate::snapshots::money -> crate::snapshots::sources::money', out)
        # An edited file maps nothing, so the same alias names no mapped head path.
        status, out = self.move_money(self.COIN.replace('snapshots::money::fee', 'snapshots::sources::money::fee'),
                                      alias='pub(crate) use sources::money;\n', name='money')
        self.assertEqual(status, 1, out)
        self.assertIn('`use` binds the old name of moved module crate::snapshots::money without naming', out)

    def test_a_moved_item_must_keep_what_its_unchanged_paths_name(self):
        escaping = self.COIN.replace('value + crate', 'value + super::helper(value).len() as u32 + crate')
        header = self.COIN.replace('impl crate::snapshots::Holder', 'impl super::Holder')
        for name, coin, alias, expect in (
            # Without the facade alias the old crate path names nothing at head.
            ('no alias', self.COIN, 'pub(crate) use sources::coin;\n',
             'path names something else after the move: fn total `crate::snapshots::money::fee`'),
            # An unchanged escaping path now starts from the new module.
            ('escaping super', escaping, 'pub(crate) use sources::coin as money;\n',
             'path names something else after the move: fn total `super::helper`'),
            ('impl header', header, 'pub(crate) use sources::coin as money;\n',
             'path names something else after the move: impl super::Holder :: fn doubled `super::Holder`'),
        ):
            with self.subTest(name):
                status, out = self.move_money(coin, alias=alias, source=coin)
                self.assertEqual(status, 1, out)
                self.assertIn(expect, out)

    ESCAPING = (COIN.replace('value + crate', 'super::helper(value).len() as u32 + value + crate')
                .replace('impl crate::snapshots::Holder', 'impl super::Holder'))
    RESPELLED = (ESCAPING.replace('crate::snapshots::money::fee()', 'crate::snapshots::sources::coin::fee()')
                 .replace('super::helper', 'super::super::helper')
                 .replace('impl super::Holder', 'impl super::super::Holder'))

    def test_module_paths_respelled_for_a_moved_module_resolve_to_the_same_items(self):
        status, out = self.move_money(self.RESPELLED, tests=None, alias='', source=self.ESCAPING)
        self.assertEqual(status, 0, out)
        self.assertIn(' 0 reflowed, 2 respelled, 0 widened, 0 problems', out)
        self.assertNotIn('file map:', out)  # the respelled file is an edited rename: it maps nothing
        self.assertIn('respelled fn total (crates/demo/src/snapshots/money.rs:3 -> '
                      'crates/demo/src/snapshots/sources/coin.rs:3)', out)
        self.assertIn('respelled impl super::Holder :: fn doubled', out)
        self.assertIn('move-only', out)
        # Its tests file is an exact rename, but `use super::*` there names the money module, which an edited
        # rename never maps: the glob binding fails, and so does the facade alias.
        status, out = self.move_money(self.RESPELLED, source=self.ESCAPING)
        self.assertEqual(status, 1, out)
        self.assertIn('`use` binding glob in crate::snapshots::money::tests now names something else', out)
        self.assertIn('`use` binds the old name of moved module crate::snapshots::money without naming its '
                      'mapped head path (?)', out)

    def test_a_respelled_path_must_resolve_to_the_same_moved_target(self):
        for name, coin in (
            ('different module', self.RESPELLED.replace('super::super::helper', 'crate::snapshots::sources::helper')),
            ('crate path respelled relative', self.RESPELLED.replace('crate::snapshots::sources::coin::fee()',
                                                                     'super::coin::fee()')),
            ('impl header to another module', self.RESPELLED.replace('impl super::super::Holder',
                                                                     'impl crate::snapshots::sources::Holder')),
            ('changed name', self.RESPELLED.replace('super::super::helper(value)', 'super::super::second(value)')),
        ):
            with self.subTest(name):
                status, out = self.move_money(coin, tests=None, alias='', source=self.ESCAPING)
                self.assertEqual(status, 1, out)
                self.assertIn('changed: ', out)

    def test_validator_edits_are_listed_and_only_for_listed_files(self):
        listed = 'crates/ottto-service/tests/support/scan_index_v201.rs'
        other = 'crates/ottto-service/tests/support/other_v201.rs'
        test = 'fn anchors() {\n    assert!(true);\n}\n'
        base = self.repo.commit({'crates/ottto-service/Cargo.toml': '[package]\nname = "s"\n', listed: test,
                                 other: test, 'scripts/test_codex_zst_downgrade.py': 'print(1)\n'})
        head = self.repo.commit({listed: test.replace('true', '!false'),
                                 'scripts/test_codex_zst_downgrade.py': 'print(2)\n'})
        status, out = run(self.repo, base, head)
        self.assertEqual(status, 0, out)
        self.assertIn(f'validator edits: {listed}, scripts/test_codex_zst_downgrade.py', out)
        status, out = run(self.repo, head, self.repo.commit({other: test.replace('true', '!false')}))
        self.assertEqual(status, 1, out)
        self.assertIn('changed: fn anchors', out)

        def symlink():
            # Git stores a link's target as its blob; a Rust target lets the run reach the item comparison.
            (self.repo.root / listed).unlink()
            os.symlink('fn anchors() {}', self.repo.root / listed)
            return self.repo.commit({})

        # Only an in-place edit of a regular file is a validator edit; the rest is checked as usual.
        for name, change in (
            ('deleted', lambda: self.repo.commit({listed: None})),
            ('added', lambda: self.repo.commit({listed: test})),
            ('symlink', symlink),
        ):
            with self.subTest(name):
                before = self.repo.git('rev-parse', 'HEAD')
                status, out = run(self.repo, before, change())
                self.assertEqual(status, 1, out)
                self.assertNotIn('validator edits', out)

    def test_report_mode_exits_zero_and_no_rust_change_is_a_pass(self):
        status, out = self.move(ROOT.replace('fn second() {}', 'fn second() { todo!() }'), None, '--report')
        self.assertEqual(status, 0)
        self.assertIn('not a move: changed: fn second', out)
        head = self.repo.commit({'README.md': 'docs\n'})
        status, out = run(self.repo, self.repo.git('rev-parse', 'HEAD~1'), head)
        self.assertEqual(status, 0)
        self.assertIn('0 changed .rs files', out)

    def test_new_file_must_be_reachable(self):
        status, out = self.move(ROOT, {src('snapshots/stray.rs'): 'fn stray() {}\n'})
        self.assertEqual(status, 1)
        self.assertIn('not reachable by mod: crates/demo/src/snapshots/stray.rs', out)



def module_files(snapshots, files):
    """A crate whose snapshots root declares `snapshots` (mod lines) beside the given src/ files."""
    return {'lib.rs': 'pub mod snapshots;\n', 'snapshots.rs': snapshots, **files}


VALUE = 'pub(crate) fn v() -> u8 {{\n    {}\n}}\n'
MOVED_F = 'pub(crate) fn f() -> u8 {{\n    {}\n}}\n'


class ModulePathTests(unittest.TestCase):
    """Module paths and `use` bindings fail closed: each counterexample fails, each control passes.

    Shorthand: S = crate::snapshots; S::old (snapshots/old.rs) moves to S::dest::new (snapshots/dest/new.rs).
    """

    def change(self, base, head):
        """Commit the `base` src/ files, then apply `head` (None deletes), and run the checker."""
        repo = Repo(self)
        before = repo.commit({src(name): text for name, text in base.items()})
        after = repo.commit({src(name): text for name, text in head.items()})
        return run(repo, before, after)

    def fails(self, base, head, *messages):
        status, out = self.change(base, head)
        self.assertEqual(status, 1, out)
        for message in messages:
            self.assertIn(message, out)

    def passes(self, base, head, *messages):
        status, out = self.change(base, head)
        self.assertEqual(status, 0, out)
        for message in (*messages, 'move-only'):
            self.assertIn(message, out)

    SIBLINGS = {'snapshots/x.rs': VALUE.format(1), 'snapshots/y.rs': VALUE.format(2),
                'snapshots/z.rs': VALUE.format(3)}

    def move_f(self, root, old_path, new_path, head_root=None, files=None, head_files=None):
        """(base, head) that move fn f from S::old to S::dest::new, its path respelled old_path -> new_path."""
        base = module_files('mod old;\n' + root, {**self.SIBLINGS, 'snapshots/old.rs': MOVED_F.format(old_path),
                                                  **(files or {})})
        head = {'snapshots.rs': 'mod dest;\n' + (root if head_root is None else head_root),
                'snapshots/old.rs': None, 'snapshots/dest.rs': 'pub(crate) mod new;\n',
                'snapshots/dest/new.rs': MOVED_F.format(new_path), **(head_files or {})}
        return base, head

    def test_a_respelled_path_resolves_through_modules_to_the_same_item(self):
        root = 'mod x;\nmod y;\nmod z;\n'
        self.passes(*self.move_f(root, 'super::x::v()', 'super::super::x::v()'), ' 1 respelled,')
        # A respelling to a different sibling.
        self.fails(*self.move_f(root, 'super::x::v()', 'super::super::y::v()'), 'changed: fn f')
        # A needless respelling: `self::` still names the moved module's own item.
        local = {'snapshots/old.rs': MOVED_F.format('self::local()') + 'fn local() -> u8 {\n    1\n}\n'}
        base, head = self.move_f(root, 'self::local()', 'crate::snapshots::dest::new::local()', files=local)
        head['snapshots/dest/new.rs'] += 'fn local() -> u8 {\n    1\n}\n'
        self.fails(base, head, 'changed: fn f')

    def test_no_respelling_through_a_use_binding_and_no_repointed_alias(self):
        # Audit (f1): the alias x is re-pointed from y to z while f respells super::x to super::super::x.
        root = 'mod y;\nmod z;\nuse self::y as x;\n'
        base, head = self.move_f(root, 'super::x::v()', 'super::super::x::v()',
                                 head_root='mod y;\nmod z;\nuse self::z as x;\n')
        self.fails(base, head, 'changed: fn f',
                   '`use` binding x in crate::snapshots now names something else: self::y -> self::z')
        # Even with the alias unchanged, a path through it is never respelled.
        self.fails(*self.move_f(root, 'super::x::v()', 'super::super::x::v()'), 'changed: fn f')

    def test_a_crate_path_respelling_must_name_the_moved_item(self):
        # Audit (f2): the moved module's own item respelled to an unrelated existing module.
        local = {'snapshots/old.rs': MOVED_F.format('crate::snapshots::old::local()')
                 + 'fn local() -> u8 {\n    1\n}\n'}
        base, head = self.move_f('mod y;\n', 'crate::snapshots::old::local()', 'crate::snapshots::y::v()',
                                 files={**local, 'snapshots/y.rs': VALUE.format(2)})
        head['snapshots/dest/new.rs'] += 'fn local() -> u8 {\n    1\n}\n'
        self.fails(base, head, 'changed: fn f')
        # Control: respelled to the item's new home.
        base, head = self.move_f('', 'crate::snapshots::old::local()', 'crate::snapshots::dest::new::local()',
                                 files=local)
        head['snapshots/dest/new.rs'] += 'fn local() -> u8 {\n    1\n}\n'
        self.passes(base, head, ' 1 respelled,')

    PADDING = ''.join(f'fn padding_{n}() {{}}\n' for n in range(20))

    def test_an_edited_rename_maps_nothing_and_items_are_judged_by_their_pairs(self):
        def old(value):
            return MOVED_F.format('crate::snapshots::old::local()') + f'fn local() -> u8 {{\n    {value}\n}}\n' \
                + self.PADDING

        def new(value):
            return MOVED_F.format('crate::snapshots::dest::new::local()') \
                + f'fn local() -> u8 {{\n    {value}\n}}\n' + self.PADDING
        # Audit (f3): a plain edited rename (R082) fails on the edited item.
        base, head = self.move_f('', '', '', files={'snapshots/old.rs': old(1)})
        self.fails(base, {**head, 'snapshots/dest/new.rs': new(7)}, 'changed: fn local')
        # Audit (f3): R082 with local swapped against a decoy: every item pairs, but f's respelled path would
        # now reach the decoy's body; f's path names the item paired into decoy, so it fails.
        decoy = 'fn local() -> u8 {{\n    {}\n}}\n'
        base, head = self.move_f('mod decoy;\n', '', '', files={'snapshots/old.rs': old(1),
                                                                 'snapshots/decoy.rs': decoy.format(2)})
        self.fails(base, {**head, 'snapshots/dest/new.rs': new(2), 'snapshots/decoy.rs': decoy.format(1)},
                   'changed: fn f')

    PART = 'pub(crate) fn g() -> u8 {{\n    {}\n}}\n'

    def test_a_file_in_more_than_one_module_context_is_never_respelled(self):
        root = 'mod x;\n'
        # Audit (f4) controls: a single-context include! and #[path] file may be respelled.
        base = module_files('mod old;\n' + root, {**self.SIBLINGS, 'snapshots/old.rs': 'include!("part.rs");\n',
                                                  'snapshots/part.rs': self.PART.format('super::x::v()')})
        head = {'snapshots.rs': 'mod dest;\n' + root, 'snapshots/old.rs': None, 'snapshots/part.rs': None,
                'snapshots/dest.rs': 'pub(crate) mod new;\n', 'snapshots/dest/new.rs': 'include!("part.rs");\n',
                'snapshots/dest/part.rs': self.PART.format('super::super::x::v()')}
        self.passes(base, head, ' 1 respelled,')
        self.fails(base, {**head, 'snapshots/dest/part.rs': self.PART.format('super::super::y::v()')},
                   'changed: fn g')
        path_base = module_files('#[path = "snapshots/legacy.rs"]\nmod old;\n' + root,
                                 {**self.SIBLINGS, 'snapshots/legacy.rs': self.PART.format('super::x::v()')})
        path_head = {'snapshots.rs': 'mod dest;\n' + root, 'snapshots/legacy.rs': None,
                     'snapshots/dest.rs': '#[path = "new_impl.rs"]\npub(crate) mod new;\n',
                     'snapshots/new_impl.rs': self.PART.format('super::super::x::v()')}
        self.passes(path_base, path_head, ' 1 respelled,')
        # Audit (f4): the moved file is also crate::other::wrap::old through #[path]; there super::x is
        # other::wrap::x before and other::x after.
        other = {'lib.rs': 'pub mod snapshots;\npub mod other;\n', 'other.rs': 'pub mod wrap;\nmod x;\n',
                 'other/x.rs': VALUE.format(3), 'other/wrap/x.rs': VALUE.format(2)}
        wrap = '#[path = "../snapshots/old.rs"]\nmod old;\nmod x;\n'
        base = module_files('mod old;\n' + root, {**self.SIBLINGS, **other, 'other/wrap.rs': wrap,
                                                  'snapshots/old.rs': self.PART.format('super::x::v()')})
        head = {'snapshots.rs': 'mod dest;\n' + root, 'snapshots/old.rs': None,
                'snapshots/dest.rs': 'pub(crate) mod new;\n',
                'snapshots/dest/new.rs': self.PART.format('super::super::x::v()'),
                'other/wrap.rs': '#[path = "../snapshots/dest/new.rs"]\nmod old;\nmod x;\n'}
        self.fails(base, head, 'changed: fn g')
        # Audit (f4): part.rs is included from snapshots/old.rs and from other/wrap/old.rs.
        base = module_files('mod old;\n' + root, {
            **self.SIBLINGS, **other, 'other/wrap.rs': 'mod old;\nmod x;\n',
            'snapshots/old.rs': 'include!("part.rs");\n', 'snapshots/part.rs': self.PART.format('super::x::v()'),
            'other/wrap/old.rs': 'include!("../../snapshots/part.rs");\n'})
        head = {'snapshots.rs': 'mod dest;\n' + root, 'snapshots/old.rs': None, 'snapshots/part.rs': None,
                'snapshots/dest.rs': 'pub(crate) mod new;\n', 'snapshots/dest/new.rs': 'include!("part.rs");\n',
                'snapshots/dest/part.rs': self.PART.format('super::super::x::v()'),
                'other/wrap/old.rs': 'include!("../../snapshots/dest/part.rs");\n'}
        self.fails(base, head, 'changed: fn g')

    def test_no_respelling_inside_a_string_a_macro_call_or_an_attribute(self):
        root = 'mod x;\n'
        text = 'pub(crate) fn f() -> &\'static str {{\n    {}\n}}\n'
        for name, before, after in (
            ('string literal', '"super::x::v"', '"super::super::x::v"'),
            ('macro call', 'stringify!(super::x::v)', 'stringify!(super::super::x::v)'),
            ('macro call with brackets', 'concat![stringify!(super::x::v)]', 'concat![stringify!(super::super::x::v)]'),
        ):
            with self.subTest(name):
                base, head = self.move_f(root, '', '', files={'snapshots/old.rs': text.format(before)})
                self.fails(base, {**head, 'snapshots/dest/new.rs': text.format(after)}, 'changed: fn f')
        attribute = '#[cfg_attr(test, derive({}))]\npub(crate) struct Probe;\n'
        base, head = self.move_f(root, '', '', files={'snapshots/old.rs': attribute.format('super::x::Marker')})
        self.fails(base, {**head, 'snapshots/dest/new.rs': attribute.format('super::super::x::Marker')},
                   'changed: struct Probe')

    def test_function_local_use_respelling_and_top_level_use_bindings(self):
        root = 'mod x;\nmod y;\n'
        body = 'pub(crate) fn f() -> u8 {{\n    use {}::{{self, v}};\n    v() + x::v()\n}}\n'
        base, head = self.move_f(root, '', '', files={'snapshots/old.rs': body.format('super::x')})
        # Audit (f6) control: a function-local `use` respelled to the same module.
        self.passes(base, {**head, 'snapshots/dest/new.rs': body.format('super::super::x')}, ' 1 respelled,')
        # A changed leaf and a glob from an unrelated module fail.
        bad = body.format('super::super::x').replace('self, v', 'self, bad')
        self.fails(base, {**head, 'snapshots/dest/new.rs': bad}, 'changed: fn f')
        glob = 'pub(crate) fn f() -> u8 {{\n    use {}::*;\n    v()\n}}\n'
        base, head = self.move_f(root, '', '', files={'snapshots/old.rs': glob.format('super::x')})
        self.fails(base, {**head, 'snapshots/dest/new.rs': glob.format('super::super::y')}, 'changed: fn f')
        # Top-level `use` trees: a re-pointed brace leaf, `self` alias and glob fail; added and removed are glue.
        siblings = module_files(root, self.SIBLINGS)
        for name, before, after, message in (
            ('brace leaf', 'use self::x::{v};\n', 'use self::y::{v};\n',
             '`use` binding v in crate::snapshots now names something else: self::x::v -> self::y::v'),
            ('self alias', 'use self::x::{self as w};\n', 'use self::y::{self as w};\n',
             '`use` binding w in crate::snapshots now names something else: self::x -> self::y'),
            ('glob', 'use self::x::*;\n', 'use self::y::*;\n',
             '`use` binding glob in crate::snapshots now names something else: self::x -> self::y'),
        ):
            with self.subTest(name):
                self.fails({**siblings, 'snapshots.rs': root + before}, {'snapshots.rs': root + after}, message)
        self.passes({**siblings, 'snapshots.rs': root + 'use self::x::v;\n'},
                    {'snapshots.rs': root + 'use self::y::v as w;\nuse self::x::*;\n'})
        # A same-target respelling of an existing binding passes; through a binding it fails.
        self.passes({**siblings, 'snapshots.rs': root + 'use self::x::v;\n'},
                    {'snapshots.rs': root + 'use crate::snapshots::x::v;\n'}, ' 1 respelled,',
                    'respelled `use` v in crate::snapshots: self::x::v -> crate::snapshots::x::v')
        self.fails({**siblings, 'snapshots.rs': root + 'use self::y as w;\nuse self::y::v;\n'},
                   {'snapshots.rs': root + 'use self::y as w;\nuse self::w::v;\n'},
                   '`use` binding v in crate::snapshots now names something else')

    CALLER = 'pub(crate) fn call() -> u8 {{\n    {}\n}}\n'

    def facade_move(self, alias, caller='crate::snapshots::old::local()'):
        old = 'pub(crate) fn local() -> u8 {\n    1\n}\n' + self.PADDING
        root = 'mod y;\nmod z;\nmod caller;\n'
        base = module_files('mod old;\n' + root, {'snapshots/old.rs': old, 'snapshots/y.rs': 'pub(crate) mod old;\n',
                                                  'snapshots/z.rs': 'pub(crate) fn local() -> u8 {\n    2\n}\n',
                                                  'snapshots/y/old.rs': 'pub(crate) fn local() -> u8 {\n    2\n}\n',
                                                  'snapshots/caller.rs': self.CALLER.format(
                                                      'crate::snapshots::old::local()')})
        head = {'snapshots.rs': 'mod dest;\n' + root + alias, 'snapshots/old.rs': None,
                'snapshots/dest.rs': 'pub(crate) mod new;\n', 'snapshots/dest/new.rs': old,
                'snapshots/caller.rs': self.CALLER.format(caller)}
        return base, head

    def test_a_facade_alias_must_name_the_moved_module(self):
        # Audit (f7) control: the alias names the exact rename's head module.
        self.passes(*self.facade_move('pub(crate) use self::dest::new as old;\n'),
                    'facade alias crate::snapshots::old -> crate::snapshots::dest::new')
        # Audit (f7): the unchanged caller would now reach z's local, or y::old's.
        for alias in ('self::z', 'self::y::old'):
            with self.subTest(alias):
                self.fails(*self.facade_move(f'use {alias} as old;\n'),
                           '`use` binds the old name of moved module crate::snapshots::old without naming its mapped '
                           f'head path (crate::snapshots::dest::new): `{alias}`')
        self.fails(*self.facade_move('pub(crate) use self::y::*;\n'),
                   'glob `use self::y::*` in crates/demo/src/snapshots.rs can bind the old name of moved module '
                   'crate::snapshots::old')
        # An unmoved item may not respell its path to the moved module.
        self.fails(*self.facade_move('pub(crate) use self::dest::new as old;\n',
                                     caller='crate::snapshots::dest::new::local()'), 'changed: fn call')

    MODEL = 'pub(crate) fn total() -> u8 {{\n    {}\n}}\n{}#[cfg(test)]\nmod tests;\n'
    UPLOAD = 'pub(crate) struct Slot;\n' + ''.join(f'fn slot_{n}() {{}}\n' for n in range(20))

    def nest_model(self, model=None, decl='pub(in crate::snapshots) mod upload;\n', upload=True):
        """(base, head): S::obs (the model, with its tests file) moves to S::usage::obs, whose old content (the
        upload state) moves to its child S::usage::obs::upload; the model gains `decl`; a facade alias keeps the
        old root name and the root's import of the upload state is respelled."""
        tests = 'use super::*;\n\n#[test]\nfn adds() {\n    assert_eq!(total(), 1);\n}\n'
        base = module_files('mod obs;\nmod usage;\nuse self::usage::obs::Slot;\n', {
            'snapshots/obs.rs': self.MODEL.format(1, self.PADDING), 'snapshots/obs/tests.rs': tests,
            'snapshots/usage.rs': 'pub(super) mod obs;\n', 'snapshots/usage/obs.rs': self.UPLOAD})
        head = {'snapshots.rs': 'mod usage;\nuse self::usage::obs::upload::Slot;\nuse usage::obs;\n',
                'snapshots/obs.rs': None, 'snapshots/obs/tests.rs': None,
                'snapshots/usage/obs.rs': model or self.MODEL.format(1, self.PADDING + decl),
                'snapshots/usage/obs/tests.rs': tests}
        if upload:
            head['snapshots/usage/obs/upload.rs'] = self.UPLOAD
        return base, head

    def test_a_rename_exact_but_for_an_added_mod_declaration_maps_its_module(self):
        # The model file gains `mod upload;` for its child: exact once that declaration is left out.
        self.passes(*self.nest_model(), ' 0 widened, 0 problems',
                    'module crate::snapshots::obs -> crate::snapshots::usage::obs',
                    'module crate::snapshots::usage::obs -> crate::snapshots::usage::obs::upload',
                    'facade alias crate::snapshots::obs -> crate::snapshots::usage::obs',
                    'respelled `use` Slot in crate::snapshots: self::usage::obs::Slot -> '
                    'self::usage::obs::upload::Slot')
        # Near misses: the model also changes one token, or gains a blank line with the declaration.
        unmapped = '`use` binds the old name of moved module crate::snapshots::obs without naming its mapped head ' \
                   'path (?)'
        self.fails(*self.nest_model(self.MODEL.format(2, self.PADDING + 'pub(in crate::snapshots) mod upload;\n')),
                   'changed: fn total', unmapped)
        self.fails(*self.nest_model(decl='\npub(in crate::snapshots) mod upload;\n'), unmapped)
        # Only whole added or removed declarations are left out: not a `#[macro_use]` one, not a changed one.
        self.fails(*self.nest_model(decl='#[macro_use]\nmod upload;\n'), unmapped)
        self.fails(*self.nest_model(self.MODEL.format(1, self.PADDING + 'mod upload;\n').replace(
            'mod tests;', 'pub(crate) mod tests;')), unmapped)

    def test_a_phantom_mod_declaration_is_not_left_out(self):
        # `mod ghost;` has no child file: the rename is not exact, so it maps nothing.
        base, head = self.nest_model()
        head['snapshots/usage/obs.rs'] = self.MODEL.format(1, self.PADDING + 'mod ghost;\n')
        self.fails(base, head, 'unresolved mod at crates/demo/src/snapshots/usage/obs.rs',
                   '`use` binds the old name of moved module crate::snapshots::obs without naming its mapped head '
                   'path (?)')

    def test_an_exact_copy_maps_only_when_its_source_path_was_rewritten_by_another_pair(self):
        old = 'pub(crate) fn local() -> u8 {\n    1\n}\n' + self.PADDING
        base = module_files('mod old;\nmod dest;\n', {'snapshots/old.rs': old, 'snapshots/dest.rs': ''})
        copy = {'snapshots/dest.rs': 'mod new;\n', 'snapshots/dest/new.rs': old}
        # The source stays unchanged, or is rewritten by no pair, while a copy of its content appears elsewhere.
        for name, source in (('unchanged', {}),
                             ('rewritten', {'snapshots/old.rs': 'pub(crate) fn other() -> u8 {\n    3\n}\n'})):
            with self.subTest(name):
                status, out = self.change(base, {**copy, **source})
                self.assertEqual(status, 1, out)
                self.assertNotIn('file map:', out)
        # One rename and one copy of the same source: only the rename maps.
        status, out = self.change(base, {'snapshots.rs': 'mod dest;\n', 'snapshots/old.rs': None,
                                         'snapshots/dest.rs': 'mod new;\nmod copy;\n',
                                         'snapshots/dest/new.rs': old, 'snapshots/dest/copy.rs': old})
        self.assertEqual(status, 1, out)
        self.assertIn('file map: 1 exact renames of .rs files, 1 module moves', out)

    def test_the_respelled_count_is_always_in_the_summary(self):
        # No file is renamed: the respelled count still shows in the main summary line.
        root = 'mod x;\nmod old;\n'
        base = module_files(root, {**self.SIBLINGS, 'snapshots/old.rs': 'fn keep() {}\n\n'
                                   + MOVED_F.format('super::x::v()')})
        head = {'snapshots.rs': root + 'mod dest;\n', 'snapshots/old.rs': 'fn keep() {}\n',
                'snapshots/dest.rs': 'pub(crate) mod new;\n', 'snapshots/dest/new.rs': MOVED_F.format(
                    'super::super::x::v()')}
        status, out = self.change(base, head)
        self.assertEqual(status, 0, out)
        self.assertIn(' 1 moved, 0 reflowed, 1 respelled, 0 widened, 0 problems', out)
        self.assertNotIn('file map:', out)

if __name__ == '__main__':
    unittest.main()
