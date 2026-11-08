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
        self.assertIn(' 1 moved, 1 reflowed, 0 widened, 0 problems', out)
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
        self.assertIn(' 1 moved, 1 reflowed, 0 widened, 0 problems', out)
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
                self.assertIn(' 1 moved, 1 reflowed, 0 widened, 0 problems', out)
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

    def test_a_number_literal_is_one_token_in_a_reflow(self):
        # [regress] Numeric boundaries remain exact on the existing fn/struct reflow surfaces.
        for value in ('1.0', '1e-3', '2.5E+10', '0x1F', '1_000u64', '1.0f32', '1.'):
            with self.subTest(value=value):
                before = f'fn f(value: [u8; {value}]) {{}}\n'
                after = f'pub(super) fn f(\n    value: [u8; {value}],\n) {{}}\n'
                status, out = self.move_long(after, before)
                self.assertEqual(status, 0, out)
                self.assertIn(' 1 moved, 1 reflowed,', out)
        for before, after in (('1.0', '1 . 0'), ('1.0', '1 .0'), ('1e-3', '1e - 3'), ('1.0f32', '1. 0f32'),
                              ('1.5', '1 .5'), ('0x1F', '0x 1F'), ('1_000u64', '1_000 u64'), ('1.', '1 .')):
            for kind in ('fn', 'struct'):
                with self.subTest(after=after, kind=kind):
                    old = (f'fn f(value: [u8; {before}]) {{}}\n' if kind == 'fn' else
                           f'struct T {{ value: [u8; {before}], }}\n')
                    new = (f'pub(super) fn f(\n    value: [u8; {after}],\n) {{}}\n' if kind == 'fn' else
                           f'pub(super) struct T {{\n    value: [u8; {after}],\n}}\n')
                    status, out = self.move_long(new, old)
                    self.assertEqual(status, 1, out)
                    self.assertIn(' 0 reflowed,', out)

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
        self.assertIn(' 2 moved, 0 reflowed, 0 widened, 0 problems', out)
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
    """A crate whose snapshots root is `snapshots`, beside the given src/ files."""
    return {'lib.rs': 'pub mod snapshots;\n', 'snapshots.rs': snapshots, **files}


VALUE = 'pub(crate) fn v() -> u8 {{\n    {}\n}}\n'
MOVED_F = 'pub(crate) fn f() -> u8 {{\n    {}\n}}\n'


class UseBindingTests(unittest.TestCase):
    """`use` glue fails closed: each counterexample fails, each control passes.

    Shorthand: S = crate::snapshots; S::old (snapshots/old.rs) moves to S::dest::new (snapshots/dest/new.rs).
    """

    SIBLINGS = {'snapshots/x.rs': VALUE.format(1), 'snapshots/z.rs': VALUE.format(2)}
    ROOT = 'mod x;\nmod z;\n'

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

    def root(self, uses, body='self::x::v()'):
        return module_files(self.ROOT + uses + MOVED_F.format(body), self.SIBLINGS)

    def move_f(self, old, new):
        """(base, head) that move S::old (fn f after the `old` text) to S::dest::new (after the `new` text)."""
        base = module_files('mod old;\n' + self.ROOT,
                            {**self.SIBLINGS, 'snapshots/old.rs': old + MOVED_F.format('v()')})
        head = {'snapshots.rs': 'mod dest;\n' + self.ROOT, 'snapshots/old.rs': None,
                'snapshots/dest.rs': 'pub(crate) mod new;\n', 'snapshots/dest/new.rs': new + MOVED_F.format('v()')}
        return base, head

    def test_a_path_changed_inside_a_moved_item_fails(self):
        base, head = self.move_f('use super::x::v;\n', 'use super::super::x::v;\n')
        self.passes(base, head, ' 1 moved,')
        base['snapshots/old.rs'] = MOVED_F.format('super::x::v()')
        head['snapshots/dest/new.rs'] = MOVED_F.format('super::super::x::v()')
        self.fails(base, head, 'changed: fn f')

    def test_an_existing_binding_keeps_its_path_visibility_attributes_and_count(self):
        both = '#[cfg(test)]\nuse self::x as y;\n#[cfg(not(test))]\nuse self::z as y;\n'
        swapped = '#[cfg(not(test))]\nuse self::x as y;\n#[cfg(test)]\nuse self::z as y;\n'
        for name, before, after, message in (
            ('cfg duplicates swapped', both, swapped,
             'use binding changed: y in crate::snapshots (crates/demo/src/snapshots.rs:3): '
             '#[cfg(test)] use self::x as y; #[cfg(not(test))] use self::z as y -> '
             '#[cfg(not(test))] use self::x as y; #[cfg(test)] use self::z as y'),
            ('cfg duplicate dropped', both, '#[cfg(test)]\nuse self::x as y;\n', 'use binding changed: y'),
            ('cfg added', 'use self::x as y;\n', '#[cfg(test)]\nuse self::x as y;\n', 'use binding changed: y'),
            ('re-pointed', 'use self::x as y;\n', 'use self::z as y;\n', 'use binding changed: y'),
            ('respelled', 'use self::x as y;\n', 'use crate::snapshots::x as y;\n', 'use binding changed: y'),
            ('widened', 'pub(in crate::snapshots) use self::x::v;\n', 'pub use self::x::v;\n',
             'use binding changed: v in crate::snapshots (crates/demo/src/snapshots.rs:3): '
             'pub(in crate::snapshots) use self::x::v -> pub use self::x::v'),
            ('narrowed', 'pub(crate) use self::x::v;\n', 'use self::x::v;\n', 'use binding changed: v'),
            ('glob attribute', 'use self::x::*;\n', '#[cfg(test)]\nuse self::x::*;\n',
             'use binding changed: self::x::* in crate::snapshots'),
        ):
            with self.subTest(name):
                body = 'y::v()' if ' y;' in before else 'v()'
                self.fails(self.root(before, body), self.root(after, body), message)
        # Regrouped, added and removed bindings are glue.
        self.passes(self.root('use self::x::v;\nuse self::z as y;\n', 'v() + y::v()'),
                    self.root('use self::{x::v, z as y};\n', 'v() + y::v()'))
        self.passes(self.root('use self::x::v;\n', 'v()'), self.root('use self::x::v;\nuse self::z as w;\n', 'v()'))
        self.passes(self.root('use self::z as w;\n'), self.root(''))

    def test_a_binding_moved_to_another_module_may_not_reach_further(self):
        base, head = self.move_f('use crate::snapshots::x::v;\n', 'pub(crate) use crate::snapshots::x::v;\n')
        self.fails(base, head, 'widened: use v (crates/demo/src/snapshots/dest/new.rs:1): private in '
                   'crate::snapshots::old -> pub(crate) in crate::snapshots::dest::new')
        base, head = self.move_f('pub(super) use crate::snapshots::x::v;\n',
                                 'pub(in crate::snapshots) use crate::snapshots::x::v;\n')
        self.passes(base, head, ' 0 widened,')

    def test_every_new_glob_in_a_module_with_moved_items_fails(self):
        base, head = self.move_f('use super::x::v;\n', 'use crate::snapshots::x::*;\nuse super::super::x::v;\n')
        self.fails(base, head, 'new glob import: use crate::snapshots::x::* in crate::snapshots::dest::new')
        # The split pattern: a new module imports everything from the module its items came from.
        base = module_files(self.ROOT + 'use self::x::v;\n' + MOVED_F.format('v()'), self.SIBLINGS)
        moved = {'snapshots.rs': 'mod dest;\n' + self.ROOT + 'use self::x::v;\n'}
        for glob in ('crate::snapshots', 'super'):
            with self.subTest(glob):
                self.fails(base, {**moved, 'snapshots/dest.rs': f'use {glob}::*;\n\n' + MOVED_F.format('v()')},
                           'new glob import:')
        # Any other glob beside a moved item fails, including one that can shadow a prelude name.
        custom = {'snapshots/custom.rs': '#[allow(non_snake_case)]\npub(crate) fn Some(value: u8) -> u8 {\n'
                                         '    value + 1\n}\n'}
        for name, files, uses in (
            ('unrelated', {}, 'use crate::snapshots::z::*;\n'),
            ('prelude shadow', custom, 'use super::*;\nuse super::custom::*;\n'),
        ):
            with self.subTest(name):
                root = moved['snapshots.rs'] + ('mod custom;\n' if files else '')
                self.fails({**base, **files, 'snapshots.rs': base['snapshots.rs'] + ('mod custom;\n' if files else '')},
                           {'snapshots.rs': root, 'snapshots/dest.rs': uses + MOVED_F.format('v()')},
                           'new glob import:')
        # A new glob in a module that existed at base fails, even without a move.
        self.fails(self.root('use self::x::v;\n', 'v()'), self.root('use self::x::v;\nuse self::z::*;\n', 'v()'),
                   'new glob import: use self::z::* in crate::snapshots')
        base['snapshots/dest.rs'] = ''
        base['snapshots.rs'] = 'mod dest;\n' + base['snapshots.rs']
        self.fails(base, {**moved, 'snapshots/dest.rs': 'use super::*;\n' + MOVED_F.format('v()')},
                   'new glob import: use super::* in crate::snapshots::dest')

    MACRO = 'macro_rules! imports {\n    () => {\n        use crate::snapshots::x::*;\n    };\n}\nimports!();\n'

    def test_a_use_added_beside_a_moved_macro_call_fails(self):
        # A macro call can expand to a `use` this check cannot see: an explicit binding added beside it
        # can shadow what the expansion bound (v from x becomes v from z).
        base, head = self.move_f(self.MACRO, self.MACRO + 'use crate::snapshots::z::v;\n')
        self.fails(base, head, 'use added beside an item-level macro call: use crate::snapshots::z::v in '
                   'crate::snapshots::dest::new')
        # A name bound explicitly at the source grants no exception beside a macro.
        base, head = self.move_f(self.MACRO + 'use crate::snapshots::x::v;\n',
                                 self.MACRO + 'use crate::snapshots::x::v;\n')
        self.fails(base, head, 'use added beside an item-level macro call:')
        # A name previously defined by an item grants no exception either.
        root = self.ROOT + self.MACRO.replace('imports', 'stays') + 'fn g() -> u8 {\n    1\n}\n'
        base = module_files(root + MOVED_F.format('g()'), self.SIBLINGS)
        moved = {'snapshots/dest.rs': 'use super::*;\n\n' + MOVED_F.format('g()')}
        self.fails(base, {**moved, 'snapshots.rs': 'mod dest;\n' + root + 'use dest::f;\n'},
                   'use added beside an item-level macro call:')
        self.fails(base, {**moved, 'snapshots.rs': 'mod dest;\n' + root + 'use self::z::v;\n'},
                   'use added beside an item-level macro call: use self::z::v in crate::snapshots')

    def test_source_globs_cannot_prove_a_binding_kept_its_identity(self):
        # [regress] A source glob can inherit a newly shadowed value, prelude name or facade.
        for name, body, extra in (
            ('value', 'v()', 'use self::z::v;\n'),
            ('prelude', 'Some(1).unwrap_or(0)', 'use self::custom::Some;\n'),
            ('facade', 'v()', 'use self::z as old;\n'),
        ):
            with self.subTest(name):
                siblings = {**self.SIBLINGS, 'snapshots/custom.rs':
                            '#[allow(non_snake_case)]\npub(crate) fn Some(_: u8) -> Option<u8> { None }\n'}
                if name == 'facade':
                    base = module_files(self.ROOT + 'mod old;\nmod custom;\n',
                                        {**siblings, 'snapshots/old.rs': VALUE.format(1) + MOVED_F.format(body)})
                    head = {'snapshots.rs': self.ROOT + 'mod dest;\nmod custom;\n' + extra,
                            'snapshots/old.rs': None, 'snapshots/dest.rs':
                            'use crate::snapshots::old::*;\n' + MOVED_F.format(body),
                            'snapshots/elsewhere.rs': VALUE.format(1)}
                    head['snapshots.rs'] += 'mod elsewhere;\n'
                else:
                    root = self.ROOT + 'mod custom;\nuse self::x::*;\n'
                    base = module_files(root + MOVED_F.format(body), siblings)
                    head = {'snapshots.rs': root + 'mod dest;\n' + extra,
                            'snapshots/dest.rs': 'use super::*;\n' + MOVED_F.format(body)}
                self.fails(base, head, 'new glob import:')

    def test_macro_names_do_not_prove_an_added_binding_is_safe(self):
        # [regress] Source binding, moved definition, disabled value and type namespace grant no exception.
        base, head = self.move_f(self.MACRO + 'use crate::snapshots::x::v;\n',
                                 self.MACRO + 'use crate::snapshots::z::v;\n')
        self.fails(base, head, 'use added beside an item-level macro call:')
        for definition in ('fn v() -> u8 { 1 }\n', '#[cfg(any())]\nfn v() -> u8 { 1 }\n', 'trait v {}\n'):
            with self.subTest(definition=definition):
                root = self.ROOT + self.MACRO
                base = module_files(root + definition + MOVED_F.format('v()'), self.SIBLINGS)
                head = {'snapshots.rs': root + 'mod dest;\nuse self::z::v;\n' + MOVED_F.format('v()'),
                        'snapshots/dest.rs': definition}
                self.fails(base, head, 'use added beside an item-level macro call:')

    def test_binding_attributes_preserve_original_literal_bytes(self):
        # [regress] Global whitespace squash must not erase a cfg string, char or raw literal change.
        for before, after in (('"a  b"', '"a b"'), ('r#"a  b"#', 'r#"a b"#'), ("'\t'", "' '")):
            with self.subTest(before=before):
                uses = f'#[cfg(flavor={before})]\nuse self::x as y;\n#[cfg(not(flavor={before}))]\nuse self::z as y;\n'
                changed = uses.replace(before, after)
                self.fails(self.root(uses, 'y::v()'), self.root(changed, 'y::v()'), 'use binding changed: y')
                # Both an inline and an outlined parent contribute their original attributes.
                for outlined in (False, True):
                    base = module_files(f'#[cfg(flavor={before})]\nmod old' + (';\n' if outlined else
                                        ' {\nuse super::x as y;\n}\n') + self.ROOT,
                                        {**self.SIBLINGS, **({'snapshots/old.rs': 'use super::x as y;\n'}
                                                           if outlined else {})})
                    head = {'snapshots.rs': base['snapshots.rs'].replace(before, after)}
                    self.fails(base, head, 'use binding changed: y')
        self.passes(self.root('#[cfg(flavor="a  b")]\nuse self::x as y;\n', 'y::v()'),
                    self.root('#[cfg(flavor="a  b")]\n\nuse self::x as y;\n', 'y::v()'))


if __name__ == '__main__':
    unittest.main()
