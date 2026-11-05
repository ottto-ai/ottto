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
            # A struct whose field visibilities trade places at the same text offsets.
            ('pub(crate) struct S {\n    pub(crate) a: u8,\n    b: u8,\n}\n',
             'pub(crate) struct S {a:u8,pub(crate) b:u8,}\n'),
        ):
            with self.subTest(after=after):
                status, out = self.move_long(after, before)
                self.assertEqual(status, 1, out)
                self.assertIn(' 0 reflowed,', out)

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


if __name__ == '__main__':
    unittest.main()
