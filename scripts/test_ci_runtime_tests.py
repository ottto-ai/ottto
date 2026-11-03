#!/usr/bin/env python3
"""Synthetic regressions for ci_runtime_tests.py; never runs cargo."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('ci_runtime_tests.py').resolve()
spec = importlib.util.spec_from_file_location('ci_runtime_tests', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SerialSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.src = Path(self.temp.name)

    def write(self, name, text):
        path = self.src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def test_every_attribute_form_marks_the_next_fn(self):
        self.write('a.rs', '\n'.join([
            'use serial_test::serial;',
            '// Tests below hold #[serial] because they swap HOME.',
            '#[test]',
            '#[serial]',
            'fn bare() {}',
            '#[test]',
            '#[serial(source_manifests)]',
            '#[serial(client_report)]',
            '/// Stacked keys.',
            '#[ignore = "run natively in serial isolation"]',
            '',
            'fn stacked() {}',
            '#[test]',
            'fn not_serial() {}',
        ]))
        self.write('nested/b.rs', '    #[serial_test::serial(source_cadences)]\n    #[test]\n    pub fn pathed() {}\n')
        self.assertEqual(runner.serial_test_functions(self.src), {'bare', 'stacked', 'pathed'})

    def test_multi_line_attribute_after_serial(self):
        self.write('a.rs', '\n'.join([
            '#[test]',
            '#[serial(source_manifests)]',
            '#[cfg_attr(',
            '    not(any(target_os = "macos", target_os = "linux")),',
            '    ignore = "needs macOS heap layout"',
            ')]',
            'fn gated() {}',
        ]) + '\n')
        self.assertEqual(runner.serial_test_functions(self.src), {'gated'})

    def test_unknown_forms_fail_closed(self):
        cases = {
            'parallel': '#[parallel]\n#[test]\nfn a() {}\n',
            'file lock': '#[file_serial]\n#[test]\nfn a() {}\n',
            'same line': '#[test] #[serial]\nfn a() {}\n',
            'grouped use': 'use serial_test::{serial, parallel};\n',
            'cfg_attr': '#[cfg_attr(test, serial)]\nfn a() {}\n',
            'macro body': '#[serial]\n#[test]\nfn $name() {}\n',
            'dangling': '#[serial]\n',
            'multi-line cfg_attr': '#[serial]\n#[cfg_attr(\n    test,\n    parallel\n)]\nfn a() {}\n',
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.write('a.rs', text)
                with self.assertRaises(runner.SetupError):
                    runner.serial_test_functions(self.src)

    def test_a_tree_without_serial_tests_is_an_error(self):
        self.write('a.rs', '#[test]\nfn a() {}\n')
        with self.assertRaises(runner.SetupError):
            runner.serial_test_functions(self.src)

    def test_the_service_crate_parses(self):
        source = SCRIPT.parent.parent / runner.SERVICE_SRC
        self.assertGreater(len(runner.serial_test_functions(source)), 100)


class GroupTests(unittest.TestCase):
    def test_selects_by_function_name_and_rejects_clashes(self):
        lib = ['a::tests::one', 'a::tests::two', 'b::tests::one']
        others = ['tests::cli_case']
        self.assertEqual(runner.serial_group(lib, {'one'}), ['a::tests::one', 'b::tests::one'])
        runner.require_unique(['a::tests::one'], lib + others)
        with self.assertRaises(runner.SetupError):
            runner.require_unique(['a::tests::one'], lib + others + ['a::tests::one'])
        with self.assertRaises(runner.SetupError):
            runner.serial_group(lib, {'missing'})

    def test_shards_cover_every_name_once(self):
        names = [f't{i}' for i in range(10)]
        shares = [runner.shard_of(names, (i, 3)) for i in (1, 2, 3)]
        self.assertEqual(sorted(sum(shares, [])), sorted(names))
        self.assertEqual(shares[0], ['t0', 't3', 't6', 't9'])
        self.assertEqual(runner.shard_of(names, (1, 1)), names)


class SummaryTests(unittest.TestCase):
    STREAM = [
        '\x1b[1m\x1b[92m     Running\x1b[0m unittests src/lib.rs (target/debug/deps/ottto_core-0123abcd)\n',
        'test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n',
        '     Running unittests src/lib.rs (target/debug/deps/ottto_service-89abcdef)\n',
        'running 5 tests\n',
        'Running a child probe\n',
        'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.0s\n',
        'test result: FAILED. 3 passed; 1 failed; 1 ignored; 0 measured; 2 filtered out; finished in 9s\n',
        '     Running unittests src/main.rs (target/debug/deps/ottto_service-76543210)\n',
        'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n',
        '   Doc-tests ottto_service\n',
    ]

    def test_lib_summary_is_the_last_one_inside_the_lib_target(self):
        summary = runner.libtest_log.lib_summary
        self.assertEqual(summary(self.STREAM, 'ottto_service'), (3, 1, 1, 0, 2))
        self.assertEqual(summary(self.STREAM[3:7], None), (3, 1, 1, 0, 2))
        self.assertIsNone(summary(self.STREAM[:2], 'ottto_service'))

    def test_counts_must_partition_the_lib(self):
        self.assertEqual(runner.check_counts('g', (3, 1, 1, 0, 2), 5, 2), [])
        self.assertTrue(runner.check_counts('g', (3, 1, 1, 0, 2), 5, 3))
        self.assertTrue(runner.check_counts('g', (3, 1, 0, 0, 2), 5, 2))
        self.assertTrue(runner.check_counts('g', None, 5, 2))

    def test_required_test_must_print_ok(self):
        lines = ['test a::receipt ... ok\n', 'test b::flaky ... ok\n', 'test b::flaky ... FAILED\n',
                 'test c::skipped ... ignored\n']
        self.assertEqual(runner.require_passed(['a::receipt'], lines), [])
        self.assertEqual(
            runner.require_passed(['b::flaky', 'c::skipped', 'receipt'], lines),
            ['b::flaky: did not pass (FAILED)', 'c::skipped: did not pass (ignored)', 'receipt: did not pass (not run)'],
        )


class RetryTests(unittest.TestCase):
    LIB = '     Running unittests src/lib.rs (target/debug/deps/ottto_service-89abcdef)\n'
    CLI = '     Running tests/cli.rs (target/debug/deps/cli-0123abcd)\n'

    @staticmethod
    def summary(passed, failed):
        state = 'FAILED' if failed else 'ok'
        return f'test result: {state}. {passed} passed; {failed} failed; 0 ignored; 0 measured; 0 filtered out\n'

    @staticmethod
    def exited(binary, status='exit status: 101'):
        """Cargo's two lines for a failing test binary."""
        return (f'error: test failed, to rerun pass `--lib`\nCaused by:\n'
                f"  process didn't exit successfully: `/w/target/debug/deps/{binary} --nocapture --exact` "
                f'({status})\n')

    def plan(self, lines, required=(), limit=3, scope_of=lambda binary: [binary], status=101):
        return runner.retry_plan([(lines, scope_of, status)], set(required), limit)

    def test_failed_names_map_to_their_binary(self):
        lines = [self.LIB, 'test a::one ... FAILED\n', 'test a::two ... ok\n', self.summary(1, 1),
                 self.exited('ottto_service-89abcdef'),
                 self.CLI, 'test case ... FAILED\n', self.summary(0, 1), self.exited('cli-0123abcd'),
                 '   Doc-tests ottto_service\n', self.summary(2, 0)]
        self.assertEqual(self.plan(lines), ([('a::one', ['ottto_service-89abcdef']), ('case', ['cli-0123abcd'])], None))

    def test_retries_nothing_it_cannot_tie_to_a_name(self):
        lib_fail = [self.LIB, 'test a::one ... FAILED\n']
        flaky_one = [self.CLI, 'test case ... FAILED\n', self.summary(0, 1), self.exited('cli-0123abcd')]
        cases = {
            'crash': lib_fail + [self.exited('ottto_service-89abcdef')],
            'count mismatch': lib_fail + [self.summary(0, 2), self.exited('ottto_service-89abcdef')],
            'signal': lib_fail + [self.summary(0, 1), self.exited('ottto_service-89abcdef', 'signal: 11, SIGSEGV')],
            'no cargo exit line': lib_fail + [self.summary(0, 1)],
            # A child probe printed a clean summary, then the binary aborted; a
            # retried flaky test elsewhere must not turn that green.
            'crash after child summary': [self.LIB, 'running 1 test\n', self.summary(1, 0),
                                          self.exited('ottto_service-89abcdef', 'signal: 6, SIGABRT')] + flaky_one,
            'non-zero exit, clean summary': [self.LIB, self.summary(3, 0),
                                             self.exited('ottto_service-89abcdef')] + flaky_one,
            'doc-test': ['   Doc-tests ottto_core\n', self.summary(1, 1),
                         'error: doctest failed, to rerun pass `-p ottto-core --doc`\n'],
            'no names': ['error: could not compile\n'],
            # Cargo could not start the binary: Running line, no summary.
            'never executed': [self.LIB, 'error: test failed, to rerun pass `-p ottto-service --lib`\n',
                               'Caused by:\n', '  could not execute process `/w/x` (never executed)\n'] + flaky_one,
            'exit line missed': lib_fail + [self.summary(0, 1), 'error: test failed, to rerun pass `--lib`\n',
                                            'error: test failed, to rerun pass `--test cli`\n'] + flaky_one,
            'target total off': lib_fail + [self.summary(0, 1), self.exited('ottto_service-89abcdef'),
                                            'error: 2 targets failed:\n'],
        }
        for label, lines in cases.items():
            with self.subTest(label):
                plan, reason = self.plan(lines)
                self.assertEqual(plan, [])
                self.assertTrue(reason)
        plan, reason = self.plan(lib_fail + [self.summary(0, 1), self.exited('ottto_service-89abcdef')],
                                 scope_of=lambda _b: None)
        self.assertIn('unknown test binary', reason)
        # A failed group with nothing to retry blocks the other group's retry.
        retried = [self.CLI, 'test case ... FAILED\n', self.summary(0, 1), self.exited('cli-0123abcd')]
        plan, reason = runner.retry_plan([(['error: build failed\n'], lambda b: [b], 101),
                                          (retried, lambda b: [b], 101)], set(), 3)
        self.assertEqual(plan, [])
        self.assertIn('without a failed test name', reason)
        # A group that passed is not read at all.
        plan, reason = runner.retry_plan([(['test x ... FAILED\n'], lambda b: [b], 0),
                                          (retried, lambda b: [b], 101)], set(), 3)
        self.assertEqual((plan, reason), ([('case', ['cli-0123abcd'])], None))

    def test_limit_money_and_receipts_are_never_retried(self):
        four = [self.LIB, *[f'test a::t{i} ... FAILED\n' for i in range(4)], self.summary(0, 4),
                self.exited('ottto_service-89abcdef')]
        self.assertIn('over the retry limit', self.plan(four)[1])
        self.assertEqual(len(self.plan(four, limit=4)[0]), 4)
        for name in ('snapshot_sync::claude_money_e2_pipeline_tests::x', 'snapshots::state_v2_money_tests::y',
                     'a::money_equivalence_tests::m::z', 'layout::receipt'):
            with self.subTest(name):
                lines = [self.LIB, f'test {name} ... FAILED\n', self.summary(0, 1), self.exited('ottto_service-89abcdef')]
                plan, reason = self.plan(lines, required=['layout::receipt'])
                self.assertEqual(plan, [])
                self.assertIn('never retried', reason)

    def test_binaries_from_cargo_json(self):
        def artifact(kind, name, exe, test=True):
            return runner.json.dumps({'reason': 'compiler-artifact', 'manifest_path': '/w/c/Cargo.toml',
                                      'target': {'kind': kind, 'name': name}, 'profile': {'test': test},
                                      'executable': exe})
        output = '\n'.join([
            artifact(['lib'], 'c', '/w/target/debug/deps/c-1'),
            artifact(['test'], 'cli', '/w/target/debug/deps/cli-2'),
            artifact(['bin'], 'tool', '/w/target/debug/deps/tool-3'),
            artifact(['bin'], 'tool', '/w/target/debug/tool', test=False),
            '{"reason": "build-finished", "success": true}',
            'not json',
        ])
        self.assertEqual(runner.test_binaries(output), {
            'c-1': ['--workspace', '--lib'],
            'cli-2': ['--workspace', '--test', 'cli'],
            'tool-3': ['--workspace', '--bin', 'tool'],
        })

    def test_modules_that_use_the_money_oracle_are_never_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a').mkdir()
            (root / 'a' / 'route_tests.rs').write_text('use x::money_oracle::assert_equivalent;\n')
            (root / 'a' / 'mod.rs').write_text('money_oracle::assert_held();\n')
            (root / 'a' / 'plain_tests.rs').write_text('fn t() {}\n')
            modules = runner.oracle_modules(root)
        self.assertEqual(modules, {'route_tests', 'a'})
        self.assertTrue(runner.never_retry('s::route_tests::x', set(), modules))
        self.assertFalse(runner.never_retry('s::plain_tests::x', set(), modules))
        source = SCRIPT.parent.parent / 'crates'
        self.assertIn('copy_prefix_route_tests', runner.oracle_modules(source))

    def test_retry_passes_kills_on_timeout_and_reports(self):
        lock = threading.Lock()

        def fake_cargo(tmp, body):
            # Stands in for cargo; ignores the `test <scope> -- ...` arguments.
            path = Path(tmp) / 'cargo'
            path.write_text(f'#!{sys.executable}\n{body}\n', encoding='utf-8')
            path.chmod(0o755)
            return str(path)

        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO())):
            passed = runner.retry_alone(fake_cargo(tmp, 'print("test a::b ... ok")'), 'a::b', ['--lib'], 30, lock)
            failed = runner.retry_alone(fake_cargo(tmp, 'print("test a::b ... FAILED"); raise SystemExit(101)'),
                                        'a::b', ['--lib'], 30, lock)
            started = time.monotonic()
            hung = runner.retry_alone(fake_cargo(tmp, 'import time; time.sleep(60)'), 'a::b', ['--lib'], 1, lock)
        self.assertTrue(passed)
        self.assertFalse(failed)
        self.assertFalse(hung)
        self.assertLess(time.monotonic() - started, 20)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'flaky.json'
            out = io.StringIO()
            # Keep the real CI step summary clean.
            with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}):
                runner.record_flaky([('a::b', 1)], str(path), (2, 3))
            record = runner.json.loads(path.read_text())
        self.assertEqual(record['shard'], '2/3')
        self.assertEqual(record['flaky'], [{'test': 'a::b', 'retry': 1}])
        self.assertEqual(runner.libtest_log.flaky(out.getvalue().splitlines()), {'a::b'})


class WatchdogTests(unittest.TestCase):
    """Real child processes; each test finishes in a few seconds."""

    def run_groups(self, scripts, idle_limit):
        lock = threading.Lock()
        last = [time.monotonic()]
        started = time.monotonic()
        # The relay writes bytes to sys.stdout.buffer, so swap in a text wrapper.
        with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO())):
            runs = [(f'g{i}', runner.start(f'g{i}', [sys.executable, '-c', code], lock, last))
                    for i, code in enumerate(scripts)]
            problems = runner.wait_groups(runs, last, idle_limit, poll=0.1)
        return problems, time.monotonic() - started, runs

    def test_only_a_failing_group_is_reported(self):
        problems, _, _ = self.run_groups(['print("a")', 'import sys; sys.exit(3)'], idle_limit=30)
        self.assertEqual(problems, ['g1: cargo test exited 3'])

    def test_a_silent_hung_group_is_killed_with_its_children(self):
        # The hung group also starts a grandchild that holds the output pipe.
        hang = ('import subprocess, sys, time; print("started", flush=True); '
                'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]); time.sleep(60)')
        problems, took, runs = self.run_groups(['print("done")', hang], idle_limit=1.5)
        self.assertLess(took, 20)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith('g1: killed after'), problems)
        self.assertEqual(runs[1][1][0].returncode, -signal.SIGKILL)

    def test_output_keeps_a_slow_group_alive(self):
        slow = 'import time\nfor _ in range(6):\n    print("tick", flush=True); time.sleep(0.5)'
        problems, _, _ = self.run_groups([slow], idle_limit=1.5)
        self.assertEqual(problems, [])


if __name__ == '__main__':
    unittest.main()
