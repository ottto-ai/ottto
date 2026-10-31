#!/usr/bin/env python3
"""Synthetic regressions for ci_runtime_tests.py; never runs cargo."""
import contextlib
import importlib.util
import io
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest

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
        self.assertEqual(runner.serial_group(lib, {'one'}, lib + others), ['a::tests::one', 'b::tests::one'])
        with self.assertRaises(runner.SetupError):
            runner.serial_group(lib, {'one'}, lib + others + ['a::tests::one'])
        with self.assertRaises(runner.SetupError):
            runner.serial_group(lib, {'missing'}, lib)

    def test_listed_tests_reads_terse_output(self):
        output = 'a::one: test\nb::bench: benchmark\n\nc::two: test\n'
        self.assertEqual(runner.listed_tests(output), ['a::one', 'c::two'])


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
        self.assertEqual(runner.lib_summary(self.STREAM, whole_stream=False), (3, 1, 1, 0, 2))
        self.assertEqual(runner.lib_summary(self.STREAM[3:7], whole_stream=True), (3, 1, 1, 0, 2))
        self.assertIsNone(runner.lib_summary(self.STREAM[:2], whole_stream=False))

    def test_counts_must_partition_the_lib(self):
        self.assertEqual(runner.check_counts('g', (3, 1, 1, 0, 2), 5, 2), [])
        self.assertTrue(runner.check_counts('g', (3, 1, 1, 0, 2), 5, 3))
        self.assertTrue(runner.check_counts('g', (3, 1, 0, 0, 2), 5, 2))
        self.assertTrue(runner.check_counts('g', None, 5, 2))



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

    def test_clean_exits_have_no_problems(self):
        problems, _, _ = self.run_groups(['print("a")', 'print("b")'], idle_limit=30)
        self.assertEqual(problems, [])

    def test_a_failing_group_is_reported(self):
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
