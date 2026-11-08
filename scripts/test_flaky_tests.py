#!/usr/bin/env python3
"""Synthetic regressions for flaky_tests.py; never calls gh."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

SCRIPT = Path(__file__).with_name('flaky_tests.py').resolve()
spec = importlib.util.spec_from_file_location('flaky_tests', SCRIPT)
flaky = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flaky)


def record(run, job, shard, *tests, attempt='1'):
    return {'run_id': run, 'run_attempt': attempt, 'job': job, 'shard': shard,
            'flaky': [{'test': t, 'retry': 1} for t in tests]}


class TallyTests(unittest.TestCase):
    def test_counts_distinct_job_runs(self):
        records = [
            record('1', 'rust', '1/1', 'a::x', 'a::y'),
            record('1', 'rust', '1/1', 'a::x'),  # same job run reported twice
            record('1', 'rust', '1/1', 'a::x', attempt='2'),
            record('2', 'rust-linux-shard', '2/3', 'a::x'),
        ]
        self.assertEqual(flaky.tally(records), {'a::x': 3, 'a::y': 1})

    def test_renamed_test_keeps_its_history(self):
        mapped = flaky.renames('target\told_test\tnew_test\n'
                               'crates/a/src/lib.rs\ta::x\ta::b::x\n'
                               'crates/a/src/lib.rs\ta::b::x\ta::c::x\n')
        self.assertEqual(mapped, {'a::x': 'a::c::x', 'a::b::x': 'a::c::x'})
        records = [
            record('1', 'rust', '1/1', 'a::x'),
            record('2', 'rust', '1/1', 'a::b::x'),
            record('3', 'rust', '1/1', 'a::c::x', 'a::y'),
        ]
        self.assertEqual(flaky.tally(records, mapped), {'a::c::x': 3, 'a::y': 1})

    def test_old_id_mapped_to_two_new_ids_stays(self):
        mapped = flaky.renames('target\told_test\tnew_test\n'
                               'crates/a/src/lib.rs\ttests::x\ta::tests::x\n'
                               'crates/b/src/lib.rs\ttests::x\tb::tests::x\n'
                               'crates/c/src/lib.rs\ttests::y\tc::tests::y\n'
                               'crates/d/src/lib.rs\ttests::y\tc::tests::y\n')
        self.assertEqual(mapped, {'tests::y': 'c::tests::y'})

    def test_reads_json_from_the_artifact_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('flaky-tests.json', json.dumps(record('3', 'rust', '1/1', 'b::z')))
            archive.writestr('notes.txt', 'ignored')
        self.assertEqual(flaky.records_of(buffer.getvalue()), [record('3', 'rust', '1/1', 'b::z')])


if __name__ == '__main__':
    unittest.main()
