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

    def test_reads_json_from_the_artifact_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('flaky-tests.json', json.dumps(record('3', 'rust', '1/1', 'b::z')))
            archive.writestr('notes.txt', 'ignored')
        self.assertEqual(flaky.records_of(buffer.getvalue()), [record('3', 'rust', '1/1', 'b::z')])


if __name__ == '__main__':
    unittest.main()
