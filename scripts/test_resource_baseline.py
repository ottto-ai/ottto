#!/usr/bin/env python3
import json
import unittest
from resource_baseline import extract, companions


class ReceiptTests(unittest.TestCase):
    def receipt(self, value):
        return 'CI prefix resource_baseline_counts ' + json.dumps(value)

    def test_observed_zero_and_positive(self):
        counts = {"quiet_ac/codex/h0": {"native_bytes": 0, "encoded_bytes": 20}}
        self.assertEqual(extract(self.receipt(counts)), counts)

    def test_missing_duplicate_and_malformed_observations(self):
        for log in ('', self.receipt({}), self.receipt({"quiet_ac/codex/h0": {}}),
                    self.receipt({"private/path": {"count": 1}})):
            with self.subTest(log=log), self.assertRaises(ValueError):
                extract(log)
        line = self.receipt({"quiet_ac/codex/h0": {"native_bytes": 0}})
        with self.assertRaises(ValueError):
            extract(line + '\n' + line)
        for value in (None, True, -1, 1.5, "0", 2**64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract(self.receipt({"quiet_ac/codex/h0": {"native_bytes": value}}))

    def test_native_companions_required(self):
        log = "resource_cli_children reuse=true login_starts=16 model_starts=16\nresource_log_replay folded=1000 per_event=3000000\nresource_rewalk_replay ordinary=8 replay=13"
        self.assertEqual(companions(log), {"cli_login_starts": 16, "cli_model_starts": 16,
                                         "offpass_folded_log_bytes": 1000, "ordinary_passes_h0": 8})
        for missing in ('', log.split('\n', 1)[1], log + '\n' + log):
            with self.assertRaises(ValueError):
                companions(missing)


if __name__ == '__main__':
    unittest.main()
