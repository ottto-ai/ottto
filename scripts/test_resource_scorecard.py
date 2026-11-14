#!/usr/bin/env python3
"""Synthetic positive/negative resource evidence. Run in CI only."""
import copy
import json
import sys
import unittest
from pathlib import Path

from resource_scorecard import ABSOLUTE, METRICS, canonical_sha, validate


def fixture(manifest_sha="a" * 64):
    metrics = {name: 1 for name in METRICS}
    metrics.update(cpu_seconds_per_hour=36, energy_mw=40, writes_gib_per_hour=0.1,
                   footprint_p50_mib=100, footprint_peak_mib=300,
                   seconds_above_500mib_per_hour=0, sidecar_reuse_ratio=1)
    candidate = dict(sampler_version=6, manifest_sha256=manifest_sha,
                     executable_sha256="c" * 64, host_class="sample-host", os_version="14.7",
                     arch="arm64", power_profile="battery", workload_class="quiet",
                     started_at="2026-11-01T00:15:00Z", ended_at="2026-11-01T02:15:00Z",
                     duration_seconds=7200, battery_seconds=7200, expected_samples=7200,
                     observed_samples=7200, max_gap_seconds=1, startup_seconds=900,
                     process_instances=1, restart_count=0, candidate_identity_verified=True,
                     peak_kind="interval_max", threshold_kind="instantaneous",
                     own_cpu_seconds=60, child_cpu_seconds=12, metrics=metrics,
                     input_counts={s: dict(files=100, appends=0, passes=8)
                                   for s in ("claude", "codex", "pi")})
    previous = copy.deepcopy(candidate)
    previous["manifest_sha256"] = "b" * 64
    previous["executable_sha256"] = "d" * 64
    return dict(schema_version=1, policy="resource-stage1-v1", candidate=candidate,
                previous_stable=previous, previous_stable_sha256=canonical_sha(previous))


class ResourceScorecardTests(unittest.TestCase):
    def check(self, card):
        return validate(card, "a" * 64, "c" * 64)

    def test_positive_and_recomputed_status(self):
        card = fixture()
        card["status"] = "failed"
        self.assertEqual(self.check(card)["status"], "passed")
        card["status"] = "passed"
        card["candidate"]["metrics"]["energy_mw"] = 101
        with self.assertRaises(ValueError):
            self.check(card)

    def test_every_missing_observation_fails(self):
        for key in fixture()["candidate"]:
            with self.subTest(key=key):
                card = fixture()
                del card["candidate"][key]
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    self.check(card)
        for metric in METRICS:
            card = fixture()
            del card["candidate"]["metrics"][metric]
            with self.assertRaises(ValueError):
                self.check(card)

    def test_every_absolute_bound_and_exact_boundary(self):
        for metric, bound in ABSOLUTE.items():
            for delta in (0, 0.001):
                with self.subTest(metric=metric, delta=delta):
                    card = fixture()
                    for label in ("candidate", "previous_stable"):
                        card[label]["metrics"][metric] = bound + delta
                        if metric == "cpu_seconds_per_hour":
                            card[label]["own_cpu_seconds"] = (bound + delta) * 2 - 12
                    card["previous_stable_sha256"] = canonical_sha(card["previous_stable"])
                    if delta:
                        with self.assertRaises(ValueError):
                            self.check(card)
                    else:
                        self.check(card)

    def test_all_relative_regressions(self):
        for metric in METRICS:
            with self.subTest(metric=metric):
                card = fixture()
                if card["previous_stable"]["metrics"][metric] == 0:
                    card["previous_stable"]["metrics"][metric] = 1
                    card["previous_stable_sha256"] = canonical_sha(card["previous_stable"])
                card["candidate"]["metrics"][metric] = (
                    0.8 if metric == "sidecar_reuse_ratio"
                    else card["previous_stable"]["metrics"][metric] * 1.21 + 0.001)
                if metric == "cpu_seconds_per_hour":
                    card["candidate"]["own_cpu_seconds"] = card["candidate"]["metrics"][metric] * 2 - 12
                with self.assertRaises(ValueError):
                    self.check(card)

    def test_incomplete_and_mismatched_windows(self):
        changes = {"observed_samples": 7127, "max_gap_seconds": 2.01,
                   "battery_seconds": 7199, "duration_seconds": 7199,
                   "startup_seconds": 899, "restart_count": 1, "process_instances": 2,
                   "candidate_identity_verified": False, "peak_kind": "sampled",
                   "threshold_kind": "interval_max", "child_cpu_seconds": None,
                   "power_profile": "ac", "host_class": "other", "os_version": "15.1",
                   "manifest_sha256": "f" * 64, "executable_sha256": "e" * 64}
        for key, value in changes.items():
            card = fixture()
            card["candidate"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(card)
        card = fixture()
        card["candidate"]["input_counts"]["codex"]["appends"] = 1
        with self.assertRaises(ValueError):
            self.check(card)
        card = fixture()
        card["previous_stable"]["metrics"]["energy_mw"] = 1000
        with self.assertRaises(ValueError):
            self.check(card)

    def test_zero_baseline_and_read_alarm(self):
        card = fixture()
        for label in ("candidate", "previous_stable"):
            card[label]["metrics"]["reads_gib_per_hour"] = 4
        card["previous_stable_sha256"] = canonical_sha(card["previous_stable"])
        self.assertTrue(self.check(card)["reads_alarm"])
        card = fixture()
        card["previous_stable"]["metrics"]["log_bytes_per_hour"] = 0
        card["previous_stable_sha256"] = canonical_sha(card["previous_stable"])
        with self.assertRaises(ValueError):
            self.check(card)
        card = fixture()
        card["previous_stable"]["metrics"]["writes_gib_per_hour"] = 0
        card["previous_stable_sha256"] = canonical_sha(card["previous_stable"])
        self.check(card)

    def test_nonfinite_and_bool_not_observations(self):
        for value in (float("nan"), float("inf"), -1, None, True):
            card = fixture()
            card["candidate"]["metrics"]["children_per_hour"] = value
            with self.assertRaises(ValueError):
                self.check(card)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        path = Path(sys.argv[2])
        evidence = json.loads(path.read_text())
        evidence["resource_scorecard"] = fixture(evidence["candidate_manifest"]["sha256"])
        evidence["local_platform"]["executable_sha256"] = "c" * 64
        path.write_text(json.dumps(evidence))
    else:
        unittest.main()
