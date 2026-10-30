"""Offline policy regressions; run on the Linux CI lane, never require a Mac."""

import copy
import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import mac_contract_reuse as policy


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 10, 30, 12, tzinfo=dt.timezone.utc)
        self.sha, self.pr_sha, self.tree = "a" * 40, "b" * 40, "c" * 40
        self.repo = "example/runtime"
        self.current = {"head_sha": self.sha, "event": "merge_group",
                        "path": ".github/workflows/ci.yml", "workflow_id": 42,
                        "head_commit": {"tree_id": self.tree}}
        self.run = {"id": 10, "event": "workflow_dispatch", "workflow_id": 42,
                    "path": ".github/workflows/ci.yml", "head_sha": self.pr_sha,
                    "head_repository": {"full_name": self.repo}, "run_attempt": 2,
                    "status": "completed", "conclusion": "success",
                    "created_at": "2026-10-30T10:00:00Z",
                    "head_commit": {"tree_id": self.tree}}
        self.job = {"id": 99, "run_id": 10, "run_attempt": 2,
                    "name": "Rust contracts", "head_sha": self.pr_sha,
                    "status": "completed", "conclusion": "success",
                    "labels": ["macos-15"], "runner_group_name": "GitHub Actions",
                    "completed_at": "2026-10-30T11:00:00Z",
                    "steps": [{"name": name, "status": "completed",
                               "conclusion": "success"} for name in policy.MAC_STEPS]}
        self.calls = []

    def api(self, path):
        self.calls.append(path)
        if path == "actions/runs/20":
            return self.current
        if path.startswith("actions/workflows/42/runs?"):
            event = "workflow_dispatch" if "workflow_dispatch" in path else "merge_group"
            return {"workflow_runs": [self.run] if self.run["event"] == event else []}
        if path == f"git/commits/{self.pr_sha}":
            return {"sha": self.pr_sha, "tree": {"sha": self.tree}}
        if path == "actions/runs/10/attempts/2/jobs?per_page=100":
            return {"jobs": [self.job]}
        raise AssertionError(path)

    def lookup(self, api=None):
        return policy.find_receipt(api or self.api, self.repo, 20, self.sha,
                                   self.tree, self.now)

    def test_same_tree_different_commits_qualifies(self):
        receipt = self.lookup()
        self.assertEqual(receipt["run_id"], "10")
        self.assertEqual(receipt["tree"], self.tree)
        self.assertIn(f"git/commits/{self.pr_sha}", self.calls)

    def test_genuine_queue_mac_also_qualifies(self):
        self.run["event"] = "merge_group"
        self.assertIsNotNone(self.lookup())

    def test_other_tree_never_qualifies(self):
        self.run["head_commit"]["tree_id"] = "d" * 40
        self.assertIsNone(self.lookup())
        self.assertFalse(any(path.startswith("git/") for path in self.calls))

    def test_index_is_not_authoritative_tree_proof(self):
        def api(path):
            if path.startswith("git/commits/"):
                return {"sha": self.pr_sha, "tree": {"sha": "d" * 40}}
            return self.api(path)
        self.assertIsNone(self.lookup(api))

    def test_candidate_provenance_and_age(self):
        original = copy.deepcopy(self.run)
        changes = (("event", "pull_request"), ("workflow_id", 43),
                   ("path", ".github/workflows/other.yml"),
                   ("head_repository", {"full_name": "untrusted/fork"}),
                   ("status", "in_progress"), ("conclusion", "failure"),
                   ("created_at", "2026-10-29T09:59:59Z"),
                   ("created_at", "2026-10-31T10:00:00Z"), ("id", 20))
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.run = copy.deepcopy(original)
                self.run[key] = value
                self.assertIsNone(self.lookup())

    def test_current_commit_tree_and_event_are_bound(self):
        original = copy.deepcopy(self.current)
        for key, value in (("head_sha", self.pr_sha), ("event", "pull_request"),
                           ("head_commit", {"tree_id": "d" * 40})):
            with self.subTest(key=key):
                self.current = copy.deepcopy(original)
                self.current[key] = value
                self.assertIsNone(self.lookup())

    def test_never_reuse_linux_or_skipped_job_or_wrong_attempt(self):
        original = copy.deepcopy(self.job)
        changes = (("labels", ["ubuntu-24.04"]), ("labels", ["self-hosted", "macos-15"]),
                   ("runner_group_name", "private"), ("head_sha", self.sha),
                   ("status", "queued"), ("conclusion", "skipped"),
                   ("run_id", 9), ("run_attempt", 1),
                   ("completed_at", "2026-10-29T11:59:59Z"),
                   ("completed_at", "2026-10-31T11:00:00Z"))
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.job = copy.deepcopy(original)
                self.job[key] = value
                self.assertIsNone(self.lookup())

    def test_every_mac_step_must_have_really_passed(self):
        for index, name in enumerate(policy.MAC_STEPS):
            with self.subTest(step=name):
                self.job["steps"][index]["conclusion"] = "skipped"
                self.assertIsNone(self.lookup())
                self.job["steps"][index]["conclusion"] = "success"
        self.job["steps"].pop()
        self.assertIsNone(self.lookup())

    def test_api_failure_outputs_false(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = {"GITHUB_REPOSITORY": self.repo, "GITHUB_SHA": self.sha,
                   "GITHUB_RUN_ID": "20", "GITHUB_OUTPUT": str(output),
                   "GH_TOKEN": "not-a-real-token"}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(policy.subprocess, "check_output", return_value=self.tree), \
                 mock.patch.object(policy.urllib.request, "urlopen", side_effect=OSError("offline")):
                policy.main()
            self.assertEqual(output.read_text(), "reuse=false\n")

    def test_all_mac_commands_are_guarded_in_workflow(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        rust = workflow.split("\n  rust:\n", 1)[1].split("\n  public-surface:", 1)[0]
        self.assertIn("name: Rust contracts", rust)
        self.assertIn("!cancelled()", rust)
        self.assertIn("needs.mac-reuse.result == 'success'", rust)
        for block in rust.split("      - name: ")[1:]:
            name = block.splitlines()[0]
            if name in policy.MAC_STEPS and name != "Checkout":
                with self.subTest(step=name):
                    self.assertIn("if: env.REUSE_MAC_CONTRACTS != 'true'", block)


if __name__ == "__main__":
    unittest.main()
