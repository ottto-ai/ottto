#!/usr/bin/env python3
"""Synthetic release evidence regressions; no release or native tools run."""
import ast
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from release_evidence_placeholders import contains_placeholder, strip_optional_not_run

SCRIPTS = Path(__file__).resolve().parent
GATES = ("macos_public_rc_gate.sh", "macos_stable_preflight.sh")


def placeholder_guard(script):
    source = (SCRIPTS / script).read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(source)
    guards = [node.test for node in tree.body if isinstance(node, ast.If)
              and isinstance(node.test, ast.Call)
              and isinstance(node.test.func, ast.Name)
              and node.test.func.id == "contains_placeholder"]
    if len(guards) != 1:
        raise AssertionError(f"{script} must have one placeholder guard")
    return tree, guards[0]


class ReleaseEvidencePlaceholdersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({
                "product": "ottto-local-platform", "channel": "stable-candidate",
                "version": "0.1.252-rc1", "commit": "a" * 40,
                "min_protocol_version": 15,
                "supply_chain": {"materials": [{"kind": "private_source", "commit": "b" * 40}]},
            }))
            result = subprocess.run([
                "bash", str(SCRIPTS / "macos_public_rc_evidence_template.sh"),
                "--candidate-manifest", str(manifest), "--output", "-",
                "--checked-at", "2026-01-01T00:00:00Z", "--macos-version", "14.7",
                "--arch", "arm64",
            ], check=True, capture_output=True, text=True)
        cls.evidence = json.loads(result.stdout)
        cls.evidence["status"] = "passed"
        cls.evidence["checks"].update({
            key: "passed" for key in cls.evidence["checks"] if key != "resource_soak"
        })
        cls.evidence["update_lifecycle"].update({
            "launch_provenance": "launchservices_bundle", "user_update_actions": 1,
            "starting_service_owner": "app_bundle",
            "service_restarted_on_target_version": True,
            "sparkle_terminated_old_process": True, "sparkle_relaunched_target_bundle": True,
            "process_id_changed": True, "final_service_owner": "app_bundle",
            "manual_process_termination": False,
            "manual_app_launch": False, "account_continuity_verified": True,
            "source_continuity_verified": True, "diagnostics_via_app_service_socket": True,
            "verify_via_app_service_socket": True,
            "owner_prefix_protocol_schema_version_converged": True,
        })
        cls.evidence["operator_notes"] = ["redacted stable-candidate RC evidence"]

    def assert_gates_reject(self, evidence, expected):
        for script in GATES:
            with self.subTest(script=script):
                _, guard = placeholder_guard(script)
                actual = eval(compile(ast.Expression(guard), script, "eval"), {
                    "contains_placeholder": contains_placeholder,
                    "strip_optional_not_run": strip_optional_not_run,
                    "evidence": evidence,
                })
                self.assertEqual(actual, expected)

    def test_filled_template_with_optional_defaults_passes_both_guards(self):
        self.assertTrue(contains_placeholder(self.evidence))
        self.assert_gates_reject(self.evidence, False)

    def test_optional_fields_can_be_absent_or_completed(self):
        for resource in (None, {"status": "passed"}):
            evidence = copy.deepcopy(self.evidence)
            if resource is None:
                evidence.pop("resource_scorecard")
                evidence["checks"].pop("resource_soak")
            else:
                evidence["resource_scorecard"] = resource
                evidence["checks"]["resource_soak"] = "passed"
            self.assert_gates_reject(evidence, False)

    def test_placeholders_outside_exact_exceptions_fail_both_guards(self):
        for value in ("not_run", "TODO", "TODO_fill_result"):
            for field in ("status", "operator_notes", "resource_scorecard", "checks"):
                with self.subTest(field=field, value=value):
                    evidence = copy.deepcopy(self.evidence)
                    evidence[field] = {
                        "status": value, "operator_notes": [{"nested": [value]}],
                        "resource_scorecard": {**evidence["resource_scorecard"], "status": value,
                                               "extra": "present"},
                        "checks": {**evidence["checks"], "other": value},
                    }[field]
                    self.assert_gates_reject(evidence, True)
        for field, value in (("policy", "other"), ("schema_version", 2), ("status", "TODO")):
            evidence = copy.deepcopy(self.evidence)
            evidence["resource_scorecard"][field] = value
            self.assert_gates_reject(evidence, True)
        evidence = copy.deepcopy(self.evidence)
        evidence["checks"]["resource_soak"] = "TODO"
        self.assert_gates_reject(evidence, True)

    def test_stripping_does_not_mutate_original_evidence(self):
        before = copy.deepcopy(self.evidence)
        stripped = strip_optional_not_run(self.evidence)
        self.assertNotIn("resource_scorecard", stripped)
        self.assertNotIn("resource_soak", stripped["checks"])
        self.assertEqual(self.evidence, before)

    def test_both_scripts_import_and_call_shared_policy(self):
        for script in GATES:
            with self.subTest(script=script):
                source = (SCRIPTS / script).read_text()
                tree, guard = placeholder_guard(script)
                self.assertIn('"$ROOT/scripts" <<\'PY\'', source)
                self.assertIn("sys.path.insert(0, sys.argv[-1])", source)
                imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                           and node.module == "release_evidence_placeholders"]
                self.assertEqual(len(imports), 1)
                self.assertEqual([name.name for name in imports[0].names],
                                 ["contains_placeholder", "strip_optional_not_run"])
                self.assertEqual(ast.unparse(guard),
                                 "contains_placeholder(strip_optional_not_run(evidence))")
                self.assertFalse(any(isinstance(node, ast.FunctionDef)
                                     and node.name in {"contains_placeholder", "strip_optional_not_run"}
                                     for node in tree.body))


if __name__ == "__main__":
    unittest.main()
