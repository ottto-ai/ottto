#!/usr/bin/env python3
"""Portable synthetic receipt checks. Never builds or executes native binaries."""
import contextlib
import copy
import hashlib
import io
import json
import unittest
from pathlib import Path
import tempfile
from unittest import mock

import money_equivalence
from money_equivalence import (NATIVE_FIXTURES, canonical_declarations, decode_receipt,
                               has_forbidden_diff, native_coverage, parse_declarations,
                               pr_declarations, receipt_diff, receipt_names,
                               require_base_harness, require_base_scan_fixture,
                               require_disjoint_head_only, signed_mismatch, signed_money_lists,
                               uncompared_receipts, value_sha256, verified_summary)


CONTRACT = "usage_decrease_hold_ack_contract"
CONTRACT_VALUE = "usage_decrease_hold_ack:v1"


def envelope():
    return {
        "source": "claude_code",
        "machine_id": "synthetic-machine",
        "snapshots": [{
            "source_file_fingerprint": "physical-identity:excluded",
            "snapshot_fingerprint": "synthetic-snapshot",
            "usage": {"input_tokens": 100, "output_tokens": 2},
            "cost_usd": "0.0123",
            "bucket": "synthetic-bucket",
            "account_id": "synthetic-account",
            "request_id": "synthetic-request",
            "refusal": None,
            "semantic_envelope": {"revision_hash": "synthetic-revision"},
        }],
    }


def encode(value, **kwargs):
    return list(json.dumps(value, **kwargs).encode())


def receipt(*bodies, claude=True, **kwargs):
    # Rust saves a Vec<Vec<u8>> of ReceiptBody::cross_build results. Claude's
    # result has another Vec<Vec<u8>> layer; Codex's is one encoded envelope.
    return json.dumps([
        encode([encode(batch, **kwargs) for batch in body], **kwargs)
        if claude else encode(body, **kwargs)
        for body in bodies
    ]).encode()


class MoneyEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.base = envelope()
        self.head = copy.deepcopy(self.base)

    def compare(self):
        return receipt_diff(receipt([self.base]), receipt([self.head]))

    def assert_change_fails(self, kind, path):
        diff = self.compare()
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff[kind], [path])

    def test_cut_c440307e6_vs_bf4d653b2_envelope_addition_passes(self):
        # Reproduce Lead B's decoded cut shape: eight Claude cases gain only
        # the batch capability (failed_then_healthy has two bodies), two Codex
        # cases are unchanged. No production/provider inputs are needed.
        self.head[CONTRACT] = CONTRACT_VALUE
        cases = {
            "duplicate_request_ids": 1, "failed_then_healthy_telemetry": 2,
            "progressive_response": 1, "quiet_sidecar_growth": 1,
            "resolver_conflict": 1, "side_owner": 1,
            "side_owner_directory_unlisted": 1, "side_without_owner": 1,
        }
        for case, count in cases.items():
            with self.subTest(case=case):
                diff = receipt_diff(receipt(*([self.base] for _ in range(count))),
                                    receipt(*([self.head] for _ in range(count))))
                self.assertFalse(has_forbidden_diff(diff))
                self.assertEqual(diff["allowed_additions"], [
                    f"/{i}/0/{CONTRACT}" for i in range(count)])
        for case in ("codex_legacy_acked_sticky", "codex_v2_sticky"):
            with self.subTest(case=case):
                codex = envelope()
                codex["source"] = "codex"
                self.assertFalse(has_forbidden_diff(receipt_diff(
                    receipt(codex, claude=False), receipt(codex, claude=False))))

    def test_multiple_batch_envelope_additions_pass(self):
        self.head[CONTRACT] = CONTRACT_VALUE
        diff = receipt_diff(receipt([self.base, self.base]), receipt([self.head, self.head]))
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], [f"/0/{j}/{CONTRACT}" for j in range(2)])

    def test_existing_allowlisted_key_unchanged_passes(self):
        self.base[CONTRACT] = self.head[CONTRACT] = CONTRACT_VALUE
        self.assertFalse(has_forbidden_diff(self.compare()))

    def test_allowlisted_addition_exact_string_passes(self):
        self.head[CONTRACT] = CONTRACT_VALUE
        diff = self.compare()
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], ["/0/0/" + CONTRACT])

    def test_allowlisted_addition_other_string_fails(self):
        self.head[CONTRACT] = "usage_decrease_hold_ack:v2"
        self.assert_change_fails("added", "/0/0/" + CONTRACT)
        self.assertEqual(self.compare()["allowed_additions"], [])

    def test_allowlisted_addition_object_fails(self):
        self.head[CONTRACT] = {"contract": CONTRACT_VALUE}
        self.assert_change_fails("added", "/0/0/" + CONTRACT)
        self.assertEqual(self.compare()["allowed_additions"], [])

    def test_allowlisted_addition_other_types_fail(self):
        for value in (None, False, 1, [CONTRACT_VALUE]):
            with self.subTest(value=value):
                self.head[CONTRACT] = value
                self.assert_change_fails("added", "/0/0/" + CONTRACT)

    def test_token_change_fails_even_with_allowed_addition(self):
        self.head[CONTRACT] = CONTRACT_VALUE
        self.head["snapshots"][0]["usage"]["input_tokens"] += 1
        self.assert_change_fails("changed", "/0/0/snapshots/0/usage/input_tokens")

    def test_cost_change_fails(self):
        self.head["snapshots"][0]["cost_usd"] = "0.0124"
        self.assert_change_fails("changed", "/0/0/snapshots/0/cost_usd")

    def test_allowlisted_key_below_envelope_fails(self):
        for location, path in (
                (self.head["snapshots"][0], "/0/0/snapshots/0/<key#9>"),
                (self.head["snapshots"][0]["usage"], "/0/0/snapshots/0/usage/<key#2>")):
            with self.subTest(path=path):
                location[CONTRACT] = CONTRACT_VALUE
                self.assert_change_fails("added", path)
                del location[CONTRACT]

    def test_allowlisted_key_removed_fails(self):
        self.base[CONTRACT] = CONTRACT_VALUE
        self.assert_change_fails("removed", "/0/0/" + CONTRACT)

    def test_allowlisted_key_changed_fails(self):
        self.base[CONTRACT] = CONTRACT_VALUE
        for value in ("usage_decrease_hold_ack:v2", None, False, {"new": True}):
            with self.subTest(value=value):
                self.head[CONTRACT] = value
                self.assert_change_fails("changed", "/0/0/" + CONTRACT)

    def test_other_envelope_additions_and_removals_fail(self):
        self.head["new_contract"] = True
        self.assert_change_fails("added", "/0/0/<key#1>")
        del self.head["new_contract"]
        del self.head["source"]
        self.assert_change_fails("removed", "/0/0/source")

    def test_money_identity_refusal_request_fields_remain_strict(self):
        for field in ("bucket", "account_id", "request_id", "refusal",
                      "snapshot_fingerprint", "source_file_fingerprint", "semantic_envelope"):
            with self.subTest(field=field):
                self.head = copy.deepcopy(self.base)
                self.head["snapshots"][0][field] = "changed"
                self.assert_change_fails("changed", "/0/0/snapshots/0/" + field)
        self.head = copy.deepcopy(self.base)
        self.head["machine_id"] = "changed"
        self.assert_change_fails("changed", "/0/0/machine_id")

    def test_decoding_ignores_json_format_and_key_order(self):
        diff = receipt_diff(receipt([self.base]), receipt(
            [self.head], indent=2, sort_keys=True))
        self.assertFalse(has_forbidden_diff(diff))

    def test_scalar_types_and_numeric_cost_precision_remain_strict(self):
        self.base["snapshots"][0]["usage"]["input_tokens"] = 1
        for value in (True, 1.0):
            self.head = copy.deepcopy(self.base)
            self.head["snapshots"][0]["usage"]["input_tokens"] = value
            self.assert_change_fails("changed", "/0/0/snapshots/0/usage/input_tokens")
        # JSON numbers that ordinary float parsing would round to equality.
        a = b'{"snapshots":[{"cost_usd":0.100000000000000001}]}'
        b = b'{"snapshots":[{"cost_usd":0.100000000000000002}]}'
        diff = receipt_diff(json.dumps([list(a)]), json.dumps([list(b)]))
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], ["/0/snapshots/0/cost_usd"])

    def test_order_and_added_removed_batches_and_snapshots_fail(self):
        other = copy.deepcopy(self.base)
        other["snapshots"][0]["request_id"] = "other-request"
        for a, b in (([self.base, other], [other, self.base]),
                     ([self.base], [self.base, other]),
                     ([self.base, other], [self.base])):
            with self.subTest(batch_counts=(len(a), len(b))):
                self.assertTrue(has_forbidden_diff(receipt_diff(receipt(a), receipt(b))))
        self.head["snapshots"].append(other["snapshots"][0])
        self.assert_change_fails("added", "/0/0/snapshots/1")
        self.base, self.head = self.head, self.base
        self.assert_change_fails("removed", "/0/0/snapshots/1")

    def test_payload_byte_arrays_are_not_decoded(self):
        self.base["payload"] = encode({CONTRACT: CONTRACT_VALUE})
        self.head = copy.deepcopy(self.base)
        self.head["payload"][0] += 1
        self.assert_change_fails("changed", "/0/0/<key#1>/0")

    def test_unknown_fields_and_values_are_redacted(self):
        self.head["snapshots"][0]["private~/key"] = "DO_NOT_LOG_THIS_VALUE"
        diff = self.compare()
        self.assertEqual(diff["added"], ["/0/0/snapshots/0/<key#3>"])
        self.assertNotIn("private", json.dumps(diff))
        self.assertNotIn("DO_NOT_LOG_THIS_VALUE", json.dumps(diff))

    def test_id_keyed_map_paths_are_redacted_with_stable_ordinals(self):
        raw_key = "id-opaque-hash/path~private"
        self.base["snapshots"][0]["usage_buckets"] = [{
            "model_usage": [{"selector_context": {raw_key: "before", "zz-other": "same"}}],
        }]
        self.head = copy.deepcopy(self.base)
        model_usage = self.head["snapshots"][0]["usage_buckets"][0]["model_usage"][0]
        context = model_usage["selector_context"]
        context[raw_key] = "after"
        diff = self.compare()
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], [
            "/0/0/snapshots/0/usage_buckets/0/model_usage/0/selector_context/<key#0>"])
        context = dict(reversed(list(context.items())))
        model_usage["selector_context"] = context
        self.assertEqual(self.compare(), diff)
        for private in (raw_key, "zz-other", "before", "after"):
            self.assertNotIn(private, json.dumps(diff))

    def test_data_map_schema_looking_keys_are_redacted(self):
        # A schema-looking key in a data map is still data, even when its value
        # is an object containing another schema-looking key.
        self.base["snapshots"][0]["semantic_envelope"]["component_hashes"] = {
            "input_tokens": {"source": "before"}}
        self.head = copy.deepcopy(self.base)
        hashes = self.head["snapshots"][0]["semantic_envelope"]["component_hashes"]
        hashes["input_tokens"]["source"] = "after"
        self.assert_change_fails(
            "changed", "/0/0/snapshots/0/semantic_envelope/component_hashes/<key#0>/<key#0>")

    def test_added_and_removed_data_map_keys_are_redacted(self):
        self.base["snapshots"][0]["semantic_envelope"]["component_hashes"] = {
            "old-id": "PRIVATE_HASH_VALUE"}
        self.head = copy.deepcopy(self.base)
        self.head["snapshots"][0]["semantic_envelope"]["component_hashes"] = {
            "new-id": "PRIVATE_HASH_VALUE"}
        diff = self.compare()
        self.assertTrue(has_forbidden_diff(diff))
        prefix = "/0/0/snapshots/0/semantic_envelope/component_hashes/"
        self.assertEqual(diff["added"], [prefix + "<key#0>"])
        self.assertEqual(diff["removed"], [prefix + "<key#1>"])
        for private in ("old-id", "new-id", "PRIVATE_HASH_VALUE"):
            self.assertNotIn(private, json.dumps(diff))

    def test_wire_money_schema_paths_are_readable_without_values(self):
        # Exact emitted record shapes from snapshots.rs, including both model
        # row locations. Traverse every record/container field, not data maps.
        money = {field: "PRIVATE_BEFORE" for field in (
            "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_5m_tokens",
            "cache_creation_1h_tokens", "reasoning_output_tokens", "unattributed_total_tokens",
            "request_count", "cost_usd", "input_cost_usd", "output_cost_usd",
            "cache_read_cost_usd", "cache_creation_cost_usd",
        )}
        part = dict(money, account_identifier_hash="PRIVATE_BEFORE", evidence_ref=0)
        model = dict(money, **{field: "PRIVATE_BEFORE" for field in (
            "model", "reasoning_effort", "auth_mode", "billing_channel", "billing_provider",
            "gateway_provider", "model_provider", "subscription_product", "account_identifier_hash",
        )}, evidence_ref=0, identity_parts=[part])
        snapshot = {
            "model_usage": [model],
            "usage_buckets": [{"bucket_start": "PRIVATE_BEFORE", "model_usage": [copy.deepcopy(model)],
                               "first_activity_at": "PRIVATE_BEFORE",
                               "last_activity_at": "PRIVATE_BEFORE"}],
            "cost": {field: "PRIVATE_BEFORE" for field in (
                "total_cost_usd", "input_cost_usd", "output_cost_usd", "cache_read_cost_usd",
                "cache_creation_cost_usd", "evidence_source",
            )},
            "session_account_evidence": {field: "PRIVATE_BEFORE" for field in (
                "provider", "account_identifier_hash", "provider_workspace_hash",
                "identity_hash_scheme", "evidence_source", "identity_disposition", "source_created_at",
            )},
            "request_evidence": [{"identity_basis": "PRIVATE_BEFORE",
                                  "provider_workspace_hash": "PRIVATE_BEFORE"}],
            "request_identity_refusals": 0,
        }

        def fields(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield path + (key,)
                    yield from fields(child, path + (key,))
            elif isinstance(value, list):
                for i, child in enumerate(value):
                    yield from fields(child, path + (i,))

        self.base["snapshots"] = [snapshot]
        for path in fields(snapshot):
            with self.subTest(path=path):
                self.head = copy.deepcopy(self.base)
                target = self.head["snapshots"][0]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = "PRIVATE_AFTER"
                expected = "/0/0/snapshots/0/" + "/".join(map(str, path))
                self.assert_change_fails("changed", expected)
                logged = json.dumps(self.compare())
                for private in ("PRIVATE_BEFORE", "PRIVATE_AFTER"):
                    self.assertNotIn(private, logged)

    def test_wire_money_data_maps_keep_schema_looking_keys_private(self):
        for location in (("model_usage", 0),
                         ("usage_buckets", 0, "model_usage", 0)):
            for field in ("selector_context", "selector_sources"):
                with self.subTest(location=location, field=field):
                    self.base = envelope()
                    self.base["snapshots"][0].update(
                        model_usage=[{}], usage_buckets=[{"model_usage": [{}]}])
                    target = self.base["snapshots"][0]
                    for key in location:
                        target = target[key]
                    target[field] = {"billing_provider": {"auth_mode": "PRIVATE_BEFORE"}}
                    self.head = copy.deepcopy(self.base)
                    target = self.head["snapshots"][0]
                    for key in location:
                        target = target[key]
                    target[field]["billing_provider"]["auth_mode"] = "PRIVATE_AFTER"
                    prefix = "/0/0/snapshots/0/" + "/".join(map(str, location))
                    self.assert_change_fails("changed", prefix + "/" + field + "/<key#0>/<key#0>")
                    for private in ("billing_provider", "auth_mode", "PRIVATE_BEFORE", "PRIVATE_AFTER"):
                        self.assertNotIn(private, json.dumps(self.compare()))

        # client_report remains an opaque data map at the batch envelope.
        self.base = envelope()
        self.base["client_report"] = {"cost": {"total_cost_usd": "PRIVATE_BEFORE"}}
        self.head = copy.deepcopy(self.base)
        self.head["client_report"]["cost"]["total_cost_usd"] = "PRIVATE_AFTER"
        self.assert_change_fails("changed", "/0/0/client_report/<key#0>/<key#0>")
        for private in ("cost", "total_cost_usd", "PRIVATE_BEFORE", "PRIVATE_AFTER"):
            self.assertNotIn(private, json.dumps(self.compare()))

    def test_invalid_receipts_fail_closed_without_values(self):
        for invalid in (b'[]', b'{}', b'[[true]]', b'[[256]]', b'[[255]]',
                        b'[[123]]', json.dumps([encode([])]),
                        json.dumps([encode([encode(42)])]),
                        json.dumps([list(b'{"x":1,"x":2}')]),
                        json.dumps([list(b'{"x":NaN}')]),
                        b'DO_NOT_LOG_THIS_VALUE'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError) as error:
                    decode_receipt(invalid)
                self.assertNotIn("DO_NOT_LOG_THIS_VALUE", str(error.exception))


HEAD_CAS = "head_cas_contract"
HEAD_CAS_VALUE = "snapshot_head_etag:v1"
NEW_FIELD = "cache_observations"
DECLARED = {"envelope": {HEAD_CAS: HEAD_CAS_VALUE}, "snapshot": {NEW_FIELD: []}}
FENCE = "`" * 3
DECLARED_INFO = "money-eq-declared-additions"


def pr_body(*blocks):
    return "Summary.\r\n\r\n" + "".join(
        f"{FENCE}money-eq-declared-additions\r\n{block}\r\n{FENCE}\r\n\r\n" for block in blocks)


class DeclaredAdditionTests(unittest.TestCase):
    """Additions the PR body declares: shaped like the observed cross-build diff."""

    def setUp(self):
        self.base = envelope()
        self.head = copy.deepcopy(self.base)

    def compare(self, declarations=DECLARED):
        return receipt_diff(receipt([self.base]), receipt([self.head]), declarations)

    def add_observed(self):
        self.head[HEAD_CAS] = HEAD_CAS_VALUE
        self.head["snapshots"][0][NEW_FIELD] = []

    def test_declared_snapshot_and_envelope_additions_pass(self):
        self.add_observed()
        diff = self.compare()
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], [
            "/0/0/" + HEAD_CAS, "/0/0/snapshots/0/" + NEW_FIELD])

    def test_declared_envelope_contract_alone_passes(self):
        self.head[HEAD_CAS] = HEAD_CAS_VALUE
        diff = self.compare(parse_declarations(pr_body(json.dumps(
            {"envelope": {HEAD_CAS: HEAD_CAS_VALUE}}))))
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], ["/0/0/" + HEAD_CAS])

    def test_declared_empty_object_passes(self):
        self.head["snapshots"][0][NEW_FIELD] = {}
        diff = self.compare({"snapshot": {NEW_FIELD: {}}})
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], ["/0/0/snapshots/0/" + NEW_FIELD])

    def test_undeclared_additions_stay_added(self):
        self.add_observed()
        for declarations in (None, {}, {"snapshot": {"other_field": []}}):
            with self.subTest(declarations=declarations):
                diff = self.compare(declarations)
                self.assertTrue(has_forbidden_diff(diff))
                self.assertEqual(diff["added"], ["/0/0/" + HEAD_CAS, "/0/0/snapshots/0/<key#2>"])
                self.assertEqual(diff["allowed_additions"], [])

    def test_declared_key_with_other_value_or_type_stays_added(self):
        # A declared key carrying content (possibly money) is not the declared empty value.
        for value in ([{}], ["x"], "x", {}, {"input_tokens": 1}, None, 0, False):
            with self.subTest(value=value):
                self.head = copy.deepcopy(self.base)
                self.head["snapshots"][0][NEW_FIELD] = value
                diff = self.compare()
                self.assertTrue(has_forbidden_diff(diff))
                self.assertEqual(diff["added"], ["/0/0/snapshots/0/" + NEW_FIELD])
                self.assertNotIn("input_tokens", json.dumps(diff))
        for value in ("snapshot_head_etag:v2", "", ["snapshot_head_etag:v1"]):
            with self.subTest(value=value):
                self.head = copy.deepcopy(self.base)
                self.head[HEAD_CAS] = value
                self.assertEqual(self.compare()["added"], ["/0/0/" + HEAD_CAS])

    def test_declared_addition_with_money_change_fails(self):
        self.add_observed()
        self.head["snapshots"][0]["usage"]["output_tokens"] += 1
        diff = self.compare()
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], ["/0/0/snapshots/0/usage/output_tokens"])
        self.assertEqual(len(diff["allowed_additions"]), 2)

    def test_declared_key_nested_or_new_entity_stays_added(self):
        self.head["snapshots"][0]["usage"][NEW_FIELD] = []
        self.assertEqual(self.compare()["added"], ["/0/0/snapshots/0/usage/<key#0>"])
        self.head = copy.deepcopy(self.base)
        self.head["snapshots"].append({NEW_FIELD: []})
        self.assertEqual(self.compare()["added"], ["/0/0/snapshots/1"])
        # A snapshot only the head has is never a declared position.
        self.base["snapshots"] = []
        self.head = copy.deepcopy(self.base)
        self.head["snapshots"].append({NEW_FIELD: []})
        self.assertEqual(self.compare()["added"], ["/0/0/snapshots/0"])
        # Data maps and the envelope's other records are not declared positions.
        self.base = envelope()
        self.base["client_report"] = {}
        self.base["snapshots"][0]["semantic_envelope"]["component_hashes"] = {}
        self.head = copy.deepcopy(self.base)
        self.head["client_report"][NEW_FIELD] = []
        self.head["snapshots"][0]["semantic_envelope"]["component_hashes"][NEW_FIELD] = []
        self.head["snapshots"][0][HEAD_CAS] = HEAD_CAS_VALUE
        diff = self.compare()
        self.assertEqual(diff["allowed_additions"], [])
        self.assertEqual(len(diff["added"]), 3)

    def test_declared_key_seen_in_base_stays_added(self):
        # A field that moved from anywhere in the base is not an addition.
        for location in (("snapshots", 0, "usage"), ("snapshots", 0, "semantic_envelope"), ()):
            with self.subTest(location=location):
                self.base = envelope()
                target = self.base
                for key in location:
                    target = target[key]
                target[NEW_FIELD] = []
                self.head = envelope()
                self.head["snapshots"][0][NEW_FIELD] = []
                diff = self.compare()
                self.assertTrue(has_forbidden_diff(diff))
                self.assertIn("/0/0/snapshots/0/" + NEW_FIELD, diff["added"])
                self.assertEqual(diff["allowed_additions"], [])
        self.base = envelope()
        self.base["snapshots"][0]["semantic_envelope"][HEAD_CAS] = HEAD_CAS_VALUE
        self.head = copy.deepcopy(self.base)
        self.head[HEAD_CAS] = HEAD_CAS_VALUE
        self.assertEqual(self.compare()["added"], ["/0/0/" + HEAD_CAS])

    def test_decimal_text_must_match(self):
        a = b'{"snapshots":[{"cost_usd":1.0}]}'
        b = b'{"snapshots":[{"cost_usd":1.00}]}'
        diff = receipt_diff(json.dumps([list(a)]), json.dumps([list(b)]))
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], ["/0/snapshots/0/cost_usd"])
        self.assertFalse(has_forbidden_diff(receipt_diff(json.dumps([list(a)]), json.dumps([list(a)]))))

    def test_number_spelling_must_match_even_with_declared_addition(self):
        # Equal values, different JSON bytes: the declared addition must not hide them.
        for base, head in (("0.01", "1e-2"), ("1.0", "1.0e0"), ("0", "-0"), ("1.0", "1.00")):
            with self.subTest(base=base, head=head):
                a = '{"snapshots":[{"cost_usd":' + base + '}]}'
                b = '{"snapshots":[{"cost_usd":' + head + ',"cache_observations":[]}]}'
                diff = receipt_diff(json.dumps([list(a.encode())]), json.dumps([list(b.encode())]),
                                    {"snapshot": {NEW_FIELD: []}})
                self.assertTrue(has_forbidden_diff(diff))
                self.assertEqual(diff["changed"], ["/0/snapshots/0/cost_usd"])
                self.assertEqual(diff["allowed_additions"], ["/0/snapshots/0/" + NEW_FIELD])

    def test_number_never_equals_string_or_bool(self):
        for base, head in (('"1"', "1"), ('"0.01"', "0.01"), ("0", "false"), ("1", "true")):
            with self.subTest(base=base, head=head):
                a = '{"snapshots":[{"cost_usd":' + base + '}]}'
                b = '{"snapshots":[{"cost_usd":' + head + '}]}'
                diff = receipt_diff(json.dumps([list(a.encode())]), json.dumps([list(b.encode())]))
                self.assertEqual(diff["changed"], ["/0/snapshots/0/cost_usd"])

    def test_parser_follows_fences(self):
        block = '\n{"snapshot": {"new_field": []}}\n'
        declared = {"snapshot": {"new_field": []}}
        # A declaration inside another fence is example text, not a declaration.
        self.assertIsNone(parse_declarations(
            "````\n" + FENCE + DECLARED_INFO + block + FENCE + "\n````\n"))
        self.assertIsNone(parse_declarations(
            "~~~\n" + FENCE + DECLARED_INFO + block + FENCE + "\n~~~\n"))
        self.assertIsNone(parse_declarations("> " + FENCE + DECLARED_INFO + "\n> {}\n> " + FENCE + "\n"))
        # Only the same character, at least as long and without info, closes a fence.
        self.assertEqual(parse_declarations("````" + DECLARED_INFO + block + "````\n"), declared)
        self.assertEqual(parse_declarations("````" + DECLARED_INFO + block + "`````\n"), declared)
        self.assertEqual(parse_declarations("~~~" + DECLARED_INFO + block + "~~~\r\n"), declared)
        self.assertEqual(parse_declarations("~~~~ " + DECLARED_INFO + " " + block + "  ~~~~~\n"), declared)
        # Another info string is an ordinary fence.
        self.assertIsNone(parse_declarations(FENCE + DECLARED_INFO + "-old" + block + FENCE + "\n"))
        for body in (
                "~~~" + DECLARED_INFO + block + "~~~\n" + FENCE + DECLARED_INFO + block + FENCE + "\n",
                "````" + DECLARED_INFO + block + FENCE + "\n",
                "~~~" + DECLARED_INFO + block + FENCE + "\n",
                FENCE + DECLARED_INFO + block + FENCE + " json\n"):
            with self.subTest(body=body), self.assertRaisesRegex(RuntimeError, "declared additions"):
                parse_declarations(body)

    def test_parser_accepts_one_block(self):
        self.assertIsNone(parse_declarations(None))
        self.assertIsNone(parse_declarations("No declarations. `money-eq-declared-additions` is the tag."))
        # An indented example documents the format without declaring anything.
        self.assertIsNone(parse_declarations(
            f"Example:\n\n    {FENCE}money-eq-declared-additions\n    {{}}\n    {FENCE}\n"))
        self.assertEqual(parse_declarations(pr_body(json.dumps(DECLARED))), DECLARED)
        self.assertEqual(parse_declarations(pr_body('{"snapshot": {"new_field": {}}}')),
                         {"snapshot": {"new_field": {}}})

    def test_parser_rejects_invalid_blocks(self):
        invalid = [
            pr_body(json.dumps(DECLARED), json.dumps(DECLARED)),
            pr_body("{not json"),
            pr_body('{"snapshot": {"a": [], "a": []}}'),
            pr_body('{"envelope": {}, "extra": {}}'),
            pr_body("[]"),
            pr_body('{"snapshot": []}'),
            f"{FENCE}money-eq-declared-additions\n{{}}\n",
        ]
        for value in ("1", "1.5", "true", "null", "[{}]", '{"a": []}', '[""]', '"x"', "NaN"):
            invalid.append(pr_body('{"snapshot": {"new_field": ' + value + "}}"))
        for value in ("1", "true", "null", '""', "[]", "{}"):
            invalid.append(pr_body('{"envelope": {"new_contract": ' + value + "}}"))
        for key in ("cost_usd", "usage", "request_id", "bucket", "account_id", "input_tokens",
                    "model_usage", "model", "total_cost_usd", "account_identifier_hash", ""):
            invalid.append(pr_body(json.dumps({"snapshot": {key: []}})))
        for key in ("machine_id", "source", "snapshots", "client_report", "schema_version",
                    "usage_decrease_hold_ack_contract", "contracts"):
            invalid.append(pr_body(json.dumps({"envelope": {key: "x"}})))
        for body in invalid:
            with self.subTest(body=body), self.assertRaisesRegex(RuntimeError, "declared additions"):
                parse_declarations(body)

    def test_explicit_base_or_no_unique_pr_uses_no_declarations(self):
        pr = {"number": 7, "baseRefName": "main", "body": pr_body(json.dumps(DECLARED))}
        self.assertEqual(pr_declarations([pr], explicit=False), (7, DECLARED))
        self.assertEqual(pr_declarations([pr], explicit=True), (None, None))
        self.assertEqual(pr_declarations([], explicit=False), (None, None))
        self.assertEqual(pr_declarations([pr, dict(pr, number=8)], explicit=False), (None, None))
        self.assertEqual(pr_declarations([dict(pr, body="")], explicit=False), (7, None))
        self.add_observed()
        self.assertTrue(has_forbidden_diff(self.compare(None)))

    def test_canonical_declarations_receipt(self):
        self.assertEqual(canonical_declarations(None), (None, None))
        text, digest = canonical_declarations(DECLARED)
        self.assertEqual(text, '{"envelope":{"head_cas_contract":"snapshot_head_etag:v1"},'
                               '"snapshot":{"cache_observations":[]}}')
        self.assertEqual(len(digest), 64)
        self.assertEqual(canonical_declarations(dict(reversed(list(DECLARED.items())))),
                         (text, digest))


def sha(canonical_text):
    return hashlib.sha256(canonical_text.encode()).hexdigest()


def entry_sha(raw_path_text, value_text):
    """Signed digest from literal canonical text: the raw path and the value."""
    return sha('{"path":' + raw_path_text + ',"value":' + value_text + "}")


RAW_SNAPSHOT = '[0,0,"snapshots",0,'


SIGNED_HEAD = "0123456789abcdef0123456789abcdef01234567"
SNAPSHOT = "/0/0/snapshots/0/"
FIXTURES = ["duplicate_request_ids.json", "side_owner.json"]


def money_block(diff, **extra):
    return dict(extra, money={"signed_by": "independent money review", "head": SIGNED_HEAD, "diff": diff})


class SignedMoneyTests(unittest.TestCase):
    """An intended money change passes only when its signed expected diff matches exactly."""

    def setUp(self):
        self.base = envelope()
        self.head = copy.deepcopy(self.base)
        snapshot = self.head["snapshots"][0]
        snapshot["usage"]["input_tokens"] = 101
        del snapshot["bucket"]
        snapshot["new_money"] = {"z": 1, "a": ["\u00e9"]}
        # Digests of the raw path and value as canonical JSON text, computed independently.
        self.signed = [
            {"path": SNAPSHOT + "usage/input_tokens", "class": "changed",
             "sha256": entry_sha(RAW_SNAPSHOT + '"usage","input_tokens"]', "101")},
            {"path": SNAPSHOT + "bucket", "class": "removed",
             "sha256": entry_sha(RAW_SNAPSHOT + '"bucket"]', '"synthetic-bucket"')},
            {"path": SNAPSHOT + "<key#3>", "class": "added",
             "sha256": entry_sha(RAW_SNAPSHOT + '"new_money"]', '{"a":["\u00e9"],"z":1}')},
        ]

    def compare(self, signed, declarations=None):
        return receipt_diff(receipt([self.base]), receipt([self.head]), declarations, signed)

    def assert_red(self, diff):
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["signed_money"], [])

    def test_exact_signed_match_passes(self):
        diff = self.compare(self.signed)
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(sorted(diff["signed_money"], key=str), sorted(self.signed, key=str))
        self.assertEqual([diff[kind] for kind in ("added", "changed", "removed", "signed_missing")],
                         [[], [], [], []])
        self.assertNotIn("synthetic-bucket", json.dumps(diff))

    def test_without_money_part_signed_paths_stay_red(self):
        diff = self.compare(None)
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], [SNAPSHOT + "usage/input_tokens"])

    def test_extra_observed_path_is_red(self):
        diff = self.compare(self.signed[:2])
        self.assert_red(diff)
        self.assertEqual(diff["added"], [SNAPSHOT + "<key#3>"])
        self.assertEqual(signed_mismatch(diff["observed"], self.signed[:2]), ([], [self.signed[2]]))

    def test_missing_signed_path_is_red(self):
        missing = {"path": SNAPSHOT + "usage/output_tokens", "class": "changed", "sha256": sha("3")}
        diff = self.compare(self.signed + [missing])
        self.assert_red(diff)
        self.assertEqual(diff["signed_missing"], [missing["path"]])
        # Nothing observed at all, but the file signs a change: still red.
        self.head = copy.deepcopy(self.base)
        diff = self.compare([missing])
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["signed_missing"], [missing["path"]])

    def test_wrong_class_is_red(self):
        signed = copy.deepcopy(self.signed)
        signed[0]["class"] = "added"
        self.assert_red(self.compare(signed))

    def test_file_signed_for_older_head_with_other_diff_is_red(self):
        # Same path, other value digest (the older head emitted 102).
        signed = copy.deepcopy(self.signed)
        signed[0]["sha256"] = sha("102")
        self.assert_red(self.compare(signed))
        # Other path set.
        signed = copy.deepcopy(self.signed)
        signed[0]["path"] = SNAPSHOT + "usage/output_tokens"
        self.assert_red(self.compare(signed))

    def test_same_paths_one_changed_leaf_differs_is_red(self):
        self.head["snapshots"][0]["usage"]["output_tokens"] = 3
        signed = self.signed + [
            {"path": SNAPSHOT + "usage/output_tokens", "class": "changed",
             "sha256": entry_sha(RAW_SNAPSHOT + '"usage","output_tokens"]', "3")}]
        self.assertFalse(has_forbidden_diff(self.compare(signed)))
        self.head["snapshots"][0]["usage"]["output_tokens"] = 4
        diff = self.compare(signed)
        self.assert_red(diff)
        self.assertEqual(diff["changed"], [SNAPSHOT + "usage/input_tokens", SNAPSHOT + "usage/output_tokens"])

    def test_same_paths_added_subtree_differs_inside_is_red(self):
        self.head["snapshots"][0]["new_money"]["a"] = ["e"]
        diff = self.compare(self.signed)
        self.assert_red(diff)
        self.assertEqual(diff["added"], [SNAPSHOT + "<key#3>"])
        self.assertNotIn('"e"', json.dumps(diff))

    def test_renamed_opaque_added_key_is_red(self):
        # Same display path (<key#3>), same subtree, other real key.
        snapshot = self.head["snapshots"][0]
        snapshot["new_money_v2"] = snapshot.pop("new_money")
        diff = self.compare(self.signed)
        self.assert_red(diff)
        self.assertEqual(diff["added"], [SNAPSHOT + "<key#3>"])
        missing, extra = signed_mismatch(diff["observed"], self.signed)
        self.assertEqual([entry["path"] for entry in missing + extra], [SNAPSHOT + "<key#3>"] * 2)
        self.assertNotIn("new_money", json.dumps(diff))

    def raw_compare(self, base, head, signed):
        return receipt_diff(json.dumps([list(base.encode())]), json.dumps([list(head.encode())]),
                            None, signed)

    def test_renamed_data_map_key_is_red(self):
        base = '{"snapshots":[{"model_usage":[{"selector_context":{}}]}]}'
        path = "/0/snapshots/0/model_usage/0/selector_context/<key#0>"
        signed = [{"path": path, "class": "added", "sha256": entry_sha(
            '[0,"snapshots",0,"model_usage",0,"selector_context","account-A"]', "101")}]
        head_a = '{"snapshots":[{"model_usage":[{"selector_context":{"account-A":101}}]}]}'
        self.assertFalse(has_forbidden_diff(self.raw_compare(base, head_a, signed)))
        head_b = head_a.replace("account-A", "account-B")
        diff = self.raw_compare(base, head_b, signed)
        self.assert_red(diff)
        self.assertEqual(diff["added"], [path])
        self.assertNotIn("account", json.dumps(diff))

    def test_changed_opaque_ancestor_key_is_red(self):
        # Same display path, class and leaf value; only an opaque ancestor key differs.
        path = "/0/snapshots/0/model_usage/0/selector_context/<key#0>/<key#0>"
        signed = [{"path": path, "class": "changed", "sha256": entry_sha(
            '[0,"snapshots",0,"model_usage",0,"selector_context","acct-1","x"]', "2")}]

        def body(account, x):
            return '{"snapshots":[{"model_usage":[{"selector_context":{"' + account + '":{"x":' + x + "}}}]}]}"
        self.assertFalse(has_forbidden_diff(self.raw_compare(body("acct-1", "1"), body("acct-1", "2"), signed)))
        diff = self.raw_compare(body("acct-2", "1"), body("acct-2", "2"), signed)
        self.assert_red(diff)
        self.assertEqual(diff["changed"], [path])
        self.assertNotIn("acct", json.dumps(diff))

    def test_declared_key_cannot_look_like_a_redacted_label(self):
        for declared in ({"snapshot": {"<key#0>": []}}, {"envelope": {"<key#0>_contract": "v1"}}):
            with self.subTest(declared=declared), self.assertRaisesRegex(RuntimeError, "redacted-key label"):
                parse_declarations(pr_body(json.dumps(declared)))

    def test_fixture_absent_from_signed_file_with_diff_is_red(self):
        lists = signed_money_lists(money_block({"side_owner.json": self.signed}), FIXTURES)
        self.assertEqual(lists, {"duplicate_request_ids.json": [], "side_owner.json": self.signed})
        self.assert_red(self.compare(lists["duplicate_request_ids.json"]))
        self.assertFalse(has_forbidden_diff(self.compare(lists["side_owner.json"])))
        self.assertIsNone(signed_money_lists(None, FIXTURES))
        self.assertIsNone(signed_money_lists({"snapshot": {NEW_FIELD: []}}, FIXTURES))

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", ("new_fixture",))
    def test_head_only_fixture_on_both_sides_is_compared_and_needs_a_signature(self):
        names = sorted(NATIVE_FIXTURES) + ["new_fixture"]
        compared, uncompared = receipt_names(*receipt_dirs(self, names, names), set(names))
        self.assertIn("new_fixture.json", compared)
        self.assertEqual(uncompared, [])
        lists = signed_money_lists(money_block({"new_fixture.json": self.signed}), compared)
        self.assertFalse(has_forbidden_diff(self.compare(lists["new_fixture.json"])))
        self.assert_red(self.compare(None))
        self.assert_red(self.compare([]))

    def test_unknown_fixture_name_is_an_error(self):
        with self.assertRaisesRegex(RuntimeError, "unknown fixtures"):
            signed_money_lists(money_block({"no_such_fixture.json": []}), FIXTURES)

    def test_declared_addition_and_signed_change_in_one_fixture_both_pass(self):
        self.head = copy.deepcopy(self.base)
        self.head["snapshots"][0][NEW_FIELD] = []
        self.head["snapshots"][0]["usage"]["input_tokens"] = 101
        declarations = parse_declarations(pr_body(json.dumps(money_block(
            {"side_owner.json": self.signed[:1]}, snapshot={NEW_FIELD: []}))))
        signed = signed_money_lists(declarations, FIXTURES)["side_owner.json"]
        diff = self.compare(signed, declarations)
        self.assertFalse(has_forbidden_diff(diff))
        self.assertEqual(diff["allowed_additions"], [SNAPSHOT + NEW_FIELD])
        self.assertEqual(diff["signed_money"], self.signed[:1])

    def test_explicit_base_ignores_money(self):
        pr = {"number": 7, "body": pr_body(json.dumps(money_block({"side_owner.json": self.signed})))}
        self.assertEqual(pr_declarations([pr], explicit=False)[1]["money"]["head"], SIGNED_HEAD)
        number, declarations = pr_declarations([pr], explicit=True)
        self.assertEqual((number, declarations), (None, None))
        diff = self.compare(signed_money_lists(declarations, FIXTURES))
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["signed_money"], [])

    def test_value_digest_uses_exact_number_text(self):
        def value(text):
            return decode_receipt(json.dumps([list(text)]))[0][0]["v"]
        self.assertEqual(value_sha256(value(b'{"v":1e-2}')), sha("1e-2"))
        self.assertEqual(value_sha256(value(b'{"v":0.01}')), sha("0.01"))
        self.assertNotEqual(value_sha256(value(b'{"v":1e-2}')), value_sha256(value(b'{"v":0.01}')))
        self.assertEqual(value_sha256(value(b'{"v":{"b":-0, "a":[1.0e0,"1",true,null]}}')),
                         sha('{"a":[1.0e0,"1",true,null],"b":-0}'))

    def test_parser_rejects_bad_money_parts(self):
        entry = {"path": SNAPSHOT + "usage/input_tokens", "class": "changed", "sha256": sha("101")}
        good = money_block({"side_owner.json": [entry]})
        self.assertEqual(parse_declarations(pr_body(json.dumps(good))), good)
        bad = []
        for signed_by in ("", "   ", "x" * 201, "line\nMONEY_EQUIVALENCE_FAKE", 7, None):
            bad.append(dict(good["money"], signed_by=signed_by))
        for head in (SIGNED_HEAD.upper(), SIGNED_HEAD[:39], SIGNED_HEAD + "0", "", None):
            bad.append(dict(good["money"], head=head))
        for changes in ({"class": "moved"}, {"class": "Changed"}, {"sha256": sha("101").upper()},
                        {"sha256": sha("101")[:63]}, {"sha256": None}, {"path": "relative"},
                        {"path": 3}, {"extra": 1}):
            bad.append(dict(good["money"], diff={"side_owner.json": [dict(entry, **changes)]}))
        bad.append(dict(good["money"], diff={"side_owner.json": [entry, dict(entry, sha256=sha("102"))]}))
        bad.append(dict(good["money"], diff={"side_owner.json": [entry, dict(entry, **{"class": "added"})]}))
        bad.append(dict(good["money"], diff={"side_owner.json": [{"path": entry["path"], "class": "changed"}]}))
        bad.append(dict(good["money"], diff={"side_owner.json": entry}))
        bad.append(dict(good["money"], diff=[entry]))
        bad.append({"signed_by": "review", "head": SIGNED_HEAD})
        bad.append(dict(good["money"], extra="x"))
        bodies = [pr_body(json.dumps({"money": money})) for money in bad]
        bodies.append(pr_body('{"money": []}'))
        # The same path both declared as a non-money addition and signed as money.
        both = money_block({"side_owner.json": [dict(entry, path=SNAPSHOT + NEW_FIELD, **{"class": "added"})]},
                           snapshot={NEW_FIELD: []})
        bodies.append(pr_body(json.dumps(both)))
        both = money_block({"side_owner.json": [dict(entry, path="/0/0/" + HEAD_CAS, **{"class": "added"})]},
                           envelope={HEAD_CAS: HEAD_CAS_VALUE})
        bodies.append(pr_body(json.dumps(both)))
        for body in bodies:
            with self.subTest(body=body), self.assertRaisesRegex(RuntimeError, "declared additions"):
                parse_declarations(body)


class TransplantTests(unittest.TestCase):
    def test_base_scanner_fixture_is_preserved_and_missing_apis_fail_closed(self):
        # Older bases must never acquire the head's ClaudeTerminalOffForTest
        # prologue. Validate the real transplant guard without touching runtime.
        with tempfile.TemporaryDirectory() as scratch:
            base = Path(scratch)
            fixture = base / "crates/ottto-service/src/snapshots/e2_pipeline_scan_fixture.rs"
            fixture.parent.mkdir(parents=True)
            original = b"// base adapter\nfn scan() {}\nfn scan_other() {}\nfn begin_durable() {}\n"
            fixture.write_bytes(original)
            require_base_scan_fixture(base)
            self.assertEqual(fixture.read_bytes(), original)
            # A base after the record store's removal begins its pass by name.
            fixture.write_bytes(original.replace(b"fn begin_durable(", b"fn begin_pass("))
            require_base_scan_fixture(base)
            fixture.write_bytes(original)
            for method in ("scan", "scan_other", "begin_durable"):
                with self.subTest(missing=method):
                    fixture.write_bytes(original.replace(f"fn {method}(".encode(), b"fn missing("))
                    with self.assertRaisesRegex(RuntimeError, "base compat"):
                        require_base_scan_fixture(base)
            fixture.unlink()
            with self.assertRaises(FileNotFoundError):
                require_base_scan_fixture(base)

    def test_base_without_the_in_tree_harness_fails_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            base = Path(scratch)
            tests = base / "crates/ottto-service/src/snapshot_sync/claude_money_e2_pipeline_tests.rs"
            tests.parent.mkdir(parents=True)
            tests.write_text("pub(in crate::snapshot_sync) mod money_equivalence_tests {}\n")
            require_base_harness(base)
            tests.write_text("mod other_tests {}\n")
            with self.assertRaisesRegex(RuntimeError, "base compat"):
                require_base_harness(base)


NEW_FIXTURE = "new_fixture"


def arm_log(arm, names):
    lines = [f"MONEY_EQUIVALENCE {name} VERIFIED bytes=1 sha256=x cross_build_sha256=y" for name in names]
    disk = ["restart_between_pages", "upgrade_without_semantic_revision"]
    disk += ["downgrade_then_reupgrade"] if arm == "base" else []
    lines += [f"MONEY_EQUIVALENCE_DISK {name} VERIFIED pages=1" for name in disk]
    return "\n".join(lines) + "\n"


def receipt_dirs(testcase, base, head, bodies=None):
    """Synthetic base/head receipt directories with saved digests."""
    scratch = tempfile.TemporaryDirectory()
    testcase.addCleanup(scratch.cleanup)
    left, right = Path(scratch.name, "base"), Path(scratch.name, "head")
    for arm, directory, names in (("base", left, base), ("head", right, head)):
        directory.mkdir()
        for name in names:
            data = (bodies or {}).get((arm, name), b"[]")
            for stem in (name, f"{name}.cross-build"):
                (directory / f"{stem}.json").write_bytes(data)
                (directory / f"{stem}.sha256").write_text(hashlib.sha256(data).hexdigest())
    return left, right


class HeadOnlyFixtureTests(unittest.TestCase):
    """A new native fixture is required on the head, optional and UNCOMPARED on the base."""

    def receipts(self, base, head):
        return receipt_dirs(self, base, head)

    def coverage_and_receipts(self, base, head):
        expected = {"base": native_coverage("base", arm_log("base", base)),
                    "head": native_coverage("head", arm_log("head", head))}
        return receipt_names(*self.receipts(base, head), expected["head"], expected["base"])

    def test_empty_head_only_set_is_todays_gate(self):
        self.assertEqual(money_equivalence.HEAD_ONLY_FIXTURES, ())
        self.assertEqual(len(NATIVE_FIXTURES), 10)
        names = sorted(NATIVE_FIXTURES)
        self.assertEqual(self.coverage_and_receipts(names, names),
                         ([f"{name}.json" for name in names], []))
        for arm in ("base", "head"):
            with self.subTest(arm=arm), self.assertRaisesRegex(RuntimeError, "incomplete native coverage"):
                native_coverage(arm, arm_log(arm, names + [NEW_FIXTURE]))
        with self.assertRaisesRegex(RuntimeError, "^missing or extra fixture receipts$"):
            receipt_names(*self.receipts(names, names + [NEW_FIXTURE]), NATIVE_FIXTURES)
        self.assertEqual(
            verified_summary(names, [], "b", "h", 1.0),
            "Money equivalence VERIFIED: 10 + 2 disk-restore fixtures, base `b`, head `h`. "
            "1.0s. Family vector/Pi remain ignored.\n")

    def test_alias_receipt_on_both_arms_is_red(self):
        # Receipt files must be exactly the VERIFIED names, not just the right count.
        names = sorted(NATIVE_FIXTURES)
        aliased = [name for name in names if name != "side_owner"] + ["side_owner_alias"]
        with self.assertRaisesRegex(RuntimeError, "^missing or extra fixture receipts$"):
            receipt_names(*self.receipts(aliased, aliased), NATIVE_FIXTURES, NATIVE_FIXTURES)

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", (NEW_FIXTURE,))
    def test_head_only_fixture_absent_on_base_is_uncompared(self):
        names = sorted(NATIVE_FIXTURES)
        compared, uncompared = self.coverage_and_receipts(names, names + [NEW_FIXTURE])
        self.assertEqual(compared, [f"{name}.json" for name in names])
        self.assertEqual(uncompared, [f"{NEW_FIXTURE}.json"])
        self.assertIn(f"10 compared | 1 new fixtures uncompared (absent on base): {NEW_FIXTURE}.json.",
                      verified_summary(compared, uncompared, "b", "h", 1.0))
        _, right = self.receipts(names, names + [NEW_FIXTURE])
        with contextlib.redirect_stdout(io.StringIO()) as log:
            records, failures = uncompared_receipts(right, uncompared, None)
        digest = hashlib.sha256(b"[]").hexdigest()
        self.assertEqual(records, {f"{NEW_FIXTURE}.json": {"head_sha256": digest,
                                                           "head_cross_build_sha256": digest}})
        self.assertEqual(failures, [])
        self.assertIn(f"MONEY_EQUIVALENCE_UNCOMPARED {NEW_FIXTURE}.json absent on base; head VERIFIED",
                      log.getvalue())
        # A signed money diff may name it, as it may name any compared fixture.
        lists = signed_money_lists({"money": {"diff": {f"{NEW_FIXTURE}.json": []}}},
                                   compared + uncompared)
        self.assertEqual(lists[f"{NEW_FIXTURE}.json"], [])

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", (NEW_FIXTURE,))
    def test_signed_diff_on_an_uncompared_fixture_is_red(self):
        names = sorted(NATIVE_FIXTURES)
        _, right = self.receipts(names, names + [NEW_FIXTURE])
        entry = {"path": "/0/snapshots/0/usage/input_tokens", "class": "changed", "sha256": "0" * 64}
        with contextlib.redirect_stdout(io.StringIO()) as log:
            _, failures = uncompared_receipts(right, [f"{NEW_FIXTURE}.json"],
                                              {f"{NEW_FIXTURE}.json": [entry]})
        self.assertEqual(failures, [f"{NEW_FIXTURE}.json"])
        self.assertIn(f"MONEY_EQUIVALENCE_SIGNED {NEW_FIXTURE}.json MISMATCH", log.getvalue())

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", (NEW_FIXTURE,))
    def test_head_only_fixture_the_base_also_emits_is_compared(self):
        names = sorted(NATIVE_FIXTURES) + [NEW_FIXTURE]
        compared, uncompared = self.coverage_and_receipts(names, names)
        self.assertEqual(compared, sorted(f"{name}.json" for name in names))
        self.assertEqual(uncompared, [])

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", (NEW_FIXTURE,))
    def test_head_missing_a_head_only_fixture_fails(self):
        names = sorted(NATIVE_FIXTURES)
        with self.assertRaisesRegex(RuntimeError, "incomplete native coverage"):
            native_coverage("head", arm_log("head", names))
        # Both sides omitting it is no different: the head arm fails first.
        native_coverage("base", arm_log("base", names))
        with self.assertRaisesRegex(RuntimeError, "missing or extra fixture receipts"):
            receipt_names(*self.receipts(names, names), NATIVE_FIXTURES | {NEW_FIXTURE})

    @mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", (NEW_FIXTURE,))
    def test_base_missing_a_regular_fixture_still_fails(self):
        names = sorted(NATIVE_FIXTURES)
        short = [name for name in names if name != "side_owner"]
        with self.assertRaisesRegex(RuntimeError, "incomplete native coverage"):
            native_coverage("base", arm_log("base", short + [NEW_FIXTURE]))
        # Nor may a regular receipt pass as uncompared.
        with self.assertRaisesRegex(RuntimeError, "missing or extra fixture receipts"):
            receipt_names(*self.receipts(short, names + [NEW_FIXTURE]),
                          NATIVE_FIXTURES | {NEW_FIXTURE})

    def test_head_only_name_overlapping_a_native_fixture_fails(self):
        for head_only in (("side_owner",), (NEW_FIXTURE, NEW_FIXTURE)):
            with self.subTest(head_only=head_only), \
                    mock.patch.object(money_equivalence, "HEAD_ONLY_FIXTURES", head_only):
                with self.assertRaisesRegex(RuntimeError, "overlap"):
                    require_disjoint_head_only()
                with self.assertRaisesRegex(RuntimeError, "overlap"):
                    native_coverage("head", arm_log("head", sorted(NATIVE_FIXTURES)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
