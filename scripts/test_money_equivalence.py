#!/usr/bin/env python3
"""Portable synthetic receipt checks. Never builds or executes native binaries."""
import copy
import json
import unittest

from money_equivalence import decode_receipt, has_forbidden_diff, receipt_diff


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
