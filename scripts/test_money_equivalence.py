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

    def test_token_change_fails_even_with_allowed_addition(self):
        self.head[CONTRACT] = CONTRACT_VALUE
        self.head["snapshots"][0]["usage"]["input_tokens"] += 1
        self.assert_change_fails("changed", "/0/0/snapshots/0/usage/input_tokens")

    def test_cost_change_fails(self):
        self.head["snapshots"][0]["cost_usd"] = "0.0124"
        self.assert_change_fails("changed", "/0/0/snapshots/0/cost_usd")

    def test_allowlisted_key_below_envelope_fails(self):
        for location, path in (
                (self.head["snapshots"][0], "/0/0/snapshots/0"),
                (self.head["snapshots"][0]["usage"], "/0/0/snapshots/0/usage")):
            with self.subTest(path=path):
                location[CONTRACT] = CONTRACT_VALUE
                self.assert_change_fails("added", path + "/" + CONTRACT)
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
        self.assert_change_fails("added", "/0/0/new_contract")
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
        a = b'{"cost_usd":0.100000000000000001}'
        b = b'{"cost_usd":0.100000000000000002}'
        diff = receipt_diff(json.dumps([list(a)]), json.dumps([list(b)]))
        self.assertTrue(has_forbidden_diff(diff))
        self.assertEqual(diff["changed"], ["/0/cost_usd"])

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
        self.assert_change_fails("changed", "/0/0/payload/0")

    def test_paths_are_escaped_and_contain_no_values(self):
        self.head["snapshots"][0]["private~/key"] = "DO_NOT_LOG_THIS_VALUE"
        diff = self.compare()
        self.assertEqual(diff["added"], ["/0/0/snapshots/0/private~0~1key"])
        self.assertNotIn("DO_NOT_LOG_THIS_VALUE", json.dumps(diff))

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
