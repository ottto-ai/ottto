#!/usr/bin/env python3
"""Dispatch-only emitted-body equality gate. Never reads provider/user state."""
import hashlib
import json
import os
from decimal import Decimal
from pathlib import Path
import re
import subprocess
import time
from collections import Counter


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def output(args):
    return subprocess.check_output(args, text=True).strip()


# Disk-only lifecycle fixtures (#806): a VERIFIED line each, no receipt file.
DISK_FIXTURES = ("restart_between_pages", "upgrade_without_semantic_revision")
# A base with the retired restart-record store also runs its downgrade
# fixture; the head has no record store to downgrade from (its Tail writer is
# forward-only), so this line is accepted only from the base and never required.
BASE_ONLY_DISK_FIXTURES = ("downgrade_then_reupgrade",)
# Native fixtures every arm must emit (one VERIFIED receipt each).
NATIVE_FIXTURES = frozenset({
    "progressive_response", "duplicate_request_ids", "resolver_conflict",
    "quiet_sidecar_growth", "side_owner", "side_without_owner",
    "side_owner_directory_unlisted", "failed_then_healthy_telemetry",
    "codex_v2_sticky", "codex_legacy_acked_sticky",
})
# New native fixtures: the head must emit each one; the base may not have it
# yet. A name the base does not emit is UNCOMPARED (the head's VERIFIED receipt
# only, never a match or a diff). Once the base emits it, it is compared like
# any other fixture and can be removed here.
HEAD_ONLY_FIXTURES = ()


# Base and head bodies must match exactly. The only accepted difference is a
# new key ADDED where both sides have the record, and only when it is not money:
# - In-tree, for every PR: a batch-envelope capability constant listed below,
#   with exactly the string value below.
# - Per PR: a key the PR body declares (see parse_declarations). The receipts
#   must show no changed or removed path, and every added path must be declared.
#   A declared key is a direct child of a batch envelope (a `*_contract` key
#   with an exact non-empty string) or of a snapshot present on both sides
#   (a new key, not in the snapshot schema, whose value is exactly [] or {}).
#   A key found anywhere in the base body never qualifies: that field moved.
#   New entities (a snapshot, bucket, request or data-map key) and anything
#   nested deeper never qualify. A declaration belongs to its PR only; a run
#   with an explicit base, or without a unique open PR, has none.
# Never accept money or identity fields here: tokens, cost, request or
# response counts, model, placement, account or organization identity, or
# upload/ACK state that feeds money.
# An INTENDED money change uses the same block's `money` part, signed by the
# PR's independent money review: for each fixture, every remaining path with
# its class (added, changed or removed) and a sha256 over its raw path (every
# real key and index, including redacted ones) and its value. The gate passes
# only if the observed remaining diff equals that list exactly; any extra,
# missing, reclassified, re-keyed or re-valued path stays red. The base is never
# changed, and the signature never carries to another PR or a release cut.
ENVELOPE_ADDITION_ALLOWLIST = {
    # Keep in sync with snapshots.rs::USAGE_DECREASE_HOLD_ACK_CONTRACT.
    "usage_decrease_hold_ack_contract": "usage_decrease_hold_ack:v1",
}

# Display vocabulary only, never comparison exclusions. Recognize record fields
# only at their schema locations; data maps (even with schema-looking keys) and
# unknown fields are conservatively redacted. Extend this for diagnostics only.
_MONEY_DIFF_SCHEMA = {key: {} for key in (
    "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_5m_tokens",
    "cache_creation_1h_tokens", "reasoning_output_tokens", "unattributed_total_tokens",
    "request_count", "cost_usd", "input_cost_usd", "output_cost_usd",
    "cache_read_cost_usd", "cache_creation_cost_usd",
)}
# Wire records: snapshots/wire.rs::{SnapshotModelUsage, SnapshotIdentityPart,
# SessionAccountEvidence, SnapshotRequestEvidence, SnapshotCost}. Empty child
# schemas intentionally keep all entries of selector/data maps redacted.
_IDENTITY_PART_DIFF_SCHEMA = dict(_MONEY_DIFF_SCHEMA, account_identifier_hash={}, evidence_ref={})
_MODEL_DIFF_SCHEMA = dict(_MONEY_DIFF_SCHEMA, **{key: {} for key in (
    "model", "reasoning_effort", "selector_context", "selector_sources",
    "account_identifier_hash", "auth_mode", "billing_channel", "billing_provider",
    "gateway_provider", "model_provider", "subscription_product", "evidence_ref",
)})
_MODEL_DIFF_SCHEMA["identity_parts"] = _IDENTITY_PART_DIFF_SCHEMA
_SNAPSHOT_DIFF_SCHEMA = dict(_MONEY_DIFF_SCHEMA, **{key: {} for key in (
    "source_session_id", "snapshot_fingerprint", "source_file_fingerprint", "status",
    "account_id", "bucket", "request_id", "refusal", "telemetry_owned_complete",
    "resolver_conflict_count", "usage_accounting_contract", "removed_request_count",
    "request_identity_refusals",
)})
_SNAPSHOT_DIFF_SCHEMA.update(
    usage=_MONEY_DIFF_SCHEMA, removed_usage=_MONEY_DIFF_SCHEMA,
    model_usage=_MODEL_DIFF_SCHEMA,
    cost={key: {} for key in (
        "total_cost_usd", "input_cost_usd", "output_cost_usd", "cache_read_cost_usd",
        "cache_creation_cost_usd", "evidence_source",
    )},
    session_account_evidence={key: {} for key in (
        "provider", "account_identifier_hash", "provider_workspace_hash",
        "identity_hash_scheme", "evidence_source", "identity_disposition", "source_created_at",
    )},
    request_evidence={"identity_basis": {}, "provider_workspace_hash": {}},
    usage_buckets={"bucket_start": {}, "model_usage": _MODEL_DIFF_SCHEMA,
                   "first_activity_at": {}, "last_activity_at": {}},
    semantic_envelope={key: {} for key in (
        "component_contract_version", "revision_contract_version", "upload_policy",
        "component_hashes", "revision_hash", "revision_v2_contract_version",
        "revision_v2_canonicalization", "revision_v2_parser_version",
        "revision_v2_scan_identity_version", "revision_v2_hash", "content_hash",
        "hash_epoch", "base_head_etag",
    )})
_ENVELOPE_DIFF_SCHEMA = {key: {} for key in (
    "schema_version", "source", "machine_id", "collector_version", "entity_ack_contract",
    "usage_decrease_hold_ack_contract", "head_cas_contract", "client_report",
)}
_ENVELOPE_DIFF_SCHEMA["snapshots"] = _SNAPSHOT_DIFF_SCHEMA

DECLARATIONS_INFO = "money-eq-declared-additions"
# A CommonMark fence line: indent 0-3, then 3+ backticks or 3+ tildes.
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
MONEY_CLASSES = ("added", "changed", "removed")
_SHA = re.compile(r"[0-9a-f]{64}")
_HEAD = re.compile(r"[0-9a-f]{40}")


def _schema_keys(schema):
    return set(schema).union(*(_schema_keys(child) for child in schema.values()))


def parse_declarations(body):
    """Return the PR body's declared additions, or None without a block.

    The block is one fenced code block with the info string above, holding
    {"envelope": {key: value}, "snapshot": {key: value}, "money": {...}}; any
    part may be omitted. Anything else fails closed.
    """
    # Follow fences like CommonMark: nothing inside a fence opens another, and a
    # fence closes only with the same character, at least as long, and no info.
    blocks, fence, block = [], None, None
    for line in (body or "").replace("\r\n", "\n").split("\n"):
        match = _FENCE.match(line)
        if fence is None:
            if match and not (match[1][0] == "`" and "`" in match[2]):
                fence = match[1]
                block = [] if match[2].strip() == DECLARATIONS_INFO else None
        elif (match and match[1][0] == fence[0] and len(match[1]) >= len(fence)
              and not match[2].strip()):
            if block is not None:
                blocks.append("\n".join(block))
            fence = block = None
        elif block is not None:
            block.append(line)
    if block is not None:
        raise RuntimeError("declared additions: unterminated block")
    if not blocks:
        return None
    if len(blocks) > 1:
        raise RuntimeError("declared additions: more than one block")
    try:
        parsed = json.loads(blocks[0], parse_float=Decimal, parse_constant=_reject_constant,
                            object_pairs_hook=_json_object)
    except ValueError as error:
        raise RuntimeError(f"declared additions: invalid JSON ({error})") from None
    if not isinstance(parsed, dict) or not parsed.keys() <= {"envelope", "snapshot", "money"}:
        raise RuntimeError("declared additions: expected an object with envelope/snapshot/money parts")
    snapshot_vocabulary = _schema_keys(_SNAPSHOT_DIFF_SCHEMA)
    for part, declared in parsed.items():
        if not isinstance(declared, dict):
            raise RuntimeError(f"declared additions: {part} must be an object")
        if part == "money":
            continue
        for key, value in declared.items():
            if part == "envelope":
                if not key.endswith("_contract") or key in ENVELOPE_ADDITION_ALLOWLIST:
                    raise RuntimeError(f"declared additions: envelope key {key!r} is not a new *_contract")
                if type(value) is not str or not value:
                    raise RuntimeError(f"declared additions: envelope {key!r} needs a non-empty string")
            else:
                if not key or key in snapshot_vocabulary:
                    raise RuntimeError(f"declared additions: snapshot key {key!r} is schema vocabulary")
                if type(value) not in (list, dict) or value:
                    raise RuntimeError(f"declared additions: snapshot {key!r} must be [] or {{}}")
            if key.startswith("<key#"):
                raise RuntimeError(f"declared additions: {key!r} looks like a redacted-key label")
    if "money" in parsed:
        _check_money(parsed["money"], {*parsed.get("envelope", {}), *parsed.get("snapshot", {})})
    return parsed


def _check_money(money, declared_keys):
    """Validate a signed expected money diff; fail closed."""
    if money.keys() != {"signed_by", "head", "diff"}:
        raise RuntimeError("declared additions: money needs exactly signed_by, head and diff")
    signed_by = money["signed_by"]
    if type(signed_by) is not str or not signed_by.strip() or len(signed_by) > 200 or not signed_by.isprintable():
        raise RuntimeError("declared additions: money signed_by must be a printable 1-200 char string")
    if type(money["head"]) is not str or not _HEAD.fullmatch(money["head"]):
        raise RuntimeError("declared additions: money head must be 40 lowercase hex")
    if not isinstance(money["diff"], dict):
        raise RuntimeError("declared additions: money diff must be an object")
    for fixture, entries in money["diff"].items():
        if not isinstance(entries, list):
            raise RuntimeError(f"declared additions: money diff {fixture!r} must be a list")
        paths = set()
        for entry in entries:
            if not isinstance(entry, dict) or entry.keys() != {"path", "class", "sha256"}:
                raise RuntimeError(f"declared additions: money entry in {fixture!r} needs path, class, sha256")
            path = entry["path"]
            if type(path) is not str or not path.startswith("/") or path in paths:
                raise RuntimeError(f"declared additions: money path {path!r} in {fixture!r} is bad or repeated")
            paths.add(path)
            if entry["class"] not in MONEY_CLASSES:
                raise RuntimeError(f"declared additions: money class {entry['class']!r} is not one of {MONEY_CLASSES}")
            if type(entry["sha256"]) is not str or not _SHA.fullmatch(entry["sha256"]):
                raise RuntimeError(f"declared additions: money sha256 for {path!r} must be 64 lowercase hex")
            leaf = path.rsplit("/", 1)[1].replace("~1", "/").replace("~0", "~")
            if leaf in declared_keys:
                raise RuntimeError(f"declared additions: {path!r} is both a non-money addition and money")


def signed_money_lists(declarations, fixtures):
    """{fixture: signed entries} when a money part exists, else None."""
    money = (declarations or {}).get("money")
    if money is None:
        return None
    unknown = sorted(set(money["diff"]) - set(fixtures))
    if unknown:
        raise RuntimeError(f"declared additions: money diff names unknown fixtures {unknown}")
    return {name: money["diff"].get(name, []) for name in fixtures}


def pr_declarations(prs, explicit):
    """(PR number, declarations) for the branch's unique open PR, else (None, None)."""
    if explicit or len(prs) != 1:
        return None, None
    return prs[0]["number"], parse_declarations(prs[0].get("body"))


def canonical_declarations(declarations):
    """(canonical JSON, sha256), or (None, None) without declarations."""
    if declarations is None:
        return None, None
    text = json.dumps(declarations, sort_keys=True, separators=(",", ":"))
    return text, hashlib.sha256(text.encode()).hexdigest()


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite JSON number")


class _JsonNumber(str):
    """A body number's exact JSON text: 0.01 vs 1e-2 or 0 vs -0 differ.

    A distinct type, so a number never equals a string (or a bool).
    """
    __slots__ = ()


_BYTE = re.compile(r"0|[1-9][0-9]{0,2}")


def _is_byte(value):
    exact = type(value) is _JsonNumber and _BYTE.fullmatch(value)
    return (type(value) is int or exact) and 0 <= int(value) <= 255


def _load_json(data, path, exact_numbers=False):
    try:
        # Exact number text never hides a cost change through rounding or respelling.
        return json.loads(data, parse_float=_JsonNumber if exact_numbers else Decimal,
                          parse_int=_JsonNumber if exact_numbers else None,
                          parse_constant=_reject_constant, object_pairs_hook=_json_object)
    except (ValueError, UnicodeDecodeError):
        # Errors, like diffs, must never print body values.
        raise ValueError(f"invalid JSON at {path or '/'}") from None


def decode_receipt(data):
    """Unwrap receipt Vec<Vec<u8>> and Claude's extra encoded-batch layer.

    Return the decoded tree and the exact paths of its batch envelopes. Never
    recursively decode payload arrays: they are content, even if byte-shaped.
    """
    receipt = _load_json(data, "")
    if not isinstance(receipt, list) or not receipt:
        raise ValueError("expected nonempty receipt array at /")

    def body(value, path):
        # Bodies keep exact number text; their encoded batches are byte arrays.
        if not isinstance(value, list) or not value or not all(map(_is_byte, value)):
            raise ValueError(f"expected encoded body at {path}")
        return _load_json(bytes(map(int, value)), path, exact_numbers=True)

    decoded, envelopes = [], set()
    for i, encoded in enumerate(receipt):
        path = f"/{i}"
        value = body(encoded, path)
        if isinstance(value, dict):
            envelopes.add(path)
        elif isinstance(value, list) and value:
            batches = []
            for j, encoded_batch in enumerate(value):
                batch_path = f"{path}/{j}"
                batch = body(encoded_batch, batch_path)
                if not isinstance(batch, dict):
                    raise ValueError(f"expected batch envelope at {batch_path}")
                batches.append(batch)
                envelopes.add(batch_path)
            value = batches
        else:
            raise ValueError(f"expected batch envelope or encoded batches at {path}")
        decoded.append(value)
    return decoded, envelopes


def _object_keys(value):
    if isinstance(value, dict):
        return set(value).union(*map(_object_keys, value.values()))
    if isinstance(value, list):
        return set().union(*map(_object_keys, value))
    return set()


def _canonical_value(value):
    """Sorted keys, compact separators, UTF-8; numbers keep their JSON text."""
    if type(value) is _JsonNumber:
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + _canonical_value(value[key])
                              for key in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(map(_canonical_value, value)) + "]"
    return json.dumps(value, ensure_ascii=False)


def value_sha256(value):
    return hashlib.sha256(_canonical_value(value).encode("utf-8", "surrogatepass")).hexdigest()


def entry_sha256(raw_path, value):
    """Digest of {"path": raw segments from the receipt root, "value": value}.

    Display paths redact opaque keys as ordinals; the raw path binds which key
    it really is (never printed), so a renamed key cannot reuse a signature.
    """
    return value_sha256({"path": list(raw_path), "value": value})


def _entry_key(entry):
    return entry["path"], entry["class"], entry["sha256"]


def signed_mismatch(observed, signed):
    """(missing, extra): signed entries not observed, observed entries not signed."""
    missing = Counter(map(_entry_key, signed))
    missing.subtract(map(_entry_key, observed))
    extra = Counter(map(_entry_key, observed))
    extra.subtract(map(_entry_key, signed))

    def entries(counts):
        return [dict(zip(("path", "class", "sha256"), key))
                for key in sorted(counts) for _ in range(counts[key])]
    return entries(missing), entries(extra)


def receipt_diff(base, head, declarations=None, signed=None):
    """Structural paths only; order and JSON scalar types remain significant.

    `observed` lists each remaining (not allowed) path with its class and the
    entry_sha256 of its raw path and head value (base value when removed).
    With `signed` (the fixture's signed money list), an exact match moves them
    to signed_money.
    """
    left, left_envelopes = decode_receipt(base)
    right, right_envelopes = decode_receipt(head)
    envelopes = left_envelopes & right_envelopes
    display_envelopes = left_envelopes | right_envelopes
    declarations = declarations or {}
    # A key the base already has anywhere was moved, not added.
    base_keys = _object_keys(left)
    diff = {kind: [] for kind in ("added", "removed", "changed", "allowed_additions",
                                  "signed_money", "signed_missing")}
    observed = []

    def record(kind, path, raw, value):
        diff[kind].append(path)
        observed.append({"path": path, "class": kind, "sha256": entry_sha256(raw, value)})

    def child(path, key):
        # RFC 6901 JSON Pointer escaping keeps paths unambiguous.
        return path + "/" + str(key).replace("~", "~0").replace("/", "~1")

    def walk(a, b, path, raw, schema, scope=None):
        # raw: the real key/index segments of path, for entry digests only.
        # scope: "envelope" for a batch envelope on both sides, "snapshot" for
        # an index of its snapshots list present on both sides, else None.
        if path in display_envelopes:
            schema = _ENVELOPE_DIFF_SCHEMA
            scope = "envelope" if path in envelopes else None
        declared = declarations.get(scope, {}) if isinstance(a, dict) else {}
        if type(a) is not type(b):
            record("changed", path, raw, b)
        elif isinstance(a, dict):
            # Stable ordinals use the sorted base/head union, independently of
            # insertion order or which side owns a key. Never print raw data keys.
            labels = {key: key if key in schema or key in declared else f"<key#{i}>"
                      for i, key in enumerate(sorted(a.keys() | b.keys()))}
            for key in sorted(b.keys() - a.keys()):
                allowed = (scope == "envelope" and key in ENVELOPE_ADDITION_ALLOWLIST and
                           type(b[key]) is str and b[key] == ENVELOPE_ADDITION_ALLOWLIST[key])
                allowed = allowed or (key in declared and key not in base_keys and
                                      type(b[key]) is type(declared[key]) and
                                      b[key] == declared[key])
                if allowed:
                    diff["allowed_additions"].append(child(path, labels[key]))
                else:
                    record("added", child(path, labels[key]), raw + (key,), b[key])
            for key in sorted(a.keys() - b.keys()):
                record("removed", child(path, labels[key]), raw + (key,), a[key])
            for key in sorted(a.keys() & b.keys()):
                walk(a[key], b[key], child(path, labels[key]), raw + (key,), schema.get(key, {}),
                     "snapshots" if scope == "envelope" and key == "snapshots" else None)
        elif isinstance(a, list):
            for i in range(min(len(a), len(b))):
                walk(a[i], b[i], child(path, i), raw + (i,), schema,
                     "snapshot" if scope == "snapshots" else None)
            for i in range(len(b), len(a)):
                record("removed", child(path, i), raw + (i,), a[i])
            for i in range(len(a), len(b)):
                record("added", child(path, i), raw + (i,), b[i])
        elif a != b:
            record("changed", path, raw, b)

    walk(left, right, "", (), {})
    diff["observed"] = observed
    if signed is not None:
        missing, extra = signed_mismatch(observed, signed)
        # A signed path that did not occur fails too, even with nothing observed.
        diff["signed_missing"] = [entry["path"] for entry in missing]
        if not missing and not extra:
            diff["signed_money"] = observed
            for kind in MONEY_CLASSES:
                diff[kind] = []
    return diff


def has_forbidden_diff(diff):
    return any(diff[kind] for kind in ("added", "removed", "changed", "signed_missing"))


def require_base_scan_fixture(base):
    """Keep the base's scanner adapter: the head's may require newer runtime APIs."""
    fixture = base / "crates/ottto-service/src/snapshots/e2_pipeline_scan_fixture.rs"
    text = fixture.read_text()
    if any(f"fn {name}(" not in text for name in ("scan", "scan_other")) or not any(
            f"fn {name}(" in text for name in ("begin_durable", "begin_pass")):
        raise RuntimeError("base compat: scanner fixture lacks scan/scan_other/begin_durable|begin_pass")


def require_base_harness(base):
    """Each arm runs its own in-tree harness under the same module name."""
    tests = base / "crates/ottto-service/src/snapshot_sync/claude_money_e2_pipeline_tests.rs"
    if "mod money_equivalence_tests" not in tests.read_text():
        raise RuntimeError("base compat: base predates the in-tree money_equivalence_tests harness")


def require_disjoint_head_only():
    """A head-only name is never an existing fixture: a renamed or moved one stays red."""
    head_only = set(HEAD_ONLY_FIXTURES)
    if head_only & NATIVE_FIXTURES or len(head_only) != len(HEAD_ONLY_FIXTURES):
        raise RuntimeError(f"head-only fixtures repeat or overlap native ones: {HEAD_ONLY_FIXTURES}")
    return head_only


def native_coverage(arm, stdout):
    """The arm's expected native fixtures; fail closed on any missing or extra line."""
    verified = re.findall(r"\bMONEY_EQUIVALENCE (\w+) VERIFIED ", stdout, re.M)
    head_only = require_disjoint_head_only()
    # The head must emit every head-only fixture; the base may omit them.
    expected = NATIVE_FIXTURES | (head_only & set(verified) if arm == "base" else head_only)
    if len(verified) != len(expected) or set(verified) != expected or "UNEXECUTED" in stdout:
        raise RuntimeError(f"incomplete native coverage: {verified}")
    # Every disk line must be VERIFIED, once per fixture.
    disk = re.findall(r"\bMONEY_EQUIVALENCE_DISK (\w+) (\w+)", stdout, re.M)
    optional = BASE_ONLY_DISK_FIXTURES if arm == "base" else ()
    if any(status != "VERIFIED" for _, status in disk) or len(disk) != len(set(disk)):
        raise RuntimeError(f"incomplete disk-restore coverage: {disk}")
    disk = [(name, status) for name, status in disk if name not in optional]
    if sorted(disk) != sorted((name, "VERIFIED") for name in DISK_FIXTURES):
        raise RuntimeError(f"incomplete disk-restore coverage: {disk}")
    if len(verified) + len(disk) != len(expected) + len(DISK_FIXTURES):
        raise RuntimeError(f"expected {len(expected)} + {len(DISK_FIXTURES)} receipts")
    return expected


def receipt_names(left, right, head_expected, base_expected=None):
    """(compared, uncompared) receipt names. Each arm's receipts are exactly its
    VERIFIED fixtures (base_expected defaults to head_expected); base must be a
    subset of head, and only a head-only fixture absent on base is uncompared."""
    def listed(directory):
        return {p.name for p in directory.glob("*.json") if not p.name.endswith(".cross-build.json")}

    def files(expected):
        return {f"{name}.json" for name in expected}
    base, head = listed(left), listed(right)
    base_expected = head_expected if base_expected is None else base_expected
    if (base != files(base_expected) or head != files(head_expected) or not base <= head
            or not head - base <= files(HEAD_ONLY_FIXTURES)):
        raise RuntimeError("missing or extra fixture receipts")
    return sorted(base & head), sorted(head - base)


def require_saved_digests(directory, name):
    cross_name = Path(name).with_suffix(".cross-build.json")
    for body_name in (Path(name), cross_name):
        data = (directory / body_name).read_bytes()
        digest = directory / body_name.with_suffix(".sha256")
        if digest.read_text() != hashlib.sha256(data).hexdigest():
            raise RuntimeError(f"invalid saved digest: {directory}/{body_name}")


def uncompared_receipts(right, uncompared, signed_lists):
    """({name: head receipt digests}, failures) for head-only fixtures absent on
    base. Nothing is compared, so a non-empty signed diff can never match."""
    records, failures = {}, []
    for name in uncompared:
        require_saved_digests(right, name)
        cross_name = Path(name).with_suffix(".cross-build.json")
        records[name] = {"head_sha256": (right / Path(name).with_suffix(".sha256")).read_text(),
                         "head_cross_build_sha256": (right / cross_name.with_suffix(".sha256")).read_text()}
        print(f"MONEY_EQUIVALENCE_UNCOMPARED {name} absent on base; head VERIFIED "
              f"sha256={records[name]['head_sha256']} "
              f"cross_build_sha256={records[name]['head_cross_build_sha256']}", flush=True)
        signed = None if signed_lists is None else signed_lists[name]
        if signed:
            missing, extra = signed_mismatch([], signed)
            print(f"MONEY_EQUIVALENCE_SIGNED {name} MISMATCH missing={json.dumps(missing)} "
                  f"extra={json.dumps(extra)}", flush=True)
            failures.append(name)
    return records, failures


def verified_summary(names, uncompared, base_sha, head_sha, seconds):
    # PR line: money_eq <id> empty on <n> compared | <k> new fixtures uncompared.
    head_only = (f"{len(names)} compared | {len(uncompared)} new fixtures uncompared "
                 f"(absent on base): {', '.join(uncompared)}. " if uncompared else "")
    return (f"Money equivalence VERIFIED: {len(names)} + {len(DISK_FIXTURES)} disk-restore fixtures, "
            f"base `{base_sha}`, head `{head_sha}`. {head_only}"
            f"{seconds:.1f}s. Family vector/Pi remain ignored.\n")


def main():
    started = time.monotonic()
    repo = Path.cwd()
    root = Path(os.environ["RUNNER_TEMP"]) / "money-equivalence"
    receipts = root / "receipts"
    receipts.mkdir(parents=True)
    ref = os.environ.get("MONEY_EQUIVALENCE_BASE", "").strip()
    explicit = bool(ref)
    prs = []
    if not ref:
        # workflow_dispatch has no pull_request payload. Resolve the branch's
        # unique open PR base; never assume its base is the candidate branch.
        prs = json.loads(output(["gh", "pr", "list", "--head", os.environ["GITHUB_REF_NAME"],
                                "--json", "number,baseRefName,body"]))
        bases = {pr["baseRefName"] for pr in prs}
        if len(bases) > 1:
            raise RuntimeError("ambiguous PR base: supply money_equivalence_base")
        ref = "origin/" + (next(iter(bases)) if bases else "main")
    if ref.startswith("-"):
        raise RuntimeError("comparison ref cannot be a git option")
    resolved = subprocess.run(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if resolved.returncode:
        # Also accept ordinary branch names and explicit pull-request refs.
        command(["git", "fetch", "--no-tags", "origin", ref])
        base_sha = output(["git", "rev-parse", "FETCH_HEAD^{commit}"])
    else:
        base_sha = resolved.stdout.strip()
    if not explicit:
        # Compare against the branch's fork point, not the base tip: later
        # base changes are not this branch's.
        base_sha = output(["git", "merge-base", base_sha, "HEAD"])
    head_sha = output(["git", "rev-parse", "HEAD"])
    require_disjoint_head_only()
    # Declarations come from the public PR body, so the receipt records them.
    pr_number, declarations = pr_declarations(prs, explicit)
    declared_text, declared_sha = canonical_declarations(declarations)
    print(f"MONEY_EQUIVALENCE_DECLARATIONS {declared_sha or 'none'} {declared_text or 'none'}",
          flush=True)
    money = (declarations or {}).get("money")
    _, money_sha = canonical_declarations(money)
    manifest = {"base": base_sha, "head": head_sha, "base_ref": ref, "pr": pr_number,
                "declarations": declared_text,
                "money_signed_by": money and money["signed_by"],
                "money_signed_head": money and money["head"],
                "money_signed_sha256": money_sha,
                "arms": ["retained_ram_tail_or_unchanged", "cold_full", "disk_restore"],
                "disk_restore": "EXECUTED: " + ", ".join(DISK_FIXTURES)}
    if declared_sha:
        manifest["declarations_sha256"] = declared_sha
    (receipts / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    declared_keys = sorted(f"{part}.{key}" for part in ("envelope", "snapshot")
                           for key in (declarations or {}).get(part, {}))
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as f:
        f.write(f"Money equivalence declared additions (PR {pr_number or 'none'}, head `{head_sha}`): "
                f"{', '.join(declared_keys) or 'none'}; sha256 `{declared_sha or 'none'}`; "
                f"`{declared_text or 'none'}`.\n\n")
        if money:
            signed_line = (f"MONEY_EQUIVALENCE_SIGNED_FILE {money_sha} signed_by={money['signed_by']} "
                           f"signed_head={money['head']} built_head={head_sha}")
            print(signed_line, flush=True)
            f.write(f"Money equivalence signed money diff: `{signed_line}` "
                    f"head_matches_signed: {str(money['head'] == head_sha).lower()}.\n\n")
    base = root / "base"
    command(["git", "worktree", "add", "--detach", str(base), base_sha])
    try:
        # Nothing is transplanted: each arm builds its own tree unchanged.
        require_base_scan_fixture(base)
        require_base_harness(base)
        expected = {}
        for arm, tree in [("base", base), ("head", repo)]:
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / f"{arm}-target"),
                       OTTTO_MONEY_EQUIVALENCE_ROOT=str(root / "inputs"),
                       OTTTO_MONEY_EQUIVALENCE_OUTPUT=str(receipts / arm))
            build = receipts / f"{arm}-build.jsonl"
            with build.open("w") as log:
                command(["cargo", "test", "-p", "ottto-service", "--lib", "--locked",
                         "--no-run", "--message-format=json"], cwd=tree, env=env, stdout=log)
            bins = [r["executable"] for r in map(json.loads, build.read_text().splitlines())
                    if r.get("reason") == "compiler-artifact" and r.get("executable")]
            if len(bins) != 1:
                raise RuntimeError(f"expected one test binary: {bins}")
            # Native tests must emit a VERIFIED receipt each; an unsupported
            # layout's explicit UNEXECUTED line (layout_supported() false, e.g.
            # an unpinned toolchain) or a zero-match test result cannot pass.
            result = subprocess.run([bins[0], "money_equivalence_tests::", "--nocapture",
                              "--test-threads=1"], cwd=tree, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(result.stdout, flush=True)
            (receipts / f"{arm}.log").write_text(result.stdout)
            result.check_returncode()
            expected[arm] = native_coverage(arm, result.stdout)
        left, right = receipts / "base", receipts / "head"
        names, uncompared = receipt_names(left, right, expected["head"], expected["base"])
        signed_lists = signed_money_lists(declarations, names + uncompared)
        uncompared_records, signed_uncompared = uncompared_receipts(right, uncompared, signed_lists)
        failures = []
        for name in names:
            inputs = Path(name).with_suffix(".inputs")
            if (left / inputs).read_bytes() != (right / inputs).read_bytes():
                raise RuntimeError(f"synthetic inputs differ across base/head: {inputs}")
            # Raw bodies/digests remain artifact evidence. Only the separately
            # guarded physical-identity exclusion is compared across builds.
            cross_name = Path(name).with_suffix(".cross-build.json")
            for directory in (left, right):
                require_saved_digests(directory, name)
            signed = None if signed_lists is None else signed_lists[name]
            diff = receipt_diff((left / cross_name).read_bytes(),
                                (right / cross_name).read_bytes(), declarations, signed)
            # Paths, classes and value digests only: the review signs these lines.
            observed = diff.pop("observed")
            if observed:
                print(f"MONEY_EQUIVALENCE_OBSERVED {name} " + json.dumps(observed), flush=True)
            if signed is not None:
                missing, extra = signed_mismatch(observed, signed)
                print(f"MONEY_EQUIVALENCE_SIGNED {name} " + (
                    "MATCH" if not missing and not extra else
                    f"MISMATCH missing={json.dumps(missing)} extra={json.dumps(extra)}"), flush=True)
            print(f"MONEY_EQUIVALENCE_DIFF {name} " + json.dumps(diff, sort_keys=True), flush=True)
            if has_forbidden_diff(diff):
                failures.append(name)
        errors = []
        if failures:
            errors.append("base/head decoded cross-build bodies differ: " + ", ".join(failures))
        if signed_uncompared:
            errors.append("signed money diff on uncompared head-only fixtures (absent on base, "
                          "nothing to match): " + ", ".join(signed_uncompared))
        if errors:
            raise RuntimeError("; ".join(errors))
        manifest.update(verdict="VERIFIED", fixtures=names, disk_fixtures=list(DISK_FIXTURES),
                        runtime_seconds=time.monotonic()-started)
        if uncompared:
            manifest["uncompared_head_only"] = uncompared_records
        print(f"MONEY_EQUIVALENCE_COUNTS compared={len(names)} uncompared={len(uncompared)}", flush=True)
        (receipts / "summary.json").write_text(json.dumps(manifest, indent=2) + "\n")
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary.open("a") as f:
            f.write(verified_summary(names, uncompared, base_sha, head_sha, manifest["runtime_seconds"]))
    finally:
        command(["git", "worktree", "remove", "--force", str(base)])


if __name__ == "__main__":
    main()
