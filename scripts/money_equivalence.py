#!/usr/bin/env python3
"""Dispatch-only emitted-body equality gate. Never reads provider/user state."""
import hashlib
import json
import os
from decimal import Decimal
from pathlib import Path
import re
import shutil
import subprocess
import time


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def output(args):
    return subprocess.check_output(args, text=True).strip()


# Cap refusals use the shared entry-cap diagnostic; capability and emitted-body
# receipts below remain the durable evidence, independent of cache counters.
# Pi writes cross-build receipts even when the base has no durable Pi store.
PI_FIXTURES = (
    "pi_plain_session", "pi_tool_turn", "pi_compaction", "pi_branch_summary",
    "pi_usage_entry_kinds", "pi_ledger_count_above_one", "pi_ledger_paired_digest",
    "pi_ledger_reused_id", "pi_ledger_reverse_pair", "pi_conflict", "pi_conflict_after_pair",
    "pi_no_response_id", "pi_selector_across_seal", "pi_provider_hour_and_late_time",
    "pi_invalid_cost", "pi_invalid_time", "pi_usage_overflow", "pi_error_zero_requests",
    "pi_cli_fork_preserves_double_count", "pi_version_rewrite_after_tail",
    "pi_restart_between_pages", "pi_upgrade_without_semantic_revision",
    "pi_downgrade_then_reupgrade", "pi_acquisition_metadata_changes",
)
# Existing disk-only lifecycle fixtures keep their strict VERIFIED contract.
DISK_FIXTURES = ("restart_between_pages", "upgrade_without_semantic_revision",
                 "downgrade_then_reupgrade") + PI_FIXTURES


# Only base -> head ADDITIONS at the batch envelope may be ignored. Never
# allowlist money or identity fields (including usage, cost, bucket, refusal or
# request fields). This is a capability declaration, not snapshot content.
# Additions must also match the exact string values below.
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
# Wire records: snapshots.rs::{SnapshotModelUsage, SnapshotIdentityPart,
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


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite JSON number")


def _load_json(data, path):
    try:
        # Exact decimals avoid hiding cost changes through float rounding.
        return json.loads(data, parse_float=Decimal, parse_constant=_reject_constant,
                          object_pairs_hook=_json_object)
    except (ValueError, UnicodeDecodeError):
        # Errors, like diffs, must never print body values.
        raise ValueError(f"invalid JSON at {path or '/'}") from None


def decode_receipt(data):
    """Unwrap receipt Vec<Vec<u8>> and Claude's extra encoded-batch layer.

    Return the decoded tree and the exact paths of its batch envelopes. Never
    recursively decode payload arrays: they are content, even if byte-shaped.
    An empty page stays an empty list, distinct from any emitted envelope.
    """
    receipt = _load_json(data, "")
    if not isinstance(receipt, list) or not receipt:
        raise ValueError("expected nonempty receipt array at /")

    def body(value, path):
        if not isinstance(value, list) or not value or any(
                type(byte) is not int or not 0 <= byte <= 255 for byte in value):
            raise ValueError(f"expected encoded body at {path}")
        return _load_json(bytes(value), path)

    decoded, envelopes = [], set()
    for i, encoded in enumerate(receipt):
        path = f"/{i}"
        value = body(encoded, path)
        if isinstance(value, dict):
            envelopes.add(path)
        elif isinstance(value, list):
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


def receipt_diff(base, head):
    """Structural paths only; order and JSON scalar types remain significant."""
    left, left_envelopes = decode_receipt(base)
    right, right_envelopes = decode_receipt(head)
    envelopes = left_envelopes & right_envelopes
    display_envelopes = left_envelopes | right_envelopes
    diff = {kind: [] for kind in ("added", "removed", "changed", "allowed_additions")}

    def child(path, key):
        # RFC 6901 JSON Pointer escaping keeps paths unambiguous.
        return path + "/" + str(key).replace("~", "~0").replace("/", "~1")

    def walk(a, b, path, schema):
        if path in display_envelopes:
            schema = _ENVELOPE_DIFF_SCHEMA
        if type(a) is not type(b):
            diff["changed"].append(path)
        elif isinstance(a, dict):
            # Stable ordinals use the sorted base/head union, independently of
            # insertion order or which side owns a key. Never print raw data keys.
            labels = {key: key if key in schema else f"<key#{i}>"
                      for i, key in enumerate(sorted(a.keys() | b.keys()))}
            for key in sorted(b.keys() - a.keys()):
                kind = ("allowed_additions" if path in envelopes and
                        key in ENVELOPE_ADDITION_ALLOWLIST and
                        type(b[key]) is str and
                        b[key] == ENVELOPE_ADDITION_ALLOWLIST[key] else "added")
                diff[kind].append(child(path, labels[key]))
            for key in sorted(a.keys() - b.keys()):
                diff["removed"].append(child(path, labels[key]))
            for key in sorted(a.keys() & b.keys()):
                walk(a[key], b[key], child(path, labels[key]), schema.get(key, {}))
        elif isinstance(a, list):
            for i in range(min(len(a), len(b))):
                walk(a[i], b[i], child(path, i), schema)
            diff["removed"].extend(child(path, i) for i in range(len(b), len(a)))
            diff["added"].extend(child(path, i) for i in range(len(a), len(b)))
        elif a != b:
            diff["changed"].append(path)

    walk(left, right, "", {})
    return diff


def has_forbidden_diff(diff):
    return any(diff[kind] for kind in ("added", "removed", "changed"))


def check_pi_capability(arm, capabilities):
    """Every Pi fixture declares one capability. Head restores Pi durably; the
    base reports either, uniformly, so a base that predates or contains durable
    Pi both compare."""
    if len(capabilities) != len(PI_FIXTURES) or {name for name, _ in capabilities} != set(PI_FIXTURES):
        raise RuntimeError(f"incomplete {arm} Pi capability declarations: {capabilities}")
    allowed = ({"SUPPORTED"},) if arm == "head" else ({"SUPPORTED"}, {"UNSUPPORTED"})
    if {status for _, status in capabilities} not in allowed:
        raise RuntimeError(f"invalid {arm} Pi capability: {capabilities}")


def require_base_scan_fixture(base):
    """Keep the base's scanner adapter: the head's may require newer runtime APIs."""
    fixture = base / "crates/ottto-service/src/snapshots/e2_pipeline_scan_fixture.rs"
    text = fixture.read_text()
    if any(f"fn {name}(" not in text for name in ("scan", "scan_other", "begin_durable")):
        raise RuntimeError("base compat: scanner fixture lacks scan/scan_other/begin_durable")


def main():
    started = time.monotonic()
    repo = Path.cwd()
    root = Path(os.environ["RUNNER_TEMP"]) / "money-equivalence"
    receipts = root / "receipts"
    receipts.mkdir(parents=True)
    ref = os.environ.get("MONEY_EQUIVALENCE_BASE", "").strip()
    if not ref:
        # workflow_dispatch has no pull_request payload. Resolve the branch's
        # unique open PR base; never assume its base is the candidate branch.
        prs = json.loads(output(["gh", "pr", "list", "--head", os.environ["GITHUB_REF_NAME"],
                                "--json", "baseRefName"]))
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
    head_sha = output(["git", "rev-parse", "HEAD"])
    manifest = {"base": base_sha, "head": head_sha, "base_ref": ref,
                "arms": ["retained_ram_tail_or_unchanged", "cold_full", "disk_restore"],
                "disk_restore": {}, "pi_durable_capability": {}, "receipt_counts": {},
                # Content-free dispositions are diagnostic observations, not failures
                # or part of the emitted-body equality comparison.
                "diagnostic_observations": {"restored_behind_accepted": ["held", "published"]}}
    (receipts / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    base = root / "base"
    command(["git", "worktree", "add", "--detach", str(base), base_sha])
    try:
        # Only test code is transplanted. No P2a/runtime/limits/lockfile changes.
        sync = Path("crates/ottto-service/src/snapshot_sync")
        require_base_scan_fixture(base)
        shutil.copy2(repo / sync / "money_equivalence_tests.rs", base / sync / "money_equivalence_tests.rs")
        # Bases before #870 have no audit-retirement reconcile: their post-save
        # step is durable_after_save alone. Call the base's own production step.
        snapshots = (base / "crates/ottto-service/src/snapshots.rs").read_text()
        if "fn durable_after_save_and_retire(" not in snapshots:
            transplanted = base / sync / "money_equivalence_tests.rs"
            text = transplanted.read_text()
            head_call = ("crate::snapshots::durable_after_save_and_retire(\n"
                         "            cache,\n"
                         "            &self.dir,\n"
                         "            source,\n"
                         "            index,\n"
                         "            &self.index,\n"
                         "        );")
            if text.count(head_call) != 1:
                raise RuntimeError("base compat: expected exactly one durable_after_save_and_retire call")
            transplanted.write_text(text.replace(
                head_call, "crate::snapshots::durable_after_save(cache, &self.dir, source, index);"))
        tests = base / sync / "claude_money_e2_pipeline_tests.rs"
        include = '\nmod money_equivalence_tests { include!("money_equivalence_tests.rs"); }\n'
        if "mod money_equivalence_tests" not in tests.read_text():
            tests.write_text(tests.read_text() + include)
        for arm, tree in [("base", base), ("head", repo)]:
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / f"{arm}-target"),
                       OTTTO_MONEY_EQUIVALENCE_ROOT=str(root / "inputs"),
                       OTTTO_MONEY_EQUIVALENCE_OUTPUT=str(receipts / arm),
                       # The base's own build decides whether it samples Pi.
                       OTTTO_MONEY_EQUIVALENCE_PI_RAM_EXPECTED="1" if arm == "head" else "any")
            build = receipts / f"{arm}-build.jsonl"
            with build.open("w") as log:
                command(["cargo", "test", "-p", "ottto-service", "--lib", "--locked",
                         "--no-run", "--message-format=json"], cwd=tree, env=env, stdout=log)
            bins = [r["executable"] for r in map(json.loads, build.read_text().splitlines())
                    if r.get("reason") == "compiler-artifact" and r.get("executable")]
            if len(bins) != 1:
                raise RuntimeError(f"expected one test binary: {bins}")
            # Native tests must emit a VERIFIED receipt each; Linux's explicit
            # UNEXECUTED line or a zero-match test result cannot pass this job.
            result = subprocess.run([bins[0], "money_equivalence_tests::", "--nocapture",
                              "--test-threads=1"], cwd=tree, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(result.stdout, flush=True)
            (receipts / f"{arm}.log").write_text(result.stdout)
            verified = re.findall(r"\bMONEY_EQUIVALENCE (\w+) VERIFIED ", result.stdout, re.M)
            expected = {
                "progressive_response", "duplicate_request_ids", "resolver_conflict",
                "quiet_sidecar_growth", "side_owner", "side_without_owner",
                "side_owner_directory_unlisted", "failed_then_healthy_telemetry",
                "codex_v2_sticky", "codex_legacy_acked_sticky",
            } | set(PI_FIXTURES)
            disk = re.findall(r"\bMONEY_EQUIVALENCE_DISK (\w+) (\w+)", result.stdout, re.M)
            capabilities = re.findall(r"\bMONEY_EQUIVALENCE_PI_CAPABILITY (\w+) (\w+)",
                                      result.stdout, re.M)
            pi_capability = dict(capabilities)
            manifest["pi_durable_capability"][arm] = pi_capability
            manifest["disk_restore"][arm] = dict(disk)
            manifest["receipt_counts"][arm] = {
                "build_sha": base_sha if arm == "base" else head_sha,
                "cross_build": {"existing": sum(name not in PI_FIXTURES for name in verified),
                                "pi": sum(name in PI_FIXTURES for name in verified),
                                "total": len(verified), "expected": len(expected)},
                "disk": {"existing": sum(name not in PI_FIXTURES for name, _ in disk),
                         "pi": sum(name in PI_FIXTURES for name, _ in disk),
                         "total": len(disk), "expected": len(DISK_FIXTURES)},
            }
            (receipts / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            result.check_returncode()
            if len(verified) != len(expected) or set(verified) != expected or "UNEXECUTED" in result.stdout:
                raise RuntimeError(f"incomplete native coverage: {verified}")
            check_pi_capability(arm, capabilities)
            expected_disk = [(name, "UNSUPPORTED" if name in PI_FIXTURES
                              and pi_capability[name] == "UNSUPPORTED" else "VERIFIED")
                             for name in DISK_FIXTURES]
            if sorted(disk) != sorted(expected_disk):
                raise RuntimeError(f"invalid {arm} disk-restore coverage: {disk}")
            if len(verified) + len(disk) != len(expected) + len(DISK_FIXTURES):
                raise RuntimeError(f"expected {len(expected)} + {len(DISK_FIXTURES)} receipts")
        left, right = receipts / "base", receipts / "head"
        names = sorted(p.name for p in left.glob("*.json") if not p.name.endswith(".cross-build.json"))
        if names != sorted(name + ".json" for name in expected) or names != sorted(
            p.name for p in right.glob("*.json") if not p.name.endswith(".cross-build.json")
        ):
            raise RuntimeError("missing or extra fixture receipts")
        failures = []
        for name in names:
            inputs = Path(name).with_suffix(".inputs")
            if (left / inputs).read_bytes() != (right / inputs).read_bytes():
                raise RuntimeError(f"synthetic inputs differ across base/head: {inputs}")
            # Raw bodies/digests remain artifact evidence. Only the separately
            # guarded physical-identity exclusion is compared across builds.
            cross_name = Path(name).with_suffix(".cross-build.json")
            for directory in (left, right):
                for body_name in (Path(name), cross_name):
                    data = (directory / body_name).read_bytes()
                    digest = directory / body_name.with_suffix(".sha256")
                    if digest.read_text() != hashlib.sha256(data).hexdigest():
                        raise RuntimeError(f"invalid saved digest: {directory}/{body_name}")
            diff = receipt_diff((left / cross_name).read_bytes(),
                                (right / cross_name).read_bytes())
            print(f"MONEY_EQUIVALENCE_DIFF {name} " + json.dumps(diff, sort_keys=True), flush=True)
            if has_forbidden_diff(diff):
                failures.append(name)
        if failures:
            raise RuntimeError("base/head decoded cross-build bodies differ: " + ", ".join(failures))
        manifest.update(verdict="VERIFIED", fixtures=names, disk_fixtures=list(DISK_FIXTURES),
                        runtime_seconds=time.monotonic()-started)
        (receipts / "summary.json").write_text(json.dumps(manifest, indent=2) + "\n")
        unsupported = [name for name, status in manifest["disk_restore"]["base"].items()
                       if status == "UNSUPPORTED"]
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary.open("a") as f:
            f.write(f"Money equivalence VERIFIED: {len(names)} + {len(DISK_FIXTURES)} disk-restore fixtures, "
                    f"base `{base_sha}`, head `{head_sha}`. "
                    f"{manifest['runtime_seconds']:.1f}s. "
                    f"Base Pi disk UNSUPPORTED: {', '.join(sorted(unsupported)) or 'none'}; "
                    f"Head Pi disk expected: VERIFIED. "
                    f"Family vector remains ignored.\n")
            counts = {kind: ", ".join(f"{arm} " + "/".join(str(manifest["receipt_counts"][arm][kind][k])
                                                            for k in ("existing", "pi", "total"))
                                      for arm in ("base", "head"))
                      for kind in ("cross_build", "disk")}
            f.write(f"Receipts existing/pi/total: {counts['cross_build']}; disk {counts['disk']}.\n")
    finally:
        command(["git", "worktree", "remove", "--force", str(base)])


if __name__ == "__main__":
    main()
