#!/usr/bin/env python3
"""Dispatch-only emitted-body equality gate. Never reads provider/user state."""
import hashlib
import json
import os
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
PI_DURABLE_EXPECTED = True
# Flip to True once the comparison base contains Pi-a (the release after Pi-a, or Pi-b2).
PI_RAM_IN_BASE = False

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
        helpers = Path("crates/ottto-service/src/snapshots/e2_pipeline_scan_fixture.rs")
        shutil.copy2(repo / helpers, base / helpers)
        shutil.copy2(repo / sync / "money_equivalence_tests.rs", base / sync / "money_equivalence_tests.rs")
        tests = base / sync / "claude_money_e2_pipeline_tests.rs"
        include = '\nmod money_equivalence_tests { include!("money_equivalence_tests.rs"); }\n'
        if "mod money_equivalence_tests" not in tests.read_text():
            tests.write_text(tests.read_text() + include)
        for arm, tree in [("base", base), ("head", repo)]:
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / f"{arm}-target"),
                       OTTTO_MONEY_EQUIVALENCE_ROOT=str(root / "inputs"),
                       OTTTO_MONEY_EQUIVALENCE_OUTPUT=str(receipts / arm),
                       OTTTO_MONEY_EQUIVALENCE_PI_RAM_EXPECTED="1" if arm == "head" or PI_RAM_IN_BASE else "0")
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
            if len(capabilities) != len(PI_FIXTURES) or {name for name, _ in capabilities} != set(PI_FIXTURES):
                raise RuntimeError(f"incomplete {arm} Pi capability declarations: {capabilities}")
            pi_support = {status for _, status in capabilities}
            allowed_support = ({"SUPPORTED"},) if arm == "head" and PI_DURABLE_EXPECTED else ({"UNSUPPORTED"},)
            if pi_support not in allowed_support:
                raise RuntimeError(f"invalid {arm} Pi capability: {capabilities}")
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
            a, b = (left / cross_name).read_bytes(), (right / cross_name).read_bytes()
            if a != b or hashlib.sha256(a).digest() != hashlib.sha256(b).digest():
                raise RuntimeError(f"base/head cross-build emitted bytes or digest differ: {name}")
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
                    f"Head Pi disk expected: {'VERIFIED' if PI_DURABLE_EXPECTED else 'UNSUPPORTED'}. "
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
