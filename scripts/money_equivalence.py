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


# Diagnostic observations are evidence only; never upload-body exclusions or
# retention failures. Registry names match the replay harness Observation list.
PI_COST_OBSERVATIONS = {
    "pi_cost_refused_overflow": ("pi_cost_refused", "overflow"),
    "pi_cost_precision_rounded": ("pi_cost_precision_rounded",),
}


def pi_cost_observations(log):
    totals = dict.fromkeys(PI_COST_OBSERVATIONS, 0)
    for line in log.splitlines():
        _, marker, payload = line.partition("ottto-service: local_resources ")
        if not marker:
            continue
        record = json.loads(payload)
        if record.get("stage") != "pi_cost_observations":
            continue
        for key, path in PI_COST_OBSERVATIONS.items():
            count = record["counts"]
            for part in path:
                count = count[part]
            if type(count) is not int or count < 0:
                raise RuntimeError(f"invalid Pi observation: {key}")
            totals[key] = max(totals[key], count)
    return totals


# Disk-only lifecycle fixtures (#806): a VERIFIED line each, no receipt file.
DISK_FIXTURES = ("restart_between_pages", "upgrade_without_semantic_revision",
                 "downgrade_then_reupgrade")


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
                "disk_restore": "EXECUTED: " + ", ".join(DISK_FIXTURES),
                "pi_cost_observations": {}}
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
                       OTTTO_MONEY_EQUIVALENCE_OUTPUT=str(receipts / arm))
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
            manifest["pi_cost_observations"][arm] = pi_cost_observations(result.stdout)
            result.check_returncode()
            verified = re.findall(r"\bMONEY_EQUIVALENCE (\w+) VERIFIED ", result.stdout, re.M)
            expected = {
                "progressive_response", "duplicate_request_ids", "resolver_conflict",
                "quiet_sidecar_growth", "side_owner", "side_without_owner",
                "side_owner_directory_unlisted", "failed_then_healthy_telemetry",
                "codex_v2_sticky", "codex_legacy_acked_sticky",
            }
            if len(verified) != len(expected) or set(verified) != expected or "UNEXECUTED" in result.stdout:
                raise RuntimeError(f"incomplete native coverage: {verified}")
            # Every disk line must be VERIFIED, once per fixture: 10 + 3 receipts.
            disk = re.findall(r"\bMONEY_EQUIVALENCE_DISK (\w+) (\w+)", result.stdout, re.M)
            if sorted(disk) != sorted((name, "VERIFIED") for name in DISK_FIXTURES):
                raise RuntimeError(f"incomplete disk-restore coverage: {disk}")
            if len(verified) + len(disk) != len(expected) + len(DISK_FIXTURES):
                raise RuntimeError(f"expected {len(expected)} + {len(DISK_FIXTURES)} receipts")
        left, right = receipts / "base", receipts / "head"
        names = sorted(p.name for p in left.glob("*.json") if not p.name.endswith(".cross-build.json"))
        if len(names) != 10 or names != sorted(p.name for p in right.glob("*.json") if not p.name.endswith(".cross-build.json")):
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
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary.open("a") as f:
            f.write(f"Money equivalence VERIFIED: {len(names)} + {len(DISK_FIXTURES)} disk-restore fixtures, "
                    f"base `{base_sha}`, head `{head_sha}`. "
                    f"{manifest['runtime_seconds']:.1f}s. Family vector/Pi remain ignored.\n")
    finally:
        command(["git", "worktree", "remove", "--force", str(base)])


if __name__ == "__main__":
    main()
