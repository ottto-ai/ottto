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
    base_sha = output(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"])
    head_sha = output(["git", "rev-parse", "HEAD"])
    manifest = {"base": base_sha, "head": head_sha, "base_ref": ref,
                "arms": ["retained_ram_tail_or_unchanged", "cold_full"],
                "disk_restore": "UNEXECUTED: E1/#806 not on main"}
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
            result = command([bins[0], "money_equivalence_tests::", "--nocapture",
                              "--test-threads=1"], cwd=tree, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, flush=True)
            (receipts / f"{arm}.log").write_text(result.stdout)
            verified = re.findall(r"^MONEY_EQUIVALENCE (\w+) VERIFIED ", result.stdout, re.M)
            if len(verified) != 10 or len(set(verified)) != 10 or "UNEXECUTED" in result.stdout:
                raise RuntimeError(f"incomplete native coverage: {verified}")
        left, right = receipts / "base", receipts / "head"
        names = sorted(p.name for p in left.glob("*.json"))
        if len(names) != 10 or names != sorted(p.name for p in right.glob("*.json")):
            raise RuntimeError("missing or extra fixture receipts")
        for name in names:
            a, b = (left / name).read_bytes(), (right / name).read_bytes()
            if a != b or hashlib.sha256(a).digest() != hashlib.sha256(b).digest():
                raise RuntimeError(f"base/head emitted bytes or digest differ: {name}")
            for directory, data in [(left, a), (right, b)]:
                if (directory / Path(name).with_suffix(".sha256")).read_text() != hashlib.sha256(data).hexdigest():
                    raise RuntimeError(f"invalid saved digest: {directory}/{name}")
        manifest.update(verdict="VERIFIED", fixtures=names, runtime_seconds=time.monotonic()-started)
        (receipts / "summary.json").write_text(json.dumps(manifest, indent=2) + "\n")
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary.open("a") as f:
            f.write(f"Money equivalence VERIFIED: {len(names)} fixtures, base `{base_sha}`, head `{head_sha}`. "
                    f"{manifest['runtime_seconds']:.1f}s. Disk restore/family vector/Pi remain ignored.\n")
    finally:
        command(["git", "worktree", "remove", "--force", str(base)])


if __name__ == "__main__":
    main()
