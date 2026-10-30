#!/usr/bin/env python3
"""Find a recent, genuine macOS contract pass for the complete checked-out tree.

This is an optimization, never a reason to bypass missing evidence: any API or
validation error returns reuse=false. No statuses, artifacts, or caches are written.
"""

import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request


MAX_AGE = dt.timedelta(hours=24)
MAC_STEPS = (
    "Checkout",
    "Install validated Rust toolchain",
    "Rust cache",
    "Compiler receipt",
    "macOS-native public surface checks",
    "Rust format",
    "Connector format",
    "Runtime clippy",
    "Connector clippy",
    "Runtime tests",
    "Layout coverage receipt",
    "Synthetic Codex counting peak memory",
    "Connector tests",
    "Connector package tests",
)


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp needs a timezone")
    return parsed


def recent(value, now):
    return dt.timedelta(0) <= now - timestamp(value) <= MAX_AGE


def genuine_mac(job, sha, now):
    """Skipped checks and previous Linux reuse receipts are not test evidence."""
    steps = job.get("steps", [])
    return (
        job.get("name") == "Rust contracts"
        and job.get("head_sha") == sha
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("labels") == ["macos-15"]
        and job.get("runner_group_name") == "GitHub Actions"
        and recent(job["completed_at"], now)
        and all(
            sum(
                step.get("name") == name
                and step.get("status") == "completed"
                and step.get("conclusion") == "success"
                for step in steps
            ) == 1
            for name in MAC_STEPS
        )
    )


def find_receipt(api, repo, run_id, sha, tree, now):
    current = api(f"actions/runs/{run_id}")
    if (
        current["head_sha"] != sha
        or current["event"] != "merge_group"
        or current["path"] != ".github/workflows/ci.yml"
        or current["head_commit"]["tree_id"] != tree
    ):
        return None

    # Bounded discovery: missing an older pass only costs a fresh Mac run.
    # tree_id in run metadata is a cheap index, then the Git commit API verifies it.
    candidates = []
    for event in ("workflow_dispatch", "merge_group"):
        query = urllib.parse.urlencode({"event": event, "per_page": 100})
        runs = api(f"actions/workflows/{current['workflow_id']}/runs?{query}")
        for run in runs["workflow_runs"]:
            if (
                run["id"] != run_id
                and run["event"] == event
                and run["workflow_id"] == current["workflow_id"]
                and run["path"] == ".github/workflows/ci.yml"
                and run["head_repository"]["full_name"] == repo
                and run["status"] == "completed"
                and run["conclusion"] == "success"
                and recent(run["created_at"], now)
                and run["head_commit"]["tree_id"] == tree
            ):
                candidates.append(run)

    for run in sorted(candidates, key=lambda row: row["created_at"], reverse=True)[:3]:
        candidate_sha = run["head_sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
            continue
        commit = api(f"git/commits/{candidate_sha}")
        if commit["sha"] != candidate_sha or commit["tree"]["sha"] != tree:
            continue
        # Pin the attempt: reruns must not mix a run record with another attempt.
        jobs = api(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
        for job in jobs["jobs"]:
            if (
                job["run_id"] == run["id"]
                and job["run_attempt"] == run["run_attempt"]
                and genuine_mac(job, candidate_sha, now)
            ):
                return {"run_id": str(run["id"]), "job_id": str(job["id"]),
                        "sha": candidate_sha, "tree": tree}
    return None


def main():
    receipt = None
    try:
        repo = os.environ["GITHUB_REPOSITORY"]
        sha = os.environ["GITHUB_SHA"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("invalid repository")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("invalid commit")
        tree = subprocess.check_output(
            ["git", "rev-parse", f"{sha}^{{tree}}"], text=True
        ).strip()

        def api(path):
            request = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/{path}",
                headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                         "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28"},
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.load(response)

        receipt = find_receipt(api, repo, int(os.environ["GITHUB_RUN_ID"]), sha,
                               tree, dt.datetime.now(dt.timezone.utc))
    except Exception as error:
        # Do not log API bodies, request headers, or credentials.
        print(f"No reusable macOS proof ({type(error).__name__}); run full contracts.")

    outputs = {"reuse": "false"}
    if receipt:
        outputs.update(receipt, reuse="true")
        print("Verified recent macOS pass: " + json.dumps(receipt, sort_keys=True))
    else:
        print("No exact-tree macOS pass found; run full contracts.")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in outputs.items():
            stream.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
