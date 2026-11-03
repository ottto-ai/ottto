#!/usr/bin/env python3
"""List tests that passed only on retry at least --threshold times in --days.

`ci_runtime_tests.py --retry-failed` lets a test that failed, then passed alone
on retry, pass the step, and writes it to flaky-tests.json; the Mac and Linux
test jobs upload that file as a `flaky-tests-*` artifact only when a test was
flaky. This counts those artifacts. A listed test needs an issue for its owner:
a retry keeps the merge moving, it does not fix the test.

Exit 0 when no test reached the threshold, 3 when one did, 2 on a gh error.
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import subprocess
import sys
import zipfile

PREFIX = "flaky-tests-"


def gh(args: list[str]) -> bytes:
    return subprocess.run(["gh", "api", *args], check=True, stdout=subprocess.PIPE).stdout


def recent_artifacts(repo: str, since: datetime.datetime) -> list[dict]:
    """Unexpired flaky-tests-* artifacts created after `since`, newest first."""
    found = []
    for page in range(1, 51):
        listing = json.loads(gh([f"repos/{repo}/actions/artifacts?per_page=100&page={page}"]))
        artifacts = listing.get("artifacts", [])
        for artifact in artifacts:
            created = datetime.datetime.fromisoformat(artifact["created_at"].replace("Z", "+00:00"))
            if created < since:
                return found
            if artifact["name"].startswith(PREFIX) and not artifact.get("expired"):
                found.append(artifact)
        if len(artifacts) < 100:
            break
    return found


def records_of(zipped: bytes) -> list[dict]:
    with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
        return [json.loads(archive.read(name)) for name in archive.namelist() if name.endswith(".json")]


def tally(records: list[dict]) -> dict[str, int]:
    """Per test: how many distinct job runs reported it flaky."""
    seen: dict[str, set[tuple]] = {}
    for record in records:
        where = (record.get("run_id"), record.get("run_attempt"), record.get("job"), record.get("shard"))
        for entry in record.get("flaky", []):
            seen.setdefault(entry["test"], set()).add(where)
    return {test: len(runs) for test, runs in seen.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--days", type=float, default=7)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--annotate", action="store_true", help="also print GitHub warning annotations")
    args = parser.parse_args()
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=args.days)
    try:
        records = [record for artifact in recent_artifacts(args.repo, since)
                   for record in records_of(gh([f"repos/{args.repo}/actions/artifacts/{artifact['id']}/zip"]))]
    except (subprocess.CalledProcessError, zipfile.BadZipFile, ValueError) as error:
        print(f"flaky_tests: {error}", file=sys.stderr)
        return 2
    counts = tally(records)
    over = sorted((test for test, n in counts.items() if n >= args.threshold), key=lambda t: (-counts[t], t))
    print(f"flaky_tests: {len(records)} report(s), {len(counts)} flaky test(s) in {args.days:g} days")
    for test in sorted(counts, key=lambda t: (-counts[t], t)):
        print(f"{counts[test]:3d}  {test}{'  <- needs an owner issue' if test in over else ''}")
        if args.annotate and test in over:
            print(f"::warning title=Repeatedly flaky test::{test} passed only on retry {counts[test]} times "
                  f"in {args.days:g} days; open an issue for its owner")
    return 3 if over else 0


if __name__ == "__main__":
    sys.exit(main())
