#!/usr/bin/env python3
"""Import one counts-only native calibration receipt into the reviewed baseline.

This never runs the fixture, changes its production revision, or raises a bound
silently. The resulting diff requires normal baseline/code review.
"""
import argparse
import json
from pathlib import Path
import re


def extract(log: str) -> dict:
    marker = "resource_baseline_counts "
    receipts = [line.split(marker, 1)[1] for line in log.splitlines() if marker in line]
    if len(receipts) != 1:
        raise ValueError("exactly one complete calibration receipt required")
    counts = json.loads(receipts[0])
    if not isinstance(counts, dict) or not counts:
        raise ValueError("missing phase observations")
    for phase, row in counts.items():
        if not re.fullmatch(r"[a-z_]+/(claude_code|codex|pi|offpass)/(h[01]|warmup|drain)", phase):
            raise ValueError("unexpected phase")
        if not isinstance(row, dict) or not row:
            raise ValueError("missing counter observations")
        for key, value in row.items():
            if not re.fullmatch(r"[a-zA-Z0-9_ .-]{1,120}", key):
                raise ValueError("unexpected counter")
            if type(value) is not int or not 0 <= value < 2**64:
                raise ValueError("counter must be an observed unsigned integer")
    return counts


def companions(log: str) -> dict:
    patterns = [
        (r"resource_cli_children reuse=true login_starts=(\d+) model_starts=(\d+)",
         ("cli_login_starts", "cli_model_starts")),
        (r"resource_log_replay folded=(\d+) per_event=\d+", ("offpass_folded_log_bytes",)),
        (r"resource_rewalk_replay ordinary=(\d+) replay=\d+", ("ordinary_passes_h0",)),
    ]
    result = {}
    for pattern, keys in patterns:
        matches = list(re.finditer(pattern, log))
        if len(matches) != 1:
            raise ValueError("exactly one native companion observation required")
        result.update(zip(keys, map(int, matches[0].groups())))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path("crates/ottto-service/src/snapshots/resource-baseline.json"))
    parser.add_argument("--production-main", required=True)
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text())
    if not re.fullmatch(r"[0-9a-f]{40}", args.production_main) or baseline["production_main"] != args.production_main:
        raise ValueError("production-main binding mismatch; review a revision change explicitly")
    log = args.log.read_text()
    baseline["counts"] = extract(log)
    baseline["companion_counts"] = companions(log)
    args.baseline.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
    print(f"Imported {len(baseline['counts'])} count phases; baseline changes require review")


if __name__ == "__main__":
    main()
