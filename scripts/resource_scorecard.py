#!/usr/bin/env python3
"""Validate redacted sampler-v6 RC aggregates; never trust reported pass flags.

Rates are per hour; energy is battery-only mW; footprint is MiB. Previous
stable evidence is embedded and bound by its canonical JSON SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path

ABSOLUTE = {
    "cpu_seconds_per_hour": 180,
    "energy_mw": 100,
    "writes_gib_per_hour": 0.25,
    "footprint_p50_mib": 150,
    "footprint_peak_mib": 600,
    "seconds_above_500mib_per_hour": 60,
}
METRICS = (*ABSOLUTE, "reads_gib_per_hour", "interrupt_wakeups_per_hour",
           "package_wakeups_per_hour", "log_bytes_per_hour", "children_per_hour",
           "sidecar_reuse_ratio")
MATCH = ("host_class", "os_version", "arch", "power_profile", "workload_class")


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def number(value: object, name: str) -> float:
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name}: missing/nonfinite/negative observation")
    return value


def digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name}: expected SHA-256")
    return value


def text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name}: missing observation")
    return value


def window(card: dict, label: str) -> dict:
    if not isinstance(card, dict) or card.get("sampler_version") != 6:
        raise ValueError(f"{label}: sampler_version must be 6")
    for key in MATCH:
        text(card.get(key), f"{label}.{key}")
    if card["power_profile"] != "battery":
        raise ValueError(f"{label}: two battery hours required")
    for key in ("manifest_sha256", "executable_sha256"):
        digest(card.get(key), f"{label}.{key}")
    started = datetime.fromisoformat(text(card.get("started_at"), label).replace("Z", "+00:00"))
    ended = datetime.fromisoformat(text(card.get("ended_at"), label).replace("Z", "+00:00"))
    if started.utcoffset() is None or ended.utcoffset() is None:
        raise ValueError(f"{label}: timezone required")
    duration = number(card.get("duration_seconds"), label)
    if duration < 7200 or (ended - started).total_seconds() != duration:
        raise ValueError(f"{label}: insufficient/inconsistent duration")
    if number(card.get("battery_seconds"), label) != duration:
        raise ValueError(f"{label}: mixed-power window")
    expected = number(card.get("expected_samples"), label)
    observed = number(card.get("observed_samples"), label)
    if expected != math.ceil(duration) or not 0.99 * expected <= observed <= expected:
        raise ValueError(f"{label}: sampling coverage below 99%")
    if number(card.get("max_gap_seconds"), label) > 2:
        raise ValueError(f"{label}: sample gap exceeds 2 seconds")
    if number(card.get("startup_seconds"), label) < 900:
        raise ValueError(f"{label}: startup exclusion below 15 minutes")
    if (type(card.get("process_instances")) is not int or type(card.get("restart_count")) is not int
            or card["process_instances"] != 1 or card["restart_count"] != 0):
        raise ValueError(f"{label}: restarted/mixed process")
    if card.get("candidate_identity_verified") is not True:
        raise ValueError(f"{label}: candidate PID/start/executable binding absent")
    if card.get("peak_kind") != "interval_max" or card.get("threshold_kind") != "instantaneous":
        raise ValueError(f"{label}: incorrect footprint observations")
    metrics = card.get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != set(METRICS):
        raise ValueError(f"{label}: metric set incomplete")
    for name in METRICS:
        number(metrics[name], f"{label}.{name}")
    if metrics["sidecar_reuse_ratio"] > 1:
        raise ValueError(f"{label}: reuse ratio outside [0,1]")
    if metrics["footprint_peak_mib"] < metrics["footprint_p50_mib"]:
        raise ValueError(f"{label}: peak below median")
    if metrics["seconds_above_500mib_per_hour"] > 3600:
        raise ValueError(f"{label}: impossible threshold duration")
    own = number(card.get("own_cpu_seconds"), label)
    child = number(card.get("child_cpu_seconds"), label)
    if not math.isclose(metrics["cpu_seconds_per_hour"], (own + child) * 3600 / duration,
                        rel_tol=1e-9, abs_tol=1e-9):
        raise ValueError(f"{label}: CPU must include children")
    inputs = card.get("input_counts")
    if not isinstance(inputs, dict) or set(inputs) != {"claude", "codex", "pi"}:
        raise ValueError(f"{label}: missing source input counts")
    for source, counts in inputs.items():
        if not isinstance(counts, dict) or set(counts) != {"files", "appends", "passes"}:
            raise ValueError(f"{label}.{source}: input count set incomplete")
        for key, value in counts.items():
            if type(value) is not int or value < 0:
                raise ValueError(f"{label}.{source}.{key}: invalid count")
        if counts["files"] == 0 or counts["passes"] == 0:
            raise ValueError(f"{label}.{source}: source not exercised")
    return metrics


def validate(scorecard: dict, manifest_sha: str, executable_sha: str) -> dict:
    if not isinstance(scorecard, dict) or scorecard.get("schema_version") != 1:
        raise ValueError("resource_scorecard: schema_version must be 1")
    if scorecard.get("policy") != "resource-stage1-v1":
        raise ValueError("resource_scorecard: unsupported policy")
    current, previous = scorecard.get("candidate"), scorecard.get("previous_stable")
    now, before = window(current, "candidate"), window(previous, "previous_stable")
    if current["manifest_sha256"] != digest(manifest_sha, "candidate manifest"):
        raise ValueError("resource_scorecard: candidate manifest mismatch")
    if current["executable_sha256"] != digest(executable_sha, "installed executable"):
        raise ValueError("resource_scorecard: candidate executable mismatch")
    if scorecard.get("previous_stable_sha256") != canonical_sha(previous):
        raise ValueError("resource_scorecard: previous stable digest mismatch")
    if previous["manifest_sha256"] == current["manifest_sha256"]:
        raise ValueError("resource_scorecard: comparator must be previous stable")
    for field in (*MATCH, "duration_seconds"):
        if current[field] != previous[field]:
            raise ValueError(f"resource_scorecard: comparator {field} mismatch")
    for source in current["input_counts"]:
        for key in ("files", "appends"):
            a, b = current["input_counts"][source][key], previous["input_counts"][source][key]
            if (a != 0 if b == 0 else not 0.8 * b <= a <= 1.2 * b):
                raise ValueError("resource_scorecard: input load mismatch")
    failures = []
    decisions = {}
    for name in METRICS:
        value, base = now[name], before[name]
        bound = ABSOLUTE.get(name)
        if bound is not None and value > bound:
            failures.append(f"{name}: absolute bound exceeded")
        if name == "sidecar_reuse_ratio":
            regressed = value * 1.2 < base
            ratio = base / value if value else (None if base else 1)
        elif base == 0:
            # A zero baseline has no relative denominator. Only an explicit
            # absolute bound permits a nonzero result; otherwise remain at zero.
            regressed = value > (bound if bound is not None else 0)
            ratio = None
        else:
            regressed = value > base * 1.2
            ratio = value / base
        if regressed:
            failures.append(f"{name}: previous stable regression exceeds 20%")
        decisions[name] = {"value": value, "baseline": base, "ratio": ratio,
                           "bound": bound, "passed": not regressed and (bound is None or value <= bound)}
    if failures:
        raise ValueError("resource_scorecard: " + "; ".join(failures))
    return {"status": "passed", "metrics": decisions,
            "reads_alarm": now["reads_gib_per_hour"] > 3}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text())
    try:
        result = validate(evidence.get("resource_scorecard"),
                          evidence["candidate_manifest"]["sha256"],
                          evidence["local_platform"].get("executable_sha256"))
    except (ValueError, KeyError, TypeError, OverflowError) as error:
        parser.exit(1, f"resource-scorecard: {error}\n")
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
