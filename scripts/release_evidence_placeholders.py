"""Shared placeholder policy for release evidence gates."""
from __future__ import annotations

from typing import Any


def contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value == "not_run" or value.startswith("TODO")
    if isinstance(value, list):
        return any(contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(contains_placeholder(item) for item in value.values())
    return False


def strip_optional_not_run(evidence: dict[str, Any]) -> dict[str, Any]:
    """Copy evidence, omitting only the template's optional resource defaults."""
    result = dict(evidence)
    if evidence.get("resource_scorecard") == {
        "schema_version": 1, "policy": "resource-stage1-v1", "status": "not_run"
    }:
        result.pop("resource_scorecard")
    if isinstance(evidence.get("checks"), dict):
        result["checks"] = {
            key: value for key, value in evidence["checks"].items()
            if not (key == "resource_soak" and value == "not_run")
        }
    return result
