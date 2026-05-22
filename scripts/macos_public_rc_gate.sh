#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_GATE="$ROOT/scripts/macos_release_gate.sh"
CANDIDATE_MANIFEST=""
EVIDENCE=""
STABLE_MANIFEST=""

usage() {
  cat <<'USAGE'
Usage: macos_public_rc_gate.sh --candidate-manifest <release-manifest.json> --evidence <stable-candidate-rc-qa.json> [--stable-manifest <release-manifest.json>]

Validates stable-candidate RC evidence before stable public-v1 promotion.
The stable-candidate manifest must pass the release gate, the evidence must be
redacted and fully passed, and an optional stable manifest must point at the
same stable-candidate evidence and commit.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --candidate-manifest)
      CANDIDATE_MANIFEST="${2:?--candidate-manifest requires a value}"
      shift 2
      ;;
    --evidence)
      EVIDENCE="${2:?--evidence requires a value}"
      shift 2
      ;;
    --stable-manifest)
      STABLE_MANIFEST="${2:?--stable-manifest requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$CANDIDATE_MANIFEST" || -z "$EVIDENCE" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$CANDIDATE_MANIFEST" ]]; then
  echo "Stable-candidate release manifest is missing: $CANDIDATE_MANIFEST" >&2
  exit 1
fi
if [[ ! -f "$EVIDENCE" ]]; then
  echo "Stable-candidate RC evidence is missing: $EVIDENCE" >&2
  exit 1
fi
if [[ -n "$STABLE_MANIFEST" && ! -f "$STABLE_MANIFEST" ]]; then
  echo "Stable release manifest is missing: $STABLE_MANIFEST" >&2
  exit 1
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command shasum
require_command python3

"$RELEASE_GATE" --manifest "$CANDIDATE_MANIFEST" >/dev/null

python3 - "$CANDIDATE_MANIFEST" "$EVIDENCE" "$STABLE_MANIFEST" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

candidate_manifest_path = Path(sys.argv[1]).resolve()
evidence_path = Path(sys.argv[2]).resolve()
stable_manifest_path = Path(sys.argv[3]).resolve() if sys.argv[3] else None

REQUIRED_CHECKS = [
    "release_gate",
    "public_surface_ci",
    "candidate_manifest_download",
    "artifact_checksums",
    "artifact_signatures",
    "notarization",
    "gatekeeper_assessment",
    "hosted_candidate_installer",
    "app_launch",
    "service_ready",
    "status_json",
    "setup_browser_claim",
    "verify_codex",
    "diagnostics_redaction",
    "update_check",
    "rollback_notes",
    "stable_formula_static",
    "stable_hosted_installer_static",
]

PRIVATE_REPO_NAME = "coding-agents-" "observability"
SECRET_PATTERN = re.compile(
    r"/Users/|" + re.escape(PRIVATE_REPO_NAME) + r"|docs/dev|\.agents|\.claude|"
    r"Bearer\s+|claim_code|setup_run_token|account_id|machine_id|"
    r"api[_-]?key|password",
    re.IGNORECASE,
)


def die(message: str) -> None:
    print(f"stable-candidate-rc-gate: {message}", file=sys.stderr)
    sys.exit(1)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        die(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        die(f"{label} must be a non-empty string")
    return value


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        die(f"{label} has invalid JSON: {error}")
    return require_object(value, label)


def resolve_reference(base_dir: Path, reference: str) -> Path:
    path = Path(reference)
    if path.is_absolute():
        return path.resolve()
    return (base_dir / path).resolve()


def contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value == "not_run" or value.startswith("TODO")
    if isinstance(value, list):
        return any(contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(contains_placeholder(item) for item in value.values())
    return False


candidate_manifest = load_json(candidate_manifest_path, "stable-candidate manifest")
evidence = load_json(evidence_path, "stable-candidate RC evidence")
candidate_sha = hashlib.sha256(candidate_manifest_path.read_bytes()).hexdigest()

if SECRET_PATTERN.search(evidence_path.read_text(encoding="utf-8")):
    die(f"evidence contains private path or secret-like material: {evidence_path}")
if contains_placeholder(evidence):
    die("evidence still contains template placeholders")

if candidate_manifest.get("product") != "ottto-local-platform":
    die("stable-candidate manifest product must be ottto-local-platform")
if candidate_manifest.get("channel") != "stable-candidate":
    die("stable-candidate manifest channel must be stable-candidate")
candidate_version = require_string(candidate_manifest.get("version"), "stable-candidate manifest version")
candidate_commit = require_string(candidate_manifest.get("commit"), "stable-candidate manifest commit")
if candidate_manifest.get("min_protocol_version") != 11:
    die("stable-candidate manifest min_protocol_version must be 11")
if not re.fullmatch(r"[0-9a-f]{7,40}", candidate_commit):
    die("stable-candidate manifest commit is not a git SHA prefix")

raw_artifacts = candidate_manifest.get("artifacts", [])
if not isinstance(raw_artifacts, list) or not raw_artifacts:
    die("stable-candidate manifest artifacts must be a non-empty array")
macos_artifacts = [
    artifact
    for artifact in raw_artifacts
    if isinstance(artifact, dict) and artifact.get("platform") == "macos"
]
kinds = {artifact.get("kind") for artifact in macos_artifacts}
for required_kind in ("macos_app", "cli", "daemon"):
    if required_kind not in kinds:
        die(f"stable-candidate manifest is missing macOS artifact kind: {required_kind}")
for artifact in macos_artifacts:
    name = require_string(artifact.get("name"), "stable-candidate manifest artifact name")
    if artifact.get("signed") is not True:
        die(f"stable-candidate macOS artifact is not marked signed: {name}")
    if artifact.get("notarized") is not True:
        die(f"stable-candidate macOS artifact is not marked notarized: {name}")
    if artifact.get("gatekeeper_assessed") is not True:
        die(f"stable-candidate macOS artifact is not marked Gatekeeper-assessed: {name}")

candidate_evidence = require_object(evidence.get("candidate_manifest"), "evidence candidate_manifest")
environment = require_object(evidence.get("environment"), "evidence environment")
local_platform = require_object(evidence.get("local_platform"), "evidence local_platform")
checks = require_object(evidence.get("checks"), "evidence checks")

if evidence.get("schema_version") != 1:
    die("evidence schema_version must be 1")
if evidence.get("gate") != "stable_candidate_rc":
    die("evidence gate must be stable_candidate_rc")
if evidence.get("status") != "passed":
    die("stable-candidate RC evidence did not pass")
if candidate_evidence.get("product") != "ottto-local-platform":
    die("evidence product must be ottto-local-platform")
if candidate_evidence.get("channel") != "stable-candidate":
    die("evidence stable-candidate channel must be stable-candidate")
if candidate_evidence.get("version") != candidate_version:
    die("evidence stable-candidate version does not match stable-candidate manifest")
if candidate_evidence.get("commit") != candidate_commit:
    die("evidence stable-candidate commit does not match stable-candidate manifest")
if candidate_evidence.get("sha256") != candidate_sha:
    die("evidence stable-candidate manifest SHA does not match stable-candidate manifest")
if local_platform.get("runtime") != "ottto-service":
    die("evidence local_platform.runtime must be ottto-service")
if local_platform.get("service_label") != "net.ottto.service":
    die("evidence local_platform.service_label must be net.ottto.service")
if local_platform.get("version") != candidate_version:
    die("evidence local_platform.version does not match stable-candidate manifest")
if local_platform.get("release_channel") != "stable-candidate":
    die("evidence local_platform.release_channel must be stable-candidate")
if local_platform.get("protocol_version") != 11:
    die("evidence local_platform.protocol_version must be 11")
if local_platform.get("release_manifest_sha256") != candidate_sha:
    die("evidence local_platform.release_manifest_sha256 does not match stable-candidate manifest")
if environment.get("host_kind") not in {"trusted_internal_macos", "clean_macos"}:
    die("evidence host_kind must be trusted_internal_macos or clean_macos")
if environment.get("arch") not in {"arm64", "x86_64", "universal"}:
    die("evidence arch must be arm64, x86_64, or universal")
require_string(environment.get("macos_version"), "evidence macos_version")

for check in REQUIRED_CHECKS:
    if checks.get(check) != "passed":
        die(f"stable-candidate RC evidence is missing passed check: {check}")

if stable_manifest_path is not None:
    stable_manifest = load_json(stable_manifest_path, "stable manifest")
    if stable_manifest.get("product") != "ottto-local-platform":
        die("stable manifest product must be ottto-local-platform")
    if stable_manifest.get("channel") != "stable":
        die("stable manifest channel must be stable")
    stable_commit = require_string(stable_manifest.get("commit"), "stable manifest commit")
    if stable_manifest.get("min_protocol_version") != 11:
        die("stable manifest min_protocol_version must be 11")
    if stable_commit != candidate_commit:
        die("stable manifest commit must match the stable-candidate RC commit")
    quality_gates = require_object(stable_manifest.get("quality_gates"), "stable quality_gates")
    gate = require_object(
        quality_gates.get("stable_candidate_rc"),
        "stable quality_gates.stable_candidate_rc",
    )
    if gate.get("status") != "passed":
        die("stable_candidate_rc gate did not pass")
    stable_evidence_path = require_string(
        gate.get("evidence_path"),
        "stable_candidate_rc evidence_path",
    )
    if resolve_reference(stable_manifest_path.parent, stable_evidence_path) != evidence_path:
        die("stable_candidate_rc evidence_path does not match the evidence file")
    if gate.get("candidate_manifest_sha256") != candidate_sha:
        die("stable_candidate_rc candidate_manifest_sha256 does not match evidence")

print(f"stable-candidate-rc-gate: passed for {candidate_version} ({candidate_commit})")
PY
