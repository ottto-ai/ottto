#!/usr/bin/env bash
set -euo pipefail

CANDIDATE_MANIFEST=""
OUTPUT=""
CHECKED_AT=""
MACOS_VERSION=""
ARCH=""
FORCE=0

usage() {
  cat <<'USAGE'
Usage: macos_public_rc_evidence_template.sh --candidate-manifest <release-manifest.json> [options]

Writes a redaction-safe stable-candidate RC QA evidence skeleton for an
exact stable-candidate release manifest. Operators must fill real
stable-candidate RC results before macos_public_rc_gate.sh or stable preflight
can pass.

Options:
  --candidate-manifest <path>  Stable-candidate release manifest to bind evidence to.
  --output <path|->          Output path. Default: stable-candidate-rc-qa.json beside the manifest.
  --checked-at <iso8601>     Evidence timestamp. Default: current UTC time.
  --macos-version <value>    macOS version used for stable-candidate RC QA. Default: TODO.
  --arch <value>             arm64, x86_64, or universal. Default: TODO.
  --force                    Overwrite an existing output file.
  -h, --help                 Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --candidate-manifest)
      CANDIDATE_MANIFEST="${2:?--candidate-manifest requires a value}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?--output requires a value}"
      shift 2
      ;;
    --checked-at)
      CHECKED_AT="${2:?--checked-at requires a value}"
      shift 2
      ;;
    --macos-version)
      MACOS_VERSION="${2:?--macos-version requires a value}"
      shift 2
      ;;
    --arch)
      ARCH="${2:?--arch requires a value}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
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

if [[ -z "$CANDIDATE_MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$CANDIDATE_MANIFEST" ]]; then
  echo "Stable-candidate release manifest is missing: $CANDIDATE_MANIFEST" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Required command not found: python3" >&2
  exit 2
fi

python3 - "$CANDIDATE_MANIFEST" "$OUTPUT" "$CHECKED_AT" "$MACOS_VERSION" "$ARCH" "$FORCE" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

manifest_path = Path(sys.argv[1]).resolve()
output_arg = sys.argv[2]
checked_at = sys.argv[3]
macos_version = sys.argv[4] or "TODO_RUN_STABLE_CANDIDATE_RC_QA_AND_FILL_VERSION"
arch = sys.argv[5] or "TODO_arm64_x86_64_or_universal"
force = sys.argv[6] == "1"

CHECKS = [
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


def die(message: str, code: int = 1) -> None:
    print(f"stable-candidate-rc-template: {message}", file=sys.stderr)
    sys.exit(code)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        die(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        die(f"{label} must be a non-empty string")
    return value


try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as error:
    die(f"invalid manifest JSON: {error}")

manifest = require_object(manifest, "manifest")
product = require_string(manifest.get("product"), "manifest.product")
channel = require_string(manifest.get("channel"), "manifest.channel")
version = require_string(manifest.get("version"), "manifest.version")
commit = require_string(manifest.get("commit"), "manifest.commit")
min_protocol_version = manifest.get("min_protocol_version")
if product != "ottto-local-platform":
    die(f"expected product=ottto-local-platform, got {product}")
if channel != "stable-candidate":
    die(f"expected stable-candidate manifest, got channel={channel}")
if min_protocol_version != 11:
    die("manifest.min_protocol_version must be 11")

if arch not in {"arm64", "x86_64", "universal", "TODO_arm64_x86_64_or_universal"}:
    die("--arch must be arm64, x86_64, or universal", code=2)

if not checked_at:
    checked_at = (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
evidence = {
    "schema_version": 1,
    "gate": "stable_candidate_rc",
    "status": "not_run",
    "checked_at": checked_at,
    "candidate_manifest": {
        "product": product,
        "channel": channel,
        "version": version,
        "commit": commit,
        "sha256": manifest_sha,
    },
    "environment": {
        "host_kind": "trusted_internal_macos",
        "macos_version": macos_version,
        "arch": arch,
    },
    "local_platform": {
        "runtime": "ottto-service",
        "service_label": "net.ottto.service",
        "version": version,
        "release_channel": channel,
        "protocol_version": min_protocol_version,
        "release_manifest_sha256": manifest_sha,
    },
    "checks": {check: "not_run" for check in CHECKS},
    "operator_notes": [
        "Fill only redacted pass/fail status facts after running stable-candidate RC QA.",
        (
            "Do not paste raw command output, local user paths, private repo paths, "
            "claim codes, setup-run secrets, account identifiers, machine identifiers, "
            "API credentials, or authorization credentials."
        ),
        (
            "Set top-level status and every check to passed only after the exact "
            "stable-candidate manifest above passed that check."
        ),
    ],
}

if output_arg:
    output_path = None if output_arg == "-" else Path(output_arg).resolve()
else:
    output_path = (manifest_path.parent / "stable-candidate-rc-qa.json").resolve()

text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
if output_path is None:
    print(text, end="")
else:
    if output_path.exists() and not force:
        die(f"output already exists, pass --force to overwrite: {output_path}", code=2)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    print(f"stable-candidate-rc-template: wrote {output_path}")
PY
