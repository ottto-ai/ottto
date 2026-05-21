#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
OUTPUT=""
CHECKED_AT=""
MACOS_VERSION=""
ARCH=""
FORCE=0

usage() {
  cat <<'USAGE'
Usage: macos_stable_qa_evidence_template.sh --manifest <release-manifest.json> [options]

Writes a redaction-safe stable clean-machine QA evidence skeleton for the exact
release manifest. The output is intentionally status=not_run; operators must
fill real clean-machine results before macos_stable_closeout_gate.sh can pass.

Options:
  --manifest <path>        Stable release manifest to bind evidence to.
  --output <path|->        Output path. Default: manifest gate evidence_path.
  --checked-at <iso8601>   Evidence timestamp. Default: current UTC time.
  --macos-version <value>  Clean Mac version, for example 15.5. Default: TODO.
  --arch <value>           arm64, x86_64, or universal. Default: TODO.
  --force                  Overwrite an existing output file.
  -h, --help               Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
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

if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing: $MANIFEST" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Required command not found: python3" >&2
  exit 2
fi

python3 - "$MANIFEST" "$OUTPUT" "$CHECKED_AT" "$MACOS_VERSION" "$ARCH" "$FORCE" <<'PY'
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
macos_version = sys.argv[4] or "TODO_RUN_ON_CLEAN_MACOS_AND_FILL_VERSION"
arch = sys.argv[5] or "TODO_arm64_x86_64_or_universal"
force = sys.argv[6] == "1"

CHECKS_BY_OWNER = {
    "homebrew": [
        "formula_syntax",
        "install",
        "service_start",
        "status_json",
        "setup_browser_claim",
        "apps_detect_json",
        "verify_codex_json",
        "doctor_json",
        "fix_codex_json",
        "diagnostics_collect_json",
        "logout_json",
        "update_check",
        "upgrade",
        "uninstall",
        "reinstall",
        "post_reinstall_status_json",
    ],
    "hosted_installer": [
        "wrapper_download",
        "wrapper_checksum",
        "native_gatekeeper",
        "install",
        "app_launch",
        "service_ready",
        "status_json",
        "setup_browser_claim",
        "apps_detect_json",
        "verify_codex_json",
        "doctor_json",
        "fix_codex_json",
        "diagnostics_collect_json",
        "logout_json",
        "update_check",
        "upgrade",
        "uninstall",
        "reinstall",
        "post_reinstall_status_json",
    ],
    "app_bundle": [
        "artifact_checksum",
        "gatekeeper",
        "install",
        "app_launch",
        "service_ready",
        "status_json",
        "setup_browser_claim",
        "apps_detect_json",
        "verify_codex_json",
        "doctor_json",
        "fix_codex_json",
        "diagnostics_collect_json",
        "logout_json",
        "update_check",
        "upgrade",
        "uninstall",
        "reinstall",
        "post_reinstall_status_json",
    ],
}


def die(message: str, code: int = 1) -> None:
    print(f"stable-qa-template: {message}", file=sys.stderr)
    sys.exit(code)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        die(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        die(f"{label} must be a non-empty string")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        die(f"{label} must be a non-empty array")
    strings: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            die(f"{label} contains a non-string value")
        strings.append(item)
    return strings


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
if channel != "stable":
    die(f"expected stable manifest, got channel={channel}")
if min_protocol_version != 11:
    die("manifest.min_protocol_version must be 11")

quality_gates = require_object(manifest.get("quality_gates"), "manifest.quality_gates")
gate = require_object(
    quality_gates.get("stable_clean_machine_qa"),
    "manifest.quality_gates.stable_clean_machine_qa",
)
evidence_path = require_string(
    gate.get("evidence_path"),
    "manifest.quality_gates.stable_clean_machine_qa.evidence_path",
)
supported_owners = sorted(set(require_string_list(
    manifest.get("supported_install_owners"), "manifest.supported_install_owners"
)))
required_owners = sorted(set(require_string_list(
    gate.get("required_install_owners"),
    "manifest.quality_gates.stable_clean_machine_qa.required_install_owners",
)))

unknown_owners = sorted(set(supported_owners).difference(CHECKS_BY_OWNER))
if unknown_owners:
    die(f"unsupported install owner(s): {', '.join(unknown_owners)}")
missing_required = sorted(set(supported_owners).difference(required_owners))
if missing_required:
    die(
        "stable_clean_machine_qa.required_install_owners is missing supported "
        f"owner(s): {', '.join(missing_required)}"
    )

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
    "gate": "stable_clean_machine_qa",
    "status": "not_run",
    "checked_at": checked_at,
    "manifest": {
        "product": product,
        "channel": channel,
        "version": version,
        "commit": commit,
        "sha256": manifest_sha,
    },
    "environment": {
        "host_kind": "clean_macos",
        "macos_version": macos_version,
        "arch": arch,
    },
    "install_owners": [
        {
            "owner": owner,
            "status": "not_run",
            "local_platform": {
                "runtime": "ottto-service",
                "service_label": "net.ottto.service",
                "version": version,
                "release_channel": channel,
                "install_owner": owner,
                "protocol_version": min_protocol_version,
                "release_manifest_sha256": manifest_sha,
            },
            "checks": {check: "not_run" for check in CHECKS_BY_OWNER[owner]},
        }
        for owner in supported_owners
    ],
    "operator_notes": [
        "Fill only redacted pass/fail status facts after running QA on a clean Mac.",
        (
            "Do not paste raw command output, local user paths, private repo paths, "
            "claim codes, setup-run secrets, account identifiers, machine identifiers, "
            "API credentials, or authorization credentials."
        ),
        (
            "Set top-level status, each owner status, and each check to passed only "
            "after that exact check passed for the manifest above."
        ),
    ],
}

if output_arg:
    output_path = None if output_arg == "-" else Path(output_arg).resolve()
else:
    output_path = (manifest_path.parent / evidence_path).resolve()

text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
if output_path is None:
    print(text, end="")
else:
    if output_path.exists() and not force:
        die(f"output already exists, pass --force to overwrite: {output_path}", code=2)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    print(f"stable-qa-template: wrote {output_path}")
PY
