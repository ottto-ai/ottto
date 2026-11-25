#!/usr/bin/env bash
set -euo pipefail

RECORD=""
MANIFEST=""
FORCE=0

usage() {
  cat <<'USAGE'
Usage: macos_stable_qa_summary.sh --record <qa-record.json> --manifest <release-manifest.json> [--force]

Writes the public stable clean-machine QA summary from the private QA record
that macos_stable_qa_evidence_template.sh created. Only allowlisted fields are
copied: operator notes, per-check notes and any other record field are dropped.
The summary is written beside the manifest under the file name the manifest's
stable_clean_machine_qa.evidence_path gives. Run macos_stable_closeout_gate.sh
on the manifest afterwards.

Options:
  --record <path>      Private QA record. Must be outside the manifest's folder.
  --manifest <path>    Stable release manifest the record is bound to.
  --force              Replace an existing summary.
  -h, --help           Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --record)
      RECORD="${2:?--record requires a value}"
      shift 2
      ;;
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
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

if [[ -z "$RECORD" || -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$RECORD" ]]; then
  echo "stable-qa-summary: QA record is missing" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "stable-qa-summary: release manifest is missing" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Required command not found: python3" >&2
  exit 2
fi

python3 - "$RECORD" "$MANIFEST" "$FORCE" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

record_path = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2]).resolve()
force = sys.argv[3] == "1"
manifest_dir = manifest_path.parent

# Same rule as scripts/macos_release_paths.sh: a plain file name, no slash.
RELEASE_FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*")
# Every copied string is a short token: no spaces, slashes or free text.
TOKEN = re.compile(r"[A-Za-z0-9_.:+-]{1,128}")
LOCAL_PLATFORM_KEYS = (
    "runtime",
    "service_label",
    "version",
    "release_channel",
    "install_owner",
    "protocol_version",
    "release_manifest_sha256",
)


def die(message: str, code: int = 1) -> None:
    print(f"stable-qa-summary: {message}", file=sys.stderr)
    sys.exit(code)


def obj(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        die(f"{label} must be an object")
    return value


def token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        die(f"{label} must be a short token (letters, digits, . _ : + -)")
    return value


def load(path: Path, label: str) -> dict[str, Any]:
    try:
        return obj(json.loads(path.read_text(encoding="utf-8")), label)
    except (UnicodeDecodeError, json.JSONDecodeError):
        die(f"{label} is not valid JSON")


if record_path == manifest_dir or manifest_dir in record_path.parents:
    die("the private QA record must live outside the release folder", code=2)

record = load(record_path, "QA record")
manifest = load(manifest_path, "release manifest")
if record.get("evidence_kind") != "private_record":
    die("input is not a private QA record (evidence_kind must be private_record)")
if record.get("schema_version") != 2 or record.get("gate") != "stable_clean_machine_qa":
    die("QA record must be schema_version 2 for gate stable_clean_machine_qa")

manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
record_manifest = obj(record.get("manifest"), "record manifest")
if record_manifest.get("sha256") != manifest_sha:
    die("QA record is bound to a different manifest")
environment = obj(record.get("environment"), "record environment")
owners = record.get("install_owners")
if not isinstance(owners, list):
    die("record install_owners must be an array")


def check(value: Any) -> dict[str, Any]:
    value = obj(value, "record check")
    out = {
        "result": token(value.get("result"), "check result"),
        "method": token(value.get("method"), "check method"),
    }
    if "from" in value:
        out["from"] = token(value.get("from"), "check from")
    return out


def local_platform_value(key: str, value: Any) -> Any:
    if key == "protocol_version":
        if type(value) is not int:
            die("record local_platform.protocol_version must be an integer")
        return value
    return token(value, f"record local_platform.{key}")


summary_owners = []
for entry in owners:
    entry = obj(entry, "record install owner")
    local_platform = obj(entry.get("local_platform"), "record local_platform")
    checks = obj(entry.get("checks"), "record checks")
    summary_owners.append({
        "owner": token(entry.get("owner"), "record install owner name"),
        "status": token(entry.get("status"), "record install owner status"),
        "local_platform": {
            key: local_platform_value(key, local_platform.get(key)) for key in LOCAL_PLATFORM_KEYS
        },
        "checks": {token(name, "check name"): check(value) for name, value in checks.items()},
    })

summary = {
    "schema_version": 2,
    "gate": "stable_clean_machine_qa",
    "status": token(record.get("status"), "record status"),
    "checked_at": token(record.get("checked_at"), "record checked_at"),
    "manifest": {
        key: token(record_manifest.get(key), f"record manifest.{key}")
        for key in ("product", "channel", "version", "commit", "sha256")
    },
    "environment": {
        key: token(environment.get(key), f"record environment.{key}")
        for key in ("host_class", "macos_version", "arch")
    },
    "install_owners": summary_owners,
}

gate = obj(
    obj(manifest.get("quality_gates"), "manifest quality_gates").get("stable_clean_machine_qa"),
    "manifest quality_gates.stable_clean_machine_qa",
)
evidence_name = gate.get("evidence_path")
if not isinstance(evidence_name, str) or not RELEASE_FILENAME.fullmatch(evidence_name):
    die("manifest stable_clean_machine_qa.evidence_path must be a plain file name")
output_path = manifest_dir / evidence_name
if output_path.is_symlink():
    die("the summary path beside the manifest must not be a symlink")
if output_path.exists() and not force:
    die(f"{evidence_name} already exists, pass --force to replace it", code=2)

text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
handle, temp_name = tempfile.mkstemp(prefix=".stable-qa-summary.", dir=manifest_dir)
try:
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.chmod(temp_name, 0o644)
    os.replace(temp_name, output_path)
except BaseException:
    if os.path.exists(temp_name):
        os.unlink(temp_name)
    raise
print(f"stable-qa-summary: wrote {evidence_name}")
PY
