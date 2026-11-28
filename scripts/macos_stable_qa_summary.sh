#!/usr/bin/env bash
set -euo pipefail

RECORD=""
MANIFEST=""
FORCE=0
STAGE="final"
OUTPUT=""

usage() {
  cat <<'USAGE'
Usage: macos_stable_qa_summary.sh --record <qa-record.json> --manifest <release-manifest.json> [--stage final] [--force]
       macos_stable_qa_summary.sh --record <qa-record.json> --manifest <release-manifest.json> \
         --stage pre-hosted --output <pre-hosted-summary.json> [--force]

Writes the public stable clean-machine QA summary from the private QA record
that macos_stable_qa_evidence_template.sh created. Only allowlisted fields are
copied: operator notes, per-check notes and any other record field are dropped.
The summary is written beside the manifest as stable-clean-machine-qa.json, the
name the manifest's stable_clean_machine_qa.evidence_path must give; it never
replaces the manifest or another release file. Run macos_stable_closeout_gate.sh
on the manifest afterwards.

A stable release is published in two stages, because the hosted installer
downloads only from the immutable versioned prefix. --stage pre-hosted writes
the pre-hosted summary for the immutable stage: the same schema plus
"stage":"pre-hosted", written create-only (unless --force) to --output
outside the release folder, compared by filesystem identity (the final summary
is the one late file in that prefix). The manifest must list hosted_installer
as supported and required. It refuses unless every
hosted_installer check in the record is not_run, the hosted_installer owner
status and the top-level status are not_run, and every other owner passed
with every check passed in this release. Run macos_stable_closeout_gate.sh
--stage pre-hosted --evidence <output> on it. After the hosted lane, fill the
hosted checks in the record and write the final summary without --stage.

Options:
  --record <path>      Private QA record. Must be outside the manifest's folder,
                       and neither a symlink nor reached through one.
  --manifest <path>    Stable release manifest the record is bound to.
  --stage <stage>      final (default): the summary beside the manifest.
                       pre-hosted: the pre-hosted summary at --output.
  --output <path>      Pre-hosted summary path, outside the manifest's folder
                       (with --stage pre-hosted only).
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
    --stage|--output)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "stable-qa-summary: $1 requires a value" >&2
        exit 2
      fi
      if [[ "$1" == "--stage" ]]; then
        STAGE="$2"
      else
        OUTPUT="$2"
      fi
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
case "$STAGE" in
  final)
    if [[ -n "$OUTPUT" ]]; then
      echo "stable-qa-summary: --output goes with --stage pre-hosted only; the final summary is written beside the manifest" >&2
      exit 2
    fi
    ;;
  pre-hosted)
    if [[ -z "$OUTPUT" ]]; then
      echo "stable-qa-summary: --stage pre-hosted requires --output <pre-hosted-summary.json>" >&2
      exit 2
    fi
    ;;
  *)
    echo "stable-qa-summary: --stage must be pre-hosted or final" >&2
    exit 2
    ;;
esac
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

python3 - "$RECORD" "$MANIFEST" "$FORCE" "$STAGE" "$OUTPUT" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

record_arg = Path(sys.argv[1]).absolute()
manifest_arg = Path(sys.argv[2]).absolute()
force = sys.argv[3] == "1"
pre_hosted = sys.argv[4] == "pre-hosted"
# The owner whose lane runs only after the immutable upload.
HOSTED_OWNER = "hosted_installer"

# The one public summary name (schema 2). Any other name could collide with the
# manifest or another release file.
SUMMARY_NAME = "stable-clean-machine-qa.json"
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


def reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def read(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        die(f"{label} is not readable")


def load(data: bytes, label: str) -> dict[str, Any]:
    try:
        return obj(json.loads(data.decode("utf-8"), parse_constant=reject_constant), label)
    except (UnicodeDecodeError, ValueError):
        die(f"{label} is not valid JSON")


def inside(path: Path, folder: Path) -> bool:
    return path == folder or folder in path.parents


def aliased(path: Path, folder: Path) -> bool:
    """The path is a symlink, or a link inside the folder leads to it."""
    if path.is_symlink():
        return True
    for ancestor in path.parents:
        if ancestor.is_symlink() and inside(ancestor.parent.resolve(), folder):
            return True
    return False


# The release folder is the manifest's physical parent, as the closeout gate
# sees it; the publisher uploads it and follows links.
if manifest_arg.is_symlink():
    die("the release manifest must not be a symlink", code=2)
manifest_dir = manifest_arg.parent.resolve()
manifest_path = manifest_dir / manifest_arg.name
if aliased(record_arg, manifest_dir):
    die("the private QA record path must not be or pass through a symlink", code=2)
record_path = record_arg.resolve()
if inside(record_path, manifest_dir):
    die("the private QA record must live outside the release folder", code=2)

record = load(read(record_path, "QA record"), "QA record")
manifest_bytes = read(manifest_path, "release manifest")
manifest = load(manifest_bytes, "release manifest")
if record.get("evidence_kind") != "private_record":
    die("input is not a private QA record (evidence_kind must be private_record)")
if type(record.get("schema_version")) is not int or record.get("schema_version") != 2 \
        or record.get("gate") != "stable_clean_machine_qa":
    die("QA record must be schema_version 2 for gate stable_clean_machine_qa")

manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
record_manifest = obj(record.get("manifest"), "record manifest")
if record_manifest.get("sha256") != manifest_sha:
    die("QA record is bound to a different manifest")
if pre_hosted:
    # The hosted lane runs after the immutable stage only when the manifest
    # advertises and requires the hosted installer owner.
    manifest_gate = (manifest.get("quality_gates") or {}).get("stable_clean_machine_qa") or {}
    supported = manifest.get("supported_install_owners")
    required = manifest_gate.get("required_install_owners") if isinstance(manifest_gate, dict) else None
    if not (isinstance(supported, list) and HOSTED_OWNER in supported
            and isinstance(required, list) and HOSTED_OWNER in required):
        die("pre-hosted: the manifest must list hosted_installer in supported_install_owners and "
            "stable_clean_machine_qa.required_install_owners; publish a release without the hosted "
            "installer lane in a single stage")
environment = obj(record.get("environment"), "record environment")
owners = record.get("install_owners")
if not isinstance(owners, list):
    die("record install_owners must be an array")


def check(value: Any, owner: Any) -> dict[str, Any]:
    value = obj(value, "record check")
    if pre_hosted and owner == HOSTED_OWNER:
        if value.get("result") != "not_run":
            die("pre-hosted: every hosted_installer check must be not_run (the hosted lane runs after the immutable upload)")
        return {"result": "not_run"}
    if pre_hosted and (
        value.get("result") != "passed" or value.get("method") not in ("live", "scripted", "static") or "from" in value
    ):
        die("pre-hosted: every check outside hosted_installer must be passed in this release (method live, scripted or static)")
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
    owner_name = token(entry.get("owner"), "record install owner name")
    owner_status = token(entry.get("status"), "record install owner status")
    if pre_hosted and owner_status != ("not_run" if owner_name == HOSTED_OWNER else "passed"):
        die("pre-hosted: the hosted_installer owner status must be not_run and every other owner status passed")
    summary_owners.append({
        "owner": owner_name,
        "status": owner_status,
        "local_platform": {
            key: local_platform_value(key, local_platform.get(key)) for key in LOCAL_PLATFORM_KEYS
        },
        "checks": {token(name, "check name"): check(value, owner_name) for name, value in checks.items()},
    })
if pre_hosted:
    if not any(entry["owner"] == HOSTED_OWNER for entry in summary_owners):
        die("pre-hosted: the QA record has no hosted_installer owner; write the final summary instead")
    if record.get("status") != "not_run":
        die("pre-hosted: the record's top-level status must be not_run until the hosted lane has passed")

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
if pre_hosted:
    summary["stage"] = "pre-hosted"

gate = obj(
    obj(manifest.get("quality_gates"), "manifest quality_gates").get("stable_clean_machine_qa"),
    "manifest quality_gates.stable_clean_machine_qa",
)
if gate.get("evidence_path") != SUMMARY_NAME:
    die(f"manifest stable_clean_machine_qa.evidence_path must be {SUMMARY_NAME}")


def release_file_names(value: Any) -> set[str]:
    """Every file name the manifest lists: artifact, SBOM, evidence and subject paths."""
    names: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("path", "verification_path", "evidence_path") and isinstance(item, str):
                names.add(Path(item).name)
            elif key == "subjects" and isinstance(item, list):
                names.update(Path(subject).name for subject in item if isinstance(subject, str))
            else:
                names.update(release_file_names(item))
    elif isinstance(value, list):
        for item in value:
            names.update(release_file_names(item))
    return names


other_gates = {key: value for key, value in obj(manifest.get("quality_gates"), "manifest quality_gates").items()
               if key != "stable_clean_machine_qa"}
manifest_without_gate = {key: value for key, value in manifest.items() if key != "quality_gates"}
release_names = (
    {manifest_path.name}
    | release_file_names(manifest_without_gate)
    | release_file_names(other_gates)
)
output_path = manifest_dir / SUMMARY_NAME
output_label = SUMMARY_NAME


def same_file(left: Path, right: Path) -> bool:
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return True


if pre_hosted:
    # The immutable stage uploads the release folder, and the final summary is
    # the one late file in that prefix, so the pre-hosted summary stays out.
    output_arg = Path(sys.argv[5]).absolute()
    if aliased(output_arg, manifest_dir):
        die("the pre-hosted summary path must not be or pass through a symlink", code=2)
    output_path = output_arg.resolve()
    if not output_path.parent.is_dir():
        die("the pre-hosted summary folder is missing", code=2)
    # Folders compare by filesystem identity, not by spelling: a case alias
    # (macOS volumes are usually case-insensitive) names the same folder.
    if inside(output_path, manifest_dir) or any(
        same_file(folder, manifest_dir) for folder in (output_path.parent, *output_path.parent.parents)
    ):
        die("the pre-hosted summary must live outside the release folder", code=2)
    if output_path == record_path or same_file(output_path, record_path):
        die("the pre-hosted summary must not replace the private QA record", code=2)
    if any(same_file(output_path, manifest_dir / name) for name in release_names if name not in ("", ".", "..")):
        die("the pre-hosted summary would replace the manifest or another release file", code=2)
    output_label = "the pre-hosted summary"
    if output_path.exists() and not force:
        die("the pre-hosted summary already exists, pass --force to replace it", code=2)
else:
    # Names compare case-insensitively (macOS volumes usually are), and an existing
    # summary path must not be the manifest or a listed file under another name or
    # a hard link.
    if SUMMARY_NAME.casefold() in {name.casefold() for name in release_names} or any(
        same_file(output_path, manifest_dir / name) for name in release_names if name not in ("", ".", "..")
    ):
        die(f"{SUMMARY_NAME} would replace the manifest or another release file")
    if output_path.is_symlink():
        die("the summary path beside the manifest must not be a symlink")
    if output_path.exists() and not force:
        die(f"{SUMMARY_NAME} already exists, pass --force to replace it", code=2)

text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
temp_name = ""
try:
    handle, temp_name = tempfile.mkstemp(prefix=".stable-qa-summary.", dir=output_path.parent)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.chmod(temp_name, 0o644)
    if pre_hosted and not force:
        # Create-only: a hard link never replaces an existing file, so of two
        # concurrent runs only one installs its summary.
        try:
            os.link(temp_name, output_path)
        except FileExistsError:
            die("the pre-hosted summary already exists, pass --force to replace it", code=2)
        os.unlink(temp_name)
    else:
        os.replace(temp_name, output_path)
except BaseException as error:
    if temp_name and os.path.exists(temp_name):
        os.unlink(temp_name)
    if isinstance(error, OSError):
        die("could not write the pre-hosted summary" if pre_hosted else f"could not write {SUMMARY_NAME} beside the manifest")
    raise
print(f"stable-qa-summary: wrote {output_label}")
PY
