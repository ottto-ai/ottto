#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
OUTPUT=""
CHECKED_AT=""
MACOS_VERSION=""
ARCH=""
HOST_CLASS=""
FORCE=0

usage() {
  cat <<'USAGE'
Usage: macos_stable_qa_evidence_template.sh --manifest <release-manifest.json> --output <path|-> --host-class <class> [options]

Writes the PRIVATE stable clean-machine QA record skeleton (evidence schema 2)
for the exact release manifest. Every check starts as result=not_run. Keep the
record outside the release folder: the publisher uploads that folder. Publish
only the summary that macos_stable_qa_summary.sh writes from the record.

Options:
  --manifest <path>        Stable release manifest to bind the record to.
  --output <path|->        Required. Record path outside the manifest's folder, or - for stdout.
  --host-class <class>     Required. The least clean class that fits the QA host:
                           clean_vm (fresh VM from an image with no Ottto),
                           clean_macos (fresh macOS install, never had Ottto),
                           qa_user_on_shared_mac (separate user on a shared Mac),
                           signing_mac (any user on the release signing Mac),
                           developer_mac (an engineer's daily Mac).
  --checked-at <iso8601>   Record timestamp. Default: current UTC time.
  --macos-version <value>  macOS product version of the QA host, for example 15.5. Default: TODO.
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
    --host-class)
      HOST_CLASS="${2:?--host-class requires a value}"
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

if [[ -z "$MANIFEST" || -z "$OUTPUT" || -z "$HOST_CLASS" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Required command not found: python3" >&2
  exit 2
fi

python3 - "$MANIFEST" "$OUTPUT" "$CHECKED_AT" "$MACOS_VERSION" "$ARCH" "$FORCE" "$HOST_CLASS" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

manifest_arg = Path(sys.argv[1]).absolute()
output_arg = sys.argv[2]
checked_at = sys.argv[3]
macos_version = sys.argv[4] or "TODO_FILL_MACOS_PRODUCT_VERSION"
arch = sys.argv[5] or "TODO_arm64_x86_64_or_universal"
force = sys.argv[6] == "1"
host_class = sys.argv[7]

HOST_CLASSES = ("clean_vm", "clean_macos", "qa_user_on_shared_mac", "signing_mac", "developer_mac")

CHECKS_BY_OWNER = {
    "homebrew": [
        "formula_syntax",
        "install",
        "service_start",
        "headless_no_app_process",
        "status_json",
        "setup_browser_claim",
        "apps_detect_json",
        "verify_codex_json",
        "doctor_json",
        "doctor_owner_drift_json",
        "fix_codex_json",
        "diagnostics_collect_json",
        "logout_json",
        "update_check",
        "update_check_owner_json",
        "upgrade",
        "post_upgrade_service_restarts_owned",
        "uninstall",
        "reinstall",
        "post_reinstall_status_json",
        "reonboard_after_keychain_wipe",
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
        "reonboard_after_keychain_wipe",
    ],
    "app_bundle": [
        "artifact_checksum",
        "gatekeeper",
        "install",
        "app_launch",
        "service_ready",
        "homebrew_second_install_safe_refusal",
        "status_json",
        "setup_browser_claim",
        "apps_detect_json",
        "verify_codex_json",
        "doctor_json",
        "doctor_owner_drift_json",
        "fix_codex_json",
        "diagnostics_collect_json",
        "logout_json",
        "update_check",
        "update_check_owner_json",
        "upgrade",
        "move_service_to_app",
        "uninstall",
        "reinstall",
        "post_reinstall_status_json",
        "reonboard_after_keychain_wipe",
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


def reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


# The release folder is the manifest's physical parent, as the closeout gate
# sees it. A linked manifest would point the checks at another folder.
if manifest_arg.is_symlink():
    die("the release manifest must not be a symlink", code=2)
manifest_dir = manifest_arg.parent.resolve()
manifest_path = manifest_dir / manifest_arg.name

try:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"), parse_constant=reject_constant)
except (OSError, UnicodeDecodeError, ValueError):
    die("the release manifest is not readable JSON")

manifest = require_object(manifest, "manifest")
product = require_string(manifest.get("product"), "manifest.product")
channel = require_string(manifest.get("channel"), "manifest.channel")
version = require_string(manifest.get("version"), "manifest.version")
commit = require_string(manifest.get("commit"), "manifest.commit")
min_protocol_version = manifest.get("min_protocol_version")
if product != "ottto-local-platform":
    die("expected product=ottto-local-platform")
if channel != "stable":
    die("expected stable manifest (channel=stable)")
if not re.fullmatch(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})", version):
    die("manifest.version must be X.Y.Z (canonical numbers, at most 9 digits each)")
if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
    die("manifest.commit must be a git SHA prefix")
if type(min_protocol_version) is not int or min_protocol_version != 15:
    die("manifest.min_protocol_version must be the integer 15")

quality_gates = require_object(manifest.get("quality_gates"), "manifest.quality_gates")
gate = require_object(
    quality_gates.get("stable_clean_machine_qa"),
    "manifest.quality_gates.stable_clean_machine_qa",
)
if gate.get("evidence_path") != "stable-clean-machine-qa.json":
    die("manifest stable_clean_machine_qa.evidence_path must be stable-clean-machine-qa.json")
supported_owners = sorted(set(require_string_list(
    manifest.get("supported_install_owners"), "manifest.supported_install_owners"
)))
required_owners = sorted(set(require_string_list(
    gate.get("required_install_owners"),
    "manifest.quality_gates.stable_clean_machine_qa.required_install_owners",
)))

if set(supported_owners).difference(CHECKS_BY_OWNER) or set(required_owners).difference(CHECKS_BY_OWNER):
    die("the manifest names an unsupported install owner")
missing_required = sorted(set(supported_owners).difference(required_owners))
if missing_required:
    die(
        "stable_clean_machine_qa.required_install_owners is missing supported "
        f"owner(s): {', '.join(missing_required)}"
    )

if arch not in {"arm64", "x86_64", "universal", "TODO_arm64_x86_64_or_universal"}:
    die("--arch must be arm64, x86_64, or universal", code=2)
if host_class not in HOST_CLASSES:
    die(f"--host-class must be one of: {', '.join(HOST_CLASSES)}", code=2)
if sys.argv[4] and not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}", macos_version):
    die("--macos-version must be a macOS product version such as 15.5", code=2)


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


# The record holds private notes; the publisher uploads the release folder and
# follows links, so the record may be neither in it nor reached through it.
if output_arg == "-":
    output_path = None
else:
    output_arg_path = Path(output_arg).absolute()
    if aliased(output_arg_path, manifest_dir):
        die("the private QA record path must not be or pass through a symlink", code=2)
    output_path = output_arg_path.resolve()
    if inside(output_path, manifest_dir):
        die(
            "the private QA record must live outside the release folder "
            "(the publisher uploads that folder); publish only the summary",
            code=2,
        )

if not checked_at:
    checked_at = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
evidence = {
    "schema_version": 2,
    "evidence_kind": "private_record",
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
        "host_class": host_class,
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
            "checks": {
                check: {"result": "not_run", "method": "TODO_live_scripted_or_static"}
                for check in CHECKS_BY_OWNER[owner]
            },
        }
        for owner in supported_owners
    ],
    "operator_notes": [
        (
            "PRIVATE record: keep it outside the release folder. Only the summary "
            "from macos_stable_qa_summary.sh is published; it drops these notes."
        ),
        (
            "result=passed only if the check ran in this release against the manifest "
            "above; method=live (driven by hand), scripted (automated run) or static "
            "(artifact inspection, only for artifact_checksum, formula_syntax, "
            "gatekeeper and native_gatekeeper)."
        ),
        (
            "Never record passed for a check that did not run here. result=carried "
            "(from=<version where it last ran>) is the honest value, but the closeout "
            "gate does not accept carry yet, so such a check blocks the release."
        ),
        (
            "host_class is the least clean class that fits: clean_vm (clean guest VM), "
            "clean_macos (clean physical Mac), qa_user_on_shared_mac, signing_mac (any "
            "user on the signing host), developer_mac. Keep per-check host details "
            "and any VM image digest in this record only."
        ),
        (
            "Do not paste raw command output, local user paths, private repo paths, "
            "claim codes, setup-run secrets, account identifiers, machine identifiers, "
            "API credentials, or authorization credentials."
        ),
        (
            "Set top-level status and each owner status to passed only when every "
            "check of that owner is passed or carried. Details may go in an optional "
            "per-check note; the summary drops it."
        ),
    ],
}

text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
if output_path is None:
    print(text, end="")
else:
    if output_path.exists() and not force:
        die("output already exists, pass --force to overwrite it", code=2)
    temp_path = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix=".stable-qa-record.",
                dir=output_path.parent,
                delete=False,
            ) as stream:
                temp_path = Path(stream.name)
                stream.write(text)
            if force:
                # Replace the directory entry without touching the old inode.
                os.replace(temp_path, output_path)
            else:
                # Atomically create the output only if it is still absent.
                try:
                    os.link(temp_path, output_path)
                except FileExistsError:
                    die("output already exists, pass --force to overwrite it", code=2)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    except OSError:
        die("could not write the private QA record")
    print("stable-qa-template: wrote the private QA record")
PY
