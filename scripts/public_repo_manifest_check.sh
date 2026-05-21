#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="${PUBLIC_MANIFEST_REPO_ROOT:-$DEFAULT_REPO_ROOT}"

usage() {
  cat <<'USAGE'
Usage: public_repo_manifest_check.sh [--staged-output <dir>]

Verifies PUBLIC_EXPORT_MANIFEST.json for a root-shaped public ottto checkout.
The manifest must list every non-manifest file with size, mode, executable bit,
and SHA-256 digest, and its content_sha256 must match that deterministic file
inventory. Override PUBLIC_MANIFEST_REPO_ROOT or pass --staged-output to check a
generated bundle.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --staged-output)
      [[ "$#" -ge 2 ]] || {
        echo "public-manifest: --staged-output requires a value" >&2
        exit 2
      }
      REPO_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-manifest: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "public-manifest: python3 is required" >&2
  exit 2
fi

python3 - "$REPO_ROOT" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath

repo_root = Path(sys.argv[1]).resolve()
manifest_path = repo_root / "PUBLIC_EXPORT_MANIFEST.json"


def die(message: str, code: int = 2) -> None:
    print(f"public-manifest: {message}", file=sys.stderr)
    sys.exit(code)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_relative_path(raw: object, *, context: str) -> str:
    if not isinstance(raw, str) or not raw:
        die(f"{context} path must be a non-empty string")
    path = PurePosixPath(raw)
    parts = path.parts
    if raw.startswith("/") or not parts or any(part in {"", ".", ".."} for part in parts):
        die(f"{context} path is not repository-relative and safe: {raw!r}")
    if parts[0] == ".git":
        die(f"{context} path must not include .git: {raw}")
    if raw == "PUBLIC_EXPORT_MANIFEST.json":
        die(f"{context} must not list PUBLIC_EXPORT_MANIFEST.json")
    return path.as_posix()


def collect_actual_records(root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    entries = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    for path in entries:
        relative = path.relative_to(root)
        parts = relative.parts
        if parts and parts[0] == ".git":
            continue
        rel = relative.as_posix()
        if path.is_symlink():
            die(f"public manifest does not support symlinked files: {rel}")
        if not path.is_file():
            continue
        if rel == "PUBLIC_EXPORT_MANIFEST.json":
            continue
        validate_relative_path(rel, context="actual file")
        mode = stat.S_IMODE(path.stat().st_mode)
        records.append(
            {
                "path": rel,
                "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size,
                "mode": f"{mode:04o}",
                "executable": bool(mode & 0o111),
            }
        )
    return records


def records_digest(records: list[dict[str, object]]) -> str:
    payload = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_manifest() -> dict[str, object]:
    if not repo_root.is_dir():
        die(f"repository root is not a directory: {repo_root}")
    if not manifest_path.is_file():
        die(f"required manifest is missing: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        die(f"manifest is invalid JSON: {error}")
    if not isinstance(manifest, dict):
        die("manifest must be a JSON object")
    return manifest


def validate_manifest_records(raw_records: object) -> list[dict[str, object]]:
    if not isinstance(raw_records, list):
        die("manifest files must be a list")
    records: list[dict[str, object]] = []
    previous_path = ""
    seen: set[str] = set()
    expected_keys = {"path", "sha256", "size_bytes", "mode", "executable"}
    for index, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            die(f"manifest file record {index} must be an object")
        extra = set(raw) - expected_keys
        missing = expected_keys - set(raw)
        if extra or missing:
            die(
                f"manifest file record {index} has invalid keys "
                f"(missing={sorted(missing)}, extra={sorted(extra)})"
            )
        path = validate_relative_path(raw["path"], context=f"manifest file record {index}")
        if path in seen:
            die(f"manifest files contain a duplicate path: {path}")
        if previous_path and path <= previous_path:
            die("manifest files must be sorted by path")
        seen.add(path)
        previous_path = path
        sha256 = raw["sha256"]
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            die(f"manifest file record {path} has invalid sha256")
        size_bytes = raw["size_bytes"]
        if not isinstance(size_bytes, int) or size_bytes < 0:
            die(f"manifest file record {path} has invalid size_bytes")
        mode = raw["mode"]
        if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{4}", mode):
            die(f"manifest file record {path} has invalid mode")
        executable = raw["executable"]
        if not isinstance(executable, bool):
            die(f"manifest file record {path} has invalid executable flag")
        records.append(
            {
                "path": path,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "mode": mode,
                "executable": executable,
            }
        )
    return records


manifest = load_manifest()
if manifest.get("schema_version") != 1:
    die("manifest schema_version must be 1")
if manifest.get("generated_by") != "public_repo_export_bundle.sh":
    die("manifest generated_by must be public_repo_export_bundle.sh")
if not isinstance(manifest.get("source_commit"), str) or not manifest["source_commit"]:
    die("manifest source_commit must be a non-empty string")
if not isinstance(manifest.get("candidate_file_count"), int) or manifest["candidate_file_count"] < 1:
    die("manifest candidate_file_count must be a positive integer")
if not isinstance(manifest.get("output_file_count"), int) or manifest["output_file_count"] < 1:
    die("manifest output_file_count must be a positive integer")
if not isinstance(manifest.get("public_roots"), list):
    die("manifest public_roots must be a list")
if not isinstance(manifest.get("rewrites_applied"), dict):
    die("manifest rewrites_applied must be an object")

manifest_records = validate_manifest_records(manifest.get("files"))
actual_records = collect_actual_records(repo_root)
if manifest["output_file_count"] != len(actual_records) + 1:
    die(
        "manifest output_file_count does not match actual files: "
        f"{manifest['output_file_count']} != {len(actual_records) + 1}"
    )

manifest_paths = {str(record["path"]) for record in manifest_records}
actual_paths = {str(record["path"]) for record in actual_records}
missing = sorted(manifest_paths - actual_paths)
extra = sorted(actual_paths - manifest_paths)
if missing:
    die(f"manifest lists missing file: {missing[0]}")
if extra:
    die(f"extra file not listed in manifest: {extra[0]}")

manifest_by_path = {str(record["path"]): record for record in manifest_records}
for actual in actual_records:
    path = str(actual["path"])
    expected = manifest_by_path[path]
    for key in ("sha256", "size_bytes", "mode", "executable"):
        if actual[key] != expected[key]:
            die(f"manifest {key} mismatch for {path}")

expected_digest = records_digest(manifest_records)
content_sha256 = manifest.get("content_sha256")
if not isinstance(content_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
    die("manifest content_sha256 must be a lowercase SHA-256 hex digest")
if content_sha256 != expected_digest:
    die("manifest content_sha256 mismatch")

actual_digest = records_digest(actual_records)
if content_sha256 != actual_digest:
    die("manifest file inventory does not match actual files")

print(f"public-manifest: checked {len(actual_records)} file hash record(s) at {repo_root}")
PY
