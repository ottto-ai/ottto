#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TARGET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${PUBLIC_CUTOVER_TARGET_DIR:-$DEFAULT_TARGET_DIR}"
SOURCE_REPO_ROOT="${PUBLIC_CUTOVER_SOURCE_REPO_ROOT:-}"
BOOTSTRAP_REPORT=""
REPORT_PATH=""
SKIP_SURFACE_CI=0

usage() {
  cat <<'USAGE'
Usage: public_repo_cutover_closeout.sh [--target-dir <dir>] [--source-repo-root <dir>] [--bootstrap-report <path>] [--report <path>] [--skip-surface-ci]

Runs the post-apply closeout gate for a root-shaped public ottto checkout.
Use it after public_repo_bootstrap_plan.sh --apply and before committing or
protecting the public repository branch. The report is machine-readable and
does not include absolute local filesystem paths.

Checks:
  - target checkout shape and private-monorepo path rejection
  - PUBLIC_EXPORT_MANIFEST.json integrity
  - optional bootstrap apply-report consistency
  - public skeleton, secret scan, and public/private contract checks
  - public-surface CI smoke unless --skip-surface-ci is passed

Environment overrides:
  PUBLIC_CUTOVER_TARGET_DIR
  PUBLIC_CUTOVER_SOURCE_REPO_ROOT
USAGE
}

fail() {
  echo "public-cutover-closeout: $*" >&2
  exit 2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$1 is required"
  fi
}

require_executable() {
  if [[ ! -x "$1" ]]; then
    fail "required executable is missing or not executable: $1"
  fi
}

resolve_path() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).expanduser().resolve())
PY
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --target-dir)
      [[ "$#" -ge 2 ]] || fail "--target-dir requires a value"
      TARGET_DIR="$2"
      shift 2
      ;;
    --source-repo-root)
      [[ "$#" -ge 2 ]] || fail "--source-repo-root requires a value"
      SOURCE_REPO_ROOT="$2"
      shift 2
      ;;
    --bootstrap-report)
      [[ "$#" -ge 2 ]] || fail "--bootstrap-report requires a value"
      BOOTSTRAP_REPORT="$2"
      shift 2
      ;;
    --report)
      [[ "$#" -ge 2 ]] || fail "--report requires a value"
      REPORT_PATH="$2"
      shift 2
      ;;
    --skip-surface-ci)
      SKIP_SURFACE_CI=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

require_command git
require_command python3

TARGET_DIR="$(resolve_path "$TARGET_DIR")"
if [[ -n "$SOURCE_REPO_ROOT" ]]; then
  SOURCE_REPO_ROOT="$(resolve_path "$SOURCE_REPO_ROOT")"
fi
if [[ -n "$BOOTSTRAP_REPORT" ]]; then
  BOOTSTRAP_REPORT="$(resolve_path "$BOOTSTRAP_REPORT")"
fi
if [[ -n "$REPORT_PATH" ]]; then
  REPORT_PATH="$(resolve_path "$REPORT_PATH")"
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  fail "target directory is not a directory: $TARGET_DIR"
fi
if ! target_root_raw="$(git -C "$TARGET_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
  fail "target directory is not a git checkout: $TARGET_DIR"
fi
TARGET_REPO_ROOT="$(resolve_path "$target_root_raw")"
if [[ "$TARGET_REPO_ROOT" != "$TARGET_DIR" ]]; then
  fail "target directory must be the git repository root: $TARGET_DIR (git root is $TARGET_REPO_ROOT)"
fi

if [[ -n "$SOURCE_REPO_ROOT" ]]; then
  if [[ ! -d "$SOURCE_REPO_ROOT" ]]; then
    fail "source repository root is not a directory: $SOURCE_REPO_ROOT"
  fi
  if ! git -C "$SOURCE_REPO_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
    fail "source repository root is not a git checkout: $SOURCE_REPO_ROOT"
  fi
fi

private_shape_paths=(
  ".agents"
  ".claude"
  "backend"
  "docs/a""i"
  "docs/d""ev"
  "frontend"
  "infra"
  "tools/ottto-local-platform"
)
for path in "${private_shape_paths[@]}"; do
  if [[ -e "$TARGET_DIR/$path" ]]; then
    fail "target contains private monorepo-shaped path: $path"
  fi
done

required_files=(
  "PUBLIC_EXPORT_MANIFEST.json"
  "public-export/roots.txt"
  "scripts/public_repo_cutover_closeout.sh"
  "scripts/public_repo_manifest_check.sh"
  "scripts/public_repo_skeleton_check.sh"
  "scripts/public_repo_secret_scan.sh"
  "scripts/public_repo_contract_check.sh"
  "scripts/public_repo_surface_ci.sh"
)
for path in "${required_files[@]}"; do
  if [[ ! -f "$TARGET_DIR/$path" ]]; then
    fail "target is missing required public file: $path"
  fi
done

required_executables=(
  "scripts/public_repo_cutover_closeout.sh"
  "scripts/public_repo_manifest_check.sh"
  "scripts/public_repo_skeleton_check.sh"
  "scripts/public_repo_secret_scan.sh"
  "scripts/public_repo_contract_check.sh"
  "scripts/public_repo_surface_ci.sh"
)
for path in "${required_executables[@]}"; do
  require_executable "$TARGET_DIR/$path"
done

python3 - "$TARGET_DIR" "$BOOTSTRAP_REPORT" "$REPORT_PATH" "$SKIP_SURFACE_CI" "$SOURCE_REPO_ROOT" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

target_root = Path(sys.argv[1]).resolve()
bootstrap_report_arg = sys.argv[2]
bootstrap_report_path = Path(bootstrap_report_arg).resolve() if bootstrap_report_arg else None
report_path = Path(sys.argv[3]).resolve() if sys.argv[3] else None
skip_surface_ci = sys.argv[4] == "1"
source_repo_root_arg = sys.argv[5]
source_root = Path(source_repo_root_arg).resolve() if source_repo_root_arg else None
EXPECTED_REMOTE_REPOSITORY = "ottto-ai/ottto"


def die(message: str, code: int = 2) -> None:
    print(f"public-cutover-closeout: {message}", file=sys.stderr)
    sys.exit(code)


def git_output(*args: str, check: bool = False) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(target_root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        if check:
            die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip() or None


def git_output_at(root: Path, *args: str, check: bool = False) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        if check:
            die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip() or None


def source_facts() -> dict[str, Any]:
    if source_root is None:
        return {
            "provided": False,
            "private_consumer_contracts": False,
            "secret_scan_scope": "target_only",
            "contract_scope": "public_only",
        }
    has_private_contracts = (source_root / "backend").is_dir() and (source_root / "frontend").is_dir()
    return {
        "provided": True,
        "head": git_output_at(source_root, "rev-parse", "HEAD", check=True),
        "private_consumer_contracts": has_private_contracts,
        "secret_scan_scope": "target_and_source_history",
        "contract_scope": "public_private" if has_private_contracts else "public_only",
    }


def target_remote_facts() -> dict[str, str]:
    remote_url = git_output("remote", "get-url", "origin")
    if remote_url is None:
        die("target origin remote is missing")
    if remote_url.startswith("git@github.com:"):
        repository = remote_url.removeprefix("git@github.com:")
        url_kind = "ssh"
    elif remote_url.startswith("ssh://git@github.com/"):
        repository = remote_url.removeprefix("ssh://git@github.com/")
        url_kind = "ssh"
    elif remote_url.startswith("https://github.com/"):
        repository = remote_url.removeprefix("https://github.com/")
        url_kind = "https"
    else:
        die("target origin remote must be a GitHub SSH or HTTPS URL")

    repository = repository.removesuffix(".git").strip("/")
    if repository != EXPECTED_REMOTE_REPOSITORY:
        die(f"target origin remote must be {EXPECTED_REMOTE_REPOSITORY}, got {repository}")
    return {
        "name": "origin",
        "repository": repository,
        "url_kind": url_kind,
    }


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        die(f"{label} is missing: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        die(f"{label} is invalid JSON: {error}")
    if not isinstance(value, dict):
        die(f"{label} must be a JSON object")
    return value


def manifest_facts() -> dict[str, Any]:
    manifest = load_json(target_root / "PUBLIC_EXPORT_MANIFEST.json", "public export manifest")
    files = manifest.get("files")
    public_roots = manifest.get("public_roots")
    return {
        "schema_version": manifest.get("schema_version"),
        "source_commit": manifest.get("source_commit"),
        "candidate_file_count": manifest.get("candidate_file_count"),
        "output_file_count": manifest.get("output_file_count"),
        "file_record_count": len(files) if isinstance(files, list) else None,
        "content_sha256": manifest.get("content_sha256"),
        "public_roots": public_roots if isinstance(public_roots, list) else [],
    }


def status_lines() -> list[str]:
    output = git_output("status", "--porcelain=v1", "--untracked-files=all")
    if not output:
        return []
    return output.splitlines()


def assert_bootstrap_report(
    manifest: dict[str, Any],
    expected_remote: dict[str, str],
    current_branch: str | None,
    current_head: str | None,
) -> dict[str, Any]:
    if bootstrap_report_path is None:
        return {"provided": False}
    if not bootstrap_report_path.is_file():
        die("bootstrap report is missing")

    raw = bootstrap_report_path.read_text(encoding="utf-8")
    forbidden_fragments = (
        "/" + "private/",
        "/" + "Users/",
        "/var/" + "folders/",
    )
    for forbidden in forbidden_fragments:
        if forbidden in raw:
            die(f"bootstrap report contains local filesystem path fragment: {forbidden}")
    report = load_json(bootstrap_report_path, "bootstrap report")
    if report.get("schema_version") != 1:
        die("bootstrap report schema_version must be 1")
    if report.get("generated_by") != "public_repo_bootstrap_plan.sh":
        die("bootstrap report was not generated by public_repo_bootstrap_plan.sh")
    if report.get("applied") is not True:
        die("bootstrap report must record applied=true")

    bundle = report.get("bundle")
    if not isinstance(bundle, dict):
        die("bootstrap report is missing bundle facts")
    if bundle.get("content_sha256") != manifest.get("content_sha256"):
        die("bootstrap report bundle digest does not match target manifest")
    if bundle.get("output_file_count") != manifest.get("output_file_count"):
        die("bootstrap report output file count does not match target manifest")
    if bundle.get("file_record_count") != manifest.get("file_record_count"):
        die("bootstrap report file record count does not match target manifest")

    post_apply = report.get("post_apply_public_checks")
    expected = {
        "manifest": "passed",
        "skeleton": "passed",
        "secret_scan": "passed",
        "contract": "passed",
    }
    if post_apply != expected:
        die("bootstrap report does not record passed post-apply public checks")

    target = report.get("target")
    if not isinstance(target, dict):
        die("bootstrap report is missing target facts")
    target_remote = target.get("remote")
    if target_remote != expected_remote:
        die("bootstrap report target remote does not match current target origin")
    target_branch = target.get("branch")
    if target_branch != current_branch:
        die("bootstrap report target branch does not match current target branch")
    target_head_before = target.get("head_before")
    if target_head_before != current_head:
        die("bootstrap report target head_before does not match current target head")

    return {
        "provided": True,
        "schema_version": report.get("schema_version"),
        "generated_by": report.get("generated_by"),
        "mode": report.get("mode"),
        "applied": report.get("applied"),
        "target_branch": target_branch,
        "target_head_before": target_head_before,
        "target_remote": target_remote,
        "content_sha256": bundle.get("content_sha256"),
        "output_file_count": bundle.get("output_file_count"),
        "file_record_count": bundle.get("file_record_count"),
        "post_apply_public_checks": post_apply,
    }


manifest = manifest_facts()
if manifest.get("schema_version") != 1:
    die("target manifest schema_version must be 1")
if not manifest.get("content_sha256"):
    die("target manifest is missing content_sha256")
if manifest.get("file_record_count") is None:
    die("target manifest is missing file inventory")
if manifest.get("file_record_count") + 1 != manifest.get("output_file_count"):
    die("target manifest file counts are inconsistent")

remote = target_remote_facts()
target_branch = git_output("branch", "--show-current")
target_head = git_output("rev-parse", "HEAD")
report = {
    "schema_version": 1,
    "generated_by": "public_repo_cutover_closeout.sh",
    "mode": "target_closeout",
    "target": {
        "branch": target_branch,
        "head": target_head,
        "remote": remote,
        "status": status_lines(),
    },
    "source": source_facts(),
    "manifest": manifest,
    "bootstrap_report": assert_bootstrap_report(manifest, remote, target_branch, target_head),
    "checks": {
        "manifest": "pending",
        "skeleton": "pending",
        "secret_scan": "pending",
        "contract": "pending",
        "surface_ci": "skipped" if skip_surface_ci else "pending",
    },
    "ready_to_commit": False,
}
report["target"]["status_count"] = len(report["target"]["status"])

if report_path is not None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

run_step() {
  local label="$1"
  shift
  echo "public-cutover-closeout: $label"
  "$@"
}

run_step "verify target manifest" \
  "$TARGET_DIR/scripts/public_repo_manifest_check.sh" --staged-output "$TARGET_DIR"

run_step "verify target skeleton" \
  env PUBLIC_SKELETON_REPO_ROOT="$TARGET_DIR" "$TARGET_DIR/scripts/public_repo_skeleton_check.sh"

if [[ -n "$SOURCE_REPO_ROOT" ]]; then
  run_step "scan target and source export history" \
    env PUBLIC_EXPORT_REPO_ROOT="$SOURCE_REPO_ROOT" \
      "$TARGET_DIR/scripts/public_repo_secret_scan.sh" --staged-output "$TARGET_DIR"
else
  run_step "scan target public contents" \
    env PUBLIC_EXPORT_REPO_ROOT="$TARGET_DIR" \
      "$TARGET_DIR/scripts/public_repo_secret_scan.sh" --staged-output "$TARGET_DIR"
fi

if [[ -n "$SOURCE_REPO_ROOT" && -d "$SOURCE_REPO_ROOT/backend" && -d "$SOURCE_REPO_ROOT/frontend" ]]; then
  run_step "verify public/private contracts" \
    "$TARGET_DIR/scripts/public_repo_contract_check.sh" \
      --staged-output "$TARGET_DIR" \
      --private-repo-root "$SOURCE_REPO_ROOT"
else
  run_step "verify public contracts" \
    "$TARGET_DIR/scripts/public_repo_contract_check.sh" --staged-output "$TARGET_DIR"
fi

if [[ "$SKIP_SURFACE_CI" -eq 0 ]]; then
  run_step "run public-surface CI smoke" \
    "$TARGET_DIR/scripts/public_repo_surface_ci.sh" --staged-output "$TARGET_DIR"
fi

python3 - "$TARGET_DIR" "$BOOTSTRAP_REPORT" "$REPORT_PATH" "$SKIP_SURFACE_CI" "$SOURCE_REPO_ROOT" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

target_root = Path(sys.argv[1]).resolve()
bootstrap_report_arg = sys.argv[2]
bootstrap_report_path = Path(bootstrap_report_arg).resolve() if bootstrap_report_arg else None
report_path = Path(sys.argv[3]).resolve() if sys.argv[3] else None
skip_surface_ci = sys.argv[4] == "1"
source_repo_root_arg = sys.argv[5]
source_root = Path(source_repo_root_arg).resolve() if source_repo_root_arg else None
EXPECTED_REMOTE_REPOSITORY = "ottto-ai/ottto"


def die(message: str, code: int = 2) -> None:
    print(f"public-cutover-closeout: {message}", file=sys.stderr)
    sys.exit(code)


def git_output(*args: str, check: bool = False) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(target_root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        if check:
            die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip() or None


def git_output_at(root: Path, *args: str, check: bool = False) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        if check:
            die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return None
    return proc.stdout.strip() or None


def source_facts() -> dict[str, Any]:
    if source_root is None:
        return {
            "provided": False,
            "private_consumer_contracts": False,
            "secret_scan_scope": "target_only",
            "contract_scope": "public_only",
        }
    has_private_contracts = (source_root / "backend").is_dir() and (source_root / "frontend").is_dir()
    return {
        "provided": True,
        "head": git_output_at(source_root, "rev-parse", "HEAD", check=True),
        "private_consumer_contracts": has_private_contracts,
        "secret_scan_scope": "target_and_source_history",
        "contract_scope": "public_private" if has_private_contracts else "public_only",
    }


def target_remote_facts() -> dict[str, str]:
    remote_url = git_output("remote", "get-url", "origin")
    if remote_url is None:
        die("target origin remote is missing")
    if remote_url.startswith("git@github.com:"):
        repository = remote_url.removeprefix("git@github.com:")
        url_kind = "ssh"
    elif remote_url.startswith("ssh://git@github.com/"):
        repository = remote_url.removeprefix("ssh://git@github.com/")
        url_kind = "ssh"
    elif remote_url.startswith("https://github.com/"):
        repository = remote_url.removeprefix("https://github.com/")
        url_kind = "https"
    else:
        die("target origin remote must be a GitHub SSH or HTTPS URL")

    repository = repository.removesuffix(".git").strip("/")
    if repository != EXPECTED_REMOTE_REPOSITORY:
        die(f"target origin remote must be {EXPECTED_REMOTE_REPOSITORY}, got {repository}")
    return {
        "name": "origin",
        "repository": repository,
        "url_kind": url_kind,
    }


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        die(f"{label} is missing: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        die(f"{label} is invalid JSON: {error}")
    if not isinstance(value, dict):
        die(f"{label} must be a JSON object")
    return value


def manifest_facts() -> dict[str, Any]:
    manifest = load_json(target_root / "PUBLIC_EXPORT_MANIFEST.json", "public export manifest")
    files = manifest.get("files")
    public_roots = manifest.get("public_roots")
    return {
        "schema_version": manifest.get("schema_version"),
        "source_commit": manifest.get("source_commit"),
        "candidate_file_count": manifest.get("candidate_file_count"),
        "output_file_count": manifest.get("output_file_count"),
        "file_record_count": len(files) if isinstance(files, list) else None,
        "content_sha256": manifest.get("content_sha256"),
        "public_roots": public_roots if isinstance(public_roots, list) else [],
    }


def status_lines() -> list[str]:
    output = git_output("status", "--porcelain=v1", "--untracked-files=all")
    if not output:
        return []
    return output.splitlines()


def bootstrap_facts(
    manifest: dict[str, Any],
    expected_remote: dict[str, str],
    current_branch: str | None,
    current_head: str | None,
) -> dict[str, Any]:
    if bootstrap_report_path is None:
        return {"provided": False}
    report = load_json(bootstrap_report_path, "bootstrap report")
    bundle = report.get("bundle")
    post_apply = report.get("post_apply_public_checks")
    if not isinstance(bundle, dict):
        die("bootstrap report is missing bundle facts")
    if bundle.get("content_sha256") != manifest.get("content_sha256"):
        die("bootstrap report bundle digest does not match target manifest")
    target = report.get("target")
    if not isinstance(target, dict):
        die("bootstrap report is missing target facts")
    target_remote = target.get("remote")
    if target_remote != expected_remote:
        die("bootstrap report target remote does not match current target origin")
    target_branch = target.get("branch")
    if target_branch != current_branch:
        die("bootstrap report target branch does not match current target branch")
    target_head_before = target.get("head_before")
    if target_head_before != current_head:
        die("bootstrap report target head_before does not match current target head")
    return {
        "provided": True,
        "schema_version": report.get("schema_version"),
        "generated_by": report.get("generated_by"),
        "mode": report.get("mode"),
        "applied": report.get("applied"),
        "target_branch": target_branch,
        "target_head_before": target_head_before,
        "target_remote": target_remote,
        "content_sha256": bundle.get("content_sha256"),
        "output_file_count": bundle.get("output_file_count"),
        "file_record_count": bundle.get("file_record_count"),
        "post_apply_public_checks": post_apply,
    }


manifest = manifest_facts()
remote = target_remote_facts()
target_branch = git_output("branch", "--show-current")
target_head = git_output("rev-parse", "HEAD")
report = {
    "schema_version": 1,
    "generated_by": "public_repo_cutover_closeout.sh",
    "mode": "target_closeout",
    "target": {
        "branch": target_branch,
        "head": target_head,
        "remote": remote,
        "status": status_lines(),
    },
    "source": source_facts(),
    "manifest": manifest,
    "bootstrap_report": bootstrap_facts(manifest, remote, target_branch, target_head),
    "checks": {
        "manifest": "passed",
        "skeleton": "passed",
        "secret_scan": "passed",
        "contract": "passed",
        "surface_ci": "skipped" if skip_surface_ci else "passed",
    },
    "ready_to_commit": True,
}
report["target"]["status_count"] = len(report["target"]["status"])

serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
forbidden_fragments = (
    "/" + "private/",
    "/" + "Users/",
    "/var/" + "folders/",
)
for forbidden in forbidden_fragments:
    if forbidden in serialized:
        die(f"closeout report contains local filesystem path fragment: {forbidden}")

if report_path is not None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(serialized, encoding="utf-8")

print(
    "public-cutover-closeout: ready_to_commit=true "
    f"status_count={report['target']['status_count']} "
    f"content_sha256={manifest['content_sha256']}"
)
if report_path is not None:
    print("public-cutover-closeout: wrote path-safe report")
PY
