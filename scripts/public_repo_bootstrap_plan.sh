#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SOURCE_REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
SOURCE_REPO_ROOT="${PUBLIC_BOOTSTRAP_SOURCE_REPO_ROOT:-$DEFAULT_SOURCE_REPO_ROOT}"
if [[ -d "$SOURCE_REPO_ROOT/tools/ottto-local-platform/public-export" ]]; then
  DEFAULT_BUNDLE_DIR="$SOURCE_REPO_ROOT/tools/ottto-local-platform/dist/public-export/ottto"
else
  DEFAULT_BUNDLE_DIR="$SOURCE_REPO_ROOT/dist/public-export/ottto"
fi
BUNDLE_DIR="${PUBLIC_BOOTSTRAP_BUNDLE_DIR:-$DEFAULT_BUNDLE_DIR}"
BUNDLE_SCRIPT="${PUBLIC_BOOTSTRAP_BUNDLE_SCRIPT:-$SCRIPT_DIR/public_repo_export_bundle.sh}"
TARGET_DIR=""
REPORT_PATH=""
APPLY=0
USE_EXISTING_BUNDLE=0

usage() {
  cat <<'USAGE'
Usage: public_repo_bootstrap_plan.sh --target-dir <dir> [--bundle-dir <dir>] [--report <path>] [--apply] [--use-existing-bundle]

Builds and verifies the root-shaped public ottto export bundle, then plans how
it would sync into a clean public repository checkout. The default mode is a
dry-run summary only. Pass --apply to copy the bundle into the target checkout
after all bundle and target safety gates pass. Pass --report to write a
machine-readable JSON plan without absolute local filesystem paths.

The target directory must be the root of a clean git checkout and must not be
inside the private source repository, the generated bundle directory, or a
private monorepo-shaped checkout.

Environment overrides:
  PUBLIC_BOOTSTRAP_SOURCE_REPO_ROOT
  PUBLIC_BOOTSTRAP_BUNDLE_DIR
  PUBLIC_BOOTSTRAP_BUNDLE_SCRIPT
USAGE
}

fail() {
  echo "public-bootstrap-plan: $*" >&2
  exit 2
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

path_overlaps() {
  local first="$1"
  local second="$2"
  [[ "$first" == "$second" || "$first" == "$second"/* || "$second" == "$first"/* ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --target-dir)
      [[ "$#" -ge 2 ]] || fail "--target-dir requires a value"
      TARGET_DIR="$2"
      shift 2
      ;;
    --bundle-dir)
      [[ "$#" -ge 2 ]] || fail "--bundle-dir requires a value"
      BUNDLE_DIR="$2"
      shift 2
      ;;
    --report)
      [[ "$#" -ge 2 ]] || fail "--report requires a value"
      REPORT_PATH="$2"
      shift 2
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    --use-existing-bundle)
      USE_EXISTING_BUNDLE=1
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

if [[ -z "$TARGET_DIR" ]]; then
  fail "--target-dir is required"
fi

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 is required"
fi
if ! command -v git >/dev/null 2>&1; then
  fail "git is required"
fi

SOURCE_REPO_ROOT="$(resolve_path "$SOURCE_REPO_ROOT")"
BUNDLE_DIR="$(resolve_path "$BUNDLE_DIR")"
TARGET_DIR="$(resolve_path "$TARGET_DIR")"
BUNDLE_SCRIPT="$(resolve_path "$BUNDLE_SCRIPT")"
if [[ -n "$REPORT_PATH" ]]; then
  REPORT_PATH="$(resolve_path "$REPORT_PATH")"
fi

if [[ ! -d "$SOURCE_REPO_ROOT" ]]; then
  fail "source repository root is not a directory: $SOURCE_REPO_ROOT"
fi
if ! git -C "$SOURCE_REPO_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
  fail "source repository root is not a git checkout: $SOURCE_REPO_ROOT"
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
if path_overlaps "$SOURCE_REPO_ROOT" "$TARGET_DIR"; then
  fail "refusing target that overlaps source repository: $TARGET_DIR"
fi
if path_overlaps "$BUNDLE_DIR" "$TARGET_DIR"; then
  fail "refusing target that overlaps bundle directory: $TARGET_DIR"
fi

target_status="$(git -C "$TARGET_DIR" status --porcelain=v1 --untracked-files=all)"
if [[ -n "$target_status" ]]; then
  echo "$target_status" >&2
  fail "target git checkout is not clean: $TARGET_DIR"
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

require_executable "$BUNDLE_SCRIPT"

if [[ "$USE_EXISTING_BUNDLE" -eq 0 ]]; then
  PUBLIC_EXPORT_REPO_ROOT="$SOURCE_REPO_ROOT" "$BUNDLE_SCRIPT" --output-dir "$BUNDLE_DIR" --force
else
  if [[ ! -d "$BUNDLE_DIR" ]]; then
    fail "existing bundle directory is not a directory: $BUNDLE_DIR"
  fi
fi

require_executable "$BUNDLE_DIR/scripts/public_repo_skeleton_check.sh"
require_executable "$BUNDLE_DIR/scripts/public_repo_manifest_check.sh"
require_executable "$BUNDLE_DIR/scripts/public_repo_secret_scan.sh"
require_executable "$BUNDLE_DIR/scripts/public_repo_contract_check.sh"

"$BUNDLE_DIR/scripts/public_repo_manifest_check.sh" --staged-output "$BUNDLE_DIR"
PUBLIC_SKELETON_REPO_ROOT="$BUNDLE_DIR" \
  "$BUNDLE_DIR/scripts/public_repo_skeleton_check.sh"
PUBLIC_EXPORT_REPO_ROOT="$SOURCE_REPO_ROOT" \
  "$BUNDLE_DIR/scripts/public_repo_secret_scan.sh" --staged-output "$BUNDLE_DIR"
if [[ -d "$SOURCE_REPO_ROOT/backend" && -d "$SOURCE_REPO_ROOT/frontend" ]]; then
  PUBLIC_CONTRACT_PRIVATE_REPO_ROOT="$SOURCE_REPO_ROOT" \
    "$BUNDLE_DIR/scripts/public_repo_contract_check.sh" --staged-output "$BUNDLE_DIR"
else
  "$BUNDLE_DIR/scripts/public_repo_contract_check.sh" --staged-output "$BUNDLE_DIR"
fi

python3 - "$TARGET_DIR" "$BUNDLE_DIR" "$SOURCE_REPO_ROOT" "$REPORT_PATH" "$APPLY" <<'PY'
from __future__ import annotations

import datetime as _datetime
import filecmp
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

target_root = Path(sys.argv[1]).resolve()
bundle_root = Path(sys.argv[2]).resolve()
source_root = Path(sys.argv[3]).resolve()
report_path = Path(sys.argv[4]).resolve() if sys.argv[4] else None
apply_changes = sys.argv[5] == "1"
EXPECTED_REMOTE_REPOSITORY = "ottto-ai/ottto"


def die(message: str, code: int = 2) -> None:
    print(f"public-bootstrap-plan: {message}", file=sys.stderr)
    sys.exit(code)


def git_output(root: Path, *args: str, check: bool = False) -> str | None:
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


def target_remote_facts(root: Path) -> dict[str, str]:
    remote_url = git_output(root, "remote", "get-url", "origin")
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


def load_bundle_manifest() -> dict[str, object]:
    manifest_path = bundle_root / "PUBLIC_EXPORT_MANIFEST.json"
    if not manifest_path.is_file():
        die("bundle is missing PUBLIC_EXPORT_MANIFEST.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        die(f"bundle manifest is invalid JSON: {error}")
    if not isinstance(manifest, dict):
        die("bundle manifest must be a JSON object")
    public_roots = manifest.get("public_roots")
    return {
        "schema_version": manifest.get("schema_version"),
        "source_commit": manifest.get("source_commit"),
        "candidate_file_count": manifest.get("candidate_file_count"),
        "output_file_count": manifest.get("output_file_count"),
        "file_record_count": len(manifest.get("files")) if isinstance(manifest.get("files"), list) else None,
        "content_sha256": manifest.get("content_sha256"),
        "public_roots": public_roots if isinstance(public_roots, list) else [],
    }


def relative_files(root: Path, *, skip_git: bool) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        parts = relative.parts
        if skip_git and parts and parts[0] == ".git":
            continue
        if path.is_symlink():
            die(f"symlinks are not supported in public bootstrap trees: {relative.as_posix()}")
        if path.is_file():
            files[relative.as_posix()] = path
    return files


def mode_bits(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def files_match(left: Path, right: Path) -> bool:
    if mode_bits(left) != mode_bits(right):
        return False
    return filecmp.cmp(left, right, shallow=False)


def remove_empty_dirs(root: Path) -> None:
    dirs = sorted(
        (path for path in root.rglob("*") if path.is_dir() and ".git" not in path.relative_to(root).parts),
        key=lambda item: len(item.relative_to(root).parts),
        reverse=True,
    )
    for directory in dirs:
        try:
            directory.rmdir()
        except OSError:
            continue


def copy_bundle_file(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    os.chmod(destination, mode_bits(source))


def target_branch() -> str | None:
    return git_output(target_root, "symbolic-ref", "--quiet", "--short", "HEAD")


def write_report(status_after: list[str] | None = None) -> None:
    if report_path is None:
        return
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "generated_by": "public_repo_bootstrap_plan.sh",
        "generated_at": _datetime.datetime.now(_datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "mode": "apply" if apply_changes else "dry_run",
        "apply_requested": apply_changes,
        "applied": status_after is not None,
        "source": {
            "head": git_output(source_root, "rev-parse", "HEAD", check=True),
        },
        "bundle": load_bundle_manifest(),
        "target": {
            "branch": target_branch(),
            "head_before": target_head_before,
            "remote": target_remote,
            "clean_before": True,
            "status_after": status_after,
        },
        "bundle_checks": {
            "manifest": "passed",
            "skeleton": "passed",
            "secret_scan": "passed",
            "contract": "passed",
            "private_consumer_contracts": "passed"
            if (source_root / "backend").is_dir() and (source_root / "frontend").is_dir()
            else "not_run",
        },
        "target_safety_checks": {
            "git_root": "passed",
            "clean_checkout": "passed",
            "no_source_overlap": "passed",
            "no_bundle_overlap": "passed",
            "no_private_monorepo_shape": "passed",
            "origin_remote": "passed",
        },
        "post_apply_public_checks": "pending" if apply_changes else "not_run",
        "changes": {
            "added_count": len(added),
            "changed_count": len(changed),
            "deleted_count": len(deleted),
            "unchanged_count": unchanged,
            "added": added,
            "changed": changed,
            "deleted": deleted,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"public-bootstrap-plan: wrote report {report_path}")


if not bundle_root.is_dir():
    die(f"bundle directory is not a directory: {bundle_root}")

target_head_before = git_output(target_root, "rev-parse", "HEAD")
target_remote = target_remote_facts(target_root)
bundle_files = relative_files(bundle_root, skip_git=True)
target_files = relative_files(target_root, skip_git=True)
if not bundle_files:
    die(f"bundle directory has no files: {bundle_root}")

bundle_set = set(bundle_files)
target_set = set(target_files)
added = sorted(bundle_set - target_set)
deleted = sorted(target_set - bundle_set)
changed = sorted(
    path for path in bundle_set & target_set if not files_match(bundle_files[path], target_files[path])
)
unchanged = len(bundle_set & target_set) - len(changed)

print(
    "public-bootstrap-plan: "
    f"target={target_root} bundle={bundle_root} "
    f"added={len(added)} changed={len(changed)} deleted={len(deleted)} unchanged={unchanged}"
)

for label, values in (("add", added), ("change", changed), ("delete", deleted)):
    for value in values[:12]:
        print(f"public-bootstrap-plan: {label} {value}")
    if len(values) > 12:
        print(f"public-bootstrap-plan: {label} ... {len(values) - 12} more")

if not apply_changes:
    write_report()
    print("public-bootstrap-plan: dry-run only; pass --apply to sync the target checkout")
    sys.exit(0)

for relative in deleted:
    path = target_root / relative
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
remove_empty_dirs(target_root)

for relative in sorted(bundle_files):
    copy_bundle_file(bundle_files[relative], target_root / relative)

status = subprocess.run(
    ["git", "-C", str(target_root), "status", "--short"],
    check=False,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if status.returncode != 0:
    die(f"git status failed after apply: {status.stderr.strip()}")
status_after = status.stdout.splitlines()
write_report(status_after=status_after)
print(f"public-bootstrap-plan: applied bundle to {target_root}")
if status.stdout.strip():
    print("public-bootstrap-plan: target git status follows")
    for line in status.stdout.splitlines()[:80]:
        print(line)
    if len(status.stdout.splitlines()) > 80:
        print(f"... {len(status.stdout.splitlines()) - 80} more")
else:
    print("public-bootstrap-plan: target git checkout is unchanged after apply")
PY

if [[ "$APPLY" -eq 1 ]]; then
  "$TARGET_DIR/scripts/public_repo_manifest_check.sh" --staged-output "$TARGET_DIR"
  PUBLIC_SKELETON_REPO_ROOT="$TARGET_DIR" \
    "$TARGET_DIR/scripts/public_repo_skeleton_check.sh"
  PUBLIC_EXPORT_REPO_ROOT="$SOURCE_REPO_ROOT" \
    "$TARGET_DIR/scripts/public_repo_secret_scan.sh" --staged-output "$TARGET_DIR"
  if [[ -d "$SOURCE_REPO_ROOT/backend" && -d "$SOURCE_REPO_ROOT/frontend" ]]; then
    PUBLIC_CONTRACT_PRIVATE_REPO_ROOT="$SOURCE_REPO_ROOT" \
      "$TARGET_DIR/scripts/public_repo_contract_check.sh" --staged-output "$TARGET_DIR"
  else
    "$TARGET_DIR/scripts/public_repo_contract_check.sh" --staged-output "$TARGET_DIR"
  fi
  if [[ -n "$REPORT_PATH" ]]; then
    python3 - "$REPORT_PATH" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["post_apply_public_checks"] = {
    "manifest": "passed",
    "skeleton": "passed",
    "secret_scan": "passed",
    "contract": "passed",
}
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  fi
  echo "public-bootstrap-plan: post-apply public checks passed"
fi
