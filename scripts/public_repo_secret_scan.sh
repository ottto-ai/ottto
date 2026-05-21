#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${PUBLIC_EXPORT_REPO_ROOT:-}" ]]; then
  REPO_ROOT="$PUBLIC_EXPORT_REPO_ROOT"
else
  REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
fi
if [[ -d "$REPO_ROOT/tools/ottto-local-platform/public-export" ]]; then
  DEFAULT_CONFIG_DIR="$REPO_ROOT/tools/ottto-local-platform/public-export"
else
  DEFAULT_CONFIG_DIR="$REPO_ROOT/public-export"
fi
CONFIG_DIR="${PUBLIC_EXPORT_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
ROOTS_FILE="${PUBLIC_EXPORT_ROOTS_FILE:-$CONFIG_DIR/roots.txt}"
DENY_PATTERNS_FILE="${PUBLIC_EXPORT_DENY_PATTERNS_FILE:-$CONFIG_DIR/deny-patterns.tsv}"
STAGED_OUTPUT_DIR=""

usage() {
  cat <<'USAGE'
Usage: public_repo_secret_scan.sh [--staged-output <dir>]

Scans the public export candidate set for private paths and secret-like content
before public repo bootstrap. The scan covers:

- current tracked export candidates
- historical blobs for paths that ever lived under export roots
- optional root-shaped staged bundle output

Override PUBLIC_EXPORT_REPO_ROOT or PUBLIC_EXPORT_*_FILE environment variables
for tests.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --staged-output)
      [[ "$#" -ge 2 ]] || {
        echo "public-secret-scan: --staged-output requires a value" >&2
        exit 2
      }
      STAGED_OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-secret-scan: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

python3 - "$REPO_ROOT" "$ROOTS_FILE" "$DENY_PATTERNS_FILE" "$STAGED_OUTPUT_DIR" <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
roots_file = Path(sys.argv[2]).resolve()
deny_patterns_file = Path(sys.argv[3]).resolve()
staged_output_arg = sys.argv[4]
staged_output_dir = Path(staged_output_arg).resolve() if staged_output_arg else None


def die(message: str, code: int = 2) -> None:
    print(f"public-secret-scan: {message}", file=sys.stderr)
    sys.exit(code)


def git_lines(*args: str, check: bool = True) -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.splitlines() if line]


def config_lines(path: Path) -> list[str]:
    if not path.is_file():
        die(f"required file is missing: {path}")
    rows: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            rows.append(raw)
    return rows


def compile_posix_ere(pattern: str) -> re.Pattern[str]:
    pattern = pattern.replace("[[:space:]]", r"\s")
    return re.compile(pattern)


def load_denies() -> list[tuple[str, re.Pattern[str], str, str]]:
    denies: list[tuple[str, re.Pattern[str], str, str]] = []
    for line in config_lines(deny_patterns_file):
        fields = line.split("\t")
        if len(fields) < 3:
            die(f"{deny_patterns_file} contains a malformed row: {line}")
        scope, pattern, description = fields[0], fields[1], fields[2]
        if scope not in {"path", "content"}:
            die(f"unknown deny-pattern scope '{scope}' for {pattern}")
        denies.append((scope, compile_posix_ere(pattern), description, pattern))
    return denies


def tracked_candidates() -> list[str]:
    candidates: list[str] = []
    for root_entry in config_lines(roots_file):
        matches: list[str] = []
        if not root_entry.endswith("/"):
            code = subprocess.run(
                ["git", "-C", str(repo_root), "ls-files", "--error-unmatch", root_entry],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            if code.returncode == 0:
                matches = [line for line in code.stdout.splitlines() if line]
        if not matches:
            matches = git_lines("ls-files", root_entry)
        if not matches:
            die(f"export root has no tracked files: {root_entry}", code=1)
        candidates.extend(matches)
    return sorted(set(candidates))


def historical_paths(current_candidates: list[str]) -> list[str]:
    paths: set[str] = set(current_candidates)
    for root_entry in config_lines(roots_file):
        paths.update(git_lines("log", "--all", "--name-only", "--format=", "--", root_entry))
    return sorted(path for path in paths if path)


def is_self_check_fixture(path: str) -> bool:
    return path in {
        "tools/ottto-local-platform/public-export/deny-patterns.tsv",
        "tools/ottto-local-platform/public-export/rewrite-rules.tsv",
        "tools/ottto-local-platform/scripts/test_public_repo_bootstrap_plan.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_contract_check.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_cutover_closeout.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_export_check.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_export_bundle.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_manifest_check.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_skeleton_check.sh",
        "tools/ottto-local-platform/scripts/test_public_repo_secret_scan.sh",
        "public-export/deny-patterns.tsv",
        "public-export/rewrite-rules.tsv",
        "scripts/test_public_repo_bootstrap_plan.sh",
        "scripts/test_public_repo_contract_check.sh",
        "scripts/test_public_repo_cutover_closeout.sh",
        "scripts/test_public_repo_export_check.sh",
        "scripts/test_public_repo_export_bundle.sh",
        "scripts/test_public_repo_manifest_check.sh",
        "scripts/test_public_repo_skeleton_check.sh",
        "scripts/test_public_repo_secret_scan.sh",
    }


def scan_path_denies(paths: list[str], denies: list[tuple[str, re.Pattern[str], str, str]], label: str, failures: list[str]) -> None:
    for path in paths:
        for scope, regex, description, _pattern in denies:
            if scope == "path" and regex.search(path):
                failures.append(f"{label} path denied: {description}: {path}")


def scan_text(
    text: str,
    path: str,
    origin: str,
    denies: list[tuple[str, re.Pattern[str], str, str]],
    failures: list[str],
) -> None:
    if is_self_check_fixture(path):
        return
    for line_number, line in enumerate(text.splitlines(), start=1):
        for scope, regex, description, _pattern in denies:
            if scope == "content" and regex.search(line):
                failures.append(f"{origin}: {description}: {path}:{line_number}")


def scan_current_files(candidates: list[str], denies: list[tuple[str, re.Pattern[str], str, str]], failures: list[str]) -> None:
    for path in candidates:
        if is_self_check_fixture(path):
            continue
        abs_path = repo_root / path
        try:
            text = abs_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = abs_path.read_bytes().decode("utf-8", errors="ignore")
        scan_text(text, path, "current content denied", denies, failures)


def blob_exists(commit: str, path: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}:{path}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def read_blob(commit: str, path: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{commit}:{path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", errors="ignore")


def scan_history(paths: list[str], denies: list[tuple[str, re.Pattern[str], str, str]], failures: list[str]) -> int:
    blob_count = 0
    for path in paths:
        if is_self_check_fixture(path):
            continue
        commits = git_lines("log", "--all", "--format=%H", "--", path, check=False)
        for commit in commits:
            if not blob_exists(commit, path):
                continue
            blob_count += 1
            text = read_blob(commit, path)
            short = commit[:12]
            scan_text(text, path, f"historical content denied at {short}", denies, failures)
    return blob_count


def scan_staged_output(staged_root: Path, denies: list[tuple[str, re.Pattern[str], str, str]], failures: list[str]) -> int:
    if not staged_root.is_dir():
        die(f"staged output directory is not a directory: {staged_root}")
    files = sorted(path for path in staged_root.rglob("*") if path.is_file())
    rel_paths = [path.relative_to(staged_root).as_posix() for path in files]
    scan_path_denies(rel_paths, denies, "staged output", failures)
    for file_path, rel in zip(files, rel_paths):
        if is_self_check_fixture(rel):
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = file_path.read_bytes().decode("utf-8", errors="ignore")
        scan_text(text, rel, "staged output content denied", denies, failures)
    return len(files)


if not repo_root.is_dir():
    die(f"repo root is not a directory: {repo_root}")
subprocess.run(["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.DEVNULL)

denies = load_denies()
current = tracked_candidates()
history_paths = historical_paths(current)
failures: list[str] = []

scan_path_denies(current, denies, "current export", failures)
scan_path_denies(history_paths, denies, "historical export", failures)
scan_current_files(current, denies, failures)
history_blob_count = scan_history(history_paths, denies, failures)
staged_count = scan_staged_output(staged_output_dir, denies, failures) if staged_output_dir else 0

if failures:
    for failure in failures:
        print(f"public-secret-scan: {failure}", file=sys.stderr)
    die(
        "failed with "
        f"{len(failures)} issue(s) across {len(current)} current candidate file(s), "
        f"{len(history_paths)} historical path(s), {history_blob_count} historical blob(s), "
        f"and {staged_count} staged output file(s)",
        code=1,
    )

print(
    "public-secret-scan: checked "
    f"{len(current)} current candidate file(s), {len(history_paths)} historical path(s), "
    f"{history_blob_count} historical blob(s), {staged_count} staged output file(s)"
)
PY
