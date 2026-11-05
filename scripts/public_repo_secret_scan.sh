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

Scans every committed HEAD blob for forbidden paths and secret-like content.
The default reads no history, working files, or untracked files. Symlinks,
gitlinks, unsafe paths, and tracked derived manifests are refused before reads.

--staged-output retains the export candidate/history and staged bundle checks
while export callers migrate.

Override PUBLIC_EXPORT_REPO_ROOT or PUBLIC_EXPORT_*_FILE environment variables
for tests. Set PUBLIC_SECRET_SCAN_ALL_REFS=1 for a whole-local-repository audit
that intentionally scans every local ref.
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

import json
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
legacy_export = staged_output_dir is not None or os.environ.get("PUBLIC_SECRET_SCAN_ALL_REFS") == "1"
policy_override = any(name in os.environ for name in ("PUBLIC_EXPORT_CONFIG_DIR", "PUBLIC_EXPORT_DENY_PATTERNS_FILE"))
scan_all_refs = os.environ.get("PUBLIC_SECRET_SCAN_ALL_REFS") == "1"
history_ref_args = ["--all"] if scan_all_refs else []


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
        die("git command failed")
    return [line for line in proc.stdout.splitlines() if line]


def config_lines(path: Path) -> list[str]:
    if not path.is_file():
        die("required configuration file is missing")
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
    for row_number, line in enumerate(policy_rows, start=1):
        fields = line.split("\t")
        if len(fields) < 3:
            die(f"malformed deny-pattern row {row_number}")
        scope, pattern, description = fields[0], fields[1], fields[2]
        if scope not in {"path", "content"}:
            die(f"unknown deny-pattern scope at row {row_number}")
        try:
            regex = compile_posix_ere(pattern)
        except re.error:
            die(f"invalid deny-pattern regex at row {row_number}")
        denies.append((scope, regex, description, pattern))
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
        paths.update(git_lines("log", *history_ref_args, "--name-only", "--format=", "--", root_entry))
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
                failures.append(f"{label} path denied: {description}: {json.dumps(path, ensure_ascii=True)}:1")


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
                failures.append(f"{origin}: {description}: {json.dumps(path, ensure_ascii=True)}:{line_number}")


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
        commits = git_lines("log", *history_ref_args, "--format=%H", "--", path, check=False)
        for commit in commits:
            if not blob_exists(commit, path):
                continue
            blob_count += 1
            text = read_blob(commit, path)
            short = commit[:12]
            scan_text(text, path, f"historical content denied at {short}", denies, failures)
    return blob_count


def git_bytes(*args: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True)
    if proc.returncode:
        die("git command failed")
    return proc.stdout


FORBIDDEN_PATH = re.compile(
    r"(^|/)(\.claude|\.agents|backend|frontend|infra|dist|target|__pycache__)(/|$)"
    r"|(^|/)tools/ottto-local-platform(/|$)|(^|/)docs/(dev|ai)(/|$)"
    r"|(^|/)[^/]*\.py[co]$|(^|/)\.env(?:\.[^/]*)?(?:/|$)"
    # Current tree only: history still holds these notes, so the tsv must not.
    r"|(^|/)docs/notes(/|$)|(^|/)docs/development(/|$)|(^|/)docs/session-20[0-9][0-9]-"
)

def committed_entries() -> list[tuple[str, str]]:
    entries = []
    for raw in git_bytes("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        if not raw:
            continue
        meta, raw_path = raw.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            die("unsafe non-UTF-8 path", code=1)
        parts = path.split("/")
        location = json.dumps(path, ensure_ascii=True) + ":1"
        if path.startswith("/") or any(part in {"", ".", "..", ".git"} for part in parts):
            die(f"unsafe path: {location}", code=1)
        if mode == "120000":
            die(f"symlink denied: {location}", code=1)
        if kind != "blob" or mode not in {"100644", "100755"}:
            die(f"non-blob or mode denied: {location}", code=1)
        if path == "PUBLIC_EXPORT_MANIFEST.json":
            die(f"derived manifest tracked: {location}", code=1)
        if FORBIDDEN_PATH.search(path):
            die(f"HEAD path denied: {location}", code=1)
        entries.append((path, oid))
    # Preserve the manifest --guard index protection as well as HEAD protection.
    if git_bytes("ls-files", "-z", "--", "PUBLIC_EXPORT_MANIFEST.json"):
        die('derived manifest tracked in index: "PUBLIC_EXPORT_MANIFEST.json":1', code=1)
    return entries


def committed_blobs(entries: list[tuple[str, str]]):
    # Object ids avoid quoting/pathspec ambiguities, including embedded newlines.
    with subprocess.Popen(["git", "-C", str(repo_root), "cat-file", "--batch"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        assert proc.stdin is not None and proc.stdout is not None
        for path, oid in entries:
            proc.stdin.write(oid.encode("ascii") + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                die("committed blob read failed")
            size = int(header[2])
            data = proc.stdout.read(size)
            if len(data) != size or proc.stdout.read(1) != b"\n":
                die("committed blob read failed")
            yield path, data.decode("utf-8", errors="ignore")
        proc.stdin.close()
        if proc.wait():
            die("committed blob read failed")


def scan_committed_tree(entries, denies, failures):
    scan_path_denies([path for path, _oid in entries], denies, "HEAD", failures)
    # Complete all path/mode refusals before opening any content blobs.
    if failures:
        return
    for path, text in committed_blobs(entries):
        scan_text(text, path, "HEAD content denied", denies, failures)


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

# Validate the complete tree before reading even the committed deny policy.
entries = [] if legacy_export else committed_entries()
if legacy_export or policy_override:
    policy_rows = config_lines(deny_patterns_file)
else:
    policy_entry = [entry for entry in entries if entry[0] == "public-export/deny-patterns.tsv"]
    if not policy_entry:
        die("required committed deny policy is missing")
    policy_text = list(committed_blobs(policy_entry))[0][1]
    policy_rows = [line for line in policy_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
denies = load_denies()
failures: list[str] = []
current, history_paths = [], []
history_blob_count = staged_count = 0
if legacy_export:
    current = tracked_candidates()
    history_paths = historical_paths(current)
    scan_path_denies(current, denies, "current export", failures)
    scan_path_denies(history_paths, denies, "historical export", failures)
    scan_current_files(current, denies, failures)
    history_blob_count = scan_history(history_paths, denies, failures)
    staged_count = scan_staged_output(staged_output_dir, denies, failures) if staged_output_dir else 0
else:
    scan_committed_tree(entries, denies, failures)

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
    f"{len(entries)} HEAD blob(s), {len(current)} current candidate file(s), {len(history_paths)} historical path(s), "
    f"{history_blob_count} historical blob(s), {staged_count} staged output file(s)"
)
PY
