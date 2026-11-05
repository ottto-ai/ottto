#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${PUBLIC_EXPORT_REPO_ROOT:-}" ]]; then
  REPO_ROOT="$PUBLIC_EXPORT_REPO_ROOT"
else
  REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
fi
CONFIG_DIR="${PUBLIC_EXPORT_CONFIG_DIR:-$REPO_ROOT/public-export}"
DENY_PATTERNS_FILE="${PUBLIC_EXPORT_DENY_PATTERNS_FILE:-$CONFIG_DIR/deny-patterns.tsv}"

usage() {
  cat <<'USAGE'
Usage: public_repo_secret_scan.sh

Scans every committed HEAD blob for forbidden paths and secret-like content.
It reads no history, working files, or untracked files. Symlinks, gitlinks,
unsafe paths, and tracked derived manifests are refused before reads.

The deny policy is the committed public-export/deny-patterns.tsv. Override
PUBLIC_EXPORT_REPO_ROOT, PUBLIC_EXPORT_CONFIG_DIR, or
PUBLIC_EXPORT_DENY_PATTERNS_FILE for tests.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
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

python3 - "$REPO_ROOT" "$DENY_PATTERNS_FILE" <<'PY'
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
deny_patterns_file = Path(sys.argv[2]).resolve()
policy_override = any(name in os.environ for name in ("PUBLIC_EXPORT_CONFIG_DIR", "PUBLIC_EXPORT_DENY_PATTERNS_FILE"))


def die(message: str, code: int = 2) -> None:
    print(f"public-secret-scan: {message}", file=sys.stderr)
    sys.exit(code)


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


def is_self_check_fixture(path: str) -> bool:
    return path in {
        "public-export/deny-patterns.tsv",
        "scripts/test_public_repo_contract_check.sh",
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


if not repo_root.is_dir():
    die(f"repo root is not a directory: {repo_root}")
subprocess.run(["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.DEVNULL)

# Validate the complete tree before reading even the committed deny policy.
entries = committed_entries()
if policy_override:
    policy_rows = config_lines(deny_patterns_file)
else:
    policy_entry = [entry for entry in entries if entry[0] == "public-export/deny-patterns.tsv"]
    if not policy_entry:
        die("required committed deny policy is missing")
    policy_text = list(committed_blobs(policy_entry))[0][1]
    policy_rows = [line for line in policy_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
denies = load_denies()
failures: list[str] = []
scan_committed_tree(entries, denies, failures)

if failures:
    for failure in failures:
        print(f"public-secret-scan: {failure}", file=sys.stderr)
    die(f"failed with {len(failures)} issue(s) across {len(entries)} HEAD blob(s)", code=1)

print(f"public-secret-scan: checked {len(entries)} HEAD blob(s)")
PY
