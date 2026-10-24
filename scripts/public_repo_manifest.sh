#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$DEFAULT_REPO_ROOT"
COMMIT="HEAD"
ACTION=""
COMPARE_PATH=""

usage() {
  cat <<'USAGE'
Usage: public_repo_manifest.sh [--repo <dir>] [--commit <rev>] (--digest | --facts | --compare <manifest.json> | --guard)

Derives the public export manifest of a root-shaped public ottto checkout from
the git tree of one commit. PUBLIC_EXPORT_MANIFEST.json is not committed: every
tracked file except a root PUBLIC_EXPORT_MANIFEST.json becomes one record with
path, SHA-256, size, mode (0644, or 0755 for executable blobs), and executable
bit, and content_sha256 is the SHA-256 of those records as compact sorted JSON.
This is the same digest public_repo_export_bundle.sh writes for a bundle
exported from a clean checkout of that commit, so it does not depend on the
working tree, umask, or file system.

Actions:
  --digest            print content_sha256
  --facts             print manifest facts as JSON (content_sha256, counts,
                      source_commit, public_roots)
  --compare <file>    require a manifest file (for example an export bundle's
                      PUBLIC_EXPORT_MANIFEST.json) to equal the derived manifest
  --guard             fail when the commit or the index still tracks a root
                      PUBLIC_EXPORT_MANIFEST.json

--repo must be the top level of a git checkout (default: this script's
repository). --commit defaults to HEAD. Symlinks and submodules are refused.
A commit that still tracks a root PUBLIC_EXPORT_MANIFEST.json (older history)
must match the derived manifest; --digest, --facts, and --compare fail
otherwise. Exit status: 0 ok, 1 mismatch or guard failure, 2 usage or
unsupported tree.
USAGE
}

fail() {
  echo "public-repo-manifest: $*" >&2
  exit 2
}

set_action() {
  if [[ -n "$ACTION" ]]; then
    fail "choose exactly one of --digest, --facts, --compare, --guard"
  fi
  ACTION="$1"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ "$#" -ge 2 ]] || fail "--repo requires a value"
      REPO_ROOT="$2"
      shift 2
      ;;
    --commit)
      [[ "$#" -ge 2 ]] || fail "--commit requires a value"
      COMMIT="$2"
      shift 2
      ;;
    --digest|--facts|--guard)
      set_action "${1#--}"
      shift
      ;;
    --compare)
      [[ "$#" -ge 2 ]] || fail "--compare requires a value"
      set_action compare
      COMPARE_PATH="$2"
      shift 2
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

[[ -n "$ACTION" ]] || fail "choose one of --digest, --facts, --compare, --guard (see --help)"
command -v git >/dev/null 2>&1 || fail "git is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

python3 - "$REPO_ROOT" "$COMMIT" "$ACTION" "$COMPARE_PATH" <<'PY'
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_NAME = "PUBLIC_EXPORT_MANIFEST.json"
RECORD_KEYS = ("path", "sha256", "size_bytes", "mode", "executable")
repo_arg, commit_arg, action, compare_arg = sys.argv[1:5]


def die(message: str, code: int = 2) -> None:
    print(f"public-repo-manifest: {message}", file=sys.stderr)
    sys.exit(code)


def git(*args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        die(f"git {' '.join(args)} failed: {detail}")
    return proc.stdout


repo_path = Path(repo_arg)
if not repo_path.is_dir():
    die(f"repository root is not a directory: {repo_arg}")
repo_root = repo_path.resolve()
# Decide by the checkout's own top level: dist/public-export/ottto lives inside
# the repository, and git would silently answer for the outer checkout.
toplevel = git("rev-parse", "--show-toplevel").decode("utf-8").strip()
if Path(toplevel).resolve() != repo_root:
    die(f"--repo must be the top level of a git checkout: {repo_arg}")

commit_proc = subprocess.run(
    ["git", "-C", str(repo_root), "rev-parse", "--verify", "--quiet", f"{commit_arg}^{{commit}}"],
    check=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)
if commit_proc.returncode != 0:
    die(f"commit not found: {commit_arg}")
commit = commit_proc.stdout.decode("utf-8").strip()


def tree_entries() -> tuple[list[tuple[str, str, str]], str | None]:
    entries: list[tuple[str, str, str]] = []
    manifest_oid: str | None = None
    for raw in git("ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not raw:
            continue
        meta, raw_path = raw.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            die(f"path is not UTF-8: {raw_path!r}")
        parts = PurePosixPath(path).parts
        if not parts or any(part in {"", ".", ".."} for part in parts) or parts[0] == ".git":
            die(f"path is not repository-relative and safe: {path!r}")
        if mode == "120000":
            die(f"public manifest does not support symlinked files: {path}")
        if kind != "blob" or mode not in {"100644", "100755"}:
            die(f"public manifest does not support {kind} entries (mode {mode}): {path}")
        if path == MANIFEST_NAME:
            manifest_oid = oid
            continue
        entries.append((path, mode, oid))
    entries.sort(key=lambda entry: entry[0])
    return entries, manifest_oid


def read_blobs(oids: list[str]) -> list[bytes]:
    proc = subprocess.Popen(
        ["git", "-C", str(repo_root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None
    blobs: list[bytes] = []
    for oid in oids:
        proc.stdin.write(oid.encode("ascii") + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) != 3 or header[1] != b"blob":
            die(f"git cat-file could not read blob {oid}")
        size = int(header[2])
        data = proc.stdout.read(size)
        proc.stdout.read(1)
        blobs.append(data)
    proc.stdin.close()
    if proc.wait() != 0:
        die("git cat-file --batch failed")
    return blobs


def records_digest(records: list[dict[str, Any]]) -> str:
    payload = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def first_record_difference(expected: list[dict[str, Any]], actual: object) -> str:
    if not isinstance(actual, list):
        return "files is not a list"
    actual_by_path: dict[str, object] = {}
    for record in actual:
        if isinstance(record, dict) and isinstance(record.get("path"), str):
            actual_by_path[record["path"]] = record
    expected_by_path = {str(record["path"]): record for record in expected}
    missing = sorted(set(expected_by_path) - set(actual_by_path))
    if missing:
        return f"missing record for {missing[0]}"
    extra = sorted(set(actual_by_path) - set(expected_by_path))
    if extra:
        return f"extra record for {extra[0]}"
    for path, record in expected_by_path.items():
        other = actual_by_path[path]
        assert isinstance(other, dict)
        for key in RECORD_KEYS:
            if other.get(key) != record[key]:
                return f"{key} differs for {path}"
        if set(other) != set(RECORD_KEYS):
            return f"record keys differ for {path}"
    if len(actual) != len(expected):
        return "files contain duplicate or malformed records"
    if actual != expected:
        return "files are not sorted by path"
    return ""


def manifest_difference(manifest: object, records: list[dict[str, Any]], digest: str) -> str:
    if not isinstance(manifest, dict):
        return "manifest is not a JSON object"
    # Name the first differing file before the aggregate fields.
    difference = first_record_difference(records, manifest.get("files"))
    if difference:
        return difference
    if manifest.get("content_sha256") != digest:
        return f"content_sha256 {manifest.get('content_sha256')} != derived {digest}"
    if manifest.get("output_file_count") != len(records) + 1:
        return f"output_file_count {manifest.get('output_file_count')} != derived {len(records) + 1}"
    return ""


def parse_manifest(data: bytes, label: str) -> object:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        die(f"{label} is invalid JSON: {error}", code=1)


entries, tracked_manifest_oid = tree_entries()

if action == "guard":
    tracked_in_index = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "--error-unmatch", "--", MANIFEST_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if tracked_manifest_oid is not None or tracked_in_index:
        where = f"commit {commit[:12]}" if tracked_manifest_oid is not None else "the git index"
        die(
            f"{where} tracks {MANIFEST_NAME}; it is derived from the commit tree and "
            f"must not be committed (scripts/public_repo_manifest.sh --facts): "
            f"git rm {MANIFEST_NAME}",
            code=1,
        )
    print(f"public-repo-manifest: {MANIFEST_NAME} is derived, not tracked, at {commit[:12]}")
    sys.exit(0)

blobs = read_blobs([oid for _path, _mode, oid in entries])
records: list[dict[str, Any]] = []
for (path, mode, _oid), data in zip(entries, blobs):
    file_mode = "0755" if mode == "100755" else "0644"
    records.append(
        {
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
            "mode": file_mode,
            "executable": file_mode == "0755",
        }
    )
digest = records_digest(records)

tracked_manifest = "absent"
if tracked_manifest_oid is not None:
    tracked = parse_manifest(read_blobs([tracked_manifest_oid])[0], f"tracked {MANIFEST_NAME}")
    difference = manifest_difference(tracked, records, digest)
    if difference:
        die(
            f"tracked {MANIFEST_NAME} at {commit[:12]} does not match the commit tree "
            f"({difference}); git rm {MANIFEST_NAME}",
            code=1,
        )
    tracked_manifest = "matches"

if action == "digest":
    print(digest)
elif action == "facts":
    public_roots: list[str] = []
    if any(path == "public-export/roots.txt" for path, _mode, _oid in entries):
        roots_text = git("show", f"{commit}:public-export/roots.txt").decode("utf-8")
        public_roots = sorted(
            {line.strip() for line in roots_text.splitlines() if line.strip() and not line.strip().startswith("#")}
        )
    facts = {
        "schema_version": 1,
        "derived_from": "git_tree",
        "manifest_path": MANIFEST_NAME,
        "source_commit": commit,
        "candidate_file_count": len(records),
        "file_record_count": len(records),
        "output_file_count": len(records) + 1,
        "content_sha256": digest,
        "public_roots": public_roots,
        "tracked_manifest": tracked_manifest,
    }
    print(json.dumps(facts, indent=2, sort_keys=True))
elif action == "compare":
    compare_path = Path(compare_arg)
    if not compare_path.is_file():
        die(f"manifest to compare is missing: {compare_arg}")
    other = parse_manifest(compare_path.read_bytes(), compare_arg)
    difference = manifest_difference(other, records, digest)
    if difference:
        die(f"{compare_arg} does not match the commit tree at {commit[:12]}: {difference}", code=1)
    print(
        f"public-repo-manifest: derived == {compare_arg} at {commit[:12]}: "
        f"content_sha256={digest} file_records={len(records)} output_file_count={len(records) + 1}"
    )
else:
    die(f"unknown action: {action}")
PY
