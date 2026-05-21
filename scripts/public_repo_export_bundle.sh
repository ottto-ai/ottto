#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
REPO_ROOT="${PUBLIC_EXPORT_REPO_ROOT:-$DEFAULT_REPO_ROOT}"
if [[ -d "$REPO_ROOT/tools/ottto-local-platform/public-export" ]]; then
  DEFAULT_CONFIG_DIR="$REPO_ROOT/tools/ottto-local-platform/public-export"
  DEFAULT_OUTPUT_DIR="$REPO_ROOT/tools/ottto-local-platform/dist/public-export/ottto"
else
  DEFAULT_CONFIG_DIR="$REPO_ROOT/public-export"
  DEFAULT_OUTPUT_DIR="$REPO_ROOT/dist/public-export/ottto"
fi
CONFIG_DIR="${PUBLIC_EXPORT_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
ROOTS_FILE="${PUBLIC_EXPORT_ROOTS_FILE:-$CONFIG_DIR/roots.txt}"
PATH_MAP_FILE="${PUBLIC_EXPORT_PATH_MAP_FILE:-$CONFIG_DIR/path-map.tsv}"
REWRITE_RULES_FILE="${PUBLIC_EXPORT_REWRITE_RULES_FILE:-$CONFIG_DIR/rewrite-rules.tsv}"
DENY_PATTERNS_FILE="${PUBLIC_EXPORT_DENY_PATTERNS_FILE:-$CONFIG_DIR/deny-patterns.tsv}"
CHECK_SCRIPT="${PUBLIC_EXPORT_CHECK_SCRIPT:-$SCRIPT_DIR/public_repo_export_check.sh}"
OUTPUT_DIR="${PUBLIC_EXPORT_OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}"
FORCE=0
ALLOW_REWRITES=0

usage() {
  cat <<'USAGE'
Usage: public_repo_export_bundle.sh [--output-dir <dir>] [--force] [--allow-rewrites]

Builds a root-shaped staging tree for the future public ottto repository. The
script first runs public_repo_export_check.sh in no-rewrite mode, then copies
only tracked export roots, applies the path map, writes PUBLIC_EXPORT_MANIFEST.json,
and scans the staged output before replacing the output directory.

Use --allow-rewrites only for legacy/test fixtures. Public-v1 bootstrap should
fail until source files already use public repository names.

Environment overrides:
  PUBLIC_EXPORT_REPO_ROOT
  PUBLIC_EXPORT_CONFIG_DIR
  PUBLIC_EXPORT_ROOTS_FILE
  PUBLIC_EXPORT_PATH_MAP_FILE
  PUBLIC_EXPORT_REWRITE_RULES_FILE
  PUBLIC_EXPORT_DENY_PATTERNS_FILE
  PUBLIC_EXPORT_CHECK_SCRIPT
  PUBLIC_EXPORT_OUTPUT_DIR
USAGE
}

fail() {
  echo "public-export-bundle: $*" >&2
  exit 2
}

require_file() {
  if [[ ! -f "$1" ]]; then
    fail "required file is missing: $1"
  fi
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ "$#" -ge 2 ]] || fail "--output-dir requires a value"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --allow-rewrites)
      ALLOW_REWRITES=1
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

require_file "$ROOTS_FILE"
require_file "$PATH_MAP_FILE"
require_file "$REWRITE_RULES_FILE"
require_file "$DENY_PATTERNS_FILE"
require_file "$CHECK_SCRIPT"

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 is required"
fi

if [[ "$ALLOW_REWRITES" == "1" ]]; then
  PUBLIC_EXPORT_REPO_ROOT="$REPO_ROOT" \
    PUBLIC_EXPORT_CONFIG_DIR="$CONFIG_DIR" \
    PUBLIC_EXPORT_ROOTS_FILE="$ROOTS_FILE" \
    PUBLIC_EXPORT_REWRITE_RULES_FILE="$REWRITE_RULES_FILE" \
    PUBLIC_EXPORT_DENY_PATTERNS_FILE="$DENY_PATTERNS_FILE" \
    "$CHECK_SCRIPT"
else
  PUBLIC_EXPORT_REPO_ROOT="$REPO_ROOT" \
    PUBLIC_EXPORT_CONFIG_DIR="$CONFIG_DIR" \
    PUBLIC_EXPORT_ROOTS_FILE="$ROOTS_FILE" \
    PUBLIC_EXPORT_REWRITE_RULES_FILE="$REWRITE_RULES_FILE" \
    PUBLIC_EXPORT_DENY_PATTERNS_FILE="$DENY_PATTERNS_FILE" \
    "$CHECK_SCRIPT" --require-no-rewrites
fi

python3 - "$REPO_ROOT" "$ROOTS_FILE" "$PATH_MAP_FILE" "$REWRITE_RULES_FILE" "$DENY_PATTERNS_FILE" "$OUTPUT_DIR" "$FORCE" "$ALLOW_REWRITES" <<'PY'
import datetime as _datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

repo_root = Path(sys.argv[1]).resolve()
roots_file = Path(sys.argv[2]).resolve()
path_map_file = Path(sys.argv[3]).resolve()
rewrite_rules_file = Path(sys.argv[4]).resolve()
deny_patterns_file = Path(sys.argv[5]).resolve()
output_dir = Path(sys.argv[6]).resolve()
force = sys.argv[7] == "1"
allow_rewrites = sys.argv[8] == "1"


def die(message: str, code: int = 2) -> None:
    print(f"public-export-bundle: {message}", file=sys.stderr)
    sys.exit(code)


def config_lines(path: Path) -> list[str]:
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(raw)
    return lines


def parse_tsv(path: Path, min_fields: int) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in config_lines(path):
        fields = line.split("\t")
        if len(fields) < min_fields:
            die(f"{path} contains a malformed row: {line}")
        rows.append(fields)
    return rows


def git_lines(*args: str, check: bool = True) -> tuple[int, list[str], str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        die(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.returncode, [line for line in proc.stdout.splitlines() if line], proc.stderr


def tracked_candidates() -> list[str]:
    candidates: list[str] = []
    for root_entry in config_lines(roots_file):
        matches: list[str] = []
        if not root_entry.endswith("/"):
            code, exact, _stderr = git_lines("ls-files", "--error-unmatch", root_entry, check=False)
            if code == 0:
                matches = exact
        if not matches:
            _code, matches, _stderr = git_lines("ls-files", root_entry)
        if not matches:
            die(f"export root has no tracked files: {root_entry}", code=1)
        candidates.extend(matches)
    return sorted(set(candidates))


def load_path_map() -> list[tuple[str, str, str]]:
    rows = parse_tsv(path_map_file, 2)
    rules: list[tuple[str, str, str]] = []
    for row in rows:
        source_prefix = row[0].strip()
        destination_prefix = row[1].strip()
        reason = row[2].strip() if len(row) > 2 else ""
        if not source_prefix:
            die(f"{path_map_file} contains an empty source prefix")
        if source_prefix.startswith("/") or destination_prefix.startswith("/"):
            die(f"{path_map_file} paths must be repository-relative")
        rules.append((source_prefix, destination_prefix, reason))
    return sorted(rules, key=lambda item: len(item[0]), reverse=True)


path_rules = load_path_map()


def validate_destination(path: str, source_path: str) -> str:
    if not path or path.startswith("/"):
        die(f"path map produced an invalid destination for {source_path}: {path}")
    parts = PurePosixPath(path).parts
    if any(part in ("", ".", "..") for part in parts):
        die(f"path map produced an unsafe destination for {source_path}: {path}")
    return "/".join(parts)


def map_candidate(source_path: str) -> str:
    for source_prefix, destination_prefix, _reason in path_rules:
        if source_prefix.endswith("/"):
            if not source_path.startswith(source_prefix):
                continue
            relative = source_path[len(source_prefix):]
        elif source_path == source_prefix:
            relative = PurePosixPath(source_path).name
        elif source_path.startswith(f"{source_prefix.rstrip('/')}/"):
            relative = source_path[len(source_prefix.rstrip('/')) + 1 :]
        else:
            continue

        if destination_prefix in ("", "."):
            destination = relative
        elif relative:
            destination = f"{destination_prefix.rstrip('/')}/{relative}"
        else:
            destination = destination_prefix.rstrip("/")
        return validate_destination(destination, source_path)
    die(f"no public path-map rule matched tracked file: {source_path}")
    raise AssertionError("unreachable")


def map_root_entry(root_entry: str) -> str:
    source = root_entry
    trailing_slash = source.endswith("/")
    if trailing_slash:
        source_probe = f"{source}__placeholder__"
    else:
        source_probe = source
    mapped_probe = map_candidate(source_probe)
    if trailing_slash:
        placeholder = "__placeholder__"
        if not mapped_probe.endswith(placeholder):
            die(f"path map produced an invalid directory root for {root_entry}: {mapped_probe}")
        mapped = mapped_probe[: -len(placeholder)]
        return mapped if mapped.endswith("/") else f"{mapped}/"
    return mapped_probe


def load_rewrites() -> list[tuple[str, str, str]]:
    rewrites: list[tuple[str, str, str]] = []
    for row in parse_tsv(rewrite_rules_file, 2):
        literal = row[0]
        replacement = row[1]
        reason = row[2] if len(row) > 2 else ""
        if literal:
            rewrites.append((literal, replacement, reason))
    return rewrites


def compile_posix_ere(pattern: str) -> re.Pattern[str]:
    pattern = pattern.replace("[[:space:]]", r"\s")
    return re.compile(pattern)


def load_denies() -> list[tuple[str, re.Pattern[str], str, str]]:
    denies: list[tuple[str, re.Pattern[str], str, str]] = []
    for row in parse_tsv(deny_patterns_file, 3):
        scope, pattern, description = row[0], row[1], row[2]
        if scope not in ("path", "content"):
            die(f"unknown deny-pattern scope '{scope}' for {pattern}")
        denies.append((scope, compile_posix_ere(pattern), description, pattern))
    return denies


def is_self_check_fixture(destination: str) -> bool:
    return destination in {
        "public-export/deny-patterns.tsv",
        "public-export/rewrite-rules.tsv",
        "scripts/test_public_repo_bootstrap_plan.sh",
        "scripts/test_public_repo_cutover_closeout.sh",
        "scripts/test_public_repo_export_check.sh",
        "scripts/test_public_repo_export_bundle.sh",
        "scripts/test_public_repo_manifest_check.sh",
        "scripts/test_public_repo_skeleton_check.sh",
        "scripts/test_public_repo_secret_scan.sh",
    }


def prepare_output() -> Path:
    if output_dir == Path("/") or output_dir == repo_root or output_dir in repo_root.parents:
        die(f"refusing unsafe output directory: {output_dir}")
    if output_dir.exists() and any(output_dir.iterdir()) and not force:
        die(f"output directory is not empty; pass --force to replace it: {output_dir}")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = output_dir.parent / f".{output_dir.name}.tmp-{os.getpid()}"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)
    return temp_dir


def write_special_public_export_files(temp_dir: Path, mapped_roots: list[str]) -> None:
    public_export_dir = temp_dir / "public-export"
    public_export_dir.mkdir(parents=True, exist_ok=True)

    roots_dest = temp_dir / "public-export" / "roots.txt"
    roots_dest.write_text(
        "# Tracked public repository export roots.\n"
        + "\n".join(mapped_roots)
        + "\n",
        encoding="utf-8",
    )

    path_map_dest = temp_dir / "public-export" / "path-map.tsv"
    path_map_lines = ["# source_prefix\tdestination_prefix\treason"]
    for root in mapped_roots:
        if root.endswith("/"):
            path_map_lines.append(f"{root}\t{root}\tPublic repository root is already in export shape.")
        else:
            parent = PurePosixPath(root).parent.as_posix()
            destination_prefix = "." if parent == "." else parent
            path_map_lines.append(
                f"{root}\t{destination_prefix}\tPublic repository root file is already in export shape."
            )
    path_map_dest.write_text("\n".join(path_map_lines) + "\n", encoding="utf-8")

    rewrite_rules_dest = temp_dir / "public-export" / "rewrite-rules.tsv"
    rewrite_rules_dest.write_text(
        "# literal\treplacement\treason\n"
        "# No private repository rewrite rules should remain after staging.\n",
        encoding="utf-8",
    )


def copy_candidates(temp_dir: Path, candidates: list[str], rewrites: list[tuple[str, str, str]]) -> tuple[dict[str, str], dict[str, int]]:
    destinations: dict[str, str] = {}
    rewrite_counts: dict[str, int] = {replacement: 0 for _literal, replacement, _reason in rewrites}
    for source_path in candidates:
        destination = map_candidate(source_path)
        previous = destinations.get(destination)
        if previous and previous != source_path:
            die(f"path map collision: {previous} and {source_path} both map to {destination}")
        destinations[destination] = source_path

        source_abs = repo_root / source_path
        dest_abs = temp_dir / destination
        dest_abs.parent.mkdir(parents=True, exist_ok=True)
        data = source_abs.read_bytes()
        output = data
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None and not is_self_check_fixture(destination):
            for literal, replacement, _reason in rewrites:
                count = text.count(literal)
                if count:
                    rewrite_counts[replacement] = rewrite_counts.get(replacement, 0) + count
                    text = text.replace(literal, replacement)
            output = text.encode("utf-8")
        dest_abs.write_bytes(output)
        os.chmod(dest_abs, stat.S_IMODE(source_abs.stat().st_mode))
    return destinations, rewrite_counts


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_records(temp_dir: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    paths = sorted(temp_dir.rglob("*"), key=lambda item: item.relative_to(temp_dir).as_posix())
    for path in paths:
        if not path.is_file():
            continue
        relative = path.relative_to(temp_dir).as_posix()
        if relative == "PUBLIC_EXPORT_MANIFEST.json":
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        records.append(
            {
                "path": relative,
                "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size,
                "mode": f"{mode:04o}",
                "executable": bool(mode & 0o111),
            }
        )
    return records


def file_records_digest(records: list[dict[str, object]]) -> str:
    payload = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_manifest(temp_dir: Path, candidate_count: int, rewrite_counts: dict[str, int], mapped_roots: list[str]) -> None:
    _code, commit_lines, _stderr = git_lines("rev-parse", "HEAD")
    records = file_records(temp_dir)
    manifest = {
        "schema_version": 1,
        "generated_by": "public_repo_export_bundle.sh",
        "generated_at": _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "source_commit": commit_lines[0],
        "candidate_file_count": candidate_count,
        "output_file_count": len(records) + 1,
        "public_roots": mapped_roots,
        "rewrites_applied": {key: count for key, count in rewrite_counts.items() if count},
        "files": records,
        "content_sha256": file_records_digest(records),
    }
    (temp_dir / "PUBLIC_EXPORT_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def scan_staged_output(temp_dir: Path, denies: list[tuple[str, re.Pattern[str], str, str]], rewrites: list[tuple[str, str, str]]) -> None:
    failures: list[str] = []
    staged_files = sorted(path for path in temp_dir.rglob("*") if path.is_file())
    for path in staged_files:
        rel = path.relative_to(temp_dir).as_posix()
        for scope, regex, description, _pattern in denies:
            if scope == "path" and regex.search(rel):
                failures.append(f"{description}: {rel}")
        if is_self_check_fixture(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_bytes().decode("utf-8", errors="ignore")
        for scope, regex, description, _pattern in denies:
            if scope == "content":
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if regex.search(line):
                        failures.append(f"{description}: {rel}:{line_number}")
        for literal, replacement, _reason in rewrites:
            if literal and literal != replacement and literal in text:
                failures.append(f"rewrite literal remained after staging: {rel} contains {literal!r}")
    if failures:
        for failure in failures:
            print(f"public-export-bundle: {failure}", file=sys.stderr)
        die(f"staged output failed with {len(failures)} issue(s)", code=1)


candidates = tracked_candidates()
mapped_roots = sorted(set(map_root_entry(root) for root in config_lines(roots_file)))
rewrites = load_rewrites()
denies = load_denies()
temp = prepare_output()
try:
    destinations, rewrite_counts = copy_candidates(temp, candidates, rewrites)
    if not allow_rewrites and sum(rewrite_counts.values()) > 0:
        die(
            "rewrite rules were applied; fix source files before public bootstrap "
            "or pass --allow-rewrites only for legacy/test fixtures",
            code=1,
        )
    write_special_public_export_files(temp, mapped_roots)
    write_manifest(temp, len(candidates), rewrite_counts, mapped_roots)
    scan_staged_output(temp, denies, rewrites)
    os.replace(temp, output_dir)
except BaseException:
    shutil.rmtree(temp, ignore_errors=True)
    raise

final_output_count = sum(1 for path in output_dir.rglob("*") if path.is_file())
print(
    "public-export-bundle: wrote "
    f"{output_dir} with {len(candidates)} source file(s), "
    f"{final_output_count} output file(s), rewrites applied: {sum(rewrite_counts.values())}"
)
PY
