#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
REPO_ROOT="${PUBLIC_EXPORT_REPO_ROOT:-$DEFAULT_REPO_ROOT}"
if [[ -d "$REPO_ROOT/tools/ottto-local-platform/public-export" ]]; then
  DEFAULT_CONFIG_DIR="$REPO_ROOT/tools/ottto-local-platform/public-export"
else
  DEFAULT_CONFIG_DIR="$REPO_ROOT/public-export"
fi
CONFIG_DIR="${PUBLIC_EXPORT_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
ROOTS_FILE="${PUBLIC_EXPORT_ROOTS_FILE:-$CONFIG_DIR/roots.txt}"
REWRITE_RULES_FILE="${PUBLIC_EXPORT_REWRITE_RULES_FILE:-$CONFIG_DIR/rewrite-rules.tsv}"
DENY_PATTERNS_FILE="${PUBLIC_EXPORT_DENY_PATTERNS_FILE:-$CONFIG_DIR/deny-patterns.tsv}"
REQUIRE_NO_REWRITES="${PUBLIC_EXPORT_REQUIRE_NO_REWRITES:-0}"

usage() {
  cat <<'USAGE'
Usage: public_repo_export_check.sh [--require-no-rewrites]

Checks the tracked local-platform files that are safe to export into the future
public ottto repository. Override PUBLIC_EXPORT_REPO_ROOT or PUBLIC_EXPORT_*_FILE
environment variables for tests.

Options:
  --require-no-rewrites  Fail when any non-fixture candidate still needs a
                         public repository rewrite.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --require-no-rewrites)
      REQUIRE_NO_REWRITES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-export: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

failures=0
rewrite_hits=0

fail() {
  echo "public-export: $*" >&2
  failures=$((failures + 1))
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "public-export: required file is missing: $1" >&2
    exit 2
  fi
}

read_config_lines() {
  local file="$1"
  grep -Ev '^[[:space:]]*($|#)' "$file"
}

is_self_check_fixture() {
  case "$1" in
    tools/ottto-local-platform/public-export/deny-patterns.tsv) return 0 ;;
    tools/ottto-local-platform/public-export/rewrite-rules.tsv) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_bootstrap_plan.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_contract_check.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_cutover_closeout.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_export_check.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_export_bundle.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_manifest_check.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_skeleton_check.sh) return 0 ;;
    tools/ottto-local-platform/scripts/test_public_repo_secret_scan.sh) return 0 ;;
    public-export/deny-patterns.tsv) return 0 ;;
    public-export/rewrite-rules.tsv) return 0 ;;
    scripts/test_public_repo_bootstrap_plan.sh) return 0 ;;
    scripts/test_public_repo_contract_check.sh) return 0 ;;
    scripts/test_public_repo_cutover_closeout.sh) return 0 ;;
    scripts/test_public_repo_export_check.sh) return 0 ;;
    scripts/test_public_repo_export_bundle.sh) return 0 ;;
    scripts/test_public_repo_manifest_check.sh) return 0 ;;
    scripts/test_public_repo_skeleton_check.sh) return 0 ;;
    scripts/test_public_repo_secret_scan.sh) return 0 ;;
    *) return 1 ;;
  esac
}

require_file "$ROOTS_FILE"
require_file "$REWRITE_RULES_FILE"
require_file "$DENY_PATTERNS_FILE"

if ! git -C "$REPO_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "public-export: repo root is not a git repository: $REPO_ROOT" >&2
  exit 2
fi

candidate_raw_file="$(mktemp "${TMPDIR:-/tmp}/public-export-candidates.XXXXXX")"
candidate_file="$(mktemp "${TMPDIR:-/tmp}/public-export-candidates-sorted.XXXXXX")"
grep_output_file="$(mktemp "${TMPDIR:-/tmp}/public-export-grep.XXXXXX")"
cleanup() {
  rm -f "$candidate_raw_file" "$candidate_file" "$grep_output_file"
}
trap cleanup EXIT

while IFS= read -r root_entry; do
  [[ -n "$root_entry" ]] || continue
  matches=()
  if [[ "$root_entry" != */ ]] && git -C "$REPO_ROOT" ls-files --error-unmatch "$root_entry" >/dev/null 2>&1; then
    matches+=("$root_entry")
  else
    while IFS= read -r tracked_file; do
      [[ -n "$tracked_file" ]] && matches+=("$tracked_file")
    done < <(git -C "$REPO_ROOT" ls-files "$root_entry")
  fi

  if [[ "${#matches[@]}" -eq 0 ]]; then
    fail "export root has no tracked files: $root_entry"
    continue
  fi

  for tracked_file in "${matches[@]}"; do
    printf '%s\n' "$tracked_file" >> "$candidate_raw_file"
  done
done < <(read_config_lines "$ROOTS_FILE")

sort -u "$candidate_raw_file" > "$candidate_file"
candidate_count="$(wc -l < "$candidate_file" | tr -d '[:space:]')"

if [[ "$candidate_count" == "0" ]]; then
  fail "no public export candidate files were found"
fi

while IFS=$'\t' read -r scope pattern description; do
  [[ -n "${scope:-}" && -n "${pattern:-}" ]] || continue
  case "$scope" in
    path)
      while IFS= read -r candidate; do
        if [[ "$candidate" =~ $pattern ]]; then
          fail "$description: $candidate"
        fi
      done < "$candidate_file"
      ;;
    content) ;;
    *)
      fail "unknown deny-pattern scope '$scope' for $pattern"
      ;;
  esac
done < <(read_config_lines "$DENY_PATTERNS_FILE")

while IFS=$'\t' read -r literal replacement reason; do
  [[ -n "${literal:-}" && -n "${replacement:-}" ]] || continue
  while IFS= read -r candidate; do
    if is_self_check_fixture "$candidate"; then
      continue
    fi
    if grep -IFq -- "$literal" "$REPO_ROOT/$candidate"; then
      rewrite_hits=$((rewrite_hits + 1))
      echo "public-export rewrite-required: $candidate contains '$literal' -> '$replacement' (${reason:-no reason recorded})"
    fi
  done < "$candidate_file"
done < <(read_config_lines "$REWRITE_RULES_FILE")

while IFS=$'\t' read -r scope pattern description; do
  [[ -n "${scope:-}" && -n "${pattern:-}" ]] || continue
  [[ "$scope" == "content" ]] || continue
  while IFS= read -r candidate; do
    if is_self_check_fixture "$candidate"; then
      continue
    fi
    if grep -IEn -- "$pattern" "$REPO_ROOT/$candidate" > "$grep_output_file" 2>/dev/null; then
      while IFS= read -r hit; do
        fail "$description: $candidate:$hit"
      done < "$grep_output_file"
      : > "$grep_output_file"
    fi
  done < "$candidate_file"
done < <(read_config_lines "$DENY_PATTERNS_FILE")

if [[ "$failures" -gt 0 ]]; then
  echo "public-export: failed with $failures issue(s) across $candidate_count candidate file(s)." >&2
  exit 1
fi

if [[ "$REQUIRE_NO_REWRITES" == "1" && "$rewrite_hits" -gt 0 ]]; then
  echo "public-export: rewrite-required references are not allowed in this mode; fix $rewrite_hits reference(s) before bootstrap." >&2
  exit 1
fi

echo "public-export: checked $candidate_count tracked file(s); rewrite-required references: $rewrite_hits"
