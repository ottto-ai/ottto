#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_export_check.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_config() {
  local repo="$1"
  mkdir -p "$repo/config"
  cat > "$repo/config/roots.txt" <<'ROOTS'
public/
ROOTS
  cat > "$repo/config/rewrite-rules.tsv" <<'REWRITES'
# literal	replacement	reason
ottto-ai/coding-agents-observability	ottto-ai/ottto	test rewrite
REWRITES
  cat > "$repo/config/deny-patterns.tsv" <<'DENY'
# scope	regex	description
path	(^|/)backend(/|$)	backend path denied
content	/Users/ronshub	local operator path denied
content	docs/dev/	private docs denied
content	Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{16,}	bearer token denied
DENY
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo/public"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Test"
  write_config "$repo"
}

run_check() {
  local repo="$1"
  shift
  PUBLIC_EXPORT_REPO_ROOT="$repo" \
    PUBLIC_EXPORT_CONFIG_DIR="$repo/config" \
    "$SCRIPT" "$@"
}

pass_repo="$tmp_dir/pass"
init_repo "$pass_repo"
cat > "$pass_repo/public/README.md" <<'EOF'
# Public Files

Attestation examples still mention ottto-ai/coding-agents-observability before
the public export rewrite step.
EOF
git -C "$pass_repo" add .
pass_output="$(run_check "$pass_repo")"
grep -q "rewrite-required" <<<"$pass_output"
rewrite_required_output="$tmp_dir/public-export-rewrite-required.out"
if run_check "$pass_repo" --require-no-rewrites >"$rewrite_required_output" 2>&1; then
  echo "Expected rewrite-required references to fail when no-rewrite mode is required" >&2
  exit 1
fi
grep -q "rewrite-required references are not allowed" "$rewrite_required_output"

secret_repo="$tmp_dir/secret"
init_repo "$secret_repo"
cat > "$secret_repo/public/README.md" <<'EOF'
Raw operator output: /Users/ronshub/private
EOF
git -C "$secret_repo" add .
if run_check "$secret_repo" >/tmp/public-export-secret.out 2>&1; then
  echo "Expected local user path to fail public export check" >&2
  exit 1
fi
grep -q "local operator path denied" /tmp/public-export-secret.out

docs_repo="$tmp_dir/private-docs"
init_repo "$docs_repo"
cat > "$docs_repo/public/README.md" <<'EOF'
See docs/dev/internal-session-note.md.
EOF
git -C "$docs_repo" add .
if run_check "$docs_repo" >/tmp/public-export-docs.out 2>&1; then
  echo "Expected private docs reference to fail public export check" >&2
  exit 1
fi
grep -q "private docs denied" /tmp/public-export-docs.out

path_repo="$tmp_dir/path"
init_repo "$path_repo"
mkdir -p "$path_repo/backend"
printf 'private backend\n' > "$path_repo/backend/private.txt"
printf 'backend/\n' >> "$path_repo/config/roots.txt"
git -C "$path_repo" add .
if run_check "$path_repo" >/tmp/public-export-path.out 2>&1; then
  echo "Expected backend export path to fail public export check" >&2
  exit 1
fi
grep -q "backend path denied" /tmp/public-export-path.out

empty_repo="$tmp_dir/empty"
init_repo "$empty_repo"
printf 'missing/\n' > "$empty_repo/config/roots.txt"
git -C "$empty_repo" add .
if run_check "$empty_repo" >/tmp/public-export-empty.out 2>&1; then
  echo "Expected missing export root to fail public export check" >&2
  exit 1
fi
grep -q "export root has no tracked files" /tmp/public-export-empty.out

echo "public_repo_export_check tests passed"
