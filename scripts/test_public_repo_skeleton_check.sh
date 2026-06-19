#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_SCRIPT="$ROOT/scripts/public_repo_export_bundle.sh"
SKELETON_SCRIPT="$ROOT/scripts/public_repo_skeleton_check.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

output_dir="$tmp_dir/public-ottto"
"$BUNDLE_SCRIPT" --output-dir "$output_dir" --force >"$tmp_dir/public-skeleton-bundle.out"

PUBLIC_SKELETON_REPO_ROOT="$output_dir" "$SKELETON_SCRIPT" >"$tmp_dir/public-skeleton-private-script.out"
PUBLIC_SKELETON_REPO_ROOT="$output_dir" "$output_dir/scripts/public_repo_skeleton_check.sh" >"$tmp_dir/public-skeleton-exported-script.out"

git_output="$tmp_dir/public-ottto-git"
cp -R "$output_dir" "$git_output"
git -C "$git_output" init -q
git -C "$git_output" config user.email "test@example.com"
git -C "$git_output" config user.name "Test"
cat > "$git_output/.gitignore" <<'EOF'
.claude/
EOF
git -C "$git_output" add .
git -C "$git_output" commit -qm init
mkdir -p "$git_output/.claude"
printf 'local helper state\n' > "$git_output/.claude/noise.txt"
PUBLIC_SKELETON_REPO_ROOT="$git_output" "$SKELETON_SCRIPT" >"$tmp_dir/public-skeleton-ignored-local.out"
mkdir -p "$git_output/backend"
printf 'private backend\n' > "$git_output/backend/file.txt"
if PUBLIC_SKELETON_REPO_ROOT="$git_output" "$SKELETON_SCRIPT" >"$tmp_dir/public-skeleton-unignored-private.out" 2>&1; then
  echo "Expected skeleton check to fail on unignored private path" >&2
  exit 1
fi
grep -q "private or non-root-shaped path must not exist: backend" "$tmp_dir/public-skeleton-unignored-private.out"

rm -f "$output_dir/docs/support.md"
if PUBLIC_SKELETON_REPO_ROOT="$output_dir" "$SKELETON_SCRIPT" >"$tmp_dir/public-skeleton-missing-support.out" 2>&1; then
  echo "Expected skeleton check to fail when support runbook is missing" >&2
  exit 1
fi
grep -q "required file is missing: docs/support.md" "$tmp_dir/public-skeleton-missing-support.out"
"$BUNDLE_SCRIPT" --output-dir "$output_dir" --force >"$tmp_dir/public-skeleton-bundle-restored.out"

rm -f "$output_dir/.github/workflows/ci.yml"
if PUBLIC_SKELETON_REPO_ROOT="$output_dir" "$SKELETON_SCRIPT" >"$tmp_dir/public-skeleton-broken.out" 2>&1; then
  echo "Expected skeleton check to fail when public CI is missing" >&2
  exit 1
fi
grep -q "required file is missing: .github/workflows/ci.yml" "$tmp_dir/public-skeleton-broken.out"

echo "public_repo_skeleton_check tests passed"
