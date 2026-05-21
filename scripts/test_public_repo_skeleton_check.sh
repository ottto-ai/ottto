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
