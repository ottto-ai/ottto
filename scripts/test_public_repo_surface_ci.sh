#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURFACE_CI_SCRIPT="$ROOT/scripts/public_repo_surface_ci.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# Stage a copy of the committed tree; --staged-output commits it in a fresh
# temporary checkout and runs every check against that commit.
real_output="$tmp_dir/real-output"
mkdir -p "$real_output"
git -C "$ROOT" archive HEAD | tar -x -C "$real_output"
"$real_output/scripts/public_repo_surface_ci.sh" --staged-output "$real_output" >"$tmp_dir/surface.out"
grep -q "completed public surface checks" "$tmp_dir/surface.out"
grep -q "check root manifest is derived from the commit tree" "$tmp_dir/surface.out"
grep -q "scan committed public tree" "$tmp_dir/surface.out"
grep -q "verify root public contracts" "$tmp_dir/surface.out"
grep -q "test stable preflight gate" "$tmp_dir/surface.out"
grep -q "test stable closeout gate" "$tmp_dir/surface.out"
grep -q "test Homebrew formula generator" "$tmp_dir/surface.out"
grep -q "test hosted native installer generator" "$tmp_dir/surface.out"
grep -q "test CycloneDX SBOM generator" "$tmp_dir/surface.out"

if "$SURFACE_CI_SCRIPT" --staged-output "$tmp_dir/missing" >"$tmp_dir/missing.out" 2>&1; then
  echo "Expected missing staged output to fail public surface CI smoke" >&2
  exit 1
fi
grep -q "staged output is not a directory" "$tmp_dir/missing.out"

echo "public_repo_surface_ci tests passed"
