#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_SCRIPT="$ROOT/scripts/public_repo_export_bundle.sh"
SURFACE_CI_SCRIPT="$ROOT/scripts/public_repo_surface_ci.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

real_output="$tmp_dir/real-output"
"$BUNDLE_SCRIPT" --output-dir "$real_output" --force >/tmp/public-surface-ci-bundle.out
"$real_output/scripts/public_repo_surface_ci.sh" --staged-output "$real_output" >/tmp/public-surface-ci.out
grep -q "completed public surface checks" /tmp/public-surface-ci.out
grep -q "generate self-exported public bundle" /tmp/public-surface-ci.out
grep -q "verify self-exported public contracts" /tmp/public-surface-ci.out
grep -q "test stable preflight gate" /tmp/public-surface-ci.out
grep -q "test stable closeout gate" /tmp/public-surface-ci.out
grep -q "test Homebrew formula generator" /tmp/public-surface-ci.out
grep -q "test hosted native installer generator" /tmp/public-surface-ci.out
grep -q "test CycloneDX SBOM generator" /tmp/public-surface-ci.out

if "$SURFACE_CI_SCRIPT" --staged-output "$tmp_dir/missing" >/tmp/public-surface-ci-missing.out 2>&1; then
  echo "Expected missing staged output to fail public surface CI smoke" >&2
  exit 1
fi
grep -q "staged output is not a directory" /tmp/public-surface-ci-missing.out

echo "public_repo_surface_ci tests passed"
