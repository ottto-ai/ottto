#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! grep -Fq 'if channel not in {"dev", "preview", "stable-candidate"}:' "$ROOT/scripts/macos_package.sh"; then
  echo "Generated hosted installer must accept stable-candidate manifests" >&2
  exit 1
fi

if ! grep -Fq "macos_dev_install.sh is for dev/preview/stable-candidate builds" "$ROOT/scripts/macos_dev_install.sh"; then
  echo "Local macOS installer channel message must include stable-candidate" >&2
  exit 1
fi

if grep -Fq "This installer only accepts dev/preview manifests" "$ROOT/scripts/macos_package.sh"; then
  echo "Generated hosted installer still has stale dev/preview-only text" >&2
  exit 1
fi

echo "macOS installer channel policy test passed"
