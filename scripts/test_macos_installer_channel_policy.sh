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

if ! grep -Fq "LaunchServices registration helper" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "register_installed_app \"\$app_target\"" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "detach_duplicate_companion_volumes \"\$app_target\"" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "hdiutil detach \"\$volume\"" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "unregister_duplicate_companion_apps \"\$app_target\" \"\$lsregister\"" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "\"\$lsregister\" -dump" "$ROOT/scripts/macos_dev_install.sh" || \
  ! grep -Fq "\"\$lsregister\" -u \"\$candidate\"" "$ROOT/scripts/macos_dev_install.sh"; then
  echo "Local macOS installer must register installed Ottto.app for ottto:// handoff" >&2
  exit 1
fi

if grep -Fq "This installer only accepts dev/preview manifests" "$ROOT/scripts/macos_package.sh"; then
  echo "Generated hosted installer still has stale dev/preview-only text" >&2
  exit 1
fi

echo "macOS installer channel policy test passed"
