#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

repo="$TMP_DIR/public-ottto"
mkdir -p "$repo/scripts" "$repo/crates/ottto-protocol/src"
cp "$ROOT/scripts/macos_package.sh" "$repo/scripts/macos_package.sh"
cat > "$repo/crates/ottto-protocol/src/lib.rs" <<'RS'
pub const PROTOCOL_VERSION: u16 = 11;
RS

git -C "$repo" init -q
git -C "$repo" config user.email "macos-package-root-test@example.invalid"
git -C "$repo" config user.name "macOS Package Root Test"
git -C "$repo" add .
git -C "$repo" commit -qm "fixture"
resolved_repo="$(cd "$repo" && pwd -P)"

if bash "$repo/scripts/macos_package.sh" \
  --version 0.1.0-stable-candidate.root-test \
  --channel stable-candidate >"$TMP_DIR/package.out" 2>&1; then
  echo "Expected package script to fail when the macOS app root is absent" >&2
  exit 1
fi

expected="macOS app root does not exist: $resolved_repo/tools/ottto-macos-app"
if ! grep -Fq "$expected" "$TMP_DIR/package.out"; then
  echo "Expected missing app-root message not found" >&2
  cat "$TMP_DIR/package.out" >&2
  exit 1
fi

if grep -Fq "not a git repository" "$TMP_DIR/package.out"; then
  echo "Package script resolved the wrong Git root" >&2
  cat "$TMP_DIR/package.out" >&2
  exit 1
fi

echo "macOS package root resolution test passed"
