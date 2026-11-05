#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if ! grep -Fq "sign_container \"\$APP_DMG\"" "$ROOT/scripts/macos_package.sh"; then
  echo "Package script must code-sign the DMG before notarization." >&2
  exit 1
fi
if ! grep -Fq "codesign --force --timestamp --sign \"\$SIGN_IDENTITY\" \"\$1\"" "$ROOT/scripts/macos_package.sh"; then
  echo "Package script must use Developer ID timestamp signing for container artifacts." >&2
  exit 1
fi
if ! grep -Fq "SUPPORTED_INSTALL_OWNERS_JSON='[\"app_bundle\", \"homebrew\"]'" "$ROOT/scripts/macos_package.sh"; then
  echo "Stable packages must advertise app_bundle and homebrew install owners." >&2
  exit 1
fi
if ! grep -Fq 'APP_LAUNCH_AGENTS/net.ottto.locald.plist' "$ROOT/scripts/macos_package.sh"; then
  echo "Packaged apps must retain the retired plist descriptor for SMAppService cleanup." >&2
  exit 1
fi
for installer in "$ROOT/scripts/macos_package.sh" "$ROOT/scripts/macos_dev_install.sh"; do
  if ! grep -Fq "\"\$app_daemon\" service cleanup-legacy --json" "$installer"; then
    echo "$installer must de-register retired SMAppService jobs after installing the app." >&2
    exit 1
  fi
done

repo="$TMP_DIR/public-ottto"
mkdir -p "$repo/scripts" "$repo/crates/ottto-protocol/src"
cp "$ROOT/scripts/macos_package.sh" "$repo/scripts/macos_package.sh"
cp "$ROOT/scripts/macos_bundle_url_scheme.sh" "$repo/scripts/macos_bundle_url_scheme.sh"
cp "$ROOT/scripts/macos_companion_entitlements.sh" "$repo/scripts/macos_companion_entitlements.sh"
cp "$ROOT/scripts/macos_sparkle_bundle_version.sh" "$repo/scripts/macos_sparkle_bundle_version.sh"
cat > "$repo/crates/ottto-protocol/src/lib.rs" <<'RS'
pub const PROTOCOL_VERSION: u16 = 11;
RS

git -C "$repo" init -q
git -C "$repo" config user.email "macos-package-root-test@example.invalid"
git -C "$repo" config user.name "macOS Package Root Test"
git -C "$repo" add .
git -C "$repo" commit -qm "fixture"
resolved_repo="$(cd "$repo" && pwd -P)"

# The packager must not carry the private-source guard or credential fetch;
# the release procedure owns those checks.
if grep -Eq 'gh api|auth git-credential|require_command gh' "$ROOT/scripts/macos_package.sh"; then
  echo "Package script must not reach a private repository or a gh credential helper" >&2
  exit 1
fi

# package_expect_failure <label> <expected message> <packager args...>
package_expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2
  if bash "$repo/scripts/macos_package.sh" "$@" >"$TMP_DIR/$label.out" 2>&1; then
    echo "Expected package script to fail: $label" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/$label.out"; then
    echo "Package failure for $label did not report: $expected" >&2
    cat "$TMP_DIR/$label.out" >&2
    exit 1
  fi
  if grep -Fq "not a git repository" "$TMP_DIR/$label.out"; then
    echo "Package script resolved the wrong Git root" >&2
    cat "$TMP_DIR/$label.out" >&2
    exit 1
  fi
}

# [behaviour] --app-root is required; there is no default app location.
package_expect_failure missing-app-root "--app-root is required" \
  --version 0.1.0-dev --channel dev

# [behaviour] A missing app root is named as passed.
package_expect_failure absent-app-root \
  "macOS app root does not exist: $resolved_repo/tools/ottto-macos-app" \
  --app-root "$resolved_repo/tools/ottto-macos-app" \
  --version 0.1.0-dev --channel dev

# [behaviour] A package root outside any Git checkout is refused after the
# public source (resolved from the script's own checkout) passes its checks.
loose_app="$TMP_DIR/loose-app"
mkdir -p "$loose_app"
printf '// fixture\n' > "$loose_app/Package.swift"
package_expect_failure loose-app-root "macOS app root must belong to the private Git checkout" \
  --app-root "$loose_app" --version 0.1.0-dev --channel dev

echo "macOS package root resolution test passed"
