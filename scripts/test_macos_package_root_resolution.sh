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

# License notices must be inside the app before it is signed, and each binary
# zip must be built from its staging folder (executable plus notices). The
# patterns match literal packager lines, so they stay in single quotes.
package_script="$ROOT/scripts/macos_package.sh"
# shellcheck disable=SC2016
copy_line="$(grep -n -Fx 'ottto_copy_app_license_notices "$ROOT" "$APP_RESOURCES"' "$package_script" | cut -d: -f1)"
# shellcheck disable=SC2016
sign_line="$(grep -n -Fx 'sign_companion "$APP_BUNDLE"' "$package_script" | cut -d: -f1)"
if [[ -z "$copy_line" || -z "$sign_line" || "$copy_line" -ge "$sign_line" ]]; then
  echo "Package script must copy the app license notices before signing the app." >&2
  exit 1
fi
for zip_stage in 'CLI_ZIP cli' 'DAEMON_ZIP daemon'; do
  zip_var="${zip_stage% *}"
  stage="${zip_stage#* }"
  if ! grep -Fxq "  ottto_release_zip \"\$ZIP_STAGE_ROOT/$stage\" \"\$$zip_var\"" "$package_script"; then
    echo "Package script must zip the $stage staging folder with its license notices." >&2
    exit 1
  fi
done
# shellcheck disable=SC2016
if grep -Eq '(ditto -c -k|ottto_release_zip) "\$OUTPUT_DIR/ottto(-service)?"' "$package_script"; then
  echo "Package script must not zip a bare executable without its license notices." >&2
  exit 1
fi

repo="$TMP_DIR/public-ottto"
mkdir -p "$repo/scripts" "$repo/crates/ottto-protocol/src"
cp "$ROOT/scripts/macos_package.sh" "$repo/scripts/macos_package.sh"
cp "$ROOT/scripts/macos_bundle_url_scheme.sh" "$repo/scripts/macos_bundle_url_scheme.sh"
cp "$ROOT/scripts/macos_companion_entitlements.sh" "$repo/scripts/macos_companion_entitlements.sh"
cp "$ROOT/scripts/macos_sparkle_bundle_version.sh" "$repo/scripts/macos_sparkle_bundle_version.sh"
cp "$ROOT/scripts/macos_license_notices.sh" "$repo/scripts/macos_license_notices.sh"
cp "$ROOT/scripts/macos_release_archive.sh" "$repo/scripts/macos_release_archive.sh"
cp "$ROOT/scripts/macos_app_binary.sh" "$repo/scripts/macos_app_binary.sh"
# The release lane's app staging folder is a fixed host path; the fixture's
# copy of the packager points it at a folder under this test's temp folder.
physical_tmp="$(cd "$TMP_DIR" && pwd -P)"
lane_base="$physical_tmp/opt/ottto-release/app-src"
# shellcheck disable=SC2016 # literal packager line
if [[ "$(grep -c -Fx 'RELEASE_APP_SRC_BASE="/opt/ottto-release/app-src"' "$repo/scripts/macos_package.sh")" != 1 ]]; then
  echo "Package script must name the release host's app staging folder once" >&2
  exit 1
fi
sed "s|^RELEASE_APP_SRC_BASE=\"/opt/ottto-release/app-src\"\$|RELEASE_APP_SRC_BASE=\"$lane_base\"|" \
  "$repo/scripts/macos_package.sh" > "$TMP_DIR/macos_package.sh"
mv "$TMP_DIR/macos_package.sh" "$repo/scripts/macos_package.sh"
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
  "macOS app root does not exist: $resolved_repo/inputs/SampleApp" \
  --app-root "$resolved_repo/inputs/SampleApp" \
  --version 0.1.0-dev --channel dev

# [behaviour] A package root outside any Git checkout is refused after the
# public source (resolved from the script's own checkout) passes its checks.
loose_app="$TMP_DIR/loose-app"
mkdir -p "$loose_app"
printf '// fixture\n' > "$loose_app/Package.swift"
package_expect_failure loose-app-root "macOS app root must belong to the private Git checkout" \
  --app-root "$loose_app" --version 0.1.0-dev --channel dev

# [behaviour] The app package must be a subdirectory of its checkout: the
# record binds that subdirectory's tree, never the whole checkout.
root_app="$TMP_DIR/root-app"
mkdir -p "$root_app"
printf '// fixture\n' > "$root_app/Package.swift"
git -C "$root_app" init -q
git -C "$root_app" config user.email "macos-package-root-test@example.invalid"
git -C "$root_app" config user.name "macOS Package Root Test"
git -C "$root_app" add .
git -C "$root_app" commit -qm "fixture"
package_expect_failure checkout-root-app "macOS app root must be a subdirectory of its Git checkout" \
  --app-root "$root_app" --version 0.1.0-dev --channel dev

# [behaviour] Child tools get no app checkout path as an operand: git and
# swift run inside the checkout, and signing reads a neutral entitlements copy.
# shellcheck disable=SC2016 # literal variable names
if grep -Eq 'git -C "\$MAC_APP|--package-path "\$MAC_APP|--entitlements "\$MAC_APP|_resources "\$MAC_APP_GIT_ROOT"|_pin "\$MAC_APP_GIT_ROOT"' \
  "$ROOT/scripts/macos_package.sh"; then
  echo "Package script must not pass the app checkout path to a child tool" >&2
  exit 1
fi

# [behaviour] The packager records no private repository identity or path.
if grep -Eq 'OTTTO_MACOS_APP_SOURCE_REPOSITORY|mac_app_source_path|git_subtree' "$ROOT/scripts/macos_package.sh"; then
  echo "Package script must not record a private repository identity or path" >&2
  exit 1
fi

# [behaviour] The release lane builds only from this run's app staging folder,
# and Swift's argv names only that folder (child argv recorded by a stub).
# A synthetic marker stands for the private checkout's own path.
marker="zq-synthetic-marker-7f3a"
stub="$TMP_DIR/stub-bin"
mkdir -p "$stub" "$physical_tmp/runner-temp" "$physical_tmp/home"
cat > "$stub/swift" <<'SH'
#!/bin/bash
printf '%s\n' "$@" > "$SWIFT_ARGV_RECORD"
pwd -P > "$SWIFT_ARGV_RECORD.cwd"
exit 3
SH
printf '#!/bin/bash\nexit 0\n' > "$stub/cargo"
chmod +x "$stub/swift" "$stub/cargo"
# make_app_checkout <folder>: a private app checkout with the app in App/.
make_app_checkout() {
  mkdir -p "$1/App"
  printf '// fixture\n' > "$1/App/Package.swift"
  cat > "$1/App/Companion.entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.automation.apple-events</key>
  <true/>
</dict>
</plist>
PLIST
  git -C "$1" init -q
  git -C "$1" config user.email "macos-package-root-test@example.invalid"
  git -C "$1" config user.name "macOS Package Root Test"
  git -C "$1" add .
  git -C "$1" commit -qm "fixture"
}
private_checkout="$physical_tmp/$marker/app-checkout"
staged_checkout="$lane_base/4242/app-checkout"
make_app_checkout "$private_checkout"
make_app_checkout "$staged_checkout"
mkdir -p "$lane_base/4243"
ln -s "$private_checkout" "$lane_base/4242/linked-checkout"
cp -R "$staged_checkout" "$lane_base/4243/app-checkout"
# lane_package <label> <app root>: a release-lane prepare run; swift records argv.
lane_package() {
  local commit
  commit="$(git -C "$2" rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)"
  rm -f "$TMP_DIR/$1.argv" "$TMP_DIR/$1.argv.cwd"
  env -i PATH="$stub:$PATH" HOME="$physical_tmp/home" OTTTO_RELEASE_LANE=candidate GITHUB_RUN_ID=4242 \
    RUNNER_TEMP="$physical_tmp/runner-temp" OTTTO_MACOS_DSYM_DIR="$physical_tmp/dsym-$1" \
    OTTTO_MACOS_APP_ROOT="$2" SWIFT_ARGV_RECORD="$TMP_DIR/$1.argv" \
    bash "$repo/scripts/macos_package.sh" --stage prepare --channel stable-candidate --version 0.1.2-rc1 \
    --app-source-commit "$commit" --release-notes "Fixture notes" >"$TMP_DIR/$1.out" 2>&1
}
for case in "private|$private_checkout/App" "linked|$lane_base/4242/linked-checkout/App" \
  "other-run|$lane_base/4243/app-checkout/App" "run-folder|$lane_base/4242" \
  "dotdot|$lane_base/4242/../4243/app-checkout/App"; do
  label="${case%%|*}"
  if lane_package "$label" "${case#*|}"; then
    echo "The release lane accepted an app root outside this run's staging folder: $label" >&2
    exit 1
  fi
  if ! grep -Fxq "The release lane builds only from the release host's app staging folder for this run." \
    "$TMP_DIR/$label.out" || [[ -e "$TMP_DIR/$label.argv" ]]; then
    echo "The release lane did not stop before any tool for: $label" >&2
    cat "$TMP_DIR/$label.out" >&2
    exit 1
  fi
  if grep -Fq -e "$marker" -e "$lane_base" "$TMP_DIR/$label.out"; then
    echo "The release lane's refusal printed a path: $label" >&2
    exit 1
  fi
done
if lane_package staged "$staged_checkout/App"; then
  echo "The swift stub's failure was not reported" >&2
  exit 1
fi
if [[ ! -f "$TMP_DIR/staged.argv" ]] || ! grep -Fq "Swift release build failed (exit 3)" "$TMP_DIR/staged.out"; then
  echo "The release lane did not reach the Swift build from the staging folder" >&2
  cat "$TMP_DIR/staged.out" >&2
  exit 1
fi
if grep -Fq "$marker" "$TMP_DIR/staged.argv" "$TMP_DIR/staged.out"; then
  echo "Swift's argv or the step output names the private checkout" >&2
  exit 1
fi
if ! grep -Fxq -- "$staged_checkout=." "$TMP_DIR/staged.argv" || \
  [[ "$(grep -c -F -- "$lane_base" "$TMP_DIR/staged.argv")" != 1 ]] || \
  [[ "$(cat "$TMP_DIR/staged.argv.cwd")" != "$staged_checkout/App" ]] || \
  ! grep -A1 -Fx -- "--package-path" "$TMP_DIR/staged.argv" | grep -Fxq .; then
  echo "Swift's only app path must be the staging folder's prefix map" >&2
  cat "$TMP_DIR/staged.argv" >&2
  exit 1
fi
# Outside the release lane (no OTTTO_RELEASE_LANE) the staging folder is not required.
if env -u OTTTO_RELEASE_LANE bash "$repo/scripts/macos_package.sh" --app-root "$private_checkout/App" \
  --version 0.1.0-dev --channel dev --skip-build >"$TMP_DIR/dev.out" 2>&1; then
  :
fi
if grep -Fq "app staging folder" "$TMP_DIR/dev.out"; then
  echo "The staging folder rule must apply only to the release lane" >&2
  exit 1
fi

echo "macOS package root resolution test passed"
