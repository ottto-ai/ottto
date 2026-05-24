#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/scripts/hosted_native_installer.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq

APP_SHA="3333333333333333333333333333333333333333333333333333333333333333"
CLI_SHA="1111111111111111111111111111111111111111111111111111111111111111"
DAEMON_SHA="2222222222222222222222222222222222222222222222222222222222222222"

write_manifest() {
  local manifest="$1"
  local channel="${2:-stable}"
  local app_url="${3:-https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg}"

  jq -n \
    --arg channel "$channel" \
    --arg app_sha "$APP_SHA" \
    --arg cli_sha "$CLI_SHA" \
    --arg daemon_sha "$DAEMON_SHA" \
    --arg app_url "$app_url" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: $channel,
      commit: "abcdef123456",
      generated_at: "2026-05-21T00:00:00Z",
      min_supported_version: "0.1.0",
      min_protocol_version: 11,
      supported_install_owners: ["app_bundle"],
      install_methods: {
        verified_native_installer: {
          kind: "verified_native_installer",
          path: "install-macos.sh",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/install-macos.sh",
          latest_url: "https://install.ottto.net/ottto-local-platform/releases/stable/latest/install-macos.sh",
          runtime_install_owner: "app_bundle"
        }
      },
      rollback: {
        strategy: "channel_latest_pointer",
        immutable_prefix: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0",
        latest_manifest_url: "https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json",
        preserve_failed_version: true,
        operator_steps: [
          "Repoint the channel latest manifest to the last known good immutable versioned prefix.",
          "Invalidate the release CDN paths for the channel latest pointer.",
          "Run download, checksum, Gatekeeper, and installed smoke verification before announcing recovery."
        ],
        verification: {
          release_gate: "scripts/macos_release_gate.sh --manifest release-manifest.json",
          stable_preflight: "scripts/macos_stable_preflight.sh --manifest release-manifest.json",
          installed_smoke: "scripts/dev_e2e_smoke.sh or stable clean-machine smoke"
        }
      },
      quality_gates: {
        packaged_app_launch: {
          status: "passed"
        }
      },
      artifacts: [
        {
          name: "Ottto.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: "/tmp/Ottto-macos-arm64.dmg",
          url: $app_url,
          verification_path: "/tmp/Ottto.app",
          sha256: $app_sha,
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        },
        {
          name: "ottto",
          kind: "cli",
          platform: "macos",
          arch: "arm64",
          path: "/tmp/ottto-macos-arm64.zip",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-macos-arm64.zip",
          verification_path: "/tmp/ottto",
          sha256: $cli_sha,
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        },
        {
          name: "ottto-service",
          kind: "daemon",
          platform: "macos",
          arch: "arm64",
          path: "/tmp/ottto-service-macos-arm64.zip",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-service-macos-arm64.zip",
          verification_path: "/tmp/ottto-service",
          sha256: $daemon_sha,
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        }
      ]
    }' > "$manifest"
}

assert_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq "$expected" "$file"; then
    echo "Expected $file to contain: $expected" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq "$unexpected" "$file"; then
    echo "Expected $file not to contain: $unexpected" >&2
    exit 1
  fi
}

expect_generation_failure() {
  local manifest="$1"
  if "$GENERATOR" --manifest "$manifest" --output "$TMP_DIR/should-not-exist.sh" >/dev/null 2>&1; then
    echo "Expected verified native installer helper generation to fail for $manifest" >&2
    exit 1
  fi
}

stable_manifest="$TMP_DIR/stable-manifest.json"
write_manifest "$stable_manifest"

installer="$TMP_DIR/install-macos.sh"
"$GENERATOR" --manifest "$stable_manifest" --output "$installer" >/dev/null

bash -n "$installer"
assert_contains "$installer" 'Usage: install-macos.sh'
assert_contains "$installer" 'https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0'
assert_contains "$installer" 'Verified native installer helper refuses channel not stable'
assert_contains "$installer" 'Verified native installer helper requires signed artifacts'
assert_contains "$installer" 'Verified native installer helper requires notarized artifacts'
assert_contains "$installer" 'Verified native installer helper requires Gatekeeper-assessed artifacts'
assert_contains "$installer" 'shasum -a 256'
assert_contains "$installer" 'xcrun stapler validate'
assert_contains "$installer" 'spctl --assess --type open --context context:primary-signature'
assert_contains "$installer" 'spctl --assess --type install'
assert_contains "$installer" 'hdiutil verify'
# shellcheck disable=SC2016
assert_contains "$installer" 'open "$artifact_path"'
assert_contains "$installer" 'This helper does not install mutable shell payloads'
assert_not_contains "$installer" 'install -m'
assert_not_contains "$installer" 'xattr -dr com.apple.quarantine'
assert_not_contains "$installer" 'launchctl bootstrap'
assert_not_contains "$installer" 'bootstrap LaunchAgent'
assert_not_contains "$installer" 'ottto-locald'
assert_not_contains "$installer" 'DEFAULT_BASE_URL="https://install.ottto.net/ottto-local-platform/releases/stable/latest'

pkg_manifest="$TMP_DIR/pkg-manifest.json"
write_manifest "$pkg_manifest" stable "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.pkg"
"$GENERATOR" --manifest "$pkg_manifest" --output "$TMP_DIR/install-macos-pkg.sh" >/dev/null
bash -n "$TMP_DIR/install-macos-pkg.sh"

dev_manifest="$TMP_DIR/dev-manifest.json"
write_manifest "$dev_manifest" dev
expect_generation_failure "$dev_manifest"

missing_app_bundle_manifest="$TMP_DIR/missing-app-bundle-manifest.json"
jq '.supported_install_owners = ["homebrew"]' \
  "$stable_manifest" > "$missing_app_bundle_manifest"
expect_generation_failure "$missing_app_bundle_manifest"

wrong_helper_owner_manifest="$TMP_DIR/wrong-helper-owner-manifest.json"
jq '.install_methods.verified_native_installer.runtime_install_owner = "hosted_installer"' \
  "$stable_manifest" > "$wrong_helper_owner_manifest"
expect_generation_failure "$wrong_helper_owner_manifest"

latest_url_manifest="$TMP_DIR/latest-url-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).url = "https://install.ottto.net/ottto-local-platform/releases/stable/latest/Ottto-macos-arm64.dmg"' \
  "$stable_manifest" > "$latest_url_manifest"
expect_generation_failure "$latest_url_manifest"

outside_prefix_manifest="$TMP_DIR/outside-prefix-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.2.0/Ottto-macos-arm64.dmg"' \
  "$stable_manifest" > "$outside_prefix_manifest"
expect_generation_failure "$outside_prefix_manifest"

bad_sha_manifest="$TMP_DIR/bad-sha-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).sha256 = "ABC"' \
  "$stable_manifest" > "$bad_sha_manifest"
expect_generation_failure "$bad_sha_manifest"

unsigned_manifest="$TMP_DIR/unsigned-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).signed = false' \
  "$stable_manifest" > "$unsigned_manifest"
expect_generation_failure "$unsigned_manifest"

unnotarized_manifest="$TMP_DIR/unnotarized-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).notarized = false' \
  "$stable_manifest" > "$unnotarized_manifest"
expect_generation_failure "$unnotarized_manifest"

ungatekeepered_manifest="$TMP_DIR/ungatekeepered-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).gatekeeper_assessed = false' \
  "$stable_manifest" > "$ungatekeepered_manifest"
expect_generation_failure "$ungatekeepered_manifest"

zip_manifest="$TMP_DIR/zip-manifest.json"
write_manifest "$zip_manifest" stable "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.zip"
expect_generation_failure "$zip_manifest"

latest_base_manifest="$TMP_DIR/latest-base-manifest.json"
jq '.rollback.immutable_prefix = "https://install.ottto.net/ottto-local-platform/releases/stable/latest"' \
  "$stable_manifest" > "$latest_base_manifest"
expect_generation_failure "$latest_base_manifest"

echo "hosted_native_installer tests passed"
