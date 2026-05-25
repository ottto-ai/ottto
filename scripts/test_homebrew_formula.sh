#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/scripts/homebrew_formula.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq

CLI_SHA="1111111111111111111111111111111111111111111111111111111111111111"
DAEMON_SHA="2222222222222222222222222222222222222222222222222222222222222222"
APP_SHA="3333333333333333333333333333333333333333333333333333333333333333"

write_manifest() {
  local manifest="$1"
  local channel="${2:-stable}"

  jq -n \
    --arg channel "$channel" \
    --arg cli_sha "$CLI_SHA" \
    --arg daemon_sha "$DAEMON_SHA" \
    --arg app_sha "$APP_SHA" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: $channel,
      commit: "abcdef123456",
      generated_at: "2026-05-21T00:00:00Z",
      min_supported_version: "0.1.0",
      min_protocol_version: 11,
      supported_install_owners: ["hosted_installer", "app_bundle", "homebrew"],
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
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg",
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
  if "$GENERATOR" --manifest "$manifest" --output "$TMP_DIR/should-not-exist.rb" >/dev/null 2>&1; then
    echo "Expected Homebrew formula generation to fail for $manifest" >&2
    exit 1
  fi
}

stable_manifest="$TMP_DIR/stable-manifest.json"
write_manifest "$stable_manifest"

formula="$TMP_DIR/Formula/ottto.rb"
"$GENERATOR" --manifest "$stable_manifest" --output "$formula" >/dev/null

assert_contains "$formula" 'class Ottto < Formula'
assert_contains "$formula" 'license "Apache-2.0"'
assert_contains "$formula" 'url "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-macos-arm64.zip"'
assert_contains "$formula" 'version "0.1.0"'
assert_contains "$formula" "sha256 \"$CLI_SHA\""
assert_contains "$formula" 'resource "ottto-service" do'
assert_contains "$formula" 'url "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-service-macos-arm64.zip"'
assert_contains "$formula" "sha256 \"$DAEMON_SHA\""
assert_contains "$formula" 'bin.install daemons.fetch(0) => "ottto-service"'
assert_contains "$formula" 'name macos: "net.ottto.service"'
assert_contains "$formula" 'brew services start ottto'
assert_contains "$formula" 'brew update && brew upgrade ottto'
assert_contains "$formula" 'brew services restart ottto'
assert_contains "$formula" 'brew services stop ottto'
assert_not_contains "$formula" '/latest/ottto-macos-arm64.zip'

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$formula" >/dev/null
fi

dev_manifest="$TMP_DIR/dev-manifest.json"
write_manifest "$dev_manifest" dev
expect_generation_failure "$dev_manifest"

missing_homebrew_manifest="$TMP_DIR/missing-homebrew-manifest.json"
jq '.supported_install_owners = ["hosted_installer", "app_bundle"]' \
  "$stable_manifest" > "$missing_homebrew_manifest"
"$GENERATOR" --manifest "$missing_homebrew_manifest" --output "$TMP_DIR/qa-only-ottto.rb" >/dev/null

latest_url_manifest="$TMP_DIR/latest-url-manifest.json"
jq '(.artifacts[] | select(.kind == "cli")).url = "https://install.ottto.net/ottto-local-platform/releases/stable/latest/ottto-macos-arm64.zip"' \
  "$stable_manifest" > "$latest_url_manifest"
expect_generation_failure "$latest_url_manifest"

outside_prefix_manifest="$TMP_DIR/outside-prefix-manifest.json"
jq '(.artifacts[] | select(.kind == "daemon")).url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.2.0/ottto-service-macos-arm64.zip"' \
  "$stable_manifest" > "$outside_prefix_manifest"
expect_generation_failure "$outside_prefix_manifest"

bad_sha_manifest="$TMP_DIR/bad-sha-manifest.json"
jq '(.artifacts[] | select(.kind == "cli")).sha256 = "ABC"' \
  "$stable_manifest" > "$bad_sha_manifest"
expect_generation_failure "$bad_sha_manifest"

unsigned_manifest="$TMP_DIR/unsigned-manifest.json"
jq '(.artifacts[] | select(.kind == "daemon")).signed = false' \
  "$stable_manifest" > "$unsigned_manifest"
expect_generation_failure "$unsigned_manifest"

wrong_arch_manifest="$TMP_DIR/wrong-arch-manifest.json"
jq '(.artifacts[] | select(.kind == "cli")).arch = "x86_64"' \
  "$stable_manifest" > "$wrong_arch_manifest"
expect_generation_failure "$wrong_arch_manifest"

echo "homebrew_formula tests passed"
