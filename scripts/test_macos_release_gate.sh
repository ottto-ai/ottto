#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/macos_release_gate.sh"
SCHEMA="$ROOT/release/manifest.schema.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command shasum

jq -e '
  (.required | index("rollback"))
  and (.required | index("supply_chain"))
  and (.properties.rollback.required | index("immutable_prefix"))
  and (.properties.rollback.required | index("latest_manifest_url"))
  and (.properties.rollback.properties.preserve_failed_version.const == true)
  and (.properties.supply_chain.properties.slsa_build.properties.predicate_type.const == "https://slsa.dev/provenance/v1")
  and (.properties.supply_chain.properties.sbom.properties.predicate_type.const == "https://cyclonedx.org/bom")
' "$SCHEMA" >/dev/null

artifact="$TMP_DIR/ottto"
printf '#!/usr/bin/env sh\nexit 0\n' > "$artifact"
chmod +x "$artifact"
sha="$(shasum -a 256 "$artifact" | awk '{print $1}')"
sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
sbom_sha="$(shasum -a 256 "$sbom" | awk '{print $1}')"
launch_evidence="$TMP_DIR/packaged-app-launch-smoke.json"

write_launch_evidence() {
  local status="$1"
  local survived="$2"
  local crash_reports="$3"
  local output="$4"

  jq -n \
    --arg status "$status" \
    --argjson survived "$survived" \
    --argjson crash_reports "$crash_reports" \
    '{
      schema_version: 1,
      gate: "packaged_app_launch",
      status: $status,
      checked_at: "2026-05-05T00:00:00Z",
      app_path: "/tmp/Fake.app",
      bundle_id: "net.ottto.fake",
      bundle_version: "0.0.0-test",
      bundle_short_version: "0.0.0-test",
      executable_name: "Fake",
      wait_seconds: 1,
      process_survived_wait: $survived,
      exit_code: null,
      crash_reports: $crash_reports
    }' > "$output"
}

write_launch_evidence "passed" "true" "[]" "$launch_evidence"

write_manifest() {
  local channel="$1"
  local sha256="$2"
  local signed="$3"
  local notarized="$4"
  local gatekeeper="$5"
  local manifest="$6"

  jq -n \
    --arg channel "$channel" \
    --arg artifact "$artifact" \
    --arg sbom "$sbom" \
    --arg sha "$sha256" \
    --arg sbom_sha "$sbom_sha" \
    --arg launch_evidence "$launch_evidence" \
    --arg rollback_immutable_prefix "https://install.ottto.net/ottto-local-platform/releases/dev/latest" \
    --arg rollback_latest_manifest_url "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json" \
    --argjson signed "$signed" \
    --argjson notarized "$notarized" \
    --argjson gatekeeper "$gatekeeper" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.0.0-test",
      channel: $channel,
      commit: "abcdef123456",
      generated_at: "2026-05-05T00:00:00Z",
      min_supported_version: "0.0.0",
      min_protocol_version: 11,
      supported_install_owners: ["hosted_installer", "app_bundle", "homebrew"],
      rollback: {
        strategy: "channel_latest_pointer",
        immutable_prefix: $rollback_immutable_prefix,
        latest_manifest_url: $rollback_latest_manifest_url,
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
      supply_chain: {
        slsa_build: {
          spec_version: "1.2",
          level: "build_l1",
          predicate_type: "https://slsa.dev/provenance/v1",
          repository: "ottto-ai/ottto",
          signer_workflow: ".github/workflows/ottto-local-platform-release.yml",
          subjects: ["ottto", "release-manifest.json", "ottto-local-platform-sbom.cdx.json"],
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ottto -R ottto-ai/ottto"
        },
        sbom: {
          format: "cyclonedx-json",
          spec_version: "1.7",
          predicate_type: "https://cyclonedx.org/bom",
          path: $sbom,
          url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/ottto-local-platform-sbom.cdx.json",
          sha256: $sbom_sha,
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ottto -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        packaged_app_launch: {
          status: "passed",
          checked_at: "2026-05-05T00:00:00Z",
          wait_seconds: 1,
          bundle_id: "net.ottto.fake",
          bundle_version: "0.0.0-test",
          bundle_short_version: "0.0.0-test",
          executable_name: "Fake",
          process_survived_wait: true,
          crash_reports: [],
          evidence_path: $launch_evidence
        }
      },
      artifacts: [
        {
          name: "ottto",
          kind: "cli",
          platform: "macos",
          arch: "arm64",
          path: $artifact,
          url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/ottto-macos-arm64.zip",
          verification_path: $artifact,
          sha256: $sha,
          signed: $signed,
          notarized: $notarized,
          gatekeeper_assessed: $gatekeeper
        }
      ]
    }' > "$manifest"
}

dev_manifest="$TMP_DIR/dev-manifest.json"
write_manifest "dev" "$sha" "false" "false" "false" "$dev_manifest"
"$GATE" --manifest "$dev_manifest" >/dev/null

missing_owner_manifest="$TMP_DIR/missing-owner-manifest.json"
jq 'del(.supported_install_owners)' "$dev_manifest" > "$missing_owner_manifest"
if "$GATE" --manifest "$missing_owner_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without supported install owners to fail" >&2
  exit 1
fi

missing_rollback_manifest="$TMP_DIR/missing-rollback-manifest.json"
jq 'del(.rollback)' "$dev_manifest" > "$missing_rollback_manifest"
if "$GATE" --manifest "$missing_rollback_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without rollback metadata to fail" >&2
  exit 1
fi

missing_supply_chain_manifest="$TMP_DIR/missing-supply-chain-manifest.json"
jq 'del(.supply_chain)' "$dev_manifest" > "$missing_supply_chain_manifest"
if "$GATE" --manifest "$missing_supply_chain_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without supply-chain metadata to fail" >&2
  exit 1
fi

bad_sbom_sha_manifest="$TMP_DIR/bad-sbom-sha-manifest.json"
jq '.supply_chain.sbom.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$dev_manifest" > "$bad_sbom_sha_manifest"
if "$GATE" --manifest "$bad_sbom_sha_manifest" >/dev/null 2>&1; then
  echo "Expected manifest with bad SBOM SHA to fail" >&2
  exit 1
fi

bad_rollback_prefix_manifest="$TMP_DIR/bad-rollback-prefix-manifest.json"
jq '.rollback.immutable_prefix = "https://install.ottto.net/ottto-local-platform/releases/dev/other"' \
  "$dev_manifest" > "$bad_rollback_prefix_manifest"
if "$GATE" --manifest "$bad_rollback_prefix_manifest" >/dev/null 2>&1; then
  echo "Expected artifact outside rollback immutable prefix to fail" >&2
  exit 1
fi

missing_launch_manifest="$TMP_DIR/missing-launch-manifest.json"
jq 'del(.quality_gates)' "$dev_manifest" > "$missing_launch_manifest"
if "$GATE" --manifest "$missing_launch_manifest" >/dev/null 2>&1; then
  echo "Expected missing launch quality gate manifest to fail" >&2
  exit 1
fi

failed_launch_evidence="$TMP_DIR/failed-packaged-app-launch-smoke.json"
write_launch_evidence "failed" "false" '["Fake_2026-05-05.crash"]' "$failed_launch_evidence"
failed_launch_manifest="$TMP_DIR/failed-launch-manifest.json"
jq --arg evidence "$failed_launch_evidence" \
  '.quality_gates.packaged_app_launch.status = "failed"
   | .quality_gates.packaged_app_launch.process_survived_wait = false
   | .quality_gates.packaged_app_launch.crash_reports = ["Fake_2026-05-05.crash"]
   | .quality_gates.packaged_app_launch.evidence_path = $evidence' \
  "$dev_manifest" > "$failed_launch_manifest"
if "$GATE" --manifest "$failed_launch_manifest" >/dev/null 2>&1; then
  echo "Expected failed launch quality gate manifest to fail" >&2
  exit 1
fi

bad_sha_manifest="$TMP_DIR/bad-sha-manifest.json"
write_manifest "dev" "0000000000000000000000000000000000000000000000000000000000000000" "false" "false" "false" "$bad_sha_manifest"
if "$GATE" --manifest "$bad_sha_manifest" >/dev/null 2>&1; then
  echo "Expected SHA mismatch manifest to fail" >&2
  exit 1
fi

stable_unsigned_manifest="$TMP_DIR/stable-unsigned-manifest.json"
jq '.channel = "stable"
    | .version = "0.1.0"
    | .rollback.immutable_prefix = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0"
    | .rollback.latest_manifest_url = "https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json"
    | .artifacts[0].url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto"
    | .supply_chain.sbom.url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-local-platform-sbom.cdx.json"
    | .supply_chain.slsa_build.level = "build_l2"
    | .supply_chain.slsa_build.attested = true
    | .supply_chain.slsa_build.verified = true
    | .supply_chain.sbom.attested = true
    | .supply_chain.sbom.verified = true' \
  "$dev_manifest" > "$stable_unsigned_manifest"
if "$GATE" --manifest "$stable_unsigned_manifest" >/dev/null 2>&1; then
  echo "Expected unsigned stable manifest to fail" >&2
  exit 1
fi

stable_unverified_manifest="$TMP_DIR/stable-unverified-manifest.json"
jq '.artifacts[0].signed = true
    | .artifacts[0].notarized = true
    | .artifacts[0].gatekeeper_assessed = true
    | .supply_chain.slsa_build.level = "build_l1"
    | .supply_chain.slsa_build.attested = false
    | .supply_chain.slsa_build.verified = false' \
  "$stable_unsigned_manifest" > "$stable_unverified_manifest"
if "$GATE" --manifest "$stable_unverified_manifest" >/dev/null 2>&1; then
  echo "Expected unverified stable supply-chain manifest to fail" >&2
  exit 1
fi

if command -v codesign >/dev/null 2>&1; then
  app_bundle="$TMP_DIR/Fake.app"
  mkdir -p "$app_bundle/Contents/MacOS"
  cp "$artifact" "$app_bundle/Contents/MacOS/Fake"
  cat > "$app_bundle/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Fake</string>
  <key>CFBundleIdentifier</key>
  <string>net.ottto.fake</string>
  <key>CFBundleShortVersionString</key>
  <string>0.0.0-test</string>
  <key>CFBundleVersion</key>
  <string>0.0.0-test</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
</dict>
</plist>
PLIST

  app_manifest="$TMP_DIR/dev-app-manifest.json"
  jq -n \
    --arg artifact "$artifact" \
    --arg app_bundle "$app_bundle" \
    --arg sbom "$sbom" \
    --arg sha "$sha" \
    --arg sbom_sha "$sbom_sha" \
    --arg launch_evidence "$launch_evidence" \
    --arg rollback_immutable_prefix "https://install.ottto.net/ottto-local-platform/releases/dev/latest" \
    --arg rollback_latest_manifest_url "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.0.0-test",
      channel: "dev",
      commit: "abcdef123456",
      generated_at: "2026-05-05T00:00:00Z",
      min_supported_version: "0.0.0",
      min_protocol_version: 11,
      supported_install_owners: ["hosted_installer", "app_bundle", "homebrew"],
      rollback: {
        strategy: "channel_latest_pointer",
        immutable_prefix: $rollback_immutable_prefix,
        latest_manifest_url: $rollback_latest_manifest_url,
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
      supply_chain: {
        slsa_build: {
          spec_version: "1.2",
          level: "build_l1",
          predicate_type: "https://slsa.dev/provenance/v1",
          repository: "ottto-ai/ottto",
          signer_workflow: ".github/workflows/ottto-local-platform-release.yml",
          subjects: ["ottto", "release-manifest.json", "ottto-local-platform-sbom.cdx.json"],
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ottto -R ottto-ai/ottto"
        },
        sbom: {
          format: "cyclonedx-json",
          spec_version: "1.7",
          predicate_type: "https://cyclonedx.org/bom",
          path: $sbom,
          url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/ottto-local-platform-sbom.cdx.json",
          sha256: $sbom_sha,
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ottto -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        packaged_app_launch: {
          status: "passed",
          checked_at: "2026-05-05T00:00:00Z",
          wait_seconds: 1,
          bundle_id: "net.ottto.fake",
          bundle_version: "0.0.0-test",
          bundle_short_version: "0.0.0-test",
          executable_name: "Fake",
          process_survived_wait: true,
          crash_reports: [],
          evidence_path: $launch_evidence
        }
      },
      artifacts: [
        {
          name: "Fake.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: $artifact,
          url: "https://install.ottto.net/ottto-local-platform/releases/dev/latest/Fake.zip",
          verification_path: $app_bundle,
          sha256: $sha,
          signed: false,
          notarized: false,
          gatekeeper_assessed: false
        }
      ]
    }' > "$app_manifest"

  if "$GATE" --manifest "$app_manifest" >/dev/null 2>&1; then
    echo "Expected unsealed dev macOS app manifest to fail" >&2
    exit 1
  fi

  codesign --force --sign - "$app_bundle" >/dev/null 2>&1
  "$GATE" --manifest "$app_manifest" >/dev/null
fi

echo "macos_release_gate tests passed"
