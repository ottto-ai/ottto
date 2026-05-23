#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/macos_public_rc_gate.sh"
TEMPLATE="$ROOT/scripts/macos_public_rc_evidence_template.sh"
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
require_command python3

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >/tmp/macos-public-rc-gate.out 2>&1; then
    echo "Expected failure: $label" >&2
    cat /tmp/macos-public-rc-gate.out >&2
    exit 1
  fi
}

app_bundle="$TMP_DIR/Ottto.app"
app_contents="$app_bundle/Contents"
app_macos="$app_contents/MacOS"
mkdir -p "$app_macos"
cat > "$app_macos/Ottto" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod +x "$app_macos/Ottto"
cat > "$app_contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>net.ottto.Companion</string>
  <key>CFBundleExecutable</key>
  <string>Ottto</string>
  <key>CFBundleVersion</key>
  <string>0.1.0-stable-candidate.1</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0-stable-candidate.1</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
</dict>
</plist>
PLIST

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$app_contents/Info.plist" >/dev/null
fi
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$app_bundle" >/dev/null 2>&1
fi

app_dmg="$TMP_DIR/Ottto-macos-arm64.dmg"
cli_zip="$TMP_DIR/ottto-macos-arm64.zip"
daemon_zip="$TMP_DIR/ottto-service-macos-arm64.zip"
sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
launch_evidence="$TMP_DIR/packaged-app-launch-smoke.json"
printf 'fake stable-candidate app dmg\n' > "$app_dmg"
printf 'fake stable-candidate cli archive\n' > "$cli_zip"
printf 'fake stable-candidate daemon archive\n' > "$daemon_zip"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
jq -n '{
  schema_version: 1,
  gate: "packaged_app_launch",
  status: "passed",
  checked_at: "2026-05-21T00:00:00Z",
  wait_seconds: 1,
  bundle_id: "net.ottto.Companion",
  bundle_version: "0.1.0-stable-candidate.1",
  bundle_short_version: "0.1.0-stable-candidate.1",
  executable_name: "Ottto",
  process_survived_wait: true,
  crash_reports: []
}' > "$launch_evidence"

write_candidate_manifest() {
  local channel="$1"
  local manifest="$2"
  local version="0.1.0-stable-candidate.1"
  local prefix="https://install.ottto.net/ottto-local-platform/releases/$channel/$version"

  jq -n \
    --arg channel "$channel" \
    --arg version "$version" \
    --arg prefix "$prefix" \
    --arg app_dmg "$app_dmg" \
    --arg app_bundle "$app_bundle" \
    --arg cli_zip "$cli_zip" \
    --arg daemon_zip "$daemon_zip" \
    --arg sbom "$sbom" \
    --arg launch_evidence "$launch_evidence" \
    --arg app_sha "$(sha256_file "$app_dmg")" \
    --arg cli_sha "$(sha256_file "$cli_zip")" \
    --arg daemon_sha "$(sha256_file "$daemon_zip")" \
    --arg sbom_sha "$(sha256_file "$sbom")" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: $version,
      channel: $channel,
      commit: "abcdef123456",
      generated_at: "2026-05-21T00:00:00Z",
      min_supported_version: "0.1.0",
      min_protocol_version: 11,
      supported_install_owners: ["hosted_installer", "app_bundle", "homebrew"],
      rollback: {
        strategy: "channel_latest_pointer",
        immutable_prefix: $prefix,
        latest_manifest_url: ("https://install.ottto.net/ottto-local-platform/releases/" + $channel + "/latest/release-manifest.json"),
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
          signer_workflow: ".github/workflows/macos-stable-release.yml",
          subjects: [
            "Ottto-macos-arm64.dmg",
            "ottto-macos-arm64.zip",
            "ottto-service-macos-arm64.zip",
            "release-manifest.json",
            "ottto-local-platform-sbom.cdx.json"
          ],
          attested: false,
          verified: false,
          verification_command: "gh attestation verify Ottto-macos-arm64.dmg -R ottto-ai/ottto"
        },
        sbom: {
          format: "cyclonedx-json",
          spec_version: "1.7",
          predicate_type: "https://cyclonedx.org/bom",
          path: $sbom,
          url: ($prefix + "/ottto-local-platform-sbom.cdx.json"),
          sha256: $sbom_sha,
          attested: false,
          verified: false,
          verification_command: "gh attestation verify Ottto-macos-arm64.dmg -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        packaged_app_launch: {
          status: "passed",
          checked_at: "2026-05-21T00:00:00Z",
          wait_seconds: 1,
          bundle_id: "net.ottto.Companion",
          bundle_version: "0.1.0-stable-candidate.1",
          bundle_short_version: "0.1.0-stable-candidate.1",
          executable_name: "Ottto",
          process_survived_wait: true,
          crash_reports: [],
          evidence_path: $launch_evidence
        }
      },
      artifacts: [
        {
          name: "Ottto.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: $app_dmg,
          url: ($prefix + "/Ottto-macos-arm64.dmg"),
          verification_path: $app_bundle,
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
          path: $cli_zip,
          url: ($prefix + "/ottto-macos-arm64.zip"),
          verification_path: "",
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
          path: $daemon_zip,
          url: ($prefix + "/ottto-service-macos-arm64.zip"),
          verification_path: "",
          sha256: $daemon_sha,
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        }
      ]
    }' > "$manifest"
}

write_stable_binding_manifest() {
  local manifest="$1"
  local commit="$2"
  local candidate_sha="$3"
  local evidence_path="$4"

  jq -n \
    --arg commit "$commit" \
    --arg candidate_sha "$candidate_sha" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: "stable",
      commit: $commit,
      min_protocol_version: 11,
      quality_gates: {
        stable_candidate_rc: {
          status: "passed",
          evidence_path: $evidence_path,
          candidate_manifest_sha256: $candidate_sha
        }
      }
    }' > "$manifest"
}

candidate_manifest="$TMP_DIR/stable-candidate-release-manifest.json"
write_candidate_manifest "stable-candidate" "$candidate_manifest"
candidate_sha="$(sha256_file "$candidate_manifest")"
template_evidence="$TMP_DIR/template-stable-candidate-rc-qa.json"
"$TEMPLATE" \
  --candidate-manifest "$candidate_manifest" \
  --output "$template_evidence" \
  --checked-at "2026-05-21T00:00:00Z" >/dev/null
jq -e \
  --arg candidate_sha "$candidate_sha" \
  '.local_platform.runtime == "ottto-service"
   and .local_platform.service_label == "net.ottto.service"
   and .local_platform.version == "0.1.0-stable-candidate.1"
   and .local_platform.release_channel == "stable-candidate"
   and .local_platform.protocol_version == 11
   and .local_platform.release_manifest_sha256 == $candidate_sha' \
  "$template_evidence" >/dev/null
expect_failure "unfilled template evidence" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$template_evidence"

stale_protocol_manifest="$TMP_DIR/stale-protocol-stable-candidate-release-manifest.json"
jq '.min_protocol_version = 10' "$candidate_manifest" > "$stale_protocol_manifest"
if "$TEMPLATE" --candidate-manifest "$stale_protocol_manifest" --output - >/tmp/macos-public-rc-template.out 2>&1; then
  echo "Expected stable-candidate RC template generation to reject stale protocol manifests" >&2
  exit 1
fi
grep -q "min_protocol_version must be 11" /tmp/macos-public-rc-template.out

passed_evidence="$TMP_DIR/stable-candidate-rc-qa.json"
jq \
  --arg macos_version "14.7" \
  '.status = "passed"
   | .environment.macos_version = $macos_version
   | .environment.arch = "arm64"
   | .checks |= with_entries(.value = "passed")
   | .operator_notes = ["redacted stable-candidate RC evidence"]' \
  "$template_evidence" > "$passed_evidence"
"$GATE" --candidate-manifest "$candidate_manifest" --evidence "$passed_evidence" >/dev/null

expect_failure "stale protocol stable-candidate manifest rejected" \
  "$GATE" --candidate-manifest "$stale_protocol_manifest" --evidence "$passed_evidence"
grep -q "stable-candidate manifest min_protocol_version must be 11" /tmp/macos-public-rc-gate.out

stable_binding="$TMP_DIR/stable-manifest.json"
write_stable_binding_manifest \
  "$stable_binding" \
  "abcdef123456" \
  "$candidate_sha" \
  "stable-candidate-rc-qa.json"
"$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$stable_binding" >/dev/null

bad_stable_protocol="$TMP_DIR/bad-stable-protocol-manifest.json"
jq '.min_protocol_version = 10' "$stable_binding" > "$bad_stable_protocol"
expect_failure "stable binding stale protocol rejected" \
  "$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$bad_stable_protocol"
grep -q "stable manifest min_protocol_version must be 11" /tmp/macos-public-rc-gate.out

dev_manifest="$TMP_DIR/dev-release-manifest.json"
write_candidate_manifest "dev" "$dev_manifest"
expect_failure "dev manifest rejected" \
  "$GATE" --candidate-manifest "$dev_manifest" --evidence "$passed_evidence"

stable_channel_manifest="$TMP_DIR/stable-channel-release-manifest.json"
write_candidate_manifest "stable" "$stable_channel_manifest"
expect_failure "stable manifest rejected as stable-candidate candidate" \
  "$GATE" --candidate-manifest "$stable_channel_manifest" --evidence "$passed_evidence"

bad_sha_evidence="$TMP_DIR/bad-sha-stable-candidate-rc-qa.json"
jq '.candidate_manifest.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$passed_evidence" > "$bad_sha_evidence"
expect_failure "bad evidence stable-candidate SHA" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_sha_evidence"

bad_runtime_evidence="$TMP_DIR/bad-runtime-stable-candidate-rc-qa.json"
jq '.local_platform.runtime = "ottto-cli"' \
  "$passed_evidence" > "$bad_runtime_evidence"
expect_failure "bad local-platform runtime" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_runtime_evidence"
grep -q "local_platform.runtime must be ottto-service" /tmp/macos-public-rc-gate.out

bad_protocol_evidence="$TMP_DIR/bad-protocol-stable-candidate-rc-qa.json"
jq '.local_platform.protocol_version = 10' \
  "$passed_evidence" > "$bad_protocol_evidence"
expect_failure "bad local-platform protocol" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_protocol_evidence"
grep -q "local_platform.protocol_version must be 11" /tmp/macos-public-rc-gate.out

bad_runtime_sha_evidence="$TMP_DIR/bad-runtime-sha-stable-candidate-rc-qa.json"
jq '.local_platform.release_manifest_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$passed_evidence" > "$bad_runtime_sha_evidence"
expect_failure "bad local-platform manifest SHA" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_runtime_sha_evidence"
grep -q "local_platform.release_manifest_sha256 does not match stable-candidate manifest" /tmp/macos-public-rc-gate.out

unsigned_candidate_manifest="$TMP_DIR/unsigned-stable-candidate-release-manifest.json"
jq '(.artifacts[] | select(.kind == "cli")).signed = false' \
  "$candidate_manifest" > "$unsigned_candidate_manifest"
expect_failure "unsigned stable-candidate manifest rejected" \
  "$GATE" --candidate-manifest "$unsigned_candidate_manifest" --evidence "$passed_evidence"
grep -q "not marked signed" /tmp/macos-public-rc-gate.out

unnotarized_candidate_manifest="$TMP_DIR/unnotarized-stable-candidate-release-manifest.json"
jq '(.artifacts[] | select(.kind == "daemon")).notarized = false' \
  "$candidate_manifest" > "$unnotarized_candidate_manifest"
expect_failure "unnotarized stable-candidate manifest rejected" \
  "$GATE" --candidate-manifest "$unnotarized_candidate_manifest" --evidence "$passed_evidence"
grep -q "not marked notarized" /tmp/macos-public-rc-gate.out

not_gatekeeper_candidate_manifest="$TMP_DIR/not-gatekeeper-stable-candidate-release-manifest.json"
jq '(.artifacts[] | select(.kind == "macos_app")).gatekeeper_assessed = false' \
  "$candidate_manifest" > "$not_gatekeeper_candidate_manifest"
expect_failure "not-gatekeeper stable-candidate manifest rejected" \
  "$GATE" --candidate-manifest "$not_gatekeeper_candidate_manifest" --evidence "$passed_evidence"
grep -q "not marked Gatekeeper-assessed" /tmp/macos-public-rc-gate.out

private_path_evidence="$TMP_DIR/private-path-stable-candidate-rc-qa.json"
private_root="/""Users"
private_repo_name="coding-agents-""observability"
private_path="$private_root/operator/private/$private_repo_name"
jq --arg private_path "$private_path" '.operator_notes += [$private_path]' \
  "$passed_evidence" > "$private_path_evidence"
expect_failure "private path evidence" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$private_path_evidence"

missing_check_evidence="$TMP_DIR/missing-check-stable-candidate-rc-qa.json"
jq 'del(.checks.verify_codex)' "$passed_evidence" > "$missing_check_evidence"
expect_failure "missing required check" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$missing_check_evidence"

bad_stable_sha="$TMP_DIR/bad-stable-sha-manifest.json"
write_stable_binding_manifest \
  "$bad_stable_sha" \
  "abcdef123456" \
  "1111111111111111111111111111111111111111111111111111111111111111" \
  "stable-candidate-rc-qa.json"
expect_failure "stable binding stable-candidate SHA mismatch" \
  "$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$bad_stable_sha"

bad_stable_path="$TMP_DIR/bad-stable-path-manifest.json"
write_stable_binding_manifest \
  "$bad_stable_path" \
  "abcdef123456" \
  "$candidate_sha" \
  "different-stable-candidate-rc-qa.json"
expect_failure "stable binding evidence path mismatch" \
  "$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$bad_stable_path"

echo "macos_public_rc_gate tests passed"
