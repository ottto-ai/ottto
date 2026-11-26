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
  <string>0.1.0-rc1</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0-rc1</string>
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
# The binaries are copies of a signed system executable on macOS, so codesign
# verifies them, and they ship in real ZIPs, as in a release.
cli_bin="$TMP_DIR/ottto"
daemon_bin="$TMP_DIR/ottto-service"
true_bin="$(type -P true)"
cp "$true_bin" "$cli_bin"
cp "$true_bin" "$daemon_bin"
python3 - "$cli_bin" "$cli_zip" "$daemon_bin" "$daemon_zip" <<'PY_ZIP'
import os
import sys
import zipfile

for binary, archive in ((sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])):
    entry = zipfile.ZipInfo(os.path.basename(binary), date_time=(2026, 5, 21, 0, 0, 0))
    entry.create_system = 3
    entry.external_attr = 0o100755 << 16
    with open(binary, "rb") as source, zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr(entry, source.read())
PY_ZIP
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
jq -n '{
  schema_version: 1,
  gate: "packaged_app_launch",
  status: "passed",
  checked_at: "2026-05-21T00:00:00Z",
  app_path: "Ottto.app",
  wait_seconds: 1,
  bundle_id: "net.ottto.Companion",
  bundle_version: "0.1.0-rc1",
  bundle_short_version: "0.1.0-rc1",
  executable_name: "Ottto",
  process_survived_wait: true,
  crash_reports: []
}' > "$launch_evidence"

write_candidate_manifest() {
  local channel="$1"
  local manifest="$2"
  local version="0.1.0-rc1"
  local prefix="https://install.ottto.net/ottto-local-platform/releases/$channel/$version"

  jq -n \
    --arg channel "$channel" \
    --arg version "$version" \
    --arg prefix "$prefix" \
    --arg app_dmg "$(basename "$app_dmg")" \
    --arg app_bundle "$(basename "$app_bundle")" \
    --arg cli_bin "$(basename "$cli_bin")" \
    --arg daemon_bin "$(basename "$daemon_bin")" \
    --arg cli_zip "$(basename "$cli_zip")" \
    --arg daemon_zip "$(basename "$daemon_zip")" \
    --arg sbom "$(basename "$sbom")" \
    --arg launch_evidence "$(basename "$launch_evidence")" \
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
      min_protocol_version: 15,
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
        materials: [
          {
            kind: "git_repository",
            repository: "ottto-ai/ottto",
            commit: "abcdef123456abcdef123456abcdef123456abcd"
          },
          {
            kind: "private_source",
            name: "ottto-macos-app",
            visibility: "private",
            commit: "123456abcdef123456abcdef123456abcdef1234",
            tree: "fedcba654321fedcba654321fedcba654321fedc",
            clean: true
          }
        ],
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
          verification_command: "gh attestation verify ./Ottto-macos-arm64.dmg -R ottto-ai/ottto"
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
          verification_command: "gh attestation verify ./Ottto-macos-arm64.dmg -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        packaged_app_launch: {
          status: "passed",
          checked_at: "2026-05-21T00:00:00Z",
          wait_seconds: 1,
          bundle_id: "net.ottto.Companion",
          bundle_version: "0.1.0-rc1",
          bundle_short_version: "0.1.0-rc1",
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
          verification_path: $cli_bin,
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
          verification_path: $daemon_bin,
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
      min_protocol_version: 15,
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
   and .candidate_manifest.app_source_commit == "123456abcdef123456abcdef123456abcdef1234"
   and .local_platform.version == "0.1.0-rc1"
   and .local_platform.release_channel == "stable-candidate"
   and .local_platform.protocol_version == 15
   and .local_platform.release_manifest_sha256 == $candidate_sha
   and .update_lifecycle.launch_provenance == "TODO_launchservices_bundle"
   and .update_lifecycle.manual_process_termination == true
   and .update_lifecycle.manual_app_launch == true
   and .checks.app_owner_version_truth == "not_run"
   and .checks.app_owner_sparkle_autonomous_lifecycle == "not_run"' \
  "$template_evidence" >/dev/null
expect_failure "unfilled template evidence" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$template_evidence"

stale_protocol_manifest="$TMP_DIR/stale-protocol-stable-candidate-release-manifest.json"
jq '.min_protocol_version = 11' "$candidate_manifest" > "$stale_protocol_manifest"
if "$TEMPLATE" --candidate-manifest "$stale_protocol_manifest" --output - >/tmp/macos-public-rc-template.out 2>&1; then
  echo "Expected stable-candidate RC template generation to reject stale protocol manifests" >&2
  exit 1
fi
grep -q "min_protocol_version must be 15" /tmp/macos-public-rc-template.out

passed_evidence="$TMP_DIR/stable-candidate-rc-qa.json"
jq \
  --arg macos_version "14.7" \
  '.status = "passed"
   | .environment.macos_version = $macos_version
   | .environment.arch = "arm64"
   | .update_lifecycle = {
       launch_provenance: "launchservices_bundle",
       user_update_actions: 1,
       starting_service_owner: "app_bundle",
       service_restarted_on_target_version: true,
       sparkle_terminated_old_process: true,
       sparkle_relaunched_target_bundle: true,
       process_id_changed: true,
       final_service_owner: "app_bundle",
       manual_process_termination: false,
       manual_app_launch: false,
       account_continuity_verified: true,
       source_continuity_verified: true,
       diagnostics_via_app_service_socket: true,
       verify_via_app_service_socket: true,
       owner_prefix_protocol_schema_version_converged: true
     }
   | .checks |= with_entries(.value = "passed")
   | .operator_notes = ["redacted stable-candidate RC evidence"]' \
  "$template_evidence" > "$passed_evidence"
python3 "$ROOT/scripts/test_resource_scorecard.py" --fixture "$passed_evidence"
"$GATE" --candidate-manifest "$candidate_manifest" --evidence "$passed_evidence" >/dev/null

# Releases do not require sampler evidence; supplied scorecards still fail closed.
optional_resource_evidence="$TMP_DIR/optional-resource-rc-qa.json"
jq 'del(.resource_scorecard, .checks.resource_soak)' "$passed_evidence" > "$optional_resource_evidence"
"$GATE" --candidate-manifest "$candidate_manifest" --evidence "$optional_resource_evidence" \
  | grep -q '^resource scorecard: absent$'
jq '.resource_scorecard = {schema_version: 1, policy: "resource-stage1-v1", status: "not_run"}
    | .checks.resource_soak = "not_run"' "$passed_evidence" > "$optional_resource_evidence"
"$GATE" --candidate-manifest "$candidate_manifest" --evidence "$optional_resource_evidence" \
  | grep -q '^resource scorecard: absent$'
jq '.resource_scorecard = {}' "$passed_evidence" > "$optional_resource_evidence"
expect_failure "supplied incomplete resource scorecard rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$optional_resource_evidence"
grep -q 'resource_scorecard: schema_version must be 1' /tmp/macos-public-rc-gate.out
jq '.resource_scorecard.candidate.metrics.energy_mw = 101' "$passed_evidence" > "$optional_resource_evidence"
expect_failure "supplied resource regression rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$optional_resource_evidence"
grep -q 'energy_mw: absolute bound exceeded' /tmp/macos-public-rc-gate.out

bad_app_commit_evidence="$TMP_DIR/bad-app-commit-stable-candidate-rc-qa.json"
jq '.candidate_manifest.app_source_commit = "999999abcdef123456abcdef123456abcdef1234"' \
  "$passed_evidence" > "$bad_app_commit_evidence"
expect_failure "evidence app source commit mismatch rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_app_commit_evidence"
grep -q "evidence stable-candidate app_source_commit does not match" /tmp/macos-public-rc-gate.out

expect_failure "stale protocol stable-candidate manifest rejected" \
  "$GATE" --candidate-manifest "$stale_protocol_manifest" --evidence "$passed_evidence"
grep -q "stable-candidate manifest min_protocol_version must be 15" /tmp/macos-public-rc-gate.out

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
jq '.min_protocol_version = 11' "$stable_binding" > "$bad_stable_protocol"
expect_failure "stable binding stale protocol rejected" \
  "$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$bad_stable_protocol"
grep -q "stable manifest min_protocol_version must be 15" /tmp/macos-public-rc-gate.out

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
jq '.local_platform.protocol_version = 11' \
  "$passed_evidence" > "$bad_protocol_evidence"
expect_failure "bad local-platform protocol" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$bad_protocol_evidence"
grep -q "local_platform.protocol_version must be 15" /tmp/macos-public-rc-gate.out

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
private_path="$private_root/example-operator/work/app-checkout"
jq --arg private_path "$private_path" '.operator_notes += [$private_path]' \
  "$passed_evidence" > "$private_path_evidence"
expect_failure "private path evidence" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$private_path_evidence"

missing_check_evidence="$TMP_DIR/missing-check-stable-candidate-rc-qa.json"
jq 'del(.checks.app_owner_version_truth)' "$passed_evidence" > "$missing_check_evidence"
expect_failure "missing app-owner version truth check" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$missing_check_evidence"
grep -q "app_owner_version_truth" /tmp/macos-public-rc-gate.out

missing_lifecycle_evidence="$TMP_DIR/missing-lifecycle-stable-candidate-rc-qa.json"
jq 'del(.update_lifecycle)' "$passed_evidence" > "$missing_lifecycle_evidence"
expect_failure "missing autonomous lifecycle evidence" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$missing_lifecycle_evidence"
grep -q "evidence update_lifecycle must be an object" /tmp/macos-public-rc-gate.out

manual_termination_evidence="$TMP_DIR/manual-termination-stable-candidate-rc-qa.json"
jq '.update_lifecycle.manual_process_termination = true' \
  "$passed_evidence" > "$manual_termination_evidence"
expect_failure "manual process termination rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$manual_termination_evidence"
grep -q "update_lifecycle.manual_process_termination must be False" /tmp/macos-public-rc-gate.out

manual_launch_evidence="$TMP_DIR/manual-launch-stable-candidate-rc-qa.json"
jq '.update_lifecycle.manual_app_launch = true' \
  "$passed_evidence" > "$manual_launch_evidence"
expect_failure "manual app launch rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$manual_launch_evidence"
grep -q "update_lifecycle.manual_app_launch must be False" /tmp/macos-public-rc-gate.out

noncanonical_launch_evidence="$TMP_DIR/noncanonical-launch-stable-candidate-rc-qa.json"
jq '.update_lifecycle.launch_provenance = "executable_path"' \
  "$passed_evidence" > "$noncanonical_launch_evidence"
expect_failure "noncanonical launch provenance rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$noncanonical_launch_evidence"
grep -q "update_lifecycle.launch_provenance must be 'launchservices_bundle'" /tmp/macos-public-rc-gate.out

boolean_action_count_evidence="$TMP_DIR/boolean-action-count-stable-candidate-rc-qa.json"
jq '.update_lifecycle.user_update_actions = true' \
  "$passed_evidence" > "$boolean_action_count_evidence"
expect_failure "boolean action count rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$boolean_action_count_evidence"
grep -q "update_lifecycle.user_update_actions must be 1" /tmp/macos-public-rc-gate.out

numeric_boolean_evidence="$TMP_DIR/numeric-boolean-stable-candidate-rc-qa.json"
jq '.update_lifecycle.sparkle_relaunched_target_bundle = 1' \
  "$passed_evidence" > "$numeric_boolean_evidence"
expect_failure "numeric boolean rejected" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$numeric_boolean_evidence"
grep -q "update_lifecycle.sparkle_relaunched_target_bundle must be True" /tmp/macos-public-rc-gate.out

homebrew_owner_evidence="$TMP_DIR/homebrew-owner-stable-candidate-rc-qa.json"
jq '.update_lifecycle.starting_service_owner = "homebrew"' \
  "$passed_evidence" > "$homebrew_owner_evidence"
expect_failure "update evidence from a Homebrew-owned service" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$homebrew_owner_evidence"
grep -q "update_lifecycle.starting_service_owner must be 'app_bundle'" /tmp/macos-public-rc-gate.out

final_owner_evidence="$TMP_DIR/final-owner-stable-candidate-rc-qa.json"
jq '.update_lifecycle.final_service_owner = "homebrew"' \
  "$passed_evidence" > "$final_owner_evidence"
expect_failure "update evidence that ends on a Homebrew-owned service" \
  "$GATE" --candidate-manifest "$candidate_manifest" --evidence "$final_owner_evidence"
grep -q "update_lifecycle.final_service_owner must be 'app_bundle'" /tmp/macos-public-rc-gate.out

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

host_path_stable="$TMP_DIR/host-path-stable-manifest.json"
write_stable_binding_manifest \
  "$host_path_stable" \
  "abcdef123456" \
  "$candidate_sha" \
  "$passed_evidence"
expect_failure "stable binding host-path evidence reference" \
  "$GATE" \
  --candidate-manifest "$candidate_manifest" \
  --evidence "$passed_evidence" \
  --stable-manifest "$host_path_stable"
grep -q "evidence reference must be a release filename beside the manifest" /tmp/macos-public-rc-gate.out
if grep -Fq "$TMP_DIR" /tmp/macos-public-rc-gate.out; then
  echo "Stable-candidate RC gate printed the rejected evidence path" >&2
  exit 1
fi

legacy_material_manifest="$TMP_DIR/legacy-material-stable-candidate-release-manifest.json"
jq '.supply_chain.materials[1] |= (.kind = "git_subtree" | .repository = "example-org/example-app" | del(.name, .visibility))' \
  "$candidate_manifest" > "$legacy_material_manifest"
if "$TEMPLATE" --candidate-manifest "$legacy_material_manifest" --output - >/tmp/macos-public-rc-template.out 2>&1; then
  echo "Expected stable-candidate RC template generation to reject a legacy app material" >&2
  exit 1
fi
grep -q "exactly one app source commit" /tmp/macos-public-rc-template.out

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

# A downloaded candidate holds the published archives, not the app and
# binaries the manifest names as verification targets, so the gate refuses it.
# The verification folder copies the record byte for byte, checks each archive
# against its SHA-256 and unpacks all three targets under their recorded
# names; the gate then passes on it with the same evidence.
DOWNLOAD="$TMP_DIR/download/run-1/ottto-macos-stable-candidate-0.1.0-rc1"
mkdir -p "$DOWNLOAD"
cp "$candidate_manifest" "$DOWNLOAD/release-manifest.json"
printf 'synthetic signature\n' > "$DOWNLOAD/release-manifest.json.sig"
cp "$app_dmg" "$cli_zip" "$daemon_zip" "$sbom" "$launch_evidence" "$DOWNLOAD/"
expect_failure "downloaded candidate without verification targets" \
  "$GATE" --candidate-manifest "$DOWNLOAD/release-manifest.json" --evidence "$passed_evidence"

# hdiutil is stubbed: the disk image "mounts" the fixture app. ditto is
# emulated where the host has none (Linux CI); macOS uses the real one.
STUB_BIN="$TMP_DIR/stub-bin"
mkdir -p "$STUB_BIN"
cat > "$STUB_BIN/hdiutil" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  attach)
    mountpoint=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "-mountpoint" ]]; then mountpoint="$2"; shift 2; else shift; fi
    done
    [[ -d "$mountpoint" ]]
    cp -pR "$FAKE_DMG_APP" "$mountpoint/"
    ;;
  detach)
    find "$2" -mindepth 1 -delete
    ;;
  *)
    exit 1
    ;;
esac
SH
if ! command -v ditto >/dev/null 2>&1; then
  cat > "$STUB_BIN/ditto" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "-x" && "$2" == "-k" ]]; then
  exec python3 - "$3" "$4" <<'PY_UNZIP'
import os
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    for entry in archive.infolist():
        target = archive.extract(entry, sys.argv[2])
        mode = (entry.external_attr >> 16) & 0o777
        if mode:
            os.chmod(target, mode)
PY_UNZIP
fi
cp -pR "$1" "$2"
SH
fi
chmod +x "$STUB_BIN"/*
STAGE="$ROOT/scripts/macos_release_verification_folder.sh"
VERIFY="$TMP_DIR/download/rc-verify"
PATH="$STUB_BIN:$PATH" FAKE_DMG_APP="$app_bundle" \
  "$STAGE" --manifest "$DOWNLOAD/release-manifest.json" --output "$VERIFY" >/dev/null
cmp "$DOWNLOAD/release-manifest.json" "$VERIFY/release-manifest.json"
test -d "$VERIFY/Ottto.app/Contents"
cmp "$cli_bin" "$VERIFY/ottto"
cmp "$daemon_bin" "$VERIFY/ottto-service"
test ! -e "$DOWNLOAD/Ottto.app"
test ! -e "$DOWNLOAD/ottto"
test ! -e "$DOWNLOAD/ottto-service"
jq -e '[.artifacts[].verification_path] == ["Ottto.app", "ottto", "ottto-service"]' \
  "$VERIFY/release-manifest.json" >/dev/null
"$GATE" --candidate-manifest "$VERIFY/release-manifest.json" --evidence "$passed_evidence" >/dev/null

expect_failure "verification folder already exists" \
  env PATH="$STUB_BIN:$PATH" FAKE_DMG_APP="$app_bundle" \
  "$STAGE" --manifest "$DOWNLOAD/release-manifest.json" --output "$VERIFY"
grep -q "output folder already exists" /tmp/macos-public-rc-gate.out
expect_failure "verification folder inside the publish input" \
  env PATH="$STUB_BIN:$PATH" FAKE_DMG_APP="$app_bundle" \
  "$STAGE" --manifest "$DOWNLOAD/release-manifest.json" --output "$DOWNLOAD/rc-verify"
grep -q "outside the downloaded release folder" /tmp/macos-public-rc-gate.out
test ! -e "$DOWNLOAD/rc-verify"
TAMPERED="$TMP_DIR/tampered/release"
mkdir -p "$TAMPERED"
cp "$DOWNLOAD"/* "$TAMPERED/"
printf 'other bytes\n' >> "$TAMPERED/ottto-macos-arm64.zip"
expect_failure "verification folder from a tampered archive" \
  env PATH="$STUB_BIN:$PATH" FAKE_DMG_APP="$app_bundle" \
  "$STAGE" --manifest "$TAMPERED/release-manifest.json" --output "$TMP_DIR/tampered/rc-verify"
grep -q "archive does not match its manifest SHA-256: ottto" /tmp/macos-public-rc-gate.out
test ! -e "$TMP_DIR/tampered/rc-verify"

echo "macos_public_rc_gate tests passed"
