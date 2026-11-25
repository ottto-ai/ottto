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
  and (.properties.channel.enum | index("stable-candidate"))
  and (.properties.quality_gates.properties.stable_candidate_rc.required | index("candidate_manifest_sha256"))
  and (.properties.supply_chain.required | index("materials"))
  and (.properties.supply_chain.properties.materials.items.properties.commit.pattern == "^[0-9a-f]{40}$")
  and (.properties.supply_chain.properties.materials.items.properties.tree.pattern == "^[0-9a-f]{40}$")
  and (.properties.supply_chain.properties.materials.items.properties.kind.enum == ["git_repository", "private_source"])
  and (.properties.supply_chain.properties.materials.items.properties | has("path") | not)
  and (."$defs".release_filename.pattern == "^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")
  and (.properties.artifacts.items.properties.path."$ref" == "#/$defs/release_filename")
  and (.properties.artifacts.items.properties.verification_path."$ref" == "#/$defs/release_filename")
  and (.properties.supply_chain.properties.sbom.properties.path."$ref" == "#/$defs/release_filename")
  and (.properties.supply_chain.properties.slsa_build.properties.predicate_type.const == "https://slsa.dev/provenance/v1")
  and (.properties.supply_chain.properties.sbom.properties.predicate_type.const == "https://cyclonedx.org/bom")
' "$SCHEMA" >/dev/null

# Release files sit beside the manifests in one release folder; manifests name
# them by plain filename.
REL="$TMP_DIR/release"
mkdir -p "$REL"
artifact="$REL/ottto"
printf '#!/usr/bin/env sh\nexit 0\n' > "$artifact"
chmod +x "$artifact"
sha="$(shasum -a 256 "$artifact" | awk '{print $1}')"
sbom="$REL/ottto-local-platform-sbom.cdx.json"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
sbom_sha="$(shasum -a 256 "$sbom" | awk '{print $1}')"
launch_evidence="$REL/packaged-app-launch-smoke.json"

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
      app_path: "Fake.app",
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
    --arg artifact "$(basename "$artifact")" \
    --arg sbom "$(basename "$sbom")" \
    --arg sha "$sha256" \
    --arg sbom_sha "$sbom_sha" \
    --arg launch_evidence "$(basename "$launch_evidence")" \
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
      min_protocol_version: 15,
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
          subjects: ["ottto", "release-manifest.json", "ottto-local-platform-sbom.cdx.json"],
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ./ottto -R ottto-ai/ottto"
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
          verification_command: "gh attestation verify ./ottto -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
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

dev_manifest="$REL/dev-manifest.json"
write_manifest "dev" "$sha" "false" "false" "false" "$dev_manifest"
"$GATE" --manifest "$dev_manifest" >/dev/null

# expect_gate_failure <label> <expected message> <jq filter>: a dev manifest
# variant, written beside the release files, must fail with that message.
expect_gate_failure() {
  local label="$1"
  local message="$2"
  local filter="$3"
  local variant="$REL/$label-manifest.json"
  jq --arg rel "$REL" "$filter" "$dev_manifest" > "$variant"
  if "$GATE" --manifest "$variant" >"$TMP_DIR/$label.out" 2>&1; then
    echo "Expected release gate to reject $label" >&2
    exit 1
  fi
  if ! grep -Fq "$message" "$TMP_DIR/$label.out"; then
    echo "Release gate did not report $label: $(cat "$TMP_DIR/$label.out")" >&2
    exit 1
  fi
  # Refusals name the field and the reason, never the rejected value, so a
  # host path in a bad record does not reach a public job log.
  if grep -Fq "$TMP_DIR" "$TMP_DIR/$label.out"; then
    echo "Release gate printed a host path while rejecting $label" >&2
    exit 1
  fi
}

# Files resolve beside the manifest, never in the working directory: a moved
# release folder checked from a directory holding same-name decoys passes.
DECOY="$TMP_DIR/decoy"
mkdir -p "$DECOY"
printf 'decoy\n' > "$DECOY/ottto"
printf '{}\n' > "$DECOY/ottto-local-platform-sbom.cdx.json"
printf '{}\n' > "$DECOY/packaged-app-launch-smoke.json"
MOVED="$TMP_DIR/moved release"
cp -R "$REL" "$MOVED"
(cd "$DECOY" && "$GATE" --manifest "$MOVED/dev-manifest.json" >/dev/null)
(cd "$DECOY" && "$GATE" --manifest "../moved release/dev-manifest.json" >/dev/null)
rm -f "$MOVED/ottto"
if (cd "$DECOY" && "$GATE" --manifest "$MOVED/dev-manifest.json" >/dev/null 2>&1); then
  echo "Expected a missing release file not to resolve to a working-directory decoy" >&2
  exit 1
fi

ln -s ottto "$REL/ottto-link"
# The filters read $rel as a jq variable, not a shell one.
# shellcheck disable=SC2016
{
# The bad artifact path is also listed as a subject, so the case reaches the
# file resolver rather than the earlier subject check.
expect_gate_failure absolute-artifact "path must name a release file beside the manifest" \
  '.artifacts[0].path = ($rel + "/ottto") | .supply_chain.slsa_build.subjects += [.artifacts[0].path]'
expect_gate_failure traversal-artifact "path must name a release file beside the manifest" \
  '.artifacts[0].path = "../release/ottto" | .supply_chain.slsa_build.subjects += [.artifacts[0].path]'
expect_gate_failure symlink-artifact "path must name a release file beside the manifest" \
  '.artifacts[0].path = "ottto-link" | .supply_chain.slsa_build.subjects += [.artifacts[0].path]'
expect_gate_failure absolute-verification "Verification path must be a release filename" \
  '.artifacts[0].verification_path = ($rel + "/ottto")'
expect_gate_failure absolute-sbom "SBOM path must name a release file beside the manifest" \
  '.supply_chain.sbom.path = ($rel + "/ottto-local-platform-sbom.cdx.json")'
expect_gate_failure absolute-launch-evidence "launch evidence_path must name a release file beside the manifest" \
  '.quality_gates.packaged_app_launch.evidence_path = ($rel + "/packaged-app-launch-smoke.json")'
expect_gate_failure absolute-command "verification commands must name a release subject" \
  '.supply_chain.slsa_build.verification_command = ("gh attestation verify " + $rel + "/ottto -R ottto-ai/ottto")'
expect_gate_failure bare-command "verification commands must name a release subject" \
  '.supply_chain.sbom.verification_command = "gh attestation verify ottto -R ottto-ai/ottto"'
expect_gate_failure non-subject-command "verification commands must name a release subject" \
  '.supply_chain.slsa_build.verification_command = "gh attestation verify ./other -R ottto-ai/ottto"'
}

# The private app source is bound by commit and tree only: exact keys and
# constants, no repository name or path.
expect_gate_failure legacy-subtree-material "app source material is invalid" \
  '.supply_chain.materials[1] = {kind: "git_subtree", repository: "example-org/example-app", commit: .supply_chain.materials[1].commit, path: "app", tree: .supply_chain.materials[1].tree, clean: true}'
expect_gate_failure material-with-repository "app source material is invalid" \
  '.supply_chain.materials[1].repository = "example-org/example-app"'
expect_gate_failure material-with-path "app source material is invalid" \
  '.supply_chain.materials[1].path = "app"'
expect_gate_failure material-missing-tree "app source material is invalid" \
  'del(.supply_chain.materials[1].tree)'
expect_gate_failure material-short-commit "app source material is invalid" \
  '.supply_chain.materials[1].commit = "123456abcdef"'
expect_gate_failure material-uppercase-tree "app source material is invalid" \
  '.supply_chain.materials[1].tree |= ascii_upcase'
expect_gate_failure material-string-clean "app source material is invalid" \
  '.supply_chain.materials[1].clean = "true"'
expect_gate_failure material-other-name "app source material is invalid" \
  '.supply_chain.materials[1].name = "other-app"'
expect_gate_failure material-public-visibility "app source material is invalid" \
  '.supply_chain.materials[1].visibility = "public"'

host_launch_evidence="$REL/host-path-launch-smoke.json"
jq '.app_path = "/tmp/Fake.app"' "$launch_evidence" > "$host_launch_evidence"
expect_gate_failure host-path-launch-app "must name the app by its release filename" \
  '.quality_gates.packaged_app_launch.evidence_path = "host-path-launch-smoke.json"'

stable_candidate_manifest="$REL/stable-candidate-manifest.json"
jq '.channel = "stable-candidate" | .version = "0.1.0-stable-candidate.1"' \
  "$dev_manifest" > "$stable_candidate_manifest"
"$GATE" --manifest "$stable_candidate_manifest" >/dev/null

missing_owner_manifest="$REL/missing-owner-manifest.json"
jq 'del(.supported_install_owners)' "$dev_manifest" > "$missing_owner_manifest"
if "$GATE" --manifest "$missing_owner_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without supported install owners to fail" >&2
  exit 1
fi

missing_rollback_manifest="$REL/missing-rollback-manifest.json"
jq 'del(.rollback)' "$dev_manifest" > "$missing_rollback_manifest"
if "$GATE" --manifest "$missing_rollback_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without rollback metadata to fail" >&2
  exit 1
fi

missing_supply_chain_manifest="$REL/missing-supply-chain-manifest.json"
jq 'del(.supply_chain)' "$dev_manifest" > "$missing_supply_chain_manifest"
if "$GATE" --manifest "$missing_supply_chain_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without supply-chain metadata to fail" >&2
  exit 1
fi

missing_materials_manifest="$REL/missing-materials-manifest.json"
jq 'del(.supply_chain.materials)' "$dev_manifest" > "$missing_materials_manifest"
if "$GATE" --manifest "$missing_materials_manifest" >/dev/null 2>&1; then
  echo "Expected manifest without source materials to fail" >&2
  exit 1
fi

spoofed_app_material_manifest="$REL/spoofed-app-material-manifest.json"
jq '.supply_chain.materials[1].kind = "git_subtree"' \
  "$dev_manifest" > "$spoofed_app_material_manifest"
if "$GATE" --manifest "$spoofed_app_material_manifest" >/dev/null 2>&1; then
  echo "Expected manifest with spoofed private app source material to fail" >&2
  exit 1
fi

bad_sbom_sha_manifest="$REL/bad-sbom-sha-manifest.json"
jq '.supply_chain.sbom.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$dev_manifest" > "$bad_sbom_sha_manifest"
if "$GATE" --manifest "$bad_sbom_sha_manifest" >/dev/null 2>&1; then
  echo "Expected manifest with bad SBOM SHA to fail" >&2
  exit 1
fi

bad_rollback_prefix_manifest="$REL/bad-rollback-prefix-manifest.json"
jq '.rollback.immutable_prefix = "https://install.ottto.net/ottto-local-platform/releases/dev/other"' \
  "$dev_manifest" > "$bad_rollback_prefix_manifest"
if "$GATE" --manifest "$bad_rollback_prefix_manifest" >/dev/null 2>&1; then
  echo "Expected artifact outside rollback immutable prefix to fail" >&2
  exit 1
fi

missing_launch_manifest="$REL/missing-launch-manifest.json"
jq 'del(.quality_gates)' "$dev_manifest" > "$missing_launch_manifest"
if "$GATE" --manifest "$missing_launch_manifest" >/dev/null 2>&1; then
  echo "Expected missing launch quality gate manifest to fail" >&2
  exit 1
fi

failed_launch_evidence="$REL/failed-packaged-app-launch-smoke.json"
write_launch_evidence "failed" "false" '["diagnostic_report"]' "$failed_launch_evidence"
failed_launch_manifest="$REL/failed-launch-manifest.json"
jq --arg evidence "$(basename "$failed_launch_evidence")" \
  '.quality_gates.packaged_app_launch.status = "failed"
   | .quality_gates.packaged_app_launch.process_survived_wait = false
   | .quality_gates.packaged_app_launch.crash_reports = ["diagnostic_report"]
   | .quality_gates.packaged_app_launch.evidence_path = $evidence' \
  "$dev_manifest" > "$failed_launch_manifest"
if "$GATE" --manifest "$failed_launch_manifest" >/dev/null 2>&1; then
  echo "Expected failed launch quality gate manifest to fail" >&2
  exit 1
fi

bad_sha_manifest="$REL/bad-sha-manifest.json"
write_manifest "dev" "0000000000000000000000000000000000000000000000000000000000000000" "false" "false" "false" "$bad_sha_manifest"
if "$GATE" --manifest "$bad_sha_manifest" >/dev/null 2>&1; then
  echo "Expected SHA mismatch manifest to fail" >&2
  exit 1
fi

stable_unsigned_manifest="$REL/stable-unsigned-manifest.json"
jq '.channel = "stable"
    | .version = "0.1.0"
    | .rollback.immutable_prefix = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0"
    | .rollback.latest_manifest_url = "https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json"
    | .artifacts[0].url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto"
    | .supply_chain.sbom.url = "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-local-platform-sbom.cdx.json"
    | .supply_chain.slsa_build.level = "build_l1"
    | .supply_chain.slsa_build.attested = true
    | .supply_chain.slsa_build.verified = true
    | .supply_chain.sbom.attested = true
    | .supply_chain.sbom.verified = true' \
  "$dev_manifest" > "$stable_unsigned_manifest"
if "$GATE" --manifest "$stable_unsigned_manifest" >/dev/null 2>&1; then
  echo "Expected unsigned stable manifest to fail" >&2
  exit 1
fi

# [behaviour] A signing-Mac (SLSA Build L1) stable release passes with verified
# provenance and SBOM attestations. No verification_path keeps this synthetic
# CLI artifact away from codesign/spctl on macOS runners.
stable_l1_manifest="$REL/stable-l1-manifest.json"
jq '.artifacts[0].signed = true
    | .artifacts[0].notarized = true
    | .artifacts[0].gatekeeper_assessed = true
    | del(.artifacts[0].verification_path)' \
  "$stable_unsigned_manifest" > "$stable_l1_manifest"
if ! "$GATE" --manifest "$stable_l1_manifest" >"$TMP_DIR/stable-l1.out" 2>&1; then
  echo "Expected a verified Build L1 stable manifest to pass" >&2
  cat "$TMP_DIR/stable-l1.out" >&2
  exit 1
fi

# [behaviour] Stable still refuses L1 provenance that was not attested and verified.
stable_unverified_manifest="$REL/stable-unverified-manifest.json"
jq '.supply_chain.slsa_build.attested = false
    | .supply_chain.slsa_build.verified = false' \
  "$stable_l1_manifest" > "$stable_unverified_manifest"
if "$GATE" --manifest "$stable_unverified_manifest" >"$TMP_DIR/stable-unverified.out" 2>&1; then
  echo "Expected unverified stable supply-chain manifest to fail" >&2
  exit 1
fi
if ! grep -Fq "Stable releases require verified SLSA provenance attestations" "$TMP_DIR/stable-unverified.out" ||
  grep -Fq "Build L2" "$TMP_DIR/stable-unverified.out"; then
  echo "Unverified stable manifest must fail on the verified-provenance check:" >&2
  cat "$TMP_DIR/stable-unverified.out" >&2
  exit 1
fi

if command -v codesign >/dev/null 2>&1; then
  app_bundle="$REL/Fake.app"
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

  app_manifest="$REL/dev-app-manifest.json"
  jq -n \
    --arg artifact "$(basename "$artifact")" \
    --arg app_bundle "$(basename "$app_bundle")" \
    --arg sbom "$(basename "$sbom")" \
    --arg sha "$sha" \
    --arg sbom_sha "$sbom_sha" \
    --arg launch_evidence "$(basename "$launch_evidence")" \
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
      min_protocol_version: 15,
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
          subjects: ["ottto", "release-manifest.json", "ottto-local-platform-sbom.cdx.json"],
          attested: false,
          verified: false,
          verification_command: "gh attestation verify ./ottto -R ottto-ai/ottto"
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
          verification_command: "gh attestation verify ./ottto -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
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

  # Launch evidence must name the app this manifest verifies.
  other_app_evidence="$REL/other-app-launch-smoke.json"
  jq '.app_path = "Other.app"' "$launch_evidence" > "$other_app_evidence"
  jq '.quality_gates.packaged_app_launch.evidence_path = "other-app-launch-smoke.json"' \
    "$app_manifest" > "$REL/other-app-manifest.json"
  if "$GATE" --manifest "$REL/other-app-manifest.json" >"$TMP_DIR/other-app.out" 2>&1; then
    echo "Expected launch evidence for a different app to fail" >&2
    exit 1
  fi
  grep -Fq "names a different app" "$TMP_DIR/other-app.out" || {
    echo "Release gate did not report the launch app mismatch: $(cat "$TMP_DIR/other-app.out")" >&2
    exit 1
  }
fi

echo "macos_release_gate tests passed"
