#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFLIGHT="$ROOT/scripts/macos_stable_preflight.sh"
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

artifact="$TMP_DIR/ottto"
printf '#!/usr/bin/env sh\nexit 0\n' > "$artifact"
chmod +x "$artifact"
sha="$(shasum -a 256 "$artifact" | awk '{print $1}')"
sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
sbom_sha="$(shasum -a 256 "$sbom" | awk '{print $1}')"
preview_manifest="$TMP_DIR/preview-release-manifest.json"
jq -n '{
  schema_version: 1,
  product: "ottto-local-platform",
  version: "0.1.0-preview.1",
  channel: "preview",
  commit: "abcdef123456"
}' > "$preview_manifest"
preview_sha="$(shasum -a 256 "$preview_manifest" | awk '{print $1}')"
public_rc_evidence="$TMP_DIR/public-release-candidate-qa.json"
jq -n \
  --arg preview_sha "$preview_sha" \
  '{
    schema_version: 1,
    gate: "public_release_candidate",
    status: "passed",
    checked_at: "2026-05-10T00:00:00Z",
    preview_manifest: {
      product: "ottto-local-platform",
      channel: "preview",
      version: "0.1.0-preview.1",
      commit: "abcdef123456",
      sha256: $preview_sha
    },
    environment: {
      host_kind: "trusted_internal_macos",
      macos_version: "14.7",
      arch: "arm64"
    },
    local_platform: {
      runtime: "ottto-service",
      service_label: "net.ottto.service",
      version: "0.1.0-preview.1",
      release_channel: "preview",
      protocol_version: 11,
      release_manifest_sha256: $preview_sha
    },
    checks: {
      release_gate: "passed",
      public_surface_ci: "passed",
      published_manifest_download: "passed",
      artifact_checksums: "passed",
      artifact_signatures: "passed",
      notarization: "passed",
      gatekeeper_assessment: "passed",
      hosted_preview_installer: "passed",
      app_launch: "passed",
      service_ready: "passed",
      status_json: "passed",
      setup_browser_claim: "passed",
      verify_codex: "passed",
      diagnostics_redaction: "passed",
      update_check: "passed",
      rollback_notes: "passed",
      stable_formula_static: "passed",
      stable_hosted_installer_static: "passed"
    }
  }' > "$public_rc_evidence"

write_manifest() {
  local channel="$1"
  local sha256="$2"
  local app_url="$3"
  local manifest="$4"

  jq -n \
    --arg channel "$channel" \
    --arg artifact "$artifact" \
    --arg sbom "$sbom" \
    --arg app_url "$app_url" \
    --arg sha "$sha256" \
    --arg sbom_sha "$sbom_sha" \
    --arg rollback_immutable_prefix "https://install.ottto.net/ottto-local-platform/releases/$channel/0.1.0" \
    --arg rollback_latest_manifest_url "https://install.ottto.net/ottto-local-platform/releases/$channel/latest/release-manifest.json" \
    --arg public_rc_evidence "$public_rc_evidence" \
    --arg preview_sha "$preview_sha" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: $channel,
      commit: "abcdef123456",
      generated_at: "2026-05-10T00:00:00Z",
      min_supported_version: "0.1.0",
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
          level: "build_l2",
          predicate_type: "https://slsa.dev/provenance/v1",
          repository: "ottto-ai/ottto",
          signer_workflow: ".github/workflows/ottto-local-platform-release.yml",
          subjects: [
            "ottto",
            "release-manifest.json",
            "ottto-local-platform-sbom.cdx.json"
          ],
          attested: true,
          verified: true,
          verification_command: "gh attestation verify Ottto-macos-arm64.dmg -R ottto-ai/ottto"
        },
        sbom: {
          format: "cyclonedx-json",
          spec_version: "1.7",
          predicate_type: "https://cyclonedx.org/bom",
          path: $sbom,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-local-platform-sbom.cdx.json",
          sha256: $sbom_sha,
          attested: true,
          verified: true,
          verification_command: "gh attestation verify Ottto-macos-arm64.dmg -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        public_release_candidate: {
          status: "passed",
          checked_at: "2026-05-10T00:00:00Z",
          evidence_path: $public_rc_evidence,
          preview_manifest_sha256: $preview_sha
        }
      },
      artifacts: [
        {
          name: "Ottto.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: $artifact,
          url: $app_url,
          verification_path: $artifact,
          sha256: $sha,
          signed: false,
          notarized: false,
          gatekeeper_assessed: false
        },
        {
          name: "ottto",
          kind: "cli",
          platform: "macos",
          arch: "arm64",
          path: $artifact,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-macos-arm64.zip",
          verification_path: $artifact,
          sha256: $sha,
          signed: false,
          notarized: false,
          gatekeeper_assessed: false
        },
        {
          name: "ottto-service",
          kind: "daemon",
          platform: "macos",
          arch: "arm64",
          path: $artifact,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-service-macos-arm64.zip",
          verification_path: $artifact,
          sha256: $sha,
          signed: false,
          notarized: false,
          gatekeeper_assessed: false
        }
      ]
    }' > "$manifest"
}

stable_manifest="$TMP_DIR/stable-manifest.json"
write_manifest \
  "stable" \
  "$sha" \
  "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg" \
  "$stable_manifest"
"$PREFLIGHT" --manifest "$stable_manifest" --dry-run >/dev/null

dev_manifest="$TMP_DIR/dev-manifest.json"
write_manifest \
  "dev" \
  "$sha" \
  "https://install.ottto.net/ottto-local-platform/releases/dev/0.1.0/Ottto-macos-arm64.dmg" \
  "$dev_manifest"
if "$PREFLIGHT" --manifest "$dev_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected dev-channel manifest to fail stable preflight" >&2
  exit 1
fi

bad_url_manifest="$TMP_DIR/bad-url-manifest.json"
write_manifest \
  "stable" \
  "$sha" \
  "http://localhost/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg" \
  "$bad_url_manifest"
if "$PREFLIGHT" --manifest "$bad_url_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected localhost stable artifact URL to fail" >&2
  exit 1
fi

bad_rollback_manifest="$TMP_DIR/bad-rollback-manifest.json"
jq '.rollback.latest_manifest_url = "https://install.ottto.net/ottto-local-platform/releases/dev/latest/release-manifest.json"' \
  "$stable_manifest" > "$bad_rollback_manifest"
if "$PREFLIGHT" --manifest "$bad_rollback_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected non-stable rollback latest manifest URL to fail" >&2
  exit 1
fi

unverified_supply_chain_manifest="$TMP_DIR/unverified-supply-chain-manifest.json"
jq '.supply_chain.slsa_build.level = "build_l1"
    | .supply_chain.slsa_build.attested = false
    | .supply_chain.slsa_build.verified = false' \
  "$stable_manifest" > "$unverified_supply_chain_manifest"
if "$PREFLIGHT" --manifest "$unverified_supply_chain_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected unverified stable supply-chain metadata to fail" >&2
  exit 1
fi

bad_sbom_sha_manifest="$TMP_DIR/bad-sbom-sha-manifest.json"
jq '.supply_chain.sbom.sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$stable_manifest" > "$bad_sbom_sha_manifest"
if "$PREFLIGHT" --manifest "$bad_sbom_sha_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected bad SBOM SHA to fail stable preflight" >&2
  exit 1
fi

missing_public_rc_manifest="$TMP_DIR/missing-public-rc-manifest.json"
jq 'del(.quality_gates.public_release_candidate)' "$stable_manifest" > "$missing_public_rc_manifest"
if "$PREFLIGHT" --manifest "$missing_public_rc_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected missing public release-candidate evidence gate to fail stable preflight" >&2
  exit 1
fi

failed_public_rc_manifest="$TMP_DIR/failed-public-rc-manifest.json"
jq '.quality_gates.public_release_candidate.status = "not_run"' \
  "$stable_manifest" > "$failed_public_rc_manifest"
if "$PREFLIGHT" --manifest "$failed_public_rc_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected failed public release-candidate evidence gate to fail stable preflight" >&2
  exit 1
fi

bad_public_rc_runtime="$TMP_DIR/public-release-candidate-bad-runtime-qa.json"
jq '.local_platform.protocol_version = 10' "$public_rc_evidence" > "$bad_public_rc_runtime"
bad_public_rc_runtime_manifest="$TMP_DIR/public-rc-bad-runtime-manifest.json"
jq --arg evidence "$bad_public_rc_runtime" \
  '.quality_gates.public_release_candidate.evidence_path = $evidence' \
  "$stable_manifest" > "$bad_public_rc_runtime_manifest"
if "$PREFLIGHT" --manifest "$bad_public_rc_runtime_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected public release-candidate runtime binding mismatch to fail stable preflight" >&2
  exit 1
fi

bad_protocol_manifest="$TMP_DIR/bad-protocol-stable-manifest.json"
jq '.min_protocol_version = 10' "$stable_manifest" > "$bad_protocol_manifest"
if "$PREFLIGHT" --manifest "$bad_protocol_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected stale stable protocol version to fail stable preflight" >&2
  exit 1
fi

commit_mismatch_manifest="$TMP_DIR/public-rc-commit-mismatch-manifest.json"
jq '.commit = "abcdef999999"' "$stable_manifest" > "$commit_mismatch_manifest"
if "$PREFLIGHT" --manifest "$commit_mismatch_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected public release-candidate preview commit mismatch to fail stable preflight" >&2
  exit 1
fi

bad_sha_manifest="$TMP_DIR/bad-sha-manifest.json"
write_manifest \
  "stable" \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg" \
  "$bad_sha_manifest"
if "$PREFLIGHT" --manifest "$bad_sha_manifest" --dry-run >/dev/null 2>&1; then
  echo "Expected SHA mismatch to fail stable preflight" >&2
  exit 1
fi

if "$PREFLIGHT" --manifest "$stable_manifest" >/dev/null 2>&1; then
  echo "Expected non-dry-run stable preflight without Apple credentials to fail" >&2
  exit 1
fi

echo "macos_stable_preflight tests passed"
