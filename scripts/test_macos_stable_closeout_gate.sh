#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/macos_stable_closeout_gate.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_manifest() {
  local output="$1"
  local gate_status="${2:-passed}"
  local evidence_path="${3:-stable-clean-machine-qa.json}"
  jq -n \
    --arg gate_status "$gate_status" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: "stable",
      commit: "244f7ea90a7a",
      generated_at: "2026-05-21T18:00:00Z",
      min_supported_version: "0.1.0",
      min_protocol_version: 11,
      supported_install_owners: ["homebrew", "hosted_installer", "app_bundle"],
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
      supply_chain: {
        slsa_build: {
          spec_version: "1.2",
          level: "build_l2",
          predicate_type: "https://slsa.dev/provenance/v1",
          repository: "ottto-ai/ottto",
          signer_workflow: ".github/workflows/ottto-local-platform-release.yml",
          subjects: [
            "Ottto-macos-arm64.dmg",
            "ottto-macos-arm64.zip",
            "ottto-service-macos-arm64.zip",
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
          path: "ottto-local-platform-sbom.cdx.json",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-local-platform-sbom.cdx.json",
          sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          attested: true,
          verified: true,
          verification_command: "gh attestation verify Ottto-macos-arm64.dmg -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
        }
      },
      quality_gates: {
        stable_clean_machine_qa: {
          status: $gate_status,
          checked_at: "2026-05-21T19:00:00Z",
          evidence_path: $evidence_path,
          required_install_owners: ["homebrew", "hosted_installer", "app_bundle"]
        }
      },
      artifacts: [
        {
          name: "Ottto.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: "Ottto-macos-arm64.dmg",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg",
          sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        },
        {
          name: "ottto",
          kind: "cli",
          platform: "macos",
          arch: "arm64",
          path: "ottto-macos-arm64.zip",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-macos-arm64.zip",
          sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        },
        {
          name: "ottto-service",
          kind: "daemon",
          platform: "macos",
          arch: "arm64",
          path: "ottto-service-macos-arm64.zip",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-service-macos-arm64.zip",
          sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        }
      ]
    }' > "$output"
}

write_evidence() {
  local manifest="$1"
  local output="$2"
  local manifest_sha
  manifest_sha="$(shasum -a 256 "$manifest" | awk '{print $1}')"
  jq -n \
    --arg manifest_sha "$manifest_sha" \
    '{
      schema_version: 1,
      gate: "stable_clean_machine_qa",
      status: "passed",
      checked_at: "2026-05-21T19:00:00Z",
      manifest: {
        product: "ottto-local-platform",
        channel: "stable",
        version: "0.1.0",
        commit: "244f7ea90a7a",
        sha256: $manifest_sha
      },
      environment: {
        host_kind: "clean_macos",
        macos_version: "15.5",
        arch: "arm64"
      },
      install_owners: [
        {
          owner: "homebrew",
          status: "passed",
          local_platform: {
            runtime: "ottto-service",
            service_label: "net.ottto.service",
            version: "0.1.0",
            release_channel: "stable",
            install_owner: "homebrew",
            protocol_version: 11,
            release_manifest_sha256: $manifest_sha
          },
          checks: {
            formula_syntax: "passed",
            install: "passed",
            service_start: "passed",
            status_json: "passed",
            setup_browser_claim: "passed",
            apps_detect_json: "passed",
            verify_codex_json: "passed",
            doctor_json: "passed",
            fix_codex_json: "passed",
            diagnostics_collect_json: "passed",
            logout_json: "passed",
            update_check: "passed",
            upgrade: "passed",
            uninstall: "passed",
            reinstall: "passed",
            post_reinstall_status_json: "passed"
          }
        },
        {
          owner: "hosted_installer",
          status: "passed",
          local_platform: {
            runtime: "ottto-service",
            service_label: "net.ottto.service",
            version: "0.1.0",
            release_channel: "stable",
            install_owner: "hosted_installer",
            protocol_version: 11,
            release_manifest_sha256: $manifest_sha
          },
          checks: {
            wrapper_download: "passed",
            wrapper_checksum: "passed",
            native_gatekeeper: "passed",
            install: "passed",
            app_launch: "passed",
            service_ready: "passed",
            status_json: "passed",
            setup_browser_claim: "passed",
            apps_detect_json: "passed",
            verify_codex_json: "passed",
            doctor_json: "passed",
            fix_codex_json: "passed",
            diagnostics_collect_json: "passed",
            logout_json: "passed",
            update_check: "passed",
            upgrade: "passed",
            uninstall: "passed",
            reinstall: "passed",
            post_reinstall_status_json: "passed"
          }
        },
        {
          owner: "app_bundle",
          status: "passed",
          local_platform: {
            runtime: "ottto-service",
            service_label: "net.ottto.service",
            version: "0.1.0",
            release_channel: "stable",
            install_owner: "app_bundle",
            protocol_version: 11,
            release_manifest_sha256: $manifest_sha
          },
          checks: {
            artifact_checksum: "passed",
            gatekeeper: "passed",
            install: "passed",
            app_launch: "passed",
            service_ready: "passed",
            status_json: "passed",
            setup_browser_claim: "passed",
            apps_detect_json: "passed",
            verify_codex_json: "passed",
            doctor_json: "passed",
            fix_codex_json: "passed",
            diagnostics_collect_json: "passed",
            logout_json: "passed",
            update_check: "passed",
            upgrade: "passed",
            uninstall: "passed",
            reinstall: "passed",
            post_reinstall_status_json: "passed"
          }
        }
      ]
    }' > "$output"
}

expect_failure() {
  local manifest="$1"
  local message="$2"
  local output="$tmp_dir/failure.out"
  if "$GATE" --manifest "$manifest" >"$output" 2>&1; then
    echo "Expected closeout gate to fail: $message" >&2
    exit 1
  fi
  grep -q "$message" "$output"
}

manifest="$tmp_dir/release-manifest.json"
evidence="$tmp_dir/stable-clean-machine-qa.json"
write_manifest "$manifest"
write_evidence "$manifest" "$evidence"
"$GATE" --manifest "$manifest" >/dev/null

not_run_manifest="$tmp_dir/not-run-manifest.json"
write_manifest "$not_run_manifest" "not_run"
write_evidence "$not_run_manifest" "$tmp_dir/not-run-evidence.json"
expect_failure "$not_run_manifest" "Stable clean-machine QA gate did not pass"

missing_owner_dir="$tmp_dir/missing-owner"
mkdir -p "$missing_owner_dir"
cp "$manifest" "$missing_owner_dir/release-manifest.json"
jq 'del(.install_owners[] | select(.owner == "homebrew"))' "$evidence" > "$missing_owner_dir/stable-clean-machine-qa.json"
expect_failure "$missing_owner_dir/release-manifest.json" "Stable clean-machine QA evidence must include exactly one entry for install owner: homebrew"

failed_check_dir="$tmp_dir/failed-check"
mkdir -p "$failed_check_dir"
cp "$manifest" "$failed_check_dir/release-manifest.json"
jq '(.install_owners[] | select(.owner == "hosted_installer") | .checks.status_json) = "failed"' \
  "$evidence" > "$failed_check_dir/stable-clean-machine-qa.json"
expect_failure "$failed_check_dir/release-manifest.json" "Stable clean-machine QA evidence is missing passed check hosted_installer.status_json"

bad_runtime_dir="$tmp_dir/bad-runtime"
mkdir -p "$bad_runtime_dir"
cp "$manifest" "$bad_runtime_dir/release-manifest.json"
jq '(.install_owners[] | select(.owner == "homebrew") | .local_platform.runtime) = "ottto-cli"' \
  "$evidence" > "$bad_runtime_dir/stable-clean-machine-qa.json"
expect_failure "$bad_runtime_dir/release-manifest.json" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: homebrew"

bad_protocol_dir="$tmp_dir/bad-protocol"
mkdir -p "$bad_protocol_dir"
cp "$manifest" "$bad_protocol_dir/release-manifest.json"
jq '(.install_owners[] | select(.owner == "hosted_installer") | .local_platform.protocol_version) = 10' \
  "$evidence" > "$bad_protocol_dir/stable-clean-machine-qa.json"
expect_failure "$bad_protocol_dir/release-manifest.json" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: hosted_installer"

bad_runtime_manifest_dir="$tmp_dir/bad-runtime-manifest"
mkdir -p "$bad_runtime_manifest_dir"
cp "$manifest" "$bad_runtime_manifest_dir/release-manifest.json"
jq '(.install_owners[] | select(.owner == "app_bundle") | .local_platform.release_manifest_sha256) = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' \
  "$evidence" > "$bad_runtime_manifest_dir/stable-clean-machine-qa.json"
expect_failure "$bad_runtime_manifest_dir/release-manifest.json" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: app_bundle"

extra_check_dir="$tmp_dir/extra-check"
mkdir -p "$extra_check_dir"
cp "$manifest" "$extra_check_dir/release-manifest.json"
jq '(.install_owners[] | select(.owner == "homebrew") | .checks.manual_override) = "passed"' \
  "$evidence" > "$extra_check_dir/stable-clean-machine-qa.json"
expect_failure "$extra_check_dir/release-manifest.json" "Stable clean-machine QA evidence includes unknown check homebrew.manual_override"

extra_required_owner_dir="$tmp_dir/extra-required-owner"
mkdir -p "$extra_required_owner_dir"
jq '.quality_gates.stable_clean_machine_qa.required_install_owners += ["manual_override"]' \
  "$manifest" > "$extra_required_owner_dir/release-manifest.json"
write_evidence "$extra_required_owner_dir/release-manifest.json" "$extra_required_owner_dir/stable-clean-machine-qa.json"
expect_failure "$extra_required_owner_dir/release-manifest.json" "Stable clean-machine QA manifest gate includes unsupported required install owner: manual_override"

bad_sha_dir="$tmp_dir/bad-sha"
mkdir -p "$bad_sha_dir"
cp "$manifest" "$bad_sha_dir/release-manifest.json"
jq '.manifest.sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' \
  "$evidence" > "$bad_sha_dir/stable-clean-machine-qa.json"
expect_failure "$bad_sha_dir/release-manifest.json" "Stable clean-machine QA evidence has an invalid envelope"

private_path_dir="$tmp_dir/private-path"
mkdir -p "$private_path_dir"
cp "$manifest" "$private_path_dir/release-manifest.json"
jq '.notes = ["raw output saved under /Users/example/Ottto"]' \
  "$evidence" > "$private_path_dir/stable-clean-machine-qa.json"
expect_failure "$private_path_dir/release-manifest.json" "private path or secret-like material"

dev_manifest="$tmp_dir/dev-manifest.json"
jq '.channel = "dev"' "$manifest" > "$dev_manifest"
expect_failure "$dev_manifest" "Stable closeout requires channel=stable"

echo "macos_stable_closeout_gate tests passed"
