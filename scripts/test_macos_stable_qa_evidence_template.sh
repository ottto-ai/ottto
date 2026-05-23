#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/scripts/macos_stable_qa_evidence_template.sh"
CLOSEOUT_GATE="$ROOT/scripts/macos_stable_closeout_gate.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_manifest() {
  local output="$1"
  jq -n '{
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
        installed_smoke: "stable clean-machine smoke"
      }
    },
    supply_chain: {
      slsa_build: {
        spec_version: "1.2",
        level: "build_l2",
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
        status: "not_run",
        evidence_path: "stable-clean-machine-qa.json",
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

manifest="$tmp_dir/release-manifest.json"
evidence="$tmp_dir/stable-clean-machine-qa.json"
write_manifest "$manifest"

"$TEMPLATE" \
  --manifest "$manifest" \
  --output "$evidence" \
  --checked-at "2026-05-21T19:05:00Z" \
  --macos-version "15.5" \
  --arch "arm64" \
  >/tmp/stable-qa-template.out

test -f "$evidence"
grep -q "stable-qa-template: wrote" /tmp/stable-qa-template.out
jq -e \
  --arg manifest_sha "$(shasum -a 256 "$manifest" | awk '{print $1}')" \
  '
    .schema_version == 1
    and .gate == "stable_clean_machine_qa"
    and .status == "not_run"
    and .checked_at == "2026-05-21T19:05:00Z"
    and .manifest.product == "ottto-local-platform"
    and .manifest.channel == "stable"
    and .manifest.version == "0.1.0"
    and .manifest.commit == "244f7ea90a7a"
    and .manifest.sha256 == $manifest_sha
    and .environment.host_kind == "clean_macos"
    and .environment.macos_version == "15.5"
    and .environment.arch == "arm64"
    and ([.install_owners[].owner] | sort == ["app_bundle", "homebrew", "hosted_installer"])
    and (.install_owners[] | select(.owner == "homebrew") | .checks.formula_syntax == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.runtime == "ottto-service")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.service_label == "net.ottto.service")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.version == "0.1.0")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.release_channel == "stable")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.install_owner == "homebrew")
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.protocol_version == 11)
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform.release_manifest_sha256 == $manifest_sha)
    and (.install_owners[] | select(.owner == "homebrew") | .checks.setup_browser_claim == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .checks.verify_codex_json == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .checks.fix_codex_json == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .checks.diagnostics_collect_json == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .checks.logout_json == "not_run")
    and (.install_owners[] | select(.owner == "homebrew") | .checks.reinstall == "not_run")
    and (.install_owners[] | select(.owner == "hosted_installer") | .checks.native_gatekeeper == "not_run")
    and (.install_owners[] | select(.owner == "hosted_installer") | .checks.upgrade == "not_run")
    and (.install_owners[] | select(.owner == "hosted_installer") | .checks.post_reinstall_status_json == "not_run")
    and (.install_owners[] | select(.owner == "app_bundle") | .checks.artifact_checksum == "not_run")
    and (.install_owners[] | select(.owner == "app_bundle") | .checks.apps_detect_json == "not_run")
  ' "$evidence" >/dev/null

if "$CLOSEOUT_GATE" --manifest "$manifest" >/tmp/stable-qa-template-closeout.out 2>&1; then
  echo "Expected closeout gate to reject an unfilled evidence template" >&2
  exit 1
fi
grep -q "template placeholders" /tmp/stable-qa-template-closeout.out

jq '
  .status = "passed"
  | .install_owners |= map(.status = "passed" | .checks |= with_entries(.value = "passed"))
' "$evidence" > "$tmp_dir/passed.json"
mv "$tmp_dir/passed.json" "$evidence"
"$CLOSEOUT_GATE" --manifest "$manifest" >/tmp/stable-qa-template-passed.out
grep -q "Stable closeout gate passed" /tmp/stable-qa-template-passed.out

if "$TEMPLATE" --manifest "$manifest" --output "$evidence" >/tmp/stable-qa-template-existing.out 2>&1; then
  echo "Expected template generation to refuse overwriting existing evidence" >&2
  exit 1
fi
grep -q "output already exists" /tmp/stable-qa-template-existing.out

bad_required="$tmp_dir/bad-required.json"
jq 'del(.quality_gates.stable_clean_machine_qa.required_install_owners[] | select(. == "homebrew"))' \
  "$manifest" > "$bad_required"
if "$TEMPLATE" --manifest "$bad_required" --output "$tmp_dir/bad-required-evidence.json" >/tmp/stable-qa-template-bad-required.out 2>&1; then
  echo "Expected template generation to reject missing required install owners" >&2
  exit 1
fi
grep -q "required_install_owners is missing supported owner(s): homebrew" /tmp/stable-qa-template-bad-required.out

dev_manifest="$tmp_dir/dev-manifest.json"
jq '.channel = "dev"' "$manifest" > "$dev_manifest"
if "$TEMPLATE" --manifest "$dev_manifest" --output - >/tmp/stable-qa-template-dev.out 2>&1; then
  echo "Expected template generation to reject non-stable manifests" >&2
  exit 1
fi
grep -q "expected stable manifest" /tmp/stable-qa-template-dev.out

stale_protocol_manifest="$tmp_dir/stale-protocol-manifest.json"
jq '.min_protocol_version = 10' "$manifest" > "$stale_protocol_manifest"
if "$TEMPLATE" --manifest "$stale_protocol_manifest" --output - >/tmp/stable-qa-template-stale-protocol.out 2>&1; then
  echo "Expected template generation to reject stale protocol manifests" >&2
  exit 1
fi
grep -q "min_protocol_version must be 11" /tmp/stable-qa-template-stale-protocol.out

echo "macos_stable_qa_evidence_template tests passed"
