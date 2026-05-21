#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""

usage() {
  cat <<'USAGE'
Usage: macos_release_gate.sh --manifest <release-manifest.json>

Validates artifact presence, SHA-256 integrity, and stable-channel signing /
notarization requirements for the clean-slate Ottto local platform.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest does not exist: $MANIFEST" >&2
  exit 1
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command shasum

valid_https_or_localhost_url() {
  local url="$1"
  case "$url" in
    https://* | http://localhost* | http://127.0.0.1* | http://\[::1\]*) return 0 ;;
    *) return 1 ;;
  esac
}

schema_version="$(jq -r '.schema_version' "$MANIFEST")"
product="$(jq -r '.product' "$MANIFEST")"
if [[ "$schema_version" != "1" ]]; then
  echo "Unsupported release manifest schema_version: $schema_version" >&2
  exit 1
fi
if [[ "$product" != "ottto-local-platform" ]]; then
  echo "Unexpected release manifest product: $product" >&2
  exit 1
fi

CHANNEL="$(jq -r '.channel' "$MANIFEST")"
if [[ "$CHANNEL" != "dev" && "$CHANNEL" != "preview" && "$CHANNEL" != "stable" ]]; then
  echo "Invalid release channel: $CHANNEL" >&2
  exit 1
fi
min_supported_version="$(jq -r '.min_supported_version // empty' "$MANIFEST")"
min_protocol_version="$(jq -r '.min_protocol_version // empty' "$MANIFEST")"
supported_owner_count="$(jq '.supported_install_owners // [] | length' "$MANIFEST")"
unsupported_owners="$(jq -r '[.supported_install_owners[]? | select(. != "hosted_installer" and . != "app_bundle" and . != "homebrew")] | join(",")' "$MANIFEST")"
if [[ -z "$min_supported_version" ]]; then
  echo "Release manifest is missing min_supported_version" >&2
  exit 1
fi
if ! [[ "$min_protocol_version" =~ ^[0-9]+$ ]] || [[ "$min_protocol_version" -lt 1 ]]; then
  echo "Release manifest has invalid min_protocol_version" >&2
  exit 1
fi
if [[ "$supported_owner_count" -lt 1 ]]; then
  echo "Release manifest must list supported install owners" >&2
  exit 1
fi
if [[ -n "$unsupported_owners" ]]; then
  echo "Release manifest has unsupported install owner(s): $unsupported_owners" >&2
  exit 1
fi
rollback_strategy="$(jq -r '.rollback.strategy // empty' "$MANIFEST")"
rollback_immutable_prefix="$(jq -r '.rollback.immutable_prefix // empty' "$MANIFEST")"
rollback_latest_manifest_url="$(jq -r '.rollback.latest_manifest_url // empty' "$MANIFEST")"
rollback_preserve_failed_version="$(jq -r '.rollback.preserve_failed_version // false' "$MANIFEST")"
rollback_operator_step_count="$(jq '.rollback.operator_steps // [] | length' "$MANIFEST")"
rollback_release_gate="$(jq -r '.rollback.verification.release_gate // empty' "$MANIFEST")"
rollback_stable_preflight="$(jq -r '.rollback.verification.stable_preflight // empty' "$MANIFEST")"
rollback_installed_smoke="$(jq -r '.rollback.verification.installed_smoke // empty' "$MANIFEST")"
if [[ -z "$rollback_strategy" ]]; then
  echo "Release manifest is missing rollback metadata" >&2
  exit 1
fi
if [[ "$rollback_strategy" != "channel_latest_pointer" ]]; then
  echo "Release manifest has unsupported rollback strategy: $rollback_strategy" >&2
  exit 1
fi
if [[ -z "$rollback_immutable_prefix" ]] || ! valid_https_or_localhost_url "$rollback_immutable_prefix"; then
  echo "Release manifest has invalid rollback immutable_prefix" >&2
  exit 1
fi
if [[ -z "$rollback_latest_manifest_url" ]] || ! valid_https_or_localhost_url "$rollback_latest_manifest_url"; then
  echo "Release manifest has invalid rollback latest_manifest_url" >&2
  exit 1
fi
if [[ "$rollback_latest_manifest_url" != */release-manifest.json ]]; then
  echo "Release manifest rollback latest_manifest_url must point to release-manifest.json" >&2
  exit 1
fi
if [[ "$rollback_preserve_failed_version" != "true" ]]; then
  echo "Release manifest rollback must preserve failed versioned artifacts" >&2
  exit 1
fi
if [[ "$rollback_operator_step_count" -lt 3 ]]; then
  echo "Release manifest rollback must include at least three operator steps" >&2
  exit 1
fi
if [[ -z "$rollback_release_gate" || -z "$rollback_stable_preflight" || -z "$rollback_installed_smoke" ]]; then
  echo "Release manifest rollback verification metadata is incomplete" >&2
  exit 1
fi

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

manifest_dir="$(cd "$(dirname "$MANIFEST")" && pwd)"
resolve_manifest_file() {
  local manifest_path="$1"
  if [[ "$manifest_path" == /* && -f "$manifest_path" ]]; then
    echo "$manifest_path"
    return
  fi
  if [[ -f "$manifest_path" ]]; then
    echo "$manifest_path"
    return
  fi
  if [[ -f "$manifest_dir/$manifest_path" ]]; then
    echo "$manifest_dir/$manifest_path"
    return
  fi
  if [[ -f "$manifest_dir/$(basename "$manifest_path")" ]]; then
    echo "$manifest_dir/$(basename "$manifest_path")"
    return
  fi
  return 1
}

slsa_spec_version="$(jq -r '.supply_chain.slsa_build.spec_version // empty' "$MANIFEST")"
slsa_level="$(jq -r '.supply_chain.slsa_build.level // empty' "$MANIFEST")"
slsa_predicate_type="$(jq -r '.supply_chain.slsa_build.predicate_type // empty' "$MANIFEST")"
slsa_repository="$(jq -r '.supply_chain.slsa_build.repository // empty' "$MANIFEST")"
slsa_signer_workflow="$(jq -r '.supply_chain.slsa_build.signer_workflow // empty' "$MANIFEST")"
slsa_attested="$(jq -r '.supply_chain.slsa_build.attested // false' "$MANIFEST")"
slsa_verified="$(jq -r '.supply_chain.slsa_build.verified // false' "$MANIFEST")"
slsa_verification_command="$(jq -r '.supply_chain.slsa_build.verification_command // empty' "$MANIFEST")"
sbom_format="$(jq -r '.supply_chain.sbom.format // empty' "$MANIFEST")"
sbom_spec_version="$(jq -r '.supply_chain.sbom.spec_version // empty' "$MANIFEST")"
sbom_predicate_type="$(jq -r '.supply_chain.sbom.predicate_type // empty' "$MANIFEST")"
sbom_path="$(jq -r '.supply_chain.sbom.path // empty' "$MANIFEST")"
sbom_url="$(jq -r '.supply_chain.sbom.url // empty' "$MANIFEST")"
sbom_expected_sha="$(jq -r '.supply_chain.sbom.sha256 // empty' "$MANIFEST")"
sbom_attested="$(jq -r '.supply_chain.sbom.attested // false' "$MANIFEST")"
sbom_verified="$(jq -r '.supply_chain.sbom.verified // false' "$MANIFEST")"
sbom_verification_command="$(jq -r '.supply_chain.sbom.verification_command // empty' "$MANIFEST")"

if [[ "$slsa_spec_version" != "1.2" ]]; then
  echo "Release manifest supply_chain.slsa_build.spec_version must be 1.2" >&2
  exit 1
fi
case "$slsa_level" in
  build_l1 | build_l2 | build_l3) ;;
  *)
    echo "Release manifest supply_chain.slsa_build.level is invalid: $slsa_level" >&2
    exit 1
    ;;
esac
if [[ "$slsa_predicate_type" != "https://slsa.dev/provenance/v1" ]]; then
  echo "Release manifest SLSA predicate type is invalid: $slsa_predicate_type" >&2
  exit 1
fi
if [[ -z "$slsa_repository" || -z "$slsa_signer_workflow" || -z "$slsa_verification_command" ]]; then
  echo "Release manifest SLSA verification metadata is incomplete" >&2
  exit 1
fi
if [[ "$sbom_format" != "cyclonedx-json" || "$sbom_spec_version" != "1.7" ]]; then
  echo "Release manifest SBOM metadata must be CycloneDX JSON 1.7" >&2
  exit 1
fi
if [[ "$sbom_predicate_type" != "https://cyclonedx.org/bom" ]]; then
  echo "Release manifest SBOM predicate type is invalid: $sbom_predicate_type" >&2
  exit 1
fi
if [[ -z "$sbom_path" || -z "$sbom_url" || -z "$sbom_expected_sha" || -z "$sbom_verification_command" ]]; then
  echo "Release manifest SBOM verification metadata is incomplete" >&2
  exit 1
fi
if ! valid_https_or_localhost_url "$sbom_url"; then
  echo "Release manifest SBOM URL must use HTTPS outside localhost: $sbom_url" >&2
  exit 1
fi
if [[ "$sbom_url" != "$rollback_immutable_prefix/"* ]]; then
  echo "Release manifest SBOM URL is outside rollback immutable_prefix: $sbom_url" >&2
  exit 1
fi
if [[ ! "$sbom_expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Release manifest SBOM SHA-256 is invalid: $sbom_expected_sha" >&2
  exit 1
fi
if ! sbom_resolved_path="$(resolve_manifest_file "$sbom_path")"; then
  echo "Release manifest SBOM file is missing: $sbom_path" >&2
  exit 1
fi
sbom_actual_sha="$(sha256_file "$sbom_resolved_path")"
if [[ "$sbom_actual_sha" != "$sbom_expected_sha" ]]; then
  echo "SBOM SHA mismatch: expected $sbom_expected_sha, got $sbom_actual_sha" >&2
  exit 1
fi
if ! jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.7"' "$sbom_resolved_path" >/dev/null; then
  echo "SBOM file is not CycloneDX JSON 1.7: $sbom_resolved_path" >&2
  exit 1
fi

launch_gate="$(jq -c '.quality_gates.packaged_app_launch // empty' "$MANIFEST")"
if [[ -z "$launch_gate" ]]; then
  echo "Missing packaged app launch quality gate" >&2
  exit 1
fi
launch_status="$(jq -r '.status // empty' <<<"$launch_gate")"
launch_wait_seconds="$(jq -r '.wait_seconds // empty' <<<"$launch_gate")"
launch_bundle_id="$(jq -r '.bundle_id // empty' <<<"$launch_gate")"
launch_bundle_version="$(jq -r '.bundle_version // empty' <<<"$launch_gate")"
launch_executable_name="$(jq -r '.executable_name // empty' <<<"$launch_gate")"
launch_process_survived="$(jq -r '.process_survived_wait // false' <<<"$launch_gate")"
launch_crash_count="$(jq '.crash_reports // [] | length' <<<"$launch_gate")"
launch_evidence_path="$(jq -r '.evidence_path // empty' <<<"$launch_gate")"

if [[ "$launch_status" != "passed" ]]; then
  echo "Packaged app launch quality gate did not pass" >&2
  exit 1
fi
if ! [[ "$launch_wait_seconds" =~ ^[0-9]+$ ]] || [[ "$launch_wait_seconds" -lt 1 ]]; then
  echo "Packaged app launch quality gate has invalid wait_seconds" >&2
  exit 1
fi
if [[ "$launch_process_survived" != "true" ]]; then
  echo "Packaged app launch quality gate did not survive the wait window" >&2
  exit 1
fi
if [[ "$launch_crash_count" != "0" ]]; then
  echo "Packaged app launch quality gate recorded crash reports" >&2
  exit 1
fi
if [[ -z "$launch_evidence_path" ]]; then
  echo "Packaged app launch quality gate is missing evidence_path" >&2
  exit 1
fi
if [[ ! -f "$launch_evidence_path" ]]; then
  launch_evidence_path="$manifest_dir/$(basename "$launch_evidence_path")"
fi
if [[ ! -f "$launch_evidence_path" ]]; then
  echo "Packaged app launch evidence file is missing: $launch_evidence_path" >&2
  exit 1
fi
if [[ "$(jq -r '.schema_version // empty' "$launch_evidence_path")" != "1" ]]; then
  echo "Packaged app launch evidence has unsupported schema_version" >&2
  exit 1
fi
if [[ "$(jq -r '.gate // empty' "$launch_evidence_path")" != "packaged_app_launch" ]]; then
  echo "Packaged app launch evidence has unexpected gate" >&2
  exit 1
fi
if [[ "$(jq -r '.status // empty' "$launch_evidence_path")" != "$launch_status" ]]; then
  echo "Packaged app launch evidence status does not match manifest gate" >&2
  exit 1
fi
if [[ "$(jq -r '.process_survived_wait // false' "$launch_evidence_path")" != "$launch_process_survived" ]]; then
  echo "Packaged app launch evidence process result does not match manifest gate" >&2
  exit 1
fi
if [[ "$(jq '.crash_reports // [] | length' "$launch_evidence_path")" != "$launch_crash_count" ]]; then
  echo "Packaged app launch evidence crash reports do not match manifest gate" >&2
  exit 1
fi

artifact_count="$(jq '.artifacts | length' "$MANIFEST")"
if [[ "$artifact_count" -lt 1 ]]; then
  echo "Release manifest has no artifacts" >&2
  exit 1
fi

required_subjects=()
while IFS= read -r subject; do
  required_subjects+=("$subject")
done < <(
  {
    jq -r '.artifacts[] | .path | split("/")[-1]' "$MANIFEST"
    printf '%s\n' "release-manifest.json" "$(basename "$sbom_path")"
  } | sort -u
)
for subject in "${required_subjects[@]}"; do
  if ! jq -e --arg subject "$subject" '.supply_chain.slsa_build.subjects | index($subject) != null' "$MANIFEST" >/dev/null; then
    echo "Release manifest SLSA subjects are missing: $subject" >&2
    exit 1
  fi
done
if [[ "$CHANNEL" == "stable" ]]; then
  if [[ "$slsa_level" == "build_l1" ]]; then
    echo "Stable releases require SLSA Build L2 or better provenance metadata" >&2
    exit 1
  fi
  if [[ "$slsa_attested" != "true" || "$slsa_verified" != "true" ]]; then
    echo "Stable releases require verified SLSA provenance attestations" >&2
    exit 1
  fi
  if [[ "$sbom_attested" != "true" || "$sbom_verified" != "true" ]]; then
    echo "Stable releases require verified SBOM attestations" >&2
    exit 1
  fi
fi

failures=0
while IFS= read -r artifact; do
  name="$(jq -r '.name' <<<"$artifact")"
  kind="$(jq -r '.kind' <<<"$artifact")"
  platform="$(jq -r '.platform' <<<"$artifact")"
  path="$(jq -r '.path' <<<"$artifact")"
  url="$(jq -r '.url // empty' <<<"$artifact")"
  verification_path="$(jq -r '.verification_path // empty' <<<"$artifact")"
  expected_sha="$(jq -r '.sha256' <<<"$artifact")"
  signed="$(jq -r '.signed' <<<"$artifact")"
  notarized="$(jq -r '.notarized' <<<"$artifact")"
  gatekeeper_assessed="$(jq -r '.gatekeeper_assessed' <<<"$artifact")"

  if [[ -z "$url" ]]; then
    echo "Missing artifact URL: $name" >&2
    failures=$((failures + 1))
  elif ! valid_https_or_localhost_url "$url"; then
    echo "Artifact URL must use HTTPS outside localhost: $name ($url)" >&2
    failures=$((failures + 1))
  elif [[ "$url" != "$rollback_immutable_prefix/"* ]]; then
    echo "Artifact URL is outside rollback immutable_prefix: $name ($url)" >&2
    failures=$((failures + 1))
  fi

  if [[ ! -f "$path" ]]; then
    echo "Missing artifact: $name ($path)" >&2
    failures=$((failures + 1))
    continue
  fi

  actual_sha="$(sha256_file "$path")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "SHA mismatch for $name: expected $expected_sha, got $actual_sha" >&2
    failures=$((failures + 1))
  fi

  if [[ "$kind" == "macos_app" && "$platform" == "macos" ]]; then
    if [[ -z "$verification_path" ]]; then
      echo "Missing macOS app verification path: $name" >&2
      failures=$((failures + 1))
    elif [[ ! -d "$verification_path" ]]; then
      echo "macOS app verification path is not a bundle directory: $name ($verification_path)" >&2
      failures=$((failures + 1))
    else
      info_plist="$verification_path/Contents/Info.plist"
      if [[ ! -f "$info_plist" ]]; then
        echo "macOS app bundle is missing Info.plist: $name" >&2
        failures=$((failures + 1))
      elif command -v plutil >/dev/null 2>&1 && ! plutil -lint "$info_plist" >/dev/null 2>&1; then
        echo "macOS app bundle has an invalid Info.plist: $name" >&2
        failures=$((failures + 1))
      fi
      if command -v plutil >/dev/null 2>&1; then
        bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$info_plist" 2>/dev/null || true)"
        bundle_version="$(plutil -extract CFBundleVersion raw -o - "$info_plist" 2>/dev/null || true)"
        executable_name="$(plutil -extract CFBundleExecutable raw -o - "$info_plist" 2>/dev/null || true)"
        if [[ -z "$launch_bundle_id" || "$bundle_id" != "$launch_bundle_id" ]]; then
          echo "Packaged app launch evidence bundle id does not match $name" >&2
          failures=$((failures + 1))
        fi
        if [[ -z "$launch_bundle_version" || "$bundle_version" != "$launch_bundle_version" ]]; then
          echo "Packaged app launch evidence bundle version does not match $name" >&2
          failures=$((failures + 1))
        fi
        if [[ -z "$launch_executable_name" || "$executable_name" != "$launch_executable_name" ]]; then
          echo "Packaged app launch evidence executable name does not match $name" >&2
          failures=$((failures + 1))
        fi
      fi
      if command -v codesign >/dev/null 2>&1; then
        if ! codesign --verify --deep --strict --verbose=2 "$verification_path" >/dev/null 2>&1; then
          echo "macOS app bundle signing/sealing verification failed for $name" >&2
          failures=$((failures + 1))
        fi
      elif [[ "$CHANNEL" == "stable" ]]; then
        echo "codesign is required to validate stable macOS app bundles: $name" >&2
        failures=$((failures + 1))
      fi
    fi
  fi

  if [[ "$CHANNEL" == "stable" ]]; then
    if [[ "$signed" != "true" ]]; then
      echo "Stable artifact is not signed: $name" >&2
      failures=$((failures + 1))
    fi
    if [[ "$notarized" != "true" ]]; then
      echo "Stable artifact is not notarized: $name" >&2
      failures=$((failures + 1))
    fi
    if [[ "$gatekeeper_assessed" != "true" ]]; then
      echo "Stable artifact has not passed Gatekeeper assessment: $name" >&2
      failures=$((failures + 1))
    fi
  fi

  if [[ "$signed" == "true" && -n "$verification_path" ]]; then
    if [[ ! -e "$verification_path" ]]; then
      echo "Verification path does not exist for $name: $verification_path" >&2
      failures=$((failures + 1))
      continue
    fi
    if command -v codesign >/dev/null 2>&1; then
      if ! codesign --verify --strict --verbose=2 "$verification_path" >/dev/null 2>&1; then
        echo "codesign verification failed for $name" >&2
        failures=$((failures + 1))
      fi
    fi
    if [[ "$CHANNEL" == "stable" ]] && command -v spctl >/dev/null 2>&1; then
      if ! spctl --assess --type execute --verbose "$verification_path" >/dev/null 2>&1; then
        echo "Gatekeeper assessment failed for $name" >&2
        failures=$((failures + 1))
      fi
    fi
  fi
done < <(jq -c '.artifacts[]' "$MANIFEST")

if [[ "$failures" -gt 0 ]]; then
  echo "Release gate failed with $failures issue(s)." >&2
  exit 1
fi

echo "Release gate passed for $CHANNEL manifest: $MANIFEST"
