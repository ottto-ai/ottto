#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/macos_release_gate.sh"

MANIFEST=""
SIGN_IDENTITY="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"
KEYCHAIN_PROFILE="${OTTTO_NOTARY_PROFILE:-}"
DRY_RUN="false"

usage() {
  cat <<'USAGE'
Usage: macos_stable_preflight.sh --manifest <release-manifest.json> [options]

Runs the stable macOS release preflight before any publish step. Dry-run mode
validates stable-channel metadata, artifact presence, and SHA-256 hashes without
requiring local Apple credentials. Non-dry-run mode also verifies Developer ID
identity, hardened runtime signatures, notarization profile access, stapling,
Gatekeeper assessment, and the stable release gate.

Options:
  --manifest <path>             Stable release manifest to validate.
  --sign-identity <identity>    Developer ID Application signing identity.
  --keychain-profile <profile>  notarytool keychain profile.
  --dry-run                     Skip credential-dependent Apple checks.
  -h, --help                    Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --sign-identity)
      SIGN_IDENTITY="${2:?--sign-identity requires a value}"
      shift 2
      ;;
    --keychain-profile)
      KEYCHAIN_PROFILE="${2:?--keychain-profile requires a value}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
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
require_command python3

if [[ "$DRY_RUN" != "true" ]]; then
  require_command codesign
  require_command security
  require_command spctl
  require_command xcrun
fi

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

gatekeeper_assessment_type() {
  local kind="$1"
  if [[ "$kind" == "macos_app" ]]; then
    printf 'execute'
  else
    printf 'install'
  fi
}

failures=0
fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

schema_version="$(jq -r '.schema_version' "$MANIFEST")"
product="$(jq -r '.product' "$MANIFEST")"
version="$(jq -r '.version // empty' "$MANIFEST")"
channel="$(jq -r '.channel // empty' "$MANIFEST")"
commit="$(jq -r '.commit // empty' "$MANIFEST")"
artifact_count="$(jq '.artifacts | length' "$MANIFEST")"
min_supported_version="$(jq -r '.min_supported_version // empty' "$MANIFEST")"
min_protocol_version="$(jq -r '.min_protocol_version // empty' "$MANIFEST")"
supported_owner_count="$(jq '.supported_install_owners // [] | length' "$MANIFEST")"
rollback_strategy="$(jq -r '.rollback.strategy // empty' "$MANIFEST")"
rollback_immutable_prefix="$(jq -r '.rollback.immutable_prefix // empty' "$MANIFEST")"
rollback_latest_manifest_url="$(jq -r '.rollback.latest_manifest_url // empty' "$MANIFEST")"
rollback_preserve_failed_version="$(jq -r '.rollback.preserve_failed_version // false' "$MANIFEST")"
rollback_operator_step_count="$(jq '.rollback.operator_steps // [] | length' "$MANIFEST")"
rollback_release_gate="$(jq -r '.rollback.verification.release_gate // empty' "$MANIFEST")"
rollback_stable_preflight="$(jq -r '.rollback.verification.stable_preflight // empty' "$MANIFEST")"
rollback_installed_smoke="$(jq -r '.rollback.verification.installed_smoke // empty' "$MANIFEST")"

if [[ "$schema_version" != "1" ]]; then
  fail "Unsupported release manifest schema_version: $schema_version"
fi
if [[ "$product" != "ottto-local-platform" ]]; then
  fail "Unexpected release manifest product: $product"
fi
if [[ "$channel" != "stable" ]]; then
  fail "Stable preflight requires channel=stable, got: $channel"
fi
if [[ -z "$version" || "$version" =~ (dev|preview|test) ]]; then
  fail "Stable release version must be a concrete customer version: $version"
fi
if ! [[ "$commit" =~ ^[0-9a-f]{7,40}$ ]]; then
  fail "Stable release commit must be a git SHA prefix: $commit"
fi
if [[ "$artifact_count" -lt 1 ]]; then
  fail "Release manifest has no artifacts"
fi
if [[ -z "$min_supported_version" ]]; then
  fail "Stable manifest is missing min_supported_version"
fi
if [[ "$min_protocol_version" != "11" ]]; then
  fail "Stable manifest min_protocol_version must be 11"
fi
if [[ "$supported_owner_count" -lt 1 ]]; then
  fail "Stable manifest must list supported install owners"
fi
if [[ "$rollback_strategy" != "channel_latest_pointer" ]]; then
  fail "Stable manifest must include channel_latest_pointer rollback metadata"
fi
if [[ "$rollback_immutable_prefix" != https://* || "$rollback_immutable_prefix" != *"/stable/$version" ]]; then
  fail "Stable rollback immutable_prefix must be the HTTPS stable versioned prefix: $rollback_immutable_prefix"
fi
if [[ "$rollback_latest_manifest_url" != https://* || "$rollback_latest_manifest_url" != *"/stable/latest/release-manifest.json" ]]; then
  fail "Stable rollback latest_manifest_url must be the HTTPS stable latest manifest: $rollback_latest_manifest_url"
fi
if [[ "$rollback_preserve_failed_version" != "true" ]]; then
  fail "Stable rollback metadata must preserve failed versioned artifacts"
fi
if [[ "$rollback_operator_step_count" -lt 3 ]]; then
  fail "Stable rollback metadata must include at least three operator steps"
fi
if [[ -z "$rollback_release_gate" || -z "$rollback_stable_preflight" || -z "$rollback_installed_smoke" ]]; then
  fail "Stable rollback verification metadata is incomplete"
fi

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

if ! python3 - "$MANIFEST" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

manifest_path = Path(sys.argv[1]).resolve()
manifest_dir = manifest_path.parent

REQUIRED_CHECKS = [
    "release_gate",
    "public_surface_ci",
    "candidate_manifest_download",
    "artifact_checksums",
    "artifact_signatures",
    "notarization",
    "gatekeeper_assessment",
    "hosted_candidate_installer",
    "app_launch",
    "service_ready",
    "status_json",
    "setup_browser_claim",
    "verify_codex",
    "diagnostics_redaction",
    "update_check",
    "rollback_notes",
    "stable_formula_static",
    "stable_hosted_installer_static",
]

PRIVATE_REPO_NAME = "coding-agents-" "observability"
SECRET_PATTERN = re.compile(
    r"/Users/|" + re.escape(PRIVATE_REPO_NAME) + r"|docs/dev|\.agents|\.claude|"
    r"Bearer\s+|claim_code|setup_run_token|account_id|machine_id|"
    r"api[_-]?key|password",
    re.IGNORECASE,
)


def die(message: str) -> None:
    print(f"stable-preflight: {message}", file=sys.stderr)
    sys.exit(1)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        die(f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        die(f"{label} must be a non-empty string")
    return value


def contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value == "not_run" or value.startswith("TODO")
    if isinstance(value, list):
        return any(contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(contains_placeholder(item) for item in value.values())
    return False


def resolve_reference(reference: str) -> Path:
    path = Path(reference)
    if path.is_absolute():
        return path.resolve()
    return (manifest_dir / path).resolve()


try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as error:
    die(f"stable manifest has invalid JSON: {error}")

manifest = require_object(manifest, "stable manifest")
if manifest.get("product") != "ottto-local-platform":
    die("stable manifest product must be ottto-local-platform")
if manifest.get("channel") != "stable":
    die("stable manifest channel must be stable")
stable_commit = require_string(manifest.get("commit"), "stable manifest commit")
if not re.fullmatch(r"[0-9a-f]{7,40}", stable_commit):
    die("stable manifest commit is not a git SHA prefix")

quality_gates = require_object(manifest.get("quality_gates"), "quality_gates")
gate = require_object(
    quality_gates.get("stable_candidate_rc"),
    "quality_gates.stable_candidate_rc",
)
if gate.get("status") != "passed":
    die("quality_gates.stable_candidate_rc.status must be passed")
evidence_reference = require_string(
    gate.get("evidence_path"),
    "quality_gates.stable_candidate_rc.evidence_path",
)
candidate_manifest_sha = require_string(
    gate.get("candidate_manifest_sha256"),
    "quality_gates.stable_candidate_rc.candidate_manifest_sha256",
)
if not re.fullmatch(r"[0-9a-f]{64}", candidate_manifest_sha):
    die("quality_gates.stable_candidate_rc.candidate_manifest_sha256 is invalid")

evidence_path = resolve_reference(evidence_reference)
if not evidence_path.is_file():
    die(f"stable-candidate RC evidence is missing: {evidence_reference}")

evidence_text = evidence_path.read_text(encoding="utf-8")
if SECRET_PATTERN.search(evidence_text):
    die("stable-candidate RC evidence contains private path or secret-like material")
try:
    evidence = json.loads(evidence_text)
except json.JSONDecodeError as error:
    die(f"stable-candidate RC evidence has invalid JSON: {error}")

evidence = require_object(evidence, "stable-candidate RC evidence")
if contains_placeholder(evidence):
    die("stable-candidate RC evidence still contains template placeholders")
if evidence.get("schema_version") != 1:
    die("stable-candidate RC evidence schema_version must be 1")
if evidence.get("gate") != "stable_candidate_rc":
    die("stable-candidate RC evidence gate must be stable_candidate_rc")
if evidence.get("status") != "passed":
    die("stable-candidate RC evidence status must be passed")

candidate = require_object(
    evidence.get("candidate_manifest"),
    "stable-candidate RC evidence candidate_manifest",
)
if candidate.get("product") != "ottto-local-platform":
    die("stable-candidate RC evidence product must be ottto-local-platform")
if candidate.get("channel") != "stable-candidate":
    die("stable-candidate RC evidence candidate channel must be stable-candidate")
if candidate.get("commit") != stable_commit:
    die("stable-candidate RC evidence commit must match stable manifest commit")
if candidate.get("sha256") != candidate_manifest_sha:
    die("stable-candidate RC evidence candidate SHA must match stable manifest gate")

environment = require_object(
    evidence.get("environment"),
    "stable-candidate RC evidence environment",
)
local_platform = require_object(
    evidence.get("local_platform"),
    "stable-candidate RC evidence local_platform",
)
if environment.get("host_kind") not in {"trusted_internal_macos", "clean_macos"}:
    die("stable-candidate RC evidence host_kind is invalid")
if environment.get("arch") not in {"arm64", "x86_64", "universal"}:
    die("stable-candidate RC evidence arch is invalid")
require_string(environment.get("macos_version"), "stable-candidate RC evidence macos_version")
if local_platform.get("runtime") != "ottto-service":
    die("stable-candidate RC evidence local_platform.runtime must be ottto-service")
if local_platform.get("service_label") != "net.ottto.service":
    die("stable-candidate RC evidence local_platform.service_label must be net.ottto.service")
if local_platform.get("version") != candidate.get("version"):
    die("stable-candidate RC evidence local_platform.version must match candidate version")
if local_platform.get("release_channel") != "stable-candidate":
    die("stable-candidate RC evidence local_platform.release_channel must be stable-candidate")
if local_platform.get("protocol_version") != 11:
    die("stable-candidate RC evidence local_platform.protocol_version must be 11")
if local_platform.get("release_manifest_sha256") != candidate_manifest_sha:
    die("stable-candidate RC evidence local_platform.release_manifest_sha256 must match candidate manifest")

checks = require_object(evidence.get("checks"), "stable-candidate RC evidence checks")
for check in REQUIRED_CHECKS:
    if checks.get(check) != "passed":
        die(f"stable-candidate RC evidence is missing passed check: {check}")
PY
then
  fail "Stable manifest stable-candidate RC quality gate is not satisfied"
fi

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
  fail "Stable manifest supply_chain.slsa_build.spec_version must be 1.2"
fi
if [[ "$slsa_level" != "build_l2" && "$slsa_level" != "build_l3" ]]; then
  fail "Stable manifest requires SLSA Build L2 or better provenance metadata"
fi
if [[ "$slsa_predicate_type" != "https://slsa.dev/provenance/v1" ]]; then
  fail "Stable manifest SLSA predicate type is invalid: $slsa_predicate_type"
fi
if [[ -z "$slsa_repository" || -z "$slsa_signer_workflow" || -z "$slsa_verification_command" ]]; then
  fail "Stable manifest SLSA verification metadata is incomplete"
fi
if [[ "$slsa_attested" != "true" || "$slsa_verified" != "true" ]]; then
  fail "Stable manifest requires verified SLSA provenance attestations"
fi
if [[ "$sbom_format" != "cyclonedx-json" || "$sbom_spec_version" != "1.7" ]]; then
  fail "Stable manifest SBOM metadata must be CycloneDX JSON 1.7"
fi
if [[ "$sbom_predicate_type" != "https://cyclonedx.org/bom" ]]; then
  fail "Stable manifest SBOM predicate type is invalid: $sbom_predicate_type"
fi
if [[ -z "$sbom_path" || -z "$sbom_url" || -z "$sbom_expected_sha" || -z "$sbom_verification_command" ]]; then
  fail "Stable manifest SBOM verification metadata is incomplete"
fi
if [[ "$sbom_url" != https://* || "$sbom_url" != "$rollback_immutable_prefix/"* ]]; then
  fail "Stable manifest SBOM URL must use the rollback immutable prefix: $sbom_url"
fi
if [[ ! "$sbom_expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
  fail "Stable manifest SBOM SHA-256 is invalid: $sbom_expected_sha"
fi
if ! sbom_resolved_path="$(resolve_manifest_file "$sbom_path")"; then
  fail "Stable manifest SBOM file is missing: $sbom_path"
else
  sbom_actual_sha="$(sha256_file "$sbom_resolved_path")"
  if [[ "$sbom_actual_sha" != "$sbom_expected_sha" ]]; then
    fail "Stable manifest SBOM SHA mismatch: expected $sbom_expected_sha, got $sbom_actual_sha"
  fi
  if ! jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.7"' "$sbom_resolved_path" >/dev/null; then
    fail "Stable manifest SBOM file is not CycloneDX JSON 1.7: $sbom_resolved_path"
  fi
fi
if [[ "$sbom_attested" != "true" || "$sbom_verified" != "true" ]]; then
  fail "Stable manifest requires verified SBOM attestations"
fi

for required_kind in macos_app cli daemon; do
  matches="$(jq --arg kind "$required_kind" '[.artifacts[] | select(.kind == $kind and .platform == "macos")] | length' "$MANIFEST")"
  if [[ "$matches" != "1" ]]; then
    fail "Stable manifest must include exactly one macOS $required_kind artifact, found $matches"
  fi
done

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
    fail "Stable manifest SLSA subjects are missing: $subject"
  fi
done

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

  if [[ "$platform" != "macos" ]]; then
    fail "Stable macOS release manifest cannot include non-macOS artifact: $name ($platform)"
  fi
  if [[ "$url" != https://* ]]; then
    fail "Stable artifact URL must use HTTPS: $name ($url)"
  fi
  if [[ "$url" != *"/stable/"* ]]; then
    fail "Stable artifact URL must include the stable channel path: $name ($url)"
  fi
  if [[ -n "$rollback_immutable_prefix" && "$url" != "$rollback_immutable_prefix/"* ]]; then
    fail "Stable artifact URL is outside rollback immutable_prefix: $name ($url)"
  fi
  if [[ "$kind" == "macos_app" && "$url" != *.dmg ]]; then
    fail "Stable macOS app artifact must be published as a DMG: $name ($url)"
  fi
  if [[ ! -f "$path" ]]; then
    fail "Missing artifact: $name ($path)"
    continue
  fi
  actual_sha="$(sha256_file "$path")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    fail "SHA mismatch for $name: expected $expected_sha, got $actual_sha"
  fi

  if [[ -z "$verification_path" || ! -e "$verification_path" ]]; then
    fail "Verification path does not exist for $name: $verification_path"
    continue
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    continue
  fi

  if [[ "$signed" != "true" ]]; then
    fail "Stable artifact is not marked signed: $name"
  fi
  if [[ "$notarized" != "true" ]]; then
    fail "Stable artifact is not marked notarized: $name"
  fi
  if [[ "$gatekeeper_assessed" != "true" ]]; then
    fail "Stable artifact is not marked Gatekeeper-assessed: $name"
  fi

  signature_details="$(codesign -dv --verbose=4 "$verification_path" 2>&1 || true)"
  if ! grep -q "Authority=Developer ID Application" <<<"$signature_details"; then
    fail "Artifact is not signed by a Developer ID Application authority: $name"
  fi
  if ! grep -q "Runtime Version" <<<"$signature_details"; then
    fail "Artifact is not signed with hardened runtime: $name"
  fi
  if ! grep -q "Timestamp=" <<<"$signature_details"; then
    fail "Artifact signature is missing a secure timestamp: $name"
  fi

  if [[ "$kind" == "macos_app" ]]; then
    if ! xcrun stapler validate "$path" >/dev/null 2>&1; then
      fail "Stapler validation failed for macOS app DMG: $name"
    fi
    if ! xcrun stapler validate "$verification_path" >/dev/null 2>&1; then
      fail "Stapler validation failed for macOS app bundle: $name"
    fi
  fi

  if ! spctl --assess --type "$(gatekeeper_assessment_type "$kind")" --verbose "$verification_path" >/dev/null 2>&1; then
    fail "Gatekeeper assessment failed for $name"
  fi
done < <(jq -c '.artifacts[]' "$MANIFEST")

if [[ "$DRY_RUN" == "true" ]]; then
  if [[ "$failures" -gt 0 ]]; then
    echo "Stable preflight dry-run failed with $failures issue(s)." >&2
    exit 1
  fi
  echo "Stable preflight dry-run passed for manifest: $MANIFEST"
  exit 0
fi

if [[ -z "$SIGN_IDENTITY" ]]; then
  fail "Developer ID signing identity is required; set OTTTO_MACOS_CODESIGN_IDENTITY or pass --sign-identity"
else
  identity_line="$(security find-identity -v -p codesigning | grep -F "$SIGN_IDENTITY" || true)"
  if [[ -z "$identity_line" ]]; then
    fail "Developer ID signing identity was not found in the local keychain: $SIGN_IDENTITY"
  elif ! grep -q "Developer ID Application" <<<"$identity_line"; then
    fail "Signing identity is not a Developer ID Application identity: $SIGN_IDENTITY"
  fi
fi

if [[ -z "$KEYCHAIN_PROFILE" ]]; then
  fail "notarytool keychain profile is required; set OTTTO_NOTARY_PROFILE or pass --keychain-profile"
else
  if ! xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" >/dev/null 2>&1; then
    fail "notarytool keychain profile could not be used: $KEYCHAIN_PROFILE"
  fi
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Stable preflight failed with $failures issue(s)." >&2
  exit 1
fi

"$GATE" --manifest "$MANIFEST"
echo "Stable preflight passed for manifest: $MANIFEST"
