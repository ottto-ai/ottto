#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""

usage() {
  cat <<'USAGE'
Usage: macos_stable_closeout_gate.sh --manifest <release-manifest.json>

Validates the stable release closeout evidence before a stable local-platform
release is promoted as externally ready. This gate is intentionally separate
from packaging preflight: it runs after the immutable stable artifact prefix is
published and clean-machine install QA has produced its evidence file.
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

failures=0

fail() {
  echo "$*" >&2
  failures=$((failures + 1))
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

required_checks_for_owner() {
  case "$1" in
    homebrew)
      printf '%s\n' \
        formula_syntax \
        install \
        service_start \
        app_launch_preserves_owner \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        doctor_owner_drift_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        update_check_owner_json \
        upgrade \
        post_upgrade_app_relaunch_preserves_owner \
        uninstall \
        reinstall \
        post_reinstall_status_json
      ;;
    hosted_installer)
      printf '%s\n' \
        wrapper_download \
        wrapper_checksum \
        native_gatekeeper \
        install \
        app_launch \
        service_ready \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        upgrade \
        uninstall \
        reinstall \
        post_reinstall_status_json
      ;;
    app_bundle)
      printf '%s\n' \
        artifact_checksum \
        gatekeeper \
        install \
        app_launch \
        service_ready \
        homebrew_second_install_safe_refusal \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        doctor_owner_drift_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        update_check_owner_json \
        upgrade \
        uninstall \
        reinstall \
        post_reinstall_status_json
      ;;
    *)
      return 1
      ;;
  esac
}

contains_value() {
  local needle="$1"
  shift
  local value
  for value in "$@"; do
    [[ "$value" == "$needle" ]] && return 0
  done
  return 1
}

require_command jq
require_command shasum
require_command grep

if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing: $MANIFEST" >&2
  exit 1
fi

manifest_dir="$(cd "$(dirname "$MANIFEST")" && pwd)"
manifest_path="$(cd "$manifest_dir" && pwd)/$(basename "$MANIFEST")"

product="$(jq -r '.product // empty' "$MANIFEST")"
channel="$(jq -r '.channel // empty' "$MANIFEST")"
version="$(jq -r '.version // empty' "$MANIFEST")"
commit="$(jq -r '.commit // empty' "$MANIFEST")"
manifest_sha="$(shasum -a 256 "$MANIFEST" | awk '{print $1}')"

if [[ "$product" != "ottto-local-platform" ]]; then
  fail "Stable closeout requires product=ottto-local-platform, got: $product"
fi
if [[ "$channel" != "stable" ]]; then
  fail "Stable closeout requires channel=stable, got: $channel"
fi
if [[ -z "$version" ]]; then
  fail "Stable closeout manifest is missing version"
fi
if [[ ! "$commit" =~ ^[0-9a-f]{7,40}$ ]]; then
  fail "Stable closeout manifest commit is not a git SHA prefix: $commit"
fi
if ! jq -e '.min_protocol_version == 11' "$MANIFEST" >/dev/null; then
  fail "Stable closeout manifest min_protocol_version must be 11"
fi

gate="$(jq -c '.quality_gates.stable_clean_machine_qa // empty' "$MANIFEST")"
if [[ -z "$gate" ]]; then
  fail "Stable manifest is missing quality_gates.stable_clean_machine_qa"
fi

gate_status="$(jq -r '.quality_gates.stable_clean_machine_qa.status // empty' "$MANIFEST")"
gate_evidence_path="$(jq -r '.quality_gates.stable_clean_machine_qa.evidence_path // empty' "$MANIFEST")"
if [[ "$gate_status" != "passed" && "$gate_status" != "not_run" ]]; then
  fail "Stable clean-machine QA manifest gate status must be passed or not_run"
fi
if [[ -z "$gate_evidence_path" ]]; then
  fail "Stable clean-machine QA gate is missing evidence_path"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Stable closeout gate failed with $failures issue(s)." >&2
  exit 1
fi

if [[ "$gate_evidence_path" == /* ]]; then
  evidence_path="$gate_evidence_path"
elif [[ -f "$gate_evidence_path" ]]; then
  evidence_path="$(cd "$(dirname "$gate_evidence_path")" && pwd)/$(basename "$gate_evidence_path")"
elif [[ -f "$manifest_dir/$gate_evidence_path" ]]; then
  evidence_path="$manifest_dir/$gate_evidence_path"
elif [[ -f "$manifest_dir/$(basename "$gate_evidence_path")" ]]; then
  evidence_path="$manifest_dir/$(basename "$gate_evidence_path")"
else
  echo "Stable clean-machine QA evidence file is missing: $gate_evidence_path" >&2
  exit 1
fi

private_repo_pattern="coding-agents-""observability"
if grep -Eiq "/Users/|${private_repo_pattern}|docs/dev|\\.agents|\\.claude|Bearer[[:space:]]+|claim_code|setup_run_token|account_id|machine_id|api[_-]?key|password" "$evidence_path"; then
  echo "Stable clean-machine QA evidence contains private path or secret-like material: $evidence_path" >&2
  exit 1
fi
if jq -e '.. | strings | select(. == "not_run" or test("^TODO"))' "$evidence_path" >/dev/null; then
  echo "Stable clean-machine QA evidence still contains template placeholders: $evidence_path" >&2
  exit 1
fi

if ! jq -e \
  --arg product "$product" \
  --arg channel "$channel" \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg manifest_sha "$manifest_sha" \
  '
    .schema_version == 1
    and .gate == "stable_clean_machine_qa"
    and .status == "passed"
    and (.checked_at | type == "string" and length > 0)
    and .manifest.product == $product
    and .manifest.channel == $channel
    and .manifest.version == $version
    and .manifest.commit == $commit
    and .manifest.sha256 == $manifest_sha
    and .environment.host_kind == "clean_macos"
    and (.environment.macos_version | type == "string" and length > 0)
    and (.environment.arch == "arm64" or .environment.arch == "x86_64" or .environment.arch == "universal")
    and (.install_owners | type == "array" and length > 0)
  ' "$evidence_path" >/dev/null; then
  fail "Stable clean-machine QA evidence has an invalid envelope or does not match $manifest_path"
fi

supported_owners=()
while IFS= read -r owner; do
  supported_owners+=("$owner")
done < <(jq -r '.supported_install_owners[]?' "$MANIFEST" | sort -u)

if [[ "${#supported_owners[@]}" -eq 0 ]]; then
  fail "Stable manifest has no supported_install_owners"
fi

required_gate_owners=()
while IFS= read -r owner; do
  required_gate_owners+=("$owner")
done < <(jq -r '.quality_gates.stable_clean_machine_qa.required_install_owners[]? // empty' "$MANIFEST" | sort -u)

for owner in "${required_gate_owners[@]}"; do
  if ! contains_value "$owner" "${supported_owners[@]}"; then
    fail "Stable clean-machine QA manifest gate includes unsupported required install owner: $owner"
  fi
done

for owner in "${supported_owners[@]}"; do
  if ! required_checks_for_owner "$owner" >/dev/null; then
    fail "Stable closeout does not know how to validate install owner: $owner"
    continue
  fi
  if ! contains_value "$owner" "${required_gate_owners[@]}"; then
    fail "Stable clean-machine QA manifest gate does not require supported install owner: $owner"
  fi
  if ! jq -e --arg owner "$owner" '[.install_owners[]? | select(.owner == $owner)] | length == 1' "$evidence_path" >/dev/null; then
    fail "Stable clean-machine QA evidence must include exactly one entry for install owner: $owner"
    continue
  fi
  if ! jq -e --arg owner "$owner" '.install_owners[] | select(.owner == $owner) | .status == "passed"' "$evidence_path" >/dev/null; then
    fail "Stable clean-machine QA evidence did not pass for install owner: $owner"
  fi
  if ! jq -e \
    --arg owner "$owner" \
    --arg version "$version" \
    --arg channel "$channel" \
    --arg manifest_sha "$manifest_sha" \
    '
      .install_owners[]
      | select(.owner == $owner)
      | .local_platform.runtime == "ottto-service"
        and .local_platform.service_label == "net.ottto.service"
        and .local_platform.version == $version
        and .local_platform.release_channel == $channel
        and .local_platform.install_owner == $owner
        and .local_platform.protocol_version == 11
        and .local_platform.release_manifest_sha256 == $manifest_sha
    ' "$evidence_path" >/dev/null; then
    fail "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: $owner"
  fi
  required_owner_checks=()
  while IFS= read -r check_name; do
    required_owner_checks+=("$check_name")
    if ! jq -e --arg owner "$owner" --arg check_name "$check_name" \
      '.install_owners[] | select(.owner == $owner) | .checks[$check_name] == "passed"' \
      "$evidence_path" >/dev/null; then
      fail "Stable clean-machine QA evidence is missing passed check $owner.$check_name"
    fi
  done < <(required_checks_for_owner "$owner")
  while IFS= read -r check_name; do
    if ! contains_value "$check_name" "${required_owner_checks[@]}"; then
      fail "Stable clean-machine QA evidence includes unknown check $owner.$check_name"
    fi
  done < <(jq -r --arg owner "$owner" '.install_owners[] | select(.owner == $owner) | (.checks // {}) | keys[]?' "$evidence_path" | sort -u)
done

while IFS= read -r owner; do
  if ! contains_value "$owner" "${supported_owners[@]}"; then
    fail "Stable clean-machine QA evidence includes unsupported install owner: $owner"
  fi
done < <(jq -r '.install_owners[]?.owner // empty' "$evidence_path" | sort -u)

if [[ "$failures" -gt 0 ]]; then
  echo "Stable closeout gate failed with $failures issue(s)." >&2
  exit 1
fi

echo "Stable closeout gate passed for $version ($commit): $evidence_path"
