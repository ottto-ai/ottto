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
      version: "0.1.7",
      channel: "stable",
      commit: "244f7ea90a7a",
      generated_at: "2026-05-21T18:00:00Z",
      min_supported_version: "0.1.7",
      min_protocol_version: 15,
      supported_install_owners: ["homebrew", "hosted_installer", "app_bundle"],
      rollback: {
        strategy: "channel_latest_pointer",
        immutable_prefix: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.7",
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
          verification_command: "gh attestation verify ./Ottto-macos-arm64.dmg -R ottto-ai/ottto"
        },
        sbom: {
          format: "cyclonedx-json",
          spec_version: "1.7",
          predicate_type: "https://cyclonedx.org/bom",
          path: "ottto-local-platform-sbom.cdx.json",
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.7/ottto-local-platform-sbom.cdx.json",
          sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          attested: true,
          verified: true,
          verification_command: "gh attestation verify ./Ottto-macos-arm64.dmg -R ottto-ai/ottto --predicate-type https://cyclonedx.org/bom"
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
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.7/Ottto-macos-arm64.dmg",
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
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.7/ottto-macos-arm64.zip",
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
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.7/ottto-service-macos-arm64.zip",
          sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          signed: true,
          notarized: true,
          gatekeeper_assessed: true
        }
      ]
    }' > "$output"
}


HOMEBREW_CHECKS='["formula_syntax","install","service_start","headless_no_app_process","status_json","setup_browser_claim","apps_detect_json","verify_codex_json","doctor_json","doctor_owner_drift_json","fix_codex_json","diagnostics_collect_json","logout_json","update_check","update_check_owner_json","upgrade","post_upgrade_service_restarts_owned","uninstall","reinstall","post_reinstall_status_json","reonboard_after_keychain_wipe"]'
HOSTED_CHECKS='["wrapper_download","wrapper_checksum","native_gatekeeper","install","app_launch","service_ready","status_json","setup_browser_claim","apps_detect_json","verify_codex_json","doctor_json","fix_codex_json","diagnostics_collect_json","logout_json","update_check","upgrade","uninstall","reinstall","post_reinstall_status_json","reonboard_after_keychain_wipe"]'
APP_CHECKS='["artifact_checksum","gatekeeper","install","app_launch","service_ready","homebrew_second_install_safe_refusal","status_json","setup_browser_claim","apps_detect_json","verify_codex_json","doctor_json","doctor_owner_drift_json","fix_codex_json","diagnostics_collect_json","logout_json","update_check","update_check_owner_json","upgrade","move_service_to_app","uninstall","reinstall","post_reinstall_status_json","reonboard_after_keychain_wipe"]'

# A schema 2 public summary with every check passed live in this release.
write_evidence() {
  local manifest="$1"
  local output="$2"
  local manifest_sha
  manifest_sha="$(shasum -a 256 "$manifest" | awk '{print $1}')"
  jq -n \
    --arg manifest_sha "$manifest_sha" \
    --argjson homebrew "$HOMEBREW_CHECKS" \
    --argjson hosted "$HOSTED_CHECKS" \
    --argjson app "$APP_CHECKS" \
    '
      def checks($names): $names | map({key: ., value: {result: "passed", method: "live"}}) | from_entries;
      def owner($name; $names): {
        owner: $name,
        status: "passed",
        local_platform: {
          runtime: "ottto-service",
          service_label: "net.ottto.service",
          version: "0.1.7",
          release_channel: "stable",
          install_owner: $name,
          protocol_version: 15,
          release_manifest_sha256: $manifest_sha
        },
        checks: checks($names)
      };
      {
        schema_version: 2,
        gate: "stable_clean_machine_qa",
        status: "passed",
        checked_at: "2026-05-21T19:00:00Z",
        manifest: {
          product: "ottto-local-platform",
          channel: "stable",
          version: "0.1.7",
          commit: "244f7ea90a7a",
          sha256: $manifest_sha
        },
        environment: {
          host_class: "signing_mac",
          macos_version: "15.5",
          arch: "arm64"
        },
        install_owners: [
          owner("homebrew"; $homebrew),
          owner("hosted_installer"; $hosted),
          owner("app_bundle"; $app)
        ]
      }
    ' > "$output"
}

base_dir="$tmp_dir/base"
mkdir -p "$base_dir" "$tmp_dir/cases"
write_manifest "$base_dir/release-manifest.json"
write_evidence "$base_dir/release-manifest.json" "$base_dir/stable-clean-machine-qa.json"

# Each case gets its own release folder (a sibling, never nested in another).
new_case() {
  local dir="$tmp_dir/cases/$1"
  mkdir -p "$dir"
  cp "$base_dir/release-manifest.json" "$base_dir/stable-clean-machine-qa.json" "$dir/"
  printf '%s' "$dir"
}

# Rewrite a case's summary with a jq filter.
mutate() {
  local dir="$1"
  local filter="$2"
  jq "$filter" "$dir/stable-clean-machine-qa.json" > "$tmp_dir/mutated.json"
  mv "$tmp_dir/mutated.json" "$dir/stable-clean-machine-qa.json"
}

expect_pass() {
  local dir="$1"
  local output="$tmp_dir/pass.out"
  shift
  if ! "$GATE" --manifest "$dir/release-manifest.json" >"$output" 2>&1; then
    echo "Expected closeout gate to pass: $dir" >&2
    cat "$output" >&2
    exit 1
  fi
  local needle
  for needle in "$@"; do
    if ! grep -qF -- "$needle" "$output"; then
      echo "Closeout gate output is missing: $needle" >&2
      cat "$output" >&2
      exit 1
    fi
  done
  if grep -qF -- "$tmp_dir" "$output"; then
    echo "Closeout gate output names the release folder path" >&2
    exit 1
  fi
}

expect_failure() {
  local dir="$1"
  local message="$2"
  local output="$tmp_dir/failure.out"
  if "$GATE" --manifest "$dir/release-manifest.json" >"$output" 2>&1; then
    echo "Expected closeout gate to fail: $message" >&2
    exit 1
  fi
  if ! grep -qF -- "$message" "$output"; then
    echo "Closeout gate failure is missing: $message" >&2
    cat "$output" >&2
    exit 1
  fi
  # Diagnostics never echo free text or paths from the release folder.
  if grep -qF -- "SYNTHETIC-PRIVATE-MARKER" "$output" || grep -qF -- "$tmp_dir" "$output"; then
    echo "Closeout gate diagnostics repeat a private marker or the folder path" >&2
    cat "$output" >&2
    exit 1
  fi
}

# carry <owner> <check> <from> [method]
carry() {
  printf '(.install_owners[] | select(.owner == "%s") | .checks.%s) = {result: "carried", method: "%s", from: "%s"}' \
    "$1" "$2" "${4:-live}" "$3"
}

# [contract] The never-carry list is one list, printed by the gate itself.
never_carry="$("$GATE" --list-never-carry-checks | sort | tr '\n' ' ')"
expected_never_carry="$(printf '%s\n' app_launch apps_detect_json artifact_checksum formula_syntax gatekeeper headless_no_app_process install native_gatekeeper post_upgrade_service_restarts_owned service_ready service_start status_json update_check update_check_owner_json upgrade wrapper_checksum wrapper_download | tr '\n' ' ')"
if [[ "$never_carry" != "$expected_never_carry" ]]; then
  echo "Never-carry checks changed: $never_carry" >&2
  exit 1
fi

# --- passing summaries -------------------------------------------------------

expect_pass "$base_dir" \
  "Stable closeout gate passed for 0.1.7 (244f7ea90a7a): stable-clean-machine-qa.json (host class signing_mac; 64 passed in this release, 0 carried)"

dir="$(new_case static-artifact-checks)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.formula_syntax.method) = "static"
  | (.install_owners[] | select(.owner == "app_bundle") | .checks.artifact_checksum.method) = "static"
  | (.install_owners[] | select(.owner == "app_bundle") | .checks.gatekeeper.method) = "static"
  | (.install_owners[] | select(.owner == "hosted_installer") | .checks.native_gatekeeper.method) = "static"
  | (.install_owners[] | select(.owner == "hosted_installer") | .checks.install.method) = "scripted"'
expect_pass "$dir"

for host_class in clean_vm clean_macos qa_user_on_shared_mac developer_mac; do
  dir="$(new_case "host-$host_class")"
  mutate "$dir" ".environment.host_class = \"$host_class\""
  expect_pass "$dir" "host class $host_class;"
done

dir="$(new_case not-run-manifest-gate)"
write_manifest "$dir/release-manifest.json" "not_run"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_pass "$dir"

# --- passed means it ran in this release -------------------------------------

must_pass="must be passed in this release, with method live or scripted"

dir="$(new_case static-runtime-check)"
mutate "$dir" '(.install_owners[] | select(.owner == "app_bundle") | .checks.logout_json.method) = "static"'
expect_failure "$dir" "app_bundle.logout_json $must_pass"

dir="$(new_case static-download)"
mutate "$dir" '(.install_owners[] | select(.owner == "hosted_installer") | .checks.wrapper_checksum.method) = "static"'
expect_failure "$dir" "hosted_installer.wrapper_checksum $must_pass"

dir="$(new_case method-parity)"
mutate "$dir" '(.install_owners[] | select(.owner == "app_bundle") | .checks.reinstall.method) = "parity"'
expect_failure "$dir" "app_bundle.reinstall $must_pass"

dir="$(new_case passed-with-from)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json.from) = "0.1.6"'
expect_failure "$dir" "homebrew.logout_json $must_pass"

dir="$(new_case result-failed)"
mutate "$dir" '(.install_owners[] | select(.owner == "hosted_installer") | .checks.status_json.result) = "failed"'
expect_failure "$dir" "hosted_installer.status_json $must_pass"

# --- carried: shape is validated, then refused until verified carry ships ----

not_accepted="is carried; carry is not accepted until verified carry ships, so it must pass in this release"
bad_carry="is carried without a valid from (an earlier release of the same X.Y line at most 5 patches back) and method live or scripted"

# In budget (same 0.1 line, at most 5 patches back, or an RC up to 0.1.7).
for from in 0.1.2 0.1.6 0.1.7-rc1 0.1.6-rc2; do
  dir="$(new_case "carried-from-$from")"
  mutate "$dir" "$(carry homebrew logout_json "$from")"
  expect_failure "$dir" "homebrew.logout_json $not_accepted"
done

dir="$(new_case carried-scripted)"
mutate "$dir" "$(carry app_bundle move_service_to_app 0.1.5 scripted)"
expect_failure "$dir" "app_bundle.move_service_to_app $not_accepted"

# Out of budget: same version, later, 6 back, other major or minor.
for from in 0.1.7 0.1.8 0.1.8-rc1 0.1.1 0.0.6 0.2.5 1.1.6; do
  dir="$(new_case "carried-bad-from-$from")"
  mutate "$dir" "$(carry homebrew logout_json "$from")"
  expect_failure "$dir" "homebrew.logout_json $bad_carry"
done

dir="$(new_case carried-without-from)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = {result: "carried", method: "live"}'
expect_failure "$dir" "homebrew.logout_json $bad_carry"

dir="$(new_case carried-static)"
mutate "$dir" "$(carry homebrew logout_json 0.1.6 static)"
expect_failure "$dir" "homebrew.logout_json $bad_carry"

# [contract] Version grammar shared with the release API reader: canonical
# numbers (no leading zero, at most 9 digits), RC suffix -rcN with N >= 1.
for from in 0.1.06 0.01.6 0.1.1234567890 0.1.7-rc0 0.1.7-rc01; do
  dir="$(new_case "carried-noncanonical-from-$from")"
  mutate "$dir" "$(carry homebrew logout_json "$from")"
  expect_failure "$dir" "is not a schema 2 summary of this manifest"
done

for target in 0.01.7 0.1.07 0.1.1234567890 0.1.7-rc1; do
  dir="$(new_case "target-version-$target")"
  jq --arg v "$target" '.version = $v' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
  expect_failure "$dir" "Stable closeout manifest version must be X.Y.Z"
done

dir="$(new_case carried-from-word)"
mutate "$dir" "$(carry homebrew logout_json latest)"
expect_failure "$dir" "is not a schema 2 summary of this manifest"

# [regression] Every never-carry check fails when carried, for each owner that has it.
for check_name in $never_carry; do
  for owner in homebrew hosted_installer app_bundle; do
    if ! jq -e --arg owner "$owner" --arg c "$check_name" \
      '.install_owners[] | select(.owner == $owner) | .checks | has($c)' \
      "$base_dir/stable-clean-machine-qa.json" >/dev/null; then
      continue
    fi
    dir="$(new_case "never-carry-$owner-$check_name")"
    mutate "$dir" "$(carry "$owner" "$check_name" 0.1.6)"
    expect_failure "$dir" "Stable clean-machine QA check $owner.$check_name cannot be carried; it must pass in this release"
  done
done

# --- closed public schema ------------------------------------------------------

dir="$(new_case not-run-check)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json.result) = "not_run"'
expect_failure "$dir" "still contains template placeholders"

dir="$(new_case missing-method)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) |= del(.method)'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case host-trusted-internal)"
mutate "$dir" '.environment.host_class = "trusted_internal_macos"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case old-host-kind)"
mutate "$dir" '.environment.host_kind = "clean_macos"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case schema-v1)"
mutate "$dir" '.schema_version = 1'
expect_failure "$dir" "must be schema_version 2 (v1 cannot record carried checks)"

dir="$(new_case operator-notes)"
mutate "$dir" '.operator_notes = ["SYNTHETIC-PRIVATE-MARKER ran on the build host"]'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case check-note)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json.note) = "SYNTHETIC-PRIVATE-MARKER"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case ownerless-extra-entry)"
mutate "$dir" '.install_owners += [{checks: {}, comment: "SYNTHETIC-PRIVATE-MARKER"}]'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case macos-version-text)"
mutate "$dir" '.environment.macos_version = "SYNTHETIC-PRIVATE-MARKER 15.5"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case check-name-text)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks["SYNTHETIC-PRIVATE-MARKER"]) = {result: "passed", method: "live"}'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case check-value-string)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = "passed"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case bad-sha)"
mutate "$dir" '.manifest.sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case private-path)"
mutate "$dir" '.environment.arch = "/Users/example/Ottto"'
expect_failure "$dir" "private path or secret-like material"

# --- the private record stays out of the release folder ----------------------

dir="$(new_case record-beside-manifest)"
printf '{"evidence_kind": "private_record"}\n' > "$dir/stable-clean-machine-qa.record.json"
expect_failure "$dir" "A private QA record is inside the release folder; move it out before publishing: stable-clean-machine-qa.record.json"

dir="$(new_case record-nested)"
mkdir -p "$dir/homebrew"
printf '{}\n' > "$dir/homebrew/qa.record.json"
expect_failure "$dir" "A private QA record is inside the release folder; move it out before publishing: qa.record.json"

dir="$(new_case record-renamed)"
mkdir -p "$dir/notes"
printf '{"evidence_kind": "private_record", "operator_notes": ["SYNTHETIC-PRIVATE-MARKER"]}\n' > "$dir/notes/qa-notes.json"
expect_failure "$dir" "A private QA record is inside the release folder; move it out before publishing: qa-notes.json"

# --- summary file resolution ---------------------------------------------------

resolve_error="Stable clean-machine QA summary is missing beside the manifest, or evidence_path is not a plain file name"

dir="$(new_case evidence-symlink)"
mv "$dir/stable-clean-machine-qa.json" "$tmp_dir/outside-summary.json"
ln -s "$tmp_dir/outside-summary.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "$resolve_error"

dir="$(new_case evidence-absolute)"
write_manifest "$dir/release-manifest.json" "passed" "$dir/stable-clean-machine-qa.json"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "$resolve_error"

# --- owners, runtime binding and manifest -------------------------------------

dir="$(new_case failed-gate)"
write_manifest "$dir/release-manifest.json" "failed"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable clean-machine QA manifest gate status must be passed or not_run"

dir="$(new_case missing-owner)"
mutate "$dir" 'del(.install_owners[] | select(.owner == "homebrew"))'
expect_failure "$dir" "Stable clean-machine QA evidence must include exactly one entry for install owner: homebrew"

dir="$(new_case unsupported-owner)"
mutate "$dir" '.install_owners += [(.install_owners[0] | .owner = "manual_override")]'
expect_failure "$dir" "Stable clean-machine QA evidence includes unsupported install owner: manual_override"

dir="$(new_case bad-runtime)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .local_platform.runtime) = "ottto-cli"'
expect_failure "$dir" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: homebrew"

dir="$(new_case bad-protocol)"
mutate "$dir" '(.install_owners[] | select(.owner == "hosted_installer") | .local_platform.protocol_version) = 10'
expect_failure "$dir" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: hosted_installer"

dir="$(new_case bad-runtime-manifest)"
mutate "$dir" '(.install_owners[] | select(.owner == "app_bundle") | .local_platform.release_manifest_sha256) = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"'
expect_failure "$dir" "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: app_bundle"

dir="$(new_case extra-check)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.manual_override) = {result: "passed", method: "live"}'
expect_failure "$dir" "Stable clean-machine QA evidence includes unknown check homebrew.manual_override"

# [regression] The pre-headless Homebrew check is no longer in the owner matrix.
dir="$(new_case old-homebrew-check)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.app_launch_preserves_owner) = {result: "passed", method: "live"}'
expect_failure "$dir" "Stable clean-machine QA evidence includes unknown check homebrew.app_launch_preserves_owner"

dir="$(new_case missing-move-to-app)"
mutate "$dir" '(.install_owners[] | select(.owner == "app_bundle") | .checks) |= del(.move_service_to_app)'
expect_failure "$dir" "app_bundle.move_service_to_app $must_pass"

dir="$(new_case extra-required-owner)"
jq '.quality_gates.stable_clean_machine_qa.required_install_owners += ["manual_override"]' \
  "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable clean-machine QA manifest gate includes unsupported required install owner: manual_override"

dir="$(new_case target-version-format)"
jq '.version = "0.1.7-beta1"' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
expect_failure "$dir" "Stable closeout manifest version must be X.Y.Z"

dir="$(new_case dev-channel)"
jq '.channel = "dev"' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
expect_failure "$dir" "Stable closeout requires channel=stable"

echo "macos_stable_closeout_gate tests passed"
