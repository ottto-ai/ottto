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

# A schema 1 summary as the pre-v2 template and runbook produced it: the old
# host_kind claim, string results and the pre-headless Homebrew checks.
write_v1_evidence() {
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
        version: "0.1.7",
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
            version: "0.1.7",
            release_channel: "stable",
            install_owner: "homebrew",
            protocol_version: 15,
            release_manifest_sha256: $manifest_sha
          },
          checks: {
            formula_syntax: "passed",
            install: "passed",
            service_start: "passed",
            app_launch_preserves_owner: "passed",
            status_json: "passed",
            setup_browser_claim: "passed",
            apps_detect_json: "passed",
            verify_codex_json: "passed",
            doctor_json: "passed",
            doctor_owner_drift_json: "passed",
            fix_codex_json: "passed",
            diagnostics_collect_json: "passed",
            logout_json: "passed",
            update_check: "passed",
            update_check_owner_json: "passed",
            upgrade: "passed",
            post_upgrade_app_relaunch_preserves_owner: "passed",
            uninstall: "passed",
            reinstall: "passed",
            post_reinstall_status_json: "passed",
            reonboard_after_keychain_wipe: "passed"
          }
        },
        {
          owner: "hosted_installer",
          status: "passed",
          local_platform: {
            runtime: "ottto-service",
            service_label: "net.ottto.service",
            version: "0.1.7",
            release_channel: "stable",
            install_owner: "hosted_installer",
            protocol_version: 15,
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
            post_reinstall_status_json: "passed",
            reonboard_after_keychain_wipe: "passed"
          }
        },
        {
          owner: "app_bundle",
          status: "passed",
          local_platform: {
            runtime: "ottto-service",
            service_label: "net.ottto.service",
            version: "0.1.7",
            release_channel: "stable",
            install_owner: "app_bundle",
            protocol_version: 15,
            release_manifest_sha256: $manifest_sha
          },
          checks: {
            artifact_checksum: "passed",
            gatekeeper: "passed",
            install: "passed",
            app_launch: "passed",
            service_ready: "passed",
            homebrew_second_install_safe_refusal: "passed",
            status_json: "passed",
            setup_browser_claim: "passed",
            apps_detect_json: "passed",
            verify_codex_json: "passed",
            doctor_json: "passed",
            doctor_owner_drift_json: "passed",
            fix_codex_json: "passed",
            diagnostics_collect_json: "passed",
            logout_json: "passed",
            update_check: "passed",
            update_check_owner_json: "passed",
            upgrade: "passed",
            uninstall: "passed",
            reinstall: "passed",
            post_reinstall_status_json: "passed",
            reonboard_after_keychain_wipe: "passed"
          }
        }
      ]
    }' > "$output"
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

# [contract] --stage final is the default gate: the same exit status and the
# same output bytes for every case below.
expect_explicit_final_same() {
  local dir="$1"
  local output="$2"
  local expected_code="$3"
  local code=0
  "$GATE" --manifest "$dir/release-manifest.json" --stage final >"$tmp_dir/explicit-final.out" 2>&1 || code=$?
  if [[ "$code" != "$expected_code" ]] || ! cmp -s "$output" "$tmp_dir/explicit-final.out"; then
    echo "The gate with --stage final differs from the default gate (exit $code, expected $expected_code)" >&2
    diff "$output" "$tmp_dir/explicit-final.out" >&2 || true
    exit 1
  fi
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
  expect_explicit_final_same "$dir" "$output" 0
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
  local code=0
  "$GATE" --manifest "$dir/release-manifest.json" >"$output" 2>&1 || code=$?
  if [[ "$code" == 0 ]]; then
    echo "Expected closeout gate to fail: $message" >&2
    exit 1
  fi
  expect_explicit_final_same "$dir" "$output" "$code"
  if ! grep -qF -- "$message" "$output"; then
    echo "Closeout gate failure is missing: $message" >&2
    cat "$output" >&2
    exit 1
  fi
  # Diagnostics never echo free text, identifier-shaped values or paths from
  # the release folder.
  if grep -qiF -- "SYNTHETIC-PRIVATE-MARKER" "$output" \
    || grep -qF -- "synthetic_private_marker" "$output" \
    || grep -qF -- "$tmp_dir" "$output"; then
    echo "Closeout gate diagnostics repeat a private marker or the folder path" >&2
    cat "$output" >&2
    exit 1
  fi
}

# Replace one literal in a case's summary text (for values jq would rewrite,
# such as 2.0), and fail the test if the literal is not there.
edit_text() {
  local file="$1" from="$2" to="$3"
  grep -qF -- "$from" "$file" || { echo "Fixture literal not found: $from" >&2; exit 1; }
  FROM="$from" TO="$to" python3 -c 'import os, sys; p = sys.argv[1]; t = open(p).read(); open(p, "w").write(t.replace(os.environ["FROM"], os.environ["TO"]))' "$file"
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
# [contract] The final gate's whole output is this one line.
printf '%s\n' "Stable closeout gate passed for 0.1.7 (244f7ea90a7a): stable-clean-machine-qa.json (host class signing_mac; 64 passed in this release, 0 carried)" \
  > "$tmp_dir/base-expected.out"
if ! cmp -s "$tmp_dir/pass.out" "$tmp_dir/base-expected.out"; then
  echo "The final gate output changed" >&2
  diff "$tmp_dir/base-expected.out" "$tmp_dir/pass.out" >&2 || true
  exit 1
fi

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

# [regression] A genuinely filled v1 summary (the pre-v2 format) stops with a
# clear v2 requirement.
dir="$(new_case schema-v1)"
write_v1_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
jq -e '.schema_version == 1 and .environment.host_kind == "clean_macos" and (.install_owners[0].checks | all(.[]; . == "passed"))' \
  "$dir/stable-clean-machine-qa.json" >/dev/null
expect_failure "$dir" "must be schema_version 2 (v1 cannot record carried checks)"

# --- whole values and JSON integers, as the release API reader checks them ----

dir="$(new_case checked-at-multiline)"
mutate "$dir" '.checked_at = "2026-05-21T19:00:00Z\nSYNTHETIC-PRIVATE-MARKER"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case macos-version-multiline)"
mutate "$dir" '.environment.macos_version = "15.5\nsynthetic_private_marker"'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case schema-version-float)"
edit_text "$dir/stable-clean-machine-qa.json" '"schema_version": 2,' '"schema_version": 2.0,'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case protocol-version-float)"
edit_text "$dir/stable-clean-machine-qa.json" '"protocol_version": 15,' '"protocol_version": 15.0,'
expect_failure "$dir" "is not a schema 2 summary of this manifest"

dir="$(new_case manifest-protocol-float)"
edit_text "$dir/release-manifest.json" '"min_protocol_version": 15,' '"min_protocol_version": 15.0,'
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable closeout manifest min_protocol_version must be the integer 15"

suffix_case=0
for target in $'0.1.7\n' '0.1.7 ' $'0.1.7\nsynthetic_private_marker'; do
  suffix_case=$((suffix_case + 1))
  dir="$(new_case "target-version-suffix-$suffix_case")"
  jq --arg v "$target" '.version = $v' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
  write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
  expect_failure "$dir" "Stable closeout manifest version must be X.Y.Z"
done

for from in $'0.1.6\n' '0.1.6 ' $'0.1.6\nsynthetic_private_marker'; do
  suffix_case=$((suffix_case + 1))
  dir="$(new_case "carried-from-suffix-$suffix_case")"
  jq --arg from "$from" \
    '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = {result: "carried", method: "live", from: $from}' \
    "$dir/stable-clean-machine-qa.json" > "$tmp_dir/mutated.json"
  mv "$tmp_dir/mutated.json" "$dir/stable-clean-machine-qa.json"
  expect_failure "$dir" "is not a schema 2 summary of this manifest"
done

record_error="A private QA record is inside the release folder"
dir="$(new_case operator-notes)"
mutate "$dir" '.operator_notes = ["SYNTHETIC-PRIVATE-MARKER ran on the build host"]'
expect_failure "$dir" "$record_error"

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

# Raw edits preserve the two members that jq would collapse to the last one.
duplicate_key_error="Stable clean-machine QA evidence contains duplicate JSON keys"
dir="$(new_case duplicate-environment-leaf)"
edit_text "$dir/stable-clean-machine-qa.json" '"arch": "arm64"' '"arch": "SYNTHETIC-PRIVATE-MARKER", "arch": "arm64"'
expect_failure "$dir" "$duplicate_key_error"

dir="$(new_case duplicate-check-result)"
edit_text "$dir/stable-clean-machine-qa.json" \
  $'"formula_syntax": {\n          "result": "passed"' \
  $'"formula_syntax": {\n          "result": "failed", "result": "passed"'
expect_failure "$dir" "$duplicate_key_error"

# --- the private record stays out of the release folder ----------------------

dir="$(new_case record-beside-manifest)"
printf '{"evidence_kind": "private_record"}\n' > "$dir/stable-clean-machine-qa.record.json"
expect_failure "$dir" "$record_error (1 file(s)); move it out before publishing"

dir="$(new_case record-nested)"
mkdir -p "$dir/homebrew"
printf '{}\n' > "$dir/homebrew/qa.record.json"
expect_failure "$dir" "$record_error"

dir="$(new_case record-renamed)"
mkdir -p "$dir/notes"
printf '{"evidence_kind": "private_record", "operator_notes": ["SYNTHETIC-PRIVATE-MARKER"]}\n' > "$dir/notes/qa-notes.json"
expect_failure "$dir" "$record_error"

# Renamed records use a JSON escape in the kind value and no distinctive suffix.
# The public summary beside each one is valid.
for encoding in utf-8 utf-8-sig utf-16 utf-32 utf-16-le utf-16-be utf-32-le; do
  dir="$(new_case "record-renamed-$encoding")"
  python3 - "$dir/qa-notes.txt" "$encoding" <<'PY'
import pathlib
import sys

record = ' \r\n{"evidence_kind": "private\\u005frecord"}\n'
pathlib.Path(sys.argv[1]).write_bytes(record.encode(sys.argv[2]))
PY
  expect_failure "$dir" "$record_error"
done

dir="$(new_case record-operator-notes-only)"
printf '{"gate": "stable_clean_machine_qa", "operator_notes": ["SYNTHETIC-PRIVATE-MARKER"]}\n' > "$dir/qa-notes.txt"
expect_failure "$dir" "$record_error"

# Public RC and launch evidence beside the manifest carry their own
# operator_notes; they are not private records.
dir="$(new_case rc-evidence-with-notes)"
printf '{"schema_version": 1, "gate": "stable_candidate_rc_qa", "status": "passed", "operator_notes": ["redacted stable-candidate RC evidence"]}\n' > "$dir/stable-candidate-rc-qa.json"
printf '{"schema_version": 1, "status": "passed", "operator_notes": ["redacted launch smoke"]}\n' > "$dir/packaged-app-launch-smoke.json"
expect_pass "$dir"

# Large binary artifacts are skipped after the prefix probe. A possible JSON
# object that exceeds the same scanner's size limit fails closed.
dir="$(new_case large-binary-artifact)"
python3 - "$dir/artifact.zip" <<'PY'
import sys

with open(sys.argv[1], "wb") as stream:
    stream.write(b"PK\x03\x04")
    stream.truncate(20 * 1024 * 1024)
PY
expect_pass "$dir"

dir="$(new_case oversized-json-object)"
python3 - "$dir/large.json" <<'PY'
import sys

with open(sys.argv[1], "wb") as stream:
    stream.write(b"{")
    stream.truncate(20 * 1024 * 1024)
PY
expect_failure "$dir" "Could not scan the release folder for private QA records"

dir="$(new_case unreadable-regular-file)"
touch "$dir/locked.dat"
chmod 000 "$dir/locked.dat"
if [[ ! -r "$dir/locked.dat" ]]; then
  expect_failure "$dir" "Could not scan the release folder for private QA records"
fi
chmod 600 "$dir/locked.dat"

# --- the release folder holds plain files only ---------------------------------

symlink_error="The release folder contains 1 symlink(s); replace them with plain files or move them out before publishing"
private_dir="$tmp_dir/private"
mkdir -p "$private_dir/notes"
printf '{"evidence_kind": "private_record", "operator_notes": ["SYNTHETIC-PRIVATE-MARKER"]}\n' > "$private_dir/qa.json"
printf '{"evidence_kind": "private_record"}\n' > "$private_dir/notes/qa.json"

# [regression] A valid summary beside a renamed link to the private record: the
# publisher follows file links, a recursive grep does not.
dir="$(new_case record-file-link)"
ln -s "$private_dir/qa.json" "$dir/qa-notes.json"
expect_failure "$dir" "$symlink_error"

dir="$(new_case record-dir-link)"
ln -s "$private_dir/notes" "$dir/notes"
expect_failure "$dir" "$symlink_error"

dir="$(new_case harmless-link)"
ln -s release-manifest.json "$dir/manifest-alias.json"
expect_failure "$dir" "$symlink_error"

dir="$(new_case dangling-link)"
ln -s "$tmp_dir/does-not-exist.json" "$dir/missing.json"
expect_failure "$dir" "$symlink_error"

dir="$(new_case evidence-symlink)"
mv "$dir/stable-clean-machine-qa.json" "$tmp_dir/outside-summary.json"
ln -s "$tmp_dir/outside-summary.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "$symlink_error"

# A folder the gate cannot read fails closed (skipped when running as root,
# where permissions do not block the scan).
dir="$(new_case unreadable-subfolder)"
mkdir -p "$dir/locked"
printf '{"evidence_kind": "private_record"}\n' > "$dir/locked/qa.json"
chmod 000 "$dir/locked"
if [[ ! -r "$dir/locked" ]]; then
  expect_failure "$dir" "Could not scan the release folder"
fi
chmod 755 "$dir/locked"

# --- summary file resolution ---------------------------------------------------

dir="$(new_case evidence-missing)"
rm "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable clean-machine QA summary stable-clean-machine-qa.json is missing beside the manifest"

evidence_name_error="Stable clean-machine QA gate evidence_path must be stable-clean-machine-qa.json"

dir="$(new_case evidence-absolute)"
write_manifest "$dir/release-manifest.json" "passed" "$dir/stable-clean-machine-qa.json"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "$evidence_name_error"

dir="$(new_case evidence-other-name)"
write_manifest "$dir/release-manifest.json" "passed" "qa-summary.json"
write_evidence "$dir/release-manifest.json" "$dir/qa-summary.json"
expect_failure "$dir" "$evidence_name_error"

dir="$(new_case evidence-manifest-name)"
write_manifest "$dir/release-manifest.json" "passed" "release-manifest.json"
expect_failure "$dir" "$evidence_name_error"

dir="$(new_case evidence-name-newline)"
write_manifest "$dir/release-manifest.json" "passed" $'stable-clean-machine-qa.json\n'
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "$evidence_name_error"

# --- diagnostics never repeat values from the files ---------------------------

# [regression] Identifier-shaped values (they could be a user or host name) are
# replaced by fixed labels.
dir="$(new_case marker-owner)"
mutate "$dir" '.install_owners += [(.install_owners[0] | .owner = "synthetic_private_marker")]'
expect_failure "$dir" "Stable clean-machine QA evidence includes unsupported install owner: <unknown owner>"

dir="$(new_case marker-check)"
mutate "$dir" '(.install_owners[] | select(.owner == "homebrew") | .checks.synthetic_private_marker) = {result: "passed", method: "live"}'
expect_failure "$dir" "Stable clean-machine QA evidence includes unknown check homebrew.<unknown check>"

dir="$(new_case marker-manifest-owner)"
jq '.supported_install_owners += ["synthetic_private_marker"] | .quality_gates.stable_clean_machine_qa.required_install_owners += ["synthetic_private_marker"]' \
  "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
write_evidence "$dir/release-manifest.json" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable closeout does not know how to validate install owner: <unknown owner>"

dir="$(new_case marker-manifest-fields)"
jq '.product = "synthetic_private_marker" | .commit = "synthetic_private_marker"' \
  "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
expect_failure "$dir" "Stable closeout requires product=ottto-local-platform"
expect_failure "$dir" "Stable closeout manifest commit is not a git SHA prefix"

dir="$(new_case marker-manifest-json)"
printf '{"product": "synthetic_private_marker",\n' > "$dir/release-manifest.json"
expect_failure "$dir" "Release manifest is not readable JSON"

mkdir -p "$tmp_dir/cases/synthetic_private_marker"
expect_failure "$tmp_dir/cases/synthetic_private_marker" "Release manifest is missing"

# An unreadable manifest gets a fixed message, not the tool's error with the
# path (skipped when running as root).
dir="$(new_case unreadable-manifest)"
chmod 000 "$dir/release-manifest.json"
if [[ ! -r "$dir/release-manifest.json" ]]; then
  expect_failure "$dir" "Release manifest is not readable"
fi
chmod 644 "$dir/release-manifest.json"

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
expect_failure "$dir" "Stable clean-machine QA evidence includes unsupported install owner: <unknown owner>"

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
expect_failure "$dir" "Stable clean-machine QA evidence includes unknown check homebrew.<unknown check>"

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
expect_failure "$dir" "Stable clean-machine QA manifest gate includes unsupported required install owner: <unknown owner>"

dir="$(new_case target-version-format)"
jq '.version = "0.1.7-beta1"' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
expect_failure "$dir" "Stable closeout manifest version must be X.Y.Z"

dir="$(new_case dev-channel)"
jq '.channel = "dev"' "$base_dir/release-manifest.json" > "$dir/release-manifest.json"
expect_failure "$dir" "Stable closeout requires channel=stable"

# --- two stages: pre-hosted, then final --------------------------------------

# [contract] The publisher's capability probe.
if [[ "$("$GATE" --supports-stages)" != "pre-hosted final" ]]; then
  echo "--supports-stages must print: pre-hosted final" >&2
  exit 1
fi

pre_hosted_dir="$tmp_dir/pre-hosted-evidence"
mkdir -p "$pre_hosted_dir"
# The base summary as the pre-hosted stage writes it: the hosted lane has not run.
PRE_HOSTED_FILTER='.stage = "pre-hosted"
  | .status = "not_run"
  | (.install_owners[] | select(.owner == "hosted_installer")) |= (.status = "not_run" | .checks |= map_values({result: "not_run"}))'

# new_pre_hosted_case <name>: a release folder without the summary; the
# pre-hosted summary is pre_hosted_evidence <name>, outside every release folder.
new_pre_hosted_case() {
  local dir
  dir="$(new_case "$1")"
  jq "$PRE_HOSTED_FILTER" "$dir/stable-clean-machine-qa.json" > "$pre_hosted_dir/$1.json"
  rm "$dir/stable-clean-machine-qa.json"
  printf '%s' "$dir"
}

pre_hosted_evidence() {
  printf '%s' "$pre_hosted_dir/$1.json"
}

mutate_pre_hosted() {
  jq "$2" "$(pre_hosted_evidence "$1")" > "$tmp_dir/mutated.json"
  mv "$tmp_dir/mutated.json" "$(pre_hosted_evidence "$1")"
}

# run_pre_hosted <dir> <evidence> <output>: the gate's exit status.
run_pre_hosted() {
  local code=0
  "$GATE" --manifest "$1/release-manifest.json" --stage pre-hosted --evidence "$2" >"$3" 2>&1 || code=$?
  return "$code"
}

expect_pre_hosted_failure() {
  local dir="$1"
  local evidence="$2"
  local message="$3"
  local output="$tmp_dir/pre-hosted-failure.out"
  if run_pre_hosted "$dir" "$evidence" "$output"; then
    echo "Expected the pre-hosted gate to fail: $message" >&2
    exit 1
  fi
  if ! grep -qF -- "$message" "$output"; then
    echo "Pre-hosted gate failure is missing: $message" >&2
    cat "$output" >&2
    exit 1
  fi
  if grep -qiF -- "SYNTHETIC-PRIVATE-MARKER" "$output" || grep -qF -- "$tmp_dir" "$output"; then
    echo "Pre-hosted gate diagnostics repeat a private marker or a path" >&2
    cat "$output" >&2
    exit 1
  fi
}

# [contract] Pre-hosted pass: every non-hosted check passed, every hosted check
# exactly not run, no summary beside the manifest. The last line is fixed.
dir="$(new_pre_hosted_case pre-hosted-pass)"
if ! run_pre_hosted "$dir" "$(pre_hosted_evidence pre-hosted-pass)" "$tmp_dir/pre-hosted-pass.out"; then
  echo "Expected the pre-hosted gate to pass" >&2
  cat "$tmp_dir/pre-hosted-pass.out" >&2
  exit 1
fi
if [[ "$(tail -n 1 "$tmp_dir/pre-hosted-pass.out")" != "Stable closeout pre-hosted gate passed for 0.1.7 (244f7ea90a7a)" ]]; then
  echo "Pre-hosted gate last line changed" >&2
  cat "$tmp_dir/pre-hosted-pass.out" >&2
  exit 1
fi
grep -qxF "stable-closeout: pre-hosted summary (host class signing_mac; 44 passed in this release, 20 hosted_installer checks not run yet)" \
  "$tmp_dir/pre-hosted-pass.out"
if grep -qF -- "$tmp_dir" "$tmp_dir/pre-hosted-pass.out"; then
  echo "Pre-hosted gate output names a path" >&2
  exit 1
fi

# [regression] A hosted check that passed is refused in the pre-hosted stage:
# the hosted lane can only run against the uploaded immutable prefix.
not_run_exactly='must be exactly {"result":"not_run"} in the pre-hosted stage'
dir="$(new_pre_hosted_case pre-hosted-hosted-passed)"
mutate_pre_hosted pre-hosted-hosted-passed \
  '(.install_owners[] | select(.owner == "hosted_installer") | .checks.wrapper_download) = {result: "passed", method: "live"}'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-hosted-passed)" "hosted_installer.wrapper_download $not_run_exactly"

dir="$(new_pre_hosted_case pre-hosted-hosted-method)"
mutate_pre_hosted pre-hosted-hosted-method \
  '(.install_owners[] | select(.owner == "hosted_installer") | .checks.install) = {result: "not_run", method: "live"}'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-hosted-method)" "hosted_installer.install $not_run_exactly"

# The final summary (hosted lane passed) is not a pre-hosted summary.
dir="$(new_pre_hosted_case pre-hosted-all-passed)"
jq '.stage = "pre-hosted"' "$base_dir/stable-clean-machine-qa.json" > "$(pre_hosted_evidence pre-hosted-all-passed)"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-all-passed)" "is not a schema 2 summary of this manifest"

for field in top hosted; do
  dir="$(new_pre_hosted_case "pre-hosted-status-$field")"
  if [[ "$field" == top ]]; then
    mutate_pre_hosted "pre-hosted-status-$field" '.status = "passed"'
  else
    mutate_pre_hosted "pre-hosted-status-$field" '(.install_owners[] | select(.owner == "hosted_installer") | .status) = "passed"'
  fi
  expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence "pre-hosted-status-$field")" "is not a schema 2 summary of this manifest"
done

# [regression] Every other check must still have passed in this release.
dir="$(new_pre_hosted_case pre-hosted-homebrew-not-run)"
mutate_pre_hosted pre-hosted-homebrew-not-run \
  '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = {result: "not_run"}'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-homebrew-not-run)" "still contains template placeholders: the pre-hosted summary"

dir="$(new_pre_hosted_case pre-hosted-app-not-run)"
mutate_pre_hosted pre-hosted-app-not-run \
  '(.install_owners[] | select(.owner == "app_bundle") | .checks.move_service_to_app) = {result: "not_run", method: "live"}'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-app-not-run)" "still contains template placeholders: the pre-hosted summary"

dir="$(new_pre_hosted_case pre-hosted-app-status)"
mutate_pre_hosted pre-hosted-app-status '(.install_owners[] | select(.owner == "app_bundle") | .status) = "not_run"'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-app-status)" "still contains template placeholders: the pre-hosted summary"

dir="$(new_pre_hosted_case pre-hosted-carried)"
mutate_pre_hosted pre-hosted-carried "$(carry app_bundle move_service_to_app 0.1.6)"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-carried)" \
  "app_bundle.move_service_to_app is carried; carry is not accepted until verified carry ships"

dir="$(new_pre_hosted_case pre-hosted-static-runtime)"
mutate_pre_hosted pre-hosted-static-runtime '(.install_owners[] | select(.owner == "homebrew") | .checks.install.method) = "static"'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-static-runtime)" "homebrew.install $must_pass"

# [regression] The summary beside the manifest is refused in the pre-hosted
# stage: it would be uploaded with the immutable prefix.
beside_error="stable-clean-machine-qa.json must not be beside the manifest"
dir="$(new_pre_hosted_case pre-hosted-summary-beside)"
cp "$base_dir/stable-clean-machine-qa.json" "$dir/"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-summary-beside)" "$beside_error"

dir="$(new_pre_hosted_case pre-hosted-evidence-beside)"
cp "$(pre_hosted_evidence pre-hosted-evidence-beside)" "$dir/stable-clean-machine-qa.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-evidence-beside)" "$beside_error"

# The pre-hosted summary lives outside the release folder, as a plain file.
dir="$(new_pre_hosted_case pre-hosted-evidence-inside)"
mkdir -p "$dir/notes"
cp "$(pre_hosted_evidence pre-hosted-evidence-inside)" "$dir/notes/pre-hosted.json"
expect_pre_hosted_failure "$dir" "$dir/notes/pre-hosted.json" "The pre-hosted summary must live outside the release folder"
expect_pre_hosted_failure "$dir" "$dir/../pre-hosted-evidence-inside/notes/pre-hosted.json" \
  "The pre-hosted summary must live outside the release folder"

dir="$(new_pre_hosted_case pre-hosted-evidence-link)"
ln -s "$(pre_hosted_evidence pre-hosted-evidence-link)" "$tmp_dir/pre-hosted-link.json"
expect_pre_hosted_failure "$dir" "$tmp_dir/pre-hosted-link.json" "The pre-hosted summary is missing or is not a single plain file"
expect_pre_hosted_failure "$dir" "$tmp_dir/pre-hosted-missing.json" "The pre-hosted summary is missing or is not a single plain file"

dir="$(new_pre_hosted_case pre-hosted-no-stage)"
mutate_pre_hosted pre-hosted-no-stage 'del(.stage)'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-no-stage)" "The pre-hosted gate needs a pre-hosted summary"

dir="$(new_pre_hosted_case pre-hosted-other-stage)"
mutate_pre_hosted pre-hosted-other-stage '.stage = "final"'
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-other-stage)" "The pre-hosted gate needs a pre-hosted summary"

# Every other final rule still applies: release-folder symlinks and private records.
dir="$(new_pre_hosted_case pre-hosted-symlink)"
ln -s "$(pre_hosted_evidence pre-hosted-symlink)" "$dir/qa-link.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-symlink)" "$symlink_error"

dir="$(new_pre_hosted_case pre-hosted-private-record)"
printf '{"evidence_kind": "private_record"}\n' > "$dir/qa.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-private-record)" "$record_error"

# [regression] A summary with a stage field is refused by the final gate,
# including the pre-hosted summary copied beside the manifest.
dir="$(new_case final-with-stage)"
mutate "$dir" '.stage = "pre-hosted"'
expect_failure "$dir" "Stable clean-machine QA evidence has a stage field"

dir="$(new_case final-with-final-stage)"
mutate "$dir" '.stage = "final"'
expect_failure "$dir" "Stable clean-machine QA evidence has a stage field"

dir="$(new_pre_hosted_case final-with-pre-hosted-summary)"
cp "$(pre_hosted_evidence final-with-pre-hosted-summary)" "$dir/stable-clean-machine-qa.json"
expect_failure "$dir" "Stable clean-machine QA evidence has a stage field"

# Usage: --evidence only with --stage pre-hosted, which needs it; two stages only.
expect_usage_error() {
  local message="$1"
  local code=0
  shift
  "$GATE" "$@" >"$tmp_dir/usage.out" 2>&1 || code=$?
  if [[ "$code" != 2 ]] || ! grep -qF -- "$message" "$tmp_dir/usage.out"; then
    echo "Expected usage error (exit 2, got $code): $message" >&2
    cat "$tmp_dir/usage.out" >&2
    exit 1
  fi
}
expect_usage_error "--stage pre-hosted requires --evidence" --manifest "$base_dir/release-manifest.json" --stage pre-hosted
expect_usage_error "--evidence goes with --stage pre-hosted only" \
  --manifest "$base_dir/release-manifest.json" --evidence "$(pre_hosted_evidence pre-hosted-pass)"
expect_usage_error "--evidence goes with --stage pre-hosted only" \
  --manifest "$base_dir/release-manifest.json" --stage final --evidence "$(pre_hosted_evidence pre-hosted-pass)"
expect_usage_error "--stage must be pre-hosted or final" --manifest "$base_dir/release-manifest.json" --stage hosted
# [regression] A missing or empty operand is a usage error, not a shell abort.
expect_usage_error "--stage requires a value" --manifest "$base_dir/release-manifest.json" --stage
expect_usage_error "--stage requires a value" --manifest "$base_dir/release-manifest.json" --stage ""
expect_usage_error "--evidence requires a value" --manifest "$base_dir/release-manifest.json" --stage pre-hosted --evidence
expect_usage_error "--evidence requires a value" --manifest "$base_dir/release-manifest.json" --stage pre-hosted --evidence ""

# [regression] The release folder is found by filesystem identity, not by the
# spelling of the path: a symlinked parent folder that leads into it is refused.
outside_error="The pre-hosted summary must live outside the release folder"
dir="$(new_pre_hosted_case pre-hosted-linked-parent)"
cp "$(pre_hosted_evidence pre-hosted-linked-parent)" "$dir/pre-hosted.json"
ln -s "$dir" "$tmp_dir/release-folder-link"
expect_pre_hosted_failure "$dir" "$tmp_dir/release-folder-link/pre-hosted.json" "$outside_error"
# [regression] A symlink followed by ".." is resolved before the "..".
dir="$(new_pre_hosted_case pre-hosted-link-dotdot)"
mkdir -p "$dir/notes"
cp "$(pre_hosted_evidence pre-hosted-link-dotdot)" "$dir/pre-hosted.json"
ln -s "$dir/notes" "$tmp_dir/release-notes-link"
expect_pre_hosted_failure "$dir" "$tmp_dir/release-notes-link/../pre-hosted.json" "$outside_error"
# A symlinked folder that resolves outside the release folder is accepted.
dir="$(new_pre_hosted_case pre-hosted-linked-outside)"
ln -s "$pre_hosted_dir" "$tmp_dir/evidence-folder-link"
if ! run_pre_hosted "$dir" "$tmp_dir/evidence-folder-link/pre-hosted-linked-outside.json" "$tmp_dir/linked-outside.out"; then
  echo "Expected the pre-hosted gate to accept evidence in a symlinked folder outside the release folder" >&2
  cat "$tmp_dir/linked-outside.out" >&2
  exit 1
fi

# [regression] A case alias of the release folder names the same folder on a
# case-insensitive volume (the macOS default). Skipped where names are case-sensitive.
dir="$(new_pre_hosted_case pre-hosted-case-alias)"
case_alias="$tmp_dir/cases/PRE-HOSTED-CASE-ALIAS"
if [[ -d "$case_alias" ]]; then
  cp "$(pre_hosted_evidence pre-hosted-case-alias)" "$dir/pre-hosted.json"
  expect_pre_hosted_failure "$dir" "$case_alias/pre-hosted.json" "$outside_error"
  cp "$base_dir/stable-clean-machine-qa.json" "$tmp_dir/cases/Pre-Hosted-Case-Alias/STABLE-CLEAN-MACHINE-QA.json"
  expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-case-alias)" "$beside_error"
else
  echo "skip: case-alias cases need a case-insensitive volume"
fi

# [regression] A hard link into the release folder is the same file under another name.
dir="$(new_pre_hosted_case pre-hosted-hard-link)"
ln "$(pre_hosted_evidence pre-hosted-hard-link)" "$dir/qa-copy.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-hard-link)" "The pre-hosted summary is missing or is not a single plain file"

# [regression] The gate reads the exact path it checked: a name with a trailing
# newline is not the name without it.
dir="$(new_pre_hosted_case pre-hosted-newline-name)"
newline_evidence="$(pre_hosted_evidence pre-hosted-newline-name)"$'\n'
jq '(.install_owners[] | select(.owner == "hosted_installer") | .checks.install) = {result: "passed", method: "live"}' \
  "$(pre_hosted_evidence pre-hosted-newline-name)" > "$newline_evidence"
expect_pre_hosted_failure "$dir" "$newline_evidence" "hosted_installer.install $not_run_exactly"

# A relative evidence path that starts with a dash is a file, not an option.
dir="$(new_pre_hosted_case pre-hosted-dash-name)"
cp "$(pre_hosted_evidence pre-hosted-dash-name)" "$pre_hosted_dir/-dash.json"
if ! (cd "$pre_hosted_dir" && "$GATE" --manifest "$dir/release-manifest.json" --stage pre-hosted --evidence -dash.json \
  >"$tmp_dir/dash.out" 2>&1); then
  echo "Expected the pre-hosted gate to read a relative path that starts with a dash" >&2
  cat "$tmp_dir/dash.out" >&2
  exit 1
fi

# [regression] The pre-hosted stage needs the hosted installer lane in the
# manifest: supported and required. Without it, publish in a single stage.
hosted_owner_error="The pre-hosted stage needs hosted_installer in the manifest's supported_install_owners"
dir="$(new_pre_hosted_case pre-hosted-no-hosted-owner)"
jq '.supported_install_owners -= ["hosted_installer"]
  | .quality_gates.stable_clean_machine_qa.required_install_owners -= ["hosted_installer"]' \
  "$dir/release-manifest.json" > "$tmp_dir/manifest.json"
mv "$tmp_dir/manifest.json" "$dir/release-manifest.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-no-hosted-owner)" "$hosted_owner_error"
dir="$(new_pre_hosted_case pre-hosted-hosted-not-required)"
jq '.quality_gates.stable_clean_machine_qa.required_install_owners -= ["hosted_installer"]' \
  "$dir/release-manifest.json" > "$tmp_dir/manifest.json"
mv "$tmp_dir/manifest.json" "$dir/release-manifest.json"
expect_pre_hosted_failure "$dir" "$(pre_hosted_evidence pre-hosted-hosted-not-required)" "$hosted_owner_error"

echo "macos_stable_closeout_gate tests passed"
