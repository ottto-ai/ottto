#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/scripts/macos_stable_qa_evidence_template.sh"
CLOSEOUT_GATE="$ROOT/scripts/macos_stable_closeout_gate.sh"
SUMMARY="$ROOT/scripts/macos_stable_qa_summary.sh"

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
    min_protocol_version: 15,
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

release_dir="$tmp_dir/release"
private_dir="$tmp_dir/private"
mkdir -p "$release_dir" "$private_dir"
manifest="$release_dir/release-manifest.json"
record="$private_dir/stable-clean-machine-qa.record.json"
summary="$release_dir/stable-clean-machine-qa.json"
write_manifest "$manifest"

expect_template_error() {
  local expected_code="$1"
  local message="$2"
  shift 2
  local code=0
  "$TEMPLATE" "$@" >"$tmp_dir/template-error.out" 2>&1 || code=$?
  if [[ "$code" != "$expected_code" ]]; then
    echo "Expected template exit $expected_code ($message), got $code" >&2
    cat "$tmp_dir/template-error.out" >&2
    exit 1
  fi
  if [[ -n "$message" ]] && ! grep -qF -- "$message" "$tmp_dir/template-error.out"; then
    echo "Template error is missing: $message" >&2
    cat "$tmp_dir/template-error.out" >&2
    exit 1
  fi
  # Diagnostics never repeat values from the manifest or the paths given.
  if grep -qF -- "synthetic_private_marker" "$tmp_dir/template-error.out" \
    || grep -qF -- "$tmp_dir" "$tmp_dir/template-error.out"; then
    echo "Template diagnostics repeat a private marker or a path" >&2
    cat "$tmp_dir/template-error.out" >&2
    exit 1
  fi
}

"$TEMPLATE" \
  --manifest "$manifest" \
  --output "$record" \
  --host-class signing_mac \
  --checked-at "2026-05-21T19:05:00Z" \
  --macos-version "15.5" \
  --arch "arm64" \
  >"$tmp_dir/template.out"

test -f "$record"
grep -qxF "stable-qa-template: wrote the private QA record" "$tmp_dir/template.out"
jq -e \
  --arg manifest_sha "$(shasum -a 256 "$manifest" | awk '{print $1}')" \
  '
    def not_run: . == {result: "not_run", method: "TODO_live_scripted_or_static"};
    .schema_version == 2
    and .evidence_kind == "private_record"
    and .gate == "stable_clean_machine_qa"
    and .status == "not_run"
    and .checked_at == "2026-05-21T19:05:00Z"
    and .manifest == {product: "ottto-local-platform", channel: "stable", version: "0.1.0", commit: "244f7ea90a7a", sha256: $manifest_sha}
    and .environment == {host_class: "signing_mac", macos_version: "15.5", arch: "arm64"}
    and (.operator_notes | type == "array" and length > 0)
    and ([.install_owners[].owner] | sort == ["app_bundle", "homebrew", "hosted_installer"])
    and all(.install_owners[]; .status == "not_run" and all(.checks[]; not_run))
    and (.install_owners[] | select(.owner == "homebrew") | .local_platform == {
      runtime: "ottto-service",
      service_label: "net.ottto.service",
      version: "0.1.0",
      release_channel: "stable",
      install_owner: "homebrew",
      protocol_version: 15,
      release_manifest_sha256: $manifest_sha
    })
    and (.install_owners[] | select(.owner == "homebrew") | .checks | keys == ([
      "formula_syntax", "install", "service_start", "headless_no_app_process", "status_json",
      "setup_browser_claim", "apps_detect_json", "verify_codex_json", "doctor_json",
      "doctor_owner_drift_json", "fix_codex_json", "diagnostics_collect_json", "logout_json",
      "update_check", "update_check_owner_json", "upgrade", "post_upgrade_service_restarts_owned",
      "uninstall", "reinstall", "post_reinstall_status_json", "reonboard_after_keychain_wipe"
    ] | sort))
    and (.install_owners[] | select(.owner == "app_bundle") | .checks | has("move_service_to_app"))
    and (.install_owners[] | select(.owner == "app_bundle") | .checks | has("homebrew_second_install_safe_refusal"))
    and (.install_owners[] | select(.owner == "hosted_installer") | .checks | has("native_gatekeeper"))
  ' "$record" >/dev/null

# The unfilled record cannot become a summary that passes the gate.
"$SUMMARY" --record "$record" --manifest "$manifest" >/dev/null
if "$CLOSEOUT_GATE" --manifest "$manifest" >"$tmp_dir/closeout-unfilled.out" 2>&1; then
  echo "Expected closeout gate to reject an unfilled record's summary" >&2
  exit 1
fi
grep -q "template placeholders" "$tmp_dir/closeout-unfilled.out"

# Fill the record honestly: artifact checks by inspection, the rest live, and
# private notes that the summary must drop.
jq '
  .status = "passed"
  | .operator_notes += ["QA ran as the dedicated QA user; details stay in this record."]
  | .install_owners |= map(
      .status = "passed"
      | .checks |= with_entries(
          .value = (if (.key | IN("artifact_checksum", "formula_syntax", "gatekeeper", "native_gatekeeper"))
            then {result: "passed", method: "static"}
            else {result: "passed", method: "live", note: "ran on the target build"} end)))
' "$record" > "$tmp_dir/filled.json"
mv "$tmp_dir/filled.json" "$record"

# [regression] A raw record copied into the release folder never passes.
cp "$record" "$summary"
if "$CLOSEOUT_GATE" --manifest "$manifest" >"$tmp_dir/closeout-record.out" 2>&1; then
  echo "Expected closeout gate to reject a raw private record as public evidence" >&2
  exit 1
fi
grep -q "A private QA record is inside the release folder" "$tmp_dir/closeout-record.out"

"$SUMMARY" --record "$record" --manifest "$manifest" --force >/dev/null
"$CLOSEOUT_GATE" --manifest "$manifest" >"$tmp_dir/closeout-passed.out"
grep -qF "Stable closeout gate passed for 0.1.0 (244f7ea90a7a): stable-clean-machine-qa.json (host class signing_mac;" "$tmp_dir/closeout-passed.out"

# --- record placement and inputs --------------------------------------------

expect_template_error 2 "" --manifest "$manifest" --host-class signing_mac
expect_template_error 2 "" --manifest "$manifest" --output "$private_dir/no-host.record.json"
expect_template_error 2 "--host-class must be one of" \
  --manifest "$manifest" --output "$private_dir/bogus.record.json" --host-class trusted_internal_macos
expect_template_error 2 "--macos-version must be a macOS product version" \
  --manifest "$manifest" --output "$private_dir/version.record.json" --host-class signing_mac --macos-version "Sonoma 15"
expect_template_error 2 "must live outside the release folder" \
  --manifest "$manifest" --output "$release_dir/qa.record.json" --host-class signing_mac
mkdir -p "$release_dir/homebrew"
expect_template_error 2 "must live outside the release folder" \
  --manifest "$manifest" --output "$release_dir/homebrew/qa.record.json" --host-class signing_mac
expect_template_error 2 "output already exists" \
  --manifest "$manifest" --output "$record" --host-class signing_mac

for host_class in clean_vm clean_macos qa_user_on_shared_mac developer_mac; do
  "$TEMPLATE" --manifest "$manifest" --output - --host-class "$host_class" >"$tmp_dir/host.json"
  jq -e --arg host_class "$host_class" '.environment.host_class == $host_class' "$tmp_dir/host.json" >/dev/null
done

bad_required="$tmp_dir/bad-required.json"
jq 'del(.quality_gates.stable_clean_machine_qa.required_install_owners[] | select(. == "homebrew"))' \
  "$manifest" > "$bad_required"
expect_template_error 1 "required_install_owners is missing supported owner(s): homebrew" \
  --manifest "$bad_required" --output "$private_dir/bad-required.record.json" --host-class signing_mac

dev_manifest="$tmp_dir/dev-manifest.json"
jq '.channel = "dev"' "$manifest" > "$dev_manifest"
expect_template_error 1 "expected stable manifest" --manifest "$dev_manifest" --output - --host-class signing_mac

stale_protocol_manifest="$tmp_dir/stale-protocol-manifest.json"
jq '.min_protocol_version = 11' "$manifest" > "$stale_protocol_manifest"
expect_template_error 1 "min_protocol_version must be the integer 15" \
  --manifest "$stale_protocol_manifest" --output - --host-class signing_mac

float_protocol_manifest="$tmp_dir/float-protocol-manifest.json"
sed 's/"min_protocol_version": 15,/"min_protocol_version": 15.0,/' "$manifest" > "$float_protocol_manifest"
grep -qF '"min_protocol_version": 15.0,' "$float_protocol_manifest"
expect_template_error 1 "min_protocol_version must be the integer 15" \
  --manifest "$float_protocol_manifest" --output - --host-class signing_mac

newline_version_manifest="$tmp_dir/newline-version-manifest.json"
jq '.version = "0.1.0\nsynthetic_private_marker"' "$manifest" > "$newline_version_manifest"
expect_template_error 1 "manifest.version must be X.Y.Z" \
  --manifest "$newline_version_manifest" --output - --host-class signing_mac

other_name_manifest="$tmp_dir/other-name-manifest.json"
jq '.quality_gates.stable_clean_machine_qa.evidence_path = "release-manifest.json"' "$manifest" > "$other_name_manifest"
expect_template_error 1 "evidence_path must be stable-clean-machine-qa.json" \
  --manifest "$other_name_manifest" --output - --host-class signing_mac

# --- diagnostics use fixed labels ---------------------------------------------

marker_manifest="$tmp_dir/marker-product-manifest.json"
jq '.product = "synthetic_private_marker"' "$manifest" > "$marker_manifest"
expect_template_error 1 "expected product=ottto-local-platform" --manifest "$marker_manifest" --output - --host-class signing_mac

marker_manifest="$tmp_dir/marker-owner-manifest.json"
jq '.supported_install_owners += ["synthetic_private_marker"] | .quality_gates.stable_clean_machine_qa.required_install_owners += ["synthetic_private_marker"]' \
  "$manifest" > "$marker_manifest"
expect_template_error 1 "the manifest names an unsupported install owner" --manifest "$marker_manifest" --output - --host-class signing_mac

expect_template_error 1 "Release manifest is missing" \
  --manifest "$tmp_dir/synthetic_private_marker/release-manifest.json" --output - --host-class signing_mac

printf '{"product": "synthetic_private_marker",\n' > "$tmp_dir/broken-manifest.json"
expect_template_error 1 "the release manifest is not readable JSON" \
  --manifest "$tmp_dir/broken-manifest.json" --output - --host-class signing_mac

# --- aliased paths --------------------------------------------------------------

alias_release="$tmp_dir/alias-release"
mkdir -p "$alias_release" "$tmp_dir/alias-outside"
write_manifest "$alias_release/release-manifest.json"

# [regression] A link in the release folder that leads outside: the record would
# land outside, but the publisher follows the link and uploads it.
ln -s "$tmp_dir/alias-outside/qa.json" "$alias_release/qa-notes.json"
expect_template_error 2 "must not be or pass through a symlink" \
  --manifest "$alias_release/release-manifest.json" --output "$alias_release/qa-notes.json" --host-class signing_mac
ln -s "$tmp_dir/alias-outside" "$alias_release/notes"
expect_template_error 2 "must not be or pass through a symlink" \
  --manifest "$alias_release/release-manifest.json" --output "$alias_release/notes/qa.json" --host-class signing_mac
ln -s "$alias_release" "$tmp_dir/release-alias"
expect_template_error 2 "must live outside the release folder" \
  --manifest "$alias_release/release-manifest.json" --output "$tmp_dir/release-alias/qa.json" --host-class signing_mac
ln -s "$private_dir/elsewhere.record.json" "$private_dir/linked.record.json"
expect_template_error 2 "must not be or pass through a symlink" \
  --manifest "$alias_release/release-manifest.json" --output "$private_dir/linked.record.json" --host-class signing_mac
if [[ -e "$tmp_dir/alias-outside/qa.json" || -e "$private_dir/elsewhere.record.json" ]]; then
  echo "Template wrote a record through a symlink" >&2
  exit 1
fi

ln -s "$alias_release/release-manifest.json" "$private_dir/linked-manifest.json"
expect_template_error 2 "the release manifest must not be a symlink" \
  --manifest "$private_dir/linked-manifest.json" --output "$private_dir/via-link.record.json" --host-class signing_mac

# An outside hard link passes the path checks. A forced write must replace
# that entry while leaving the signed manifest's original bytes intact.
hard_link_manifest="$alias_release/release-manifest.json"
hard_link_output="$private_dir/hard-linked.record.json"
cp "$hard_link_manifest" "$tmp_dir/manifest-before-template.json"
ln "$hard_link_manifest" "$hard_link_output"
"$TEMPLATE" --manifest "$hard_link_manifest" --output "$hard_link_output" --host-class signing_mac --force >/dev/null
cmp "$hard_link_manifest" "$tmp_dir/manifest-before-template.json"
jq -e '.evidence_kind == "private_record"' "$hard_link_output" >/dev/null

# --- the pre-v2 runbook call stops before writing ----------------------------

# [regression] The old call wrote the evidence straight into the release folder
# with no host class. It must stop loudly and leave the folder untouched.
old_release="$tmp_dir/old-call-release"
mkdir -p "$old_release"
write_manifest "$old_release/release-manifest.json"
expect_template_error 2 "" \
  --manifest "$old_release/release-manifest.json" --output "$old_release/stable-clean-machine-qa.json" --force
if [[ -e "$old_release/stable-clean-machine-qa.json" ]]; then
  echo "The pre-v2 template call wrote into the release folder" >&2
  exit 1
fi
expect_template_error 2 "must live outside the release folder" \
  --manifest "$old_release/release-manifest.json" --output "$old_release/stable-clean-machine-qa.json" --force --host-class clean_macos
if [[ -e "$old_release/stable-clean-machine-qa.json" ]]; then
  echo "The template wrote into the release folder" >&2
  exit 1
fi

echo "macos_stable_qa_evidence_template tests passed"
