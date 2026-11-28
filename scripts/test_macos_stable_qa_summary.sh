#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/scripts/macos_stable_qa_evidence_template.sh"
SUMMARY="$ROOT/scripts/macos_stable_qa_summary.sh"
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

"$TEMPLATE" --manifest "$manifest" --output "$record" --host-class clean_vm \
  --checked-at "2026-05-21T19:05:00Z" --macos-version "15.5" --arch arm64 >/dev/null

# A filled private record with notes, a per-check note, one carried check and
# an extra field the summary must drop.
jq '
  .status = "passed"
  | .operator_notes += ["SYNTHETIC-PRIVATE-MARKER: details of the QA host"]
  | .private_extra = {host: "SYNTHETIC-PRIVATE-MARKER"}
  | .environment.image_digest = "sha256:0000"
  | .install_owners |= map(
      .status = "passed"
      | .operator_detail = "SYNTHETIC-PRIVATE-MARKER"
      | .checks |= with_entries(.value = {result: "passed", method: "live", note: "SYNTHETIC-PRIVATE-MARKER"}))
  | (.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) =
      {result: "carried", method: "live", from: "0.1.0-rc1", note: "SYNTHETIC-PRIVATE-MARKER"}
' "$record" > "$tmp_dir/filled.json"
mv "$tmp_dir/filled.json" "$record"

expect_summary_error() {
  local expected_code="$1"
  local message="$2"
  shift 2
  local code=0
  "$SUMMARY" "$@" >"$tmp_dir/summary-error.out" 2>&1 || code=$?
  if [[ "$code" != "$expected_code" ]]; then
    echo "Expected summary exit $expected_code ($message), got $code" >&2
    cat "$tmp_dir/summary-error.out" >&2
    exit 1
  fi
  if ! grep -qF -- "$message" "$tmp_dir/summary-error.out"; then
    echo "Summary error is missing: $message" >&2
    cat "$tmp_dir/summary-error.out" >&2
    exit 1
  fi
  if grep -qF -- "SYNTHETIC-PRIVATE-MARKER" "$tmp_dir/summary-error.out" \
    || grep -qF -- "synthetic_private_marker" "$tmp_dir/summary-error.out" \
    || grep -qF -- "$tmp_dir" "$tmp_dir/summary-error.out"; then
    echo "Summary diagnostics repeat a private marker or a path" >&2
    exit 1
  fi
}

"$SUMMARY" --record "$record" --manifest "$manifest" >"$tmp_dir/summary.out"
grep -qxF "stable-qa-summary: wrote stable-clean-machine-qa.json" "$tmp_dir/summary.out"

# [contract] The summary is the closed public shape: notes and extras are gone,
# from is kept, keys are sorted and match what the closeout gate accepts.
if grep -qF -- "SYNTHETIC-PRIVATE-MARKER" "$summary" || grep -qF -- "private_record" "$summary"; then
  echo "Summary kept private record content" >&2
  exit 1
fi
jq -e '
  keys == ["checked_at", "environment", "gate", "install_owners", "manifest", "schema_version", "status"]
  and .schema_version == 2
  and .environment == {arch: "arm64", host_class: "clean_vm", macos_version: "15.5"}
  and all(.install_owners[];
    keys == ["checks", "local_platform", "owner", "status"]
    and all(.checks[]; keys == ["method", "result"] or keys == ["from", "method", "result"]))
  and (.install_owners[] | select(.owner == "homebrew") | .checks.logout_json == {from: "0.1.0-rc1", method: "live", result: "carried"})
' "$summary" >/dev/null
first_sha="$(shasum -a 256 "$summary" | awk '{print $1}')"

# The closeout gate reads the summary; carry is not accepted yet.
if "$CLOSEOUT_GATE" --manifest "$manifest" >"$tmp_dir/gate.out" 2>&1; then
  echo "Expected the closeout gate to refuse a carried check" >&2
  exit 1
fi
grep -qF "homebrew.logout_json is carried; carry is not accepted until verified carry ships" "$tmp_dir/gate.out"

# Overwrite only with --force; the output is deterministic.
expect_summary_error 2 "stable-clean-machine-qa.json already exists, pass --force" --record "$record" --manifest "$manifest"
"$SUMMARY" --record "$record" --manifest "$manifest" --force >/dev/null
[[ "$(shasum -a 256 "$summary" | awk '{print $1}')" == "$first_sha" ]]
# [contract] --stage final is the default: the same bytes, and no stage field.
"$SUMMARY" --record "$record" --manifest "$manifest" --stage final --force >/dev/null
[[ "$(shasum -a 256 "$summary" | awk '{print $1}')" == "$first_sha" ]]
jq -e 'has("stage") | not' "$summary" >/dev/null

# With every check passed in this release, the summary passes the gate.
jq '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = {result: "passed", method: "live"}' \
  "$record" > "$tmp_dir/all-passed.json"
mv "$tmp_dir/all-passed.json" "$record"
"$SUMMARY" --record "$record" --manifest "$manifest" --force >/dev/null
"$CLOSEOUT_GATE" --manifest "$manifest" >"$tmp_dir/gate-passed.out"
grep -qF "Stable closeout gate passed for 0.1.0 (244f7ea90a7a): stable-clean-machine-qa.json (host class clean_vm;" "$tmp_dir/gate-passed.out"
if find "$release_dir" -name '.stable-qa-summary.*' | grep -q .; then
  echo "Summary left a temporary file in the release folder" >&2
  exit 1
fi

# --- refusals ------------------------------------------------------------------

inside_record="$release_dir/qa.json"
cp "$record" "$inside_record"
expect_summary_error 2 "must live outside the release folder" --record "$inside_record" --manifest "$manifest" --force
rm -f "$inside_record"

cp "$summary" "$private_dir/summary-copy.json"
expect_summary_error 1 "input is not a private QA record" --record "$private_dir/summary-copy.json" --manifest "$manifest" --force

other_manifest_dir="$tmp_dir/other"
mkdir -p "$other_manifest_dir"
jq '.commit = "abcdefabcdef"' "$manifest" > "$other_manifest_dir/release-manifest.json"
expect_summary_error 1 "QA record is bound to a different manifest" \
  --record "$record" --manifest "$other_manifest_dir/release-manifest.json"

mutated_record() {
  jq "$1" "$record" > "$private_dir/mutated.record.json"
  printf '%s' "$private_dir/mutated.record.json"
}

expect_summary_error 1 "record environment.macos_version must be a short token" \
  --record "$(mutated_record '.environment.macos_version = "SYNTHETIC-PRIVATE-MARKER 15.5"')" --manifest "$manifest" --force
expect_summary_error 1 "record install owner name must be a short token" \
  --record "$(mutated_record '.install_owners += [{checks: {}, local_platform: {}, comment: "SYNTHETIC-PRIVATE-MARKER"}]')" --manifest "$manifest" --force
expect_summary_error 1 "check from must be a short token" \
  --record "$(mutated_record '(.install_owners[0].checks.logout_json.from) = "/Users/example"')" --manifest "$manifest" --force
expect_summary_error 1 "record check must be an object" \
  --record "$(mutated_record '(.install_owners[0].checks.logout_json) = "passed"')" --manifest "$manifest" --force
expect_summary_error 1 "record local_platform.protocol_version must be an integer" \
  --record "$(mutated_record '(.install_owners[0].local_platform.protocol_version) = "15"')" --manifest "$manifest" --force

symlink_dir="$tmp_dir/symlinked"
mkdir -p "$symlink_dir"
cp "$manifest" "$symlink_dir/release-manifest.json"
ln -s "$tmp_dir/elsewhere.json" "$symlink_dir/stable-clean-machine-qa.json"
expect_summary_error 1 "must not be a symlink" --record "$record" --manifest "$symlink_dir/release-manifest.json" --force

path_dir="$tmp_dir/path-evidence"
mkdir -p "$path_dir"
jq '.quality_gates.stable_clean_machine_qa.evidence_path = "../stable-clean-machine-qa.json"' "$manifest" > "$path_dir/release-manifest.json"
jq --arg sha "$(shasum -a 256 "$path_dir/release-manifest.json" | awk '{print $1}')" '.manifest.sha256 = $sha' \
  "$record" > "$private_dir/path.record.json"
expect_summary_error 1 "evidence_path must be stable-clean-machine-qa.json" \
  --record "$private_dir/path.record.json" --manifest "$path_dir/release-manifest.json"

sed 's/"protocol_version": 15,/"protocol_version": 15.0,/' "$record" > "$private_dir/float.record.json"
grep -qF '"protocol_version": 15.0,' "$private_dir/float.record.json"
expect_summary_error 1 "record local_platform.protocol_version must be an integer" \
  --record "$private_dir/float.record.json" --manifest "$manifest" --force
expect_summary_error 1 "record install owner name must be a short token" \
  --record "$(mutated_record '.install_owners[0].owner = "homebrew\nsynthetic_private_marker"')" --manifest "$manifest" --force
expect_summary_error 1 "release manifest is missing" \
  --record "$record" --manifest "$tmp_dir/synthetic_private_marker/release-manifest.json"

# --- the summary never replaces the manifest or another release file ---------

# bind_record <manifest> <output record>: the filled record, bound to that manifest.
bind_record() {
  jq --arg sha "$(shasum -a 256 "$1" | awk '{print $1}')" '.manifest.sha256 = $sha' "$record" > "$2"
}

# [regression] A manifest that is itself named like the summary keeps its bytes
# even with --force.
named_dir="$tmp_dir/manifest-named-summary"
mkdir -p "$named_dir"
cp "$manifest" "$named_dir/stable-clean-machine-qa.json"
named_sha="$(shasum -a 256 "$named_dir/stable-clean-machine-qa.json" | awk '{print $1}')"
expect_summary_error 1 "would replace the manifest or another release file" \
  --record "$record" --manifest "$named_dir/stable-clean-machine-qa.json" --force
[[ "$(shasum -a 256 "$named_dir/stable-clean-machine-qa.json" | awk '{print $1}')" == "$named_sha" ]]

# [regression] A case variant names the same file on a case-insensitive volume.
case_dir="$tmp_dir/manifest-case-variant"
mkdir -p "$case_dir"
cp "$manifest" "$case_dir/Stable-Clean-Machine-QA.json"
case_sha="$(shasum -a 256 "$case_dir/Stable-Clean-Machine-QA.json" | awk '{print $1}')"
expect_summary_error 1 "would replace the manifest or another release file" \
  --record "$record" --manifest "$case_dir/Stable-Clean-Machine-QA.json" --force
[[ "$(shasum -a 256 "$case_dir/Stable-Clean-Machine-QA.json" | awk '{print $1}')" == "$case_sha" ]]

# [regression] A hard link to the manifest under the summary name.
hardlink_dir="$tmp_dir/manifest-hard-link"
mkdir -p "$hardlink_dir"
cp "$manifest" "$hardlink_dir/release-manifest.json"
ln "$hardlink_dir/release-manifest.json" "$hardlink_dir/stable-clean-machine-qa.json"
hardlink_sha="$(shasum -a 256 "$hardlink_dir/release-manifest.json" | awk '{print $1}')"
expect_summary_error 1 "would replace the manifest or another release file" \
  --record "$record" --manifest "$hardlink_dir/release-manifest.json" --force
[[ "$(shasum -a 256 "$hardlink_dir/release-manifest.json" | awk '{print $1}')" == "$hardlink_sha" ]]

# [regression] evidence_path naming the manifest is refused; the manifest survives.
self_dir="$tmp_dir/evidence-names-manifest"
mkdir -p "$self_dir"
jq '.quality_gates.stable_clean_machine_qa.evidence_path = "release-manifest.json"' "$manifest" > "$self_dir/release-manifest.json"
self_sha="$(shasum -a 256 "$self_dir/release-manifest.json" | awk '{print $1}')"
bind_record "$self_dir/release-manifest.json" "$private_dir/self.record.json"
expect_summary_error 1 "evidence_path must be stable-clean-machine-qa.json" \
  --record "$private_dir/self.record.json" --manifest "$self_dir/release-manifest.json" --force
[[ "$(shasum -a 256 "$self_dir/release-manifest.json" | awk '{print $1}')" == "$self_sha" ]]

artifact_dir="$tmp_dir/artifact-collision"
mkdir -p "$artifact_dir"
jq '.artifacts[0].path = "stable-clean-machine-qa.json"' "$manifest" > "$artifact_dir/release-manifest.json"
printf 'synthetic artifact bytes\n' > "$artifact_dir/stable-clean-machine-qa.json"
bind_record "$artifact_dir/release-manifest.json" "$private_dir/artifact.record.json"
expect_summary_error 1 "would replace the manifest or another release file" \
  --record "$private_dir/artifact.record.json" --manifest "$artifact_dir/release-manifest.json" --force
grep -qxF 'synthetic artifact bytes' "$artifact_dir/stable-clean-machine-qa.json"

# --- aliased record and manifest paths ----------------------------------------

alias_dir="$tmp_dir/alias-release"
mkdir -p "$alias_dir" "$tmp_dir/alias-outside"
cp "$manifest" "$alias_dir/release-manifest.json"
cp "$record" "$tmp_dir/alias-outside/qa.json"

# [regression] A link inside the release folder to a record outside it: the
# publisher follows the link.
ln -s "$tmp_dir/alias-outside/qa.json" "$alias_dir/qa-notes.json"
expect_summary_error 2 "must not be or pass through a symlink" \
  --record "$alias_dir/qa-notes.json" --manifest "$alias_dir/release-manifest.json"
rm "$alias_dir/qa-notes.json"
ln -s "$tmp_dir/alias-outside" "$alias_dir/notes"
expect_summary_error 2 "must not be or pass through a symlink" \
  --record "$alias_dir/notes/qa.json" --manifest "$alias_dir/release-manifest.json"
rm "$alias_dir/notes"
ln -s "$tmp_dir/alias-outside/qa.json" "$private_dir/linked.record.json"
expect_summary_error 2 "must not be or pass through a symlink" \
  --record "$private_dir/linked.record.json" --manifest "$alias_dir/release-manifest.json"
ln -s "$alias_dir/release-manifest.json" "$private_dir/linked-manifest.json"
expect_summary_error 2 "the release manifest must not be a symlink" \
  --record "$record" --manifest "$private_dir/linked-manifest.json"
if [[ -e "$alias_dir/stable-clean-machine-qa.json" ]]; then
  echo "Summary was written from an aliased path" >&2
  exit 1
fi

# --- two stages: the pre-hosted summary, then the final summary ---------------

stage_dir="$tmp_dir/two-stage-release"
mkdir -p "$stage_dir"
cp "$manifest" "$stage_dir/release-manifest.json"
stage_manifest="$stage_dir/release-manifest.json"
stage_record="$private_dir/two-stage.record.json"
pre_hosted="$private_dir/pre-hosted-summary.json"
"$TEMPLATE" --manifest "$stage_manifest" --output "$stage_record" --host-class clean_vm \
  --checked-at "2026-05-21T19:05:00Z" --macos-version "15.5" --arch arm64 >/dev/null

# The record before the hosted lane: every other owner passed with notes, the
# hosted_installer owner and the top-level status still as the template wrote them.
jq '
  .operator_notes += ["SYNTHETIC-PRIVATE-MARKER: details of the QA host"]
  | .install_owners |= map(
      if .owner == "hosted_installer" then .
      else .status = "passed" | .checks |= map_values({result: "passed", method: "live", note: "SYNTHETIC-PRIVATE-MARKER"})
      end)
' "$stage_record" > "$tmp_dir/stage.json"
mv "$tmp_dir/stage.json" "$stage_record"

# [contract] Pre-hosted pass: the final schema plus stage, written outside the
# release folder, with every hosted check exactly {"result":"not_run"}.
"$SUMMARY" --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$pre_hosted" \
  >"$tmp_dir/pre-hosted.out"
grep -qxF "stable-qa-summary: wrote the pre-hosted summary" "$tmp_dir/pre-hosted.out"
if [[ -e "$stage_dir/stable-clean-machine-qa.json" ]] || find "$stage_dir" -name '.stable-qa-summary.*' | grep -q .; then
  echo "The pre-hosted summary wrote into the release folder" >&2
  exit 1
fi
if grep -qF -- "SYNTHETIC-PRIVATE-MARKER" "$pre_hosted" || grep -qF -- "TODO" "$pre_hosted"; then
  echo "The pre-hosted summary kept record notes or placeholders" >&2
  exit 1
fi
jq -e '
  keys == ["checked_at", "environment", "gate", "install_owners", "manifest", "schema_version", "stage", "status"]
  and .stage == "pre-hosted"
  and .status == "not_run"
  and all(.install_owners[] | select(.owner == "hosted_installer");
    .status == "not_run" and (.checks | length) == 20 and all(.checks[]; . == {result: "not_run"}))
  and all(.install_owners[] | select(.owner != "hosted_installer");
    .status == "passed" and all(.checks[]; . == {method: "live", result: "passed"}))
' "$pre_hosted" >/dev/null
"$CLOSEOUT_GATE" --manifest "$stage_manifest" --stage pre-hosted --evidence "$pre_hosted" >"$tmp_dir/pre-hosted-gate.out"
[[ "$(tail -n 1 "$tmp_dir/pre-hosted-gate.out")" == "Stable closeout pre-hosted gate passed for 0.1.0 (244f7ea90a7a)" ]]
# The final gate still needs the final summary beside the manifest.
if "$CLOSEOUT_GATE" --manifest "$stage_manifest" >/dev/null 2>&1; then
  echo "Expected the final gate to refuse a release with no final summary" >&2
  exit 1
fi

# Create-only unless --force; the output is deterministic.
pre_hosted_sha="$(shasum -a 256 "$pre_hosted" | awk '{print $1}')"
expect_summary_error 2 "the pre-hosted summary already exists, pass --force" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$pre_hosted"
"$SUMMARY" --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$pre_hosted" --force >/dev/null
[[ "$(shasum -a 256 "$pre_hosted" | awk '{print $1}')" == "$pre_hosted_sha" ]]

# stage_record_with <jq filter>: a mutated copy of the pre-hosted record.
stage_record_with() {
  jq "$1" "$stage_record" > "$private_dir/stage-mutated.record.json"
  printf '%s' "$private_dir/stage-mutated.record.json"
}

# [regression] A hosted check that passed is refused: the hosted lane runs only
# against the uploaded immutable prefix.
expect_summary_error 1 "every hosted_installer check must be not_run" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "hosted_installer") | .checks.install) = {result: "passed", method: "live"}')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
# [regression] Every other check must have passed in this release.
expect_summary_error 1 "every check outside hosted_installer must be passed in this release" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "homebrew") | .checks.logout_json) = {result: "not_run", method: "live"}')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "every check outside hosted_installer must be passed in this release" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "app_bundle") | .checks.upgrade) = {result: "carried", method: "live", from: "0.1.0-rc1"}')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "every check outside hosted_installer must be passed in this release" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "app_bundle") | .checks.upgrade.method) = "TODO_live_scripted_or_static"')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "the hosted_installer owner status must be not_run and every other owner status passed" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "hosted_installer") | .status) = "passed"')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "the hosted_installer owner status must be not_run and every other owner status passed" \
  --record "$(stage_record_with '(.install_owners[] | select(.owner == "homebrew") | .status) = "not_run"')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "the record's top-level status must be not_run" \
  --record "$(stage_record_with '.status = "passed"')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "the QA record has no hosted_installer owner" \
  --record "$(stage_record_with '.install_owners |= map(select(.owner != "hosted_installer"))')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
if [[ -e "$private_dir/refused.json" ]]; then
  echo "A refused pre-hosted summary was written" >&2
  exit 1
fi

# The pre-hosted summary stays out of the release folder, off links and off the record.
expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$stage_dir/pre-hosted.json"
mkdir -p "$stage_dir/notes"
expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$stage_dir/notes/../pre-hosted.json"
rmdir "$stage_dir/notes"
ln -s "$stage_dir" "$tmp_dir/stage-link"
expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$tmp_dir/stage-link/pre-hosted.json"
ln -s "$private_dir/elsewhere.json" "$private_dir/pre-hosted-link.json"
expect_summary_error 2 "the pre-hosted summary path must not be or pass through a symlink" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/pre-hosted-link.json"
expect_summary_error 2 "the pre-hosted summary must not replace the private QA record" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$stage_record" --force
expect_summary_error 2 "the pre-hosted summary folder is missing" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/missing/pre-hosted.json"
if [[ -e "$stage_dir/pre-hosted.json" || -e "$private_dir/elsewhere.json" ]]; then
  echo "A refused pre-hosted summary was written" >&2
  exit 1
fi

# Usage: --output only with --stage pre-hosted, which needs it; two stages only.
expect_summary_error 2 "--stage pre-hosted requires --output" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted
expect_summary_error 2 "--output goes with --stage pre-hosted only" \
  --record "$stage_record" --manifest "$stage_manifest" --output "$private_dir/refused.json"
expect_summary_error 2 "--stage must be pre-hosted or final" \
  --record "$stage_record" --manifest "$stage_manifest" --stage hosted --output "$private_dir/refused.json"
# [regression] A missing or empty operand is a usage error, not a shell abort.
expect_summary_error 2 "--stage requires a value" --record "$stage_record" --manifest "$stage_manifest" --stage
expect_summary_error 2 "--stage requires a value" --record "$stage_record" --manifest "$stage_manifest" --stage ""
expect_summary_error 2 "--output requires a value" --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output
expect_summary_error 2 "--output requires a value" --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output ""

stage_manifest_sha="$(shasum -a 256 "$stage_manifest" | awk '{print $1}')"
# [regression] The release folder is found by filesystem identity: a case alias
# names the same folder on a case-insensitive volume (the macOS default), even
# with --force. Skipped where names are case-sensitive.
stage_alias="$tmp_dir/TWO-STAGE-RELEASE"
if [[ -d "$stage_alias" ]]; then
  expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
    --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$stage_alias/pre-hosted.json"
  expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
    --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$stage_alias/release-manifest.json" --force
  if [[ -e "$stage_dir/pre-hosted.json" ]]; then
    echo "A pre-hosted summary was written through a case alias of the release folder" >&2
    exit 1
  fi
else
  echo "skip: case-alias cases need a case-insensitive volume"
fi
# [regression] A symlink followed by ".." is resolved before the "..".
mkdir -p "$stage_dir/notes"
ln -s "$stage_dir/notes" "$tmp_dir/stage-notes-link"
expect_summary_error 2 "the pre-hosted summary must live outside the release folder" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$tmp_dir/stage-notes-link/../pre-hosted.json"
rmdir "$stage_dir/notes"
# [regression] A hard link to the manifest outside the folder is still the manifest.
ln "$stage_manifest" "$private_dir/manifest-hard-link.json"
expect_summary_error 2 "the pre-hosted summary would replace the manifest or another release file" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/manifest-hard-link.json" --force
rm "$private_dir/manifest-hard-link.json"
[[ "$(shasum -a 256 "$stage_manifest" | awk '{print $1}')" == "$stage_manifest_sha" ]]

# [regression] The pre-hosted stage needs the hosted installer lane in the
# manifest: supported and required. Without it, publish in a single stage.
for omission in both required; do
  omission_dir="$tmp_dir/no-hosted-$omission"
  mkdir -p "$omission_dir"
  if [[ "$omission" == both ]]; then
    jq '.supported_install_owners -= ["hosted_installer"]
      | .quality_gates.stable_clean_machine_qa.required_install_owners -= ["hosted_installer"]' \
      "$stage_manifest" > "$omission_dir/release-manifest.json"
  else
    jq '.quality_gates.stable_clean_machine_qa.required_install_owners -= ["hosted_installer"]' \
      "$stage_manifest" > "$omission_dir/release-manifest.json"
  fi
  jq --arg sha "$(shasum -a 256 "$omission_dir/release-manifest.json" | awk '{print $1}')" '.manifest.sha256 = $sha' \
    "$stage_record" > "$private_dir/no-hosted.record.json"
  expect_summary_error 1 "the manifest must list hosted_installer in supported_install_owners" \
    --record "$private_dir/no-hosted.record.json" --manifest "$omission_dir/release-manifest.json" \
    --stage pre-hosted --output "$private_dir/refused.json"
done
if [[ -e "$private_dir/refused.json" ]]; then
  echo "A refused pre-hosted summary was written" >&2
  exit 1
fi

# After the hosted lane passes, the final summary goes beside the manifest with
# no stage field, and the final gate passes; the pre-hosted gate now refuses.
jq '
  .status = "passed"
  | (.install_owners[] | select(.owner == "hosted_installer")) |=
      (.status = "passed" | .checks |= map_values({result: "passed", method: "live"}))
' "$stage_record" > "$tmp_dir/stage.json"
mv "$tmp_dir/stage.json" "$stage_record"
"$SUMMARY" --record "$stage_record" --manifest "$stage_manifest" >/dev/null
jq -e 'has("stage") | not' "$stage_dir/stable-clean-machine-qa.json" >/dev/null
"$CLOSEOUT_GATE" --manifest "$stage_manifest" >"$tmp_dir/stage-final.out"
grep -qF "Stable closeout gate passed for 0.1.0 (244f7ea90a7a): stable-clean-machine-qa.json (host class clean_vm; 64 passed in this release, 0 carried)" \
  "$tmp_dir/stage-final.out"
if "$CLOSEOUT_GATE" --manifest "$stage_manifest" --stage pre-hosted --evidence "$pre_hosted" >"$tmp_dir/stage-late.out" 2>&1; then
  echo "Expected the pre-hosted gate to refuse a summary beside the manifest" >&2
  exit 1
fi
grep -qF "stable-clean-machine-qa.json must not be beside the manifest" "$tmp_dir/stage-late.out"
# With the hosted lane filled, the record no longer makes a pre-hosted summary.
expect_summary_error 1 "the hosted_installer owner status must be not_run" \
  --record "$stage_record" --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"
expect_summary_error 1 "every hosted_installer check must be not_run" \
  --record "$(stage_record_with '.status = "not_run" | (.install_owners[] | select(.owner == "hosted_installer") | .status) = "not_run"')" \
  --manifest "$stage_manifest" --stage pre-hosted --output "$private_dir/refused.json"

echo "macos_stable_qa_summary tests passed"
