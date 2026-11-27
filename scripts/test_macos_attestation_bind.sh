#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINDER="$ROOT/scripts/macos_attestation_bind.sh"
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

mock_bin="$TMP_DIR/bin"
mkdir -p "$mock_bin"
cat > "$mock_bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${GH_MOCK_LOG:?}"
if [[ "${GH_ATTEST_FAIL:-}" == "1" ]]; then
  exit 1
fi
if [[ "$1" != "attestation" || "$2" != "verify" ]]; then
  echo "unexpected gh invocation: $*" >&2
  exit 2
fi
predicate_type=""
signer_workflow=""
source_ref=""
source_digest=""
format=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --predicate-type)
      predicate_type="${2:?}"
      shift 2
      ;;
    --signer-workflow)
      signer_workflow="${2:?}"
      shift 2
      ;;
    --source-ref)
      source_ref="${2:?}"
      shift 2
      ;;
    --source-digest)
      source_digest="${2:?}"
      shift 2
      ;;
    --format)
      format="${2:?}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$predicate_type" || -z "$signer_workflow" || -z "$source_ref" || -z "$source_digest" || "$format" != "json" ]]; then
  echo "missing attestation origin binding flags: $*" >&2
  exit 2
fi
if [[ "$signer_workflow" != "ottto-ai/ottto/.github/workflows/macos-stable-release.yml" ]]; then
  echo "unexpected signer workflow: $signer_workflow" >&2
  exit 2
fi
if [[ "$source_ref" != "refs/tags/v0.1.0" || "$source_digest" != "abcdef123456" ]]; then
  echo "unexpected source binding: $source_ref $source_digest" >&2
  exit 2
fi
printf '[{"verificationResult":{"statement":{"predicateType":"%s"}}}]
' "$predicate_type"
exit 0
MOCK
chmod +x "$mock_bin/gh"
export PATH="$mock_bin:$PATH"
export GH_MOCK_LOG="$TMP_DIR/gh.log"

# The release folder path has a space, and the binder runs from elsewhere.
REL="$TMP_DIR/release folder"
ELSEWHERE="$TMP_DIR/elsewhere"
mkdir -p "$REL" "$ELSEWHERE"
artifact="$REL/Ottto-macos-arm64.dmg"
cli="$REL/ottto-macos-arm64.zip"
daemon="$REL/ottto-service-macos-arm64.zip"
sbom="$REL/ottto-local-platform-sbom.cdx.json"
installer="$REL/install-macos.sh"
manifest="$REL/release-manifest.json"
printf 'app artifact\n' > "$artifact"
printf 'cli artifact\n' > "$cli"
printf 'daemon artifact\n' > "$daemon"
printf '#!/usr/bin/env bash\nexit 0\n' > "$installer"
chmod +x "$installer"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
sbom_sha="$(shasum -a 256 "$sbom" | awk '{print $1}')"

jq -n \
  --arg sbom "$(basename "$sbom")" \
  --arg sbom_sha "$sbom_sha" \
  '{
    schema_version: 1,
    product: "ottto-local-platform",
    version: "0.1.0",
    channel: "stable",
    commit: "abcdef123456",
    generated_at: "2026-05-23T00:00:00Z",
    min_supported_version: "0.1.0",
    min_protocol_version: 15,
    supported_install_owners: ["hosted_installer", "app_bundle", "homebrew"],
    rollback: {
      strategy: "channel_latest_pointer",
      immutable_prefix: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0",
      latest_manifest_url: "https://install.ottto.net/ottto-local-platform/releases/stable/latest/release-manifest.json",
      preserve_failed_version: true,
      operator_steps: ["one", "two", "three"],
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
        level: "build_l1",
        predicate_type: "https://slsa.dev/provenance/v1",
        repository: "ottto-ai/ottto",
        signer_workflow: ".github/workflows/macos-stable-release.yml",
        subjects: ["placeholder"],
        attested: false,
        verified: false,
        verification_command: "not verified yet"
      },
      sbom: {
        format: "cyclonedx-json",
        spec_version: "1.7",
        predicate_type: "https://cyclonedx.org/bom",
        path: $sbom,
        url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-local-platform-sbom.cdx.json",
        sha256: $sbom_sha,
        attested: false,
        verified: false,
        verification_command: "not verified yet"
      }
    },
    quality_gates: {
      packaged_app_launch: {status: "passed"}
    },
    artifacts: []
  }' > "$manifest"

write_checksums() {
  (
    cd "$REL"
    shasum -a 256 \
      Ottto-macos-arm64.dmg \
      ottto-macos-arm64.zip \
      ottto-service-macos-arm64.zip \
      ottto-local-platform-sbom.cdx.json \
      release-manifest.json \
      install-macos.sh > subject.checksums.txt
  )
}
write_checksums

# run_binder <manifest> <checksums>: bind from a directory outside the release.
run_binder() {
  (
    cd "$ELSEWHERE"
    OTTTO_RELEASE_SOURCE_REF=refs/tags/v0.1.0 "$BINDER" \
      --manifest "$1" \
      --subject-checksums "$2" \
      --repo ottto-ai/ottto \
      --signer-workflow .github/workflows/macos-stable-release.yml
  )
}

before_without_supply="$TMP_DIR/before-without-supply.json"
after_without_supply="$TMP_DIR/after-without-supply.json"
jq 'del(.supply_chain)' "$manifest" > "$before_without_supply"

# [behaviour] The source ref has no default: without it the binder refuses to run.
if (unset OTTTO_RELEASE_SOURCE_REF; "$BINDER" \
  --manifest "$manifest" \
  --subject-checksums "$REL/subject.checksums.txt" \
  --repo ottto-ai/ottto >"$TMP_DIR/no-ref.out" 2>&1); then
  echo "Expected binder to fail without a source ref" >&2
  exit 1
fi
if ! grep -Fq "Source ref is required" "$TMP_DIR/no-ref.out" || [[ -s "$GH_MOCK_LOG" ]]; then
  echo "Binder without a source ref did not fail before attestation verification" >&2
  exit 1
fi

# A checksum list must name plain files beside the manifest; anything else is
# refused before any attestation is verified.
expect_subject_rejection() {
  local label="$1"
  local message="$2"
  local checksums="$3"
  if run_binder "$manifest" "$checksums" >"$TMP_DIR/$label.out" 2>&1; then
    echo "Expected binder to reject $label subjects" >&2
    exit 1
  fi
  if ! grep -Fq "$message" "$TMP_DIR/$label.out" || [[ -s "$GH_MOCK_LOG" ]]; then
    echo "Binder did not refuse $label subjects up front: $(cat "$TMP_DIR/$label.out")" >&2
    exit 1
  fi
}
first_line="$(head -n 1 "$REL/subject.checksums.txt")"
digest="${first_line%% *}"
printf '%s  %s\n' "$digest" "$REL/Ottto-macos-arm64.dmg" > "$REL/absolute.checksums.txt"
expect_subject_rejection absolute "must name a release file beside the manifest" "$REL/absolute.checksums.txt"
printf '%s  %s\n' "$digest" "../release folder/Ottto-macos-arm64.dmg" > "$REL/escaping.checksums.txt"
expect_subject_rejection escaping "must name a release file beside the manifest" "$REL/escaping.checksums.txt"
printf '%s\n%s\n' "$first_line" "$first_line" > "$REL/duplicate.checksums.txt"
expect_subject_rejection duplicate "duplicate subject" "$REL/duplicate.checksums.txt"
printf '%s  %s\n' "$digest" "missing.dmg" > "$REL/missing.checksums.txt"
expect_subject_rejection missing "missing or not a regular file" "$REL/missing.checksums.txt"
ln -s Ottto-macos-arm64.dmg "$REL/linked.dmg"
printf '%s  %s\n' "$digest" "linked.dmg" > "$REL/symlink.checksums.txt"
expect_subject_rejection symlink "missing or not a regular file" "$REL/symlink.checksums.txt"
printf 'not a checksum line\n' > "$REL/malformed.checksums.txt"
expect_subject_rejection malformed "not shasum-compatible" "$REL/malformed.checksums.txt"
cp "$REL/subject.checksums.txt" "$ELSEWHERE/subject.checksums.txt"
expect_subject_rejection elsewhere "must sit beside the manifest" "$ELSEWHERE/subject.checksums.txt"

run_binder "$manifest" "$REL/subject.checksums.txt" >/dev/null

jq 'del(.supply_chain)' "$manifest" > "$after_without_supply"
if ! cmp -s "$before_without_supply" "$after_without_supply"; then
  echo "Attestation binder changed fields outside supply_chain" >&2
  exit 1
fi

jq -e '
  .supply_chain.slsa_build.level == "build_l1"
  and .supply_chain.slsa_build.attested == true
  and .supply_chain.slsa_build.verified == true
  and .supply_chain.slsa_build.repository == "ottto-ai/ottto"
  and .supply_chain.slsa_build.signer_workflow == ".github/workflows/macos-stable-release.yml"
  and .supply_chain.slsa_build.source_ref == "refs/tags/v0.1.0"
  and .supply_chain.slsa_build.source_digest == "abcdef123456"
  and (.supply_chain.slsa_build.subjects | index("release-manifest.json") != null)
  and .supply_chain.materials[1].kind == "private_source"
  and .supply_chain.materials[1].tree == "fedcba654321fedcba654321fedcba654321fedc"
  and .supply_chain.sbom.attested == true
  and .supply_chain.sbom.verified == true
' "$manifest" >/dev/null

# The recorded commands are examples run from the release folder: one subject
# operand relative to it and never a build-host path. The real verifications
# above ran on the actual files.
# The binder resolves subjects in the physical release folder (on macOS a
# temporary folder under /var is /private/var).
REL_PHYSICAL="$(cd "$REL" && pwd -P)"
jq -e --arg rel "$REL" --arg rel_physical "$REL_PHYSICAL" '
  [.supply_chain.slsa_build.verification_command, .supply_chain.sbom.verification_command]
  | length == 2
    and all(.[]; startswith("gh attestation verify ./Ottto-macos-arm64.dmg --repo ottto-ai/ottto ")
      and (contains($rel) | not)
      and (contains($rel_physical) | not)
      and (test(" /") | not))
' "$manifest" >/dev/null || {
  echo "Recorded verification commands must name ./<subject> only" >&2
  exit 1
}
if ! grep -Fq -- "verify $REL_PHYSICAL/Ottto-macos-arm64.dmg " "$GH_MOCK_LOG" ||
  ! grep -Fq -- "verify $REL_PHYSICAL/install-macos.sh " "$GH_MOCK_LOG"; then
  echo "Expected gh attestation verify to run on the real subject files" >&2
  exit 1
fi

expected_invocations=$((6 * 2))
actual_invocations="$(wc -l < "$GH_MOCK_LOG" | tr -d ' ')"
if [[ "$actual_invocations" != "$expected_invocations" ]]; then
  echo "Expected $expected_invocations gh attestation verify calls, got $actual_invocations" >&2
  exit 1
fi
if ! grep -Fq -- "--predicate-type https://slsa.dev/provenance/v1" "$GH_MOCK_LOG"; then
  echo "Expected SLSA attestation verification predicate type" >&2
  exit 1
fi
if ! grep -Fq -- "--predicate-type https://cyclonedx.org/bom" "$GH_MOCK_LOG"; then
  echo "Expected SBOM attestation verification predicate type" >&2
  exit 1
fi
if ! grep -Fq -- "--signer-workflow ottto-ai/ottto/.github/workflows/macos-stable-release.yml" "$GH_MOCK_LOG"; then
  echo "Expected signer workflow attestation verification binding" >&2
  exit 1
fi
if ! grep -Fq -- "--source-ref refs/tags/v0.1.0" "$GH_MOCK_LOG" || ! grep -Fq -- "--source-digest abcdef123456" "$GH_MOCK_LOG"; then
  echo "Expected source ref and digest attestation verification binding" >&2
  exit 1
fi

# Binding again after the workflow regenerates checksums writes the same bytes.
first_bind="$TMP_DIR/first-bind.json"
cp "$manifest" "$first_bind"
write_checksums
run_binder "$manifest" "$REL/subject.checksums.txt" >/dev/null
if ! cmp -s "$first_bind" "$manifest"; then
  echo "Rebinding changed the manifest bytes" >&2
  exit 1
fi

# [behaviour] --verify-only checks a sealed, read-only folder: it passes when the
# manifest already carries the binding and writes nothing there.
run_verify_only() {
  (
    cd "$ELSEWHERE"
    OTTTO_RELEASE_SOURCE_REF=refs/tags/v0.1.0 "$BINDER" --verify-only \
      --manifest "$1" \
      --subject-checksums "$2" \
      --repo ottto-ai/ottto \
      --signer-workflow .github/workflows/macos-stable-release.yml
  )
}
SEALED="$TMP_DIR/sealed folder"
mkdir -p "$SEALED"
for name in Ottto-macos-arm64.dmg ottto-macos-arm64.zip ottto-service-macos-arm64.zip \
  ottto-local-platform-sbom.cdx.json release-manifest.json install-macos.sh subject.checksums.txt; do
  cp "$REL/$name" "$SEALED/$name"
done
listing_before="$(ls -A "$SEALED")"
chmod -R a-w "$SEALED"
if ! run_verify_only "$SEALED/release-manifest.json" "$SEALED/subject.checksums.txt" >"$TMP_DIR/verify.out" 2>&1; then
  chmod -R u+w "$SEALED"
  echo "--verify-only refused a correctly bound sealed folder: $(cat "$TMP_DIR/verify.out")" >&2
  exit 1
fi
chmod -R u+w "$SEALED"
if [[ "$(ls -A "$SEALED")" != "$listing_before" ]] || ! cmp -s "$first_bind" "$SEALED/release-manifest.json"; then
  echo "--verify-only wrote into the sealed folder" >&2
  exit 1
fi
# A manifest without the binding fails, and is left as it was.
jq '.supply_chain.sbom.verification_command = "not verified yet"' "$SEALED/release-manifest.json" \
  > "$TMP_DIR/unbound.json"
cp "$TMP_DIR/unbound.json" "$SEALED/release-manifest.json"
(
  cd "$SEALED"
  shasum -a 256 Ottto-macos-arm64.dmg ottto-macos-arm64.zip ottto-service-macos-arm64.zip \
    ottto-local-platform-sbom.cdx.json release-manifest.json install-macos.sh > subject.checksums.txt
)
if run_verify_only "$SEALED/release-manifest.json" "$SEALED/subject.checksums.txt" >"$TMP_DIR/verify.out" 2>&1; then
  echo "--verify-only accepted a manifest without the attestation binding" >&2
  exit 1
fi
if ! cmp -s "$TMP_DIR/unbound.json" "$SEALED/release-manifest.json"; then
  echo "--verify-only changed a manifest it refused" >&2
  exit 1
fi

failed_manifest="$REL/failed-manifest.json"
cp "$manifest" "$failed_manifest"
jq '.supply_chain.slsa_build.verified = false | .supply_chain.sbom.verified = false' \
  "$failed_manifest" > "$failed_manifest.next"
mv "$failed_manifest.next" "$failed_manifest"
export GH_ATTEST_FAIL=1
if OTTTO_RELEASE_SOURCE_REF=refs/tags/v0.1.0 "$BINDER" \
  --manifest "$failed_manifest" \
  --subject-checksums "$REL/subject.checksums.txt" \
  --repo ottto-ai/ottto >/dev/null 2>&1; then
  echo "Expected binder to fail when gh attestation verify fails" >&2
  exit 1
fi
if jq -e '.supply_chain.slsa_build.verified == true or .supply_chain.sbom.verified == true' "$failed_manifest" >/dev/null; then
  echo "Binder set verified=true after gh attestation verify failed" >&2
  exit 1
fi

echo "macos_attestation_bind tests passed"
