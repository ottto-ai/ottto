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
if [[ "$source_ref" != "refs/heads/main" || "$source_digest" != "abcdef123456" ]]; then
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

artifact="$TMP_DIR/Ottto-macos-arm64.dmg"
cli="$TMP_DIR/ottto-macos-arm64.zip"
daemon="$TMP_DIR/ottto-service-macos-arm64.zip"
sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
installer="$TMP_DIR/install-macos.sh"
manifest="$TMP_DIR/release-manifest.json"
printf 'app artifact\n' > "$artifact"
printf 'cli artifact\n' > "$cli"
printf 'daemon artifact\n' > "$daemon"
printf '#!/usr/bin/env bash\nexit 0\n' > "$installer"
chmod +x "$installer"
jq -n '{bomFormat: "CycloneDX", specVersion: "1.7", version: 1}' > "$sbom"
sbom_sha="$(shasum -a 256 "$sbom" | awk '{print $1}')"

jq -n \
  --arg sbom "$sbom" \
  --arg sbom_sha "$sbom_sha" \
  '{
    schema_version: 1,
    product: "ottto-local-platform",
    version: "0.1.0",
    channel: "stable",
    commit: "abcdef123456",
    generated_at: "2026-05-23T00:00:00Z",
    min_supported_version: "0.1.0",
    min_protocol_version: 14,
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

(
  cd "$TMP_DIR"
  shasum -a 256 \
    Ottto-macos-arm64.dmg \
    ottto-macos-arm64.zip \
    ottto-service-macos-arm64.zip \
    ottto-local-platform-sbom.cdx.json \
    release-manifest.json \
    install-macos.sh > subject.checksums.txt
)

before_without_supply="$TMP_DIR/before-without-supply.json"
after_without_supply="$TMP_DIR/after-without-supply.json"
jq 'del(.supply_chain)' "$manifest" > "$before_without_supply"

"$BINDER" \
  --manifest "$manifest" \
  --subject-checksums "$TMP_DIR/subject.checksums.txt" \
  --repo ottto-ai/ottto \
  --signer-workflow .github/workflows/macos-stable-release.yml >/dev/null

jq 'del(.supply_chain)' "$manifest" > "$after_without_supply"
if ! cmp -s "$before_without_supply" "$after_without_supply"; then
  echo "Attestation binder changed fields outside supply_chain" >&2
  exit 1
fi

jq -e '
  .supply_chain.slsa_build.level == "build_l2"
  and .supply_chain.slsa_build.attested == true
  and .supply_chain.slsa_build.verified == true
  and .supply_chain.slsa_build.repository == "ottto-ai/ottto"
  and .supply_chain.slsa_build.signer_workflow == ".github/workflows/macos-stable-release.yml"
  and .supply_chain.slsa_build.source_ref == "refs/heads/main"
  and .supply_chain.slsa_build.source_digest == "abcdef123456"
  and (.supply_chain.slsa_build.subjects | index("release-manifest.json") != null)
  and .supply_chain.sbom.attested == true
  and .supply_chain.sbom.verified == true
' "$manifest" >/dev/null

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
if ! grep -Fq -- "--source-ref refs/heads/main" "$GH_MOCK_LOG" || ! grep -Fq -- "--source-digest abcdef123456" "$GH_MOCK_LOG"; then
  echo "Expected source ref and digest attestation verification binding" >&2
  exit 1
fi

failed_manifest="$TMP_DIR/failed-manifest.json"
cp "$manifest" "$failed_manifest"
jq '.supply_chain.slsa_build.verified = false | .supply_chain.sbom.verified = false' \
  "$failed_manifest" > "$failed_manifest.next"
mv "$failed_manifest.next" "$failed_manifest"
export GH_ATTEST_FAIL=1
if "$BINDER" \
  --manifest "$failed_manifest" \
  --subject-checksums "$TMP_DIR/subject.checksums.txt" \
  --repo ottto-ai/ottto >/dev/null 2>&1; then
  echo "Expected binder to fail when gh attestation verify fails" >&2
  exit 1
fi
if jq -e '.supply_chain.slsa_build.verified == true or .supply_chain.sbom.verified == true' "$failed_manifest" >/dev/null; then
  echo "Binder set verified=true after gh attestation verify failed" >&2
  exit 1
fi

echo "macos_attestation_bind tests passed"
