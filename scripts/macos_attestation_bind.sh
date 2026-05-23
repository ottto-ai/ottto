#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
SUBJECT_CHECKSUMS=""
REPOSITORY="${OTTTO_RELEASE_REPOSITORY:-ottto-ai/ottto}"
SIGNER_WORKFLOW="${OTTTO_RELEASE_SIGNER_WORKFLOW:-.github/workflows/macos-stable-release.yml}"
SLSA_ATTESTATION_URL=""
SBOM_ATTESTATION_URL=""

usage() {
  cat <<'USAGE'
Usage: macos_attestation_bind.sh --manifest <release-manifest.json> --subject-checksums <subject.checksums.txt> [options]

Verifies GitHub artifact attestations for the final release subjects and binds
only release-manifest.json supply_chain.slsa_build and supply_chain.sbom fields.
The script refuses to set verified=true unless gh attestation verify passes for
both SLSA provenance and CycloneDX SBOM attestations.

Options:
  --repo <owner/repo>              Expected GitHub repository. Default: ottto-ai/ottto
  --signer-workflow <path>         Expected signer workflow path.
  --slsa-attestation-url <url>     Optional URL recorded on supply_chain.slsa_build.
  --sbom-attestation-url <url>     Optional URL recorded on supply_chain.sbom.
  -h, --help                      Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --subject-checksums)
      SUBJECT_CHECKSUMS="${2:?--subject-checksums requires a value}"
      shift 2
      ;;
    --repo)
      REPOSITORY="${2:?--repo requires a value}"
      shift 2
      ;;
    --signer-workflow)
      SIGNER_WORKFLOW="${2:?--signer-workflow requires a value}"
      shift 2
      ;;
    --slsa-attestation-url)
      SLSA_ATTESTATION_URL="${2:?--slsa-attestation-url requires a value}"
      shift 2
      ;;
    --sbom-attestation-url)
      SBOM_ATTESTATION_URL="${2:?--sbom-attestation-url requires a value}"
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

if [[ -z "$MANIFEST" || -z "$SUBJECT_CHECKSUMS" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest does not exist: $MANIFEST" >&2
  exit 1
fi
if [[ ! -f "$SUBJECT_CHECKSUMS" ]]; then
  echo "Subject checksums file does not exist: $SUBJECT_CHECKSUMS" >&2
  exit 1
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command gh
require_command jq
require_command python3
require_command shasum

if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Repository must be owner/repo: $REPOSITORY" >&2
  exit 2
fi
if [[ "$SIGNER_WORKFLOW" != .github/workflows/*.yml && "$SIGNER_WORKFLOW" != .github/workflows/*.yaml ]]; then
  echo "Signer workflow must be a GitHub workflow path: $SIGNER_WORKFLOW" >&2
  exit 2
fi

manifest_dir="$(cd "$(dirname "$MANIFEST")" && pwd)"
checksum_dir="$(cd "$(dirname "$SUBJECT_CHECKSUMS")" && pwd)"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

subjects_json="$(
  python3 - "$SUBJECT_CHECKSUMS" "$checksum_dir" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PurePosixPath

checksums = Path(sys.argv[1]).resolve()
checksum_dir = Path(sys.argv[2]).resolve()
subjects: list[dict[str, str]] = []
seen: set[str] = set()

for line_number, raw in enumerate(checksums.read_text(encoding="utf-8").splitlines(), start=1):
    if not raw.strip():
        continue
    match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", raw)
    if not match:
        print(f"subject checksums line {line_number} is not shasum-compatible", file=sys.stderr)
        sys.exit(1)
    digest, name = match.groups()
    if name.startswith("/") or "\\" in name:
        print(f"subject checksums line {line_number} must use a relative POSIX subject path", file=sys.stderr)
        sys.exit(1)
    posix = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in posix.parts):
        print(f"subject checksums line {line_number} has unsafe subject path: {name}", file=sys.stderr)
        sys.exit(1)
    if name in seen:
        print(f"subject checksums contain duplicate subject: {name}", file=sys.stderr)
        sys.exit(1)
    seen.add(name)
    path = (checksum_dir / Path(*posix.parts)).resolve()
    if not path.is_file():
        print(f"subject file is missing: {name}", file=sys.stderr)
        sys.exit(1)
    subjects.append({"name": name, "sha256": digest, "path": str(path)})

if not subjects:
    print("subject checksums file has no subjects", file=sys.stderr)
    sys.exit(1)

print(json.dumps(subjects, separators=(",", ":"), sort_keys=True))
PY
)"

while IFS= read -r subject; do
  name="$(jq -r '.name' <<<"$subject")"
  expected_sha="$(jq -r '.sha256' <<<"$subject")"
  path="$(jq -r '.path' <<<"$subject")"
  actual_sha="$(sha256_file "$path")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "Subject SHA mismatch for $name: expected $expected_sha, got $actual_sha" >&2
    exit 1
  fi
done < <(jq -c '.[]' <<<"$subjects_json")

sbom_predicate_type="$(jq -r '.supply_chain.sbom.predicate_type // "https://cyclonedx.org/bom"' "$MANIFEST")"
if [[ "$sbom_predicate_type" != "https://cyclonedx.org/bom" ]]; then
  echo "Manifest SBOM predicate type is invalid: $sbom_predicate_type" >&2
  exit 1
fi

while IFS= read -r subject; do
  path="$(jq -r '.path' <<<"$subject")"
  gh attestation verify "$path" --repo "$REPOSITORY" >/dev/null
  gh attestation verify "$path" --repo "$REPOSITORY" --predicate-type "$sbom_predicate_type" >/dev/null
done < <(jq -c '.[]' <<<"$subjects_json")

subjects_names_json="$(jq -c '[.[].name] | sort' <<<"$subjects_json")"
first_subject_path="$(jq -r '.[0].path' <<<"$subjects_json")"
slsa_verification_command="gh attestation verify $first_subject_path --repo $REPOSITORY"
sbom_verification_command="gh attestation verify $first_subject_path --repo $REPOSITORY --predicate-type $sbom_predicate_type"

tmp_manifest="$(mktemp "$manifest_dir/release-manifest.attestation-bind.XXXXXX")"
trap 'rm -f "$tmp_manifest"' EXIT

jq \
  --arg repository "$REPOSITORY" \
  --arg signer_workflow "$SIGNER_WORKFLOW" \
  --arg slsa_verification_command "$slsa_verification_command" \
  --arg sbom_verification_command "$sbom_verification_command" \
  --arg slsa_attestation_url "$SLSA_ATTESTATION_URL" \
  --arg sbom_attestation_url "$SBOM_ATTESTATION_URL" \
  --argjson subjects "$subjects_names_json" \
  '
  .supply_chain.slsa_build = (
    .supply_chain.slsa_build
    + {
        spec_version: "1.2",
        level: "build_l2",
        predicate_type: "https://slsa.dev/provenance/v1",
        repository: $repository,
        signer_workflow: $signer_workflow,
        subjects: $subjects,
        attested: true,
        verified: true,
        verification_command: $slsa_verification_command
      }
    + (if $slsa_attestation_url == "" then {} else {attestation_url: $slsa_attestation_url} end)
  )
  | .supply_chain.sbom = (
    .supply_chain.sbom
    + {
        format: "cyclonedx-json",
        spec_version: "1.7",
        predicate_type: "https://cyclonedx.org/bom",
        attested: true,
        verified: true,
        verification_command: $sbom_verification_command
      }
    + (if $sbom_attestation_url == "" then {} else {attestation_url: $sbom_attestation_url} end)
  )
  ' "$MANIFEST" > "$tmp_manifest"

if ! jq empty "$tmp_manifest" >/dev/null; then
  echo "Generated manifest is invalid JSON" >&2
  exit 1
fi

mv "$tmp_manifest" "$MANIFEST"
trap - EXIT
echo "Bound verified GitHub attestations in $MANIFEST"
