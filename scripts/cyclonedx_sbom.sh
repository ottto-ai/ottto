#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT=""
VERSION="${OTTTO_RELEASE_VERSION:-0.1.0-dev}"

usage() {
  cat <<'USAGE'
Usage: cyclonedx_sbom.sh --output <bom.cdx.json> [options]

Generates a minimal CycloneDX JSON SBOM for the Ottto local-platform Rust
workspace from cargo metadata. The release manifest records this SBOM and its
attestation requirements; this script only creates the local JSON document.

Options:
  --output <path>    SBOM output path.
  --version <value>  Release/component version. Default: OTTTO_RELEASE_VERSION or 0.1.0-dev.
  -h, --help         Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT="${2:?--output requires a value}"
      shift 2
      ;;
    --version)
      VERSION="${2:?--version requires a value}"
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

if [[ -z "$OUTPUT" ]]; then
  usage >&2
  exit 2
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command cargo
require_command jq

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

metadata_path="$tmp_dir/cargo-metadata.json"
cargo metadata --format-version 1 --manifest-path "$ROOT/Cargo.toml" > "$metadata_path"

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
serial_hex="$(
  {
    printf '%s\0' "$VERSION"
    cat "$metadata_path"
  } | shasum -a 256 | awk '{print $1}'
)"
variant_nibble="$(printf '%x' "$(( (0x${serial_hex:16:1} & 0x3) | 0x8 ))")"
serial_uuid="${serial_hex:0:8}-${serial_hex:8:4}-5${serial_hex:13:3}-${variant_nibble}${serial_hex:17:3}-${serial_hex:20:12}"
mkdir -p "$(dirname "$OUTPUT")"

jq -n \
  --arg generated_at "$generated_at" \
  --arg serial_number "urn:uuid:$serial_uuid" \
  --arg version "$VERSION" \
  --slurpfile metadata "$metadata_path" \
  '{
    bomFormat: "CycloneDX",
    serialNumber: $serial_number,
    specVersion: "1.7",
    version: 1,
    metadata: {
      timestamp: $generated_at,
      component: {
        type: "application",
        "bom-ref": ("pkg:generic/ottto-local-platform@" + $version),
        name: "ottto-local-platform",
        version: $version
      }
    },
    components: (
      ($metadata[0].packages // [])
      | sort_by(.name, .version)
      | map({
          type: "library",
          "bom-ref": ("pkg:cargo/" + .name + "@" + .version),
          name: .name,
          version: .version,
          purl: ("pkg:cargo/" + .name + "@" + .version)
        })
    )
  }' > "$OUTPUT"

echo "Wrote CycloneDX SBOM: $OUTPUT"
