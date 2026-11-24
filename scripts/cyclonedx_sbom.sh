#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT=""
VERSION="${OTTTO_RELEASE_VERSION:-0.1.0-dev}"
SPARKLE_VERSION=""
SPARKLE_REVISION=""
# Releases ship Apple Silicon binaries only.
TARGET="aarch64-apple-darwin"
CRATES_IO_SOURCE="registry+https://github.com/rust-lang/crates.io-index"

usage() {
  cat <<'USAGE'
Usage: cyclonedx_sbom.sh --output <bom.cdx.json> [options]

Generates a CycloneDX 1.7 JSON SBOM for the Apple Silicon (aarch64-apple-darwin)
build of the ottto CLI and ottto-service: every package in their normal and
build dependency graph, with the license each crate declares. With the Sparkle
options it also lists the macOS Companion app, its embedded Sparkle framework
and its bundled fonts. The release manifest records this SBOM and its
attestation requirements; this script only creates the local JSON document.

Options:
  --output <path>                SBOM output path.
  --version <value>              Release/component version. Default: OTTTO_RELEASE_VERSION or 0.1.0-dev.
  --sparkle-version <semver>     Sparkle version embedded in the Companion app.
  --sparkle-revision <40-hex>    Sparkle Git commit from the app's lockfile.
                                 Give both Sparkle options or neither.
  -h, --help                     Show help.
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
    --sparkle-version)
      SPARKLE_VERSION="${2:?--sparkle-version requires a value}"
      shift 2
      ;;
    --sparkle-revision)
      SPARKLE_REVISION="${2:?--sparkle-revision requires a value}"
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
INCLUDE_APP="false"
if [[ -n "$SPARKLE_VERSION" || -n "$SPARKLE_REVISION" ]]; then
  if [[ -z "$SPARKLE_VERSION" || -z "$SPARKLE_REVISION" ]]; then
    echo "--sparkle-version and --sparkle-revision must be given together" >&2
    exit 2
  fi
  if [[ ! "$SPARKLE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
    echo "--sparkle-version must be a semantic version: $SPARKLE_VERSION" >&2
    exit 2
  fi
  if [[ ! "$SPARKLE_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "--sparkle-revision must be a 40-character lowercase hex commit" >&2
    exit 2
  fi
  INCLUDE_APP="true"
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
output_tmp=""
cleanup() {
  rm -rf "$tmp_dir"
  if [[ -n "$output_tmp" ]]; then
    rm -f "$output_tmp"
  fi
}
trap cleanup EXIT

# Raw Cargo output holds checkout and registry paths: it stays in scratch and
# only public fields (name, version, license, registry purl) reach the SBOM.
metadata_path="$tmp_dir/cargo-metadata.json"
tree_path="$tmp_dir/cargo-tree.txt"
selected_path="$tmp_dir/selected.json"
components_path="$tmp_dir/components.json"
(
  cd "$ROOT"
  cargo metadata --locked --format-version 1 --filter-platform "$TARGET"
) > "$metadata_path"
# The release builds -p ottto-cli -p ottto-service; their target graph without
# dev-dependencies is what the shipped binaries are built from.
(
  cd "$ROOT"
  cargo tree --locked --target "$TARGET" -p ottto-cli -p ottto-service \
    --edges normal,build --prefix none --format '{p}' --color never
) > "$tree_path"

# Each row is "<name> v<version>" plus optional "(path)", "(proc-macro)" or "(*)".
if ! awk '
  NF == 0 { next }
  $1 !~ /^[A-Za-z0-9_-]+$/ || $2 !~ /^v[0-9][0-9A-Za-z.+-]*$/ {
    printf "Unexpected cargo tree row %d\n", NR > "/dev/stderr"
    exit 1
  }
  { print $1 "\t" substr($2, 2) }
' "$tree_path" | sort -u | jq -R -s -c '
  split("\n") | map(select(length > 0) | split("\t") | {name: .[0], version: .[1]})
' > "$selected_path"; then
  echo "Could not read the cargo dependency tree" >&2
  exit 1
fi

jq -n \
  --slurpfile metadata "$metadata_path" \
  --slurpfile selected "$selected_path" \
  --arg crates_io "$CRATES_IO_SOURCE" \
  '
  def fail($message): error($message);
  $metadata[0] as $m
  | ($m.workspace_members // []) as $members
  | (reduce $m.packages[] as $p ({}; .[[$p.name, $p.version] | @json] += [$p])) as $by_identity
  | $selected[0] as $rows
  | if ($rows | length) == 0 then fail("cargo tree selected no packages") else . end
  | if ([$rows[] | select(.name == "ottto-cli" or .name == "ottto-service")] | length) != 2
    then fail("cargo tree must include the ottto-cli and ottto-service release roots")
    else . end
  | [
      $rows[]
      | . as $row
      | ($row.name + "@" + $row.version) as $label
      | ($by_identity[[$row.name, $row.version] | @json] // []) as $matches
      | if ($matches | length) != 1
        then fail("Expected one cargo metadata package for " + $label + ", found " + ($matches | length | tostring))
        else $matches[0] end
      | . as $package
      | (($package.license // "") | gsub("\\s*/\\s*"; " OR ") | gsub("^\\s+|\\s+$"; "")) as $license
      | if $license == ""
        then fail("Rust package " + $label + " declares no SPDX license expression; resolve it before release")
        else . end
      | ($members | index($package.id) != null) as $workspace
      | if $workspace then
          {
            type: (if ($row.name == "ottto-cli" or $row.name == "ottto-service") then "application" else "library" end),
            "bom-ref": ("cargo-workspace:" + $label),
            name: $row.name,
            version: $row.version
          }
        elif $package.source == $crates_io then
          ("pkg:cargo/" + ($row.name | @uri) + "@" + ($row.version | @uri)) as $purl
          | {type: "library", "bom-ref": $purl, name: $row.name, version: $row.version, purl: $purl}
        else
          fail("Rust package " + $label + " comes from an unsupported source; add an SBOM identity for it")
        end
      | . + {licenses: [{expression: $license}]}
    ]
  ' > "$components_path"

if [[ "$INCLUDE_APP" == "true" ]]; then
  jq \
    --arg version "$VERSION" \
    --arg sparkle_version "$SPARKLE_VERSION" \
    --arg sparkle_revision "$SPARKLE_REVISION" \
    '
    . + [
      {
        type: "application",
        "bom-ref": ("net.ottto.Companion@" + $version),
        name: "Ottto",
        version: $version,
        description: "Closed-source macOS Companion app",
        licenses: [{expression: "LicenseRef-Ottto-Proprietary"}]
      },
      {
        type: "library",
        "bom-ref": ("pkg:github/sparkle-project/sparkle@" + ($sparkle_version | @uri)),
        name: "Sparkle",
        version: $sparkle_version,
        purl: ("pkg:github/sparkle-project/sparkle@" + ($sparkle_version | @uri)),
        licenses: [{expression: "MIT AND BSD-2-Clause AND Zlib"}],
        externalReferences: [{
          type: "vcs",
          url: ("https://github.com/sparkle-project/Sparkle/tree/" + $sparkle_revision)
        }]
      },
      {
        type: "file",
        "bom-ref": "font:Fraunces",
        name: "Fraunces",
        description: "Font bundled in the macOS Companion app",
        licenses: [{license: {id: "OFL-1.1"}}]
      },
      {
        type: "file",
        "bom-ref": "font:JetBrains Mono",
        name: "JetBrains Mono",
        description: "Font bundled in the macOS Companion app",
        licenses: [{license: {id: "OFL-1.1"}}]
      }
    ]
    ' "$components_path" > "$components_path.next"
  mv "$components_path.next" "$components_path"
fi

jq -e '
  sort_by(.name, (.version // ""), ."bom-ref") | . as $sorted
  | if ([.[]."bom-ref"] | unique | length) != length
    then error("SBOM component bom-refs must be unique") else $sorted end
' "$components_path" > "$components_path.next"
mv "$components_path.next" "$components_path"

if [[ "$INCLUDE_APP" == "true" ]]; then
  product_license="Apache-2.0 AND LicenseRef-Ottto-Proprietary"
  product_description="Ottto local platform for Apple Silicon Macs: the ottto CLI, ottto-service and the macOS Companion app. First-party terms apply per component (Apache-2.0 for the Rust workspace, proprietary for the closed-source app); third-party licenses are recorded on each component."
else
  product_license="Apache-2.0"
  product_description="Ottto local platform Rust workspace for Apple Silicon Macs: the ottto CLI and ottto-service. Third-party licenses are recorded on each component."
fi

# The serial number is stable for the same release version, target and public
# inventory, and never hashes raw Cargo output.
serial_hex="$(
  {
    printf '%s\0%s\0%s\0' "$VERSION" "$TARGET" "$product_license"
    jq -cS . "$components_path"
  } | shasum -a 256 | awk '{print $1}'
)"
variant_nibble="$(printf '%x' "$(( (0x${serial_hex:16:1} & 0x3) | 0x8 ))")"
serial_uuid="${serial_hex:0:8}-${serial_hex:8:4}-5${serial_hex:13:3}-${variant_nibble}${serial_hex:17:3}-${serial_hex:20:12}"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

output_dir="$(dirname "$OUTPUT")"
mkdir -p "$output_dir"
output_tmp="$(mktemp "$output_dir/.$(basename "$OUTPUT").XXXXXX")"
jq -n \
  --arg generated_at "$generated_at" \
  --arg serial_number "urn:uuid:$serial_uuid" \
  --arg version "$VERSION" \
  --arg product_license "$product_license" \
  --arg product_description "$product_description" \
  --slurpfile components "$components_path" \
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
        version: $version,
        description: $product_description,
        licenses: [{expression: $product_license}]
      }
    },
    components: $components[0]
  }' > "$output_tmp"
# mktemp creates the file owner-only; the SBOM is a published artifact.
chmod 0644 "$output_tmp"
mv "$output_tmp" "$OUTPUT"
output_tmp=""

echo "Wrote CycloneDX SBOM: $OUTPUT"
