#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/scripts/cyclonedx_sbom.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq

sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
"$GENERATOR" --output "$sbom" --version 0.1.0-test >/dev/null

jq -e '
  .bomFormat == "CycloneDX"
  and (.serialNumber | test("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
  and .specVersion == "1.7"
  and .metadata.component.name == "ottto-local-platform"
  and .metadata.component.version == "0.1.0-test"
  and (.components | length > 0)
  and (.components | all(.type == "library" and (.purl | startswith("pkg:cargo/"))))
' "$sbom" >/dev/null

echo "cyclonedx_sbom tests passed"
