#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
OUTPUT=""
HOMEPAGE="${OTTTO_HOMEBREW_HOMEPAGE:-https://ottto.net}"
LICENSE="${OTTTO_HOMEBREW_LICENSE:-Apache-2.0}"

usage() {
  cat <<'USAGE'
Usage: homebrew_formula.sh --manifest <release-manifest.json> --output <Formula/ottto.rb> [options]

Generates the Ottto Homebrew formula from a stable local-platform release
manifest. The generator refuses manifests that are not signed, notarized,
Gatekeeper-assessed, and immutable-prefix pinned. A formula may be generated for
QA before Homebrew is advertised as a supported install owner.

Options:
  --manifest <path>   Stable release manifest to read.
  --output <path>     Formula output path, typically <tap>/Formula/ottto.rb.
  --homepage <url>    Formula homepage. Default: https://ottto.net
  --license <spdx>    Formula license. Default: Apache-2.0
  -h, --help          Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?--output requires a value}"
      shift 2
      ;;
    --homepage)
      HOMEPAGE="${2:?--homepage requires a value}"
      shift 2
      ;;
    --license)
      LICENSE="${2:?--license requires a value}"
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

if [[ -z "$MANIFEST" || -z "$OUTPUT" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest does not exist: $MANIFEST" >&2
  exit 1
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq

failures=0
fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

safe_ruby_string() {
  local label="$1"
  local value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *'"'* || "$value" == *\\* ]]; then
    fail "$label contains characters that cannot be emitted as a safe Ruby string"
  fi
}

schema_version="$(jq -r '.schema_version // empty' "$MANIFEST")"
product="$(jq -r '.product // empty' "$MANIFEST")"
version="$(jq -r '.version // empty' "$MANIFEST")"
channel="$(jq -r '.channel // empty' "$MANIFEST")"
rollback_immutable_prefix="$(jq -r '.rollback.immutable_prefix // empty' "$MANIFEST")"
rollback_latest_manifest_url="$(jq -r '.rollback.latest_manifest_url // empty' "$MANIFEST")"

if [[ "$schema_version" != "1" ]]; then
  fail "Unsupported release manifest schema_version: $schema_version"
fi
if [[ "$product" != "ottto-local-platform" ]]; then
  fail "Unexpected release manifest product: $product"
fi
if [[ "$channel" != "stable" ]]; then
  fail "Homebrew formula generation requires channel=stable, got: $channel"
fi
if [[ ! "$version" =~ ^[0-9]+([.][0-9]+){1,3}([_+.-][A-Za-z0-9]+)?$ ]]; then
  fail "Stable release version is not formula-safe: $version"
fi
if [[ "$rollback_immutable_prefix" != https://* || "$rollback_immutable_prefix" != *"/stable/$version" ]]; then
  fail "Stable rollback immutable_prefix must be the HTTPS stable versioned prefix: $rollback_immutable_prefix"
fi
if [[ "$rollback_latest_manifest_url" != https://* || "$rollback_latest_manifest_url" != *"/stable/latest/release-manifest.json" ]]; then
  fail "Stable rollback latest_manifest_url must be the HTTPS stable latest manifest: $rollback_latest_manifest_url"
fi
if [[ "$HOMEPAGE" != https://* ]]; then
  fail "Formula homepage must use HTTPS: $HOMEPAGE"
fi
if [[ ! "$LICENSE" =~ ^[A-Za-z0-9_.+-]+$ ]]; then
  fail "Formula license must be a simple SPDX identifier or supported token: $LICENSE"
fi

safe_ruby_string "version" "$version"
safe_ruby_string "homepage" "$HOMEPAGE"
safe_ruby_string "license" "$LICENSE"

select_artifact() {
  local kind="$1"
  local count
  count="$(jq --arg kind "$kind" '[.artifacts[]? | select(.kind == $kind and .platform == "macos")] | length' "$MANIFEST")"
  if [[ "$count" != "1" ]]; then
    fail "Stable manifest must include exactly one macOS $kind artifact, found $count"
    return 1
  fi
  jq -c --arg kind "$kind" '.artifacts[] | select(.kind == $kind and .platform == "macos")' "$MANIFEST"
}

cli_artifact="$(select_artifact cli || true)"
daemon_artifact="$(select_artifact daemon || true)"

artifact_field() {
  local artifact="$1"
  local field="$2"
  jq -r --arg field "$field" '.[$field] // empty' <<<"$artifact"
}

validate_formula_artifact() {
  local artifact="$1"
  local label="$2"
  local url sha arch signed notarized gatekeeper

  url="$(artifact_field "$artifact" url)"
  sha="$(artifact_field "$artifact" sha256)"
  arch="$(artifact_field "$artifact" arch)"
  signed="$(artifact_field "$artifact" signed)"
  notarized="$(artifact_field "$artifact" notarized)"
  gatekeeper="$(artifact_field "$artifact" gatekeeper_assessed)"

  if [[ "$arch" != "arm64" ]]; then
    fail "Homebrew formula currently supports only arm64 macOS artifacts: $label ($arch)"
  fi
  if [[ "$url" != https://* ]]; then
    fail "Homebrew artifact URL must use HTTPS: $label ($url)"
  fi
  if [[ "$url" == *"/latest/"* ]]; then
    fail "Homebrew artifact URL must point at an immutable versioned artifact, not latest: $label ($url)"
  fi
  if [[ -n "$rollback_immutable_prefix" && "$url" != "$rollback_immutable_prefix/"* ]]; then
    fail "Homebrew artifact URL is outside rollback immutable_prefix: $label ($url)"
  fi
  if [[ "$url" != *.zip ]]; then
    fail "Homebrew artifact must be a zip archive: $label ($url)"
  fi
  if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    fail "Homebrew artifact SHA-256 is invalid: $label ($sha)"
  fi
  if [[ "$signed" != "true" ]]; then
    fail "Homebrew artifact is not marked signed: $label"
  fi
  if [[ "$notarized" != "true" ]]; then
    fail "Homebrew artifact is not marked notarized: $label"
  fi
  if [[ "$gatekeeper" != "true" ]]; then
    fail "Homebrew artifact has not passed Gatekeeper assessment: $label"
  fi

  safe_ruby_string "$label url" "$url"
  safe_ruby_string "$label sha256" "$sha"
}

if [[ -n "$cli_artifact" ]]; then
  validate_formula_artifact "$cli_artifact" "ottto CLI"
fi
if [[ -n "$daemon_artifact" ]]; then
  validate_formula_artifact "$daemon_artifact" "ottto service"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Homebrew formula generation failed with $failures issue(s)." >&2
  exit 1
fi

cli_url="$(artifact_field "$cli_artifact" url)"
cli_sha="$(artifact_field "$cli_artifact" sha256)"
daemon_url="$(artifact_field "$daemon_artifact" url)"
daemon_sha="$(artifact_field "$daemon_artifact" sha256)"

mkdir -p "$(dirname "$OUTPUT")"
cat > "$OUTPUT" <<FORMULA
# Generated from ${product} ${version} (${channel}).
# Do not hand-edit: run tools/ottto-local-platform/scripts/homebrew_formula.sh.
class Ottto < Formula
  desc "Local Ottto CLI and per-user service"
  homepage "${HOMEPAGE}"
  url "${cli_url}"
  version "${version}"
  sha256 "${cli_sha}"
  license "${LICENSE}"

  depends_on arch: :arm64
  depends_on macos: :sonoma

  resource "ottto-service" do
    url "${daemon_url}"
    sha256 "${daemon_sha}"
  end

  def install
    bin.install "ottto"

    resource("ottto-service").stage do
      daemons = Dir["*"].select { |path| File.file?(path) && File.executable?(path) }
      odie "ottto-service resource did not contain exactly one executable" if daemons.length != 1
      bin.install daemons.fetch(0) => "ottto-service"
    end
  end

  service do
    name macos: "net.ottto.service"
    run [
      opt_bin/"ottto-service",
      "serve",
      "--socket",
      "#{Dir.home}/Library/Application Support/Ottto/ottto-service.sock",
    ]
    keep_alive true
    environment_variables PATH: std_service_path_env
    log_path "#{Dir.home}/Library/Logs/Ottto/ottto-service.log"
    error_log_path "#{Dir.home}/Library/Logs/Ottto/ottto-service.error.log"
  end

  def caveats
    <<~EOS
      Start the Ottto local service:
        brew services start ottto

      Check status after the service is started:
        ottto --no-autostart status --json

      Update this Homebrew-managed install:
        brew update && brew upgrade ottto
        brew services restart ottto

      Stop and uninstall:
        brew services stop ottto
        brew uninstall ottto

      The Homebrew service owns launchd label net.ottto.service and the default
      per-user socket at ~/Library/Application Support/Ottto/ottto-service.sock.
    EOS
  end

  test do
    system bin/"ottto", "--help"
    system bin/"ottto-service", "--help"
  end
end
FORMULA

echo "Wrote Homebrew formula: $OUTPUT"
