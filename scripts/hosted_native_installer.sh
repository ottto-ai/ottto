#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
OUTPUT=""
BASE_URL=""

usage() {
  cat <<'USAGE'
Usage: hosted_native_installer.sh --manifest <release-manifest.json> --output <install-macos.sh> [options]

Generates the Ottto stable verified native installer helper from a stable
local-platform release manifest. The generated wrapper verifies the immutable
signed and notarized native DMG/PKG, then opens it. It does not install mutable
shell payloads, clear quarantine, or bootstrap launchd jobs, so the runtime
install owner remains app_bundle after the user installs from the DMG/PKG.

Options:
  --manifest <path>   Stable release manifest to read.
  --output <path>     Installer wrapper output path.
  --base-url <url>    Immutable HTTPS release prefix. Defaults to manifest rollback.immutable_prefix.
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
    --base-url)
      BASE_URL="${2:?--base-url requires a value}"
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
require_command python3

failures=0
fail() {
  echo "$1" >&2
  failures=$((failures + 1))
}

safe_literal() {
  local label="$1"
  local value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *'"'* || "$value" == *"'"* || "$value" == *\\* ]]; then
    fail "$label contains characters that cannot be emitted safely"
  fi
}

schema_version="$(jq -r '.schema_version // empty' "$MANIFEST")"
product="$(jq -r '.product // empty' "$MANIFEST")"
version="$(jq -r '.version // empty' "$MANIFEST")"
channel="$(jq -r '.channel // empty' "$MANIFEST")"
rollback_immutable_prefix="$(jq -r '.rollback.immutable_prefix // empty' "$MANIFEST")"
rollback_latest_manifest_url="$(jq -r '.rollback.latest_manifest_url // empty' "$MANIFEST")"
app_bundle_supported="$(jq -r '(.supported_install_owners // []) | index("app_bundle") != null' "$MANIFEST")"
verified_installer_owner="$(jq -r '.install_methods.verified_native_installer.runtime_install_owner // empty' "$MANIFEST")"

if [[ -z "$BASE_URL" ]]; then
  BASE_URL="$rollback_immutable_prefix"
fi

if [[ "$schema_version" != "1" ]]; then
  fail "Unsupported release manifest schema_version: $schema_version"
fi
if [[ "$product" != "ottto-local-platform" ]]; then
  fail "Unexpected release manifest product: $product"
fi
if [[ "$channel" != "stable" ]]; then
  fail "Verified native installer helper generation requires channel=stable, got: $channel"
fi
if [[ ! "$version" =~ ^[0-9]+([.][0-9]+){1,3}([_+.-][A-Za-z0-9]+)?$ ]]; then
  fail "Stable release version is not installer-safe: $version"
fi
if [[ "$app_bundle_supported" != "true" ]]; then
  fail "Release manifest does not advertise app_bundle as a supported install owner"
fi
if [[ -n "$verified_installer_owner" && "$verified_installer_owner" != "app_bundle" ]]; then
  fail "Verified native installer helper must bind to runtime_install_owner=app_bundle"
fi
if [[ "$rollback_immutable_prefix" != https://* || "$rollback_immutable_prefix" != *"/stable/$version" ]]; then
  fail "Stable rollback immutable_prefix must be the HTTPS stable versioned prefix: $rollback_immutable_prefix"
fi
if [[ "$rollback_latest_manifest_url" != https://* || "$rollback_latest_manifest_url" != *"/stable/latest/release-manifest.json" ]]; then
  fail "Stable rollback latest_manifest_url must be the HTTPS stable latest manifest: $rollback_latest_manifest_url"
fi
if [[ "$BASE_URL" != https://* ]]; then
  fail "Verified native installer helper base URL must use HTTPS: $BASE_URL"
fi
if [[ "$BASE_URL" == *"/latest"* || "$BASE_URL" == *"/latest/"* ]]; then
  fail "Verified native installer helper base URL must be immutable, not latest: $BASE_URL"
fi
if [[ -n "$rollback_immutable_prefix" && "${BASE_URL%/}" != "${rollback_immutable_prefix%/}" ]]; then
  fail "Verified native installer helper base URL must match rollback immutable_prefix: $BASE_URL"
fi

safe_literal "version" "$version"
safe_literal "base URL" "$BASE_URL"

app_count="$(jq '[.artifacts[]? | select(.kind == "macos_app" and .platform == "macos")] | length' "$MANIFEST")"
if [[ "$app_count" != "1" ]]; then
  fail "Stable manifest must include exactly one macOS app artifact, found $app_count"
fi
app_artifact="$(jq -c '.artifacts[]? | select(.kind == "macos_app" and .platform == "macos")' "$MANIFEST")"

artifact_field() {
  local artifact="$1"
  local field="$2"
  jq -r --arg field "$field" '.[$field] // empty' <<<"$artifact"
}

if [[ -n "$app_artifact" ]]; then
  app_url="$(artifact_field "$app_artifact" url)"
  app_sha="$(artifact_field "$app_artifact" sha256)"
  app_arch="$(artifact_field "$app_artifact" arch)"
  app_signed="$(artifact_field "$app_artifact" signed)"
  app_notarized="$(artifact_field "$app_artifact" notarized)"
  app_gatekeeper="$(artifact_field "$app_artifact" gatekeeper_assessed)"

  if [[ "$app_arch" != "arm64" ]]; then
    fail "Verified native installer helper currently supports only arm64 macOS artifacts: $app_arch"
  fi
  if [[ "$app_url" != https://* ]]; then
    fail "Verified native installer helper artifact URL must use HTTPS: $app_url"
  fi
  if [[ "$app_url" == *"/latest/"* ]]; then
    fail "Verified native installer helper artifact URL must point at an immutable versioned artifact, not latest: $app_url"
  fi
  if [[ -n "$rollback_immutable_prefix" && "$app_url" != "${rollback_immutable_prefix%/}/"* ]]; then
    fail "Verified native installer helper artifact URL is outside rollback immutable_prefix: $app_url"
  fi
  if [[ "$app_url" != *.dmg && "$app_url" != *.pkg ]]; then
    fail "Verified native installer helper artifact must be a native DMG or PKG: $app_url"
  fi
  if [[ ! "$app_sha" =~ ^[0-9a-f]{64}$ ]]; then
    fail "Verified native installer helper artifact SHA-256 is invalid: $app_sha"
  fi
  if [[ "$app_signed" != "true" ]]; then
    fail "Verified native installer helper artifact is not marked signed"
  fi
  if [[ "$app_notarized" != "true" ]]; then
    fail "Verified native installer helper artifact is not marked notarized"
  fi
  if [[ "$app_gatekeeper" != "true" ]]; then
    fail "Verified native installer helper artifact has not passed Gatekeeper assessment"
  fi

  safe_literal "app URL" "$app_url"
  safe_literal "app SHA-256" "$app_sha"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Verified native installer helper generation failed with $failures issue(s)." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
cat > "$OUTPUT" <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail

DEFAULT_BASE_URL="__OTTTO_HOSTED_NATIVE_BASE_URL__"
BASE_URL="$DEFAULT_BASE_URL"
DOWNLOAD_DIR=""
NO_OPEN=0
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: install-macos.sh [options]

Downloads the Ottto stable release manifest, verifies the signed/notarized
native DMG or PKG checksum and Gatekeeper state, then opens the native artifact.
This helper does not install mutable shell payloads, clear quarantine, or
bootstrap launchd jobs; after installation, the runtime owner is app_bundle.

Options:
  --base-url <url>       Immutable HTTPS release prefix. Default is embedded.
  --download-dir <path>  Keep downloaded files in this directory.
  --no-open              Verify the native artifact but do not open it.
  --dry-run              Validate the hosted manifest plan without downloading the artifact.
  -h, --help             Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:?--base-url requires a value}"
      shift 2
      ;;
    --download-dir)
      DOWNLOAD_DIR="${2:?--download-dir requires a value}"
      shift 2
      ;;
    --no-open)
      NO_OPEN=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command curl
require_command python3
require_command shasum
require_command awk

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Ottto native installer is currently supported only on macOS." >&2
  exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  echo "This Ottto native installer currently supports Apple Silicon Macs only." >&2
  exit 1
fi

BASE_URL="${BASE_URL%/}"
if [[ "$BASE_URL" != https://* || "$BASE_URL" == *"/latest"* || "$BASE_URL" == *"/latest/"* ]]; then
  echo "Base URL must be an immutable HTTPS release prefix, not latest: $BASE_URL" >&2
  exit 1
fi

CLEANUP_DIR=""
if [[ -n "$DOWNLOAD_DIR" ]]; then
  WORK_DIR="$DOWNLOAD_DIR"
  mkdir -p "$WORK_DIR"
else
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ottto-install.XXXXXX")"
  CLEANUP_DIR="$WORK_DIR"
fi

cleanup() {
  if [[ -n "$CLEANUP_DIR" ]]; then
    rm -rf "$CLEANUP_DIR"
  fi
}
trap cleanup EXIT

manifest_path="$WORK_DIR/release-manifest.json"
manifest_url="$BASE_URL/release-manifest.json"
echo "Downloading Ottto release manifest from $manifest_url"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "$manifest_url" \
  --output "$manifest_path"

plan_tsv="$(
  python3 - "$manifest_path" "$BASE_URL" <<'PY'
import json
import re
import sys
from pathlib import PurePosixPath
from urllib.parse import urlparse

manifest_path = sys.argv[1]
base_url = sys.argv[2].rstrip("/")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

if manifest.get("schema_version") != 1:
    fail("Unsupported release manifest schema_version")
if manifest.get("product") != "ottto-local-platform":
    fail("Unexpected release manifest product")
if manifest.get("channel") != "stable":
    fail("Verified native installer helper refuses channel not stable")

version = str(manifest.get("version") or "")
if not re.fullmatch(r"[0-9]+([.][0-9]+){1,3}([_+.-][A-Za-z0-9]+)?", version):
    fail("Stable release version is not installer-safe")

owners = manifest.get("supported_install_owners") or []
if "app_bundle" not in owners:
    fail("Release manifest does not advertise app_bundle support")

verified_installer = (manifest.get("install_methods") or {}).get("verified_native_installer") or {}
runtime_owner = verified_installer.get("runtime_install_owner")
if runtime_owner is not None and runtime_owner != "app_bundle":
    fail("Verified native installer helper must bind to runtime_install_owner=app_bundle")

rollback = manifest.get("rollback") or {}
prefix = str(rollback.get("immutable_prefix") or "").rstrip("/")
latest_manifest_url = str(rollback.get("latest_manifest_url") or "")
if not prefix.startswith("https://") or not prefix.endswith(f"/stable/{version}"):
    fail("Stable rollback immutable_prefix is invalid")
if not latest_manifest_url.startswith("https://") or not latest_manifest_url.endswith("/stable/latest/release-manifest.json"):
    fail("Stable rollback latest_manifest_url is invalid")
if base_url != prefix:
    fail("Installer base URL must match manifest rollback immutable_prefix")

artifacts = [
    artifact
    for artifact in manifest.get("artifacts", [])
    if artifact.get("kind") == "macos_app" and artifact.get("platform") == "macos"
]
if len(artifacts) != 1:
    fail(f"Stable manifest must include exactly one macOS app artifact, found {len(artifacts)}")
artifact = artifacts[0]

url = str(artifact.get("url") or "")
sha = str(artifact.get("sha256") or "")
arch = str(artifact.get("arch") or "")
if arch != "arm64":
    fail("Verified native installer helper currently supports only arm64 macOS artifacts")
if not url.startswith("https://"):
    fail("Verified native installer helper artifact URL must use HTTPS")
if "/latest/" in url:
    fail("Verified native installer helper artifact URL must be immutable, not latest")
if not url.startswith(prefix + "/"):
    fail("Verified native installer helper artifact URL is outside rollback immutable_prefix")
if not re.fullmatch(r"[0-9a-f]{64}", sha):
    fail("Verified native installer helper artifact SHA-256 is invalid")
if artifact.get("signed") is not True:
    fail("Verified native installer helper requires signed artifacts")
if artifact.get("notarized") is not True:
    fail("Verified native installer helper requires notarized artifacts")
if artifact.get("gatekeeper_assessed") is not True:
    fail("Verified native installer helper requires Gatekeeper-assessed artifacts")

parsed = urlparse(url)
filename = PurePosixPath(parsed.path).name
if not re.fullmatch(r"[A-Za-z0-9._+-]+", filename):
    fail("Verified native installer helper artifact filename is not safe")
ext = PurePosixPath(filename).suffix.lower().lstrip(".")
if ext not in {"dmg", "pkg"}:
    fail("Verified native installer helper artifact must be a native DMG or PKG")

print("\t".join([version, url, sha, filename, ext]))
PY
)"

IFS=$'\t' read -r version artifact_url artifact_sha artifact_filename artifact_ext <<< "$plan_tsv"
echo "Verified stable Ottto manifest plan for $version: $artifact_filename"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run complete; native artifact download/open skipped."
  exit 0
fi

artifact_path="$WORK_DIR/$artifact_filename"
echo "Downloading Ottto native artifact from $artifact_url"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "$artifact_url" \
  --output "$artifact_path"

computed_sha="$(shasum -a 256 "$artifact_path" | awk '{print $1}')"
if [[ "$computed_sha" != "$artifact_sha" ]]; then
  echo "SHA-256 mismatch for $artifact_filename" >&2
  echo "expected: $artifact_sha" >&2
  echo "actual:   $computed_sha" >&2
  exit 1
fi
echo "Verified SHA-256 for $artifact_filename"

require_command xcrun
require_command spctl

case "$artifact_ext" in
  dmg)
    require_command hdiutil
    hdiutil verify "$artifact_path"
    xcrun stapler validate "$artifact_path"
    spctl --assess --type open --context context:primary-signature --verbose "$artifact_path"
    ;;
  pkg)
    xcrun stapler validate "$artifact_path"
    spctl --assess --type install --verbose "$artifact_path"
    ;;
  *)
    echo "Unsupported native artifact extension: $artifact_ext" >&2
    exit 1
    ;;
esac

echo "Verified native artifact signature, notarization ticket, and Gatekeeper assessment."

if [[ "$NO_OPEN" -eq 1 ]]; then
  CLEANUP_DIR=""
  echo "Native artifact is ready at $artifact_path"
else
  CLEANUP_DIR=""
  echo "Opening $artifact_filename; downloaded files are kept in $WORK_DIR"
  open "$artifact_path"
fi
INSTALLER

python3 - "$OUTPUT" "${BASE_URL%/}" <<'PY'
import sys

path = sys.argv[1]
base_url = sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    content = handle.read()
content = content.replace("__OTTTO_HOSTED_NATIVE_BASE_URL__", base_url)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(content)
PY

chmod 0755 "$OUTPUT"
echo "Wrote verified native installer helper: $OUTPUT"
