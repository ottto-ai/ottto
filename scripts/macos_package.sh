#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
MAC_APP_ROOT="${OTTTO_MACOS_APP_ROOT:-$ROOT/tools/ottto-macos-app}"

VERSION="0.1.0-dev"
CHANNEL="dev"
OUTPUT_DIR="$ROOT/dist/macos"
SIGN_IDENTITY="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"
NOTARIZED="false"
SKIP_BUILD="false"
ARTIFACT_BASE_URL=""
MIN_SUPPORTED_VERSION="${OTTTO_MIN_SUPPORTED_VERSION:-0.1.0}"

usage() {
  cat <<'USAGE'
Usage: macos_package.sh [options]

Options:
  --version <version>        Release version. Default: 0.1.0-dev
  --channel <channel>        dev, preview, stable-candidate, or stable. Default: dev
  --output-dir <path>        Output directory. Default: tools/ottto-local-platform/dist/macos
  --sign-identity <identity> Developer ID signing identity.
  --artifact-base-url <url>  Public URL prefix for generated artifacts.
  --notarized               Mark artifacts notarized after external notarization.
  --skip-build              Reuse existing release build outputs.
  -h, --help                Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --channel)
      CHANNEL="${2:?--channel requires a value}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?--output-dir requires a value}"
      shift 2
      ;;
    --sign-identity)
      SIGN_IDENTITY="${2:?--sign-identity requires a value}"
      shift 2
      ;;
    --artifact-base-url)
      ARTIFACT_BASE_URL="${2:?--artifact-base-url requires a value}"
      shift 2
      ;;
    --notarized)
      NOTARIZED="true"
      shift
      ;;
    --skip-build)
      SKIP_BUILD="true"
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

case "$CHANNEL" in
  dev|preview|stable-candidate|stable) ;;
  *)
    echo "--channel must be dev, preview, stable-candidate, or stable" >&2
    exit 2
    ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command shasum
require_command swift
require_command cargo
require_command ditto
require_command hdiutil
require_command plutil
require_command codesign

ARCH="$(uname -m)"
if [[ "$ARCH" == "aarch64" ]]; then
  ARCH="arm64"
fi

if [[ -z "$ARTIFACT_BASE_URL" ]]; then
  ARTIFACT_BASE_URL="https://install.ottto.net/ottto-local-platform/releases/$CHANNEL/$VERSION"
fi
ARTIFACT_BASE_URL="${ARTIFACT_BASE_URL%/}"
RELEASE_CHANNEL_URL_ROOT="${ARTIFACT_BASE_URL%/"$VERSION"}"
if [[ "$RELEASE_CHANNEL_URL_ROOT" == "$ARTIFACT_BASE_URL" ]]; then
  RELEASE_CHANNEL_URL_ROOT="https://install.ottto.net/ottto-local-platform/releases/$CHANNEL"
fi
LATEST_MANIFEST_URL="$RELEASE_CHANNEL_URL_ROOT/latest/release-manifest.json"
if [[ -n "${OTTTO_SUPPORTED_INSTALL_OWNERS_JSON:-}" ]]; then
  SUPPORTED_INSTALL_OWNERS_JSON="$OTTTO_SUPPORTED_INSTALL_OWNERS_JSON"
elif [[ "$CHANNEL" == "stable" ]]; then
  SUPPORTED_INSTALL_OWNERS_JSON='["app_bundle", "homebrew"]'
else
  SUPPORTED_INSTALL_OWNERS_JSON='["hosted_installer", "app_bundle", "homebrew"]'
fi
if ! jq -e 'type == "array" and length > 0 and all(.[]; type == "string" and length > 0)' <<<"$SUPPORTED_INSTALL_OWNERS_JSON" >/dev/null; then
  echo "OTTTO_SUPPORTED_INSTALL_OWNERS_JSON must be a non-empty JSON string array" >&2
  exit 2
fi
if [[ ! -d "$MAC_APP_ROOT" ]]; then
  echo "macOS app root does not exist: $MAC_APP_ROOT" >&2
  echo "Set OTTTO_MACOS_APP_ROOT to the OtttoCompanion Swift package root." >&2
  exit 2
fi
if [[ ! -f "$MAC_APP_ROOT/Package.swift" ]]; then
  echo "macOS app root is missing Package.swift: $MAC_APP_ROOT" >&2
  exit 2
fi

COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
MIN_PROTOCOL_VERSION="${OTTTO_MIN_PROTOCOL_VERSION:-$(sed -n 's/.*PROTOCOL_VERSION: u16 = \([0-9][0-9]*\).*/\1/p' "$ROOT/crates/ottto-protocol/src/lib.rs" | head -n1)}"
if [[ -z "$MIN_PROTOCOL_VERSION" ]]; then
  echo "Could not determine local protocol version" >&2
  exit 1
fi

if [[ "$SKIP_BUILD" != "true" ]]; then
  (
    cd "$ROOT"
    OTTTO_RELEASE_VERSION="$VERSION" \
      OTTTO_RELEASE_CHANNEL="$CHANNEL" \
      GIT_COMMIT="$COMMIT" \
      cargo build --release -p ottto-cli -p ottto-service
  )
  swift build -c release --package-path "$MAC_APP_ROOT"
fi

SWIFT_BUILD_DIR="$MAC_APP_ROOT/.build/release"
APP_EXECUTABLE="$SWIFT_BUILD_DIR/OtttoCompanion"
CLI_BINARY="$ROOT/target/release/ottto"
DAEMON_BINARY="$ROOT/target/release/ottto-service"

for binary in "$APP_EXECUTABLE" "$CLI_BINARY" "$DAEMON_BINARY"; do
  if [[ ! -x "$binary" ]]; then
    echo "Expected executable is missing: $binary" >&2
    exit 1
  fi
done

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

APP_BUNDLE="$OUTPUT_DIR/Ottto.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"

mkdir -p "$APP_MACOS" "$APP_HELPERS" "$APP_RESOURCES" "$APP_LAUNCH_AGENTS"
cp "$APP_EXECUTABLE" "$APP_MACOS/Ottto"
cp "$CLI_BINARY" "$APP_HELPERS/ottto"
cp "$DAEMON_BINARY" "$APP_HELPERS/ottto-service"
cp "$MAC_APP_ROOT/Sources/OtttoCompanion/Resources/OtttoCompanionIcon.icns" "$APP_RESOURCES/OtttoCompanionIcon.icns"
# Mirror the SwiftPM resource bundle's payload into Contents/Resources/ so
# OtttoResourceImage.resourceImage(name:) can resolve PNGs via Bundle.main
# without touching Bundle.module (whose generated accessor crashes inside an
# .app wrapper because it expects OtttoCompanion_OtttoCompanion.bundle next to
# Bundle.main.bundleURL, which is the .app root).
SWIFTPM_RESOURCE_BUNDLE="$SWIFT_BUILD_DIR/OtttoCompanion_OtttoCompanion.bundle"
if [[ -d "$SWIFTPM_RESOURCE_BUNDLE/Resources" ]]; then
  cp -R "$SWIFTPM_RESOURCE_BUNDLE/Resources/." "$APP_RESOURCES/"
else
  echo "Expected SwiftPM resource bundle is missing: $SWIFTPM_RESOURCE_BUNDLE" >&2
  exit 1
fi
cp "$CLI_BINARY" "$OUTPUT_DIR/ottto"
cp "$DAEMON_BINARY" "$OUTPUT_DIR/ottto-service"

cat > "$APP_CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleDisplayName</key>
  <string>Ottto</string>
  <key>CFBundleExecutable</key>
  <string>Ottto</string>
  <key>CFBundleIdentifier</key>
  <string>net.ottto.Companion</string>
  <key>CFBundleIconFile</key>
  <string>OtttoCompanionIcon</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Ottto</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>Ottto Local Platform</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>ottto</string>
      </array>
    </dict>
  </array>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>LSMultipleInstancesProhibited</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

plutil -lint "$APP_CONTENTS/Info.plist" >/dev/null

cat > "$APP_LAUNCH_AGENTS/net.ottto.service.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>net.ottto.service</string>
  <key>BundleProgram</key>
  <string>Contents/Helpers/ottto-service</string>
  <key>ProgramArguments</key>
  <array>
    <string>ottto-service</string>
    <string>serve-xpc</string>
    <string>--mach-service</string>
    <string>net.ottto.service.xpc</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>net.ottto.service.xpc</key>
    <true/>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
PLIST

plutil -lint "$APP_LAUNCH_AGENTS/net.ottto.service.plist" >/dev/null

SIGNED="false"
if [[ -n "$SIGN_IDENTITY" ]]; then
  sign_code() {
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$1"
  }
  sign_container() {
    codesign --force --timestamp --sign "$SIGN_IDENTITY" "$1"
  }
  SIGNED="true"
else
  sign_code() {
    codesign --force --sign - "$1"
  }
  sign_container() {
    codesign --force --sign - "$1"
  }
fi

sign_code "$APP_HELPERS/ottto"
sign_code "$APP_HELPERS/ottto-service"
sign_code "$APP_MACOS/Ottto"
sign_code "$OUTPUT_DIR/ottto"
sign_code "$OUTPUT_DIR/ottto-service"
sign_code "$APP_BUNDLE"

LAUNCH_SMOKE_EVIDENCE="$OUTPUT_DIR/packaged-app-launch-smoke.json"
"$ROOT/scripts/macos_launch_smoke.sh" \
  --app "$APP_BUNDLE" \
  --wait-seconds "${OTTTO_MACOS_LAUNCH_SMOKE_WAIT_SECONDS:-10}" \
  --output "$LAUNCH_SMOKE_EVIDENCE"

APP_DMG="$OUTPUT_DIR/Ottto-macos-$ARCH.dmg"
DMG_STAGING="$OUTPUT_DIR/dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"
ditto "$APP_BUNDLE" "$DMG_STAGING/Ottto.app"
ln -s /Applications "$DMG_STAGING/Applications"
hdiutil create -volname "Ottto" -srcfolder "$DMG_STAGING" -ov -format UDZO "$APP_DMG" >/dev/null
sign_container "$APP_DMG"
rm -rf "$DMG_STAGING"
CLI_ZIP="$OUTPUT_DIR/ottto-macos-$ARCH.zip"
DAEMON_ZIP="$OUTPUT_DIR/ottto-service-macos-$ARCH.zip"
ditto -c -k "$OUTPUT_DIR/ottto" "$CLI_ZIP"
ditto -c -k "$OUTPUT_DIR/ottto-service" "$DAEMON_ZIP"
SBOM_PATH="$OUTPUT_DIR/ottto-local-platform-sbom.cdx.json"
"$ROOT/scripts/cyclonedx_sbom.sh" --output "$SBOM_PATH" --version "$VERSION" >/dev/null

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

gatekeeper_assessment_type() {
  local kind="$1"
  if [[ "$kind" == "macos_app" ]]; then
    printf 'execute'
  else
    printf 'install'
  fi
}

gatekeeper_assessed() {
  local kind="$1"
  local target="$2"
  if [[ "$SIGNED" != "true" ]] || ! command -v spctl >/dev/null 2>&1; then
    printf 'false'
    return
  fi
  if spctl --assess --type "$(gatekeeper_assessment_type "$kind")" --verbose "$target" >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
APP_SHA="$(sha256_file "$APP_DMG")"
CLI_SHA="$(sha256_file "$CLI_ZIP")"
DAEMON_SHA="$(sha256_file "$DAEMON_ZIP")"
SBOM_SHA="$(sha256_file "$SBOM_PATH")"
APP_GATEKEEPER="$(gatekeeper_assessed macos_app "$APP_BUNDLE")"
CLI_GATEKEEPER="$(gatekeeper_assessed cli "$OUTPUT_DIR/ottto")"
DAEMON_GATEKEEPER="$(gatekeeper_assessed daemon "$OUTPUT_DIR/ottto-service")"

jq -n \
  --arg version "$VERSION" \
  --arg channel "$CHANNEL" \
  --arg commit "$COMMIT" \
  --arg generated_at "$GENERATED_AT" \
  --arg min_supported_version "$MIN_SUPPORTED_VERSION" \
  --argjson min_protocol_version "$MIN_PROTOCOL_VERSION" \
  --arg rollback_immutable_prefix "$ARTIFACT_BASE_URL" \
  --arg rollback_latest_manifest_url "$LATEST_MANIFEST_URL" \
  --arg arch "$ARCH" \
  --arg app_path "$APP_DMG" \
  --arg app_url "$ARTIFACT_BASE_URL/$(basename "$APP_DMG")" \
  --arg app_verification_path "$APP_BUNDLE" \
  --arg app_sha "$APP_SHA" \
  --arg cli_path "$OUTPUT_DIR/ottto" \
  --arg cli_zip "$CLI_ZIP" \
  --arg cli_url "$ARTIFACT_BASE_URL/$(basename "$CLI_ZIP")" \
  --arg cli_sha "$CLI_SHA" \
  --arg daemon_path "$OUTPUT_DIR/ottto-service" \
  --arg daemon_zip "$DAEMON_ZIP" \
  --arg daemon_url "$ARTIFACT_BASE_URL/$(basename "$DAEMON_ZIP")" \
  --arg daemon_sha "$DAEMON_SHA" \
  --arg sbom_path "$SBOM_PATH" \
  --arg sbom_url "$ARTIFACT_BASE_URL/$(basename "$SBOM_PATH")" \
  --arg sbom_sha "$SBOM_SHA" \
  --arg app_file "$(basename "$APP_DMG")" \
  --arg cli_file "$(basename "$CLI_ZIP")" \
  --arg daemon_file "$(basename "$DAEMON_ZIP")" \
  --arg sbom_file "$(basename "$SBOM_PATH")" \
  --arg manifest_file "release-manifest.json" \
  --arg installer_file "install-macos.sh" \
  --arg verified_installer_url "$ARTIFACT_BASE_URL/install-macos.sh" \
  --arg verified_installer_latest_url "$RELEASE_CHANNEL_URL_ROOT/latest/install-macos.sh" \
  --arg repository "${OTTTO_RELEASE_REPOSITORY:-ottto-ai/ottto}" \
  --arg signer_workflow "${OTTTO_RELEASE_SIGNER_WORKFLOW:-.github/workflows/macos-stable-release.yml}" \
  --arg launch_smoke_path "$LAUNCH_SMOKE_EVIDENCE" \
  --argjson supported_install_owners "$SUPPORTED_INSTALL_OWNERS_JSON" \
  --argjson signed "$SIGNED" \
  --argjson notarized "$NOTARIZED" \
  --argjson app_gatekeeper "$APP_GATEKEEPER" \
  --argjson cli_gatekeeper "$CLI_GATEKEEPER" \
  --argjson daemon_gatekeeper "$DAEMON_GATEKEEPER" \
  --slurpfile launch_smoke "$LAUNCH_SMOKE_EVIDENCE" \
  '{
    schema_version: 1,
    product: "ottto-local-platform",
    version: $version,
    channel: $channel,
    commit: $commit,
    generated_at: $generated_at,
    min_supported_version: $min_supported_version,
    min_protocol_version: $min_protocol_version,
    supported_install_owners: $supported_install_owners,
    install_methods: (if $channel == "stable" then {
      verified_native_installer: {
        kind: "verified_native_installer",
        path: $installer_file,
        url: $verified_installer_url,
        latest_url: $verified_installer_latest_url,
        runtime_install_owner: "app_bundle"
      }
    } else {} end),
    rollback: {
      strategy: "channel_latest_pointer",
      immutable_prefix: $rollback_immutable_prefix,
      latest_manifest_url: $rollback_latest_manifest_url,
      preserve_failed_version: true,
      operator_steps: [
        "Repoint the channel latest manifest to the last known good immutable versioned prefix.",
        "Invalidate the release CDN paths for the channel latest pointer.",
        "Run download, checksum, Gatekeeper, and installed smoke verification before announcing recovery."
      ],
      verification: {
        release_gate: "scripts/macos_release_gate.sh --manifest release-manifest.json",
        stable_preflight: "scripts/macos_stable_preflight.sh --manifest release-manifest.json",
        installed_smoke: "scripts/dev_e2e_smoke.sh or stable clean-machine smoke"
      }
    },
    supply_chain: {
      slsa_build: {
        spec_version: "1.2",
        level: "build_l1",
        predicate_type: "https://slsa.dev/provenance/v1",
        repository: $repository,
        signer_workflow: $signer_workflow,
        subjects: [$app_file, $cli_file, $daemon_file, $manifest_file, $sbom_file],
        attested: false,
        verified: false,
        verification_command: ("gh attestation verify " + $app_path + " -R " + $repository)
      },
      sbom: {
        format: "cyclonedx-json",
        spec_version: "1.7",
        predicate_type: "https://cyclonedx.org/bom",
        path: $sbom_path,
        url: $sbom_url,
        sha256: $sbom_sha,
        attested: false,
        verified: false,
        verification_command: ("gh attestation verify " + $app_path + " -R " + $repository + " --predicate-type https://cyclonedx.org/bom")
      }
    },
    quality_gates: ({
      packaged_app_launch: {
          status: $launch_smoke[0].status,
          checked_at: $launch_smoke[0].checked_at,
          wait_seconds: $launch_smoke[0].wait_seconds,
          bundle_id: $launch_smoke[0].bundle_id,
          bundle_version: $launch_smoke[0].bundle_version,
          bundle_short_version: $launch_smoke[0].bundle_short_version,
          executable_name: $launch_smoke[0].executable_name,
          process_survived_wait: $launch_smoke[0].process_survived_wait,
          crash_reports: $launch_smoke[0].crash_reports,
          evidence_path: $launch_smoke_path
        }
      } + (if $channel == "stable" then {
        stable_candidate_rc: {
          status: "not_run",
          evidence_path: "stable-candidate-rc-qa.json",
          candidate_manifest_sha256: "not_run"
        },
        stable_clean_machine_qa: {
          status: "not_run",
          evidence_path: "stable-clean-machine-qa.json",
          required_install_owners: $supported_install_owners
        }
      } else {} end)),
    artifacts: [
      {
        name: "Ottto.app",
        kind: "macos_app",
        platform: "macos",
        arch: $arch,
        path: $app_path,
        url: $app_url,
        verification_path: $app_verification_path,
        sha256: $app_sha,
        signed: $signed,
        notarized: $notarized,
        gatekeeper_assessed: $app_gatekeeper
      },
      {
        name: "ottto",
        kind: "cli",
        platform: "macos",
        arch: $arch,
        path: $cli_zip,
        url: $cli_url,
        verification_path: $cli_path,
        sha256: $cli_sha,
        signed: $signed,
        notarized: $notarized,
        gatekeeper_assessed: $cli_gatekeeper
      },
      {
        name: "ottto-service",
        kind: "daemon",
        platform: "macos",
        arch: $arch,
        path: $daemon_zip,
        url: $daemon_url,
        verification_path: $daemon_path,
        sha256: $daemon_sha,
        signed: $signed,
        notarized: $notarized,
        gatekeeper_assessed: $daemon_gatekeeper
      }
    ]
  }' > "$OUTPUT_DIR/release-manifest.json"

INSTALLER_SCRIPT="$OUTPUT_DIR/install-macos-dev.sh"
cat > "$INSTALLER_SCRIPT" <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${OTTTO_LOCAL_PLATFORM_RELEASE_URL:-__ARTIFACT_BASE_URL__}"
APP_DIR="${OTTTO_LOCAL_PLATFORM_APP_DIR:-$HOME/Applications}"
BIN_DIR="${OTTTO_LOCAL_PLATFORM_BIN_DIR:-$HOME/.ottto/bin}"
BOOTSTRAP_DAEMON="true"
OPEN_APP="true"
DRY_RUN="false"

usage() {
  cat <<'USAGE'
Usage: install-macos-dev.sh [options]

Installs Ottto on macOS (Apple Silicon).

Options:
  --base-url <url>   Release URL. Default: embedded release URL.
  --app-dir <path>   App install directory. Default: ~/Applications
  --bin-dir <path>   CLI/daemon install directory. Default: ~/.ottto/bin
  --no-bootstrap     Install files without bootstrapping ottto-service.
  --no-open          Install files without opening Ottto.
  --dry-run          Validate the manifest and exit.
  -h, --help         Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:?--base-url requires a value}"
      shift 2
      ;;
    --app-dir)
      APP_DIR="${2:?--app-dir requires a value}"
      shift 2
      ;;
    --bin-dir)
      BIN_DIR="${2:?--bin-dir requires a value}"
      shift 2
      ;;
    --no-bootstrap)
      BOOTSTRAP_DAEMON="false"
      shift
      ;;
    --no-open)
      OPEN_APP="false"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
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

if [[ -t 1 ]]; then
  C_GREEN=$'\033[32m'
  C_ORANGE=$'\033[38;5;208m'
  C_YELLOW=$'\033[33m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
else
  C_GREEN=""
  C_ORANGE=""
  C_YELLOW=""
  C_BOLD=""
  C_RESET=""
fi

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Ottto Companion installs are macOS-only." >&2
  exit 2
fi

ARCH="$(uname -m)"
if [[ "$ARCH" == "aarch64" ]]; then
  ARCH="arm64"
fi
if [[ "$ARCH" != "arm64" ]]; then
  echo "Ottto Companion currently supports Apple Silicon Macs only. Detected: $ARCH" >&2
  exit 2
fi

require_command curl
require_command ditto
require_command hdiutil
require_command install
require_command shasum
require_command awk
require_command python3

stop_running_companion() {
  /usr/bin/osascript -e 'tell application id "net.ottto.Companion" to quit' >/dev/null 2>&1 || true

  local process
  for process in Ottto OtttoCompanion; do
    if ! pgrep -x "$process" >/dev/null 2>&1; then
      continue
    fi
    for _ in $(seq 1 20); do
      if ! pgrep -x "$process" >/dev/null 2>&1; then
        break
      fi
      sleep 0.2
    done
    /usr/bin/pkill -x "$process" >/dev/null 2>&1 || true
  done
}

wait_for_daemon() {
  local cli="$1"
  for _ in $(seq 1 90); do
    if "$cli" --no-autostart status --json >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

cleanup_legacy_service() {
  local legacy_label="net.ottto.locald"
  local legacy_target="$BIN_DIR/ottto-locald"
  local legacy_plist="$HOME/Library/LaunchAgents/$legacy_label.plist"
  local legacy_domain
  legacy_domain="gui/$(id -u)/$legacy_label"

  if command -v launchctl >/dev/null 2>&1; then
    launchctl disable "$legacy_domain" >/dev/null 2>&1 || true
    launchctl bootout "$legacy_domain" >/dev/null 2>&1 || true
  fi
  /usr/bin/pkill -x ottto-locald >/dev/null 2>&1 || true
  rm -f "$legacy_target" "$legacy_plist"
}

copy_app_artifact() {
  local app_artifact="$1"
  local app_target="$2"
  local old_app_target="$3"
  local extract_dir="$tmp_dir/app"
  local mount_dir="$tmp_dir/app-dmg"

  rm -rf "$extract_dir" "$mount_dir"
  mkdir -p "$extract_dir"

  case "$app_artifact" in
    *.zip)
      ditto -x -k "$app_artifact" "$extract_dir" >/dev/null 2>&1
      if [[ ! -d "$extract_dir/Ottto.app" ]]; then
        echo "App archive did not contain Ottto.app" >&2
        exit 1
      fi
      stop_running_companion
      rm -rf "$app_target" "$old_app_target"
      ditto "$extract_dir/Ottto.app" "$app_target" >/dev/null 2>&1
      ;;
    *.dmg)
      mkdir -p "$mount_dir"
      hdiutil attach -nobrowse -readonly -mountpoint "$mount_dir" "$app_artifact" >/dev/null
      if [[ ! -d "$mount_dir/Ottto.app" ]]; then
        hdiutil detach "$mount_dir" >/dev/null 2>&1 || true
        echo "App disk image did not contain Ottto.app" >&2
        exit 1
      fi
      stop_running_companion
      rm -rf "$app_target" "$old_app_target"
      ditto "$mount_dir/Ottto.app" "$app_target" >/dev/null 2>&1
      hdiutil detach "$mount_dir" >/dev/null
      ;;
    *)
      echo "Unsupported app artifact format: $app_artifact" >&2
      exit 1
      ;;
  esac
}

BASE_URL="${BASE_URL%/}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

manifest_path="$tmp_dir/release-manifest.json"
artifact_plan="$tmp_dir/artifacts.tsv"
version_file="$tmp_dir/version"

printf '\nSetting up Ottto...\n\n'

curl -fsSL --retry 3 --connect-timeout 10 \
  "$BASE_URL/release-manifest.json" \
  -o "$manifest_path"

python3 - "$manifest_path" "$ARCH" "$version_file" > "$artifact_plan" <<'PY'
import json
import re
import sys
from pathlib import PurePosixPath
from urllib.parse import urlparse

manifest_path, expected_arch, version_path = sys.argv[1:4]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

if manifest.get("schema_version") != 1:
    raise SystemExit("Unsupported release manifest schema_version")
if manifest.get("product") != "ottto-local-platform":
    raise SystemExit("Unexpected release manifest product")
channel = manifest.get("channel")
if channel not in {"dev", "preview", "stable-candidate"}:
    raise SystemExit("This installer only accepts dev/preview/stable-candidate manifests")

with open(version_path, "w", encoding="utf-8") as out:
    out.write(str(manifest.get("version", "unknown")))

required = ("macos_app", "cli", "daemon")
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, list):
    raise SystemExit("Release manifest artifacts must be a list")

for kind in required:
    matches = [
        artifact
        for artifact in artifacts
        if artifact.get("kind") == kind
        and artifact.get("platform") == "macos"
        and artifact.get("arch") == expected_arch
    ]
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one {kind} artifact for {expected_arch}")
    artifact = matches[0]
    url = str(artifact.get("url") or "")
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise SystemExit(f"Artifact URL must be HTTPS or local HTTP: {kind}")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit(f"HTTP artifact URL is only allowed for localhost: {kind}")
    sha256 = str(artifact.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise SystemExit(f"Invalid SHA-256 for {kind}")
    filename = PurePosixPath(parsed.path).name
    if not filename or "/" in filename:
        raise SystemExit(f"Invalid artifact filename for {kind}")
    print(f"{kind}\t{url}\t{sha256.lower()}\t{filename}")
PY

VERSION="$(cat "$version_file")"
app_target="$APP_DIR/Ottto.app"
# Remove the pre-cutover bundle name during installs so Finder does not show two apps.
old_app_target="$APP_DIR/Ottto Companion.app"
cli_target="$BIN_DIR/ottto"
daemon_target="$BIN_DIR/ottto-service"

if [[ "$DRY_RUN" == "true" ]]; then
  exit 0
fi

app_zip=""
cli_zip=""
daemon_zip=""
while IFS=$'\t' read -r kind url expected_sha filename; do
  target="$tmp_dir/$filename"
  curl -fsSL --retry 3 --connect-timeout 10 "$url" -o "$target"
  actual_sha="$(shasum -a 256 "$target" | awk '{print $1}')"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "SHA-256 mismatch for $filename" >&2
    echo "  expected: $expected_sha" >&2
    echo "  actual:   $actual_sha" >&2
    exit 1
  fi
  case "$kind" in
    macos_app) app_zip="$target" ;;
    cli) cli_zip="$target" ;;
    daemon) daemon_zip="$target" ;;
  esac
done < "$artifact_plan"

if [[ -z "$app_zip" || -z "$cli_zip" || -z "$daemon_zip" ]]; then
  echo "Release manifest did not include all required macOS artifacts." >&2
  exit 1
fi

mkdir -p "$APP_DIR" "$BIN_DIR"

cleanup_legacy_service
copy_app_artifact "$app_zip" "$app_target" "$old_app_target"

ditto -x -k "$cli_zip" "$tmp_dir/cli" >/dev/null 2>&1
ditto -x -k "$daemon_zip" "$tmp_dir/daemon" >/dev/null 2>&1
if [[ ! -x "$tmp_dir/cli/ottto" ]]; then
  echo "CLI archive did not contain executable ottto" >&2
  exit 1
fi
if [[ ! -x "$tmp_dir/daemon/ottto-service" ]]; then
  echo "Daemon archive did not contain executable ottto-service" >&2
  exit 1
fi
install -m 0755 "$tmp_dir/cli/ottto" "$cli_target"
install -m 0755 "$tmp_dir/daemon/ottto-service" "$daemon_target"

if command -v xattr >/dev/null 2>&1; then
  xattr -dr com.apple.quarantine "$app_target" "$cli_target" "$daemon_target" 2>/dev/null || true
fi

SETUP_NOTES=()

if [[ "$BOOTSTRAP_DAEMON" == "true" ]]; then
  if ! "$daemon_target" service bootstrap --executable "$daemon_target" --json >/dev/null 2>&1; then
    SETUP_NOTES+=("ottto-service LaunchAgent bootstrap failed. Open Ottto to retry.")
  elif ! wait_for_daemon "$cli_target"; then
    "$daemon_target" service bootstrap --executable "$daemon_target" --json >/dev/null 2>&1 || true
    if ! wait_for_daemon "$cli_target"; then
      SETUP_NOTES+=("ottto-service did not become ready. Open Ottto to retry.")
    fi
  fi
fi

if [[ "$OPEN_APP" == "true" ]]; then
  open "$app_target"
fi

display_app="${app_target/#$HOME/~}"
display_bin="${BIN_DIR/#$HOME/~}"

bin_suffix="${BIN_DIR#$HOME/}"
if [[ "$bin_suffix" != "$BIN_DIR" ]]; then
  bin_cmd_path="\$HOME/$bin_suffix"
else
  bin_cmd_path="$BIN_DIR"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    SETUP_NOTES+=("PATH|$display_bin is not in your PATH. Run:|echo 'export PATH=\"$bin_cmd_path:\$PATH\"' >> ~/.zshrc && source ~/.zshrc")
    ;;
esac

printf '%s✔ Ottto successfully installed!%s\n\n' "$C_GREEN" "$C_RESET"
printf '  Version: %s%s%s\n\n' "$C_ORANGE" "$VERSION" "$C_RESET"
printf '  Location: %s%s%s\n\n\n' "$C_ORANGE" "$display_app" "$C_RESET"
printf '  Next: Open Ottto or run %sottto --help%s\n\n' "$C_ORANGE" "$C_RESET"

if [[ ${#SETUP_NOTES[@]} -gt 0 ]]; then
  printf '%s%s⚠ Setup notes:%s\n' "$C_YELLOW" "$C_BOLD" "$C_RESET"
  for note in "${SETUP_NOTES[@]}"; do
    if [[ "$note" == PATH\|* ]]; then
      rest="${note#PATH|}"
      label="${rest%%|*}"
      command_part="${rest#*|}"
      printf '  %s●%s %s\n\n' "$C_ORANGE" "$C_RESET" "$label"
      printf '    %s\n' "$command_part"
    else
      printf '  %s●%s %s\n' "$C_ORANGE" "$C_RESET" "$note"
    fi
  done
  printf '\n\n'
fi

printf '%s✅ Installation complete!%s\n' "$C_GREEN" "$C_RESET"
INSTALLER

escaped_base_url="${ARTIFACT_BASE_URL//\\/\\\\}"
escaped_base_url="${escaped_base_url//&/\\&}"
sed -i.bak "s|__ARTIFACT_BASE_URL__|$escaped_base_url|g" "$INSTALLER_SCRIPT"
rm -f "$INSTALLER_SCRIPT.bak"
chmod 0755 "$INSTALLER_SCRIPT"

echo "Wrote $OUTPUT_DIR/release-manifest.json"
echo "Wrote $INSTALLER_SCRIPT"
