#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/macos_sparkle_bundle_version.sh
source "$SCRIPT_DIR/macos_sparkle_bundle_version.sh"
# shellcheck source=scripts/macos_bundle_url_scheme.sh
source "$SCRIPT_DIR/macos_bundle_url_scheme.sh"
# shellcheck source=scripts/macos_companion_entitlements.sh
source "$SCRIPT_DIR/macos_companion_entitlements.sh"
# shellcheck source=scripts/macos_license_notices.sh
source "$SCRIPT_DIR/macos_license_notices.sh"
# shellcheck source=scripts/macos_release_archive.sh
source "$SCRIPT_DIR/macos_release_archive.sh"
# shellcheck source=scripts/macos_app_binary.sh
source "$SCRIPT_DIR/macos_app_binary.sh"
ROOT="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
MAC_APP_ROOT=""
MAC_APP_SOURCE_PIN=""

VERSION="0.1.0-dev"
CHANNEL="dev"
OUTPUT_DIR="$ROOT/dist/macos"
SIGN_IDENTITY="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"
NOTARIZED="false"
SKIP_BUILD="false"
PACKAGE_STAGE="all"
PRIVACY_STATE=""
ARTIFACT_BASE_URL=""
MIN_SUPPORTED_VERSION="${OTTTO_MIN_SUPPORTED_VERSION:-0.1.0}"
RELEASE_NOTES="${OTTTO_RELEASE_NOTES:-}"

usage() {
  cat <<'USAGE'
Usage: macos_package.sh [options]

Options:
  --app-root <path>          Required. The app's Swift package root: a tracked,
                             clean subdirectory of its Git checkout.
  --app-source-commit <sha>  40-hex commit the app checkout must be at.
                             Required for stable-candidate and stable;
                             dev and preview default to the checkout HEAD.
  --version <version>        Release version. Default: 0.1.0-dev
  --channel <channel>        dev, preview, stable-candidate, or stable. Default: dev
  --output-dir <path>        Output directory. Default: tools/ottto-local-platform/dist/macos
  --sign-identity <identity> Developer ID signing identity.
  --artifact-base-url <url>  Public URL prefix for generated artifacts.
  --release-notes <text>     User-facing "What's new" notes for release manifests.
  --notarized               Mark artifacts notarized after external notarization.
  --skip-build              Reuse existing release build outputs (dev and
                             preview only).
  --stage <stage>           all (default), prepare or finish; stable channels
                             only for prepare and finish. prepare stops before
                             signing and makes the unsigned app and binaries
                             immutable for the release privacy gate; finish
                             signs exactly those files.
  --privacy-state <folder>  With --stage finish: the privacy gate's state
                             folder. Its clean unsigned record must match the
                             prepared files.
  -h, --help                Show help.

Environment:
  OTTTO_MACOS_DSYM_DIR       Private folder for the Companion dSYM and the
                             build tool logs. Required for stable-candidate and
                             stable; never printed or uploaded.

The release manifest records the app source as private_source material: its
commit and tree, with no repository name or path. The caller proves that the
checkout is the canonical app source before packaging.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-root)
      MAC_APP_ROOT="${2:?--app-root requires a value}"
      shift 2
      ;;
    --app-source-commit)
      MAC_APP_SOURCE_PIN="${2:?--app-source-commit requires a value}"
      shift 2
      ;;
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
    --release-notes)
      RELEASE_NOTES="${2:?--release-notes requires a value}"
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
    --stage)
      PACKAGE_STAGE="${2:?--stage requires a value}"
      shift 2
      ;;
    --privacy-state)
      PRIVACY_STATE="${2:?--privacy-state requires a value}"
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

case "$CHANNEL" in
  dev|preview|stable-candidate|stable) ;;
  *)
    echo "--channel must be dev, preview, stable-candidate, or stable" >&2
    exit 2
    ;;
esac
case "$PACKAGE_STAGE" in
  all) ;;
  prepare|finish)
    if [[ "$CHANNEL" != "stable-candidate" && "$CHANNEL" != "stable" ]]; then
      echo "--stage prepare and finish are for stable-candidate and stable channels" >&2
      exit 2
    fi
    ;;
  *)
    echo "--stage must be all, prepare, or finish" >&2
    exit 2
    ;;
esac
if [[ "$PACKAGE_STAGE" == "finish" && -z "$PRIVACY_STATE" ]]; then
  echo "--stage finish requires --privacy-state" >&2
  exit 2
fi
if [[ -z "$MAC_APP_ROOT" ]]; then
  echo "--app-root is required: pass the app's Swift package root" >&2
  exit 2
fi
if [[ -n "$MAC_APP_SOURCE_PIN" && ! "$MAC_APP_SOURCE_PIN" =~ ^[0-9a-f]{40}$ ]]; then
  echo "--app-source-commit must be a 40-hex app source commit" >&2
  exit 2
fi
if [[ ( "$CHANNEL" == "stable-candidate" || "$CHANNEL" == "stable" ) && -z "$MAC_APP_SOURCE_PIN" ]]; then
  echo "--app-source-commit is required for stable-candidate and stable channels" >&2
  exit 2
fi


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
require_command install_name_tool
require_command otool

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
  echo "Pass --app-root the Ottto Swift package root." >&2
  exit 2
fi
if [[ ! -f "$MAC_APP_ROOT/Package.swift" ]]; then
  echo "macOS app root is missing Package.swift: $MAC_APP_ROOT" >&2
  exit 2
fi
if [[ "$CHANNEL" == "stable-candidate" || "$CHANNEL" == "stable" ]]; then
  if ! grep -q '[^[:space:]]' <<<"$RELEASE_NOTES"; then
    echo "--release-notes or OTTTO_RELEASE_NOTES is required for stable release channels" >&2
    exit 2
  fi
fi

if ! git -C "$ROOT" diff --quiet HEAD -- .; then
  echo "Public release source has tracked changes; freeze a clean public commit before packaging" >&2
  exit 2
fi
if [[ -n "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]]; then
  echo "Public release source has untracked files; freeze a clean public commit before packaging" >&2
  exit 2
fi
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
COMMIT="${SOURCE_COMMIT:0:12}"
MAC_APP_GIT_ROOT="$(git -C "$MAC_APP_ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$MAC_APP_GIT_ROOT" ]]; then
  echo "macOS app root must belong to the private Git checkout: $MAC_APP_ROOT" >&2
  exit 2
fi
MAC_APP_GIT_ROOT="$(cd "$MAC_APP_GIT_ROOT" && pwd -P)"
MAC_APP_ROOT="$(cd "$MAC_APP_ROOT" && pwd -P)"
case "$MAC_APP_ROOT/" in
  "$MAC_APP_GIT_ROOT/"*)
    MAC_APP_SOURCE_PATH="${MAC_APP_ROOT#"$MAC_APP_GIT_ROOT"/}"
    ;;
  *)
    echo "macOS app root is outside its Git checkout" >&2
    exit 2
    ;;
esac
if [[ "$MAC_APP_ROOT" == "$MAC_APP_GIT_ROOT" || -z "$MAC_APP_SOURCE_PATH" ]]; then
  echo "macOS app root must be a subdirectory of its Git checkout, not the checkout root" >&2
  exit 2
fi
# The caller validates source ownership before handing off the app checkout.
if ! git -C "$MAC_APP_GIT_ROOT" diff --quiet HEAD -- "$MAC_APP_SOURCE_PATH"; then
  echo "macOS app source subtree has tracked changes; freeze a clean private commit before packaging" >&2
  exit 2
fi
if [[ -n "$(git -C "$MAC_APP_GIT_ROOT" ls-files --others --exclude-standard -- "$MAC_APP_SOURCE_PATH")" ]]; then
  echo "macOS app source subtree has untracked files; freeze a clean private commit before packaging" >&2
  exit 2
fi
MAC_APP_SOURCE_COMMIT="$(git -C "$MAC_APP_GIT_ROOT" rev-parse HEAD)"
# Stable channels pin the app source commit (the release workflow takes it
# from the release tag); dev and preview builds default to the checkout HEAD.
MAC_APP_SOURCE_PIN="${MAC_APP_SOURCE_PIN:-$MAC_APP_SOURCE_COMMIT}"
if [[ "$MAC_APP_SOURCE_COMMIT" != "$MAC_APP_SOURCE_PIN" ]]; then
  echo "macOS app source checkout is at $MAC_APP_SOURCE_COMMIT, not --app-source-commit $MAC_APP_SOURCE_PIN" >&2
  exit 2
fi
MAC_APP_SOURCE_TREE="$(git -C "$MAC_APP_GIT_ROOT" rev-parse --verify --quiet "$MAC_APP_SOURCE_COMMIT:$MAC_APP_SOURCE_PATH" || true)"
if [[ ! "$MAC_APP_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] || \
  [[ "$(git -C "$MAC_APP_GIT_ROOT" cat-file -t "$MAC_APP_SOURCE_TREE" 2>/dev/null || true)" != "tree" ]]; then
  echo "macOS app root must be a tracked directory at the app source commit" >&2
  exit 2
fi
COMPANION_ENTITLEMENTS="$MAC_APP_ROOT/Companion.entitlements.plist"
# Bind the signed plist to the verified private commit, not the index.
COMPANION_ENTITLEMENTS_BLOB="$(git -C "$MAC_APP_GIT_ROOT" rev-parse --verify --quiet "HEAD:$MAC_APP_SOURCE_PATH/Companion.entitlements.plist" || true)"
if [[ -z "$COMPANION_ENTITLEMENTS_BLOB" || ! -f "$COMPANION_ENTITLEMENTS" ]] || \
  [[ "$(git -C "$MAC_APP_GIT_ROOT" hash-object -- "$COMPANION_ENTITLEMENTS")" != "$COMPANION_ENTITLEMENTS_BLOB" ]]; then
  echo "Companion entitlements plist must match the private app source commit" >&2
  exit 2
fi
if ! ottto_macos_check_companion_entitlements "$COMPANION_ENTITLEMENTS"; then
  exit 2
fi
BUNDLE_VERSION="$(ottto_sparkle_bundle_version "$VERSION")"
MIN_PROTOCOL_VERSION="${OTTTO_MIN_PROTOCOL_VERSION:-$(sed -n 's/.*PROTOCOL_VERSION: u16 = \([0-9][0-9]*\).*/\1/p' "$ROOT/crates/ottto-protocol/src/lib.rs" | head -n1)}"
if [[ -z "$MIN_PROTOCOL_VERSION" ]]; then
  echo "Could not determine local protocol version" >&2
  exit 1
fi

if ! ottto_macos_check_binary_policy "$CHANNEL" "$SKIP_BUILD" "$ROOT" "$OUTPUT_DIR" "$MAC_APP_GIT_ROOT"; then
  exit 2
fi
SWIFT_SCRATCH_PATH="$(ottto_macos_swift_scratch "$CHANNEL" "$MAC_APP_ROOT")"
ottto_macos_package_cleanup() {
  if ottto_macos_is_stable_channel "$CHANNEL"; then
    rm -rf "$SWIFT_SCRATCH_PATH"
  fi
  if [[ -n "$OTTTO_MACOS_DSYM_INCOMING" ]]; then
    rm -rf "$OTTTO_MACOS_DSYM_INCOMING"
  fi
}
trap ottto_macos_package_cleanup EXIT
# Debug-map object paths are recorded relative to this folder; dsymutil
# prepends it again to find the objects.
if ottto_macos_path_within "$SWIFT_SCRATCH_PATH" "$MAC_APP_GIT_ROOT"; then
  SWIFT_OSO_PREFIX="$MAC_APP_GIT_ROOT"
  SWIFT_SCRATCH_MAP=()
else
  SWIFT_OSO_PREFIX="$SWIFT_SCRATCH_PATH"
  SWIFT_SCRATCH_MAP=(-Xswiftc -file-prefix-map -Xswiftc "$SWIFT_SCRATCH_PATH=.build")
fi

if [[ "$SKIP_BUILD" != "true" && "$PACKAGE_STAGE" != "finish" ]]; then
  # Compilers record source paths (panic locations, debug maps). Map the build
  # Mac's folders to neutral prefixes so shipped binaries do not carry them.
  (
    cd "$ROOT"
    ottto_macos_release_build_env "$ROOT"
    OTTTO_RELEASE_VERSION="$VERSION" \
      OTTTO_RELEASE_CHANNEL="$CHANNEL" \
      GIT_COMMIT="$COMMIT" \
      ottto_macos_run_logged "Rust release build" \
      cargo build --locked --release -p ottto-cli -p ottto-service
  )
  # --disable-automatic-resolution builds exactly the committed Package.resolved.
  ottto_macos_run_logged "Swift release build" \
    swift build -c release --package-path "$MAC_APP_ROOT" \
    --scratch-path "$SWIFT_SCRATCH_PATH" \
    --disable-automatic-resolution \
    -Xswiftc -file-prefix-map -Xswiftc "$MAC_APP_GIT_ROOT=." \
    ${SWIFT_SCRATCH_MAP[@]+"${SWIFT_SCRATCH_MAP[@]}"} \
    -Xlinker -oso_prefix -Xlinker "$SWIFT_OSO_PREFIX/"
fi

APP_BUNDLE="$OUTPUT_DIR/Ottto.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_FRAMEWORKS="$APP_CONTENTS/Frameworks"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"
# Unsigned assembly. --stage finish skips it and signs the files --stage
# prepare left behind (see "end of the unsigned assembly" below).
if [[ "$PACKAGE_STAGE" != "finish" ]]; then
SWIFT_BUILD_DIR="$SWIFT_SCRATCH_PATH/release"
APP_EXECUTABLE="$SWIFT_BUILD_DIR/Ottto"
CLI_BINARY="$ROOT/target/release/ottto"
DAEMON_BINARY="$ROOT/target/release/ottto-service"

for binary in "$APP_EXECUTABLE" "$CLI_BINARY" "$DAEMON_BINARY"; do
  if [[ ! -x "$binary" ]]; then
    echo "Expected executable is missing: $(basename "$binary")" >&2
    exit 1
  fi
done

# Report (never fail on) build-Mac home paths left in the shipped executables.
# The privacy gate enforces; this is an early hint in the job log.
for binary in "$APP_EXECUTABLE" "$CLI_BINARY" "$DAEMON_BINARY"; do
  [[ -n "${HOME:-}" ]] || break
  home_paths="$(LC_ALL=C /usr/bin/grep -a -c -F "$HOME/" "$binary" || true)"
  if [[ "${home_paths:-0}" != "0" ]]; then
    echo "::warning::$(basename "$binary") still contains $home_paths build-Mac home path string(s)"
  fi
done
if [[ -d "$SWIFT_BUILD_DIR/OtttoCompanion_OtttoCompanion.bundle" ]]; then
  echo "::warning::The app source still declares SwiftPM resources; its Bundle.module accessor stores the build folder in the binary"
fi

# Sparkle.framework powers the seamless in-app updater. SwiftPM copies it next
# to the built executable; fall back to the extracted XCFramework slice.
SPARKLE_FRAMEWORK="$SWIFT_BUILD_DIR/Sparkle.framework"
if [[ ! -d "$SPARKLE_FRAMEWORK" ]]; then
  SPARKLE_FRAMEWORK="$(find "$SWIFT_SCRATCH_PATH" -type d -path '*macos-arm64*/Sparkle.framework' -print -quit 2>/dev/null || true)"
fi
if [[ ! -d "$SPARKLE_FRAMEWORK" ]]; then
  echo "Sparkle.framework not found in the Swift build folder (did 'swift build' resolve Sparkle?)" >&2
  exit 1
fi

# A cancelled prepared run leaves immutable files behind.
if [[ -e "$OUTPUT_DIR" ]]; then
  chflags -R nouchg "$OUTPUT_DIR" 2>/dev/null || true
fi
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

mkdir -p "$APP_MACOS" "$APP_HELPERS" "$APP_RESOURCES" "$APP_FRAMEWORKS" "$APP_LAUNCH_AGENTS"
cp "$APP_EXECUTABLE" "$APP_MACOS/Ottto"
# The dSYM reads the unstripped build output while its objects still exist;
# the bundle copy loses its debug map and local symbols before signing.
if [[ "$SKIP_BUILD" != "true" ]]; then
  ottto_macos_make_dsym "$APP_EXECUTABLE" "$SWIFT_OSO_PREFIX"
fi
ottto_macos_strip_companion "$APP_MACOS/Ottto"
# Embed Sparkle.framework (ditto preserves the Versions/Current symlinks). The
# app links Sparkle, so the bundle will not launch without this.
ditto "$SPARKLE_FRAMEWORK" "$APP_FRAMEWORKS/Sparkle.framework"
cp "$CLI_BINARY" "$APP_HELPERS/ottto"
cp "$DAEMON_BINARY" "$APP_HELPERS/ottto-service"
# Ship the listed Resources of the recorded app commit (never its README).
# Inside Ottto.app the app finds them through Bundle.main.
ottto_macos_copy_companion_resources "$MAC_APP_GIT_ROOT" "$MAC_APP_SOURCE_COMMIT" "$MAC_APP_SOURCE_PATH" "$APP_RESOURCES"
# License notices go into Resources before the app is signed. The Sparkle pin
# comes from the verified app commit and must match the vendored license.
sparkle_pin="$(ottto_macos_sparkle_pin "$MAC_APP_GIT_ROOT" "$MAC_APP_SOURCE_COMMIT" "$MAC_APP_SOURCE_PATH")" || exit 2
sparkle_version="$(jq -r '.version' <<< "$sparkle_pin")"
sparkle_revision="$(jq -r '.revision' <<< "$sparkle_pin")"
ottto_check_sparkle_license_pin "$sparkle_version" "$sparkle_revision" "$APP_FRAMEWORKS/Sparkle.framework" || exit 2
ottto_copy_app_license_notices "$ROOT" "$APP_RESOURCES"
cp "$CLI_BINARY" "$OUTPUT_DIR/ottto"
cp "$DAEMON_BINARY" "$OUTPUT_DIR/ottto-service"

# Sparkle feed keys ship whenever the EdDSA public key is configured. The public
# key is baked as a default below (it is public; the matching private key lives
# only in the signing Mac's login Keychain), so signed releases emit the updater
# feed keys automatically. Override OTTTO_SPARKLE_PUBLIC_ED_KEY to rotate it.
: "${OTTTO_SPARKLE_PUBLIC_ED_KEY:=7+mQTEYSADfrrzjx3bpVlVUlZNo/UHDEPSSFV85jtYE=}"
SPARKLE_INFO_PLIST_KEYS=""
if [[ -n "${OTTTO_SPARKLE_PUBLIC_ED_KEY:-}" ]]; then
  SPARKLE_FEED_URL="${OTTTO_SPARKLE_FEED_URL:-$RELEASE_CHANNEL_URL_ROOT/latest/appcast.xml}"
  SPARKLE_INFO_PLIST_KEYS=$(cat <<SPARKLEKEYS
  <key>SUFeedURL</key>
  <string>${SPARKLE_FEED_URL}</string>
  <key>SUPublicEDKey</key>
  <string>${OTTTO_SPARKLE_PUBLIC_ED_KEY}</string>
  <key>SUEnableAutomaticChecks</key>
  <true/>
SPARKLEKEYS
)
fi

# Only the stable app may own the production deep-link scheme. Candidate,
# preview, and developer bundles remain launchable directly and complete
# browser claims through daemon polling or the CLI fallback without leaving a
# stale ottto:// handler behind on QA and release-runner machines.
OTTTO_URL_TYPES_PLIST="$(ottto_macos_url_types_plist "$CHANNEL")"

# Do not declare LSMultipleInstancesProhibited. Launch Services applies it
# across user sessions, so a second macOS user could not open Ottto while
# another user had it open. The app enforces one process per user itself, and
# its service, socket and support files are per user.
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
  <string>${BUNDLE_VERSION}</string>
${OTTTO_URL_TYPES_PLIST}
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSAppleEventsUsageDescription</key>
  <string>${OTTTO_MACOS_APPLE_EVENTS_USAGE}</string>
${SPARKLE_INFO_PLIST_KEYS}
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
  <key>EnvironmentVariables</key>
  <dict>
    <key>MallocLargeCache</key>
    <string>0</string>
    <key>MallocSpaceEfficient</key>
    <string>1</string>
  </dict>
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

# Keep a disabled descriptor for the retired plist name so a current app-bundle
# helper can resolve the old same-parent SMAppService and unregister it. This
# plist is never registered by current code.
cat > "$APP_LAUNCH_AGENTS/net.ottto.locald.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>net.ottto.locald</string>
  <key>BundleProgram</key>
  <string>Contents/Helpers/ottto-service</string>
  <key>ProgramArguments</key>
  <array>
    <string>ottto-service</string>
    <string>status</string>
    <string>--json</string>
  </array>
  <key>Disabled</key>
  <true/>
</dict>
</plist>
PLIST

plutil -lint "$APP_LAUNCH_AGENTS/net.ottto.locald.plist" >/dev/null
fi # end of the unsigned assembly

SIGNED="false"
if [[ -n "$SIGN_IDENTITY" ]]; then
  sign_code() {
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$1"
  }
  sign_companion() {
    codesign --force --options runtime --timestamp --entitlements "$COMPANION_ENTITLEMENTS" --sign "$SIGN_IDENTITY" "$1"
  }
  sign_container() {
    codesign --force --timestamp --sign "$SIGN_IDENTITY" "$1"
  }
  SIGNED="true"
else
  sign_code() {
    codesign --force --sign - "$1"
  }
  sign_companion() {
    codesign --force --entitlements "$COMPANION_ENTITLEMENTS" --sign - "$1"
  }
  sign_container() {
    codesign --force --sign - "$1"
  }
fi

# Sign Sparkle's nested code inside-out (XPC services, Autoupdate, Updater.app),
# then the framework. Never use --deep (it corrupts the XPC service signatures).
sign_sparkle() {
  local fw="$1"
  local v="$fw/Versions/B"
  if [[ -n "$SIGN_IDENTITY" ]]; then
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$v/XPCServices/Installer.xpc"
    codesign --force --options runtime --timestamp --preserve-metadata=entitlements --sign "$SIGN_IDENTITY" "$v/XPCServices/Downloader.xpc"
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$v/Autoupdate"
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$v/Updater.app"
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$fw"
  else
    local target
    for target in \
      "$v/XPCServices/Installer.xpc" \
      "$v/XPCServices/Downloader.xpc" \
      "$v/Autoupdate" \
      "$v/Updater.app" \
      "$fw"; do
      codesign --force --sign - "$target"
    done
  fi
}

# Add the runpath so the embedded Sparkle.framework resolves at launch. Must run
# before the main executable is signed (a later install_name_tool voids it).
if [[ "$PACKAGE_STAGE" != "finish" ]] && ! otool -l "$APP_MACOS/Ottto" | grep -q "@executable_path/../Frameworks"; then
  install_name_tool -add_rpath "@executable_path/../Frameworks" "$APP_MACOS/Ottto"
fi

# --stage finish: the prepared files must still be the ones the privacy gate
# found clean. Only then are they made writable again for signing.
if [[ "$PACKAGE_STAGE" == "finish" ]]; then
  sparkle_pin="$(ottto_macos_sparkle_pin "$MAC_APP_GIT_ROOT" "$MAC_APP_SOURCE_COMMIT" "$MAC_APP_SOURCE_PATH")" || exit 2
  sparkle_version="$(jq -r '.version' <<< "$sparkle_pin")"
  sparkle_revision="$(jq -r '.revision' <<< "$sparkle_pin")"
  ottto_check_sparkle_license_pin "$sparkle_version" "$sparkle_revision" "$APP_FRAMEWORKS/Sparkle.framework" || exit 2
  if ! python3 -I "$ROOT/scripts/macos_privacy_gate.py" check-record --state "$PRIVACY_STATE" --root "$OUTPUT_DIR"; then
    echo "The prepared files are not the ones the privacy gate checked" >&2
    exit 1
  fi
  chflags -R nouchg "$APP_BUNDLE" "$OUTPUT_DIR/ottto" "$OUTPUT_DIR/ottto-service"
fi

# Resources are final before signing: the listed Companion files and the
# license files.
ottto_macos_check_app_resources "$APP_RESOURCES"
if [[ "$PACKAGE_STAGE" == "prepare" ]]; then
  # The dSYM UUID does not change when the app is signed.
  ottto_macos_keep_dsym "$APP_MACOS/Ottto" "$VERSION"
  chflags -R uchg "$APP_BUNDLE" "$OUTPUT_DIR/ottto" "$OUTPUT_DIR/ottto-service"
  echo "Prepared the unsigned app and binaries; sign them with --stage finish after the privacy gate"
  exit 0
fi
sign_code "$APP_HELPERS/ottto"
sign_code "$APP_HELPERS/ottto-service"
sign_companion "$APP_MACOS/Ottto"
sign_code "$OUTPUT_DIR/ottto"
sign_code "$OUTPUT_DIR/ottto-service"
sign_sparkle "$APP_FRAMEWORKS/Sparkle.framework"
sign_companion "$APP_BUNDLE"
expected_companion_entitlements="[\"$OTTTO_MACOS_COMPANION_ENTITLEMENT_KEY\"]"
if [[ "$(ottto_macos_signed_entitlement_keys "$APP_BUNDLE")" != "$expected_companion_entitlements" ]]; then
  echo "Signed Ottto.app must carry only the Companion Apple Events entitlement" >&2
  exit 1
fi
for helper in "$APP_HELPERS/ottto" "$APP_HELPERS/ottto-service" "$OUTPUT_DIR/ottto" "$OUTPUT_DIR/ottto-service"; do
  if [[ "$(ottto_macos_signed_entitlement_keys "$helper")" != "[]" ]]; then
    echo "Bundled helpers must not carry entitlements: $helper" >&2
    exit 1
  fi
done
ottto_macos_check_no_stabs "$APP_MACOS/Ottto"
ottto_macos_keep_dsym "$APP_MACOS/Ottto" "$VERSION"
if [[ "$PACKAGE_STAGE" == "finish" && -n "${OTTTO_MACOS_DSYM_DIR:-}" ]]; then
  app_uuid="$(ottto_macos_dsym_uuid "$APP_MACOS/Ottto")" || app_uuid=""
  if [[ -z "$app_uuid" || ! -d "$OTTTO_MACOS_DSYM_DIR/Ottto-$VERSION-$app_uuid.dSYM" ]]; then
    echo "The Companion dSYM kept by --stage prepare does not match the signed app" >&2
    exit 1
  fi
fi

LAUNCH_SMOKE_EVIDENCE="$OUTPUT_DIR/packaged-app-launch-smoke.json"
"$ROOT/scripts/macos_launch_smoke.sh" \
  --app "$APP_BUNDLE" \
  --manifest-dir "$OUTPUT_DIR" \
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
# Each zip holds its executable plus the license notices at the zip root. The
# staging folders live outside the release output folder, so a failed run
# cannot leave them where release files are collected.
(
  ZIP_STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ottto-zip-stage.XXXXXX")"
  trap 'rm -rf "$ZIP_STAGE_ROOT"' EXIT
  ottto_stage_license_archive "$ROOT" "$OUTPUT_DIR/ottto" "$ZIP_STAGE_ROOT/cli"
  ottto_stage_license_archive "$ROOT" "$OUTPUT_DIR/ottto-service" "$ZIP_STAGE_ROOT/daemon"
  ottto_release_zip "$ZIP_STAGE_ROOT/cli" "$CLI_ZIP"
  ottto_release_zip "$ZIP_STAGE_ROOT/daemon" "$DAEMON_ZIP"
)
SBOM_PATH="$OUTPUT_DIR/ottto-local-platform-sbom.cdx.json"
# The SBOM describes the Apple Silicon build and the validated Sparkle pin.
if [[ "$ARCH" != "arm64" ]]; then
  echo "The macOS release SBOM requires Apple Silicon artifacts" >&2
  exit 2
fi
"$ROOT/scripts/cyclonedx_sbom.sh" --output "$SBOM_PATH" --version "$VERSION" \
  --sparkle-version "$sparkle_version" --sparkle-revision "$sparkle_revision" >/dev/null

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
  --arg source_commit "$SOURCE_COMMIT" \
  --arg mac_app_source_commit "$MAC_APP_SOURCE_COMMIT" \
  --arg mac_app_source_tree "$MAC_APP_SOURCE_TREE" \
  --arg generated_at "$GENERATED_AT" \
  --arg release_notes "$RELEASE_NOTES" \
  --arg min_supported_version "$MIN_SUPPORTED_VERSION" \
  --argjson min_protocol_version "$MIN_PROTOCOL_VERSION" \
  --arg rollback_immutable_prefix "$ARTIFACT_BASE_URL" \
  --arg rollback_latest_manifest_url "$LATEST_MANIFEST_URL" \
  --arg arch "$ARCH" \
  --arg app_url "$ARTIFACT_BASE_URL/$(basename "$APP_DMG")" \
  --arg app_verification_path "$(basename "$APP_BUNDLE")" \
  --arg app_sha "$APP_SHA" \
  --arg cli_path "ottto" \
  --arg cli_url "$ARTIFACT_BASE_URL/$(basename "$CLI_ZIP")" \
  --arg cli_sha "$CLI_SHA" \
  --arg daemon_path "ottto-service" \
  --arg daemon_url "$ARTIFACT_BASE_URL/$(basename "$DAEMON_ZIP")" \
  --arg daemon_sha "$DAEMON_SHA" \
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
  --arg launch_smoke_path "$(basename "$LAUNCH_SMOKE_EVIDENCE")" \
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
    release_notes: (if ($release_notes | gsub("[[:space:]]"; "") | length) > 0 then $release_notes else null end),
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
      materials: [
        {
          kind: "git_repository",
          repository: $repository,
          commit: $source_commit
        },
        {
          kind: "private_source",
          name: "ottto-macos-app",
          visibility: "private",
          commit: $mac_app_source_commit,
          tree: $mac_app_source_tree,
          clean: true
        }
      ],
      slsa_build: {
        spec_version: "1.2",
        level: "build_l1",
        predicate_type: "https://slsa.dev/provenance/v1",
        repository: $repository,
        signer_workflow: $signer_workflow,
        subjects: [$app_file, $cli_file, $daemon_file, $manifest_file, $sbom_file],
        attested: false,
        verified: false,
        verification_command: ("gh attestation verify ./" + $app_file + " -R " + $repository)
      },
      sbom: {
        format: "cyclonedx-json",
        spec_version: "1.7",
        predicate_type: "https://cyclonedx.org/bom",
        path: $sbom_file,
        url: $sbom_url,
        sha256: $sbom_sha,
        attested: false,
        verified: false,
        verification_command: ("gh attestation verify ./" + $app_file + " -R " + $repository + " --predicate-type https://cyclonedx.org/bom")
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
        path: $app_file,
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
        path: $cli_file,
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
        path: $daemon_file,
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

deregister_legacy_smappservice() {
  local app_daemon="$app_target/Contents/Helpers/ottto-service"
  if [[ ! -x "$app_daemon" ]]; then
    return 0
  fi
  if ! "$app_daemon" service cleanup-legacy --json >/dev/null; then
    echo "Warning: could not de-register the retired net.ottto.locald login item; Ottto will retry at daemon startup." >&2
  fi
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

deregister_legacy_smappservice

SETUP_NOTES=()

if [[ "$BOOTSTRAP_DAEMON" == "true" ]]; then
  if ! "$daemon_target" service bootstrap --executable "$daemon_target" --json >/dev/null 2>&1; then
    SETUP_NOTES+=("ottto-service LaunchAgent bootstrap failed. Run $cli_target status to retry.")
  elif ! wait_for_daemon "$cli_target"; then
    "$daemon_target" service bootstrap --executable "$daemon_target" --json >/dev/null 2>&1 || true
    if ! wait_for_daemon "$cli_target"; then
      SETUP_NOTES+=("ottto-service did not become ready. Run $cli_target status to retry.")
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
