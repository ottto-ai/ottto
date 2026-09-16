#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/dist/macos/release-manifest.json"
APP_DIR="$HOME/Applications"
BIN_DIR="$HOME/.ottto/bin"
CLEAR_QUARANTINE="false"
WRITE_LAUNCH_AGENT="false"
BOOTSTRAP_LAUNCH_AGENT="false"
DRY_RUN="false"
TRUST_DEV_COMPANION="false"
# A Developer ID signed ottto-service demands a Developer ID signed Companion. A
# dev/preview bundle is only ad-hoc sealed, so it carries no Apple team and
# cannot satisfy that. This is the requirement a dev LaunchAgent installs
# instead: same bundle identifier, no team assertion. Only needed when a release
# daemon has to run against an internal Companion; an internal daemon already
# accepts one. Never use it for a customer install.
DEV_COMPANION_CODE_REQUIREMENT='identifier "net.ottto.Companion"'

usage() {
  cat <<'USAGE'
Usage: macos_dev_install.sh [options]

Installs a dev/preview/stable-candidate Ottto local-platform package after
verifying its release manifest and artifact checksums. This path is intended for
internal QA and trusted testers before stable customer promotion.

Options:
  --manifest <path>          Release manifest. Default: dist/macos/release-manifest.json
  --app-dir <path>           App install directory. Default: ~/Applications
  --bin-dir <path>           CLI/daemon install directory. Default: ~/.ottto/bin
  --clear-quarantine         Remove com.apple.quarantine from installed dev artifacts.
  --write-launch-agent       Write the per-user ottto-service LaunchAgent plist.
  --bootstrap-launch-agent   Write and bootstrap the per-user LaunchAgent.
  --trust-dev-companion      QA only: make the LaunchAgent trust a locally built,
                             ad-hoc-signed Ottto.app even when the daemon is a
                             signed release build. A normal dev install does not
                             need this: an internal daemon already accepts an
                             internal Companion.
  --dry-run                  Validate and print planned paths without installing.
  -h, --help                 Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
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
    --clear-quarantine)
      CLEAR_QUARANTINE="true"
      shift
      ;;
    --write-launch-agent)
      WRITE_LAUNCH_AGENT="true"
      shift
      ;;
    --bootstrap-launch-agent)
      WRITE_LAUNCH_AGENT="true"
      BOOTSTRAP_LAUNCH_AGENT="true"
      shift
      ;;
    --trust-dev-companion)
      TRUST_DEV_COMPANION="true"
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

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command ditto
require_command hdiutil

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

# True when the bundle satisfies Apple's Developer ID designated-requirement
# fragment, i.e. it could satisfy the daemon's baked-in team requirement. An
# ad-hoc sealed dev/preview bundle does not.
developer_id_signed() {
  local app_target="$1"
  codesign -v -R='anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' \
    "$app_target" >/dev/null 2>&1
}

canonical_app_path() {
  local path="$1"
  local parent
  local base
  parent="$(dirname "$path")"
  base="$(basename "$path")"
  if [[ -d "$parent" ]]; then
    (cd -P "$parent" && printf '%s/%s\n' "$(pwd)" "$base")
  else
    printf '%s\n' "$path"
  fi
}

unregister_duplicate_companion_apps() {
  local app_target="$1"
  local lsregister="$2"
  local target_path
  local candidate
  local candidate_path
  local bundle_id

  target_path="$(canonical_app_path "$app_target")"
  {
    if command -v mdfind >/dev/null 2>&1; then
      mdfind 'kMDItemCFBundleIdentifier == "net.ottto.Companion"' 2>/dev/null || true
    fi
    "$lsregister" -dump 2>/dev/null | awk '
      /^path:[[:space:]]/ {
        path = $0
        sub(/^path:[[:space:]]+/, "", path)
        sub(/[[:space:]]+\(0x[0-9a-fA-F]+\).*$/, "", path)
      }
      /^identifier:[[:space:]]+net[.]ottto[.]Companion$/ && path != "" {
        print path
      }
    ' || true
  } | sort -u | while IFS= read -r candidate; do
    [[ -n "$candidate" && -d "$candidate" ]] || continue
    candidate_path="$(canonical_app_path "$candidate")"
    [[ "$candidate_path" != "$target_path" ]] || continue
    if command -v plutil >/dev/null 2>&1 && [[ -f "$candidate/Contents/Info.plist" ]]; then
      bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$candidate/Contents/Info.plist" 2>/dev/null || true)"
      [[ "$bundle_id" == "net.ottto.Companion" ]] || continue
    fi
    "$lsregister" -u "$candidate" >/dev/null 2>&1 || true
  done
}

detach_duplicate_companion_volumes() {
  local app_target="$1"
  local target_path
  local candidate
  local candidate_path
  local bundle_id
  local volume

  if ! command -v hdiutil >/dev/null 2>&1 || ! command -v plutil >/dev/null 2>&1; then
    return 0
  fi

  target_path="$(canonical_app_path "$app_target")"
  for candidate in /Volumes/*/Ottto.app; do
    [[ -d "$candidate" && -f "$candidate/Contents/Info.plist" ]] || continue
    candidate_path="$(canonical_app_path "$candidate")"
    [[ "$candidate_path" != "$target_path" ]] || continue
    bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$candidate/Contents/Info.plist" 2>/dev/null || true)"
    [[ "$bundle_id" == "net.ottto.Companion" ]] || continue
    volume="$(dirname "$candidate")"
    hdiutil detach "$volume" >/dev/null 2>&1 || hdiutil detach -force "$volume" >/dev/null 2>&1 || true
  done
}

register_installed_app() {
  local app_target="$1"
  local lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

  if [[ ! -x "$lsregister" ]]; then
    echo "Warning: LaunchServices registration helper was not found; ottto:// links may require opening $app_target once." >&2
    return 0
  fi

  detach_duplicate_companion_volumes "$app_target"
  unregister_duplicate_companion_apps "$app_target" "$lsregister"
  if ! "$lsregister" -f "$app_target" >/dev/null 2>&1; then
    echo "Warning: failed to register $app_target with LaunchServices; ottto:// links may require opening the app once." >&2
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
      ditto -x -k "$app_artifact" "$extract_dir"
      if [[ ! -d "$extract_dir/Ottto.app" ]]; then
        echo "App archive did not contain Ottto.app" >&2
        exit 1
      fi
      stop_running_companion
      rm -rf "$app_target" "$old_app_target"
      ditto "$extract_dir/Ottto.app" "$app_target"
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
      ditto "$mount_dir/Ottto.app" "$app_target"
      hdiutil detach "$mount_dir" >/dev/null
      ;;
    *)
      echo "Unsupported app artifact format: $app_artifact" >&2
      exit 1
      ;;
  esac
}

"$ROOT/scripts/macos_release_gate.sh" --manifest "$MANIFEST" >/dev/null

channel="$(jq -r '.channel' "$MANIFEST")"
if [[ "$channel" == "stable" ]]; then
  echo "macos_dev_install.sh is for dev/preview/stable-candidate builds. Use the signed stable local-platform package path for stable manifests." >&2
  exit 2
fi

artifact_path() {
  local kind="$1"
  jq -er --arg kind "$kind" '.artifacts[] | select(.kind == $kind) | .path' "$MANIFEST"
}

app_zip="$(artifact_path macos_app)"
cli_zip="$(artifact_path cli)"
daemon_zip="$(artifact_path daemon)"

app_target="$APP_DIR/Ottto.app"
# Remove the pre-cutover bundle name during installs so Finder does not show two apps.
old_app_target="$APP_DIR/Ottto Companion.app"
cli_target="$BIN_DIR/ottto"
daemon_target="$BIN_DIR/ottto-service"

echo "Ottto local platform dev install plan"
echo "  channel: $channel"
echo "  app: $app_target"
echo "  cli: $cli_target"
echo "  daemon: $daemon_target"
echo "  launch agent: $WRITE_LAUNCH_AGENT"
echo "  bootstrap launch agent: $BOOTSTRAP_LAUNCH_AGENT"
echo "  trust dev companion: $TRUST_DEV_COMPANION"

if [[ "$DRY_RUN" == "true" ]]; then
  exit 0
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$APP_DIR" "$BIN_DIR"

cleanup_legacy_service
copy_app_artifact "$app_zip" "$app_target" "$old_app_target"

ditto -x -k "$cli_zip" "$tmp_dir/cli"
ditto -x -k "$daemon_zip" "$tmp_dir/daemon"
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

if [[ "$CLEAR_QUARANTINE" == "true" ]] && command -v xattr >/dev/null 2>&1; then
  xattr -dr com.apple.quarantine "$app_target" "$cli_target" "$daemon_target" 2>/dev/null || true
fi

register_installed_app "$app_target"
deregister_legacy_smappservice

launch_agent_companion_args=()
if [[ "$TRUST_DEV_COMPANION" == "true" ]]; then
  launch_agent_companion_args=(--companion-code-requirement "$DEV_COMPANION_CODE_REQUIREMENT")
fi

if [[ "$WRITE_LAUNCH_AGENT" == "true" ]]; then
  if [[ "$BOOTSTRAP_LAUNCH_AGENT" == "true" ]]; then
    "$daemon_target" service bootstrap --executable "$daemon_target" \
      ${launch_agent_companion_args[@]+"${launch_agent_companion_args[@]}"} --json
    if ! wait_for_daemon "$cli_target"; then
      echo "Warning: ottto-service did not become ready after bootstrap; retrying once." >&2
      "$daemon_target" service bootstrap --executable "$daemon_target" \
        ${launch_agent_companion_args[@]+"${launch_agent_companion_args[@]}"} --json >/dev/null 2>&1 || true
      if ! wait_for_daemon "$cli_target"; then
        echo "Warning: installed files, but ottto-service did not become ready. Open Ottto or rerun this installer with --bootstrap-launch-agent to retry." >&2
      fi
    fi
  else
    "$daemon_target" service write-launch-agent --executable "$daemon_target" \
      ${launch_agent_companion_args[@]+"${launch_agent_companion_args[@]}"} --json
  fi
  # The daemon only demands a Developer ID Companion when the daemon itself is
  # Developer ID signed, so a normal dev install (ad-hoc daemon + ad-hoc app)
  # needs no flag. Warn only about the mismatch that does break: a release
  # daemon next to an internal app.
  if [[ "$TRUST_DEV_COMPANION" != "true" ]] &&
    developer_id_signed "$daemon_target" &&
    ! developer_id_signed "$app_target"; then
    echo "Note: $daemon_target is Developer ID signed but $app_target is not, so the" >&2
    echo "      daemon will refuse it token-less Companion trust. Rerun with" >&2
    echo "      --trust-dev-companion for local QA." >&2
  fi
fi

echo "Installed Ottto local platform dev build."
echo "Open: $app_target"
echo "CLI: $cli_target"
