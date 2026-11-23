#!/usr/bin/env bash

ottto_macos_url_types_plist() {
  local channel="${1:-}"
  case "$channel" in
    stable)
      cat <<'PLISTKEYS'
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
PLISTKEYS
      ;;
    dev|preview|stable-candidate)
      ;;
    *)
      echo "Unsupported macOS release channel: $channel" >&2
      return 2
      ;;
  esac
}
