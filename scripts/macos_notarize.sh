#!/usr/bin/env bash
set -euo pipefail

MANIFEST=""
KEYCHAIN_PROFILE="${OTTTO_NOTARY_PROFILE:-}"
NOTARY_WAIT_TIMEOUT="${OTTTO_NOTARY_WAIT_TIMEOUT:-}"
ARTIFACT_NAMES=()
ARTIFACT_KINDS=()
VALIDATE_ONLY="false"

usage() {
  cat <<'USAGE'
Usage: macos_notarize.sh --manifest <release-manifest.json> [options]

Submits every macOS artifact archive in the clean-slate release manifest to
Apple notarization, staples supported app bundles, validates Gatekeeper, and
updates notarized/gatekeeper flags only after validation succeeds.

Options:
  --timeout <duration>       Optional notarytool wait timeout, for example 30m
                             or 1h. Apple continues processing after a local
                             timeout.
  --artifact-name <name>     Submit only artifacts with this manifest name.
                             May be passed more than once.
  --artifact-kind <kind>     Submit only artifacts with this manifest kind,
                             for example cli or daemon. May be passed more
                             than once.
  --validate-only            Do not submit artifacts to Apple. Only staple
                             supported app artifacts, run Gatekeeper
                             assessment, and update manifest flags after those
                             local validations pass.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --keychain-profile)
      KEYCHAIN_PROFILE="${2:?--keychain-profile requires a value}"
      shift 2
      ;;
    --timeout)
      NOTARY_WAIT_TIMEOUT="${2:?--timeout requires a value}"
      shift 2
      ;;
    --artifact-name)
      ARTIFACT_NAMES+=("${2:?--artifact-name requires a value}")
      shift 2
      ;;
    --artifact-kind)
      ARTIFACT_KINDS+=("${2:?--artifact-kind requires a value}")
      shift 2
      ;;
    --validate-only)
      VALIDATE_ONLY="true"
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

if [[ -z "$MANIFEST" || ( "$VALIDATE_ONLY" != "true" && -z "$KEYCHAIN_PROFILE" ) ]]; then
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
require_command shasum
require_command xcrun
require_command codesign
require_command spctl

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

notary_submit() {
  local archive="$1"
  local -a submit_args
  submit_args=(notarytool submit "$archive" --keychain-profile "$KEYCHAIN_PROFILE" --wait)
  if [[ -n "$NOTARY_WAIT_TIMEOUT" ]]; then
    submit_args+=(--timeout "$NOTARY_WAIT_TIMEOUT")
  fi
  xcrun "${submit_args[@]}"
}

mktemp_zip_path() {
  local prefix="$1"
  local path
  path="$(mktemp "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
  rm -f "$path"
  printf '%s.zip' "$path"
}

rebuild_dmg_from_app() {
  local app_bundle="$1"
  local dmg_path="$2"
  local sign_identity="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"

  require_command ditto
  require_command hdiutil
  if [[ -z "$sign_identity" ]]; then
    echo "OTTTO_MACOS_CODESIGN_IDENTITY is required to rebuild signed app DMGs." >&2
    exit 2
  fi

  local staging
  staging="$(mktemp -d)"
  ditto "$app_bundle" "$staging/$(basename "$app_bundle")"
  ln -s /Applications "$staging/Applications"
  rm -f "$dmg_path"
  hdiutil create -volname "Ottto" -srcfolder "$staging" -ov -format UDZO "$dmg_path" >/dev/null
  rm -rf "$staging"
  codesign --force --timestamp --sign "$sign_identity" "$dmg_path"
}

matches_filter() {
  local name="$1"
  local kind="$2"

  if [[ "${#ARTIFACT_NAMES[@]}" -eq 0 && "${#ARTIFACT_KINDS[@]}" -eq 0 ]]; then
    return 0
  fi

  local candidate
  local i
  for ((i = 0; i < ${#ARTIFACT_NAMES[@]}; i++)); do
    candidate="${ARTIFACT_NAMES[$i]}"
    if [[ "$name" == "$candidate" ]]; then
      return 0
    fi
  done

  for ((i = 0; i < ${#ARTIFACT_KINDS[@]}; i++)); do
    candidate="${ARTIFACT_KINDS[$i]}"
    if [[ "$kind" == "$candidate" ]]; then
      return 0
    fi
  done

  return 1
}

tmp_manifest="$(mktemp)"
trap 'rm -f "$tmp_manifest"' EXIT
cp "$MANIFEST" "$tmp_manifest"

index=0
processed=0
while IFS= read -r artifact; do
  platform="$(jq -r '.platform' <<<"$artifact")"
  path="$(jq -r '.path' <<<"$artifact")"
  verification_path="$(jq -r '.verification_path // empty' <<<"$artifact")"
  kind="$(jq -r '.kind' <<<"$artifact")"
  name="$(jq -r '.name' <<<"$artifact")"

  if [[ "$platform" != "macos" ]]; then
    index=$((index + 1))
    continue
  fi
  if ! matches_filter "$name" "$kind"; then
    index=$((index + 1))
    continue
  fi
  if [[ ! -f "$path" ]]; then
    echo "Artifact archive does not exist for $name: $path" >&2
    exit 1
  fi
  if [[ -z "$verification_path" || ! -e "$verification_path" ]]; then
    echo "Verification path does not exist for $name: $verification_path" >&2
    exit 1
  fi

  codesign --verify --strict --verbose=2 "$verification_path" >/dev/null

  if [[ "$kind" == "macos_app" ]]; then
    if [[ "$VALIDATE_ONLY" != "true" ]]; then
      app_notary_zip="$(mktemp_zip_path ottto-app-notary)"
      ditto -c -k --keepParent "$verification_path" "$app_notary_zip"
      notary_submit "$app_notary_zip"
      rm -f "$app_notary_zip"
      xcrun stapler staple "$verification_path"
      xcrun stapler validate "$verification_path"
      rebuild_dmg_from_app "$verification_path" "$path"
      notary_submit "$path"
    fi
    xcrun stapler staple "$path"
    xcrun stapler validate "$path"
    xcrun stapler staple "$verification_path"
    xcrun stapler validate "$verification_path"
  elif [[ "$VALIDATE_ONLY" != "true" ]]; then
    notary_submit "$path"
  fi

  spctl --assess --type "$(gatekeeper_assessment_type "$kind")" --verbose "$verification_path" >/dev/null
  sha256="$(sha256_file "$path")"
  jq \
    --argjson index "$index" \
    --arg sha256 "$sha256" \
    '.artifacts[$index].notarized = true
      | .artifacts[$index].gatekeeper_assessed = true
      | .artifacts[$index].sha256 = $sha256' \
    "$tmp_manifest" > "$tmp_manifest.next"
  mv "$tmp_manifest.next" "$tmp_manifest"

  processed=$((processed + 1))
  index=$((index + 1))
done < <(jq -c '.artifacts[]' "$MANIFEST")

if [[ "$processed" -eq 0 ]]; then
  echo "No macOS artifacts matched the notarization filter." >&2
  exit 1
fi

mv "$tmp_manifest" "$MANIFEST"
trap - EXIT
echo "Updated notarization state in $MANIFEST"
