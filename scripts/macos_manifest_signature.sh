#!/usr/bin/env bash
set -euo pipefail

MODE=""
MANIFEST=""
SIGNATURE=""
IDENTITY="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"
KEYCHAIN=""

usage() {
  cat <<'USAGE'
Usage: macos_manifest_signature.sh <sign|verify> --manifest <release-manifest.json> [options]

Signs release-manifest.json with a Developer ID-backed CMS signature and
verifies that release-manifest.json.sig decodes to exactly the manifest bytes.

Options:
  --signature <path>  Signature path. Default: <manifest>.sig
  --identity <name>   Developer ID Application identity for sign mode.
  --keychain <path>   Optional keychain passed to security cms.
  -h, --help          Show help.
USAGE
}

if [[ $# -gt 0 ]]; then
  MODE="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --signature)
      SIGNATURE="${2:?--signature requires a value}"
      shift 2
      ;;
    --identity)
      IDENTITY="${2:?--identity requires a value}"
      shift 2
      ;;
    --keychain)
      KEYCHAIN="${2:?--keychain requires a value}"
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

if [[ "$MODE" != "sign" && "$MODE" != "verify" ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$SIGNATURE" ]]; then
  SIGNATURE="$MANIFEST.sig"
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

require_command cmp
require_command security

security_common_args=(cms)
if [[ -n "$KEYCHAIN" ]]; then
  security_common_args+=(-k "$KEYCHAIN")
fi

if [[ "$MODE" == "sign" ]]; then
  if [[ -z "$IDENTITY" ]]; then
    echo "Developer ID Application identity is required for signing" >&2
    exit 2
  fi
  if [[ "$IDENTITY" != Developer\ ID\ Application:* ]]; then
    echo "Manifest CMS signing identity must be a Developer ID Application identity" >&2
    exit 2
  fi
  security "${security_common_args[@]}" -S -u 6 -H SHA256 -G -N "$IDENTITY" -i "$MANIFEST" -o "$SIGNATURE"
  echo "Wrote CMS signature: $SIGNATURE"
  exit 0
fi

if [[ ! -f "$SIGNATURE" ]]; then
  echo "Signature does not exist: $SIGNATURE" >&2
  exit 1
fi

decoded="$(mktemp)"
trap 'rm -f "$decoded"' EXIT
security "${security_common_args[@]}" -D -u 6 -i "$SIGNATURE" -o "$decoded"
if ! cmp -s "$MANIFEST" "$decoded"; then
  echo "CMS signature payload does not match manifest bytes" >&2
  exit 1
fi

echo "Verified CMS signature payload for $MANIFEST"
