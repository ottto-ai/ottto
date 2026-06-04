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
verifies that release-manifest.json.sig decodes to exactly the manifest bytes
and is signed by the expected Developer ID identity.

Options:
  --signature <path>  Signature path. Default: <manifest>.sig
  --identity <name>   Expected Developer ID Application identity for signing and verification.
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
require_command openssl

security_common_args=(cms)
security_find_args=(find-certificate)
if [[ -n "$KEYCHAIN" ]]; then
  security_common_args+=(-k "$KEYCHAIN")
  security_find_args+=(-k "$KEYCHAIN")
fi

validate_developer_id_identity() {
  if [[ -z "$IDENTITY" ]]; then
    echo "Developer ID Application identity is required for $MODE" >&2
    exit 2
  fi
  if [[ "$IDENTITY" != Developer\ ID\ Application:* ]]; then
    echo "Manifest CMS signing identity must be a Developer ID Application identity" >&2
    exit 2
  fi
}

if [[ "$MODE" == "sign" ]]; then
  validate_developer_id_identity
  security "${security_common_args[@]}" -S -u 6 -H SHA256 -G -N "$IDENTITY" -i "$MANIFEST" -o "$SIGNATURE"
  echo "Wrote CMS signature: $SIGNATURE"
  exit 0
fi

if [[ ! -f "$SIGNATURE" ]]; then
  echo "Signature does not exist: $SIGNATURE" >&2
  exit 1
fi

validate_developer_id_identity

signer_details="$(mktemp)"
signer_cert="$(mktemp)"
decoded="$(mktemp)"
trap 'rm -f "$signer_details" "$signer_cert" "$decoded"' EXIT

if ! security "${security_find_args[@]}" -c "$IDENTITY" -p >/dev/null; then
  echo "Expected Developer ID identity was not found in the keychain: $IDENTITY" >&2
  exit 1
fi
# Decode and cryptographically verify the CMS signature against a trusted object-signing
# chain (certusage 6), capturing the manifest payload for the byte-equality check below.
if ! security "${security_common_args[@]}" -D -u 6 -i "$SIGNATURE" -o "$decoded" 2>"$signer_details"; then
  cat "$signer_details" >&2
  exit 1
fi
# Origin-bind the signature to the expected Developer ID. `security cms -D -v` does not
# emit the signer certificate, so extract the certificate that actually produced the
# signature with openssl: -signer reports the real signer (not every embedded cert), so a
# decoy certificate carrying a matching subject cannot satisfy this check. Then confirm
# the signer's subject is the expected identity.
if ! openssl cms -verify -inform DER -in "$SIGNATURE" -noverify -signer "$signer_cert" -out /dev/null 2>"$signer_details"; then
  cat "$signer_details" >&2
  echo "Failed to extract a CMS signer certificate from signature: $SIGNATURE" >&2
  exit 1
fi
if ! openssl x509 -in "$signer_cert" -noout -subject 2>/dev/null | grep -Fq "$IDENTITY"; then
  echo "CMS signature was not signed by expected identity: $IDENTITY" >&2
  exit 1
fi
if ! cmp -s "$MANIFEST" "$decoded"; then
  echo "CMS signature payload does not match manifest bytes" >&2
  exit 1
fi

echo "Verified CMS signature payload and signer for $MANIFEST"
