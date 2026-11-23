#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNER="$ROOT/scripts/macos_manifest_signature.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mock_bin="$TMP_DIR/bin"
mkdir -p "$mock_bin"

# Mock `security`: find-certificate accepts any Developer ID Application identity (the
# keychain holds the cert), and `cms` round-trips a fake signature whose first line is
# "SIGNER=<identity>" followed by the manifest payload.
cat > "$mock_bin/security" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "find-certificate" ]]; then
  identity=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c) identity="${2:?}"; shift 2 ;;
      -p) shift ;;
      -k) shift 2 ;;
      find-certificate) shift ;;
      *) echo "unexpected security find-certificate option: $1" >&2; exit 2 ;;
    esac
  done
  # Simulate "the expected Developer ID exists in the keychain" for any Developer ID.
  if [[ "$identity" != Developer\ ID\ Application:* ]]; then
    exit 1
  fi
  printf 'mock certificate for %s\n' "$identity"
  exit 0
fi
if [[ "$1" != "cms" ]]; then
  echo "unexpected security command: $*" >&2
  exit 2
fi
shift
mode=""; input=""; output=""; identity=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -S|-D) mode="$1"; shift ;;
    -i) input="${2:?}"; shift 2 ;;
    -o) output="${2:?}"; shift 2 ;;
    -N) identity="${2:?}"; shift 2 ;;
    -H|-u|-k) shift 2 ;;
    -G|-v) shift ;;
    *) echo "unexpected security cms option: $1" >&2; exit 2 ;;
  esac
done
test -n "$mode"; test -n "$input"
if [[ "$mode" == "-S" ]]; then
  test -n "$output"; test -n "$identity"
  { printf 'SIGNER=%s\n' "$identity"; cat "$input"; } > "$output"
elif [[ "$mode" == "-D" ]]; then
  # Decode = strip the SIGNER marker line, leaving the manifest payload.
  if [[ -n "$output" ]]; then tail -n +2 "$input" > "$output"; else tail -n +2 "$input"; fi
else
  exit 2
fi
MOCK
chmod +x "$mock_bin/security"

# Mock `openssl`: `cms -verify -signer <out>` extracts the *real* signer from the fake
# signature's SIGNER= line; `x509 -subject` renders that into a certificate subject.
cat > "$mock_bin/openssl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
sub="${1:?}"; shift
case "$sub" in
  cms)
    input=""; signer=""; output=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -in) input="${2:?}"; shift 2 ;;
        -signer) signer="${2:?}"; shift 2 ;;
        -out) output="${2:?}"; shift 2 ;;
        -inform) shift 2 ;;
        -verify|-noverify) shift ;;
        *) echo "unexpected openssl cms option: $1" >&2; exit 2 ;;
      esac
    done
    test -n "$input"; test -n "$signer"
    # The signer cert is identified by the SIGNER= marker line of the signature.
    head -n 1 "$input" > "$signer"
    if [[ -n "$output" ]]; then tail -n +2 "$input" > "$output"; fi
    exit 0
    ;;
  x509)
    input=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -in) input="${2:?}"; shift 2 ;;
        -noout|-subject) shift ;;
        *) echo "unexpected openssl x509 option: $1" >&2; exit 2 ;;
      esac
    done
    test -n "$input"
    id="$(sed -n 's/^SIGNER=//p' "$input")"
    printf 'subject= /UID=TEAM/CN=%s/OU=TEAM/O=Org/C=US\n' "$id"
    exit 0
    ;;
  *) echo "unexpected openssl subcommand: $sub" >&2; exit 2 ;;
esac
MOCK
chmod +x "$mock_bin/openssl"

export PATH="$mock_bin:$PATH"

manifest="$TMP_DIR/release-manifest.json"
signature="$TMP_DIR/release-manifest.json.sig"
printf '{"schema_version":1,"product":"ottto-local-platform"}\n' > "$manifest"

# Non-Developer ID identity is rejected at sign time.
if "$SIGNER" sign \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Apple Development: Example" >/dev/null 2>&1; then
  echo "Expected non-Developer ID signing identity to fail" >&2
  exit 1
fi

"$SIGNER" sign \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Ottto Inc (TEAMID1234)" >/dev/null
test -f "$signature"

# Happy path: signer matches the expected identity.
"$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Ottto Inc (TEAMID1234)" >/dev/null

# Origin binding: a different Developer ID (present in the keychain) must still fail
# because the *actual signer* of the signature is not the expected identity.
if "$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Evil Example (EVILTEAM)" >/dev/null 2>&1; then
  echo "Expected signature verification to fail for the wrong Developer ID signer" >&2
  exit 1
fi

# Payload integrity: a mutated manifest must fail the byte-equality check.
printf '{"schema_version":1,"product":"changed"}\n' > "$manifest"
if "$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Ottto Inc (TEAMID1234)" >/dev/null 2>&1; then
  echo "Expected signature verification to fail after manifest mutation" >&2
  exit 1
fi

echo "macos_manifest_signature tests passed"
