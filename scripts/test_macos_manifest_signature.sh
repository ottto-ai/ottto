#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNER="$ROOT/scripts/macos_manifest_signature.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mock_bin="$TMP_DIR/bin"
mkdir -p "$mock_bin"
cat > "$mock_bin/security" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "find-certificate" ]]; then
  identity=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c)
        identity="${2:?}"
        shift 2
        ;;
      -p)
        shift
        ;;
      -k)
        shift 2
        ;;
      find-certificate)
        shift
        ;;
      *)
        echo "unexpected security find-certificate option: $1" >&2
        exit 2
        ;;
    esac
  done
  if [[ "$identity" != "Developer ID Application: Ottto Inc (TEAMID1234)" ]]; then
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
mode=""
input=""
output=""
identity=""
verbose="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -S|-D)
      mode="$1"
      shift
      ;;
    -i)
      input="${2:?}"
      shift 2
      ;;
    -o)
      output="${2:?}"
      shift 2
      ;;
    -N)
      identity="${2:?}"
      shift 2
      ;;
    -H|-u|-k)
      shift 2
      ;;
    -G)
      shift
      ;;
    -v)
      verbose="1"
      shift
      ;;
    *)
      echo "unexpected security cms option: $1" >&2
      exit 2
      ;;
  esac
done
test -n "$mode"
test -n "$input"
if [[ "$mode" == "-S" ]]; then
  test -n "$output"
  test -n "$identity"
  {
    printf 'SIGNER=%s\n' "$identity"
    cat "$input"
  } > "$output"
elif [[ "$mode" == "-D" ]]; then
  if [[ "$verbose" == "1" ]]; then
    head -n 1 "$input" >&2
  fi
  if [[ -n "$output" ]]; then
    tail -n +2 "$input" > "$output"
  else
    tail -n +2 "$input"
  fi
else
  exit 2
fi
MOCK
chmod +x "$mock_bin/security"
export PATH="$mock_bin:$PATH"

manifest="$TMP_DIR/release-manifest.json"
signature="$TMP_DIR/release-manifest.json.sig"
printf '{"schema_version":1,"product":"ottto-local-platform"}\n' > "$manifest"

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
"$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Ottto Inc (TEAMID1234)" >/dev/null

if "$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Evil Example (EVILTEAM)" >/dev/null 2>&1; then
  echo "Expected signature verification to fail for the wrong Developer ID signer" >&2
  exit 1
fi

printf '{"schema_version":1,"product":"changed"}\n' > "$manifest"
if "$SIGNER" verify \
  --manifest "$manifest" \
  --signature "$signature" \
  --identity "Developer ID Application: Ottto Inc (TEAMID1234)" >/dev/null 2>&1; then
  echo "Expected signature verification to fail after manifest mutation" >&2
  exit 1
fi

echo "macos_manifest_signature tests passed"
