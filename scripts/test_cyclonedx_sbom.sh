#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/scripts/cyclonedx_sbom.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq

sparkle_revision="6276ba2b404829d139c45ff98427cf90e2efc59b"

# [behaviour] The release SBOM lists the Apple Silicon CLI/daemon graph with
# declared licenses, plus the Companion app, Sparkle and the bundled fonts.
sbom="$TMP_DIR/ottto-local-platform-sbom.cdx.json"
"$GENERATOR" --output "$sbom" --version 0.1.0-test \
  --sparkle-version 2.9.2 --sparkle-revision "$sparkle_revision" >/dev/null

check_sbom() {
  local label="$1"
  local filter="$2"
  if ! jq -e --arg revision "$sparkle_revision" "$filter" "$sbom" >/dev/null; then
    echo "SBOM check failed: $label" >&2
    exit 1
  fi
}

check_sbom "format, serial and release version" '
  .bomFormat == "CycloneDX"
  and (.serialNumber | test("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
  and .specVersion == "1.7"
  and .metadata.component.name == "ottto-local-platform"
  and .metadata.component.version == "0.1.0-test"
  and .metadata.component.licenses == [{expression: "Apache-2.0 AND LicenseRef-Ottto-Proprietary"}]
'
check_sbom "every component has a license and a unique bom-ref" '
  (.components | length > 0)
  and (.components | all((.licenses | length) > 0))
  and ([.components[]."bom-ref"] | unique | length) == (.components | length)
'
check_sbom "slash license syntax becomes OR; other expressions are kept" '
  (.components | all(.licenses | all((.expression // "") | contains("/") | not)))
  and ([.components[] | select(.name == "fallible-iterator") | .licenses] == [[{expression: "MIT OR Apache-2.0"}]])
  and ([.components[] | select(.name == "webpki-roots") | .licenses[0].expression] == ["CDLA-Permissive-2.0"])
'
check_sbom "Apple Silicon crates are present" '
  any(.components[]; .name == "objc2-core-foundation")
'
check_sbom "off-target and test-only crates are absent" '
  all(.components[]; .name != "windows-sys" and .name != "sqlite-wasm-rs" and .name != "serial_test")
'
check_sbom "workspace crates carry no registry purl" '
  ([.components[] | select(."bom-ref" | startswith("cargo-workspace:")) | .name] | sort)
    == ["ottto-cli", "ottto-core", "ottto-protocol", "ottto-service"]
  and all(.components[] | select(.name | startswith("ottto-")); .purl == null and .licenses == [{expression: "Apache-2.0"}])
  and ([.components[] | select(.type == "application" and (."bom-ref" | startswith("cargo-workspace:"))) | .name] | sort)
    == ["ottto-cli", "ottto-service"]
'
check_sbom "registry crates carry a Cargo purl" '
  any(.components[]; .name == "serde" and .purl == ("pkg:cargo/serde@" + .version) and ."bom-ref" == .purl)
'
check_sbom "Companion app is listed as closed source at the release version" '
  [.components[] | select(.name == "Ottto")] == [{
    type: "application",
    "bom-ref": "net.ottto.Companion@0.1.0-test",
    name: "Ottto",
    version: "0.1.0-test",
    description: "Closed-source macOS Companion app",
    licenses: [{expression: "LicenseRef-Ottto-Proprietary"}]
  }]
'
# shellcheck disable=SC2016 # $revision is a jq variable.
check_sbom "Sparkle carries its licenses, purl and pinned revision" '
  [.components[] | select(.name == "Sparkle")] == [{
    type: "library",
    "bom-ref": "pkg:github/sparkle-project/sparkle@2.9.2",
    name: "Sparkle",
    version: "2.9.2",
    purl: "pkg:github/sparkle-project/sparkle@2.9.2",
    licenses: [{expression: "MIT AND BSD-2-Clause AND Zlib"}],
    externalReferences: [{type: "vcs", url: ("https://github.com/sparkle-project/Sparkle/tree/" + $revision)}]
  }]
'
check_sbom "bundled fonts are OFL-1.1" '
  ([.components[] | select(.type == "file") | {name, licenses}] | sort_by(.name)) == [
    {name: "Fraunces", licenses: [{license: {id: "OFL-1.1"}}]},
    {name: "JetBrains Mono", licenses: [{license: {id: "OFL-1.1"}}]}
  ]
'

# [behaviour] Without the Sparkle options the SBOM is the Rust inventory only.
rust_only="$TMP_DIR/rust-only.cdx.json"
"$GENERATOR" --output "$rust_only" --version 0.1.0-test >/dev/null
if ! jq -e '
  .metadata.component.licenses == [{expression: "Apache-2.0"}]
  and (.components | length > 0)
  and all(.components[]; .name != "Ottto" and .name != "Sparkle" and .type != "file")
' "$rust_only" >/dev/null; then
  echo "Rust-only SBOM must omit the Companion app, Sparkle and fonts" >&2
  exit 1
fi

# A fake cargo records every call and serves a tiny synthetic workspace whose
# selected dependency declares no license.
fake_bin="$TMP_DIR/fake-bin"
cargo_calls="$TMP_DIR/cargo.calls"
mkdir -p "$fake_bin"
cat > "$fake_bin/cargo" <<CARGO
#!/usr/bin/env bash
printf '%s\\n' "\$1" >> "$cargo_calls"
case "\$1" in
  metadata)
    cat <<'JSON'
{"workspace_members":["cli-id","service-id"],"packages":[
 {"id":"cli-id","name":"ottto-cli","version":"0.1.0","license":"Apache-2.0","source":null},
 {"id":"service-id","name":"ottto-service","version":"0.1.0","license":"Apache-2.0","source":null},
 {"id":"dep-id","name":"unlicensed-dep","version":"1.2.3","license":null,"source":"registry+https://github.com/rust-lang/crates.io-index"}
]}
JSON
    ;;
  tree)
    printf 'ottto-cli v0.1.0 (/synthetic/ottto-cli)\nunlicensed-dep v1.2.3\nottto-service v0.1.0 (/synthetic/ottto-service)\nunlicensed-dep v1.2.3 (*)\n'
    ;;
  *) exit 2 ;;
esac
CARGO
chmod +x "$fake_bin/cargo"

# [behaviour] A selected crate with no declared license fails and leaves no SBOM.
missing_license="$TMP_DIR/missing-license.cdx.json"
if PATH="$fake_bin:$PATH" "$GENERATOR" --output "$missing_license" \
  >"$TMP_DIR/missing-license.out" 2>&1; then
  echo "Expected a selected crate without a license to fail" >&2
  exit 1
fi
if ! grep -Fq "unlicensed-dep@1.2.3 declares no SPDX license expression" "$TMP_DIR/missing-license.out"; then
  echo "Missing-license failure did not name the crate:" >&2
  cat "$TMP_DIR/missing-license.out" >&2
  exit 1
fi
if [[ -n "$(find "$TMP_DIR" -maxdepth 1 -name '*missing-license.cdx.json*' -print)" ]]; then
  echo "A failed SBOM run must not leave an output or temporary file" >&2
  exit 1
fi

# [behaviour] Sparkle options are paired and validated before Cargo runs.
rm -f "$cargo_calls"
expect_usage_error() {
  local expected="$1"
  shift
  if PATH="$fake_bin:$PATH" "$GENERATOR" --output "$TMP_DIR/usage.cdx.json" "$@" \
    >"$TMP_DIR/usage.out" 2>&1; then
    echo "Expected the generator to reject: $*" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/usage.out"; then
    echo "Generator rejection did not report: $expected" >&2
    cat "$TMP_DIR/usage.out" >&2
    exit 1
  fi
}
expect_usage_error "must be given together" --sparkle-version 2.9.2
expect_usage_error "must be given together" --sparkle-revision "$sparkle_revision"
expect_usage_error "must be a semantic version" --sparkle-version v2.9.2 --sparkle-revision "$sparkle_revision"
expect_usage_error "40-character lowercase hex" --sparkle-version 2.9.2 --sparkle-revision "${sparkle_revision:0:12}"
if [[ -e "$cargo_calls" ]]; then
  echo "Invalid Sparkle options must be rejected before Cargo runs" >&2
  exit 1
fi

echo "cyclonedx_sbom tests passed"
