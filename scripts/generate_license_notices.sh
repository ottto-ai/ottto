#!/usr/bin/env bash
# Regenerates LICENSE-THIRD-PARTY.html, the notices for the third-party Rust
# crates in the shipped ottto CLI and ottto-service binaries, from Cargo.lock
# with cargo-about 0.9.2 and licenses/about.toml + licenses/about.hbs.
#
#   scripts/generate_license_notices.sh          regenerate the committed file
#   scripts/generate_license_notices.sh --check  fail if it is out of date
#
# CI runs --check, so any Cargo.lock change that alters the notices must
# commit the regenerated file. See licenses/README.md.
set -euo pipefail

CARGO_ABOUT_VERSION="0.9.2"
# The clarifications in licenses/about.toml hash files of these exact
# versions. A bump must re-check those hashes (see licenses/README.md).
PINNED_CRATES="ring 0.17.14
webpki-roots 1.0.12"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$ROOT/LICENSE-THIRD-PARTY.html"
REGENERATE="bash scripts/generate_license_notices.sh"

check="false"
case "${1:-}" in
  "") ;;
  --check) check="true" ;;
  *)
    echo "usage: generate_license_notices.sh [--check]" >&2
    exit 2
    ;;
esac

fail() {
  echo "license notices: $*" >&2
  exit 1
}

actual_version="$(cargo about --version 2>/dev/null || true)"
if [[ "$actual_version" != "cargo-about $CARGO_ABOUT_VERSION" ]]; then
  fail "need cargo-about $CARGO_ABOUT_VERSION (found: ${actual_version:-none}); see licenses/README.md"
fi

while read -r crate version; do
  locked="$(awk -v name="$crate" '
    $0 == "[[package]]" { in_pkg = 1; pkg = ""; next }
    in_pkg && $1 == "name" { pkg = $3; gsub(/"/, "", pkg) }
    in_pkg && $1 == "version" && pkg == name { v = $3; gsub(/"/, "", v); print v }
  ' "$ROOT/Cargo.lock")"
  if [[ "$locked" != "$version" ]]; then
    fail "Cargo.lock has $crate ${locked:-<none>}, but licenses/about.toml was checked against $crate $version; re-check its clarification hashes and update both"
  fi
done <<<"$PINNED_CRATES"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
generated="$tmp_dir/LICENSE-THIRD-PARTY.html"

# --fail turns unresolved or unaccepted licenses into errors. A clarification
# whose file hash no longer matches only warns and falls back, so the checks
# below verify the special license texts themselves.
(
  cd "$ROOT"
  cargo about generate --locked --workspace --fail \
    --manifest-path Cargo.toml \
    --config licenses/about.toml \
    --target aarch64-apple-darwin \
    --output-file "$generated" \
    licenses/about.hbs
)

python3 -I - "$generated" <<'PY'
import hashlib
import re
import sys
from html.parser import HTMLParser

# crate -> (license section id, sha256 of the exact license text) it must be
# listed under. ring's own LICENSE only points at these files.
REQUIRED = [
    ("ring", "Apache-2.0", "005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d"),
    ("ring", "ISC", "f025ccfb7dfb6bdfedc75ca0f67acc69e6fb4998143d834f7c2f38a29989680f"),
    ("ring", "MIT", "9eacbcb81be660840c714a560a9d65ba07913db98dd4baf969f78dd499fdd60f"),
    ("ring", "Apache-2.0", "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2"),
    ("ring", "MIT", "6ee2ed6c77710de911761acd5fc1ad1da00f476beb1a7ef27e78c2d1858deafc"),
    ("webpki-roots", "CDLA-Permissive-2.0", "e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8"),
]
# Crates that offer a choice and are used under Apache-2.0, whose full terms
# must then appear in the same section.
APACHE_SELECTED = ["objc2-core-foundation", "objc2-core-services"]
LOCAL_PATH = re.compile(r"(/Users/|/home/|/root/|/private/var/|/var/folders/|\.cargo/registry|[A-Za-z]:\\)")


class Sections(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = []
        self.in_pre = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "section":
            self.sections.append({"license": attrs.get("data-license", ""), "crates": set(), "text": ""})
        elif tag == "li" and "data-crate" in attrs and self.sections:
            self.sections[-1]["crates"].add(attrs["data-crate"])
        elif tag == "pre":
            self.in_pre = True

    def handle_endtag(self, tag):
        if tag == "pre":
            self.in_pre = False

    def handle_data(self, data):
        if self.in_pre and self.sections:
            self.sections[-1]["text"] += data


raw = open(sys.argv[1], encoding="utf-8").read()
parser = Sections()
parser.feed(raw)
parser.close()
errors = []
if not parser.sections:
    errors.append("no license sections were generated")
for section in parser.sections:
    if not section["crates"] or not section["text"].strip():
        errors.append(f"empty {section['license'] or 'unnamed'} section")
    section["sha256"] = hashlib.sha256(section["text"].encode("utf-8")).hexdigest()
for crate, license_id, digest in REQUIRED:
    if not any(
        crate in s["crates"] and s["license"] == license_id and s["sha256"] == digest
        for s in parser.sections
    ):
        errors.append(f"{crate} is missing its {license_id} text {digest[:12]}")
for crate in APACHE_SELECTED:
    if not any(
        crate in s["crates"] and s["license"] == "Apache-2.0" and "TERMS AND CONDITIONS" in s["text"]
        for s in parser.sections
    ):
        errors.append(f"{crate} is not listed with the full Apache-2.0 terms")
if LOCAL_PATH.search(raw):
    errors.append("output contains a local filesystem path")
for error in errors:
    print(f"license notices: {error}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY

if [[ "$check" == "true" ]]; then
  if ! cmp -s "$generated" "$OUTPUT"; then
    diff -u "$OUTPUT" "$generated" | head -n 60 >&2 || true
    fail "LICENSE-THIRD-PARTY.html is out of date; run: $REGENERATE (cargo-about $CARGO_ABOUT_VERSION) and commit the result"
  fi
  echo "license notices: LICENSE-THIRD-PARTY.html is up to date"
else
  cp "$generated" "$OUTPUT.tmp"
  mv "$OUTPUT.tmp" "$OUTPUT"
  echo "license notices: wrote LICENSE-THIRD-PARTY.html"
fi
