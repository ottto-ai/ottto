#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_secret_scan.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_config() {
  local repo="$1"
  mkdir -p "$repo/config"
  cat > "$repo/config/deny-patterns.tsv" <<'DENY'
# scope	regex	description
path	(^|/)backend(/|$)	backend path denied
content	/Users/ronshub	local operator path denied
content	docs/dev/	private docs denied
content	Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{16,}	bearer token denied
DENY
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo/public"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Test"
  write_config "$repo"
}

run_scan() {
  local repo="$1"
  shift
  PUBLIC_EXPORT_REPO_ROOT="$repo" \
    PUBLIC_EXPORT_CONFIG_DIR="$repo/config" \
    "$SCRIPT" "$@"
}

clean_repo="$tmp_dir/clean"
init_repo "$clean_repo"
cat > "$clean_repo/public/README.md" <<'EOF'
# Public Files

No private paths or credentials here.
EOF
git -C "$clean_repo" add public
git -C "$clean_repo" commit -qm clean
run_scan "$clean_repo" >/tmp/public-secret-clean.out
grep -q "checked 1 HEAD blob(s)" /tmp/public-secret-clean.out

history_repo="$tmp_dir/history"
init_repo "$history_repo"
cat > "$history_repo/public/README.md" <<'EOF'
Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456
EOF
git -C "$history_repo" add public
git -C "$history_repo" commit -qm secret
cat > "$history_repo/public/README.md" <<'EOF'
# Public Files

Secret removed before export.
EOF
git -C "$history_repo" add public
git -C "$history_repo" commit -qm clean
# [behaviour] The HEAD-only scan ignores content removed from history.
run_scan "$history_repo" >"$tmp_dir/head-only.out"

current_repo="$tmp_dir/current"
init_repo "$current_repo"
cat > "$current_repo/public/README.md" <<'EOF'
Raw operator output: /Users/ronshub/private
EOF
git -C "$current_repo" add public
git -C "$current_repo" commit -qm current-secret
if run_scan "$current_repo" >/tmp/public-secret-current.out 2>&1; then
  echo "Expected current local path to fail secret scan" >&2
  exit 1
fi
grep -q "HEAD content denied" /tmp/public-secret-current.out
grep -q "local operator path denied" /tmp/public-secret-current.out

if run_scan "$current_repo" --staged-output "$tmp_dir/missing" >"$tmp_dir/retired-option.out" 2>&1; then
  echo "Expected the retired --staged-output option to be refused" >&2
  exit 1
fi
grep -q "unknown argument: --staged-output" "$tmp_dir/retired-option.out"

path_repo="$tmp_dir/path"
init_repo "$path_repo"
mkdir -p "$path_repo/public/backend"
printf 'private\n' > "$path_repo/public/backend/file.txt"
git -C "$path_repo" add public
git -C "$path_repo" commit -qm backend-path
if run_scan "$path_repo" >/tmp/public-secret-path.out 2>&1; then
  echo "Expected backend path to fail secret scan" >&2
  exit 1
fi
grep -q "HEAD path denied" /tmp/public-secret-path.out

side_ref_repo="$tmp_dir/side-ref"
init_repo "$side_ref_repo"
cat > "$side_ref_repo/public/README.md" <<'EOF'
# Public Files
EOF
git -C "$side_ref_repo" add public
git -C "$side_ref_repo" commit -qm clean
main_branch="$(git -C "$side_ref_repo" branch --show-current)"
git -C "$side_ref_repo" checkout -qb unrelated-local-ref
mkdir -p "$side_ref_repo/public/target"
cat > "$side_ref_repo/public/target/noise.txt" <<'EOF'
Raw operator output: /Users/ronshub/private
EOF
git -C "$side_ref_repo" add public
git -C "$side_ref_repo" commit -qm unrelated-build-output
git -C "$side_ref_repo" checkout -q "$main_branch"
# [behaviour] Other local refs are not part of the checked HEAD tree.
run_scan "$side_ref_repo" >/tmp/public-secret-side-ref-default.out

# [behaviour] Working/index/untracked content and removed history are not HEAD.
printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$clean_repo/public/README.md"
printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$clean_repo/untracked.txt"
git -C "$clean_repo" add public/README.md
run_scan "$clean_repo" >"$tmp_dir/working-isolation.out"

expect_failure() {
  local repo="$1"
  local category="$2"
  if run_scan "$repo" >"$tmp_dir/negative.out" 2>&1; then
    echo "Expected secret scan refusal: $category" >&2
    exit 1
  fi
  grep -q "$category" "$tmp_dir/negative.out"
  if grep -q 'abcdefghijklmnopqrstuvwxyz123456' "$tmp_dir/negative.out"; then
    echo "Secret scan printed matched bytes" >&2
    exit 1
  fi
}

# [format] Every committed symlink mode is refused without resolving its target.
printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$tmp_dir/outside"
for target in README.md ../../outside missing; do
  repo="$tmp_dir/link-${target##*/}"
  init_repo "$repo"
  printf 'safe\n' > "$repo/public/README.md"
  ln -s "$target" "$repo/public/link"
  git -C "$repo" add public
  git -C "$repo" commit -qm symlink
  expect_failure "$repo" 'symlink denied'
done

# [format] Gitlinks are refused from mode/type metadata, without checking out.
repo="$tmp_dir/gitlink"
init_repo "$repo"
printf 'safe\n' > "$repo/public/README.md"
git -C "$repo" add public
git -C "$repo" commit -qm root
commit="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" update-index --add --cacheinfo "160000,$commit,vendor/sub"
git -C "$repo" commit -qm gitlink
expect_failure "$repo" 'non-blob or mode denied'

# [behaviour] Denies cover the whole tree, at root and at arbitrary depths.
for path in .claude/config .agents/config tools/ottto-local-platform/x backend/x \
  docs/dev/x docs/ai/x frontend/x infra/x dist/x target/x __pycache__/x \
  x.pyc x.pyo .env .env.test; do
  for prefix in '' nested/; do
    repo="$tmp_dir/forbidden"
    rm -rf "$repo"
    init_repo "$repo"
    mkdir -p "$(dirname "$repo/$prefix$path")"
    printf 'safe\n' > "$repo/$prefix$path"
    git -C "$repo" add "$prefix$path"
    git -C "$repo" commit -qm forbidden
    expect_failure "$repo" 'HEAD path denied'
  done
done

# [behaviour] Notes paths are refused in the HEAD tree with location-only output.
for path in docs/notes/x.md docs/development/x.md docs/session-2026-x.md; do
  repo="$tmp_dir/notes"
  rm -rf "$repo"
  init_repo "$repo"
  mkdir -p "$(dirname "$repo/$path")"
  printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$repo/$path"
  git -C "$repo" add "$path"
  git -C "$repo" commit -qm notes
  expect_failure "$repo" 'HEAD path denied'
  python3 - "$tmp_dir/negative.out" "$path" <<'CHECK'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
assert text == f'public-secret-scan: HEAD path denied: "{sys.argv[2]}":1\n', text
CHECK
done

# [behaviour] An unusual filename is one escaped location, never injected output.
repo="$tmp_dir/unusual"
init_repo "$repo"
filename=$'public/space\tline\nquote"back\\.txt'
printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$repo/$filename"
git -C "$repo" add public
git -C "$repo" commit -qm unusual
expect_failure "$repo" 'HEAD content denied'
python3 - "$tmp_dir/negative.out" <<'CHECK'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
assert r'space\tline\nquote\"back\\.txt":1' in text, text
assert len(text.splitlines()) == 2, text
CHECK

# A clean unusual filename also passes, even with a secret in its older blob.
printf 'safe\n' > "$repo/$filename"
git -C "$repo" add public
git -C "$repo" commit -qm clean
run_scan "$repo" > "$tmp_dir/unusual-clean.out"

# [behaviour] Malformed config diagnostics never include rows, scopes or regexes.
for row in $'abcdefghijklmnopqrstuvwxyz123456' \
  $'abcdefghijklmnopqrstuvwxyz123456\tx\tx' \
  $'content\t[abcdefghijklmnopqrstuvwxyz123456\tx'; do
  printf '%s\n' "$row" > "$repo/config/deny-patterns.tsv"
  expect_failure "$repo" 'deny-pattern'
done

# [format] Both HEAD and index derived manifests are refused before blob reads.
repo="$tmp_dir/manifest"
init_repo "$repo"
printf 'safe\n' > "$repo/public/README.md"
git -C "$repo" add public
git -C "$repo" commit -qm root
printf '{}\n' > "$repo/PUBLIC_EXPORT_MANIFEST.json"
git -C "$repo" add PUBLIC_EXPORT_MANIFEST.json
expect_failure "$repo" 'derived manifest tracked in index'
git -C "$repo" commit -qm manifest
expect_failure "$repo" 'derived manifest tracked'

# [format] The default policy is committed too, with unchanged digest/facts.
repo="$tmp_dir/policy"
init_repo "$repo"
mkdir -p "$repo/public-export"
printf 'content\tBearer[[:space:]]+[a-z0-9]{16,}\tcredential denied\n' \
  > "$repo/public-export/deny-patterns.tsv"
printf 'safe\n' > "$repo/public/README.md"
git -C "$repo" add public public-export
git -C "$repo" commit -qm root
"$ROOT/scripts/public_repo_manifest.sh" --repo "$repo" --facts > "$tmp_dir/before.json"
"$ROOT/scripts/public_repo_manifest.sh" --repo "$repo" --digest > "$tmp_dir/before.digest"
printf 'invalid working policy\n' > "$repo/public-export/deny-patterns.tsv"
PUBLIC_EXPORT_REPO_ROOT="$repo" "$SCRIPT" > "$tmp_dir/committed-policy.out"
"$ROOT/scripts/public_repo_manifest.sh" --repo "$repo" --facts > "$tmp_dir/after.json"
"$ROOT/scripts/public_repo_manifest.sh" --repo "$repo" --digest > "$tmp_dir/after.digest"
cmp "$tmp_dir/before.json" "$tmp_dir/after.json"
cmp "$tmp_dir/before.digest" "$tmp_dir/after.digest"
printf 'Bearer abcdefghijklmnopqrstuvwxyz123456\n' > "$repo/public/README.md"
git -C "$repo" add public
git -C "$repo" commit -qm secret
if PUBLIC_EXPORT_REPO_ROOT="$repo" "$SCRIPT" > "$tmp_dir/policy-secret.out" 2>&1; then
  echo 'Expected committed content denial despite edited policy' >&2
  exit 1
fi
grep -q 'HEAD content denied' "$tmp_dir/policy-secret.out"
if grep -q 'abcdefghijklmnopqrstuvwxyz123456' "$tmp_dir/policy-secret.out"; then
  echo 'Secret scan printed matched bytes' >&2
  exit 1
fi

echo "public_repo_secret_scan tests passed"
