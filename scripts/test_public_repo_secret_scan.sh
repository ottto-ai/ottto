#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_secret_scan.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_config() {
  local repo="$1"
  mkdir -p "$repo/config"
  cat > "$repo/config/roots.txt" <<'ROOTS'
public/
ROOTS
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
git -C "$clean_repo" add .
git -C "$clean_repo" commit -qm clean
run_scan "$clean_repo" >/tmp/public-secret-clean.out
grep -q "current candidate file" /tmp/public-secret-clean.out

history_repo="$tmp_dir/history"
init_repo "$history_repo"
cat > "$history_repo/public/README.md" <<'EOF'
Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456
EOF
git -C "$history_repo" add .
git -C "$history_repo" commit -qm secret
cat > "$history_repo/public/README.md" <<'EOF'
# Public Files

Secret removed before export.
EOF
git -C "$history_repo" add .
git -C "$history_repo" commit -qm clean
if run_scan "$history_repo" >/tmp/public-secret-history.out 2>&1; then
  echo "Expected historical bearer token to fail secret scan" >&2
  exit 1
fi
grep -q "historical content denied" /tmp/public-secret-history.out
grep -q "bearer token denied" /tmp/public-secret-history.out

current_repo="$tmp_dir/current"
init_repo "$current_repo"
cat > "$current_repo/public/README.md" <<'EOF'
Raw operator output: /Users/ronshub/private
EOF
git -C "$current_repo" add .
git -C "$current_repo" commit -qm current-secret
if run_scan "$current_repo" >/tmp/public-secret-current.out 2>&1; then
  echo "Expected current local path to fail secret scan" >&2
  exit 1
fi
grep -q "current content denied" /tmp/public-secret-current.out
grep -q "local operator path denied" /tmp/public-secret-current.out

staged_repo="$tmp_dir/staged"
init_repo "$staged_repo"
cat > "$staged_repo/public/README.md" <<'EOF'
# Public Files
EOF
git -C "$staged_repo" add .
git -C "$staged_repo" commit -qm staged-clean
mkdir -p "$tmp_dir/staged-output"
cat > "$tmp_dir/staged-output/README.md" <<'EOF'
See docs/dev/internal-session-note.md.
EOF
if run_scan "$staged_repo" --staged-output "$tmp_dir/staged-output" >/tmp/public-secret-staged.out 2>&1; then
  echo "Expected staged private docs reference to fail secret scan" >&2
  exit 1
fi
grep -q "staged output content denied" /tmp/public-secret-staged.out
grep -q "private docs denied" /tmp/public-secret-staged.out

path_repo="$tmp_dir/path"
init_repo "$path_repo"
mkdir -p "$path_repo/public/backend"
printf 'private\n' > "$path_repo/public/backend/file.txt"
git -C "$path_repo" add .
git -C "$path_repo" commit -qm backend-path
if run_scan "$path_repo" >/tmp/public-secret-path.out 2>&1; then
  echo "Expected backend path to fail secret scan" >&2
  exit 1
fi
grep -q "current export path denied" /tmp/public-secret-path.out

echo "public_repo_secret_scan tests passed"
