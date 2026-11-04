#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/macos_release_source_check.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for command_name in git jq; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command not found: $command_name" >&2
    exit 2
  }
done

# Public main stand-in: the check fetches main by URL.
remote="$TMP_DIR/remote.git"
work="$TMP_DIR/work"
git init -q --bare "$remote"
git init -q "$work"
git -C "$work" config user.email "release-source-test@example.invalid"
git -C "$work" config user.name "Release Source Test"
git -C "$work" commit -q --allow-empty -m "base"
git -C "$work" commit -q --allow-empty -m "release commit"
release_sha="$(git -C "$work" rev-parse HEAD)"
git -C "$work" commit -q --allow-empty -m "later main commit"
main_sha="$(git -C "$work" rev-parse HEAD)"
git -C "$work" push -q "$remote" HEAD:refs/heads/main
git -C "$work" checkout -q "$release_sha"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="url.$remote.insteadOf"
export GIT_CONFIG_VALUE_0="https://github.com/ottto-ai/ottto.git"

app_commit="0123456789abcdef0123456789abcdef01234567"
tag_object="fedcba9876543210fedcba9876543210fedcba98"
fixtures="$TMP_DIR/fixtures"
mock_bin="$TMP_DIR/bin"
mkdir -p "$fixtures" "$mock_bin"

# gh mock: serves the fixture JSON for each API path, fails for anything else.
cat > "$mock_bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${GH_MOCK_LOG:?}"
[[ "$1" == "api" ]] || { echo "unexpected gh invocation: $*" >&2; exit 2; }
path=""
for arg in "$@"; do
  case "$arg" in repos/*) path="$arg" ;; esac
done
case "$path" in
  repos/ottto-ai/ottto/git/ref/tags/*) file=ref.json ;;
  repos/ottto-ai/ottto/git/tags/*) file=tag.json ;;
  repos/ottto-ai/ottto/actions/workflows/ci.yml/runs) file=runs.json ;;
  repos/ottto-ai/ottto/actions/runs/*/jobs) file=jobs.json ;;
  *) echo "unexpected gh api path: $*" >&2; exit 2 ;;
esac
[[ -f "$GH_FIXTURES/$file" ]] || { echo "HTTP 404: $path" >&2; exit 1; }
cat "$GH_FIXTURES/$file"
GH
chmod +x "$mock_bin/gh"
export PATH="$mock_bin:$PATH"
export GH_FIXTURES="$fixtures"
export GH_MOCK_LOG="$TMP_DIR/gh.log"

write_ref() {
  jq -n --arg type "$1" --arg sha "$2" \
    '{ref: "refs/tags/v0.1.2", object: {type: $type, sha: $sha}}' > "$fixtures/ref.json"
}

write_tag() {
  jq -n --arg sha "$1" --arg message "$2" \
    '{tag: "v0.1.2", object: {type: "commit", sha: $sha}, message: $message}' > "$fixtures/tag.json"
}

# write_run <head_sha> <head_branch> <head_repository>
write_run() {
  jq -n --arg sha "$1" --arg branch "$2" --arg repo "$3" '{
    workflow_runs: [
      {id: 41, event: "merge_group", status: "completed", conclusion: "success",
       head_sha: $sha, head_branch: $branch, head_repository: {full_name: $repo}},
      {id: 7, event: "merge_group", status: "completed", conclusion: "success",
       head_sha: $sha, head_branch: $branch, head_repository: {full_name: $repo}}
    ]
  }' > "$fixtures/runs.json"
}

# write_jobs <conclusion of Rust advisory audit>
write_jobs() {
  jq -n --arg audit "$1" '{
    jobs: [
      {name: "Rust contracts", status: "completed", conclusion: "success"},
      {name: "Public surface checks", status: "completed", conclusion: "success"},
      {name: "Rust advisory audit", status: "completed", conclusion: $audit},
      {name: "Dependency review", status: "completed", conclusion: "skipped"}
    ]
  }' > "$fixtures/jobs.json"
}

good_fixtures() {
  write_ref tag "$tag_object"
  write_tag "$release_sha" "$(printf 'Ottto 0.1.2\n\nApp-Source-Commit: %s\n' "$app_commit")"
  write_run "$release_sha" "gh-readonly-queue/main/pr-12-abc" ottto-ai/ottto
  write_jobs success
}

# run_check <ref> [sha]
run_check() {
  : > "$TMP_DIR/github_env"
  (
    cd "$work"
    GITHUB_REF="$1" GITHUB_SHA="${2:-$release_sha}" GITHUB_ENV="$TMP_DIR/github_env" \
      bash "$CHECK" release
  ) >"$TMP_DIR/out" 2>&1
}

expect_reject() {
  local label="$1"
  local expected="$2"
  shift 2
  if run_check "$@"; then
    echo "Expected release source check to fail: $label" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/out"; then
    echo "Release source check for $label did not report: $expected" >&2
    cat "$TMP_DIR/out" >&2
    exit 1
  fi
  if [[ -s "$TMP_DIR/github_env" ]]; then
    echo "Release source check wrote GITHUB_ENV after failing: $label" >&2
    exit 1
  fi
}

# [behaviour] A tested, first-parent main commit behind an annotated tag passes
# and exports the app source pin from the tag trailer.
good_fixtures
if ! run_check refs/tags/v0.1.2; then
  echo "Expected the release source check to pass" >&2
  cat "$TMP_DIR/out" >&2
  exit 1
fi
if [[ "$(cat "$TMP_DIR/github_env")" != "OTTTO_MACOS_APP_SOURCE_COMMIT=$app_commit" ]]; then
  echo "Release source check did not export the app source pin" >&2
  exit 1
fi
if ! grep -Fq "Public CI run 41" "$TMP_DIR/out"; then
  echo "Release source check did not pick the newest successful run" >&2
  exit 1
fi
if ! grep -Fq -- "-f filter=latest" "$GH_MOCK_LOG"; then
  echo "Release source check must read the latest attempt's jobs" >&2
  exit 1
fi

# [behaviour] ci-run alone prints the run id for the exact SHA.
if [[ "$(bash "$CHECK" ci-run "$release_sha")" != "41" ]]; then
  echo "ci-run did not print the newest successful run id" >&2
  exit 1
fi

# [behaviour] Only a v<X.Y.Z> tag ref is accepted.
expect_reject branch-ref "must be a refs/tags/v<X.Y.Z> release tag" refs/heads/main
expect_reject rc-tag-ref "must be a refs/tags/v<X.Y.Z> release tag" refs/tags/v0.1.2-rc1
expect_reject head-mismatch "checked-out HEAD is not" refs/tags/v0.1.2 "$(git -C "$work" rev-parse HEAD~1)"

# [behaviour] The tag must be annotated and point at the built commit.
write_ref commit "$release_sha"
expect_reject lightweight-tag "must be an annotated tag" refs/tags/v0.1.2
good_fixtures
write_tag "$(git -C "$work" rev-parse HEAD~1)" "App-Source-Commit: $app_commit"
expect_reject tag-elsewhere "does not point at commit" refs/tags/v0.1.2

# [behaviour] Exactly one valid App-Source-Commit trailer.
trailer_error="must carry exactly one 'App-Source-Commit: <40-hex>' trailer"
write_tag "$release_sha" "Ottto 0.1.2"
expect_reject missing-trailer "$trailer_error" refs/tags/v0.1.2
write_tag "$release_sha" "App-Source-Commit: ${app_commit:0:12}"
expect_reject short-trailer "$trailer_error" refs/tags/v0.1.2
write_tag "$release_sha" "App-Source-Commit: $(printf '%s' "$app_commit" | tr 'a-f' 'A-F')"
expect_reject uppercase-trailer "$trailer_error" refs/tags/v0.1.2
write_tag "$release_sha" "$(printf 'App-Source-Commit: %s\nApp-Source-Commit: %s' "$app_commit" "$app_commit")"
expect_reject duplicate-trailer "$trailer_error" refs/tags/v0.1.2

# [behaviour] The commit must be on main's first-parent line.
good_fixtures
git -C "$work" checkout -q -b side "$release_sha"
git -C "$work" commit -q --allow-empty -m "side commit"
side_sha="$(git -C "$work" rev-parse HEAD)"
write_tag "$side_sha" "App-Source-Commit: $app_commit"
write_run "$side_sha" "gh-readonly-queue/main/pr-13-def" ottto-ai/ottto
expect_reject not-on-main "is not on the first-parent line of main" refs/tags/v0.1.2 "$side_sha"
# Merged into main as a second parent only: still not first-parent.
git -C "$work" checkout -q "$main_sha"
git -C "$work" merge -q --no-ff -m "merge side" "$side_sha"
git -C "$work" push -q "$remote" HEAD:refs/heads/main
git -C "$work" checkout -q "$side_sha"
expect_reject second-parent "is not on the first-parent line of main" refs/tags/v0.1.2 "$side_sha"
git -C "$work" checkout -q "$release_sha"

# [behaviour] A successful merge_group run for the exact SHA with the three jobs.
good_fixtures
printf '{"workflow_runs":[]}\n' > "$fixtures/runs.json"
expect_reject no-run "no successful Public CI merge_group run" refs/tags/v0.1.2
write_run "$(git -C "$work" rev-parse HEAD~1)" "gh-readonly-queue/main/pr-12-abc" ottto-ai/ottto
expect_reject other-sha-run "no successful Public CI merge_group run" refs/tags/v0.1.2
write_run "$release_sha" "main" ottto-ai/ottto
expect_reject push-run "no successful Public CI merge_group run" refs/tags/v0.1.2
write_run "$release_sha" "gh-readonly-queue/main/pr-12-abc" someone/ottto
expect_reject fork-run "no successful Public CI merge_group run" refs/tags/v0.1.2
good_fixtures
write_jobs failure
expect_reject failed-job 'has no successful "Rust advisory audit" job' refs/tags/v0.1.2

echo "macos_release_source_check tests passed"
