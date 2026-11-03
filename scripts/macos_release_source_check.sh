#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${OTTTO_RELEASE_REPOSITORY:-ottto-ai/ottto}"
REQUIRED_JOBS=("Rust contracts" "Public surface checks" "Rust advisory audit")

usage() {
  cat <<'USAGE'
Usage: macos_release_source_check.sh release
       macos_release_source_check.sh ci-run <sha>

release  Verifies the source of a macOS stable release run. Reads GITHUB_REF,
         GITHUB_SHA and GITHUB_ENV from the environment and requires:
         - GITHUB_REF is refs/tags/v<X.Y.Z> and names an annotated tag whose
           object is the commit GITHUB_SHA, which is also the checked-out HEAD;
         - the tag message carries exactly one trailer
           "App-Source-Commit: <40-hex>";
         - GITHUB_SHA is on the first-parent line of a freshly fetched main;
         - ci-run passes for GITHUB_SHA.
         Writes OTTTO_MACOS_APP_SOURCE_COMMIT=<trailer value> to GITHUB_ENV.

ci-run   Prints the id of the newest successful "Public CI" merge_group run
         for exactly <sha>: head branch gh-readonly-queue/main/..., head
         repository the release repository, and the latest attempt's jobs
         Rust contracts, Public surface checks and Rust advisory audit all
         successful. Fails when there is none.

The repository is OTTTO_RELEASE_REPOSITORY (default ottto-ai/ottto). gh uses
its usual GH_TOKEN or login.
USAGE
}

fail() {
  echo "release-source: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

ci_run() {
  local sha="$1"
  local run_id job_names job
  run_id="$(
    gh api -X GET "repos/$REPOSITORY/actions/workflows/ci.yml/runs" \
      -f head_sha="$sha" -f event=merge_group -f status=success -f per_page=100 |
      jq -r --arg sha "$sha" --arg repo "$REPOSITORY" '
        [.workflow_runs[]?
          | select(
              .event == "merge_group"
              and .status == "completed"
              and .conclusion == "success"
              and .head_sha == $sha
              and (.head_branch // "" | startswith("gh-readonly-queue/main/"))
              and .head_repository.full_name == $repo
              and (.id | type) == "number"
            )]
        | sort_by(.id) | last | .id // empty'
  )" || fail "could not list Public CI runs for $sha"
  [[ "$run_id" =~ ^[0-9]+$ ]] ||
    fail "no successful Public CI merge_group run for $sha"
  job_names="$(
    gh api -X GET "repos/$REPOSITORY/actions/runs/$run_id/jobs" \
      -f filter=latest -f per_page=100 |
      jq -r '.jobs[]? | select(.status == "completed" and .conclusion == "success") | .name'
  )" || fail "could not list jobs of Public CI run $run_id"
  for job in "${REQUIRED_JOBS[@]}"; do
    grep -qxF "$job" <<<"$job_names" ||
      fail "Public CI run $run_id has no successful \"$job\" job"
  done
  printf '%s\n' "$run_id"
}

release() {
  local tag ref_json tag_object tag_json trailers app_commit main_tip run_id
  local trailer_re='^App-Source-Commit: ([0-9a-f]{40})$'
  [[ "${GITHUB_REF:-}" =~ ^refs/tags/v[0-9]+[.][0-9]+[.][0-9]+$ ]] ||
    fail "GITHUB_REF must be a refs/tags/v<X.Y.Z> release tag: ${GITHUB_REF:-<unset>}"
  tag="${GITHUB_REF#refs/tags/}"
  [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA must be a 40-hex commit"
  [[ -n "${GITHUB_ENV:-}" ]] || fail "GITHUB_ENV is required"
  [[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || fail "checked-out HEAD is not $GITHUB_SHA"

  ref_json="$(gh api "repos/$REPOSITORY/git/ref/tags/$tag")" || fail "could not read tag $tag"
  [[ "$(jq -r '.ref' <<<"$ref_json")" == "$GITHUB_REF" &&
    "$(jq -r '.object.type' <<<"$ref_json")" == "tag" ]] ||
    fail "$tag must be an annotated tag"
  tag_object="$(jq -r '.object.sha' <<<"$ref_json")"
  [[ "$tag_object" =~ ^[0-9a-f]{40}$ ]] || fail "$tag has no tag object"
  tag_json="$(gh api "repos/$REPOSITORY/git/tags/$tag_object")" || fail "could not read tag object of $tag"
  [[ "$(jq -r '.tag' <<<"$tag_json")" == "$tag" &&
    "$(jq -r '.object.type' <<<"$tag_json")" == "commit" &&
    "$(jq -r '.object.sha' <<<"$tag_json")" == "$GITHUB_SHA" ]] ||
    fail "$tag does not point at commit $GITHUB_SHA"
  trailers="$(jq -r '.message' <<<"$tag_json" | grep -E '^App-Source-Commit:' || true)"
  # One line exactly: the anchors span the whole string, so a second trailer fails.
  [[ "$trailers" =~ $trailer_re ]] ||
    fail "$tag message must carry exactly one 'App-Source-Commit: <40-hex>' trailer"
  app_commit="${BASH_REMATCH[1]}"

  git fetch -q --no-tags "https://github.com/$REPOSITORY.git" refs/heads/main ||
    fail "could not fetch main"
  main_tip="$(git rev-parse FETCH_HEAD)"
  git rev-list --first-parent "$main_tip" | grep -xF "$GITHUB_SHA" >/dev/null ||
    fail "$GITHUB_SHA is not on the first-parent line of main ($main_tip)"

  run_id="$(ci_run "$GITHUB_SHA")"
  printf 'OTTTO_MACOS_APP_SOURCE_COMMIT=%s\n' "$app_commit" >>"$GITHUB_ENV"
  echo "release-source: $tag -> $GITHUB_SHA (first-parent on main $main_tip, Public CI run $run_id), app source $app_commit"
}

require_command gh
require_command jq
if [[ ! "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Repository must be owner/repo: $REPOSITORY" >&2
  exit 2
fi

case "${1:-}" in
  release)
    [[ $# -eq 1 ]] || { usage >&2; exit 2; }
    release
    ;;
  ci-run)
    [[ $# -eq 2 && "$2" =~ ^[0-9a-f]{40}$ ]] || { usage >&2; exit 2; }
    ci_run "$2"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
