#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_commit_guards.py"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# Follow the workflow policy test pattern and exercise the run block itself.
python3 - "$ROOT/.github/workflows/ci.yml" "$tmp_dir/step.sh" <<'PY'
import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
job = re.search(r"^  public-surface:\n(.*?)(?=^  \w|\Z)", workflow, re.M | re.S)
assert job, "Public surface job is missing"
job = job[1]
condition = (
    "${{ !github.event.pull_request.draft && !(github.event_name == 'workflow_dispatch'"
    " && (inputs.money_equivalence || inputs.scan_stack_margin)) }}"
)
assert re.findall(r"^    if: (.*)$", job, re.M) == [condition], "Public surface job condition changed"
assert not re.search(r"^    (needs|continue-on-error):", job, re.M), "Public surface job can skip or ignore failure"
step = re.search(r"^      - name: Check public commit identities and root\n(.*?)(?=^      - |\Z)", job, re.M | re.S)
assert step, "Commit guard step is missing"
assert not re.search(r"^        (if|continue-on-error):", step[1], re.M), "Commit guard step can skip or ignore failure"
run = step[1].split("        run: |\n", 1)[1]
assert "${{" not in run, "Pass workflow expressions to the commit guard through env"
Path(sys.argv[2]).write_text(run, encoding="utf-8")
PY

export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
unset PUBLIC_REPO_ROOT GITHUB_EVENT_NAME GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
export GIT_AUTHOR_NAME='Test Author' GIT_COMMITTER_NAME='Test Committer'
export GIT_AUTHOR_EMAIL='author@ottto.net' GIT_COMMITTER_EMAIL='committer@ottto.net'

mkdir "$tmp_dir/repo"
cd "$tmp_dir/repo"
git init -q --initial-branch=main --object-format=sha1
git commit --allow-empty -qm root
base="$(git rev-parse HEAD)"
git update-ref refs/remotes/origin/main "$base"
tree="$(git rev-parse 'HEAD^{tree}')"
mkdir scripts
ln -s "$SCRIPT" scripts/public_repo_commit_guards.py

out="$tmp_dir/out"
accept() {
  if ! "$@" >"$out" 2>&1 || [[ -s "$out" ]]; then
    echo 'Expected a silent commit guard pass' >&2
    exit 1
  fi
}

reject() {
  local sha="$1" reason="$2" status=0
  shift 2
  "$@" >"$out" 2>&1 || status=$?
  if [[ "$status" != 1 ]] || ! printf '%.12s %s\n' "$sha" "$reason" | cmp -s - "$out"; then
    printf 'Expected exit 1 with only the abbreviated SHA and rejection reason (%s), got exit %s\n' "$reason" "$status" >&2
    exit 1
  fi
}

make_commit() {
  git commit-tree "$tree" -p "$base" -m "$1"
}

guard() {
  python3 "$SCRIPT" "$@"
}

good="$(make_commit 'Good commit')"
accept guard --base "$base" --head "$good"
git reset -q --hard "$good"

bad_author="$(GIT_AUTHOR_EMAIL=author@example.test make_commit 'Wrong author')"
printf 'Approved <author@ottto.net> <author@example.test>\n' > .mailmap
reject "$bad_author" 'disallowed author email' guard --base "$base" --head "$bad_author"
bad_committer="$(GIT_COMMITTER_EMAIL=committer@example.test make_commit 'Wrong committer')"
reject "$bad_committer" 'disallowed committer email' guard --base "$base" --head "$bad_committer"
bad_committer_case="$(GIT_COMMITTER_EMAIL=NoReply@github.com make_commit 'Wrong committer case')"
reject "$bad_committer_case" 'disallowed committer email' guard --base "$base" --head "$bad_committer_case"
bad_author_name="$(GIT_AUTHOR_NAME='x@sample.corp' make_commit 'Wrong author name')"
reject "$bad_author_name" 'disallowed author or committer name email' guard --base "$base" --head "$bad_author_name"
bad_committer_name="$(GIT_COMMITTER_NAME='Contact x@sample.corp' make_commit 'Wrong committer name')"
reject "$bad_committer_name" 'disallowed author or committer name email' guard --base "$base" --head "$bad_committer_name"
web_flow="$(GIT_AUTHOR_EMAIL='1+test[bot]@Users.NoReply.GitHub.Com' GIT_COMMITTER_EMAIL=noreply@github.com make_commit 'Web commit')"
accept guard --base "$base" --head "$web_flow"
for address in noreply@github.com author@ottto.net.evil.com author@evilottto.net '"local name"@ottto.net'; do
  bad="$(GIT_AUTHOR_EMAIL="$address" make_commit 'Wrong author email')"
  reject "$bad" 'disallowed author email' guard --base "$base" --head "$bad"
done

for message in 'Subject outside@sample.corp' \
  $'Subject\n\nContact mailto:outside@sample.corp for details.' \
  $'Subject\n\nReviewed-by: Test <"outside contact"@sample.corp>' \
  'Contact "x outside@sample.corp"@ottto.net' \
  'Contact "x outside@sample.corp"@local' \
  'Use outside@ottto.net.evil.com or author@ottto.net' \
  'Contact outside@evilottto.net' \
  'Contact outside@anthropic.com' 'Contact outside@openai.com' 'Contact noreply@github.com'; do
  bad="$(make_commit "$message")"
  reject "$bad" 'disallowed commit message email' guard --base "$base" --head "$bad"
done

allowed_message="$(cat <<'MESSAGE'
Update pkg@1.2.3, install-action@v2.90.0, actions/checkout@main, and react@latest.

Use a@example.com, a@example.org, a@example.net, a@demo.example,
a@demo.invalid, a@demo.test, a@localhost, a@mail.example.com, or a@foo.localhost.

Co-authored-by: Test <noreply@anthropic.com>
Co-authored-by: Test <noreply@openai.com>
Signed-off-by: dependabot[bot] <support@github.com>
Co-authored-by: Test <"local name"@OTTTO.NET>
Co-authored-by: Test <1+test[bot]@users.noreply.github.com>
MESSAGE
)"
allowed="$(make_commit "$allowed_message")"
accept guard --base "$base" --head "$allowed"

bad_utf8="$(
  {
    printf 'tree %s\nparent %s\n' "$tree" "$base"
    printf 'author Test <author@ottto.net> 0 +0000\ncommitter Test <committer@ottto.net> 0 +0000\n'
    printf 'encoding ISO-8859-1\n\nInvalid UTF-8: \377\n'
  } | git hash-object -w -t commit --stdin
)"
reject "$bad_utf8" 'invalid UTF-8 commit data' guard --base "$base" --head "$bad_utf8"

zero=0000000000000000000000000000000000000000
missing=1111111111111111111111111111111111111111
reject "$good" 'base commit is missing or invalid' guard --base "$missing" --head "$good"
reject "$missing" 'head commit is missing or invalid' guard --base "$base" --head "$missing"
git tag -a -m 'Fixture tag' fixture "$good"
tag="$(git rev-parse fixture)"
reject "$tag" 'head commit is missing or invalid' guard --base "$base" --head "$tag"
reject "$base" 'empty commit range' guard --base "$base" --head "$base"
reject '------------' 'invalid head SHA' guard --base "$base" --head author@example.test
reject '------------' 'invalid arguments' guard --head "$good"

other_root="$(git commit-tree "$tree" -m 'Second root')"
two_roots="$(git commit-tree "$tree" -p "$good" -p "$other_root" -m 'Merge unrelated history')"
reject "$two_roots" 'head does not share the single base root' guard --base "$base" --head "$two_roots"
reject "$two_roots" 'head does not share the single base root' guard --root-only --head "$two_roots"
reject "$good" 'base must have one root' guard --base "$two_roots" --head "$good"
accept guard --root-only --head "$bad_author"
PUBLIC_REPO_ROOT="$base" accept guard --root-only --head "$good"
PUBLIC_REPO_ROOT="$other_root" reject "$good" 'configured root does not match base root' guard --root-only --head "$good"
PUBLIC_REPO_ROOT=invalid reject "$good" 'configured root does not match base root' guard --base "$base" --head "$good"
git replace "$bad_author" "$good"
reject "$bad_author" 'disallowed author email' guard --base "$base" --head "$bad_author"
git replace -d "$bad_author" >/dev/null
git clone -q --depth=1 "file://$PWD" "$tmp_dir/shallow"
(cd "$tmp_dir/shallow" && reject "$good" 'complete history required' guard --root-only --head "$good")

limit="$base"
for ((i = 1; i <= 250; i++)); do
  limit="$(git commit-tree "$tree" -p "$limit" -m "Fixture commit $i")"
done
accept guard --base "$base" --head "$limit"
over_limit="$(git commit-tree "$tree" -p "$limit" -m 'One more commit')"
reject "$over_limit" 'commit range exceeds 250 commits' guard --base "$base" --head "$over_limit"

run_event() (
  export GITHUB_EVENT_NAME="$1" GITHUB_SHA="${4:-$3}"
  case "$1" in
    pull_request) export PR_BASE="$2" PR_HEAD="$3" ;;
    merge_group) export QUEUE_BASE="$2" QUEUE_HEAD="$3" ;;
    push) export PUSH_BEFORE="$2" PUSH_AFTER="$3" ;;
  esac
  bash "$tmp_dir/step.sh"
)

accept run_event pull_request "$good" "$allowed"
reject "$good" 'base commit is missing or invalid' run_event pull_request '' "$good"
PUBLIC_REPO_ROOT="$other_root" reject "$good" 'configured root does not match base root' run_event pull_request "$base" "$good"
reject "$bad_author" 'disallowed author email' run_event pull_request "$base" "$bad_author"
accept run_event merge_group "$base" "$good"
reject "$allowed" 'merge group head does not match checkout' run_event merge_group "$base" "$allowed"
reject "$good" 'merge group head does not match checkout' run_event merge_group "$base" "$good" "$allowed"
reject "$good" 'cannot verify base ancestry' run_event merge_group "$allowed" "$good"
reject "$good" 'empty commit range' run_event merge_group "$good" "$good"
after_bad="$(git commit-tree "$tree" -p "$bad_author" -m 'Clean queue tip')"
git reset -q --hard "$after_bad"
reject "$bad_author" 'disallowed author email' run_event merge_group "$base" "$after_bad"
accept run_event push "$base" "$good"
reject "$bad_committer" 'disallowed committer email' run_event push "$base" "$bad_committer"
reject "$good" 'cannot verify base ancestry' run_event push "$allowed" "$good"
reject "$good" 'empty commit range' run_event push "$good" "$good"
accept run_event push "$zero" "$bad_author"
accept run_event schedule '' ''
accept run_event workflow_dispatch '' ''
git reset -q --hard "$two_roots"
reject "$two_roots" 'head does not share the single base root' run_event schedule '' ''
reject '------------' 'unsupported workflow event' run_event unknown '' ''

echo 'public_repo_commit_guards tests passed'
