#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/macos-stable-release.yml"

if [[ ! -f "$WORKFLOW" ]]; then
  echo "Stable release workflow is missing: $WORKFLOW" >&2
  exit 1
fi

require_grep() {
  local pattern="$1"
  local description="$2"
  if ! grep -Eq -- "$pattern" "$WORKFLOW"; then
    echo "Workflow policy missing: $description" >&2
    exit 1
  fi
}

deny_grep() {
  local pattern="$1"
  local description="$2"
  if grep -Eq -- "$pattern" "$WORKFLOW"; then
    echo "Workflow policy violation: $description" >&2
    exit 1
  fi
}

require_grep '^  workflow_dispatch:$' 'workflow_dispatch trigger'
deny_grep '^  (push|pull_request):$' 'stable release workflow must not run on push or PR'
deny_grep 'refs/heads/main' 'stable releases must not build from main'
deny_grep '^    if:' 'a wrong-ref dispatch must fail red in the policy step, not skip the job'
require_grep 'refs/tags/v\[0-9\]' 'release tag guard'
require_grep 'OTTTO_RELEASE_SOURCE_REF: \$\{\{ github\.ref \}\}' 'attestation source ref from the release tag'
require_grep 'scripts/macos_release_source_check\.sh release' 'release source verification step'
require_grep 'actions: read' 'actions read permission for the Public CI evidence check'
require_grep 'fetch-depth: 0' 'full history for the first-parent check'
require_grep 'environment: macos-stable-release' 'protected release environment'
require_grep 'contents: write' 'contents write permission for the GitHub Release verification mirror'
require_grep 'id-token: write' 'OIDC permission for attestations'
require_grep 'attestations: write' 'attestation write permission'
require_grep 'artifact-metadata: write' 'artifact metadata permission'
deny_grep 'packages: write|deployments: write' 'public workflow must not have package or deployment publish permissions'
require_grep 'stable-candidate' 'stable-candidate channel option'
require_grep '^[[:space:]]+- stable$' 'stable channel option'
require_grep 'publish_intent:' 'publish_intent input'
require_grep '^[[:space:]]+- none$' 'publish_intent none-only option'
require_grep 'release_notes:' 'release_notes input'
# shellcheck disable=SC2016 # This assertion intentionally matches literal "$RELEASE_NOTES".
require_grep '--release-notes "\$RELEASE_NOTES"' 'release notes passed into macos_package before manifest signing'
require_grep 'ottto-release-bootstrap' 'bootstrap signing runner label'
require_grep 'ottto-signing-mac' 'release signing runner label'
require_grep 'ottto-cloud-mac' 'cloud signing runner label'
require_grep 'OTTTO_MACOS_STABLE_RUNNER_LABELS' 'cloud runner label variable hook'
require_grep 'actions/checkout@[0-9a-f]{40}' 'pinned checkout action'
require_grep 'actions/attest@[0-9a-f]{40}' 'pinned attest action'
require_grep 'actions/upload-artifact@[0-9a-f]{40}' 'pinned upload-artifact action'
require_grep 'scripts/macos_package\.sh' 'packaging step'
# shellcheck disable=SC2016 # These assertions intentionally match literal variables.
deny_grep '--app-root' 'the app root reaches macos_package through the runner environment, not argv'
require_grep 'test -n "\$\{OTTTO_MACOS_APP_ROOT:-\}"' 'app root required from the runner environment'
# shellcheck disable=SC2016
require_grep '--app-source-commit "\$OTTTO_MACOS_APP_SOURCE_COMMIT"' 'release-tag app source commit passed into macos_package'
# The release record names no private repository, so the workflow reads none.
if grep -Fq 'OTTTO_MACOS_APP_SOURCE_REPOSITORY' "$WORKFLOW"; then
  echo "macOS stable release workflow must not read an app source repository identity" >&2
  exit 1
fi
require_grep 'scripts/macos_notarize\.sh' 'notarization step'
require_grep 'scripts/macos_attestation_bind\.sh' 'attestation binding step'
require_grep 'scripts/macos_manifest_signature\.sh sign' 'manifest signature step'
require_grep 'scripts/macos_stable_preflight\.sh' 'stable preflight step'
require_grep '--record-sha256' 'install-macos.sh SHA-256 recorded in the stable manifest'
require_grep '--require-installer-sha256' 'new stable releases require the installer helper SHA-256'
require_grep 'dist/macos/stable-candidate-rc-qa\.json' 'stable-candidate RC evidence bound into the release folder'

# Release privacy gate: every outbound step reads sealed, checked copies.
require_grep 'OTTTO_RELEASE_PRIVACY_POLICY: \$\{\{ vars\.OTTTO_RELEASE_PRIVACY_POLICY \}\}' 'privacy policy from the release environment'
require_grep 'macos_privacy_gate\.py register-masks' 'privacy policy load and log masks'
require_grep 'macos_privacy_gate\.py scan --profile dispatch' 'dispatch input check'
require_grep '--stage prepare' 'unsigned prepare stage'
require_grep 'macos_privacy_gate\.py scan --profile unsigned' 'unsigned artifact check before signing'
require_grep '--stage finish' 'signing finish stage'
# shellcheck disable=SC2016 # These assertions match literal variables.
require_grep 'scan --profile attest .*--stage attest-1 .*--root "\$OTTTO_PRIVACY_WORK/attest-1"' 'first attestation subjects sealed'
# shellcheck disable=SC2016
require_grep 'scan --profile attest .*--stage attest-2 .*--root "\$OTTTO_PRIVACY_WORK/attest-2"' 'final attestation subjects sealed'
# shellcheck disable=SC2016
require_grep 'scan --profile upload .*--root "\$OTTTO_PRIVACY_WORK/upload"' 'upload set sealed'
require_grep 'path: \$\{\{ env\.OTTTO_PRIVACY_WORK \}\}/upload/$' 'uploader reads only the sealed upload folder'
require_grep 'name: ottto-macos-\$\{\{ inputs\.channel \}\}-\$\{\{ inputs\.version \}\}-attempt-\$\{\{ github\.run_attempt \}\}' 'artifact name carries the run attempt'
deny_grep 'subject-checksums: dist/macos|sbom-path: dist/macos' 'attestations must read sealed copies'
# shellcheck disable=SC2016 # These assertions match literal variables.
deny_grep '--keychain "\$OTTTO_MANUAL_SIGNING_KEYCHAIN"' 'tools get a neutral keychain link, not the keychain path'

# Optional, verification-only GitHub Release mirror.
require_grep 'github_release_mirror:' 'github_release_mirror input'
require_grep "inputs\.channel == 'stable' && inputs\.github_release_mirror == true" 'release mirror is stable-only and input-gated'
require_grep "if: false && inputs\.channel == 'stable' && inputs\.github_release_mirror == true" 'release mirror stays disabled until it publishes a checked folder'
require_grep 'gh release create' 'release mirror uses gh release create'
require_grep '--verify-tag' 'release mirror publishes the existing release tag only'
deny_grep '--target' 'release mirror must never create a tag'
require_grep 'gh release view' 'release mirror refuses an existing tag/release'
require_grep 'dist/macos/release-manifest\.json\.sig' 'release mirror uploads the signed manifest signature'
require_grep 'dist/macos/subject\.checksums\.txt' 'release mirror uploads the subject checksums'
deny_grep 'aws s3|cloudfront|stable/latest|promote_latest|local-platform publish' 'public workflow must not publish or promote stable/latest'

python3 - "$WORKFLOW" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
uses = re.findall(r"uses:\s*([^\s#]+)", workflow)
unpinned = [item for item in uses if not re.search(r"@[0-9a-f]{40}$", item)]
if unpinned:
    print(f"Workflow has unpinned actions: {', '.join(unpinned)}", file=sys.stderr)
    sys.exit(1)
if workflow.count("actions/attest@") < 4:
    print("Expected initial and final provenance/SBOM attestation steps", file=sys.stderr)
    sys.exit(1)
record = workflow.find("--record-sha256")
first_checksums = workflow.find("- name: Generate attestation subject checksums")
first_sign = workflow.find("scripts/macos_manifest_signature.sh sign")
if not (0 <= record < first_checksums < first_sign):
    print(
        "install-macos.sh SHA-256 must be recorded before attestation checksums and manifest signing",
        file=sys.stderr,
    )
    sys.exit(1)
steps = re.split(r"\n      - name: ", workflow)
names = [step.split("\n", 1)[0] for step in steps[1:]]
bodies = dict(zip(names, steps[1:]))
if names[:4] != ["Checkout", "Load release privacy policy", "Check dispatch inputs for private strings",
                 "Enforce dispatch policy"]:
    print("The privacy policy load, then the dispatch input check, must come first after checkout",
          file=sys.stderr)
    sys.exit(1)
# No input value in a policy message: the step's echo lines name no input variable.
for line in bodies["Enforce dispatch policy"].splitlines():
    if "echo" in line and re.search(r"\$\{?(VERSION|CHANNEL|ARTIFACT_BASE_URL|RELEASE_NOTES|RELEASE_MODE|"
                                   r"OPERATOR_APPROVAL|PUBLISH_INTENT|GITHUB_REF)\b", line):
        print("A dispatch policy message names an input value: " + line.strip(), file=sys.stderr)
        sys.exit(1)
# Release tools print paths, names and selector values: each runs through the
# fixed-status wrapper, whose output is one line.
quiet = re.compile(r"scripts/(macos_package|macos_notarize|macos_attestation_bind|macos_manifest_signature|"
                   r"macos_stable_preflight|homebrew_formula|hosted_native_installer|macos_release_source_check|"
                   r"macos_release_gate)\.sh")
for name, body in bodies.items():
    if "if: false" in body:
        continue
    for line in body.splitlines():
        if quiet.search(line) and "macos_quiet_step.sh" not in line:
            print(f"{name}: release tool output must go through macos_quiet_step.sh", file=sys.stderr)
            sys.exit(1)
for name, body in bodies.items():
    if "secrets.OTTTO_PRIVACY_MARKERS" in body and not (
        "macos_privacy_gate.py" in body or "scripts/macos_notarize.sh" in body
    ):
        print(f"Only gate steps may receive the marker list: {name}", file=sys.stderr)
        sys.exit(1)
job_env = workflow.split("    steps:", 1)[0]
if "OTTTO_PRIVACY_MARKERS" in job_env:
    print("The marker list must not be in the job environment", file=sys.stderr)
    sys.exit(1)
order = [
    ("Check dispatch inputs for private strings", "Prepare unsigned macOS artifacts"),
    ("Prepare unsigned macOS artifacts", "Check unsigned artifacts for private strings"),
    ("Check unsigned artifacts for private strings", "Package signed macOS artifacts"),
    ("Seal first attestation subjects", "Create provenance attestation"),
    ("Seal final attestation subjects", "Create final provenance attestation"),
    ("Seal upload set", "Upload release workflow artifacts"),
]
for before, after in order:
    if before not in names or after not in names or names.index(before) > names.index(after):
        print(f"Workflow step {before!r} must run before {after!r}", file=sys.stderr)
        sys.exit(1)
if names[-1] != "Remove sealed release copies" or "if: always()" not in bodies[names[-1]]:
    print("Sealed copies must be removed in a final always() step", file=sys.stderr)
    sys.exit(1)
in_run = False
for number, line in enumerate(workflow.splitlines(), 1):
    stripped = line.strip()
    if stripped == "run: |":
        in_run, indent = True, len(line) - len(line.lstrip()) + 2
        continue
    if in_run and stripped and len(line) - len(line.lstrip()) < indent:
        in_run = False
    if in_run and "${{" in line:
        print(f"Workflow line {number}: pass expressions to run blocks through env", file=sys.stderr)
        sys.exit(1)
PY

# [behaviour] Run the dispatch policy step itself against tag and version cases.
policy_dir="$(mktemp -d)"
trap 'rm -rf "$policy_dir"' EXIT
python3 - "$WORKFLOW" "$policy_dir/policy.sh" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
start = lines.index("      - name: Enforce dispatch policy")
run = next(i for i in range(start, len(lines)) if lines[i] == "        run: |")
body = []
for line in lines[run + 1 :]:
    if line.strip() and not line.startswith(" " * 10):
        break
    body.append(line[10:])
Path(sys.argv[2]).write_text("\n".join(body) + "\n", encoding="utf-8")
PY

# run_policy <ref> <channel> <version>: no app source identity is set.
run_policy() {
  env -i PATH="$PATH" \
    GITHUB_EVENT_NAME=workflow_dispatch \
    GITHUB_REF="$1" \
    CHANNEL="$2" \
    VERSION="$3" \
    ARTIFACT_BASE_URL="https://install.example.invalid/releases/$3" \
    RELEASE_NOTES="Policy fixture" \
    PUBLISH_INTENT=none \
    RELEASE_MODE=standard \
    OPERATOR_APPROVAL= \
    bash "$policy_dir/policy.sh" >"$policy_dir/out" 2>&1
}

expect_policy_accept() {
  if ! run_policy "$@"; then
    echo "Dispatch policy rejected $*:" >&2
    cat "$policy_dir/out" >&2
    exit 1
  fi
}

expect_policy_reject() {
  local expected="$1"
  shift
  if run_policy "$@"; then
    echo "Dispatch policy accepted $*" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$policy_dir/out"; then
    echo "Dispatch policy rejected $* without: $expected" >&2
    cat "$policy_dir/out" >&2
    exit 1
  fi
}

expect_policy_accept refs/tags/v0.1.2 stable 0.1.2
# A rejected input value is never printed back.
expect_policy_reject "Invalid version input." refs/tags/v0.1.2 stable "0.1.2 synthetic-input-value"
if grep -Fq "synthetic-input-value" "$policy_dir/out"; then
  echo "The dispatch policy printed a rejected input value" >&2
  exit 1
fi
expect_policy_accept refs/tags/v0.1.2 stable-candidate 0.1.2-rc1
expect_policy_accept refs/tags/v0.1.2 stable-candidate 0.1.2-rc12
expect_policy_reject "must run from a v<X.Y.Z> release tag" refs/heads/main stable 0.1.2
expect_policy_reject "must run from a v<X.Y.Z> release tag" refs/heads/v0.1.2 stable 0.1.2
expect_policy_reject "must run from a v<X.Y.Z> release tag" refs/tags/v0.1.2-rc1 stable-candidate 0.1.2-rc1
expect_policy_reject "must run from a v<X.Y.Z> release tag" refs/tags/release-0.1.2 stable 0.1.2
expect_policy_reject "does not match tag" refs/tags/v0.1.2 stable 0.1.3
expect_policy_reject "does not match tag" refs/tags/v0.1.2 stable 0.1.2-rc1
expect_policy_reject "must be 0.1.2-rc<N>" refs/tags/v0.1.2 stable-candidate 0.1.2
expect_policy_reject "must be 0.1.2-rc<N>" refs/tags/v0.1.2 stable-candidate 0.1.3-rc1
expect_policy_reject "must be 0.1.2-rc<N>" refs/tags/v0.1.2 stable-candidate 0.1.2-rcx
# The tag's dots are literal: tag v0.1.2 must not accept version 0.112-rc1.
expect_policy_reject "must be 0.1.2-rc<N>" refs/tags/v0.1.2 stable-candidate 0.112-rc1

echo "macos_stable_release_workflow tests passed"
