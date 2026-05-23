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
  if ! grep -Eq "$pattern" "$WORKFLOW"; then
    echo "Workflow policy missing: $description" >&2
    exit 1
  fi
}

deny_grep() {
  local pattern="$1"
  local description="$2"
  if grep -Eq "$pattern" "$WORKFLOW"; then
    echo "Workflow policy violation: $description" >&2
    exit 1
  fi
}

require_grep '^  workflow_dispatch:$' 'workflow_dispatch trigger'
deny_grep '^  (push|pull_request):$' 'stable release workflow must not run on push or PR'
require_grep 'github\.ref == '\''refs/heads/main'\''' 'main branch guard'
require_grep 'environment: macos-stable-release' 'protected release environment'
require_grep 'contents: read' 'read-only contents permission'
require_grep 'id-token: write' 'OIDC permission for attestations'
require_grep 'attestations: write' 'attestation write permission'
require_grep 'artifact-metadata: write' 'artifact metadata permission'
deny_grep 'contents: write|packages: write|deployments: write' 'public workflow must not have publish permissions'
require_grep 'stable-candidate' 'stable-candidate channel option'
require_grep '^[[:space:]]+- stable$' 'stable channel option'
require_grep 'publish_intent:' 'publish_intent input'
require_grep '^[[:space:]]+- none$' 'publish_intent none-only option'
require_grep 'ottto-release-bootstrap' 'bootstrap signing runner label'
require_grep 'ottto-signing-mac' 'release signing runner label'
require_grep 'ottto-cloud-mac' 'cloud signing runner label'
require_grep 'OTTTO_MACOS_STABLE_RUNNER_LABELS' 'cloud runner label variable hook'
require_grep 'actions/checkout@[0-9a-f]{40}' 'pinned checkout action'
require_grep 'actions/attest@[0-9a-f]{40}' 'pinned attest action'
require_grep 'actions/upload-artifact@[0-9a-f]{40}' 'pinned upload-artifact action'
require_grep 'scripts/macos_package\.sh' 'packaging step'
require_grep 'scripts/macos_notarize\.sh' 'notarization step'
require_grep 'scripts/macos_attestation_bind\.sh' 'attestation binding step'
require_grep 'scripts/macos_manifest_signature\.sh sign' 'manifest signature step'
require_grep 'scripts/macos_stable_preflight\.sh' 'stable preflight step'
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
PY

echo "macos_stable_release_workflow tests passed"
