#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PUBLIC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PUBLIC_ROOT="${PUBLIC_CONTRACT_REPO_ROOT:-$DEFAULT_PUBLIC_ROOT}"
PRIVATE_REPO_ROOT="${PUBLIC_CONTRACT_PRIVATE_REPO_ROOT:-}"
PRIVATE_RUNTIME_PIN="${PUBLIC_CONTRACT_PRIVATE_RUNTIME_PIN:-}"
REQUIRE_PUBLIC_AUTHORITY="${PUBLIC_CONTRACT_REQUIRE_PUBLIC_AUTHORITY:-false}"

usage() {
  cat <<'USAGE'
Usage: public_repo_contract_check.sh [--staged-output <dir>] [--private-repo-root <dir>] [--private-runtime-pin <path>] [--require-public-authority]

Checks that a root-shaped public ottto repository checkout carries the JSON,
schema, registry, setup, and redaction contracts consumed by the private Ottto
backend/frontend. By default the script checks the repository root containing
scripts/. Use --staged-output to check a generated public export bundle. When
--private-repo-root is supplied, the private repository must also carry a
public-runtime pin whose manifest digest matches the checked public root.
Use --require-public-authority after public repo cutover: it requires the
private pin to name a public repo commit and verifies that the checked public
root is a clean git checkout at that commit.

Environment overrides:
  PUBLIC_CONTRACT_REPO_ROOT
  PUBLIC_CONTRACT_PRIVATE_REPO_ROOT
  PUBLIC_CONTRACT_PRIVATE_RUNTIME_PIN
  PUBLIC_CONTRACT_REQUIRE_PUBLIC_AUTHORITY
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --staged-output)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --staged-output requires a value" >&2
        exit 2
      }
      PUBLIC_ROOT="$2"
      shift 2
      ;;
    --private-repo-root)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --private-repo-root requires a value" >&2
        exit 2
      }
      PRIVATE_REPO_ROOT="$2"
      shift 2
      ;;
    --private-runtime-pin)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --private-runtime-pin requires a value" >&2
        exit 2
      }
      PRIVATE_RUNTIME_PIN="$2"
      shift 2
      ;;
    --require-public-authority)
      REQUIRE_PUBLIC_AUTHORITY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-contract: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

python3 - "$PUBLIC_ROOT" "$PRIVATE_REPO_ROOT" "$PRIVATE_RUNTIME_PIN" "$REQUIRE_PUBLIC_AUTHORITY" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

PUBLIC_PROTOCOL_VERSION = 15
PUBLIC_ROOT = Path(sys.argv[1]).resolve()
PRIVATE_REPO_ROOT = Path(sys.argv[2]).resolve() if sys.argv[2] else None
PRIVATE_RUNTIME_PIN_ARG = sys.argv[3]
REQUIRE_PUBLIC_AUTHORITY = sys.argv[4].lower() in {"1", "true", "yes"}
REQUIRED_CONNECTOR_REDACTION_CLASSES = {
    "prompt",
    "response",
    "tool_output",
    "command_output",
    "local_path",
    "credential",
}
FORBIDDEN_CONNECTOR_SAMPLE_KEYS = {
    "api_key",
    "command_output",
    "cookie",
    "credential",
    "credentials",
    "local_path",
    "password",
    "prompt",
    "prompts",
    "raw_content",
    "raw_prompt",
    "raw_response",
    "response",
    "responses",
    "secret",
    "tool_output",
}

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def die(message: str, code: int = 2) -> None:
    print(f"public-contract: {message}", file=sys.stderr)
    sys.exit(code)


def require_file(relative_path: str) -> Path | None:
    path = PUBLIC_ROOT / relative_path
    if not path.is_file():
        fail(f"required file is missing: {relative_path}")
        return None
    return path


def require_private_file(relative_path: str) -> Path | None:
    if PRIVATE_REPO_ROOT is None:
        return None
    path = PRIVATE_REPO_ROOT / relative_path
    if not path.is_file():
        fail(f"private consumer file is missing: {relative_path}")
        return None
    return path


def private_runtime_pin_path() -> tuple[Path | None, str]:
    default_relative = "backend/app/domain/local_platform/public_runtime_pin.json"
    if PRIVATE_REPO_ROOT is None:
        return None, default_relative
    if PRIVATE_RUNTIME_PIN_ARG:
        path = Path(PRIVATE_RUNTIME_PIN_ARG)
        if not path.is_absolute():
            path = PRIVATE_REPO_ROOT / path
        return path.resolve(), PRIVATE_RUNTIME_PIN_ARG
    return (PRIVATE_REPO_ROOT / default_relative).resolve(), default_relative


def load_json(relative_path: str) -> Any | None:
    path = require_file(relative_path)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{relative_path}: invalid JSON: {error}")
        return None


def load_toml(relative_path: str) -> Any | None:
    path = require_file(relative_path)
    if path is None:
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        fail(f"{relative_path}: invalid TOML: {error}")
        return None


def load_ndjson(relative_path: str) -> list[dict[str, Any]]:
    path = require_file(relative_path)
    if path is None:
        return []
    events: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as error:
            fail(f"{relative_path}:{line_number}: invalid NDJSON event: {error}")
            continue
        if not isinstance(event, dict):
            fail(f"{relative_path}:{line_number}: event must be a JSON object")
            continue
        events.append(event)
    if not events:
        fail(f"{relative_path}: no NDJSON events found")
    return events


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def expect_protocol(value: Any, context: str) -> None:
    expect(value == PUBLIC_PROTOCOL_VERSION, f"{context} protocol_version must be {PUBLIC_PROTOCOL_VERSION}")


def git_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(PUBLIC_ROOT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"public authority git check failed for {' '.join(args)}: {error}")
        return None
    return result.stdout.strip()


def require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} must be a JSON object")
        return {}
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{context} must be a JSON array")
        return []
    return value


def string_list(value: Any, context: str) -> list[str]:
    return [
        item
        for item in require_list(value, context)
        if isinstance(item, str)
    ]


def expect_same_string_field(left: dict[str, Any], right: dict[str, Any], field: str, message: str) -> None:
    expect(isinstance(left.get(field), str) and bool(left.get(field)), f"{message} {field} must be non-empty")
    expect(left.get(field) == right.get(field), f"{message} {field} must match registry")


def expect_same_string_list(
    left: dict[str, Any],
    right_values: list[str],
    field: str,
    message: str,
    *,
    allow_empty: bool = False,
) -> None:
    values = string_list(left.get(field), f"{message} {field}")
    if not allow_empty:
        expect(values, f"{message} {field} must not be empty")
    expect(sorted(values) == sorted(right_values), f"{message} {field} must match registry")


def check_source_docs_contract(
    source_dir: Path,
    display_name: str,
    collector_ids: list[str],
) -> None:
    relative_source_dir = source_dir.relative_to(PUBLIC_ROOT).as_posix()
    readme_path = source_dir / "README.md"
    policy_path = source_dir / "POLICY.md"
    if not readme_path.is_file():
        fail(f"{relative_source_dir}/README.md is required for public source package docs")
        return
    if not policy_path.is_file():
        fail(f"{relative_source_dir}/POLICY.md is required for public source package policy")
        return

    readme_text = readme_path.read_text(encoding="utf-8")
    policy_text = policy_path.read_text(encoding="utf-8")
    expect(
        display_name in readme_text,
        f"{relative_source_dir}/README.md must name source display_name {display_name}",
    )
    expect(
        "Collectors:" in readme_text,
        f"{relative_source_dir}/README.md must include a Collectors section",
    )
    for collector_id in collector_ids:
        expect(
            f"`{collector_id}`" in readme_text,
            f"{relative_source_dir}/README.md must document collector {collector_id}",
        )
    expect(
        "Raw prompts" in readme_text or "raw prompts" in readme_text,
        f"{relative_source_dir}/README.md must document raw prompt/content upload boundary",
    )

    expect(
        f"# {display_name} Source Policy" in policy_text,
        f"{relative_source_dir}/POLICY.md must be titled for {display_name}",
    )
    for heading in (
        "## Default Posture",
        "## Documented Surfaces",
        "## Undocumented Surfaces",
        "## Local-Only Behavior",
        "## Upload Boundaries",
    ):
        expect(
            heading in policy_text,
            f"{relative_source_dir}/POLICY.md must include {heading}",
        )
    expect(
        "Review tier: `official`" in policy_text,
        f"{relative_source_dir}/POLICY.md must preserve official review tier",
    )
    expect(
        "Do not upload" in policy_text,
        f"{relative_source_dir}/POLICY.md must document upload prohibitions",
    )


def check_connector_docs_contracts() -> None:
    docs_path = require_file("docs/connectors.md")
    if docs_path is not None:
        text = docs_path.read_text(encoding="utf-8")
        expectations = [
            (
                "Use the public Rust testkit helpers in source-package tests instead of copying\nbackend generator logic",
                "connector docs must route source-package tests through the public Rust testkit",
            ),
            (
                "assert_collector_manifest_contract",
                "connector docs must document collector manifest testkit assertions",
            ),
            (
                "CollectorManifestContract",
                "connector docs must document the collector manifest contract helper",
            ),
            (
                "uv run python scripts/generate_connector_registry.py --check",
                "connector docs must preserve registry generator check command",
            ),
            (
                "Official first-party fixtures must not expose raw prompts, responses, tool\n  output, command output, local paths, credentials, cookies, API keys,\n  passwords, or secrets.",
                "connector docs must preserve fixture raw-content prohibition",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)

    readme_path = require_file("connectors/README.md")
    if readme_path is not None:
        text = readme_path.read_text(encoding="utf-8")
        expectations = [
            (
                "## SDK And Testkit Helpers",
                "connector README must include SDK/testkit helper section",
            ),
            (
                "`ottto-connector-sdk` owns schema-version constants",
                "connector README must document SDK ownership",
            ),
            (
                "`ottto-connector-testkit` owns contract assertion helpers",
                "connector README must document testkit ownership",
            ),
            (
                "ottto-connector-testkit/tests/first_party_sources.rs",
                "connector README must name first-party source contract tests",
            ),
            (
                "Use the testkit in source package tests instead of copying backend generator\nlogic",
                "connector README must prohibit copying backend generator logic into source tests",
            ),
            (
                "-p ottto-connector-testkit \\\n    --test first_party_sources",
                "connector README must preserve first-party source test command",
            ),
            (
                "Changing manifests without updating the\ngenerated registry is incomplete",
                "connector README must require registry refresh with manifest changes",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)


def check_docs_index_contracts() -> None:
    docs_index = require_file("docs/README.md")
    if docs_index is None:
        return

    text = docs_index.read_text(encoding="utf-8")
    expectations = [
        (
            "not private development scripts",
            "docs index must keep private development scripts out of public setup",
        ),
        ("[Install](install.md)", "docs index must link install docs"),
        ("[Setup](setup.md)", "docs index must link setup docs"),
        ("[Privacy](privacy.md)", "docs index must link privacy docs"),
        ("[Diagnostics](diagnostics.md)", "docs index must link diagnostics docs"),
        ("[Support Runbook](support.md)", "docs index must link support runbook"),
        ("[Connector Contribution](connectors.md)", "docs index must link connector contribution docs"),
        ("[Agent Adapters](agent-adapters.md)", "docs index must link agent adapter docs"),
        ("[Release Verification](release-verification.md)", "docs index must link release verification docs"),
        ("[Troubleshooting](troubleshooting.md)", "docs index must link troubleshooting docs"),
        ("[Examples](examples.md)", "docs index must link examples docs"),
        (
            "Automation should consume only `ottto --json` output",
            "docs index must require automation to consume JSON output",
        ),
        (
            "`--json --watch` emits newline-delimited JSON progress events and a final event",
            "docs index must document NDJSON watch semantics",
        ),
        (
            "Customer-facing commands use app language",
            "docs index must preserve public app-language command guidance",
        ),
        ("ottto apps --json", "docs index must include apps JSON command"),
        ("ottto setup --json", "docs index must include setup JSON command"),
        (
            "ottto diagnostics collect --json",
            "docs index must include diagnostics JSON command",
        ),
        (
            "public docs should prefer `apps` and `--app`",
            "docs index must prefer apps and --app over lower-level source nouns",
        ),
    ]
    for needle, message in expectations:
        expect(needle in text, message)


def check_examples_docs_contracts() -> None:
    examples_docs = require_file("docs/examples.md")
    if examples_docs is None:
        return

    text = examples_docs.read_text(encoding="utf-8")
    expectations = [
        ("consume only JSON\noutput", "examples docs must keep examples JSON-only"),
        ("ottto status --json", "examples docs must include status JSON command"),
        ("ottto account --json", "examples docs must include account JSON command"),
        ("ottto apps --json", "examples docs must include apps JSON command"),
        ("ottto context --json", "examples docs must include context JSON command"),
        (
            "ottto context --json --range today --source codex",
            "examples docs must include source-scoped context JSON command",
        ),
        (
            "ottto context --json --all-machines --max-tokens 4000",
            "examples docs must include bounded all-machines context JSON command",
        ),
        (
            "ottto costs --json --range today --source codex",
            "examples docs must include source-scoped costs JSON command",
        ),
        (
            "ottto costs --json --all-machines --bucket day",
            "examples docs must include all-machines cost bucket JSON command",
        ),
        (
            "ottto sessions --json --limit 20 --source codex",
            "examples docs must include bounded source-scoped sessions JSON command",
        ),
        (
            "ottto sessions --json --all-machines --sort-by cost --sort-dir desc",
            "examples docs must include bounded all-machines sessions JSON command",
        ),
        ("machine-readable agent surfaces", "examples docs must preserve machine-readable agent guidance"),
        ("require this Mac to be connected", "examples docs must document connected-Mac requirement"),
        ("`--app", "examples docs must document app alias flag"),
        ("codex|claude-code|pi", "examples docs must list public app aliases"),
        ("`--source`", "examples docs must document source slug flag"),
        ("backend source slugs", "examples docs must explain source slugs as backend values"),
        (
            "ottto setup --json --no-browser --no-wait",
            "examples docs must include headless setup JSON command",
        ),
        ("exits `60`", "examples docs must document setup exit 60"),
        ("`claim_url`", "examples docs must preserve claim_url handoff"),
        ("`claim_code`", "examples docs must preserve claim_code handoff"),
        (
            "treat the nonzero exit as a corrupt response",
            "examples docs must preserve nonzero JSON setup boundary",
        ),
        (
            "ottto apps status --app claude-code --json",
            "examples docs must include Claude Code app status command",
        ),
        (
            "ottto verify --app claude-code --json",
            "examples docs must include Claude Code read-only verify command",
        ),
        (
            "ottto verify --repair --app claude-code --json",
            "examples docs must include Claude Code bounded repair command",
        ),
        ("Plain verify is read-only", "examples docs must preserve read-only verify boundary"),
        (
            "Use `--repair` only when the JSON reports config drift",
            "examples docs must keep repair conditional on JSON config drift",
        ),
        (
            "daemon-owned WriteConfig",
            "examples docs must preserve daemon-owned WriteConfig repair boundary",
        ),
        ("ottto doctor --json", "examples docs must include doctor JSON command"),
        (
            "ottto verify --repair --app codex --json",
            "examples docs must include Codex bounded repair command",
        ),
        ("ottto fix --app codex --json", "examples docs must include Codex fix JSON command"),
        ("ottto verify --app codex --json", "examples docs must include Codex post-fix verify command"),
        ("Apply repair only through `ottto fix`", "examples docs must route Codex repair through ottto fix"),
        (
            "Do not patch `~/.codex/config.toml`\ndirectly",
            "examples docs must prohibit direct Codex config patching",
        ),
        ("ottto diagnostics collect --json", "examples docs must include diagnostics JSON command"),
        (
            "Summarize the redaction report",
            "examples docs must preserve diagnostics redaction summary guidance",
        ),
        ("ottto diagnostics collect --upload", "examples docs must include diagnostics upload command"),
        ("--approve-upload", "examples docs must require upload approval flag"),
        ("--accept-retention-disclosure", "examples docs must require retention disclosure flag"),
        ("--support-claim <claim>", "examples docs must require support claim argument shape"),
        (
            "Use this only after the user approves upload and retention disclosure",
            "examples docs must preserve diagnostics upload approval boundary",
        ),
        ("ottto update check --json", "examples docs must include update check JSON command"),
        ("install owner", "examples docs must preserve install-owner update guidance"),
    ]
    for needle, message in expectations:
        expect(needle in text, message)


def check_privacy_docs_contracts() -> None:
    privacy_docs = require_file("docs/privacy.md")
    if privacy_docs is None:
        return

    text = privacy_docs.read_text(encoding="utf-8")
    expectations = [
        (
            "local state and secret material on the Mac unless a user-approved setup or\n"
            "diagnostics flow sends a redacted payload",
            "privacy docs must preserve local-first redacted-upload boundary",
        ),
        ("`ottto-service` owns:", "privacy docs must name ottto-service as local owner"),
        ("local control token storage", "privacy docs must keep control token storage daemon-owned"),
        ("diagnostics redaction", "privacy docs must keep diagnostics redaction daemon-owned"),
        (
            "Agents, the CLI, the macOS app, and the web app are clients",
            "privacy docs must keep agents and apps as clients",
        ),
        (
            "should not\nduplicate local setup or repair logic",
            "privacy docs must prohibit duplicate setup/repair logic",
        ),
        (
            "must not upload raw prompts, raw responses, tool output,\n"
            "command output, browser cookies, OAuth credentials, API keys, passwords,\n"
            "absolute local paths, or raw provider account ids",
            "privacy docs must prohibit uploading raw private local data",
        ),
        ("derived and redacted fields", "privacy docs must require derived/redacted snapshot fields"),
        ("hashed workspace identity", "privacy docs must preserve hashed workspace identity wording"),
        ("display-safe account or plan evidence", "privacy docs must preserve display-safe account evidence"),
        ("Live telemetry is source-level opt-in", "privacy docs must keep live telemetry source-level opt-in"),
        (
            "Opt-out must remove fenced\nlocal config or Keychain state before backend setup-key revocation completes",
            "privacy docs must preserve opt-out local cleanup ordering",
        ),
        ("`ottto fix --json` returns repair authority metadata", "privacy docs must preserve fix authority metadata"),
        (
            "Terminal repair is allowed\nonly for setup-safe actions tied to an active setup-run binding",
            "privacy docs must keep terminal repair setup-run bound",
        ),
        (
            "Credential,\nauth-adjacent, stale-account, or disconnected cases require browser approval",
            "privacy docs must require browser approval for auth-adjacent repair",
        ),
        ("`ottto verify --repair --json` is narrower", "privacy docs must keep verify repair narrower than fix"),
        (
            "can repair only Codex or Claude\nCode WriteConfig drift",
            "privacy docs must bound verify repair to Codex/Claude WriteConfig drift",
        ),
        (
            "`OTTTO_PATCH_CODEX_DISABLED` and\n"
            "`OTTTO_PATCH_CLAUDE_CODE_DISABLED` block repair writes and return\n"
            "`patch_disabled`",
            "privacy docs must preserve patch-disabled repair block",
        ),
        (
            "Uploads require explicit\napproval, retention disclosure acceptance, and either an active login or a\nsupport claim",
            "privacy docs must require diagnostics upload approval, retention, and authorization",
        ),
        (
            "Redaction covers local paths, secret tokens, account identifiers,\n"
            "machine identifiers, raw prompts, and command output before display or upload",
            "privacy docs must list diagnostics redaction categories before display/upload",
        ),
        (
            "Do not paste full\ndiagnostics payloads or raw JSON containing local identifiers",
            "privacy docs must prohibit pasting full diagnostics payloads",
        ),
        (
            "reviewed for redaction",
            "privacy docs must require redaction review before sharing diagnostics JSON",
        ),
    ]
    for needle, message in expectations:
        expect(needle in text, message)


def check_setup_output_shape(payload: dict[str, Any], context: str) -> list[dict[str, Any]]:
    source_count = payload.get("source_count")
    detected_sources = require_list(payload.get("detected_sources"), f"{context} detected_sources")
    actions = require_list(payload.get("actions"), f"{context} actions")
    agent_action = require_dict(payload.get("agent_action"), f"{context} agent_action")
    expect(isinstance(agent_action.get("kind"), str) and bool(agent_action.get("kind")), f"{context} agent_action.kind must be non-empty")
    expect(isinstance(agent_action.get("requires_user"), bool), f"{context} agent_action.requires_user must be boolean")
    expect(isinstance(agent_action.get("retryable"), bool), f"{context} agent_action.retryable must be boolean")
    expect(isinstance(agent_action.get("description"), str) and bool(agent_action.get("description")), f"{context} agent_action.description must be non-empty")
    expect(isinstance(source_count, int) and source_count >= 0, f"{context} source_count must be a non-negative integer")
    if isinstance(source_count, int):
        expect(source_count == len(detected_sources), f"{context} source_count must match detected_sources length")
    expect(not (payload.get("next_question") is not None and payload.get("next_action") is not None), f"{context} must not set both next_question and next_action")
    for index, source_value in enumerate(detected_sources):
        source = require_dict(source_value, f"{context} detected_sources[{index}]")
        expect(isinstance(source.get("source"), str) and bool(source.get("source")), f"{context} detected_sources[{index}].source must be non-empty")
        expect(isinstance(source.get("state"), str) and bool(source.get("state")), f"{context} detected_sources[{index}].state must be non-empty")
        readiness = source.get("readiness_percent")
        expect(isinstance(readiness, int) and 0 <= readiness <= 100, f"{context} detected_sources[{index}].readiness_percent must be 0-100")
        missing_fields = require_list(source.get("missing_fields"), f"{context} detected_sources[{index}].missing_fields")
        for field_index, field in enumerate(missing_fields):
            expect(isinstance(field, str) and bool(field), f"{context} detected_sources[{index}].missing_fields[{field_index}] must be non-empty")
    for index, action_value in enumerate(actions):
        action = require_dict(action_value, f"{context} actions[{index}]")
        expect(isinstance(action.get("type"), str) and bool(action.get("type")), f"{context} actions[{index}].type must be non-empty")
    return [source for source in detected_sources if isinstance(source, dict)]


def check_setup_agent_action(
    payload: dict[str, Any],
    context: str,
    expected_kind: str,
    *,
    requires_user: bool,
    retryable: bool,
    description: str,
) -> dict[str, Any]:
    agent_action = require_dict(payload.get("agent_action"), f"{context} agent_action")
    expect(
        agent_action.get("kind") == expected_kind,
        f"{context} agent_action.kind must be {expected_kind}",
    )
    expect(
        agent_action.get("requires_user") is requires_user,
        f"{context} agent_action.requires_user must be {str(requires_user).lower()}",
    )
    expect(
        agent_action.get("retryable") is retryable,
        f"{context} agent_action.retryable must be {str(retryable).lower()}",
    )
    expect(
        agent_action.get("description") == description,
        f"{context} agent_action.description must be stable",
    )
    return agent_action


def check_connector_fixture_contract(
    fixture_path: Path,
    source_id: str,
    collector_id: str,
    emits: list[str],
    uploads_raw_content: bool,
) -> None:
    relative_path = fixture_path.relative_to(PUBLIC_ROOT).as_posix()
    fixture = require_dict(load_json(relative_path), f"{relative_path} fixture")
    expect(
        fixture.get("schema_version") == "collector_fixture.v1",
        f"{relative_path} schema_version must be collector_fixture.v1",
    )
    expect(fixture.get("source_id") == source_id, f"{relative_path} source_id must match registry")
    expect(
        fixture.get("collector_id") == collector_id,
        f"{relative_path} collector_id must match registry",
    )

    input_fixture_paths = require_list(
        fixture.get("input_fixture_paths"), f"{relative_path} input_fixture_paths"
    )
    fixture_root = fixture_path.parent.resolve()
    for index, input_path_value in enumerate(input_fixture_paths):
        expect(
            isinstance(input_path_value, str) and bool(input_path_value),
            f"{relative_path} input_fixture_paths[{index}] must be non-empty",
        )
        if not isinstance(input_path_value, str) or not input_path_value:
            continue
        resolved_input_path = (fixture_root / input_path_value).resolve()
        expect(
            resolved_input_path.is_file(),
            f"{relative_path} input_fixture_paths[{index}] must point to a file",
        )
        expect(
            resolved_input_path.is_relative_to(PUBLIC_ROOT),
            f"{relative_path} input_fixture_paths[{index}] must stay inside public repo",
        )

    upload_policy = require_dict(fixture.get("upload_policy"), f"{relative_path} upload_policy")
    expect(
        upload_policy.get("uploads_raw_content") == uploads_raw_content,
        f"{relative_path} upload_policy.uploads_raw_content must match registry",
    )
    expect(
        upload_policy.get("uploads_raw_content") is False,
        f"{relative_path} upload_policy.uploads_raw_content must be false for public v1",
    )
    redacts = [
        value
        for value in require_list(
            upload_policy.get("redacts"), f"{relative_path} upload_policy.redacts"
        )
        if isinstance(value, str)
    ]
    expect(
        len(redacts) == len(set(redacts)),
        f"{relative_path} upload_policy.redacts values must be unique",
    )
    missing_redactions = sorted(REQUIRED_CONNECTOR_REDACTION_CLASSES.difference(redacts))
    expect(
        not missing_redactions,
        f"{relative_path} upload_policy.redacts missing required classes: {', '.join(missing_redactions)}",
    )

    emitted_records = require_list(
        fixture.get("emitted_records"), f"{relative_path} emitted_records"
    )
    actual_record_types = []
    for index, record_value in enumerate(emitted_records):
        record = require_dict(record_value, f"{relative_path} emitted_records[{index}]")
        record_type = record.get("record_type")
        expect(
            isinstance(record_type, str) and bool(record_type),
            f"{relative_path} emitted_records[{index}].record_type must be non-empty",
        )
        if isinstance(record_type, str):
            actual_record_types.append(record_type)
        sample = require_dict(record.get("sample"), f"{relative_path} emitted_records[{index}].sample")
        check_connector_fixture_sample_keys(
            sample,
            f"{relative_path} emitted_records[{index}].sample",
        )
    expect(
        sorted(actual_record_types) == sorted(emits),
        f"{relative_path} emitted record types must match registry emits",
    )
    expect(
        len(actual_record_types) == len(set(actual_record_types)),
        f"{relative_path} emitted record types must be unique",
    )


def check_connector_fixture_sample_keys(value: Any, context: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child_context = f"{context}.{key}" if context else str(key)
            if key.lower() in FORBIDDEN_CONNECTOR_SAMPLE_KEYS:
                fail(f"{child_context} exposes raw-content sample key")
            check_connector_fixture_sample_keys(item, child_context)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            check_connector_fixture_sample_keys(item, f"{context}[{index}]")


def iter_json_strings(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        strings: list[tuple[str, str]] = []
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            strings.extend(iter_json_strings(item, child_path))
        return strings
    if isinstance(value, list):
        strings = []
        for index, item in enumerate(value):
            strings.extend(iter_json_strings(item, f"{path}[{index}]"))
        return strings
    return []


DIAGNOSTICS_ALLOWED_PLACEHOLDERS = {
    "[REDACTED]",
    "[account_id]",
    "[machine_id]",
    "[path]",
    "[prompt]",
}

DIAGNOSTICS_FORBIDDEN_VALUE_PATTERNS = (
    (re.compile(r"(?i)(^|[\s:=])Bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "bearer token"),
    (re.compile(r"(?i)(^|[\s:=])x-api-key\s*[:=]\s*[A-Za-z0-9._-]{8,}"), "API key header"),
    (re.compile(r"\b(?:ghp|github_pat|sk|xox[baprs])[-_A-Za-z0-9]{8,}\b"), "secret token"),
    (re.compile(r"\bclaim_(?!machine\b|claimed\b)[A-Za-z0-9]{6,}\b"), "setup claim"),
    (re.compile(r"\bsupport_[A-Za-z0-9]{6,}\b"), "support claim"),
    (re.compile(r"\b(?:org|usr|acct)_[A-Za-z0-9]{6,}\b"), "account identifier"),
    (re.compile(r"\b(?:machine|otm|device)_[A-Za-z0-9]{6,}\b"), "machine identifier"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "UUID identifier"),
    (re.compile(r"(?i)\b(?:serial|serial_number|hardware_serial)\s*[:=]\s*[A-Z0-9]{8,}\b"), "hardware serial"),
    (re.compile(r"(?:^|\s)(?:/Users|/private|/var|/tmp|/etc|/opt|/Applications)/[^\s]+"), "local path"),
    (re.compile(r"(?:^|\s)~/[^\s]+"), "home-relative path"),
    (re.compile(r"(?i)(?:raw_prompt|prompt_text|completion_text|command_output)\s*[:=]"), "raw prompt or command output"),
)


def check_diagnostics_values_are_redacted(value: Any, context: str) -> None:
    for path, raw in iter_json_strings(value, context):
        if raw in DIAGNOSTICS_ALLOWED_PLACEHOLDERS:
            continue
        for pattern, label in DIAGNOSTICS_FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(raw):
                fail(f"{path} exposes unredacted {label}: {raw!r}")


def check_schema_contracts() -> None:
    schema_expectations = {
        "schemas/connector-registry.schema.json": ("connector registry schema", "connector_registry.v1"),
        "schemas/source-manifest.schema.json": ("source manifest schema", "source_manifest.v1"),
        "schemas/collector-manifest.schema.json": ("collector manifest schema", "collector_manifest.v1"),
        "schemas/collector-fixture.schema.json": ("collector fixture schema", None),
    }
    for path, (label, schema_version) in schema_expectations.items():
        schema = require_dict(load_json(path), label)
        expect(schema.get("type") == "object", f"{path} must define an object schema")
        if schema_version is not None:
            properties = require_dict(schema.get("properties"), f"{path} properties")
            version = require_dict(properties.get("schema_version"), f"{path} schema_version")
            expect(version.get("const") == schema_version, f"{path} must pin {schema_version}")

    release_schema = require_dict(
        load_json("release/manifest.schema.json"), "release manifest schema"
    )
    release_properties = require_dict(
        release_schema.get("properties"), "release manifest schema properties"
    )
    product = require_dict(release_properties.get("product"), "release manifest product")
    expect(product.get("const") == "ottto-local-platform", "release manifest product must be ottto-local-platform")
    expect(
        "min_protocol_version" in require_list(
            release_schema.get("required"), "release manifest required fields"
        ),
        "release manifest schema must require min_protocol_version",
    )


def check_registry_contract() -> None:
    registry = require_dict(load_json("connectors/registry.generated.json"), "connector registry")
    expect(registry.get("schema_version") == "connector_registry.v1", "registry schema_version must be connector_registry.v1")
    sources = require_list(registry.get("sources"), "registry sources")
    source_ids = [source.get("source_id") for source in sources if isinstance(source, dict)]
    expected_sources = {"claude_code", "codex", "pi"}
    missing = sorted(expected_sources.difference(source_ids))
    expect(not missing, f"registry is missing required source(s): {', '.join(missing)}")
    expect(len(source_ids) == len(set(source_ids)), "registry source_id values must be unique")

    for source_value in sources:
        source = require_dict(source_value, "registry source")
        source_id = source.get("source_id")
        context = f"registry source {source_id or '<unknown>'}"
        manifest_path = source.get("manifest_path")
        expect(isinstance(manifest_path, str) and manifest_path.startswith("connectors/sources/"), f"{context} manifest_path must point under connectors/sources")
        source_manifest: dict[str, Any] = {}
        if isinstance(manifest_path, str):
            source_manifest = require_dict(load_toml(manifest_path), f"{manifest_path} manifest")
            expect(
                source_manifest.get("schema_version") == "source_manifest.v1",
                f"{manifest_path} schema_version must be source_manifest.v1",
            )
            for field in ("source_id", "app_slug", "display_name", "publisher", "review_tier", "maturity"):
                expect_same_string_field(source_manifest, source, field, f"{manifest_path}")
        operations = require_list(source.get("operations"), f"{context} operations")
        for operation in ("detect", "verify", "repair", "collect_usage", "monitor_quota", "upload_snapshot", "diagnostics"):
            expect(operation in operations, f"{context} operations must include {operation}")
        operation_values = [operation for operation in operations if isinstance(operation, str)]
        if isinstance(manifest_path, str):
            expect_same_string_list(source_manifest, operation_values, "operations", f"{manifest_path}")
        collectors = require_list(source.get("collectors"), f"{context} collectors")
        collector_ids = [
            collector.get("collector_id") for collector in collectors if isinstance(collector, dict)
        ]
        expect(collector_ids, f"{context} must expose at least one collector")
        expect(
            len(collector_ids) == len(set(collector_ids)),
            f"{context} collector_id values must be unique",
        )
        collector_id_values = [collector_id for collector_id in collector_ids if isinstance(collector_id, str)]
        if isinstance(manifest_path, str):
            expect_same_string_list(source_manifest, collector_id_values, "collectors", f"{manifest_path}")
            display_name = source.get("display_name")
            if isinstance(display_name, str):
                check_source_docs_contract(
                    (PUBLIC_ROOT / manifest_path).parent,
                    display_name,
                    collector_id_values,
                )
        for collector_value in collectors:
            collector = require_dict(collector_value, f"{context} collector")
            collector_context = f"{context} collector {collector.get('collector_id') or '<unknown>'}"
            collector_manifest_path = collector.get("manifest_path")
            collector_manifest: Path | None = None
            collector_manifest_payload: dict[str, Any] = {}
            expect(
                isinstance(collector_manifest_path, str)
                and collector_manifest_path.startswith("connectors/sources/")
                and collector_manifest_path.endswith("/collector.toml"),
                f"{collector_context} manifest_path must point to a collector manifest",
            )
            if isinstance(collector_manifest_path, str):
                collector_manifest = require_file(collector_manifest_path)
                collector_manifest_payload = require_dict(
                    load_toml(collector_manifest_path), f"{collector_manifest_path} manifest"
                )
                expect(
                    collector_manifest_payload.get("schema_version") == "collector_manifest.v1",
                    f"{collector_manifest_path} schema_version must be collector_manifest.v1",
                )
                expect(
                    collector_manifest_payload.get("source_id") == source_id,
                    f"{collector_manifest_path} source_id must match registry source",
                )
                for field in (
                    "collector_id",
                    "display_name",
                    "data_source_kind",
                    "default_state",
                    "review_tier",
                    "maturity",
                ):
                    expect_same_string_field(
                        collector_manifest_payload,
                        collector,
                        field,
                        f"{collector_manifest_path}",
                    )
            expect(isinstance(collector.get("uploads_raw_content"), bool), f"{collector_context} uploads_raw_content must be boolean")
            emits = [
                emit
                for emit in require_list(collector.get("emits"), f"{collector_context} emits")
                if isinstance(emit, str)
            ]
            expect(emits, f"{collector_context} emits must not be empty")
            if isinstance(collector_manifest_path, str):
                expect_same_string_list(
                    collector_manifest_payload,
                    [operation for operation in require_list(collector.get("operations"), f"{collector_context} operations") if isinstance(operation, str)],
                    "operations",
                    f"{collector_manifest_path}",
                )
                expect_same_string_list(
                    collector_manifest_payload,
                    [risk for risk in require_list(collector.get("risk_classes"), f"{collector_context} risk_classes") if isinstance(risk, str)],
                    "risk_classes",
                    f"{collector_manifest_path}",
                    allow_empty=True,
                )
                expect(
                    collector_manifest_payload.get("uploads_raw_content") == collector.get("uploads_raw_content"),
                    f"{collector_manifest_path} uploads_raw_content must match registry",
                )
                expect(
                    collector_manifest_payload.get("uploads_raw_content") is False,
                    f"{collector_manifest_path} uploads_raw_content must be false for public v1",
                )
                expect_same_string_list(collector_manifest_payload, emits, "emits", f"{collector_manifest_path}")
            if not isinstance(source_id, str) or not isinstance(collector.get("collector_id"), str):
                continue
            if not isinstance(collector.get("uploads_raw_content"), bool):
                continue
            if isinstance(collector_manifest_path, str) and collector_manifest is not None:
                fixture_dir = collector_manifest.parent / "fixtures"
                expect(fixture_dir.is_dir(), f"{collector_context} fixtures directory must exist")
                fixture_paths = sorted(fixture_dir.glob("*.json")) if fixture_dir.is_dir() else []
                expect(fixture_paths, f"{collector_context} must include at least one fixture")
                for fixture_path in fixture_paths:
                    check_connector_fixture_contract(
                        fixture_path,
                        source_id,
                        collector.get("collector_id"),
                        emits,
                        collector.get("uploads_raw_content"),
                    )


def check_cli_contracts() -> None:
    status_output = require_dict(load_json("fixtures/cli/status-json-output.json"), "CLI status output")
    expect_protocol(status_output.get("protocol_version"), "CLI status output")
    expect(status_output.get("daemon") == "running", "CLI status output daemon must be running")

    error_output = require_dict(load_json("fixtures/cli/daemon-unavailable-error.json"), "CLI daemon error")
    error = require_dict(error_output.get("error"), "CLI daemon error payload")
    expect(error.get("code") == "daemon_unavailable", "daemon error code must be daemon_unavailable")
    expect(error.get("retryable") is True, "daemon error must be retryable")

    watch_without_json_output = require_dict(
        load_json("fixtures/cli/watch-without-json-error.json"),
        "CLI watch without JSON error",
    )
    watch_without_json_error = require_dict(
        watch_without_json_output.get("error"),
        "CLI watch without JSON error payload",
    )
    expect(
        watch_without_json_error.get("code") == "invalid_request",
        "watch without JSON error code must be invalid_request",
    )
    expect(
        watch_without_json_error.get("message") == "--watch requires --json",
        "watch without JSON error message must explain --json requirement",
    )
    expect(
        watch_without_json_error.get("retryable") is False,
        "watch without JSON error must not be retryable",
    )
    expect(
        require_dict(
            watch_without_json_error.get("details"),
            "CLI watch without JSON error details",
        )
        == {},
        "watch without JSON error details must stay empty",
    )

    for fixture_name, message in (
        ("context-without-json-error.json", "ottto context is agent JSON only; pass --json"),
        ("costs-without-json-error.json", "ottto costs is agent JSON only; pass --json"),
        ("sessions-without-json-error.json", "ottto sessions is agent JSON only; pass --json"),
        (
            "recommendations-without-json-error.json",
            "ottto recommendations is agent JSON only; pass --json",
        ),
        (
            "provider-impact-without-json-error.json",
            "ottto provider-impact is agent JSON only; pass --json",
        ),
    ):
        agent_error_output = require_dict(
            load_json(f"fixtures/cli/{fixture_name}"),
            f"CLI {fixture_name}",
        )
        agent_error = require_dict(agent_error_output.get("error"), f"CLI {fixture_name} payload")
        expect(
            agent_error.get("code") == "invalid_request",
            f"{fixture_name} error code must be invalid_request",
        )
        expect(
            agent_error.get("message") == message,
            f"{fixture_name} error message must match agent JSON contract",
        )
        expect(
            agent_error.get("retryable") is False,
            f"{fixture_name} error must not be retryable",
        )
        expect(
            require_dict(agent_error.get("details"), f"CLI {fixture_name} details") == {},
            f"{fixture_name} error details must stay empty",
        )

    setup_claim = require_dict(load_json("fixtures/cli/setup-claim-request.json"), "CLI setup claim request")
    expect_protocol(setup_claim.get("protocol_version"), "CLI setup claim request")
    expect(setup_claim.get("client_kind") == "cli", "CLI setup claim request client_kind must be cli")
    expect(setup_claim.get("command") == "setup", "CLI setup claim request command must be setup")

    setup_headless = require_dict(
        load_json("fixtures/cli/setup-headless-request.json"),
        "CLI setup headless request",
    )
    expect_protocol(setup_headless.get("protocol_version"), "CLI setup headless request")
    expect(setup_headless.get("client_kind") == "cli", "CLI setup headless request client_kind must be cli")
    expect(setup_headless.get("command") == "setup", "CLI setup headless request command must be setup")
    expect(setup_headless.get("claim_code") is None, "CLI setup headless request claim_code must be null")

    login_headless = require_dict(
        load_json("fixtures/cli/login-headless-request.json"),
        "CLI login headless request",
    )
    expect_protocol(login_headless.get("protocol_version"), "CLI login headless request")
    expect(login_headless.get("client_kind") == "cli", "CLI login headless request client_kind must be cli")
    expect(login_headless.get("command") == "setup", "CLI login headless request must use daemon setup command")
    expect(login_headless.get("claim_code") is None, "CLI login headless request claim_code must be null")

    account = require_dict(load_json("fixtures/cli/account-request.json"), "CLI account request")
    expect_protocol(account.get("protocol_version"), "CLI account request")
    expect(account.get("client_kind") == "cli", "CLI account request client_kind must be cli")
    expect(account.get("command") == "account", "CLI account request command must be account")

    logout = require_dict(load_json("fixtures/cli/logout-request.json"), "CLI logout request")
    expect_protocol(logout.get("protocol_version"), "CLI logout request")
    expect(logout.get("client_kind") == "cli", "CLI logout request client_kind must be cli")
    expect(logout.get("command") == "auth_reset", "CLI logout request command must be auth_reset")
    expect(logout.get("local_only") is False, "CLI logout request must be cloud-first by default")

    logout_local = require_dict(
        load_json("fixtures/cli/logout-local-request.json"),
        "CLI logout local-only request",
    )
    expect_protocol(logout_local.get("protocol_version"), "CLI logout local-only request")
    expect(logout_local.get("client_kind") == "cli", "CLI logout local-only request client_kind must be cli")
    expect(logout_local.get("command") == "auth_reset", "CLI logout local-only request command must be auth_reset")
    expect(logout_local.get("local_only") is True, "CLI logout local-only request local_only must be true")

    diagnostics_collect = require_dict(
        load_json("fixtures/cli/diagnostics-collect-request.json"),
        "CLI diagnostics collect request",
    )
    expect_protocol(diagnostics_collect.get("protocol_version"), "CLI diagnostics collect request")
    expect(diagnostics_collect.get("command") == "diagnostics_collect", "CLI diagnostics collect request command must be diagnostics_collect")
    expect(diagnostics_collect.get("upload") is False, "CLI diagnostics collect request upload must be false")

    diagnostics_upload = require_dict(
        load_json("fixtures/cli/diagnostics-upload-request.json"),
        "CLI diagnostics upload request",
    )
    expect_protocol(diagnostics_upload.get("protocol_version"), "CLI diagnostics upload request")
    expect(diagnostics_upload.get("command") == "diagnostics_collect", "CLI diagnostics upload request command must be diagnostics_collect")
    expect(diagnostics_upload.get("upload") is True, "CLI diagnostics upload request upload must be true")
    upload_approval = require_dict(
        diagnostics_upload.get("upload_approval"), "CLI diagnostics upload approval"
    )
    expect(upload_approval.get("approved") is True, "CLI diagnostics upload approval must be accepted")
    expect(
        upload_approval.get("retention_disclosure_accepted") is True,
        "CLI diagnostics upload retention disclosure must be accepted",
    )

    doctor = require_dict(load_json("fixtures/cli/doctor-request.json"), "CLI doctor request")
    expect_protocol(doctor.get("protocol_version"), "CLI doctor request")
    expect(doctor.get("client_kind") == "cli", "CLI doctor request client_kind must be cli")
    expect(doctor.get("command") == "status", "CLI doctor request command must be status")
    expect(doctor.get("refresh_agent_status") is False, "CLI doctor request must not refresh agent status")

    fix_codex = require_dict(load_json("fixtures/cli/fix-codex-request.json"), "CLI fix Codex request")
    expect_protocol(fix_codex.get("protocol_version"), "CLI fix Codex request")
    expect(fix_codex.get("client_kind") == "cli", "CLI fix Codex request client_kind must be cli")
    expect(fix_codex.get("command") == "repair", "CLI fix Codex request command must be repair")
    expect(fix_codex.get("source") == "codex", "CLI fix Codex request source must be codex")
    expect(fix_codex.get("dry_run") is False, "CLI fix Codex request dry_run must be false")

    verify_repair = require_dict(
        load_json("fixtures/cli/verify-repair-request.json"),
        "CLI verify repair request",
    )
    expect_protocol(verify_repair.get("protocol_version"), "CLI verify repair request")
    expect(verify_repair.get("client_kind") == "cli", "CLI verify repair request client_kind must be cli")
    expect(verify_repair.get("command") == "verify", "CLI verify repair request command must be verify")
    expect(verify_repair.get("source") == "codex", "CLI verify repair request source must be codex")
    expect(verify_repair.get("repair") is True, "CLI verify repair request repair must be true")

    apps_root = require_dict(
        load_json("fixtures/cli/apps-root-request.json"),
        "CLI apps root request",
    )
    expect_protocol(apps_root.get("protocol_version"), "CLI apps root request")
    expect(apps_root.get("client_kind") == "cli", "CLI apps root request client_kind must be cli")
    expect(apps_root.get("command") == "status", "CLI apps root request command must be status")
    expect(apps_root.get("refresh_agent_status") is False, "CLI apps root request must not refresh agent status")

    apps_detect = require_dict(
        load_json("fixtures/cli/apps-detect-request.json"),
        "CLI apps detect request",
    )
    expect_protocol(apps_detect.get("protocol_version"), "CLI apps detect request")
    expect(apps_detect.get("client_kind") == "cli", "CLI apps detect request client_kind must be cli")
    expect(apps_detect.get("command") == "status", "CLI apps detect request command must be status")
    expect(apps_detect.get("refresh_agent_status") is True, "CLI apps detect request must refresh agent status")

    apps_status = require_dict(
        load_json("fixtures/cli/apps-status-pi-request.json"),
        "CLI apps status request",
    )
    expect_protocol(apps_status.get("protocol_version"), "CLI apps status request")
    expect(apps_status.get("client_kind") == "cli", "CLI apps status request client_kind must be cli")
    expect(apps_status.get("command") == "agent_status_refresh", "CLI apps status request command must be agent_status_refresh")
    expect(apps_status.get("source") == "pi", "CLI apps status request source must be pi")

    update_check = require_dict(
        load_json("fixtures/cli/update-check-request.json"),
        "CLI update check request",
    )
    expect_protocol(update_check.get("protocol_version"), "CLI update check request")
    expect(update_check.get("client_kind") == "cli", "CLI update check request client_kind must be cli")
    expect(update_check.get("command") == "update_check", "CLI update check request command must be update_check")

    uninstall = require_dict(load_json("fixtures/cli/uninstall-request.json"), "CLI uninstall request")
    expect_protocol(uninstall.get("protocol_version"), "CLI uninstall request")
    expect(uninstall.get("client_kind") == "cli", "CLI uninstall request client_kind must be cli")
    expect(uninstall.get("command") == "uninstall_execute", "CLI uninstall request command must be uninstall_execute")
    expect(uninstall.get("confirm") is True, "CLI uninstall request confirm must be true")

    browser_claim = require_dict(
        load_json("fixtures/cli/setup-browser-claim-output.json"),
        "CLI browser claim output",
    )
    browser_claim_sources = check_setup_output_shape(browser_claim, "browser claim output")
    expect(browser_claim.get("status") == "waiting_for_browser", "browser claim status must be waiting_for_browser")
    expect(browser_claim.get("setup_run_id") is None, "browser claim setup_run_id must be null before claim")
    expect(browser_claim.get("claim_code_provided") is False, "browser claim output must not mark claim_code_provided")
    expect(browser_claim.get("claim_code"), "browser claim output must include claim_code")
    expect(browser_claim.get("claim_url"), "browser claim output must include claim_url")
    expect(browser_claim.get("next_question") is None, "browser claim next_question must be null")
    expect(browser_claim_sources == [], "browser claim detected_sources must be empty")
    next_action = require_dict(browser_claim.get("next_action"), "browser claim next_action")
    expect(next_action.get("type") == "browser_claim", "browser claim next_action type must be browser_claim")
    expect(next_action.get("claim_code") == browser_claim.get("claim_code"), "browser claim next_action must repeat claim_code")
    expect(next_action.get("claim_url") == browser_claim.get("claim_url"), "browser claim next_action must repeat claim_url")
    check_setup_agent_action(
        browser_claim,
        "browser claim",
        "open_browser_claim",
        requires_user=True,
        retryable=True,
        description="Open or share the browser claim URL or code with the user.",
    )

    needs_user = require_dict(
        load_json("fixtures/cli/setup-needs-user-action-output.json"),
        "CLI needs-user-action output",
    )
    needs_user_sources = check_setup_output_shape(needs_user, "needs-user-action output")
    expect(needs_user.get("status") == "waiting_for_approval", "needs-user-action status must be waiting_for_approval")
    expect(needs_user.get("claim_code_provided") is False, "needs-user-action output must not mark claim_code_provided")
    expect(needs_user.get("next_action") is None, "needs-user-action next_action must be null while waiting for approval")
    question = require_dict(needs_user.get("next_question"), "needs-user-action next_question")
    expect(question.get("type") == "approval", "needs-user-action next_question type must be approval")
    expect(question.get("source") == "codex", "needs-user-action next_question source must be codex")
    check_setup_agent_action(
        needs_user,
        "needs-user-action",
        "answer_setup_question",
        requires_user=True,
        retryable=True,
        description="Ask the user to answer the structured next_question prompt.",
    )
    expect(len(needs_user_sources) == 1, "needs-user-action output must expose one detected source")
    if needs_user_sources:
        source = needs_user_sources[0]
        expect(source.get("source") == "codex", "needs-user-action detected source must be codex")
        expect(source.get("state") == "ready_to_install", "needs-user-action detected source state must be ready_to_install")
        expect("browser_approval" in require_list(source.get("missing_fields"), "needs-user-action missing_fields"), "needs-user-action missing_fields must include browser_approval")

    timed_out = require_dict(
        load_json("fixtures/cli/setup-timed-out-output.json"), "CLI setup timed-out output"
    )
    timed_out_sources = check_setup_output_shape(timed_out, "setup timed-out output")
    expect(timed_out.get("status") == "timed_out", "setup timed-out status must be timed_out")
    expect(timed_out.get("claim_code_provided") is True, "setup timed-out output must preserve claim_code_provided")
    expect(timed_out.get("next_question") is None, "setup timed-out next_question must be null")
    expect(timed_out.get("next_action") is None, "setup timed-out next_action must be null")
    check_setup_agent_action(
        timed_out,
        "setup timed-out",
        "retry_setup",
        requires_user=False,
        retryable=True,
        description="Setup timed out. Retry setup or check status before taking manual action.",
    )
    expect(len(timed_out_sources) == 1, "setup timed-out output must expose one detected source")
    if timed_out_sources:
        source = timed_out_sources[0]
        expect(source.get("source") == "codex", "setup timed-out detected source must be codex")
        expect(source.get("state") == "waiting_for_telemetry", "setup timed-out detected source state must be waiting_for_telemetry")
        expect("fresh_telemetry" in require_list(source.get("missing_fields"), "setup timed-out missing_fields"), "setup timed-out missing_fields must include fresh_telemetry")

    failed = require_dict(
        load_json("fixtures/cli/setup-failed-output.json"), "CLI setup failed output"
    )
    failed_sources = check_setup_output_shape(failed, "setup failed output")
    expect(failed.get("status") == "failed", "setup failed status must be failed")
    expect(failed.get("claim_code_provided") is True, "setup failed output must preserve claim_code_provided")
    expect(failed.get("next_question") is None, "setup failed next_question must be null")
    expect(failed.get("next_action") is None, "setup failed next_action must be null")
    check_setup_agent_action(
        failed,
        "setup failed",
        "inspect_failure",
        requires_user=False,
        retryable=True,
        description="Inspect setup failure details and run doctor before repair.",
    )
    expect(len(failed_sources) == 1, "setup failed output must expose one detected source")
    if failed_sources:
        source = failed_sources[0]
        expect(source.get("source") == "codex", "setup failed detected source must be codex")
        expect(source.get("state") == "failed", "setup failed detected source state must be failed")
        expect("setup_run_failed" in require_list(source.get("missing_fields"), "setup failed missing_fields"), "setup failed missing_fields must include setup_run_failed")

    status_events = load_ndjson("fixtures/cli/status-watch-output.ndjson")
    if status_events:
        final = status_events[-1]
        expect(final.get("event") == "final", "status watch final event must be final")
        expect(final.get("ok") is True, "status watch final event must be ok")
        expect(final.get("exit_code") == 0, "status watch final exit_code must be 0")
        payload = require_dict(final.get("payload"), "status watch final payload")
        expect_protocol(payload.get("protocol_version"), "status watch final payload")

    error_events = load_ndjson("fixtures/cli/daemon-unavailable-watch-output.ndjson")
    if error_events:
        final = error_events[-1]
        expect(final.get("event") == "final", "daemon error watch final event must be final")
        expect(final.get("ok") is False, "daemon error watch final event must not be ok")
        expect(final.get("exit_code") == 10, "daemon error watch final exit_code must be 10")
        watch_error = require_dict(final.get("error"), "daemon error watch final error")
        expect(watch_error.get("code") == "daemon_unavailable", "daemon error watch code must be daemon_unavailable")

    uninstall_events = load_ndjson("fixtures/cli/uninstall-incomplete-output.ndjson")
    expect(len(uninstall_events) == 2, "uninstall incomplete output must include progress and final events")
    if uninstall_events:
        progress = uninstall_events[0]
        expect(progress.get("event") == "progress", "uninstall incomplete first event must be progress")
        expect(progress.get("command") == "uninstall", "uninstall incomplete progress command must be uninstall")
        expect_protocol(progress.get("protocol_version"), "uninstall incomplete progress event")
        final = uninstall_events[-1]
        expect(final.get("event") == "final", "uninstall incomplete final event must be final")
        expect(final.get("ok") is False, "uninstall incomplete final event must not be ok")
        expect(final.get("exit_code") == 70, "uninstall incomplete final exit_code must be 70")
        uninstall_error = require_dict(final.get("error"), "uninstall incomplete final error")
        expect(uninstall_error.get("code") == "internal", "uninstall incomplete error code must be internal")
        expect(uninstall_error.get("retryable") is True, "uninstall incomplete error must be retryable")
        details = require_dict(uninstall_error.get("details"), "uninstall incomplete error details")
        expect(details.get("status") == "incomplete", "uninstall incomplete details status must be incomplete")
        expect(
            len(require_list(details.get("failed_operations"), "uninstall incomplete failed operations")) >= 1,
            "uninstall incomplete must include failed operations",
        )


def check_control_contracts() -> None:
    request = require_dict(load_json("fixtures/control/status-request.json"), "control status request")
    expect(request.get("command") == "status", "control status request command must be status")
    expect_protocol(request.get("protocol_version"), "control status request")
    expect(request.get("token") == "[REDACTED]", "control status request token must be redacted")

    response = require_dict(load_json("fixtures/control/status-response.json"), "control status response")
    expect(response.get("ok") is True, "control status response must be ok")
    expect(response.get("error") is None, "control status response error must be null")
    payload = require_dict(response.get("payload"), "control status response payload")
    expect_protocol(payload.get("protocol_version"), "control status response payload")
    expect(payload.get("daemon") == "running", "control status response daemon must be running")


def check_setup_and_redaction_contracts() -> None:
    bundle = require_dict(
        load_json("fixtures/diagnostics/redacted-bundle.json"), "redacted diagnostics bundle"
    )
    expect(bundle.get("bundle_id"), "redacted diagnostics bundle must include bundle_id")
    upload = require_dict(bundle.get("upload"), "redacted diagnostics upload")
    expect(upload.get("requested") is False, "redacted diagnostics upload requested must be false")
    expect(upload.get("status") == "local_only", "redacted diagnostics upload status must be local_only")
    expect(upload.get("approval_required") is True, "redacted diagnostics upload must require approval")
    expect(upload.get("approved") is False, "redacted diagnostics upload approved must be false")
    expect(upload.get("authorization") == "not_requested", "redacted diagnostics authorization must be not_requested")
    retention = require_dict(upload.get("retention"), "redacted diagnostics upload retention")
    expect(retention.get("accepted") is False, "redacted diagnostics retention must not be accepted for local-only bundles")
    retention_text = retention.get("text")
    expect(
        isinstance(retention_text, str) and "30 days" in retention_text and "support request" in retention_text,
        "redacted diagnostics retention text must disclose 30-day support retention",
    )
    expect(
        upload.get("support_claim_provided") is False,
        "redacted diagnostics support_claim_provided must be false for local-only bundles",
    )
    expect("support_claim" not in upload, "redacted diagnostics upload must not expose support_claim")
    redaction = require_dict(bundle.get("redaction"), "redacted diagnostics redaction")
    expect(redaction.get("policy_version") == 1, "redacted diagnostics policy_version must be 1")
    covered_surfaces = set(require_list(redaction.get("covered_surfaces"), "redaction covered surfaces"))
    for surface in (
        "diagnostics",
        "support_output",
        "agent_output",
        "setup_error",
        "command_output",
    ):
        expect(surface in covered_surfaces, f"redaction covered surfaces must include {surface}")
    categories = set(require_list(redaction.get("redacted_categories"), "redacted categories"))
    for category in (
        "local_path",
        "secret_token",
        "account_identifier",
        "machine_identifier",
        "raw_prompt",
        "command_output",
    ):
        expect(category in categories, f"redaction categories must include {category}")
    fields = set(require_list(redaction.get("redacted_fields"), "redacted fields"))
    expect(bundle.get("machine_id") == "[machine_id]", "diagnostics machine_id must be redacted")
    for field in (
        "account_id",
        "device_id",
        "installation_id",
        "machine_id",
        "org_id",
        "user_id",
        "installation.launch_agent_path",
        "security.auth_header",
    ):
        expect(field in fields, f"redaction fields must include {field}")
    preserved_fields = set(require_list(redaction.get("preserved_fields"), "redaction preserved fields"))
    expect(
        "machine_id" not in preserved_fields,
        "redaction preserved_fields must not include machine_id",
    )
    sections = require_list(bundle.get("sections"), "redacted diagnostics sections")
    section_items = {
        section.get("name"): section.get("items")
        for section in sections
        if isinstance(section, dict) and isinstance(section.get("items"), dict)
    }
    expect(len(section_items) == len(sections), "redacted diagnostics sections must have object items")
    installation = require_dict(section_items.get("installation"), "redacted installation section")
    expect(installation.get("launch_agent_path") == "[path]", "launch_agent_path must be path-redacted")
    security = require_dict(section_items.get("security"), "redacted security section")
    expect(security.get("auth_header") == "[REDACTED]", "auth_header must be redacted")
    check_diagnostics_values_are_redacted(
        {"machine_id": bundle.get("machine_id"), "upload": upload, "sections": sections},
        "diagnostics",
    )

    setup = require_dict(load_json("fixtures/setup/claim-run.json"), "setup claim run")
    expect(setup.get("status") == "waiting_for_approval", "setup claim run status must be waiting_for_approval")
    expect(setup.get("setup_run_id"), "setup claim run must include setup_run_id")
    events = require_list(setup.get("events"), "setup claim run events")
    event_by_step = {
        event.get("step"): event for event in events if isinstance(event, dict)
    }
    claim_machine = require_dict(event_by_step.get("claim_machine"), "claim_machine setup event")
    expect(claim_machine.get("status") == "succeeded", "claim_machine setup event must succeed")
    metadata = require_dict(claim_machine.get("metadata"), "claim_machine metadata")
    expect(metadata.get("setup_code") == "[REDACTED]", "claim_machine setup_code must be redacted")
    request_approval = require_dict(
        event_by_step.get("request_approval"), "request_approval setup event"
    )
    expect(request_approval.get("status") == "waiting", "request_approval setup event must be waiting")
    expect(request_approval.get("source") == "codex", "request_approval setup event source must be codex")
    event_metadata = [
        {"metadata": require_dict(event.get("metadata"), f"setup event {index} metadata")}
        for index, event in enumerate(events)
        if isinstance(event, dict)
    ]
    check_diagnostics_values_are_redacted({"events": event_metadata}, "setup")


def check_local_health_diagnostics_contract() -> None:
    cases = require_list(
        load_json("fixtures/local-health/contract-matrix.v1.json"),
        "local health contract matrix",
    )
    diagnostics_cases = [
        case
        for case in cases
        if isinstance(case, dict) and case.get("case_id") == "diagnostics_redaction"
    ]
    expect(
        len(diagnostics_cases) == 1,
        "local health contract matrix must include exactly one diagnostics_redaction case",
    )
    if len(diagnostics_cases) != 1:
        return

    case = require_dict(diagnostics_cases[0], "local health diagnostics_redaction case")
    expect(
        case.get("fixture_schema_version") == "local_health_contract_fixture.v1",
        "local health diagnostics_redaction fixture_schema_version must be local_health_contract_fixture.v1",
    )
    expect(
        case.get("contract_version") == "local_machine_health.v1",
        "local health diagnostics_redaction contract_version must be local_machine_health.v1",
    )
    tags = set(string_list(case.get("tags"), "local health diagnostics_redaction tags"))
    for tag in ("diagnostics", "redaction"):
        expect(tag in tags, f"local health diagnostics_redaction tags must include {tag}")

    health = require_dict(case.get("health"), "local health diagnostics_redaction health")
    expect(
        health.get("schema_version_name") == "local_machine_health.v1",
        "local health diagnostics_redaction schema_version_name must be local_machine_health.v1",
    )
    capabilities = set(string_list(health.get("capabilities"), "local health diagnostics_redaction capabilities"))
    expect(
        "diagnostics.collect" in capabilities,
        "local health diagnostics_redaction capabilities must include diagnostics.collect",
    )
    overall = require_dict(health.get("overall"), "local health diagnostics_redaction overall")
    expect(
        overall.get("primary_blocker") == "diagnostics_collected",
        "local health diagnostics_redaction primary_blocker must be diagnostics_collected",
    )
    expect(
        overall.get("next_action") == "share_redacted_bundle",
        "local health diagnostics_redaction next_action must be share_redacted_bundle",
    )

    sources = require_list(health.get("sources"), "local health diagnostics_redaction sources")
    diagnostics_sources = [
        source
        for source in sources
        if isinstance(source, dict) and source.get("authority") == "diagnostics"
    ]
    expect(
        diagnostics_sources,
        "local health diagnostics_redaction must include a diagnostics-authority source",
    )
    for source_value in diagnostics_sources:
        source = require_dict(source_value, "local health diagnostics_redaction source")
        expect(
            source.get("next_action") == "share_redacted_bundle",
            "local health diagnostics_redaction source next_action must be share_redacted_bundle",
        )

    blockers = require_list(health.get("blockers"), "local health diagnostics_redaction blockers")
    diagnostics_blockers = [
        blocker
        for blocker in blockers
        if isinstance(blocker, dict) and blocker.get("code") == "diagnostics_collected"
    ]
    expect(
        diagnostics_blockers,
        "local health diagnostics_redaction must include diagnostics_collected blocker",
    )
    for blocker_value in diagnostics_blockers:
        blocker = require_dict(blocker_value, "local health diagnostics_redaction blocker")
        expect(
            blocker.get("owner") == "support",
            "local health diagnostics_redaction blocker owner must be support",
        )
        expect(
            blocker.get("source") == "diagnostics",
            "local health diagnostics_redaction blocker source must be diagnostics",
        )

    events = require_list(case.get("events"), "local health diagnostics_redaction events")
    diagnostics_events = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event_type") == "DiagnosticsCollected"
    ]
    expect(
        len(diagnostics_events) == 1,
        "local health diagnostics_redaction must include exactly one DiagnosticsCollected event",
    )
    if len(diagnostics_events) != 1:
        return

    event = require_dict(diagnostics_events[0], "local health diagnostics_redaction event")
    expect(
        event.get("authority") == "diagnostics",
        "local health diagnostics_redaction event authority must be diagnostics",
    )
    payload = require_dict(event.get("payload"), "local health diagnostics_redaction event payload")
    redacted_identifiers = set(
        string_list(
            payload.get("redacted_identifiers"),
            "local health diagnostics_redaction redacted_identifiers",
        )
    )
    for identifier in ("machine_id", "device_id", "account_id"):
        expect(
            identifier in redacted_identifiers,
            f"local health diagnostics_redaction redacted_identifiers must include {identifier}",
        )
    excluded_secret_classes = set(
        string_list(
            payload.get("excluded_secret_classes"),
            "local health diagnostics_redaction excluded_secret_classes",
        )
    )
    for secret_class in (
        "cookies",
        "passwords",
        "setup_secrets",
        "private_keys",
        "hardware_serials",
        "raw_credentials",
    ):
        expect(
            secret_class in excluded_secret_classes,
            f"local health diagnostics_redaction excluded_secret_classes must include {secret_class}",
        )
    included_sections = set(
        string_list(
            payload.get("included_sections"),
            "local health diagnostics_redaction included_sections",
        )
    )
    for section in ("runtime", "versions", "installation", "command_ledger"):
        expect(
            section in included_sections,
            f"local health diagnostics_redaction included_sections must include {section}",
        )
    check_diagnostics_values_are_redacted(
        {"event_payload": payload},
        "local-health.diagnostics_redaction",
    )


def check_agent_adapter_contracts() -> None:
    docs_path = require_file("docs/agent-adapters.md")
    if docs_path is not None:
        text = docs_path.read_text(encoding="utf-8")
        expect(
            "MCP adapter is intentionally deferred" in text,
            "agent adapter docs must document the public-v1 MCP deferral",
        )
        expect(
            "must not own setup authority" in text,
            "agent adapter docs must prohibit MCP setup authority ownership",
        )
        expect(
            "agent-adapters/codex-skill/" in text,
            "agent adapter docs must name the exported Codex skill",
        )
        expect(
            "agent-adapters/claude-code-skill/" in text,
            "agent adapter docs must name the exported Claude Code skill",
        )
        docs_expectations = [
            (
                "Pi is supported through the same public CLI app value, `--app pi`",
                "agent adapter docs must route Pi through the public CLI app value",
            ),
            (
                "consume machine-readable `ottto --json` output",
                "agent adapter docs must require machine-readable JSON output",
            ),
            (
                "avoid direct edits to agent config, credentials, cookies, hooks, status-line\n  monitors, or local source files",
                "agent adapter docs must prohibit direct config/credential/hook/source edits",
            ),
            (
                "summarize redacted status facts instead of pasting raw diagnostics payloads",
                "agent adapter docs must require redacted summaries instead of raw diagnostics",
            ),
            (
                "keep support claims out of public issues, chat, returned JSON, and uploaded\n  bundle content",
                "agent adapter docs must keep support claims out of public issues/chat/JSON/bundles",
            ),
        ]
        for needle, message in docs_expectations:
            expect(needle in text, message)

    require_file("agent-adapters/codex-skill/SKILL.md")
    require_file("agent-adapters/claude-code-skill/SKILL.md")
    for relative_path in (
        "agent-adapters/mcp",
        "agent-adapters/mcp-server",
        "mcp",
        "mcp-server",
    ):
        if (PUBLIC_ROOT / relative_path).exists():
            fail(f"MCP adapter must remain deferred for public v1: {relative_path}")

    skill_expectations = {
        "agent-adapters/codex-skill/SKILL.md": {
            "required": [
                ("Always pass `--json`", "Codex skill must require JSON output for consumed CLI responses"),
                ("`--json --watch` emits compact\nNDJSON", "Codex skill must document NDJSON watch semantics"),
                ("Do not parse human output", "Codex skill must prohibit parsing human output"),
                ("bypass browser/setup authority", "Codex skill must preserve browser/setup authority"),
                ("do not hand-edit local app config", "Codex skill must prohibit direct config edits"),
                ("Do not ask users to paste support claims into public issues or chat", "Codex skill must keep support claims out of chat"),
                ("must not appear in returned JSON", "Codex skill must keep support claims out of returned JSON"),
                ("uploaded bundle content", "Codex skill must document support-claim upload containment"),
            ],
            "forbidden": [
                ("allowed-tools:", "Codex skill must not pregrant tools"),
                ("hooks:", "Codex skill must not install hooks"),
                ("statusline:", "Codex skill must not install status-line metadata"),
                ("status-line:", "Codex skill must not install status-line metadata"),
                ("tools/ottto-local-platform", "Codex skill must not reference private monorepo install paths"),
            ],
        },
        "agent-adapters/claude-code-skill/SKILL.md": {
            "required": [
                ("Always pass `--json`", "Claude Code skill must require JSON output for consumed CLI responses"),
                ("`--json --watch` emits compact\nNDJSON", "Claude Code skill must document NDJSON watch semantics"),
                ("Do not parse human output", "Claude Code skill must prohibit parsing human output"),
                ("bypass browser/setup authority", "Claude Code skill must preserve browser/setup authority"),
                ("do not write telemetry\nenvironment variables", "Claude Code skill must prohibit direct telemetry config edits"),
                ("Do not ask users to paste support claims into public issues or chat", "Claude Code skill must keep support claims out of chat"),
                ("must not appear in returned JSON", "Claude Code skill must keep support claims out of returned JSON"),
                ("uploaded bundle content", "Claude Code skill must document support-claim upload containment"),
            ],
            "forbidden": [
                ("allowed-tools:", "Claude Code skill must not pregrant tools"),
                ("hooks:", "Claude Code skill must not define hooks metadata"),
                ("statusline:", "Claude Code skill must not define status-line metadata"),
                ("status-line:", "Claude Code skill must not define status-line metadata"),
                ("tools/ottto-local-platform", "Claude Code skill must not reference private monorepo install paths"),
            ],
        },
        "agent-adapters/codex-skill/agents/openai.yaml": {
            "required": [
                ("Manage Ottto local setup", "Codex agent manifest must stay scoped to Ottto lifecycle"),
            ],
            "forbidden": [
                ("allowed_tools:", "Codex agent manifest must not pregrant tools"),
                ("tools:", "Codex agent manifest must not pregrant tools"),
                ("mcp", "Codex agent manifest must not advertise MCP for public v1"),
                ("hooks:", "Codex agent manifest must not define hooks"),
                ("statusline:", "Codex agent manifest must not define status-line metadata"),
                ("status-line:", "Codex agent manifest must not define status-line metadata"),
            ],
        },
    }
    for relative_path, expectations in skill_expectations.items():
        path = require_file(relative_path)
        if path is None:
            continue
        text = path.read_text(encoding="utf-8")
        for needle, message in expectations["required"]:
            expect(needle in text, message)
        lowered = text.lower()
        for needle, message in expectations["forbidden"]:
            if needle.lower() in lowered:
                fail(message)


def check_setup_docs_contracts() -> None:
    setup_docs = require_file("docs/setup.md")
    if setup_docs is None:
        return

    text = setup_docs.read_text(encoding="utf-8")
    expectations = [
        (
            "Default setup opens a browser claim and waits for approval",
            "setup docs must preserve browser-claim-first setup guidance",
        ),
        ("ottto setup --json", "setup docs must include JSON setup command"),
        (
            "parseable JSON payload with a\nnonzero exit code",
            "setup docs must document nonzero JSON setup payloads",
        ),
        (
            "ottto setup --json --no-browser --no-wait",
            "setup docs must include headless no-browser/no-wait setup command",
        ),
        (
            "Show the returned `claim_url` or `claim_code` to the user",
            "setup docs must preserve headless claim handoff guidance",
        ),
        (
            "Exit code `60` means\nbrowser or user action is required",
            "setup docs must document needs-user-action exit code",
        ),
        (
            "Exit code `61` means a wait timed out",
            "setup docs must document setup timeout exit code",
        ),
        (
            "ottto setup --claim-code <code> --json",
            "setup docs must include claim-code setup command",
        ),
        ("ottto login --json", "setup docs must include login JSON command"),
        (
            "ottto login --json --no-browser --no-wait",
            "setup docs must include headless login command",
        ),
        ("ottto account --json", "setup docs must include account JSON command"),
        ("ottto logout --json", "setup docs must include cloud-first logout command"),
        (
            "Use local-only logout only as an explicit emergency cleanup path",
            "setup docs must keep local-only logout as emergency-only",
        ),
        (
            "ottto logout --local-only --json",
            "setup docs must include explicit local-only logout command",
        ),
        (
            "ottto apps detect --json",
            "setup docs must include apps detect JSON command",
        ),
        (
            "ottto apps status --app codex --json",
            "setup docs must include app status command",
        ),
        (
            "ottto verify --app claude-code --json",
            "setup docs must include app verify command",
        ),
        (
            "ottto verify --repair --app codex --json",
            "setup docs must include bounded repair verify command",
        ),
        (
            "Plain verify is read-only",
            "setup docs must preserve read-only verify boundary",
        ),
        (
            "`verify --repair` is limited to daemon-owned\nWriteConfig repair",
            "setup docs must preserve daemon-owned repair boundary",
        ),
        (
            "Pi keeps its existing verification\nflow and has no config patching",
            "setup docs must preserve Pi no-config-patching boundary",
        ),
        (
            "Do not hand-edit local Codex, Claude Code, or\nPi config as a setup shortcut",
            "setup docs must prohibit hand-edit setup shortcuts",
        ),
        ("| `0` | Success or setup complete |", "setup docs must list exit code 0"),
        ("| `10` | `ottto-service` unavailable |", "setup docs must list exit code 10"),
        ("| `60` | Setup needs user or browser action |", "setup docs must list exit code 60"),
        ("| `61` | Setup timed out |", "setup docs must list exit code 61"),
        ("| `70` | Internal error |", "setup docs must list exit code 70"),
        (
            "branch on `agent_action.kind` before inspecting human text",
            "setup docs must require branching on agent_action.kind before human text",
        ),
        (
            "not treat the nonzero exit as corrupt JSON",
            "setup docs must treat setup exit 60/61 payloads as parseable JSON",
        ),
        ("`open_browser_claim`", "setup docs must document open_browser_claim"),
        (
            "Show the structured `claim_url` or `claim_code`",
            "setup docs must tell agents to surface structured claim URL/code",
        ),
        ("`answer_setup_question`", "setup docs must document answer_setup_question"),
        (
            "Ask the user for the structured `next_question`",
            "setup docs must tell agents to use structured next_question",
        ),
        ("`run_next_action`", "setup docs must document run_next_action"),
        (
            "Follow the structured `next_action` object",
            "setup docs must tell agents to use structured next_action",
        ),
        ("`retry_setup`", "setup docs must document retry_setup"),
        ("`wait_or_check_status`", "setup docs must document wait_or_check_status"),
        ("`inspect_failure`", "setup docs must document inspect_failure"),
        ("`check_status`", "setup docs must document check_status"),
        (
            "Agents must consume the structured setup JSON and `agent_action` values rather\nthan parsing human output.",
            "setup docs must prohibit parsing human output for setup state",
        ),
    ]
    for needle, message in expectations:
        expect(needle in text, message)


def check_diagnostics_docs_contracts() -> None:
    diagnostics_docs = require_file("docs/diagnostics.md")
    if diagnostics_docs is not None:
        text = diagnostics_docs.read_text(encoding="utf-8")
        expectations = [
            (
                "Upload only when the user approves the upload and accepts the retention\ndisclosure.",
                "diagnostics docs must require explicit upload approval and retention acceptance",
            ),
            (
                "An active login or support claim is required",
                "diagnostics docs must require active login or support claim",
            ),
            (
                "Support claims are authorization material",
                "diagnostics docs must classify support claims as authorization material",
            ),
            (
                "must not appear in the returned JSON payload or uploaded bundle\ncontent",
                "diagnostics docs must keep support claims out of payloads and bundles",
            ),
            (
                "machine ids, must appear only as redacted\nplaceholders such as `[machine_id]`",
                "diagnostics docs must require machine-id placeholders",
            ),
            (
                "Do not share raw local paths, prompts, account ids, machine ids, credential\nmaterial, cookies, or command output.",
                "diagnostics docs must prohibit sharing raw private diagnostics values",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)

    troubleshooting_docs = require_file("docs/troubleshooting.md")
    if troubleshooting_docs is not None:
        text = troubleshooting_docs.read_text(encoding="utf-8")
        expectations = [
            (
                "Do not parse human summaries. Use JSON status, error codes, and next-action\n"
                "fields.",
                "troubleshooting docs must prohibit parsing human summaries",
            ),
            (
                "prefer `agent_action.kind` as the stable\nmachine branch",
                "troubleshooting docs must preserve setup agent_action branch guidance",
            ),
            (
                "`60` | Browser/user action needed | Open or share the claim URL/code.",
                "troubleshooting docs must preserve browser/user-action exit code",
            ),
            (
                "`61` | Setup timed out | Rerun setup or use headless setup with claim URL/code.",
                "troubleshooting docs must preserve setup-timeout exit code",
            ),
            (
                "Plain verify is read-only. `verify --repair` repairs only daemon-owned\n"
                "WriteConfig config drift",
                "troubleshooting docs must keep verify repair daemon-owned and narrow",
            ),
            (
                "runs telemetry smoke only after\nthe config is clean",
                "troubleshooting docs must keep telemetry smoke after clean config",
            ),
            (
                "If repair JSON requires browser approval, or if verify\n"
                "returns `patch_disabled`, do not edit config files directly.",
                "troubleshooting docs must prohibit direct config edits on browser approval or patch_disabled",
            ),
            (
                "binds a deterministic per-user fallback port and reports the active endpoint in\n"
                "`ottto status --json`",
                "troubleshooting docs must preserve relay fallback endpoint contract",
            ),
            (
                "Do not kill another user's process unless you own that test\n"
                "account and have confirmed it is not the active customer install.",
                "troubleshooting docs must prohibit killing another user's active service",
            ),
            (
                "Use cloud-first logout:",
                "troubleshooting docs must preserve cloud-first logout guidance",
            ),
            (
                "Use local-only cleanup only after the user accepts that cloud disconnect did not\n"
                "complete.",
                "troubleshooting docs must keep local-only logout user-accepted",
            ),
            (
                "Upload only with explicit approval, retention disclosure acceptance, and an\nactive login or support claim.",
                "troubleshooting docs must require approval, retention acceptance, and authorization before upload",
            ),
            (
                "Support claims are authorization material",
                "troubleshooting docs must classify support claims as authorization material",
            ),
            (
                "do\nnot paste them into issues, chat, diagnostics summaries, or support bundle\ncontent.",
                "troubleshooting docs must prohibit pasting support claims",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)


def check_install_docs_contracts() -> None:
    install_docs = require_file("docs/install.md")
    if install_docs is not None:
        text = install_docs.read_text(encoding="utf-8")
        expectations = [
            (
                "Do not install by copying binaries from a mutable directory. Use the install\nowner named by the release channel.",
                "install docs must prohibit mutable binary-copy installs",
            ),
            (
                "`net.ottto.service` is a single-owner user LaunchAgent",
                "install docs must document single-owner LaunchAgent authority",
            ),
            (
                "Homebrew-owned LaunchAgent stays managed by `brew services`",
                "install docs must keep Homebrew-owned services under brew services",
            ),
            (
                "Do not install both the\napp bundle and Homebrew as independent service owners.",
                "install docs must prohibit independent Homebrew/app-bundle owners",
            ),
            (
                "The formula must pin immutable artifact URLs and SHA-256 hashes from the stable\nrelease manifest.",
                "install docs must require immutable Homebrew artifacts from the stable manifest",
            ),
            (
                "Do not self-overwrite a Homebrew-managed install",
                "install docs must prohibit self-overwriting Homebrew-managed installs",
            ),
            (
                "The helper verifies and opens the signed native DMG or PKG. It must not install\nmutable shell payloads, clear quarantine, or bootstrap launchd itself.",
                "install docs must keep verified native helper non-mutating before the signed package",
            ),
            (
                "the runtime install owner is `app_bundle`",
                "install docs must bind verified native installs to app_bundle",
            ),
            (
                "Do not use development install scripts unless the user explicitly asks for\ninternal QA on a trusted machine.",
                "install docs must keep development install scripts out of customer flows",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)

    support_docs = require_file("docs/support.md")
    if support_docs is not None:
        text = support_docs.read_text(encoding="utf-8")
        expectations = [
            (
                "This runbook is public-safe. Do not add private infrastructure details",
                "support docs must preserve public-safe boundary",
            ),
            (
                "account\nidentifiers, machine identifiers, raw command output, screenshots with local\npaths",
                "support docs must prohibit raw identifiers, command output, and local-path screenshots",
            ),
            (
                "claim codes, setup-run tokens, setup keys",
                "support docs must prohibit claim/setup secrets",
            ),
            (
                "raw prompts, raw model output, or private repository links",
                "support docs must prohibit raw model content and private repo links",
            ),
            (
                "Identify the installed surface without parsing human text",
                "support docs must require JSON status instead of human parsing",
            ),
            ("ottto status --json", "support docs must include status JSON command"),
            (
                "ottto update check --json",
                "support docs must include update check JSON command",
            ),
            (
                "ottto setup --json --no-browser --no-wait",
                "support docs must include headless setup JSON command",
            ),
            ("ottto account --json", "support docs must include account JSON command"),
            (
                "Share the claim URL or code with the user when JSON returns\n   `needs_user_action`",
                "support docs must route claim handoff through structured JSON",
            ),
            (
                "The CLI must not collect an Ottto password in the\n   terminal",
                "support docs must prohibit terminal password collection",
            ),
            (
                "Check app/source status with public app nouns",
                "support docs must preserve app-language triage",
            ),
            (
                "ottto apps detect --json",
                "support docs must include apps detect command",
            ),
            (
                "ottto apps status --app codex --json",
                "support docs must include app status command",
            ),
            (
                "ottto verify --repair --app codex --json",
                "support docs must include bounded verify repair command",
            ),
            (
                "respect repair authority metadata",
                "support docs must require repair authority metadata",
            ),
            (
                "If JSON requires browser approval, do not edit local config directly",
                "support docs must prohibit local config edits when browser approval is required",
            ),
            (
                "`verify --repair` may repair only WriteConfig config drift",
                "support docs must keep verify repair bounded to WriteConfig drift",
            ),
            (
                "Share only the command family, exit code, high-level status, support bundle\nstate, redaction summary, and next user action",
                "support docs must restrict diagnostics sharing to summary fields",
            ),
            (
                "Do not paste raw diagnostics\nJSON into public issues or chat",
                "support docs must prohibit raw diagnostics JSON in issues/chat",
            ),
            (
                "Upload diagnostics only after explicit user approval and retention disclosure\nacceptance",
                "support docs must require explicit approval and retention acceptance before upload",
            ),
            (
                "Do not ask users to paste\nclaims into public issues",
                "support docs must prohibit support claims in public issues",
            ),
            (
                "diagnostics JSON and uploaded bundle content should expose only that a support\nclaim was provided, not the claim value",
                "support docs must keep support claim values out of JSON and bundles",
            ),
            (
                "Use the detected install owner from JSON status and the release manifest:",
                "support docs must route update/rollback by detected install owner and manifest",
            ),
            (
                "Do not self-overwrite owner-managed files.",
                "support docs must prohibit self-overwriting owner-managed files",
            ),
            (
                "verify checksums, signing/notarization state,\nGatekeeper assessment, and `ottto status --json`",
                "support docs must require checksum/signing/Gatekeeper/status rollback verification",
            ),
            (
                "Security-sensitive reports go to `security@ottto.net`, not public issues",
                "support docs must route security reports away from public issues",
            ),
            (
                "Public issues are appropriate only for redacted, reproducible CLI",
                "support docs must scope public issues to redacted reproducible public-runtime bugs",
            ),
            (
                "Passwords, cookies, API keys, bearer tokens, setup-run tokens, setup keys,\n  claim codes, support claims, or raw credentials",
                "support docs must prohibit credential and claim collection",
            ),
            (
                "Raw prompts, raw model output, transcripts, customer data",
                "support docs must prohibit raw prompt/output/transcript/customer data collection",
            ),
            (
                "Absolute local filesystem paths, account identifiers, machine identifiers",
                "support docs must prohibit absolute paths and raw identifiers",
            ),
            (
                "evidence records contain only redacted pass/fail facts and stable artifact\n  references",
                "support docs must keep closeout evidence redacted and artifact-scoped",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)

    release_docs = require_file("docs/release-verification.md")
    if release_docs is not None:
        text = release_docs.read_text(encoding="utf-8")
        expectations = [
            (
                "Stable local-platform releases must be verifiable without trusting mutable\ninstaller state.",
                "release verification docs must distrust mutable installer state",
            ),
            (
                "Do not trust a release where the manifest omits required public-v1 metadata.",
                "release verification docs must treat manifest metadata as required",
            ),
            (
                "The computed digest must exactly match the manifest.",
                "release verification docs must require checksum equality with manifest",
            ),
            (
                "Verify `release-manifest.json.sig` with\n`macos_manifest_signature.sh verify --manifest release-manifest.json --identity \"$OTTTO_MACOS_CODESIGN_IDENTITY\"`",
                "release verification docs must require manifest signature verification",
            ),
            (
                "bound to the expected Ottto Developer ID identity",
                "release verification docs must bind signatures to Ottto Developer ID identity",
            ),
            (
                "The macOS stable release workflow can optionally publish a public GitHub Release\nas a **verification mirror only**.",
                "release verification docs must keep GitHub releases verification-only",
            ),
            (
                "The CDN at\n`install.ottto.net` remains the install and update source of truth",
                "release verification docs must keep CDN as install/update source of truth",
            ),
            (
                "stable-candidate RC QA",
                "release verification docs must require stable-candidate RC QA",
            ),
            (
                "The evidence must\nnot include private repo paths, local user paths, raw claim/setup tokens,\naccount or machine identifiers, passwords, API keys, or bearer credentials.",
                "release verification docs must keep stable-candidate evidence redacted",
            ),
            ("ottto status --json", "release verification docs must include status JSON check"),
            (
                "ottto update check --json",
                "release verification docs must include update-check JSON check",
            ),
            (
                "The JSON should report the expected version, install owner, update state, and\ndaemon reachability.",
                "release verification docs must require installed-runtime JSON fields",
            ),
            (
                "requires clean-machine evidence for every install owner advertised by the\nmanifest",
                "release verification docs must require clean-machine evidence per advertised owner",
            ),
            (
                "The verified native\ninstaller helper is not a runtime owner",
                "release verification docs must keep verified native helper out of runtime owners",
            ),
            (
                "Homebrew\nmust remain absent from `supported_install_owners` until its clean-machine\nlifecycle evidence passes.",
                "release verification docs must gate Homebrew owner support on clean-machine evidence",
            ),
            (
                "App-bundle\nevidence has to prove a second Homebrew install/start attempt is either a safe\nrefusal with instructions or an explicit migration, not silent owner takeover.",
                "release verification docs must prohibit silent app/Homebrew owner takeover",
            ),
            (
                "must not contain\nextra required install owners, unknown per-owner check names, local user paths,\nprivate repo paths, raw claim codes, account IDs, machine IDs, passwords, or\ntokens.",
                "release verification docs must keep stable evidence redacted and owner-scoped",
            ),
        ]
        for needle, message in expectations:
            expect(needle in text, message)


def check_private_runtime_pin() -> int:
    if PRIVATE_REPO_ROOT is None:
        return 0

    pin_path, pin_label = private_runtime_pin_path()
    if pin_path is None:
        return 0
    if not pin_path.is_file():
        fail(f"private runtime pin is missing: {pin_label}")
        return 0

    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"private runtime pin is invalid JSON: {error}")
        return 0
    if not isinstance(pin, dict):
        fail("private runtime pin must be a JSON object")
        return 0

    expect(pin.get("schema_version") == 1, "private runtime pin schema_version must be 1")
    expect(
        pin.get("generated_by") == "public_runtime_pin.v1",
        "private runtime pin generated_by must be public_runtime_pin.v1",
    )
    expect(
        pin.get("expected_repository") == "ottto-ai/ottto",
        "private runtime pin expected_repository must be ottto-ai/ottto",
    )
    authority_state = pin.get("authority_state")
    expect(
        authority_state in {"pre_public_repo_export", "public_repo_commit"},
        "private runtime pin authority_state must be pre_public_repo_export or public_repo_commit",
    )
    if REQUIRE_PUBLIC_AUTHORITY and authority_state != "public_repo_commit":
        fail("private runtime pin authority_state must be public_repo_commit when public authority is required")

    pinned_manifest = require_dict(
        pin.get("public_export_manifest"), "private runtime pin public_export_manifest"
    )
    public_manifest = require_dict(load_json("PUBLIC_EXPORT_MANIFEST.json"), "public export manifest")
    public_files = public_manifest.get("files")
    public_file_record_count = len(public_files) if isinstance(public_files, list) else None

    content_sha256 = pinned_manifest.get("content_sha256")
    expect(
        isinstance(content_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None,
        "private runtime pin content_sha256 must be a lowercase SHA-256 hex digest",
    )
    expect(
        content_sha256 == public_manifest.get("content_sha256"),
        "private runtime pin content_sha256 must match public manifest content_sha256",
    )
    expect(
        pinned_manifest.get("output_file_count") == public_manifest.get("output_file_count"),
        "private runtime pin output_file_count must match public manifest output_file_count",
    )
    expect(
        pinned_manifest.get("file_record_count") == public_file_record_count,
        "private runtime pin file_record_count must match public manifest file record count",
    )

    if authority_state == "public_repo_commit":
        public_commit = require_dict(
            pin.get("public_repo_commit"), "private runtime pin public_repo_commit"
        )
        expect(
            public_commit.get("repository") == pin.get("expected_repository"),
            "private runtime pin public_repo_commit.repository must match expected_repository",
        )
        commit = public_commit.get("commit")
        expect(
            isinstance(commit, str)
            and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "private runtime pin public_repo_commit.commit must be a full 40-character git SHA",
        )
        expect(
            public_commit.get("manifest_path") == "PUBLIC_EXPORT_MANIFEST.json",
            "private runtime pin public_repo_commit.manifest_path must be PUBLIC_EXPORT_MANIFEST.json",
        )
        expect(
            public_commit.get("manifest_content_sha256") == content_sha256,
            "private runtime pin public_repo_commit.manifest_content_sha256 must match pinned manifest content_sha256",
        )
        git_toplevel = git_output(["rev-parse", "--show-toplevel"])
        if git_toplevel is not None:
            expect(
                Path(git_toplevel).resolve() == PUBLIC_ROOT,
                "public authority check requires the public root to be the git checkout root",
            )
        git_head = git_output(["rev-parse", "HEAD"])
        if isinstance(commit, str) and git_head:
            expect(
                git_head.startswith(commit),
                "private runtime pin public_repo_commit.commit must match public root HEAD",
            )
        git_status = git_output(["status", "--porcelain"])
        if git_status is not None:
            expect(
                git_status == "",
                "public authority check requires a clean public root git checkout",
            )
    return 1


def check_private_consumers() -> int:
    if PRIVATE_REPO_ROOT is None:
        return 0
    if not PRIVATE_REPO_ROOT.is_dir():
        fail(f"private repo root is not a directory: {PRIVATE_REPO_ROOT}")
        return 0

    checks = 0
    checks += check_private_runtime_pin()

    registry_loader = require_private_file("backend/app/domain/connectors/registry.py")
    if registry_loader is not None:
        text = registry_loader.read_text(encoding="utf-8")
        expect(
            'REPO_ROOT / "connectors" / "registry.generated.json"' in text,
            "private backend registry loader must read root connectors/registry.generated.json",
        )
        expect("schema_version: Literal[\"connector_registry.v1\"]" in text, "private backend registry model must pin connector_registry.v1")
        checks += 1

    setup_schema = require_private_file("backend/app/schemas/setup_runs.py")
    if setup_schema is not None:
        text = setup_schema.read_text(encoding="utf-8")
        expect(
            'product: Literal["ottto-local-platform"]' in text,
            "private backend release response must pin ottto-local-platform product",
        )
        checks += 1

    setup_service = require_private_file("backend/app/features/setup_runs/service.py")
    if setup_service is not None:
        text = setup_service.read_text(encoding="utf-8")
        expect(
            'manifest.get("schema_version") != 1' in text,
            "private backend release loader must reject unsupported release manifest schema_version",
        )
        expect(
            'manifest.get("product") != "ottto-local-platform"' in text,
            "private backend release loader must reject unexpected release manifest product",
        )
        checks += 1

    frontend_control = require_private_file("frontend/src/lib/apps/local-telemetry-control.ts")
    if frontend_control is not None:
        text = frontend_control.read_text(encoding="utf-8")
        expect(
            "LOCAL_CONTROL_PROTOCOL_VERSION = 15" in text
            or re.search(r"LOCAL_CONTROL_PROTOCOL_VERSIONS\s*=\s*\[\s*15\b", text) is not None,
            "private frontend local-control client must send protocol version 15",
        )
        expect(
            'command: "telemetry_control"' in text,
            "private frontend local-control client must send telemetry_control command",
        )
        expect(
            'targetAddressSpace?: "loopback"' in text,
            "private frontend local-control client must request loopback target address space",
        )
        checks += 1

    return checks


if not PUBLIC_ROOT.is_dir():
    die(f"public repository root is not a directory: {PUBLIC_ROOT}")

check_schema_contracts()
check_registry_contract()
check_cli_contracts()
check_control_contracts()
check_setup_and_redaction_contracts()
check_local_health_diagnostics_contract()
check_docs_index_contracts()
check_examples_docs_contracts()
check_privacy_docs_contracts()
check_connector_docs_contracts()
check_agent_adapter_contracts()
check_diagnostics_docs_contracts()
check_install_docs_contracts()
check_setup_docs_contracts()
private_check_count = check_private_consumers()

if failures:
    for failure in failures:
        print(f"public-contract: {failure}", file=sys.stderr)
    die(f"failed with {len(failures)} issue(s) under {PUBLIC_ROOT}", code=1)

if private_check_count:
    print(
        "public-contract: checked public contracts at "
        f"{PUBLIC_ROOT} and {private_check_count} private consumer file(s)"
    )
else:
    print(f"public-contract: checked public contracts at {PUBLIC_ROOT}; private consumer checks skipped")
PY
