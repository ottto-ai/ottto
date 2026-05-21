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
from pathlib import Path
from typing import Any

PUBLIC_PROTOCOL_VERSION = 11
PUBLIC_ROOT = Path(sys.argv[1]).resolve()
PRIVATE_REPO_ROOT = Path(sys.argv[2]).resolve() if sys.argv[2] else None
PRIVATE_RUNTIME_PIN_ARG = sys.argv[3]
REQUIRE_PUBLIC_AUTHORITY = sys.argv[4].lower() in {"1", "true", "yes"}

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
        if isinstance(manifest_path, str):
            require_file(manifest_path)
        operations = require_list(source.get("operations"), f"{context} operations")
        for operation in ("detect", "verify", "repair", "collect_usage", "monitor_quota", "upload_snapshot", "diagnostics"):
            expect(operation in operations, f"{context} operations must include {operation}")
        collectors = require_list(source.get("collectors"), f"{context} collectors")
        collector_ids = [
            collector.get("collector_id") for collector in collectors if isinstance(collector, dict)
        ]
        expect(collector_ids, f"{context} must expose at least one collector")
        expect(
            len(collector_ids) == len(set(collector_ids)),
            f"{context} collector_id values must be unique",
        )
        for collector_value in collectors:
            collector = require_dict(collector_value, f"{context} collector")
            collector_context = f"{context} collector {collector.get('collector_id') or '<unknown>'}"
            collector_manifest_path = collector.get("manifest_path")
            expect(
                isinstance(collector_manifest_path, str)
                and collector_manifest_path.startswith("connectors/sources/")
                and collector_manifest_path.endswith("/collector.toml"),
                f"{collector_context} manifest_path must point to a collector manifest",
            )
            if isinstance(collector_manifest_path, str):
                require_file(collector_manifest_path)
            expect(isinstance(collector.get("uploads_raw_content"), bool), f"{collector_context} uploads_raw_content must be boolean")
            require_list(collector.get("emits"), f"{collector_context} emits")


def check_cli_contracts() -> None:
    status_output = require_dict(load_json("fixtures/cli/status-json-output.json"), "CLI status output")
    expect_protocol(status_output.get("protocol_version"), "CLI status output")
    expect(status_output.get("daemon") == "running", "CLI status output daemon must be running")

    error_output = require_dict(load_json("fixtures/cli/daemon-unavailable-error.json"), "CLI daemon error")
    error = require_dict(error_output.get("error"), "CLI daemon error payload")
    expect(error.get("code") == "daemon_unavailable", "daemon error code must be daemon_unavailable")
    expect(error.get("retryable") is True, "daemon error must be retryable")

    setup_claim = require_dict(load_json("fixtures/cli/setup-claim-request.json"), "CLI setup claim request")
    expect_protocol(setup_claim.get("protocol_version"), "CLI setup claim request")
    expect(setup_claim.get("client_kind") == "cli", "CLI setup claim request client_kind must be cli")
    expect(setup_claim.get("command") == "setup", "CLI setup claim request command must be setup")

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

    browser_claim = require_dict(
        load_json("fixtures/cli/setup-browser-claim-output.json"),
        "CLI browser claim output",
    )
    expect(browser_claim.get("status") == "waiting_for_browser", "browser claim status must be waiting_for_browser")
    expect(browser_claim.get("claim_code"), "browser claim output must include claim_code")
    expect(browser_claim.get("claim_url"), "browser claim output must include claim_url")
    next_action = require_dict(browser_claim.get("next_action"), "browser claim next_action")
    expect(next_action.get("type") == "browser_claim", "browser claim next_action type must be browser_claim")
    expect(next_action.get("claim_code") == browser_claim.get("claim_code"), "browser claim next_action must repeat claim_code")
    expect(next_action.get("claim_url") == browser_claim.get("claim_url"), "browser claim next_action must repeat claim_url")

    needs_user = require_dict(
        load_json("fixtures/cli/setup-needs-user-action-output.json"),
        "CLI needs-user-action output",
    )
    expect(needs_user.get("status") == "waiting_for_approval", "needs-user-action status must be waiting_for_approval")
    question = require_dict(needs_user.get("next_question"), "needs-user-action next_question")
    expect(question.get("type") == "approval", "needs-user-action next_question type must be approval")

    timed_out = require_dict(
        load_json("fixtures/cli/setup-timed-out-output.json"), "CLI setup timed-out output"
    )
    expect(timed_out.get("status") == "timed_out", "setup timed-out status must be timed_out")
    expect(timed_out.get("claim_code_provided") is True, "setup timed-out output must preserve claim_code_provided")

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
    expect(upload.get("approval_required") is True, "redacted diagnostics upload must require approval")
    expect(upload.get("authorization") == "not_requested", "redacted diagnostics authorization must be not_requested")
    redaction = require_dict(bundle.get("redaction"), "redacted diagnostics redaction")
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
    expect("installation.launch_agent_path" in fields, "redaction fields must include launch_agent_path")
    expect("security.auth_header" in fields, "redaction fields must include auth_header")
    sections = require_list(bundle.get("sections"), "redacted diagnostics sections")
    section_items = {
        section.get("name"): section.get("items")
        for section in sections
        if isinstance(section, dict) and isinstance(section.get("items"), dict)
    }
    installation = require_dict(section_items.get("installation"), "redacted installation section")
    expect(installation.get("launch_agent_path") == "[path]", "launch_agent_path must be path-redacted")
    security = require_dict(section_items.get("security"), "redacted security section")
    expect(security.get("auth_header") == "[REDACTED]", "auth_header must be redacted")

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
            and re.fullmatch(r"[0-9a-f]{7,40}", commit) is not None,
            "private runtime pin public_repo_commit.commit must be a git SHA prefix",
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
            "LOCAL_CONTROL_PROTOCOL_VERSION = 11" in text,
            "private frontend local-control client must send protocol version 11",
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
check_agent_adapter_contracts()
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
