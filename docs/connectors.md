# Connector Contribution

Ottto source packages describe apps and collectors without giving them runtime
permission by default. Manifests are closed contracts and must be validated
before they are accepted.

## Package Layout

Source packages live under `connectors/sources/<source>/`:

- `source.toml`: source package manifest.
- `README.md`: contributor-facing source explanation.
- `POLICY.md`: supported surfaces, unsupported surfaces, local-only behavior,
  and upload boundaries.
- `collectors/<collector>/collector.toml`: collector manifest.
- `collectors/<collector>/fixtures/*.json`: safe emitted-record examples and
  upload policy evidence.

The generated registry lives at `connectors/registry.generated.json`.

## Required Safety Rules

- Unknown manifest fields fail validation.
- Required fields must be present; use explicit empty arrays when empty.
- Hidden credential reads, raw prompt/output upload, network calls, live
  telemetry, config writes, and undocumented auth/network surfaces cannot
  default to enabled.
- Official first-party fixtures must not expose raw prompts, responses, tool
  output, command output, local paths, credentials, cookies, API keys,
  passwords, or secrets.
- Connector manifests do not grant Advisor action permissions and do not replace
  pricing selector or attribution contracts.

## Validate A Change

Run the generator and registry tests from the repository root:

```bash
cd backend
uv run python scripts/generate_connector_registry.py
uv run python scripts/generate_connector_registry.py --check
```

Use the public Rust testkit helpers in source-package tests instead of copying
backend generator logic:

```rust
use ottto_connector_testkit::{
    assert_collector_manifest_contract, CollectorManifestContract,
};
```

First-party packages for Codex, Claude Code, and Pi are examples of the
expected shape.
