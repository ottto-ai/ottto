# Pi Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it uploads aggregate usage and metadata only.
- `live_batches` is disabled by default. It remains documented as a future live path, but Pi acceptance must use local session and route evidence until live ingestion is explicitly re-enabled.
- `route_status` defaults on when local non-secret route metadata is available.
- `identity_probe` defaults on as a parity stub: it runs no subprocess, reads no files, and never accesses Keychain. It emits `not_applicable` heartbeats so the resolver can distinguish intentional absence from collector failure.

## Documented Surfaces

- Pi local session JSONL may be read locally for aggregate assistant-message usage snapshots.
- Pi live usage batches may be collected only through the authenticated Pi/Ottto ingestion path.
- Local route status may report explicit non-secret route, provider, model, selector, and subscription evidence.

## Undocumented Surfaces

- Pi `source_id` remains `pi` even when the model or billing provider is OpenAI, Anthropic, Vertex, Bedrock, OpenRouter, Vercel AI Gateway, or another gateway.
- Do not infer gateway or fast/speed mode from provider/model identity. Preserve explicit selector and route evidence only.
- Do not scrape browser sessions, cookies, private account pages, or provider dashboards.
- `identity_probe` must remain a stub until/unless Pi ships a documented identity CLI. It must never read token bytes, access Keychain items, scan disk for credentials, or call any provider account endpoint.

## Local-Only Behavior

- Local Pi session reads stay on the user's machine until transformed into aggregate usage, source-plan, or collector-health records.
- Local route observations must omit provider credentials and raw endpoint secrets.
- A Pi smoke that creates a local session is sufficient for local-only source acceptance. Missing fresh live telemetry must be reported as `pi_local_only`, not as a repair-required telemetry failure.

## Upload Boundaries

- Do not upload raw prompts, responses, local paths, provider credentials, or API keys.
- Use `gateway_provider` only for gateway/proxy/broker evidence.
