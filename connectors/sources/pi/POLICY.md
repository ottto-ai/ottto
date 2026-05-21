# Pi Source Policy

Review tier: `official`

## Default Posture

- `local_sessions` defaults on for official pilot installs because it uploads aggregate usage and metadata only.
- `live_batches` requires an authenticated Pi/Ottto live path and keeps normalized assistant-message usage bounded to the existing ingestion contract.
- `route_status` defaults on when local non-secret route metadata is available.

## Documented Surfaces

- Pi local session JSONL may be read locally for aggregate assistant-message usage snapshots.
- Pi live usage batches may be collected only through the authenticated Pi/Ottto ingestion path.
- Local route status may report explicit non-secret route, provider, model, selector, and subscription evidence.

## Undocumented Surfaces

- Pi `source_id` remains `pi` even when the model or billing provider is OpenAI, Anthropic, Vertex, Bedrock, OpenRouter, Vercel AI Gateway, or another gateway.
- Do not infer gateway or fast/speed mode from provider/model identity. Preserve explicit selector and route evidence only.
- Do not scrape browser sessions, cookies, private account pages, or provider dashboards.

## Local-Only Behavior

- Local Pi session reads stay on the user's machine until transformed into aggregate usage, source-plan, or collector-health records.
- Local route observations must omit provider credentials and raw endpoint secrets.

## Upload Boundaries

- Do not upload raw prompts, responses, local paths, provider credentials, or API keys.
- Use `gateway_provider` only for gateway/proxy/broker evidence.
