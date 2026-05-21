# Pi Source Package

Pi remains an official Ottto app/source with provider-aware attribution. This package describes the internal collectors that preserve Pi as the app that produced usage while keeping billing and model provider fields independent.

Collectors:

- `local_sessions`: reads local Pi session JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `live_batches`: describes Pi's first-party normalized live usage endpoint.
- `route_status`: describes local route/provider/model observations used for setup verification and billing identity evidence.

Pi collectors must preserve `billing_provider`, `model_provider`, `billing_channel`, `auth_mode`, `gateway_provider`, and `subscription_product` when evidence exists. Do not collapse Pi usage into Codex, Claude Code, OpenAI, or Anthropic based on provider alone.
