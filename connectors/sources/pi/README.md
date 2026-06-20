# Pi Source Package

Pi remains an official Ottto app/source with provider-aware attribution. This package describes the internal collectors that preserve Pi as the app that produced usage while keeping billing and model provider fields independent.

Collectors:

- `local_sessions`: reads local Pi session JSONL files through `ottto-locald` and uploads aggregate local usage snapshots.
- `live_batches`: describes Pi's first-party normalized live usage endpoint.
- `route_status`: describes local route/provider/model observations used for setup verification and billing identity evidence.
- `identity_probe`: parity stub. Pi has no equivalent vendor identity CLI today; the collector emits `not_applicable` heartbeats so the resolver can tell intentional absence from collector failure. Per-turn `gateway_provider` already lives in Pi's `message_end` events, so identity_probe pairing is unnecessary for attribution.

Pi collectors must preserve `billing_provider`, `model_provider`, `billing_channel`, `auth_mode`, `gateway_provider`, and `subscription_product` when evidence exists. Do not collapse Pi usage into Codex, Claude Code, OpenAI, or Anthropic based on provider alone.
