# Codex effective rate-limit snapshot

## Outcome

Codex quota collection now gives the app server's top-level `rateLimits`
snapshot authority over the auxiliary `rateLimitsByLimitId` map. This restores
the single effective weekly Pro quota and the credit balance carried by that
same snapshot instead of publishing inactive internal pools as customer quotas.

The limit-id map remains a compatibility fallback for app-server versions that
omit a usable effective snapshot. Reset-bank counts remain separate from
ChatGPT credits.

## Verification

- Targeted `ottto-service` Codex app-server parser tests pass.
- Regression coverage includes an effective weekly `codex` snapshot beside
  zero-valued `base_model_inference` and `codex_bengalfox` auxiliary pools.
- A top-level snapshot containing only null placeholders still falls back to a
  usable compatibility-map snapshot.
- The regression proves only the effective weekly window, its credit balance,
  and the separately reported reset bank are emitted.
