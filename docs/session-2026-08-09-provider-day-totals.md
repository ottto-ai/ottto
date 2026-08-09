# Session: Provider day totals and model breakdown

Date: 2026-08-09

## Outcome

The Codex daily-aggregate normalizer now reads the provider's day-level
`totals` object and `models` array. Provider-owned rows use the reserved
`provider_day_total` surface: `model=__all__` is the provider's complete day
total, while a bounded model slug is the provider's day-level model grain.
Client-derived surface rows remain unchanged.

Per-model rows continue to omit credits because the provider's model entries
do not attribute that meter. Day totals and recognized client sums are compared
locally for every mutually reported counter. A mismatch emits a bounded warning
containing only the UTC day, metric name, provider number, and recognized-client
number.

The live payload's `users` member is an integer aggregate count at total,
client, and model grains, not an array of user records. The collector recognizes
its shape for accounting but does not upload it because
`provider_daily_reference.v1` has no user-count field and the customer outcome
being added is the provider money/token comparison.

## Privacy and disclosure

The outgoing batch schema is unchanged. Only counts, UTC days, the closed
surface vocabulary, bounded model slugs, and opaque fingerprints can cross the
wire; no prompts, titles, content, credentials, account identifiers, or user
values are retained.

No disclosure bump is required. The existing v1 disclosure already says daily
totals are broken down by Codex surface and model, and this change corrects that
declared behavior without reading a new endpoint or content category.

## Verification

- `cargo test -p ottto-service provider_daily_reference`
- `cargo fmt --all --check`
- `scripts/public_repo_manifest_check.sh`
