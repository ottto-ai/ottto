# Quota observation and check evidence

Quota windows retain the original observation time when a local cache is reused.
Successful OAuth windows use local response-completion time, not a provider-supplied
timestamp or a later upload time. Optional collection diagnostics distinguish
successful responses, failed requests, breaker suppression and local cache reuse.
Their timestamp describes that outcome, not a new quota observation.

Desktop statusLine resolution preserves account and organization proof in the
existing local cache and bounded memo. Equal claims in different workspaces remain
ambiguous. Existing account-only cache readings do not invent a workspace.

A supported statusLine meter may replace an older OAuth meter only with matching
account/workspace and comparable window/pool metadata, newer supported observation
time and an actual reading. Missing identity/clocks, future clocks, different pools
and unreported windows cannot replace or erase a known meter. Other meters and
credits remain independently dated. Existing refresh/retry/breaker policy is unchanged.

Backend admission of the additive diagnostic timestamp/binding fields must deploy
before promoting this daemon. Golden typed diagnostics/leaf fixtures and focused
resolver, replacement, cache-preservation and redaction tests cover this boundary.
No cadence improvement or provider-confirmed cache behavior is claimed.
