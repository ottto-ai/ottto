# Quota credit model follow-up

Three small corrections to the shared daemon credit model and the
backend-upload redaction, from the re-review of the quota contract v2.2 change.

- **Upload privacy check folds ASCII too.** `is_backend_safe_credit_text` no
  longer skips its lookalike fold for ASCII input. The fold collapses
  whitespace runs, so a title such as `Bearer<TAB>x` now fails like
  `Bearer x`, matching the backend's privacy match. Ordinary display text is
  unaffected.
- **Claude saved-reset count is cleared without a complete list.**
  `ListObservation::Unavailable` and `ListObservation::NotSupported` now carry
  the provider. For Anthropic saved resets, `GrantsBuild::apply_to` sets
  `remaining` to the sum of `resets_left` for a complete list and clears it in
  every other state, including an unread or unsupported list; the status
  follows (`unknown`). A Codex `availableCount` is the provider's own count
  and stays.
- **One-time pool instants are normalized by the model.** `one_time_credit`
  takes `TimeInput` for `expires_at` and `observed_at`, normalizes them to UTC
  like grant times, and returns a `field_refused` diagnostic for an instant it
  cannot read.

`SectionCache::observe_balances` also ignores the grant-list section, which
only `observe_grant_list` fills.

Adapter-visible changes: the two `ListObservation` variants gain `provider`,
and `one_time_credit` takes `TimeInput` instead of formatted strings. The
canonical fixtures are unchanged.

Not verified here: provider adapters and live provider reads.
