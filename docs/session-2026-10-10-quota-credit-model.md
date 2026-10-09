# Quota contract v2.2 credit types and shared credit model

The agent-status protocol now carries per-grant credit detail and what each
credit balance is. `AgentCreditBalance` gains grant, expiry and read-clock
fields (`observed_at`, `expires_at`, `disabled_reason`, `grant_count`,
`grants`, `grants_state`, `grants_observed_at`) and the v2.2 fields `kind`,
`title`, `next_expires_at`, `latest_granted_at` and the provider readiness
passthrough (`eligible`, `at_limit`, `ineligible_reason`, `cooldown_until`).
`AgentCreditGrant` is new. Every new field is optional and skipped when
absent, so an older balance serializes byte for byte as before (pinned by a
test). New enum values decode leniently: an unknown `kind`, grant type or
grant status becomes `unknown`, and an unknown `grants_state` becomes absent.

The backend-upload redaction checks every new field one at a time; a bad value
never rides along and never drops the balance. Provider text (balance and grant
`title`) passes the privacy guard, also after folding Unicode lookalikes
(full-width forms, slash lookalikes, invisible format characters). Reason codes
(`disabled_reason`, `ineligible_reason`, grant `clears`) must be short
lowercase codes. `disabled_reason` rides only with `enabled: false`, and
readiness only on saved resets. Timestamps must be RFC 3339 instants. A grant
with a malformed `grant_key` is dropped, and the list is then no longer
complete.

`ottto-service` gains one shared credit model, `quota_credit_model`, used by
both provider adapters:
- grant keys (SHA-256 of `<provider>:credit_grant:<id>`, case-preserving);
- grant building: status table, per-field refusal, the 20-grant cap in
  soonest-expiry order, and `grants_state` with `partial` > `capped` > `complete`;
- complete-gated summaries (soonest expiry, latest grant time, Claude
  saved-reset count), with the saved-reset `status` following the count;
- provider titles pass the privacy guard on the value as given and on its
  NFKC form (as the backend does) before any truncation;
- readiness passthrough and the switched-off balance shape;
- the one-time pool shape;
- `SectionCache`, which re-sends the last observed section when a reading
  skipped it, so read cadence never toggles what the backend sees.

Its decisions live in private fields: adapters build inputs, call the
constructors and `apply_to`, and read diagnostics.

Credit balances never carry `updated_at`, fresh or re-sent. Today's consumers
read it as an observation time and otherwise fall back to the snapshot's
capture time.

Adapter submodules for Codex grants and Claude pools exist as empty stubs; the
adapters wire the model in follow-up changes. Until then the model module and
the new imports carry temporary dead-code allowances.

The duplicate-slot meter fingerprint also ignores the two provider read clocks,
because a re-sent section keeps its original read time.

Canonical synthetic fixtures live in `fixtures/agent-status/quota-contract-v2.2/`
(provider inputs, expected wire output, a 21-grant cap case and two re-send
sequences). The model tests regenerate and check them byte for byte.

Not verified here: provider adapters, live provider reads, backend acceptance
of the new fields and installed-app decoding. Nothing in this change emits the
new fields yet.
