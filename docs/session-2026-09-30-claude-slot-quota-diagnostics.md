# Exact-slot Claude quota diagnostics

Registered Claude quota failures previously discarded the usage collector's
diagnostics before the degraded account snapshot was built. Consequently a
provider request failure and a local suppressed check could both appear only
as `claude_quota_temporarily_unavailable`.

`ClaudeConfigSlotCollectionStatusV1.quota_check_diagnostics` now retains a
default-empty, bounded set of existing `AgentStatusDiagnostic` outcomes. Only
known codes with the same nonempty account and organization hashes survive.
Messages are canonical safe descriptions; paths, raw provider errors, account
labels and arbitrary diagnostic codes are not copied. Clearing a slot binding
also clears these outcomes. Older persisted slots decode with an empty field.

The registered error return and successful cached-result path preserve these
outcomes for degraded projection. Existing failed-check, suppressed-check,
cache-reuse and successful-check codes keep their actual producer clocks.
Missing, malformed and future clocks remain absent, never substituted with
slot `observed_at`, snapshot `captured_at`, last full read or upload time.
Collection state and upkeep result codes are untimed. An existing upkeep
`attempted_at` is exposed separately as `claude_slot_upkeep_attempt_started`;
it is not an upkeep completion or quota provider-check clock.

Backend-upload diagnostics retain only safe descriptions, outcome clocks and
exact hashes through the existing redaction contract. No backend schema change
is required: the current schema already accepts these diagnostic fields.

This is evidence preservation, not an acquisition fix. A working Claude
Desktop Team usage panel does not prove the independently registered Claude
Code credential root can collect quota. Distinct accounts need distinct live
receipts; one account's prior authentication rejection is not another's cause.
No authentication, provider-request, cache, breaker, upkeep, retry, polling or
quota-state behavior changes.

Validation: focused `ottto-service` diagnostic, registered-error/persistence
and degraded exact-binding/profile fixtures; existing protocol compatibility
fixture; formatting, public export manifest and diff checks. No provider
traffic or full unchanged suite is required for these synthetic fixtures.

AutoReview: one explicit GPT-6.1-Sol/high CLI attempt failed before substantive
review with HTTP 400, unsupported model for this CLI ChatGPT account. No model
substitution or repeated invocation. Unavailable posture recorded; native
independent review remains the owner's pre-intake requirement.

Agent: Codex Desktop, GPT-6.1-Sol/high, native turn-context verified.
Session: `01a0f319-9ba4-7a41-ba08-037155894627`.
Effort: Ingestion North Star QUOTA/SOURCE, bounded A/B diagnostic preservation.
Owner review/intake and a released exact-pair live receipt remain separate.
