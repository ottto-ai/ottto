# Claude upkeep terminal result readback

Installed0.1.140 returned a retained Claude binding with no windows,
`claude_slot_collection_refresh_due` and `claude_slot_upkeep_in_progress`,
without an attempt-start clock. That combination did not prove a vendor
command was running. Foreground collection enqueued upkeep and called it
InProgress, while worker failures before a durable claim were not published.

The foreground now returns the existing RefreshDue result for queued work.
InProgress remains the durable claim state. Preclaim CredentialUnreadable,
ProbeFailed and queue-thread SpawnFailed results use the existing upkeep state
file and FinalSpawnGate. Their private witnesses preserve absent attempted_at,
record a genuine local result-observed clock and fence registration, exact
account/organization binding and credential deadlines. Removal, rebind,
consent/suppression changes, future/backward clocks and a newer active claim
refuse publication or replay. Legacy string attempted_at witnesses still decode.
Existing upkeep retry bounds are reused for terminal preclaim evidence. Prior
same-expiry claimed failure count and backoff deadline are preserved; an
unclaimed observation does not increment or reset the vendor retry budget.

Safe enum-derived terminal diagnostic codes carry that original local result
clock through the existing snapshot diagnostic representation. It is not a
quota measurement, successful provider check or vendor-command attempt.
No public protocol enum/field, provider cadence setting, login, breaker reset,
credential reader or separate registry/queue is added.

Focused mocked tests cover missing preclaim metadata, typed probe/spawn outcomes,
absence of a vendor call/attempt clock, expiry/binding/registration/clock fences,
newer active claims, backward decode, consent/removal/rebind/suppression and
redacted diagnostic projection. A negative control disabling only preclaim
publication fails the worker→next-status fixture at the missing terminal result.
Existing NeedsLogin and completed claimed-result readback fixtures remain scoped
regressions. Full service suite is deliberately not run: unrelated detached
worker test isolation is tracked by the separate held PR417.

Exact GPT-6.1-Sol/high standard AutoReview found two P2s, both accepted:
replace repeated exact-code receipts so a later outcome keeps its genuine newer
clock, and preserve claimed retry history on preclaim publication. Focused
fixtures verify receipt replacement and six prior failures retaining their
exponential retry bound. A focused review follows that repair; no provider/model
substitution or broad review repeat.

This change makes local upkeep continuity diagnosable. It does not identify or
recover the installed binding's actual acquisition failure. Only the two
approved public status commands were run; no follow-up auth/provider probes.

Agent: Codex Desktop, native gpt-6.1-sol/high.
Agent session id: 01a0f43d-2be9-7820-a5ba-a54acdc2c080.
Agent session name: claude_0140_acquisition.
Agent session source: native Codex turn_context at2026-09-30T21:34:07.941Z.
Effort board: Unified durable quota connections / QUOTA-SOURCE.
Repo-wide board update: no - private owner maintains the same existing ignored
account-key-revalidation receipt and owner plan; no effort-state completion claim.
Marketing board update: N/A - not marketing scope.
