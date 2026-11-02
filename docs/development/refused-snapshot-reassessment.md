# Refused snapshot reassessment

An older activity timestamp does not prove that accepted usage covers a refused
snapshot. `accepted_log_stale_older_upload` remains owed and its exact refused
bytes stay suppressed. Input changes can produce a new body and one new offer.
`accepted_log_stale_older_mixed` uses ordinary non-permanent retry custody.
These reply paths are shared by Claude, Codex and Pi; the observed timestamp
refusal and the head-comparison operator action currently concern Claude.

Existing terminal records retain their disposition without an operator action.
They remain counted as owed. To apply a server head comparison, place a regular
JSON file beside the destination/source upload-progress JSON, replacing its
`.json` extension with `.stale-older-reopen-once`:

```json
{
  "nonce": "unique-operator-action",
  "entities": [{
    "entity_hash": "2fe67006",
    "source_session_id": "session-example",
    "snapshot_fingerprint": "<64 lowercase hex from the retained record>",
    "body_witness": "<64 lowercase hex from that exact refusal>",
    "verdict": "covered"
  }]
}
```

The entity hash is the first eight lowercase hex digits of SHA-256 of the UTF-8
source slug, machine identifier and source session identifier, separated by byte
`0x1f`. The example hash uses `claude_code`, `machine-example` and
`session-example`. Supply the verdict from the server's per-entity head
comparison; activity order is never coverage proof. Use `owed` when any portion
has no coverage proof, including unknown hour/model grains. Unlisted records
retain their disposition and debt. Symlinks, invalid bindings and a body that
has since changed grant no action. The list is validated before it is applied.

A `covered` verdict marks the exact retained revision `superseded_terminal`
without reading a source or creating an ACK. An `owed` verdict sets the existing
quarantine to `retry_pending` and requests one fresh Full through existing
pacing and the existing shared per-cycle retry limit. It does not resend
identical refused bytes. The claim remains pending until an owning acquisition
lease is recorded; a failed save prevents acquisition. The last nonce and
pending claims are durable, so leaving the file present does not renew them.
A later explicit action uses a new nonce. There is no timer, new cap or ongoing
OFF switch. The action records an attempt, never discharges the remaining debt.
Input changes and subsequent server answers retain their ordinary behavior.

Exact refused revisions stay with the existing refusal owner. A changed-body
ACK does not establish coverage of another revision. Proof, identity, ACK
custody and server acceptance authority are unchanged.

Existing refusal counters, `native_collection_page` and `source_finish` records
carry scalar owed count, known requests/tokens, unknown counts and oldest known
age. Existing terminal counters remain alongside them. Overlapping revisions
count as one entity; known usage describes one retained revision, not the sum of
overlapping bodies. Tokens respect the declared cached-input scope. Missing age
stays unknown. The existing per-source last-line counter emits an alarm when the
owed count or oldest known age rises. Page and finish records also support daily inspection; there is
no separate daily replay, observation window, history or age bucket structure.
Diagnostics gate and retire nothing.

State extensions default absent and are omitted when empty. Existing reason and
disposition vocabulary, schema and parser versions are unchanged. A malformed
optional exposure observation cannot discard its owning refusal.
