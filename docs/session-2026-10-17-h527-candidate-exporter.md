# Read-only historical candidate exporter (`h527_candidates:v1`)

`snapshots/h527_candidates.rs` turns one operator manifest of exactly 18 Claude sessions into a candidate packet for a separate, reviewed admission writer. It has no runtime caller and no CLI. It does not scan, parse, upload, call a provider or the backend, or write scan index, upload progress, quarantine, status or ACK state. Its inputs are the production pipeline's own values, borrowed read-only: the post-policy upload set, `ClaudeUsageAuthorityDisposition` and `ScanIndex`.

## Packet

```
{contract_version:"h527_candidates:v1", operation_id, user_id, organization_id, device_id,
 machine_id, producer_revision, collector_version, scope_session_keys:[18],
 members:[{source_session_id, session_key_sha256, prior_refusal_body_witness,
           disposition:"eligible"|"held", reason, qualification_report_sha256,
           cross_session_conservation:"qualified"|"unknown",
           batch_request_json?, batch_request_sha256?}]}
```

- `session_key_sha256` is SHA-256 of the UTF-8 `session_key:v1` string: (`claude_code`, machine id, full source session id), backslash doubled, pipe as `\p`, joined by `|`. This matches the backend's `session_entity_key`, not the unit-separated storage locator. Tests pin four backend-computed vectors.
- Scope ids must be lowercase canonical UUIDs, `producer_revision` a 40-hex commit, `collector_version` this binary's own version. Every member must be a full Claude session id (UUID, optionally `_agent-` suffixed), its key must bind that id, and its refusal witness must be 64 hex. Members and keys are distinct; anything else refuses the whole export. The refusal witness is copied, not verified.
- An eligible member carries `batch_request_json`, the exact bytes of the ordinary `SnapshotBatchRequest` serializer for one cloned pipeline item (semantic envelope, entity-ACK declaration, head-CAS rule, `validate_snapshot_batch_request`), and `batch_request_sha256` of those bytes. The client report is `ClientReport::empty()`, as in the snapshot audit's offline reproduction. A held member omits both fields. The packet does not canonicalize bodies; post-policy canonical witnesses stay with the server plan.
- Each member has a content-free qualification report (RFC 8785, `h527_candidate_qualification:v1`) with census, fence, hold and request-set facts, the body hash, and `conservation_scope: local_complete_census:v1`. Only its SHA travels in the packet; the report stays with the operator.

## Verdicts

Reasons are closed: eligible `qualified_source_ownership`, `exact_exclusion`, `exact_previous_ack_membership`; held `unknown_owner`, `incomplete_census`, `cap_overflow`, `creator_hold`, `missing_evidence`, `money_decrease`. Checks run in this order:

1. Account deferral of the session → `creator_hold`. Other authority quarantine, or more than one upload item for the id → `unknown_owner`. No upload item → `missing_evidence`.
2. Census not complete, invalid, missing coverage, or with unobserved family members → `incomplete_census`.
3. Duplicate-witness overflow, either census fence, or a page cap invalidation → `cap_overflow`.
4. No `session_exclusive_reported_usage:v1` from the pipeline, or counted requests without request ids → `missing_evidence`.
5. A request hash in the durable duplicate witness that the member's exact legacy exclusion does not remove → `unknown_owner`.
6. Otherwise eligible: `exact_exclusion` when an existing legacy exclusion removed one of the member's requests, else `qualified_source_ownership`.

The exporter never emits `exact_previous_ack_membership` (no retained per-request membership of an acknowledged revision exists) or `money_decrease` (pricing belongs to the server plan). It never sets a contract, tag or fingerprint on an item. Contract-5 rows and the untagged no-evidence fallback are whatever the ordinary pipeline produced.

## Limits

- The local census cannot see an accepted body whose transcript was deleted or left the window. `qualified` means qualified within `local_complete_census:v1` only.
- There is no production caller. Producing real inputs needs a read-only split of the sync cycle's pre-upload phase (local evidence with the cycle's ordinary contract-5 permit, account binding, upload policy, backfill cutoff) that runs on in-memory copies and never saves. That phase lives in the scan/sync owner's files and is not changed here.

Fixture `fixtures/h527-candidates/held-mixed.v1.json` is the exact packet for a synthetic census with every member-scoped hold class. Tests drive real parser items from synthetic transcripts. Validation is hosted Public CI only; no local Cargo was run.
