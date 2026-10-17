# Read-only historical candidate exporter (`h527_candidates:v1`)

`snapshots/h527_candidates.rs` turns one operator manifest of exactly 18 Claude sessions into a candidate packet for a separate, reviewed admission writer. It is a non-functional core: there is no runtime caller or CLI, and today every member is held without a body. It does not scan, parse, upload, call a provider or the backend, fetch an activity hint, or write scan index, upload progress, quarantine, status or ACK state. Its inputs are the production pipeline's own values, borrowed read-only: the post-policy upload set, `ClaudeUsageAuthorityDisposition` and `ScanIndex`.

## Packet

```
{contract_version:"h527_candidates:v1", operation_id, user_id, organization_id, device_id,
 machine_id, producer_revision, producer_revision_source:"operator_supplied_unverified",
 producer_binary_sha256, collector_version, unresolved_fields:["prior_refusal_body_witness"],
 scope_session_keys:[18],
 members:[{source_session_id, session_key_sha256, prior_refusal_body_witness,
           disposition:"held", reason, qualification_report_sha256,
           cross_session_conservation:"unknown"}]}
```

- `session_key_sha256` is SHA-256 of the UTF-8 `session_key:v1` string: (`claude_code`, machine id, full source session id), with backslash doubled and pipe written as `\p`, joined by `|`. This matches the backend's `session_entity_key`, not the unit-separated storage locator. Tests pin four backend-computed vectors.
- Scope and member validation:
  - Scope ids must be lowercase canonical UUIDs.
  - `producer_revision` must be a 40-hex commit. The operator supplies it and the binary cannot prove it.
  - Every member must be a full Claude session id: a UUID, optionally with an `_agent-` suffix.
  - Each member's key must bind its id, and its refusal value must be 64 hex.
  - Members and keys must be distinct.
  - Anything else refuses the whole export.
- `collector_version` and `producer_binary_sha256` describe the build that actually ran the export: its own compiled version and the SHA-256 of its executable. They never claim to be the installed daemon's version.
- `prior_refusal_body_witness` is opaque diagnostic metadata, copied and not verified. The daemon's additive upload body witness covers only additive evidence, so it does not identify a refused body. `unresolved_fields` keeps that gate explicit until a retained refusal record is defined and qualified.
- Each member has a content-free qualification report (RFC 8785, `h527_candidate_qualification:v1`) with local hold, census, fence and request-set facts, `local_checks_passed`, and `global_conservation_evidence: "unavailable"`. Only the report's SHA travels in the packet; the report stays with the operator.

## Verdicts

Reasons are a closed set:

- eligible: `qualified_source_ownership`, `exact_exclusion`, `exact_previous_ack_membership`
- held: `unknown_owner`, `incomplete_census`, `cap_overflow`, `creator_hold`, `missing_evidence`, `money_decrease`

No member is eligible today. Cross-session conservation has to cover the target set and every already-counted accepted session. That includes accepted bodies whose transcripts were deleted or left the census window. A complete local census cannot prove absence there, and no interface supplies qualified historical evidence. So conservation stays `unknown`, and no caller flag or report hash can change that.

Local checks still run, first failure wins:

1. If the session is account-deferred, the reason is `creator_hold`.
2. If it is in another authority quarantine, or has more than one upload item, the reason is `unknown_owner`.
3. If it has no upload item, the reason is `missing_evidence`.
4. If the local census is incomplete, invalid, missing coverage, or has unobserved family members, the reason is `incomplete_census`.
5. If the duplicate witness overflowed, either census fence tripped, or a page cap invalidation happened, the reason is `cap_overflow`.
6. If counted requests have no provider request ids, the reason is `missing_evidence`.
7. If a request hash is in the durable duplicate witness and the member's exact legacy exclusion does not remove it, the reason is `unknown_owner`.

A member that passes every local check is held as `incomplete_census`, with `local_checks_passed: true`. Session-exclusive proof is not required: a truthful unproven transcript body passes the local checks the same way a proven one does.

Items are never changed. Contract-5 rows can only come from the ordinary sync cycle's own fresh permit. The exporter neither forces nor fakes one, and a body built without that permit stays untagged.

Fixture `fixtures/h527-candidates/held-mixed.v1.json` is the exact packet for a synthetic census covering every member-scoped hold class and the global hold. Tests drive real parser items from synthetic transcripts. Validation is hosted Public CI only; no local Cargo was run. A green CI does not make this core releasable.
