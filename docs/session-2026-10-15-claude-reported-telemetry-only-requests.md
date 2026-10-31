# Contract 5 for reported usage with telemetry-only requests

Date: 2026-10-15.

## Problem

A Claude Code session whose family a complete census proves gets
`session_exclusive_reported_usage:v1`. `rebuild_claude_reported_usage` then
rebuilds its usage from the local telemetry ledger. That ledger can hold
requests the transcript does not: Haiku side calls, or calls that report only
aggregate cache creation. The rebuild counts them, so
`item.request_count = totals.request_count`, while
`claude_usage_request_ids` keeps the transcript's request ids only.

Contract-5 tagging (`claude_request_identity::tag_item`) required
`claude_snapshot_request_id_hashes(item)`, which needs
`request_count == claude_usage_request_ids.len()`. A reported item with any
telemetry-only request therefore failed before its grouping was read. It went
back to D1, and D1 emits `own_request_account_unknown:v1` under a permit.

The body is accepted: it carries more usage under a stronger usage authority.
So a session first sent as contract 5 on the transcript path, and later proven
reported with telemetry-only requests, replaced its contract-5 body with an
unknown-account body. Its per-request names were lost.

## Fix

A reported item no longer uses the transcript request-id count. It is checked
against the requests its own rebuild admitted:

- `RequestSink::add` counts each request it admits. It counts transcript
  requests (those with an owned transcript occurrence) separately from
  telemetry-only ones. `Grouping` carries the two counters, so nothing grows
  with the request count.
- For a reported item, `tag_item` requires
  `Grouping::reported_requests_admissible`, which is exact owned-request
  accounting (`Grouping::owned_reported_requests`) or, failing that, the old
  request-id count check (see "Legacy exclusions" below). Owned-request
  accounting holds when:
  - the rebuild admitted exactly the item's owned transcript requests:
    `transcript_requests == claude_usage_request_ids.len() - excluded`, and
    that is more than zero;
  - transcript plus telemetry-only requests equal `item.request_count`;
  - every admitted request is the item's own (see below).
- The ledger holds one row per request id (`reduce_claude_usage_ledger`), and
  the transcript request ids are a set, so each counted request is distinct.
- The transcript path keeps `claude_snapshot_request_id_hashes` unchanged.
- `apply_grouped` still has to reproduce every bucket and top-level row
  exactly, and money must be micro-exact. The byte cap and fallback are
  unchanged.

What stays the same:

- **Classification.** A telemetry-only request is classified on its own
  telemetry row and trace owner, as before. It has no transcript occurrence,
  so it has no transcript clock and no marker, and it cannot borrow the
  parent's. Its observer clock does not qualify, so it is refused
  (`BadClock`). With an invalid or missing login of its own, it is refused
  `InvalidEvidence`. Its usage stays on its row, untagged and counted as
  refused. The transcript requests keep their telemetry tags.
  2026-10-31 ID1: telemetry-only side calls take their own row's complete account (B3, #1018); BadClock refusal no longer applies to them; money bucket unchanged.
- **Unsettled census.** `withdraw_transcript_tags` still removes only
  marker-derived tags. Telemetry tags stay, so the item stays contract 5.
- No collection, reads, retained state, wire fields, hashes or fences change.
  The W0 r5 digest test is unchanged.

## Legacy exclusions

A top-level fork written before `forkedFrom` existed copies its parent's first
responses. When a complete census proves that prefix belongs to another root,
the family witness records it in `legacy_excluded_request_id_hashes`, and
`rebuild_claude_reported_usage` leaves it out. Those requests stay in the
item's `claude_usage_request_ids`, but never in its rows, count or usage:

- the rebuild returns false if any of the member's ledger rows is excluded,
  before any row is counted or given to the sink;
- `item.request_count` is set to the number of ledger rows, one per request;
- the ledger rows of the child root cannot hold another root's request: a
  request owner is unique across roots, and the exclusion requires a different
  owner (`claude_legacy_request_owners`,
  `claude_legacy_exclusion_evidence_fingerprint`).

The sink proves this rather than subtracting counts:

- `RequestSink::excluding` takes the exclusions the call site passes to the
  rebuild. It records how many of them are request ids of the item. If any is
  not, the owned count is unknown and owned-request accounting fails.
- `RequestSink::add` marks the grouping when it admits an excluded request, a
  transcript request that is not one of the item's ids, or a telemetry-only
  request that is. Such a grouping is never tagged, whatever the counts. An
  excluded request is never classified, so it cannot tag the child or lend it
  the parent's telemetry login.

So a legacy fork with excluded requests is contract 5 with or without
telemetry-only requests: its owned transcript requests carry their own
telemetry tags, and the excluded usage stays with the parent.

Before this change, such a reported item passed only when the number of
excluded requests happened to equal the number of telemetry-only requests,
because only then did `request_count == claude_usage_request_ids.len()` hold.
That check is kept as the fallback, so no item it admitted is now refused.
When the exclusions cannot be proven to be the item's own requests, the old
check alone decides, as it did. It only ever admitted the rebuild's own rows.

## Re-offer of already accepted unknown-account bodies

A daemon that already sent the unknown-account body for such a session does
not need a replay. The existing re-arm re-offers it:

1. In every pass with a complete census and healthy reports,
   `apply_claude_reported_usage_with_index_and_limits` proves each complete
   family again (`prove_claude_usage_family`).
2. In the same pass, inside `if census_complete`, every member of a proven
   family that the pass did not parse has its index entry's
   `source_file_fingerprint` cleared. The condition is
   `proven.contains_key(root) && !current_ids.contains(member)`. It does not
   check whether the proof changed, so it re-arms every complete census.
3. `candidate_decision_with_reason_at` parses an entry with an empty
   fingerprint (`Rearmed`).
4. The next pass rebuilds the family from its witness
   (`reconstruct_claude_usage_family`). The item is reported again, and under
   a permit it is now tagged as contract 5.
5. `finalize_scan_after_policy_with_body_witness` drops a re-parsed file as a
   no-op only when the snapshot fingerprints and upload body witness of the
   file are unchanged. The contract-5 body has a different collector and
   identity, so its fingerprint differs and it is uploaded.

This is conditional, not automatic:

- A later complete census must prove the family again. Members parsed in that
  census pass itself are tagged in that pass.
- The re-parse cycle must hold a permit. A denied cycle re-sends the same
  unknown-account body, which is a no-op, and the next complete census re-arms
  the member again.
- A family that is reconstructed but no longer proven is not re-armed by this
  path.

Step 2 is also why every complete census re-parses all proven members it did
not parse itself. Narrowing that re-arm to changed proofs would remove this
re-offer path for bodies that are already accepted. Such a change needs its
own one-time re-arm of reported members whose body is not contract 5.

## Not in this change

- A persisted "last accepted body was contract 5, so hold rather than
  downgrade" flag. It brings revocation and delayed-money questions with it.
- Any change to server fences.
- Tags for telemetry-only requests. Their own observer clock does not qualify
  under the current rules.

## Tests

In `snapshots/claude_request_identity_tests.rs`:

- `reported_rebuild_groups_requests_without_changing_its_output` runs the real
  reported rebuild with no telemetry-only request, then with a Haiku side call
  plus an aggregate cache-creation call, each with and without a login of its
  own.
  - The rebuild output is byte-identical with and without contract-5
    evidence.
  - Both items are sent as contract 5, and usage and money are conserved
    against the untagged body.
  - The four transcript requests are tagged with their telemetry login. The
    two telemetry-only requests are untagged, carrying all 7 aggregate
    cache-creation tokens, and give two refused rows.
  - If the item names a transcript request the rebuild did not admit, or a
    count the rebuild did not make, the item stays on today's path with its
    bytes unchanged.
- `proven_reported_members_are_rearmed_and_reoffered_as_contract5`:
  1. Page A observes the family.
  2. A complete census page that does not parse it proves the family and
     re-arms both members.
  3. The next, unsettled pass rebuilds them as reported. Before tagging, D1
     makes the parent unknown-account (the body sent before this change).
     After tagging it is contract 5, with a different fingerprint and
     conserved usage.

Both tests fail on the previous source at the contract-5 outcome assertion:
one item was sent and one was ineligible, where both should be sent. Every
other assertion before that point already held on the previous source.

Legacy exclusions, also in `snapshots/claude_request_identity_tests.rs`:

- `legacy_excluded_reported_fork_stays_contract5_by_owned_requests` runs the
  real census, legacy-exclusion proof and reported rebuild on a legacy fork.
  The parent's telemetry carries a different login. It runs with one, none
  and two telemetry-only requests.
  - The child counts only its own and its telemetry-only requests, and the
    parent keeps the shared request's usage.
  - Owned-request accounting admits the child in every case. The old count
    check admits it only with one telemetry-only request, the case already
    sent as contract 5 before this change.
  - Both items are sent as contract 5 with usage conserved. The child's own
    requests carry its own login, its telemetry-only requests stay untagged
    and refused, and the parent's login appears nowhere in the child's body.
- `legacy_exclusion_skew_never_tags_or_borrows_the_parent` drives skewed
  exclusions through the real rebuild, with two telemetry-only requests so the
  old count check is negative:
  - a missing exclusion, an exclusion of a request the child owns, and
    excluding every request: there is no reported body;
  - an exclusion that is not one of the child's requests, a count mismatch,
    and unadmitted transcript ids: never tagged, bytes unchanged. One
    unadmitted id that makes the old count coincide is still admitted by that
    check, as before;
  - a grouping that admitted the excluded request is refused, even though the
    old count check is positive.

On the previous revision of this change, the first test fails at the
contract-5 outcome with one telemetry-only request: one item sent, one
ineligible.
