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
  `Grouping::admitted_reported_requests`. The rebuild must have admitted every
  transcript request id of the item, with none excluded, and transcript plus
  telemetry-only requests must equal `item.request_count`. The ledger holds
  one row per request id (`reduce_claude_usage_ledger`), so each counted
  request is distinct.
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
- **Unsettled census.** `withdraw_transcript_tags` still removes only
  marker-derived tags. Telemetry tags stay, so the item stays contract 5.
- **Exclusions.** A reported item whose rebuild excluded transcript requests
  (a legacy fork prefix owned by another root) stays on today's path. The old
  check let such an item through only when the number of excluded requests
  happened to equal the number of telemetry-only requests. Now it never
  passes.
- No collection, reads, retained state, wire fields, hashes or fences change.
  The W0 r5 digest test is unchanged.

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
- Contract 5 for reported items with legacy exclusions.

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
