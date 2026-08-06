# Claude account attribution uses exact transcript request coverage

2026-08-06. Follow-up to the root/subagent account-family attribution shipped
in `0.1.106`.

## Live QA finding

A fresh Claude Task parent and child created on `0.1.106` passed end to end:
both snapshots, sessions, and usage facts carried the same strong subscription
profile, with no unattributed tokens or NULL fact-level profile.

A separate post-release root session exposed a remaining forward gap. Its
Claude transcript contained 83 unique billed API response ids. The local OTLP
sidecar contained all 83 plus 16 additional Haiku requests under the same root
session id. All 99 sidecar rows were identity-checked, named one account, and
the 16 sidecar-only rows were consistent with auxiliary prompt-suggestion
traffic. The prior aggregate token/count equality guard therefore rejected a
session whose billed requests were completely covered by strong local evidence.

## Change

The Claude transcript parser now retains the exact response ids whose usage it
counted. They are local-only scratch evidence: `SnapshotItem` skips the field
during serialization, so raw response ids never enter the snapshot wire body,
semantic envelope, or backend.

Account attribution accepts either the existing exact aggregate match or exact
request coverage:

- every billed transcript request id must appear exactly once in local OTLP;
- every OTLP row for the root session must be identity-checked and all rows must
  name the same account;
- extra same-account OTLP requests may exist, because Claude Code can emit
  auxiliary requests without adding billed usage records to the transcript;
- missing billed requests, duplicate matches, unidentified rows, conflicting
  accounts, or unattributed transcript tokens still fail closed.

Parent/subagent family witnesses now bind each member to a privacy-safe digest
of its request-id set. A complete filesystem census must prove the explicit
family and its member request sets must be disjoint. A same-count request change
invalidates the witness, preventing count-only reuse from authorizing a changed
child. Only digests, never raw request ids, are persisted in the scan index.

Existing `0.1.106` (`v29`) family witnesses have no request-set digests. At the
first complete census after upgrade, the daemon schedules only those legacy
family files for a bounded local reparse before discarding their count-only
witness. The replay rebuilds exact v30 request proof without using the legacy
witness to authorize new attribution; no server backfill or Gold refresh is
required.

`CLAUDE_CODE_SNAPSHOT_PARSER_VERSION` advances to `claude_code_jsonl:v30`.
Scan identity remains at `v24` because session mapping did not change. This is a
forward fix: new or subsequently changed transcripts collect request coverage;
unchanged historical files are not replayed solely because of the parser bump.

## Verification

- focused account tests cover root sessions with auxiliary requests, missing
  billed requests, conflicting accounts, complete families with auxiliary
  requests, incomplete families, split census pages, and stale witnesses whose
  request ids change without their counts changing;
- a serialized v29 index test proves legacy witnesses schedule both family
  members for replay and rebuild a request-bound v30 witness at terminal census;
- serialization coverage proves the local request-id set is absent from the
  snapshot JSON;
- the semantic-envelope golden changes only Claude parser provenance and its
  derived revision hashes; content identity remains unchanged;
- `cargo test -p ottto-service --lib`: 1,326 passed, 2 ignored before the parser
  provenance update; the final workspace and lint gates are recorded in the PR.
