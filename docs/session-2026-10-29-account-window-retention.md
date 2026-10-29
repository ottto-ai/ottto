# Account-pending window retention

Historical Claude account windows now retain the first and last observation of
consecutive runs identical in every field except `census_window_end`. The current
window stays separate. Request counts, request sets, revisions, version, member
counts, validity and completion all participate in strict run equality. An
exhaustive window destructure forces comparison review when a field is added.

New windows extend an existing run's last endpoint; a second observation first
creates that endpoint. A load proposes the same collapse for older histories,
then compares each root's member/timestamp/account/invalid/revision summary and
history-existence predicate in RAM before removing anything. A discrepancy
refuses that root. Unparseable, future, current-equal, duplicate or reversed
historical boundaries also refuse the entire root. Indexes with opaque decode
holds skip retention on both load and push: their original encoded size funds
held-record admission, and shrinking another root could otherwise break save.
No historical copy is retained.

The normal generation save persists the result through its existing temporary
file, fsync and atomic replace. Load itself never rewrites the index. A crash
before save repeats the same collapse on reload. Persisted schema, scan identity,
fingerprints and upload/accepted witnesses are unchanged. No transcript, sidecar,
or durable-store access is added. A downgrade may regrow history; re-upgrade
collapses it again.

The existing local collection diagnostics carry roots collapsed, windows
collapsed, historical-array bytes before/after, bytes saved and roots refused.
Byte counts use compact JSON arrays, streamed to a counter without an encoded
history buffer. Diagnostic encoded-size/heap readers intentionally reflect the
smaller representation; account decisions and scheduling retain their semantics.
M4 runtime numbers will be reported after release.

Regression fixtures replay real retirement decisions and the scheduling reader,
cover A -> B -> A and non-boundary changes, preserve unsafe histories, exercise a
defective-plan refusal, verify normal save/crash-before-save/idempotence, and
compare all other serialized index fields. The frozen 0.1.201 account-record
codec comes from source commit f174d111fbcdfb0ab9c2abeb299c12d50b435c29;
that reader decodes the shorter arrays using the same schema.

Validation: package-scoped Clippy with all targets and warnings denied is the
local compile gate. Tests run in CI; no local cargo test is authorized for this
change. No installed daemon, user index or production state is modified by the PR.
