# Claude in-page frozen extents

A sampled Claude Full or Tail read freezes the opened length in reader-relative
units. At a genuine unchanged EOF it applies the buffered unterminated row with
the native trailing-line rule. If the held object grew, a successful sealed-prefix
certificate permits publication of complete rows through the frozen extent.

The grown route refuses a prefix shorter than the member's last committed size.
Replacement, shrink, same-size edits, changed samples, changed dependencies,
lossy reads, short traversal and growth after an EOF fragment was already applied
retain their existing refusal paths. Response loss discovered only during native
finalization also refuses the grown prefix, so every published prefix can retain
its durable audit marker even when D1 storage is unavailable. The shared
`FinishGrant::certified` constructor grants finish identity only.

The grown-read checkpoint is discarded: no retained copy, cache insert, audit
credit or source verification. The index keeps the opened fingerprint and size,
so the appended suffix is selected normally on the next scan. Existing prepared
audit debt keeps its deadline. A Full with no earlier obligation prepares a
bounded deadline before reading within the existing audit metadata-slot bound; a stable verified completion clears it, while
a grown publication keeps it for the quiet audit.

An unverified D1 source record or durable audit marker explicitly excludes its
family from fresh or reconstructed proof and v1, owned-start certification,
cache/curve admission and both strict and file-birth posture admission. API rows
assigned by traces may legitimately exceed transcript request sets as auxiliary
calls, so request-set inequality alone is insufficient. Historical witnesses and
their demotion/hold accounting remain intact, but cannot authorize the prefix.
Missing D1 records still fail closed through the durable audit marker.

The certificate accepts the append-only sample-preserving interior-rewrite
residual. The existing quiet full audit repairs the observed body and emits
`sampled_audit_comparison` counts, including `semantic_changed` and
`effective_body_changed`; the regression fixture checks this follow-up. No new
claim of arbitrary mutation detection is made.

Tests are synthetic and run only in CI. The Claude fixtures are copied from
#670, without the independent Codex Stage2-pre failing rows. They cover Full and
Tail growth, trailing fragments, relative offsets, post-EOF growth, replacement,
truncate/regrow, loss, minimum committed size, prepared debt, D1 replacement,
pending-census changes and proof exclusion with extra API rows. Codex and Pi
behavior stays covered by controls. The former SP11 Claude failure assertion now
expects uncertified prefix publication.

`transcript_acquisition.rs`, `sampled_jsonl.rs`, cache insertion and heap-bound
implementations are unchanged. The implementation uses Rust 1.80-compatible
APIs and no new persisted fields.

This remains a draft pending the source-acquisition owner's ACK. Intended landing
is with or after Stage2-pre (#660 → #665 → Stage2-pre), or FE-first only with that
owner's agreement. No landing is authorized by this implementation.
