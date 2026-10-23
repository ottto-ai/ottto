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

SOURCE ruling (B) narrows exclusion to FE-published sealed prefixes and D1 tail
records used directly without native recomposition. A matching D1 record must
also describe a current loss-free parse: terminal oversized-line settlement,
path twins and stale or retired records cannot grant the recomposition exemption. Ordinary fully recomposed,
EOF-revalidated Tail/Unchanged bodies retain proof, v1, owned-start, cache/curve
and posture admission while continuing to owe their Full audit. API rows assigned
by traces may exceed transcript request sets as auxiliary calls, so request-set
inequality alone is insufficient. Historical witnesses remain available for
existing demotion/hold accounting, but cannot authorize a prefix.

Provenance uses the existing version string:
`semantic_sync:v2+sampled_unverified:v2:<deadline>:p` for a prefix, or `:c` for a
complete native recomposition. A known clean full identity also means complete;
old, unknown, missing or malformed provenance fails closed. Tags remain within
the existing 64-byte marker allocation. Record, replay, normalization, unsettled
subset carry and save/load preserve prefix exclusion and the oldest deadline.
Missing D1 is harmless: the tag binds the exact source-file fingerprint to its
logical family even after physical-key drift.

Only an EOF-revalidated loss-free native Full/Tail recomposition or Full audit
can clear the tag, bound to the exact recorded fingerprint. A Tail replays a
complete retained baseline; FE never inserts a prefix reduction. A later grown
Tail publication keeps the prefix tag. Clearing provenance on a complete Tail
keeps its audit deadline and does not mark its D1 record source-verified. Local
content-free totals count `prefix_excluded_bodies` and `prefix_tag_clears`.

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
