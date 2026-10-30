# Production ScanIndex reader

Reader N accepts legacy and schema-3/storage-1/logical-2 roots and writes legacy
at the same synchronous saves. Full semantic CAS and retry maxima merging stay
in place; published commit errors keep their committed generation.

The existing account/usage decoders and census visitor must keep every record
before a map becomes known. Missing, stale, digest, decode, descriptor and unsafe
failures become explicit UNKNOWN. Trusted metadata and known siblings remain
readable, while acquisition and destructive/proof transitions refuse. Clone,
subsets and captured recovery retain availability and immutable baseline custody.
Only version refusals become an update-app health blocker.

The existing local resource envelope receives fixed map/cause counts on both
successful and failed opens. Additional retained custody is admitted against the
shared parked budget and is included in heap/Arc/Clone accounting. ScanIndexEntry
is unchanged; native layout remains pinned at 480 bytes. No local tests were run;
all-target compilation and Linux runtime/native contract jobs supply validation.
See scan-index-persistence.md for representation, downgrade and release gates.

Round 9 adds direct manifest refusal/counting, per-source UNKNOWN health and an
alarm once per unavailable episode. Each map has a damaged/held/restored E2,
finalization, context and manifest fixture comparing the retained page against
an undamaged nonzero-money control with zero transcript reads. Projection
fixtures cover repeated loads, recovery, captured state, sibling sources and
set/clear events between status reads. Proposed label/hover strings are constants
pending wording approval; companion/web presentation remains separate.


Round 10 applies the approved plain-language copy in the existing constants.
The existing user Repair override cannot exit an UNKNOWN-map hold without new
behavior: it only arms for a whole-index rebuild-loop pause and carries identity
into a replacement index. Partial load succeeds, retains metadata and clears
that separate pause. Keep `contact_support`; map-scoped recovery remains a
release blocker pending review, with no repair bypass enabled.

Round 9 Linux failed in the healthy control before damage: finalization dropped
E2's request-owned literal because the fixture left active body revision 0.
Production preparation activates the compiled revision before scanning. The
fixture now does the same, stamps that revision, and reproduces the revision-0
veto on the same emitted body as a negative witness. All exact nonzero money,
body/manifest equality and zero-transcript-read assertions remain. Runtime
qualification must use final-head CI; no tests were run locally.
