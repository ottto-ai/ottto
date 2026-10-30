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

Round 11 reserves the exact N+1 prior-root and verified-complete filenames as
opaque local repair state. Fresh-init cleanup keeps them and their directory,
without object validation, and admits the first legacy save when only those
names remain. Previously seen-root guards and malformed-name refusal remain.
Complete/UNKNOWN loads, two prior roots, recovery preservation and native layout
requirements are covered by compiled fixtures; no local tests were run. The
writer inherits the reader and excludes these names from GC without pinning
prior-only payloads. No repair behavior or release gate is enabled by reserving
names; the round-10 source health and repair hold remain unchanged.

## Mac recovery-fixture correction

Reader Mac run40967578629 at89c653a8c passed the seven named native layout/heap
tests but failed the old killed-first-cycle history fixture with
`scan_index_prior_state_requires_repair`. Main merge-group40965613120 atf45c36fd5
ran Rust contracts successfully and explicitly passed that same test; this is
an intentional reader refusal-path difference, not established main flakiness.

The fixture called a complete successful upload/finish cycle, then deleted its
published index and backfill state and rewrote its ledger as a local claim.
That is loss after publication: the reader's durable `.storage-prior` witness
still exists. It cannot prove a kill before the first save. The corrected
fixture asserts the successful publication and witness before deleting only the
root, drops warm daemon custody, then requires prepare to refuse with zero
transcript acquisitions, no replacement index, unchanged witness/ledger bytes
and no re-upload. Production refusal, reserved names and UNKNOWN logic remain
unchanged. The separate `only_server_attested_ledger_records_are_prior_history`
fixture retains the distinction between a local replay claim and server history;
the genuine no-store first-install control remains. A missing root with saved
progress is still conservative prior state, even if that progress claims no ACK;
this change does not introduce an unattended reset or reread exception.

No local tests or macOS workflow dispatch. A later native run must qualify the
corrected fixture; compiling it on this Mac and Linux CI do not substitute for
that runtime receipt.
