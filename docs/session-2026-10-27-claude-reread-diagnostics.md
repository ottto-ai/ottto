# Claude re-read diagnostic counters

The local resource carrier now distinguishes parsed-entry restoration from
actual nonempty-to-empty clears. Restoration keeps the existing conservative
save rule, separating prior empty/nonempty fingerprints and local held/sibling
keys, with a separate count for exact-incidence-only sibling rejection. The
owned-start, invalid account-witness, retry admission and authority normalization
sites retain their existing decisions and gain fixed local counts.

Claude collection scopes carry exact cache lifecycle events across cooperative
steps and worker moves. Existing process cache totals remain unchanged; sparse
page events identify the causing source, with count/byte capacity eviction
splits and failed destructive-hit reinsertion. Preparation/save intervals report
through the existing comparison decision stage, including when comparison is
disabled. Counts never enter wire/persisted models or authorize progress.

Tests cover source/thread/nested-scope isolation, resumed aggregation, sparse
encoding, saturation, real subset restoration and unchanged saved entries, plus
existing native pipeline/layout and resource budget contracts in CI. Validation
runs and exact head are recorded in the PR. No local Rust build/test/clippy,
installation, runtime collection, release or production action was performed.

Round 2 adds `stale_carry_rejection_counts` as a fixed JSON suffix to the existing
stale Claude start re-arm text line, captured before fingerprint clears. It
separates start admission, window/ordinary scratch, member/evidence, cancellation
funding and actual reservation failures, plus qualified and final carried roots.
Failed streaming probes are discarded when a fallback rescues them; capped
roots cannot acquire a second failure. Existing structured transition rows,
layout prices, source walks, decisions and assertions stay unchanged. New
fixtures exercise first-stage precedence, scratch paths, funding/reservation,
streaming rescue and bounded-batch probe isolation; all existing traversal-start
fixtures also assert the complete root partition through a test-only observer.

Round 3 merges the current main branch, preserving the family-scoped hold veto
and deferred-return state restoration together with diagnostic-aware settlement,
and retaining the ctime/birth and parent-ledger metadata checks. The histogram's
plain stderr carrier is intentional and documented. Existing assertions, census
entry size pin and visit/memory budgets remain unchanged; final Linux and native
Rust contract receipts are recorded in the PR.

The merge review also found that preparation errors could discard normalization
counts without a native lease. The no-lease error path now emits nonzero counts
through the existing decision carrier; leased error reporting stays unchanged.
A real preparation regression loads an unbound record and forces progress
generation overflow under both gate states, checking one reported clear and the
unchanged failure and durable progress.

Desktop metadata uses the existing page `local_resources` counts carrier under
`desktop_metadata`. All four fields are sparse, saturating integers, scoped to
Claude work and merged across cooperative steps. There is no new emitter or
wire field:

- `inventory_restarts`: changed/unknown ordered store inventory resets the
  metadata cursor, ceiling and coverage claims. An old absent inventory counts
  once when established; subsequent unchanged loads count zero.
- `source_revision_body_rereads`: a `SourceChanged` selection actually consumes
  its first transcript body bytes. This includes Desktop/usage sidecar revisions
  and opened-object revisions; it is not exclusively Desktop attribution.
- `legacy_identity_body_rereads`: the same actual-read event selected by the
  separate legacy identity adoption path. Both body counters count files per
  attempt, including attempts that later fail; selection or an unchanged native
  reduction reuse alone counts zero.
- `lineage_window_read_attempts`: a selected-file finalization opens an uncached
  parent transcript to resolve an ambiguous Desktop id. Existing head/tail caps
  apply (256 KiB at each end); cached windows and metadata census work count zero.

Inventory changes cool down even a successful small metadata sweep using the
existing 60-second initial retry and one-hour ceiling. A changed inventory during
backoff revokes the census witness immediately, retains the deadline, and does
no metadata-file or transcript-window reads. A completed cached census remains
usable during its quiet period. Census coverage does not itself revise session
selection: original-account evidence still refuses completeness while coverage
is missing. Selection hashes only that session's metadata, including reachable
parent metadata in its own store. Ambiguous parent windows resolve after an
independently selected native read; census discovery never opens transcripts.
A healthy spawned session adopts this metadata dependency revision once; unrelated
profiles and later coverage loss/recovery do not select unchanged transcripts.
