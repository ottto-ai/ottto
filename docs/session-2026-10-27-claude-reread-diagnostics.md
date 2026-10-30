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
`desktop_metadata`. All fields are sparse, saturating integers, scoped to
Claude work and merged across cooperative steps. There is no new emitter or
wire field, and none of these counters selects a file:

- `source_revision_body_rereads`: a `SourceChanged` selection or actual
  `Full(ScopeChanged)` acquisition consumes its first transcript body bytes.
  This includes Desktop/usage sidecar revisions and opened-object/interpretation
  revisions; it is not exclusively Desktop attribution.
- `legacy_identity_body_rereads`: the same actual-read event selected by the
  separate legacy identity adoption path. Both body counters count files per
  attempt, including attempts that later fail; selection or an unchanged native
  reduction reuse alone counts zero.
- `recovered_hold_body_rereads`: first body bytes read after the metadata census
  recovers a complete, unique Desktop proof for an existing account-held file.
  This observes existing account-held retries; it does not select or rearm any
  file or invalidate accepted bodies.
- `lineage_window_read_attempts`: a Claude transcript opened to resolve an
  ambiguous Desktop id. Existing head/tail caps apply; a failed open counts zero.
- `inventory_restarts` and `scoped_acquisition_attempts` have no production
  caller yet, so they stay absent.

`lineage_parentless_while_incomplete{files}` counts distinct source files in
finalized offers whose cached Desktop metadata identifies a child, whose lineage
census is incomplete, and whose emitted facts/origin have no parent reference.
It runs after held-body and semantic no-op removal, using resident metadata only;
no read, persisted field, selector or attribution decision is added. Scratch is
bounded by emitted page items. Retries can count the same file again; this is
offered work, not distinct lifetime sessions or stored-body ACKs.

`claude_desktop_store_inventory` is decode-and-drop in `ScanIndex`. It is in the
`FIELDS` registry so legacy and sharded indexes carrying it load, it steers
nothing, and no save writes it, so a stale digest cannot vouch for a census that
never saw its stores. A malformed value is dropped and adds to
`tombstone_decode_drops`; it is never a refusal, and a duplicate key keeps the
first value. `crate::claude_desktop` is compiled for tests only: sibling Desktop
roots reach no status, census or selection path.
