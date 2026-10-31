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
wire field:

- `inventory_restarts`: changed/unknown ordered store inventory resets the
  metadata cursor, ceiling and coverage claims. An old absent inventory counts
  once when established; subsequent unchanged loads count zero.
- `source_revision_body_rereads`: a `SourceChanged` selection or actual
  `Full(ScopeChanged)` acquisition consumes
  its first transcript body bytes. This includes Desktop/usage sidecar revisions
  and opened-object/interpretation revisions; it is not exclusively Desktop
  attribution. Checking the actual mode covers simultaneous growth and metadata
  changes even when the first selection gate was `TranscriptChanged`.
- `legacy_identity_body_rereads`: the same actual-read event selected by the
  separate legacy identity adoption path. Both body counters count files per
  attempt, including attempts that later fail; selection or an unchanged native
  reduction reuse alone counts zero.
- `recovered_hold_body_rereads`: first body bytes read after the metadata census
  recovers a complete, unique Desktop proof for an existing account-held file.
  Unchanged RAM reuse counts zero. This observes existing account-held retries;
  it does not select or rearm any file or invalidate accepted bodies.
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

A new legacy binding also defers when a Desktop account hash is present but its
original proof is missing while the Desktop census is incomplete. A cached unique
hash cannot win before an unseen sibling is read. Existing owners and independently
qualified contract-5 requests keep their admission rules. Complete census recovery
marks existing account-held retries with a now-complete Desktop proof for read
accounting. Their existing retry/retention path remains authoritative. Recovery
never clears source fingerprints, the accepted body ledger or the owner map.

`scoped_acquisition_attempts` counts Claude acquisition attempts whose inventory
coverage is incomplete but whose per-session reduction dependencies are checked.
This continuation requires an existing native index entry or that file's own
held-new certificate. A new cold file under incomplete coverage keeps the
unsampled native read and its existing copy-refusal exemption.
Claude captures native reductions before applying Desktop metadata at finish;
exact file scope, object/prefix samples, audit debt, copy limits and family gates
still decide reuse. An unrelated inventory restart therefore does not convert a
growing session's valid Tail into a prefix Full. This narrows acquisition's
coverage prerequisite for Claude only. Census/identity/publication gates and
Codex's closed-world prerequisite remain unchanged. A native macOS Tail fixture
compares emitted bodies against a cold Full under the same partial metadata;
Linux verifies the unsupported-layout Full fallback. A healthy inventory cooldown
keeps retry_attempt=0, so a subsequent first metadata error retains the existing
initial one-minute retry rather than accidentally doubling it.

Cached entries retain their canonical Desktop-store scope while that profile's
directory disappears/reappears during backoff. Inventory discovery must not split
one cached store into per-file scopes and invalidate unchanged child lineage.
The scoped re-emission fixture includes this OWN-profile flap in both directions.

For an ambiguous parent Desktop id, the child's dependency hash also includes
only those candidate parents' indexed size, mtime and birth metadata. A fresh
import can resolve before either parent has been indexed; the next cycle then
selects only the dependent child to recover its parent fact. Missing windows
remain pending, with at most one resolution pass per cycle. No census transcript
IO or recursive source-fingerprint dependency is introduced. Unrelated sessions
and unambiguous parent links do not acquire these window dependencies.

`lineage_parentless_while_incomplete{files}` counts distinct source files in
finalized offers whose cached Desktop metadata identifies a child, whose lineage
census is incomplete, and whose emitted facts/origin have no parent reference.
It runs after held-body and semantic no-op removal, using resident metadata only;
no read, persisted field, selector or attribution decision is added. Scratch is
bounded by emitted page items. Retries can count the same file again; this is
offered work, not distinct lifetime sessions or stored-body ACKs.
