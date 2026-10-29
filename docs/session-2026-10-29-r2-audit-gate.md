# Standalone audit gates on checkpoint reuse

Approved 2026-10-29: this gate-only slice lands standalone on main, ahead
of its former R2 slot. It can enter R1 if green and merged before the R1 cut.
It supplies the LA-1 audit-gate dependency for the Pi restore work. Only the
two audit-gate commits are transplanted; bootstrap and format work stay separate.

Ordinary checkpoint-backed acquisition now chooses Tail or Unchanged from
content identity, scope and the existing head/boundary checks. An old full-check
time, a due audit deadline or a regressed audit clock does not force Full.
Completing a Tail or Unchanged read keeps the prior verification time and debt;
it grants no Full-audit or additional census credit. Content identity continues
to use `same_content`, which excludes ctime.

Pending audit count no longer gates ordinary sampling/restore, clears the cache
or disables its copy-budget calculation. Existing resource measurements and
caps remain in force. Legacy audit-capacity diagnostics still report actual
pending/slot state; they can be false while ordinary sampling is allowed.
The `clear_metadata_unsupported` counter remains in the diagnostics shape but
this acquisition path no longer emits it.

This is the gate-only cut. Parent-proof seal horizons, Codex cursor-prefix
completion, legacy prefix admission, verification migration and persisted
formats remain separate work. Missing checkpoints are classified StateMissing,
never AuditDue/ClockChanged. S2 owns the disposition and allowed-cause admission;
a new label grants no additional read permission. It makes
no whole-source restart-coverage or zero-byte restoration claim. Existing
restore head/named-line re-derivation is still accounted separately from native
Tail bytes.

Regression coverage uses the existing production scanner and durable writer /
restore paths with a fresh cache owner: a two-hour-old record with an append,
a due quiet record, a regressed clock, 256/300 independent pending audit keys
a same-size edit, 50-hour-old records, restore admission refusal plus index
debt and cleared selection plus debt. Assertions distinguish actual disk restoration, Full /
Tail / Unchanged, native read extent, debt and emitted-body equality. Additional
Unix acquisition tests restore a serialized certificate and inspect actual FD
suffix bytes without requiring the native heap layout. A test-only observer at the shared File::read call captures the stream offset,
requested length, returned bytes and errors for certificate head/boundary reads.
It covers quiet, append and short-read/EOF cases independently of completed
context metrics; it does not measure rederive, other readers or page-cache disk
activity. Quiet restore reads both samples, so total zero-byte restore remains
unmet. Existing proof-fence assertions retain their clock and audit refusals.

The restore fixture uses main's always-capturing scanner binding outside a sync
cycle, replacing the retired capture-default helper in its two store openings.
All assertions and real writer/restore paths are retained.

Validation: explicit-file rustfmt and `git diff --check`; no local Cargo build,
test or Clippy. Linux CI runs on the review-ready standalone PR. Native restore
fixtures still require the supported heap layout; native contracts, money
equality and E3/Lead B owner review remain owed. The Mac slot order is #857,
then #854, then this PR; the owning integration agent dispatches those checks.

The standalone review exposed overdue Codex Tail restarting at cursor completion.
The seal now uses the selector's identical exact-stamp audit predicate: ordinary
Checkpoint views are non-exact, while PrefixSeal proof views remain exact and
retain their deadline refusal. No new field or cursor implementation change.
Tail completion preserves its prior full-verification time and debt verbatim.

Regression coverage adds a real durable restart with a Codex suffix larger than
the existing scaled cursor budget, checks resumed/certified publication and
replacement index/disk binding, then restarts again and asserts zero native
suffix bytes with the same debt. Claude exercises ordinary overdue Tail as a
negative regression control. The seal unit case fails before this fix at the
overdue commit; the Codex integration case fails on audit Restart. The Claude
control and exact-stamp proof refusal already pass before the fix and guard
against widening. These native paths still need supported-layout CI evidence.

The superseded Linux run exposed a bootstrap-only Serde assumption in the
certificate fixture. It now round-trips through main's actual binary durable
store writer/reader before exercising the same FD/read/debt assertions. Existing
proof-horizon and rotating-cursor tests now distinguish ordinary acquisition
from exact-stamp proof expiry: both rotating files must publish overdue Tails
without resetting verification or debt; this can occur within the same census
generation.

Round 4 repairs four macOS-only test expectations; production is unchanged.
The rotating-file test now requires a later completed Tail and a strictly larger
sealed offset for each file, since audit age does not rotate the census token.
The converged cursor test proves that a one-row suffix fits the singleton budget,
completes/publishes without another cursor job, and keeps the original Full time
and its deadline.

The durable restart test now observes both raw native output and the finalized
upload candidates. It requires the changed Tail to emit the same production
body as cold Full, then requires zero finalized candidates at the next restart,
with identical accepted fingerprints, semantic group and body witness. A changed
additive-body negative control still emits under the same semantic identity. Raw
Unchanged output alone is not a publication: production suppresses identical
bodies during post-policy finalization before constructing the upload batch.
The audit-capacity refusal test retains its no-output/no-checkpoint/no-marker
requirements and pins ScopeObject as the sole refusal: a frozen read with growth
and no H3c grant fails completion object revalidation. No local Cargo execution;
E1 must rerun Linux, native macOS contracts and money, then obtain exact-head
review. Prior money and review receipts do not qualify the new head.


Round 7 pairs gate removal with bounded sampled-obligation retention. A complete
`c` entry may retire only on an ordinary Unchanged read whose scope/object and
checkpoint content stamp still match, with both <=4 KiB head/boundary samples
and held-FD EOF/stamp revalidation. Native completion must remain complete,
loss-free and sealed, and the replacement copy must be admitted. That produces a pending retirement. With a durable slot the index marker
remains until the existing writer persists a debt-free record and a second
index CAS clears the marker. Full verification time stays old,
and source_verified, census and Full-audit credit still see the owed debt.
Deferred/failed persistence remains owed on the older disk certificate; a disk
retirement is asserted only after its writer receipt.

At 256 marked entries, only an unmarked file needing fresh debt takes its native
Full fallback (`audit_cap_full`); already-marked files still Tail, and quiet
debt-free checkpoint reuse remains available. Existing/imported obligations are
never evicted; positively proven absence may retire them without read credit. New prefix/lossy obligations without a slot
are refused before publication and retained in the existing traversal retry queue
with the age-window bypass. Quiet retirement releases capacity for the next
committed scan, while this page reserves it against partial-save restoration.
Central staging
and prefix-marking checks enforce the cap, including unavailable Codex cohorts.
`audit_quiet_retired` and `audit_cap_full` sit beside pending/overdue diagnostics;
a positive cap count emits the local `sampled_audit_cap_alarm`.

Prefix `p`, malformed/legacy tags, growing or changed files, partial/lossy reads,
cursor fragments, failed samples/final revalidation and refused retention keep
their obligation. No new representation, store/codec, proof rule, cap increase,
Full cause enum or global sampling switch is introduced. Native/money CI and
SOURCE/Lead B sign-off remain owner gates; no local Cargo execution.

Round 8 excludes keys in `claude_account_deferred_holds` from quiet retirement
and both `audit_cap_full` decisions. Their withheld-body retry remains owned by
the account-hold path, with no double count against `withheld_reparse`.
Checkpoint debt is retained; central marker admission still refuses marker 257.
Fresh held markers also require a slot reserved before this scan, including
ordinary debt, sealed prefixes and cursor fragments; a working retirement cannot
fund them before a partial save restores the old obligation.
After release, normal quiet validation and per-file cap policy resume. Held-key
partial saves preserve the obligation; retirement still releases capacity only
for the next scan of the committed index.

The cap remains `CACHE_ENTRIES = 256`. Marker storage is at most 64 bytes per
marked entry, so scheduling payload is at most 16,384 bytes (16 KiB) per index
copy, within the existing 1 MiB marker-and-scratch reserve. This derived bound
covers marker payload, not existing entry/key/map/receipt memory or daemon RSS.
The existing cache count is reused without raising a resource limit. The
`sampled_audit_cap_alarm` fires on the first cap event (`audit_cap_full > 0`),
with no minimum event count or cooldown. Held quiet/release and saturated held
retry fixtures complement the partial-save slot-reservation regression; native
execution and fresh money/SOURCE/selection reviews remain owed.

Round 10 preserves acquisition debt when account classification releases a hold
AFTER scanning. With committed capacity it keeps the sampled marker; otherwise
it queues the existing exact retry and clears the existing source fingerprint
as an explicit reparse witness. That witness survives traversal resets and
bypasses activity filtering, including for a quiet equal-size file. On its next
nonheld visit the ordinary per-file cap policy applies; no marker 257 is minted
and working retirements never refund a committed slot. Missing retained custody
keeps a retry rather than implying that an obligation was discharged. This
changes scheduling, not account attribution, accepted bodies or audit credit.

Release pairing uses #865's debt-carrying writer, merged first on main; this
branch merges main without rebasing. Required native cases exercise that writer:
record-present quiet restart with zero Full, and the legacy index-saved/old-record
crash window with at most one counted Full. Both changes ship in the same
release; exact-head execution remains required before merge. The previous 0.1.201 map/default decoder
contract is pinned for the ordinary identity written by marker retirement.

Same-size interior rewrites (or truncate/regrow) completed before opening, with
restored mtime and matching head/boundary samples, may retire stale scheduling
debt: this is the existing #819/§13 same-stat forgery residual, not whole-content
verification. No ctime-based reread or additional Full authority is introduced.

The cap stays 256 and cap Full must stay exceptional. After release the release
owner reports the highest pending-marker count observed on the M4 using existing
diagnostics. A nonzero audit_cap_full in normal use requires named Ron approval
or a cap redesign; never silently raise it. Exact-head Linux and macOS native
fixtures must pass before merge; local Clippy compilation is not test execution.


Round11 merges main after #865, preserving both appended-test sets in the two
merge conflicts. Quiet retirement now keeps its scheduling marker through the
first index save, writer deferral/error and restart. A pending RAM candidate
contains only fixed key/fingerprint digests; the original marker is the durable
obligation. Only a fully accounted successful #865 write/clean receipt permits
a second index CAS to clear that marker. Its record carries no debt, and the
old Full verification time stays unchanged. Dropping a stale RAM proof candidate
never removes the marker; it must revalidate on its next visit. Index-new/record-old
legacy crash recovery remains at most one counted Full on the next visit.

Cap fallback now uses a separate fixed 256-slot RAM pace keyed by path digest,
six hours by SystemTime. Backwards clocks and jumps beyond 30 days expire toward
reading. At overflow it evicts the oldest stamp, enrolls the candidate and emits
pace_evicted with its own immediate alarm. Within the pace it counts a delay,
keeps committed size old and persists an age-bypassing retry. Already-marked
files keep Tailing and held files remain excluded. Restart permits at most one
extra cap Full per key. This table is to unify with P2's shared paced_full map at
integration. A first read without an index entry uses its ordinary A1 path,
without acquiring a cap label. Refused prefix/lossy output counts a delay, not
a Full that never happened.

The existing audit cap remains 256: each marker reserves at most 64 bytes,
16384 bytes per index copy inside the existing 1 MiB audit/scratch reserve. The
new pace and pending-retirement tables have 256 fixed inline slots with no
copied paths/fingerprints; existing SharedCache/Arc/context size accounting
charges their complete inline layouts, including empty slots.

Absence uses E3/#876's exact proven_absent(Path, &[PathBuf]) seam: NotFound with
both immediate parent and configured root readable. The bounded reconciliation
path retires marked obligations and counts audit_retired_absent without Full,
source or census credit. Unsafe ancestors/root permission uncertainty keep debt;
round18 below strengthens the proof for a missing intermediate directory.
Codex-protected entries keep their history; only audit scheduling ends. The
account-hold carve-out has the same helper name and two call sites as #876;
whichever lands second must retain both paths and the three-producer vanished
diagnostic inventory. Reappearance after removal is an ordinary new-object
FirstRead. #876's full withheld counter carrier is still an integration seam.

New fixtures cover paced growth/expiry/backwards clock/overflow alarm, durable
pre-writer crash/deferral/rename failure/receipt-before-index crash/legacy carrier
mismatch, proven deletion/missing-parent/recreation and protected Codex retention.
Synthetic acquisition clocks precede wall time so #865's deadline clamp cannot
turn fixture timing into a carrier mismatch. Fixtures remain unexecuted until
E1's exact-head Linux and one native macOS contracts run; only serialized local
package Clippy is authorized here. Existing raw/finalized money equality stays.


Round12 repairs the five Linux contract failures from round11. The dense native
resource record keeps its existing 4 KiB limit: cap delays emit their exact count
as sampled_audit_cap_delay on the existing carrier, while pace_evicted stays on
its existing immediate alarm. The origin-unknown acquisition test checks its
admission block rather than treating an unrelated pacing field as cache history.
The deleted forced-member test now requires its proven-absent account hold to
be released while retaining SOURCE N3 fingerprint incidence. #865's discarded
envelope debt is explicitly absent from decoded checkpoints; live index debt
still wins, remains due across Unchanged sampling and is never Full permission.
The standalone acquisition fixture supplies that live debt at the prepare seam.
Missing-entry and foreign-context write-only descriptor controls mirror P3;
this branch already classified the same-context carrier before membership.

The hardened absence predicate and helper are an exact round18 copy from E3's
#876 while it is unmerged, to be replaced by #876's implementation at merge.
Every parent below the configured root opens by no-follow openat; final
fstatat(AT_SYMLINK_NOFOLLOW) must report precisely ENOENT; the pinned chain is
revalidated. A missing intermediate component beneath a securely opened readable
ancestor is positive absence. Intermediate/dangling links, non-directory or
unreadable ancestors and missing/unreadable roots keep debt; non-Unix always
returns false. This supersedes round11's immediate-parent-only predicate.
The existing 4096-hold bound also limits the held-new absence inventory; omission
from the index or observed set alone cannot release a hold. The account item
stops reconciliation after retirement, preserving SOURCE N3 incidence. Request-
census removal now counts through the same shared seam. Native cohort controls
use non-directory unavailable ancestors, so no valid absence proof frees them.

The new platform/held-new/missing-intermediate controls remain unexecuted until
E1's exact-head Linux and supported-layout macOS contracts. Local Clippy compiles
all targets but does not execute them. No version/field, money, proof, codec,
allowlist, audit-cap value or Full admission rule changes in this round.


Round14 repairs the two remaining Linux fixture expectations without changing
production. A reset carrier still re-arms current-index scheduling debt before
restoration, while a missing checkpoint selects StateMissing independently of
that debt; the fixture now asserts both the read reason and the exact carried
deadline, retaining its real clean-record replacement checks. Account-hold
pruning now uses the same rooted-filesystem premises as the shared hardened
absence helper: no proof root or a still-present file retains the hold, and
actual deletion beneath a readable configured root permits release. Existing
persistence, resolving-parse, partial-page and population-bound assertions stay.
Local all-target Clippy is required; runtime qualification remains CI-only.

Round15 gives cap delays durable custody through the existing empty source
fingerprint witness. Both paced and unfunded completions preserve committed
size and stay age-exempt even when a changed root configuration replaces the
watcher queue. The production-scanner regression delays real growth, commits a
partial subset, saves/reloads, advances beyond the activity window, adds a root
and verifies counted catch-up with no lost entry or marker and cold Full body
parity. A separate control serializes the retry without any traversal present.

The hardened absence predicate matches the shared account-hold implementation;
its diagnostic carriers do not. Both audit retirement and deleted-account-hold
release currently emit temporary traversal-point counts. Integration with the
shared diagnostics must preserve both carve-outs and replace those emitters
without duplicate counts. No new persisted field or cap increase is introduced.

Round16 pins the accepted temporary diagnostic contract through the actual
deleted-account-hold scan: audit_retired_absent{events} and
withheld_hold_released{deleted} each emit once, with the shared source/schema
and count meaning, and neither emits on the next generation. Counting all
records makes duplicate carriers fail the fixture. The temporary audit count
now uses the same events object as the integrated diagnostics. Deleted-hold
tokens remain unreported until shared withheld-account bookkeeping lands.
Whichever implementation integrates second must unify onto one emitter per
count and retain the exactly-once fixture; both retirement paths stay present.

Round17 composes with main's rearm attribution, optional Codex header facts and
development replay harness. Incidental telemetry-only Unchanged reads before
the audit deadline preserve index and checkpoint debt exactly; only a due,
eligible sampled quiet validation can retire it. Cap Full fallback keeps the
ordinary frozen acquisition extent while existing prefix/marker refusals stay.
Cap-delay clears use the shared rearm wrapper with the audit_cap_delay cause,
attributing the later Full and completed native bytes without changing its
read permission or persisted retry witness.

The multi-file fixtures now seed the held key before arming its quiet sibling,
and temporarily park the cohort control beneath an uncertain non-directory
ancestor while building other cohorts. Original mode, marker-population,
pacing, partial-save and Tail assertions remain. The partial-save regression
retains its original quiet-before-growing order check. Optional header and
decoder admission rules are unchanged. Local Clippy compiles all targets;
runtime tests remain CI-only.
