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
loss-free and sealed, and the replacement copy must be admitted. Only then are
checkpoint debt and index scheduling marker cleared together; the existing
save/writer persists the cleared certificate. Full verification time stays old,
and source_verified, census and Full-audit credit still see the owed debt.
Deferred/failed persistence remains owed on the older disk certificate; a disk
retirement is asserted only after its writer receipt.

At 256 marked entries, only an unmarked file needing fresh debt takes its native
Full fallback (`audit_cap_full`); already-marked files still Tail, and quiet
debt-free checkpoint reuse remains available. Existing/imported obligations are
never evicted or capped by deletion. New prefix/lossy obligations without a slot
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
