# Idempotent Claude proof re-arm while the duplicate fence stays closed (C1a)

At every complete Claude census, the terminal fold re-armed every earlier-page
member of every proven family (`proof_candidate`). It cleared the member's
source revision, so the next traversal re-read it. While the duplicate fence
stays closed (for example, one transcript response without a `requestId`), the
fence never reopens to settle the family. So the same unchanged members were
re-read as semantic no-ops at every terminal, forever.

## Change

A proven family keeps its earlier-page members unarmed at one terminal only
when every check below holds. Every other case takes the old re-arm.

Terminal-wide checks:
- the fence was closed before this census and stays closed after it;
- the terminal is not a full re-arm;
- the contract-5 identity latch (below) is clear, and the recorded contract
  equals the one this fold runs under;
- no page of this traversal was partially settled;
- the accepted ledger is the current version, no legacy-settlement rebuild is
  pending, and the upload context is unchanged.

Family checks:
- the family is complete, which also excludes twin index keys;
- it has no legacy exclusion fields;
- it has no authority quarantine record (this also covers correction debt);
- no member is demoting;
- its witness fingerprint is the same before and after this census;
- its pending is valid and from this census window;
- no member is in the owned-start census;
- its request hashes are disjoint from every retained or detected duplicate
  hash and from every changed duplicate;
- it is not the owner of another family's legacy copied prefix, does not share
  such a prefix, and does not own a request that leads an unproven current
  family.

Member checks (all or nothing for the family):
- the member's committed body set is non-empty, accepted and unquarantined;
- its revision is armed (not already cleared);
- it is not on this page;
- it is not account-held or confirmed empty;
- it was not re-armed by a witness invalidation or a changed duplicate;
- it appears in this window's pending.

No predicate for h527 targets or protected copied-overlap identities exists in
this tree. The duplicate-hash, owned-start and legacy-linkage exclusions above
are the conservative proxies.

**Contract-5 identity latch.** `ScanIndex` gains two fields:
- `claude_request_identity_contract`: the full collector token, or `""`, as
  recorded at traversal start. A change that happens mid-traversal records
  `changed_within_traversal` instead.
- `claude_request_identity_contract_changed`: the latch.

Rules:
- Each prepared Claude cycle compares its contract with the record. Any
  difference sets the latch, including an unknown (absent) or malformed record.
- While the latch is set, nothing skips.
- The first complete, settled closed-fence terminal whose traversal ran under
  the recorded contract re-arms every family file and clears the latch. That
  includes members an earlier skip left unread, which no proof would otherwise
  re-arm. A full re-arm terminal under that contract also clears it.
- A partial save ORs in the committed latch.
- A cycle whose prepared contract never matches its fold (only test scanners
  without a permit) never clears or re-arms: BASE.

**Fence recovery.** A skipped family is not re-read, so its pending goes stale
and its files stay unobserved. A closed fence reopens only after one window
observes every indexed Claude file. Consider the case where all of the
following hold:
- every non-current pending belongs to a witnessed family, and every pending is
  valid;
- the duplicate witness is within bound;
- every unobserved file belongs to a witnessed family that this window did not
  read.

In that case BASE, which re-reads proven families at every terminal, would
reopen as soon as the invalid source is fixed. The fix instead re-arms every
family file once at that terminal and reopens one window later. A family that
was read in this window but still leaves a member unobserved does not qualify,
so the re-arm cannot repeat for it.

A late `claude_api_request:v2` row needs no new state. The sidecar-inclusive
selection fingerprint already re-selects every member of its family, whether or
not the terminal re-armed them.

**Resources.** The scratch is a `BTreeMap<&str, bool>` over the terminal's
proven families. A `BTreeSet<&str>` of legacy-excluded prefix hashes is added
only when one exists. Both borrow their keys.

Before any allocation, both are priced with full-node `tree_nodes` against
`PARKED_BUDGET` (8 MiB):
- 539 B per family entry and 528 B per prefix hash, plus one root node each;
- the peak is `(P + 1) * 539 + (H + 1) * 528` bytes.

An unsupported layout or a refused price keeps the old re-arm for the whole
terminal. That fallback is counted content-free in
`CLAUDE_UNCHANGED_PROOF_BUDGET_FALLBACKS`.

## Diagnostics

The Claude local-evidence counts line (`ClaudeLocalEvidenceStats`) gains one
content-free row, `first_proof_hold`. It is never a decision input:
- `dormant_owner_successor_family_count`: at a complete terminal with healthy
  reports, unproven families read in this window whose root occurrences
  include a request that current API and trace evidence assigns to a
  different witnessed root with no current pending. A root the skip left
  unread looks like that. Such a successor counts only in a window that reads
  it.
- `oldest_dormant_owner_successor_age`: `under_1h`, `1h_to_6h`, `6h_to_24h`,
  `over_24h` or `unknown`, for the oldest such family. The age is an upper
  bound on the hold: the census end minus the family's earliest reported
  request.
- `census_withheld_retry_pending_family_count`: Claude families in
  RetryPending on this page. While it is non-zero, census completion is
  withheld for the whole Claude source.

The encoded row is at most 176 bytes.

## Tests

The tests are in `snapshot_sync/proof_rearm_idempotence_pipeline_tests.rs`. They run on the
real bounded pipeline (`RearmFixture`) plus one request-id-less transcript, with
a BASE arm that refuses the budget:
- closed-fence skip against BASE;
- refused fallback equals the BASE windows recorded on the baseline commit;
- fixed invalid transcript reopens the fence one window after BASE;
- changed-witness, same-window (single page), split-family, account-hold and
  twin-key controls;
- M1 late identity row re-selected and tagged in the same window as BASE;
- contract off→on, older collector, unknown (downgrade) and malformed after
  the skip is active, each re-arming the skipped family once;
- off→on→off within one traversal;
- shed and lost-ACK traversals, including an interrupted full re-arm
  terminal page, keep the latch;
- late copied import with the skip active;
- late API row after the family's pages of a window that reads the family:
  the changed witness keeps the re-arm, and liveness equals BASE;
- late API row between windows: both arms hold the family identically;
- a receipt-only disclosure of the dormant-window residual: a late row
  diverges from BASE, and member growth holds both arms;
- contract off→on re-emission: after the latch re-arm, every family body is
  re-read, built under the contract-5 collector, and offered and
  acknowledged as a new body;
- dormant owner plus a new copied-prefix successor: the successor stays
  unproven while the owner is skipped and is counted with its age bucket.
  The due closed-fence full re-arm still runs, re-arms the owner and the
  successor, and sets the next deadline within a day. The next window proves
  the successor. BASE proves it in the window it appears;
- the first-proof hold row's width and age buckets.

No local tests or builds were run. Results are CI-only.

## Residuals

- **Late provider row for a dormant family.** A family skipped at one
  terminal is not re-read in the next window. Suppose its existing API rows
  are rewritten after its directory was walked in that window and before its
  terminal page. BASE read the family on that window's earlier pages, so its
  terminal re-proves the family from that window's pending and the new rows.
  The fix has no current pending for the family, so its next window
  reconstructs against the earlier witness and goes to RetryPending. This is
  the existing held path for any dormant witnessed family. When a member
  transcript grows at the same point instead, BASE also holds the family in
  the next window, so both arms behave the same.
  - Re-arming the family at that terminal would not help. The re-read
    still reconstructs against the earlier witness, as the between-windows
    control shows for BASE.
  - A sidecar change in a window that does read the family already keeps
    the BASE re-arm: the re-proved witness differs, so the unchanged-proof
    check fails.
  - Parity would need either a terminal re-proof from the carried pending,
    which promotes stale evidence to currentness, or a traversal change that
    reads such a family on the terminal page. Neither is in this slice.
  - The receipt test records both arms.
- **Copied-prefix successor of a dormant owner.** A new fork, `/branch` or
  takeover successor whose copied prefix belongs to a family the skip left
  unread cannot derive its legacy exclusion in that window: the derivation
  needs the owner's root sequence in the same window's pending. It stays
  unproven, priced from its transcript, until a window reads both. That is at
  the latest the window after the closed-fence full re-arm, at most
  86,400 s later. SOURCE accepted this under amendment 1. The receipt test
  pins it, and `first_proof_hold` counts it. A narrowed owner-root pull
  (re-arm a witnessed owner's root when an unproven current family's
  occurrences hit its requests) is a tracked follow-up.
- **RetryPending withholds the whole census.** While any Claude family is in
  RetryPending, as the late-row residual above causes, census completion is
  withheld for the whole Claude source, not just that family. No terminal
  fold runs in that time, so there is no first proof or re-proof for any
  other family and no fence decision. This is BASE's existing mechanism.
  `census_withheld_retry_pending_family_count` counts it.
- **Closed-fence reopen with other unread files.** When an unrelated
  unchanged file is also unobserved, neither arm reopens before the
  closed-fence full re-arm. The late-copy test checks that both arms reopen in
  the same generation.
- **Contract change cost.** The first closed-fence terminal after a contract
  change (or after this field first appears) re-arms every family file once.
- **Fence recovery is one window later than BASE.** It applies only when
  witnessed families are all that keep the fence closed. Otherwise both arms
  wait for the same full re-arm.
