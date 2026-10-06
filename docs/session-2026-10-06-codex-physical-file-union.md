# Forward Codex physical-file joining

A logical Codex session can occupy several rollout files. Sending each file as a
complete replacement can leave the server with only the final segment. The
local scanner now joins a bounded, proven group before ordinary upload. The
existing snapshot wire format, semantic identity, UI observation times and
common representative ACK remain the publication contract.

## Admission and ownership

The existing directory traversal supplies a frozen roster including old and
unchanged files. A secure first-header inventory identifies the owning session
and Codex home. Joining requires the same owning header and home, a complete
stable directory census, and the complete group within the ordinary file page.
At most 32 members, 256 MiB of source lengths and 50,000 parsed records are
admitted per group. Header inventory is bounded to 32,768 files, 64 KiB per first
header and 32 MiB of total reads, including read-ahead. Legacy traversal metadata
without the directory witness cannot certify a join; ordinary retry obtains a
fresh census.

One proof pass establishes unique native response identities, a contiguous
thread-token counter chain across files, and coverage of exact UI usage events.
Whole-record digests collapse complete copies into one canonical input.
Conflicting overlap, gaps, resets, ordinal/fork boundaries, incomplete native
replay, contradictory creator headers and loss of any protected member hold the
group, including a still-contiguous surviving prefix. They do not
declare it empty or advance its previous checkpoint.
Healthy groups remain eligible. Existing bounded traversal retry and counts
expose these holds; there is no additional scheduler.

The canonical order is replayed through the existing parser. File-local model,
effort, turn and pricing selector context reset between members. The logical
account envelope and conflict evidence retain normal ownership rules. Explicit
missing/conflicting creator evidence cannot fall back to a cached or current-home
account guess. Before the first joined replacement of a previously settled
legacy file, the native single-file derivation must reproduce its old settled
entity set after binding and policy. A comparison-only old account binding can
isolate the intentional removal of a previous guess; it never becomes emitted
ownership. An unreproducible old pricing decision holds that correction.

## Requested-priority evidence and crash recovery

The optional, versioned local ScanIndex receipts retain a previously derived
selector decision. They are application evidence, not independent provider
billing truth. In particular, the existing logs_2 turn signal can be uncertain
for mixed requests in one turn. This change preserves that inherited meaning
without claiming a new response-level pricing source.

Receipts contain hashed physical-record/context identities, a parsed-prefix
digest, derivation and upload-context fingerprints, and bounded selector
provenance. No transcript, raw response ID, request body or provider credential
is retained. Exact old record, prefix and context matching can restore an old
priority decision after traces expire. New appended contributions do not inherit
that receipt merely because they share a turn. Cumulative-only legacy rows use
their exact physical record digest; this supplies no response-ownership proof.

New selector facts are captured before a protected POST, under the existing
progress lock and ScanIndex compare-and-swap. Capture does not advance committed
file/body/ACK witnesses. A newly captured file is explicitly uncommitted and
eligible until a validated common ACK and safe checkpoint settle it. No lock is
held across the network. A failed capture, stale generation or changed source
holds the protected group before POST. Capture survives a lost response,
rejection, partial checkpoint and restart; only normal accepted settlement
promotes it to applied evidence. Accepting an older body cannot discard newer
captured facts: promotion requires that the accepted derivation covers those
facts. The driver rechecks the current member objects
and directory membership before send and checkpoint.

All outgoing joined aliases also capture a versioned hash of the current
physical member set, including standard-priced groups. This closes the crash
between durable server ACK and local index promotion: losing a member after
that crash holds a replacement rather than shrinking accepted usage. Pending
membership is separate from applied membership and has no account authority.
Fresh proof must include every previously protected physical path before
superseding a pending set; expansion/rejection cannot forget an older member.
Only the matching current common ACK and validated checkpoint clear it, so an
older body's acknowledgement cannot clear newer pending membership.

Pending membership is limited to the existing 32,768-file census bound per
index, with owner-atomic refusal and no eviction. Each fixed marker contains
one version prefix and 64 hex characters (87 bytes), below 2.8 MiB of marker
values at that bound, plus existing file entry and hash-only owner metadata.
Unknown versions or malformed markers preserve the index and hold the affected
owner. There is no timeout that deletes protection. Missing required evidence
must be restored with compatible source files and reader. All known members
present with an independently valid native contribution chain can demonstrate
a legitimate correction, including a lower total. If a member cannot return,
recovery requires explicit review of complete replacement source evidence and
a scoped index migration; this patch supplies no automatic reset or backfill.

Each file retains at most 512 priority contributions. Applied and captured
receipt serialization together is capped at 2 MiB per index. Replacement is
file-owned; there is no age-based selector eviction or silent downgrade to
standard to satisfy a cap. Missing required, malformed, unknown-version,
changed-prefix or changed-context evidence holds its correction. A valid future
or malformed receipt preserves the surrounding index and becomes a scoped hold.
A hash-only logical-owner marker in each protected file entry prevents a
state-database total from replacing its joined or priced history after physical
source retirement. It grants no account authority. Missing sources retain their
file-owned metadata and the existing bounded retry witness; quiet ticks neither
rescan headers nor inflate counts. Unrelated physical owners remain eligible.
Age/missing-source reconciliation cannot evict protected entries. Malformed
owner metadata preserves the index and conservatively holds state-only fallback.
An operator must restore compatible evidence or perform an explicitly reviewed
recovery; automatic scans do not erase the protected state.

These additive fields preserve existing index/wire paths and older files migrate
without claiming newly proven history. Older binaries that ignore the fields
cannot enforce the new protection and must not write this index during a
rollback. Erasing the whole index or all receipt/requirement fields also erases
local evidence; this is not a supported way to repair protected pricing. No
claim is made that absent historical provider evidence can be reconstructed.

## Work and verification boundaries

Selected groups use two bounded native parser passes plus bounded header reads;
there is no raw transcript buffer or extra ledger. An unchanged acknowledged
group checks headers and strong member identities, then skips full replay.
Aliases associate the one common body with every physical member. The existing
common ACK and safe file checkpoint settle all members together; capture alone
cannot settle an alias. Inventory uses the traversal's resolved secure roots,
including supported configured root symlinks. Replayed owners must match their
inventoried group; protected physical paths cannot be repurposed for another
owner. A file-group hold does not invalidate an otherwise complete directory
walk, so known healthy owners remain eligible on later pages. Each publication
boundary checks
a home's roster once for all its selected owners and rechecks individual member
objects. No roster validation result is cached across network or checkpoint
boundaries. Checkpoint validation covers all completed groups whose state can
be saved, including groups whose unchanged bodies were suppressed as no-ops.

Synthetic native tests cover disjoint/copy decisions, overlap/gap/reset/ownership
holds, source mutation, legacy first-import reconciliation, exact tier replay,
metadata loss and caps, capture disk/CAS/authority failures, the real loopback
HTTP client and typed common ACK, crashes before POST and after durable ACK,
trace expiry, lost responses and ordinary restart, pending membership expansion, stale ACKs and valid lower-total
corrections. Synthetic transport evidence
does not prove historical provider billing truth or installed backend behavior.
This implementation does not dispatch a release, change a Druid cluster, replay
historical data or introduce backend wire fields.
