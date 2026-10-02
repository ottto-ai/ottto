# Local Claude worker outcome diagnostics

Normal registered-slot upkeep now publishes a closed `claude_slot_worker_*`
diagnostic through the existing exact-account diagnostic field. Its original
completion time is a **local worker** clock, not a provider-check, quota-reading,
credential-expiry, or vendor-command-attempt time. A queued `refresh_due` alone
still does not prove that a worker ran.

The worker can report its typed upkeep outcome, an exact-root identity-verifier
failure, rejected valid-access reconciliation, or accepted same-root/same-pair
metadata reconciliation. Local reconciliation preserves saved limits state and
original quota/check clocks; it does not claim recovered limits.

Publication uses existing registration, consent, network, suppression and
transaction owners. Full lock-time registration/binding/deadline equality and
bounded original clocks are required. Removed/rebound slots are not recreated.
If those gates or persistence refuse publication, absence remains **unknown**,
not evidence of no worker or a successful check. Old unfenced upkeep witnesses
are not promoted into these diagnostics.

The next blocked saved-expiry collection retains the receipt and original local
clock, including a blocked candidate cloned before worker completion. The
existing batch owner checks an ephemeral blocked-branch descriptor under
registration then collection locks: unchanged root/service/owner, both hashes
and deadlines, no suppression and no newer candidate local receipt. Retention
refuses a collection observation newer than the original local receipt.
A historical saved enum may still be fresh when its access expires;
the actual blocked branch, not that stale enum, gates receipt retention. No descriptor
is supplied by fresh/provider or suppressed collection branches. Registration
failure refuses guarded persistence instead of falling back to unfenced retention.
A genuine new collection can replace it with that collection's own
evidence; this is not a worker history or a new retry mechanism. Unsupported UI
consumers may ignore the new closed codes without treating them as provider
success. Supported JSON consumers must likewise distinguish these local codes
from `claude_oauth_usage_check_succeeded`.

When the default slot supplies the meters for the same exact account and
workspace pair, the blocked canonical anchor is neither uploaded nor turned
into a degraded snapshot. Its single closed worker receipt, with its original
local clock, now travels on that winning snapshot's diagnostics. Only exact-pair
`claude_slot_worker_*` codes move; the anchor's provider-check and collection
codes stay with the anchor, and the anchor uploading itself carries nothing extra.

A pre-claim `needs_login` read from the slot's actual credential is no longer
masked by an older witness recorded for a later credential expiry. Such a
witness is history from before the credential was replaced or signed out;
returning it reported a stale `expiry_unchanged` every pass without running a
vendor command. Only a running claim, or a newer witness written while this
read was in progress, keeps precedence.

For a blocked saved anchor (`refresh_due` or `stale_access_token`), the exact
fenced worker receipt now sets saved-connection health. `needs_login` projects
`reconnect_required`. A refresh-failure receipt projects `attention_required`
once the saved access deadline is more than 24 hours past. Failure receipts
include `expiry_unchanged`, `nonzero_exit`, `timed_out`, `backoff`,
`reconciliation_refused` and the identity failures. Any other or newer receipt
leaves the anchor `temporarily_unavailable`, and a successful pass replaces the
receipt. Meters and quota clocks are unchanged.

Session: Codex native 01a0f43d. No provider checks, auth mutations, cadence,
consent, breaker or release changes were performed for this correction.
