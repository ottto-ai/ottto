# Session admission and bounded recovery

Session items now use the deployed backend budget: 655,360 decoded JSON bytes
(640 KiB), with 656,384 bytes only for the explicit cleared-curve exception
whose ordinary item fits. Full hourly usage, selectors, semantic witnesses and
accounting remain intact. The exact request preflight stays 4 MiB, packing stays
2 MiB and 50 entities, and money and upload identities do not change.

The existing scan-index quarantine witness records the item admission limit.
Old witness JSON defaults to the former 128 KiB limit. Each ordinary cycle
re-arms at most 50 currently indexed refusals under an older limit, including
four-failure terminal records, and saves the index through its existing atomic
CAS before delivery. Accepted marks remain. Legacy records have no durable
rejection reason, so recovery also re-offers other current old-limit refusals;
it cannot claim size-only selection. Superseded and absent terminal records
remain disclosed. This does not change compiled historical replay revisions,
create a second replay, or clear all successful uploads.

The existing upload ledger adopts this newer index obligation, leases retries
on its existing deadline, and records only exact accepted/unchanged ACKs.
Restart, failed checkpoint, conflict and lost-ACK behavior remain bounded by
existing delivery. A failed re-offer enters the normal four-failure quarantine
ladder under the new policy and is not re-armed by this migration again. The
existing full local replay window is used while a current-policy refusal remains pending, including conflicts
and refusals with nonzero failure counts; account-switch cutoffs and upload policy still apply. Source
files which are gone cannot be recovered by a larger limit. Completed traversal
is not proof that every body was ACKed.

Gzip remains opt-in. The encoder now chooses identity for exact serialized
requests above 1 MiB decoded, or an encoded body above 2 MiB compressed. This
avoids the backend gzip middleware's separate 413 boundary without changing
batch limits, discarding data, disabling gzip process-wide, or treating a
refusal as acceptance.

Release must contain the backend cap and synchronous cost-fact chunking fix
before installing this daemon. Synthetic source proofs do not establish
installed historical recovery: release acceptance must record the runtime pin,
installed version, current destination, bounded refused-body re-offers, exact
ACKs, full hourly materialization, sibling progress and remaining terminal
counts. No historical upload, daemon restart or release is part of this source
change.
