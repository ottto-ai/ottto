# Preserve settled files after an upload error

An upload pass can durably acknowledge an earlier page and then fail on a
later page. Previously, shed responses saved a partial scan index, while
terminal upload errors left all file checkpoints uncommitted. If a following
upload delta omitted an acknowledged item, the resumable driver's bounded
input pruning removed its disposable page ACK. A returning unchanged file
could then be offered again.

Shed and terminal-error handling now share the existing partial-index operation.
Before index CAS, it locks and reads the saved progress ledger, verifies the
same destination, generation and serialized settlement state, and checks exact
current body witnesses. Unsaved or racing ACKs cannot certify a file. Local-state
upload errors skip this operation because their durability is uncertain.
The destination binding is revalidated before saving, and locally held account
or usage families remain excluded. Existing quarantine and replay obligations
are preserved by `ScanIndex::committable_subset`.

Failed passes preserve their original upload error and source failure cadence.
They do not publish a complete-census manifest, retire progress, complete a
backfill or historical replay, or adopt a global upload context. Fully settled
file groups can retain their per-file body revision. No new scheduler, writer,
payload spool, provider call or wire contract is introduced.

A file with several semantic entities still needs every member settled before
its new checkpoint can commit. The change does not solve ACK retirement across
varying deltas for a partially settled multi-entity file. It also does not
establish the cause of all historical same-body reoffers: body/contract updates,
legacy recovery, quarantine retries and intentional replay remain valid.
Backend profile-binding precedence is a separate ownership problem.

Native regression tests use tiny synthetic rollouts and the production batch
preflight, exact ACK validator, resumable driver, progress/index CAS and partial
checkpoint helper. They cover omitted-item restart, stable resume, unsaved ACKs,
progress/index races and save failures, changed body/destination, held groups,
pending replay and the multi-entity residual. Existing admission-recovery and
scope/replay controls remain required. Release and installed acceptance are
separate from source verification.
