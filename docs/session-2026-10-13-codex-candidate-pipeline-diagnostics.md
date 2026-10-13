# Bounded Codex candidate pipeline diagnostics

Codex census diagnostics previously sampled quarantined entities only. A native
file never offered for upload could therefore have no per-file evidence, while
the fenced census record itself precedes delivery.

The optional local v4 block keeps two deterministic samples of identified file
objects, preserving the four existing quarantine samples. It records the actual
candidate decision, metadata/fingerprint equality against an existing checkpoint,
parse hold, finalized single-entity fingerprint and group-body digest, queue
membership, and matching validated request-body/ACK disposition. First holds are
never overwritten. Multi-entity files deliberately remain unqualified for
per-entity delivery. Unsampled files, pre-identification losses, incomplete pages,
legacy ACKs and unmatched entities remain unknown. Counts represent observations,
not unique sessions, billable requests or complete discovery.

The existing census callback publishes pre-delivery state with its process-start,
attempt and generation binding; the existing terminal journal carries later
state. Readers must match those bindings and the outcome sidecar and preserve the
phase distinction. Public status/upload DTOs and collection/accounting/replay
behavior are unchanged. No new journal, per-file write, credential lookup,
provider call or healthy outcome-sidecar write is introduced. Diagnostics do not
acknowledge delivery until the existing request identity, body and ACK validators
succeed; remote acceptance and local checkpoint failure remain separate facts.

The two-slot inline state must fit 768 bytes. Fixed arrays retain no independent
heap storage; completion/layout bounds include the new state. Serialization must
fit the existing 8 KiB census and 32 KiB local diagnostic ceilings; optional
encoding failure retains the existing refusal/drop behavior. The sampling score
is not serialized. Raw paths, session IDs, account strings, body text and arbitrary
errors are absent.

Synthetic production-scanner controls compare complete snapshot bytes and
checkpoint bytes with sampling enabled/disabled. Additional controls cover first
hold preservation, unmatched ACKs, multi-entity uncertainty, counter overflow,
privacy and fixed-buffer serialization. Validation of publication fences and
transport side effects remains separate from these focused controls. These
observations do not establish installed collection completeness or repair missing
uploads. The diagnostic extension is source work; release and ordinary-operation
acceptance require their own evidence.
