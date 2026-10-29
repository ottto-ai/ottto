# Large-record restore integration — 2026-10-29

The integration branch merges the complete large-record restore chain onto
3c0ced41, then merges main at 68094b0d. History is preserved through merges;
no rebase, squash or force push is used. This is a static development snapshot,
with no pull request or release qualification.

The final durable-v1 behavior wins for process-lifetime T14 rebuild history,
missing-carrier recovery, stored compatibility-debt hashing, typed restore
provenance and the removal of the UpgradeMissing hold. The restore chain keeps
its active lease, disk admission floor, pending receipt reconciliation,
lossless original-return custody (three attempts), old-checkpoint prepare_io
fallthrough, large-Codex refusal and resource-growth Full handling. Main's
always-on capture semantics remain in the native preparation check.

Caller repairs carry audit debt through the parked original-return frame,
adapt record/test constructors and direct private restore calls, and report
Pending independently from Held or successful restore on the existing
local_resources carrier. Pending-only pages remain visible. Diagnostic fields
are additive to schema 2.

The Claude restore predecessor must land first: its exhausted-retail growth
fallback closes the terminal-drop dependency. Funded re-derivation, structural
active-bound handling and the shared fail-toward-reading pacing map remain the
next integration's work. No active limit, format version, parser version or
scan-identity version is raised here.

Validation: explicit-file rustfmt parsing/formatting and git diff --check only.
Existing production restart, return-refusal and receipt-retry tests are retained;
they have not been executed on this combined head. The shared transition fixture
is still draft #882. Its final API and matrix rows, crash-edge coverage, Linux,
native layout/Clippy, emitted-money equality and independent owner reviews remain
required before opening/qualifying the logical pull request. No local Cargo,
CI dispatch, production write or release was performed for this integration.
