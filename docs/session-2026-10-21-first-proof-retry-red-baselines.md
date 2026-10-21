# First-proof retry F0: test-only red baselines

This change adds desired-behavior assertions for quiet, accepted-unproven
Claude families. It changes no production behavior. The baselines use the
existing p12 scan, evidence fold, policy finalizer, exact body ACK, selected
checkpoint and save/load fixture without editing it. The new module is nested
under the fixture module so it can import the private helpers.

## Design summary

The recovery target is a fresh whole-family observation in the next eligible
healthy traversal, followed by an exactly acknowledged reported-usage body
within two further healthy traversals. Scheduling alone cannot supply usage
proof, physical membership, account identity or acceptance.

- R0: the same physical root grows within W0 and is re-read through a queued
  watcher candidate. The fold must report member_changed and invalid pending;
  a healthy terminal accepts honest unproven bodies and prunes pending. After
  reload, W1 must create a first witness and W2 must deliver v1 corrections.
  Expected baseline failure: the pruned obligation is never selected again.
- R1: an accepted earlier root is skipped while a new child is observed.
  Eventual child telemetry predates the earlier acceptance, so adding the child
  does not change the root's sidecar fingerprint. W1 must co-observe every
  physical member in one window and deliver by W2. Two-file and one-file page
  variants run before the combined assertion. Expected baseline failure:
  missing-member co-observation is forgotten at terminal pruning.
- R2: a serialized, accepted-unproven index has no witness or pending and
  quiet matching telemetry. Ordinary discovery must enroll and prove it.
  Expected baseline failure: existing backlog receives no retry obligation.
  The setup uses the real R0 history and removes the proposed optional retry
  envelope to model an older index; discovery gets no new refusal or edit.

The closed fence's existing replay deadline is placed 23 hours after W0.
Every recovery page asserts full_rearm=false, unchanged upload/replay context,
and no reads of unrelated settled transcripts. No parser bump, old-window
occurrence promotion or seeded witness is used. The only scheduling injection
is the closed-fence input and R0's exact watcher candidate in its persisted
checkpoint; the subsequent read and proof invalidation execute normally.

## Proofstop summary

A complete healthy fold can prove current valid families even while the
duplicate fence remains closed. A first-proof failure can instead be lost:
terminal cleanup prunes unquarantined pending, while ordinary terminal rearm
selects proven families and other existing obligations. With stable accepted
files and sidecars, a quiet unwitnessed family can then remain skipped.
These assertions distinguish that liveness defect from proof-gate failures.

Green controls cover physical twins, cross-project copies, hard links and
content/path disagreement; identity-invalid observations; actual admission
over the production occurrence cap; exact ledger mismatch; and late API or
trace rows selecting both root and children through normal fingerprint retry.
The cap control expands an actual parsed synthetic observation in memory;
it does not introduce a test cap or alter production limits.

The content/path control uses a top-level K.jsonl containing identity L and
asserts the parsed identity before scanning. Subagent identities are explicitly
re-keyed from paths by the existing parser; changing only a subagent event's
parent sessionId does not create the intended identity disagreement.

## Validation and limits

Tests execute in public CI only. Local validation is explicit-file rustfmt.
The intended red result is exactly R0/R1/R2; the controls must pass. This slice
does not implement or certify scheduler cadence, cursor/wrap behavior,
resource admission, revision tombstones, legacy-owner pulls, or new-state
restore/CAS semantics. Those require the future scheduler. In particular,
backlog discovery's sidecar-load accounting and unknown-age diagnostics cannot
be asserted before that implementation exists.

The PR remains draft and must not merge with these intentional failures.

Agent: Codex GPT-Sol (opus-cli-agent helper for Claude Code owner)
Agent session id: 166654d2-a05b-43d0-aca6-9d31e77ae2b3
Agent session name: Daemon StateMissing/repeated-full-scan
Agent session source: opus-cli-agent headless helper

## LITE test and accounting extension

The branch now merges main at 7c46fab6 and adds test-only LITE fixtures for
multiple quiet windows, continuing growth with fixed telemetry, missing/extra
membership, unchanged-revision nonprogress, 130 families across a 128-family
batch, an indivisible 1,025-file family, and off-page partial/held-save recovery.
The save probes explicitly supply a proposed fingerprint clear as controlled
input to existing selected-save code; they install no production policy.

An open-fence R0 diagnostic shows whether BASE global replay masks targeted
recovery. It is expected red while the existing fence transition triggers
that replay. Candidate reason decoding, a pinned old-reader shape, absent-byte
identity, exact scalar carrier pricing, oldest-first ordering and an N=6 guard
are standalone test-local contracts. They do not install a decoder, runtime
carrier, historical discovery, or production fingerprint clear.

A no-state terminal clear cannot retain cap-deferred work after pending prune,
certify an exclusive transient failure from a first-cause enum after evidence
loss, or enforce a cross-window N guard. Those resource and policy gaps remain
explicit. The future optional path must remain fail-closed until the exact
reason provenance, current hold/exclusion gates and owner funding are approved.
