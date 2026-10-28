# Claude relay recovery and endpoint health

Listener recovery now retries the approved Claude candidate port through the
existing supervisor backoff, reading consent and settings again per attempt.
Startup still uses its existing fallback policy. Missing approval or an
out-of-list approved endpoint retains recovery's old/default/fallback chain.

Status responses and support diagnostics report an approved endpoint mismatch
without persisting it or changing relay state, settings, account identity or
money computation. Human doctor/status output includes the finding's two
loopback ports. Matching ports and withdrawn approval clear the finding.

Regression tests cover a briefly busy approved port, absent approval, invalid
candidate, status/doctor JSON and human output, diagnostics, automatic clearing,
settings preservation and unchanged saved relay/account state. Validation runs
in Linux CI and a final-head macOS contracts dispatch; no local Cargo commands.
