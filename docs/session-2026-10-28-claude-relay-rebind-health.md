# Claude relay recovery and endpoint health

Listener recovery now retries the approved Claude candidate port through the
existing supervisor backoff for at most three attempts, reading consent and
settings again per attempt. After three failures, it immediately falls back to
the old port, then default and per-user candidates. The shared control, health
and OTLP listener must recover even if the approved endpoint stays busy.
This resolves review feedback that unlimited approved-port retries could leave
the whole relay unavailable after startup had already selected a fallback.
Startup still uses its existing fallback policy. Missing approval or an
out-of-list approved endpoint retains recovery's old/default/fallback chain.

Status responses and support diagnostics report an approved endpoint mismatch
without persisting it or changing relay state, settings, account identity or
money computation. Human doctor/status output includes the finding's two
loopback ports. Matching ports and withdrawn approval clear the finding.

Regression tests cover a free or briefly busy approved port, a permanently busy
approved port falling back after exactly three attempts and serving health
requests with a mismatch finding, absent approval, invalid
candidate, status/doctor JSON and human output, diagnostics, automatic clearing,
settings preservation and unchanged saved relay/account state. Validation runs
in Linux CI and a final-head macOS contracts dispatch; no local Cargo commands.
