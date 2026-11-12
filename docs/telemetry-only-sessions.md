# Telemetry-only Claude sessions

This collector remains dark until the server advertises
`claude_otel_only_sessions:v1` with a valid pairing floor, local usage
reconciliation and required head CAS. Missing or withdrawn capability prevents
synthetic reads, builds and sends. Activation is recorded once per pairing
chain in the existing destination upload-progress ledger.

Only new append notifications enter scheduling. Pre-activation files stay held;
this feature does not backfill or delete that backlog. Registered transcript
families and positive request holders take precedence over telemetry-only
sessions. Incomplete scope or evidence stays owed.

The collector regenerates cumulative bodies from the strict API and trace pair
loaders, uses the ordinary request reducer and identity rules, and uploads
through normal CAS and exact entity acknowledgement. Retention requires an
accepted-only binding committed in the same progress ledger, for this
destination, body and pair generations. Generation equality is rechecked under
the relay append lock before unlinking.

Verification prompts use fresh UUIDs in reserved namespace
`6f747474-6f00-4f00-8f00-*`. The relay excludes these API and trace rows before
persistence. Ordinary SDK sessions remain eligible. The child also disables
OpenTelemetry exporters through inline settings and preserves
`--no-session-persistence`. The local usage refresher is unchanged.

Candidates remain in the existing root-keyed progress ledger while evidence,
identity or delivery proof is incomplete. Receiver identity limits hold the
whole telemetry-only body and use the existing over-cap diagnostics. They
never authorize sending a smaller or identity-stripped replacement.

Transcript takeover, pre-activation refusal, permanent server refusal and
completed cleanup release scheduling metadata. Cleanup retries use the original
accepted generation, tolerate already-unlinked members and sync both directories
before releasing metadata. A committed candidate remains discoverable even when
both files are absent. Older releases tolerate and drop this additive ledger;
rolling forward then conservatively starts a later activation window.
