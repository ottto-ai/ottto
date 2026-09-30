# Configured subscription availability and check clocks

Previously accepted Codex account/workspace registrations remain in agent status
when current credential identity cannot be verified. These rows use `config_file`
collection, `degraded` status, unknown login state, and the diagnostic
`codex_configured_account_unavailable`. They carry only the previously accepted
identity hashes, no quota windows, credits, invented email, or plan. A current
snapshot of the same exact pair suppresses the unavailable duplicate. Remembered
registration never becomes live credential, quota, or transcript authority.

Claude slot collection adds an optional machine-local `account_profile`: the
exact account and organization hashes, profile capture time, and independently
reported email, organization label, plan, and product. Degraded snapshots retain
these labels only for the same complete binding. Missing values stay unknown;
changed or missing bindings and future profile clocks fail closed. This profile
is not quota freshness evidence. Backend uploads still redact email, raw account
and organization IDs, and organization labels.

Successful Codex app-server reads expose `codex_app_server_usage_response` through
the existing diagnostic contract, with `observed_at` set at successful response
completion and the validated exact account/workspace hashes. This clock says
when the local app-server read completed; it does not prove a new provider
observation or an upstream cache refresh. The original quota window observation
time remains unknown. Empty usage, missing exact identity, failed reads, and
missing or future check clocks cannot emit this success witness.

`codex_usage_probe_failed` records the failure outcome clock separately. Consumers
must distinguish configured presence, current quota availability, successful
local check time, original quota observation time, and snapshot capture time.
They must not label unknown original readings live solely from snapshot capture.

Focused Rust tests cover unavailable configured inventory, live duplicate
suppression, unidentified registration refusal, exact Claude profile retention,
binding switches, missing product labels, privacy redaction, legacy protocol
decoding, and successful/unknown Codex check clocks. Existing polling, retry,
breaker, authentication and release behavior is unchanged.
