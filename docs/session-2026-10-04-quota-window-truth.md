# Quota observation and credit state fixes

Codex provider reads stamp quota windows once at response completion. Cached packaging retains that clock. Window starts derived from provider durations report `started_at_basis: provider_duration`; Claude nominal five-hour/seven-day durations report `assumed_duration`. Absent durations and model-scoped windows keep an absent basis.

Claude passive status-line percentages can replace a finished cycle only with a newer observation for the exact same account, organization and meter, a later reset, and a nominal start that contains the observation. Existing same-reset tolerance remains. Dollar/total-bearing OAuth readings keep their independent evidence and are never overwritten by percentage-only status-line values.

Claude explicitly disabled usage credit pools emit unknown amounts with enabled false. An enabled pool without amounts stays unknown. The client-supported extra_usage null monthly limit maps to unlimited; zero remains exhausted. Existing money conversion and currency semantics are preserved. Reason, one-time expiry, grant lists and credit observation clocks are not emitted before backend durability readiness.

Four new and 21 existing hermetic Rust fixture tests passed. Tests cover exact meter/account isolation, stale observations, later-cycle start/reset guards, retained monetary readings, provider clock and start basis, disabled/unlimited/unknown/zero states, and existing parser/cache behavior. No live daemon, provider credential, grant-use or forced provider request is needed.

Codex source evidence: OpenAI source b741e480e203f037ca726bc2a76d99a8e8668e66, account_processor.rs get_account_rate_limits_response fetches the provider through BackendClient and ordinarily requests reset details unless exclude_reset_credit_details is true. This establishes the read path, not that our connected accounts returned grant rows. Actual grant acquisition and decimal-string emission remain separate gated follow-ups. A bounded diagnostic on the existing ordinary read reports list presence/length and at most 20 rows of status counts/expiry presence. Its existing exact-account/workspace and completion-clock gate refuses unbound evidence; ids, titles and timestamps are not retained. It neither emits grants nor adds a provider request.

Independent model review and signed installed acceptance remain outstanding. No independent review pass or installed/live fix is claimed.
