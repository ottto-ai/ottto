# Claude admission re-offer scan window

The optional support-directory marker `claude_admission_reoffer_window_enabled`
limits admission-triggered widening of the Claude scan window. It defaults OFF.
Only a regular file enables it; symlinks and directories do not. The setting is
pinned per process at the first Claude preparation, including OFF: one marker
stat then, a cached boolean thereafter. Restart to apply marker changes.
No incidence files are statted OFF.

When enabled, every current-limit RetryPending record follows one rule, whether
ordinary, legacy or armed by admission re-offer: widen only if some incidence
file is outside the current window or unknown. All known incidences inside the
window leave it unchanged; the narrow walk already visits those files. Failure
counts and retry deadlines are not provenance and do not affect this decision.
Below-limit records retain the existing admission-reoffer behavior.

The rule uses committed file/entity incidence and the scanner's existing mtime
cutoff on current file metadata. Missing incidence, stat/mtime errors and
non-files conservatively widen. No ACK or quarantine is settled by this decision.

Metadata work is incidence-proportional: up to the sum of matching incidences
across qualifying records, with early exit per record on outside/unknown. A file
shared by multiple entities may be statted repeatedly. The retry lease budget
does not cap this query. A hold aging out can still widen the scan and change
its traversal context; settlement can narrow it again. These residual flips
preserve discovery of owed retries.

The enabled path logs only `outside_or_unknown` and `inside` record counts.
Explicit historical and context-curve replay decisions stay unchanged. OFF,
Codex and Pi retain the original pending query. No persisted format is added.
