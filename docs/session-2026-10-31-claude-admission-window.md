# Claude admission re-offer scan window

The optional support-directory marker `claude_admission_reoffer_window_enabled`
limits admission-triggered widening of the Claude scan window. It defaults OFF.
Only a regular file enables it; symlinks and directories do not. The marker is
read at source-cycle preparation, independently of the terminal-off setting.

When enabled, an ordinary current-limit RetryPending hold inside the negotiated
window leaves that window unchanged. The one-shot admission re-offer still
widens the scan: its existing zero failure count and zero retry deadline mark
an unspent re-entry. Legacy settlement reconciliation uses that same shape and
keeps its recovery opportunity. No persisted field or upload format is added.

A pending retry outside the discovery window also keeps widening, including one
that aged out after refusal. This uses committed file/entity incidence and the
scanner's existing mtime cutoff, using current file metadata. Missing metadata,
non-files and unknown incidence conservatively keep the broad scan. This avoids
relying on a committed mtime that could be stale after a restore or copy.
No ACK or quarantine is settled by this window decision.

The enabled path logs only counts: `armed`, `outside_or_unknown`, and
`ordinary_inside`. Explicit historical and context-curve replays retain their
existing window decisions. With the marker absent, the original pending query
is used. Codex and Pi retain that original query under either setting.
