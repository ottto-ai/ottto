//! Thread-local status-pass state and heap-layout implementations.
//! Called through the agent-status facade by collection and tests.
//! Keeps the existing state and layout macro invocations together.

#[cfg(test)]
use super::CodexAppServerTestTimeouts;
use super::{AgentStatusCollection, ClaudePass, CodexHomeBinding};

#[cfg(test)]
thread_local! {
    /// Desktop session JSON reads on this thread: (attempts, bytes read).
    pub(super) static CLAUDE_DESKTOP_JSON_READ_RECEIPT: std::cell::Cell<(usize, u64)> =
        const { std::cell::Cell::new((0, 0)) };
}

thread_local! {
    pub(super) static CLAUDE_PASS: std::cell::Cell<Option<ClaudePass>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    pub(super) static CODEX_APP_SERVER_TEST_TIMEOUTS: std::cell::Cell<Option<CodexAppServerTestTimeouts>> =
        const { std::cell::Cell::new(None) };
}

crate::heap_layout_bound::fields!(AgentStatusCollection; snapshots, source_health_snapshot, codex_scan_homes, codex_home_bindings, setup_snapshot_index);

crate::heap_layout_bound::fields!(CodexHomeBinding; home, account_identifier_hash, workspace_identifier_hash, auth_modified_at);
