//! The money/placement oracle exercises two hydrates on one live session.

/// [money] Reused pending summaries preserve emitted money and placement,
/// including the fixture’s two-account placement positive control.
#[test]
fn reused_session_usage_heads_preserve_money_and_placement() {
    super::cold_row_with_memo("duplicate_request_ids", true);
}
