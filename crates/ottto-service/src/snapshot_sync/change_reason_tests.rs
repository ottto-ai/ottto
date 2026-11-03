//! Change-reason delivery override over synthetic upload progress only.
use super::*;
use crate::local_resource_diagnostics::change_reason::Token;

/// [behaviour] A pure resend of the held body takes its delivery cause
/// (head conflict or ACK recovery); a changed body keeps its selection cause.
#[test]
fn pure_resend_overrides_to_delivery_cause() {
    let mut progress = SnapshotUploadProgress::new(
        "c".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    let (entity, session) = ("a".repeat(64), "synthetic-session");
    progress.quarantine_retryable_body(&entity, "held-body", 0);
    let resend = |progress: &SnapshotUploadProgress, body: &str| {
        progress.change_reason_resend(&entity, Some(session), || body.to_string())
    };
    assert_eq!(resend(&progress, "held-body"), Some(Token::AckRecovery));
    assert_eq!(resend(&progress, "changed-body"), None);
    progress.head_conflict_challenges.insert(
        cache_session_key(session),
        HeadConflictChallenge {
            challenge: "challenge".into(),
            stale_revision_v2_hash: "stale".into(),
            answer_attempts: 0,
            last_answer_unix: 0,
        },
    );
    assert_eq!(resend(&progress, "held-body"), Some(Token::HeadConflict));
    assert_eq!(resend(&progress, "changed-body"), None);
    assert_eq!(
        progress.change_reason_resend("unrelated", Some(session), || unreachable!()),
        None,
        "an untracked entity never computes its body witness"
    );
}
