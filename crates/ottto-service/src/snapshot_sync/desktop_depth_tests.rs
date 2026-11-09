use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

/// [money] Desktop census loss followed by recovery emits the never-flipped
/// body's bytes and placement, with two logins, a switch, a gap and a side call.
#[test]
fn desktop_depth_recovery_matches_never_flipped_money_and_placement() {
    with_e2(|| {
        let mut corpus = Corpus::new("desktop-depth-recovery");
        corpus.root = corpus.base.join(".claude/projects");
        let transcript = line(ROOT, "first", AT, 10)
            + &line(ROOT, "switch", "2026-08-02T07:01:10Z", 20)
            + &line(ROOT, "gap", "2026-08-02T07:02:10Z", 30);
        corpus.root(ROOT, &transcript);
        corpus.evidence(
            &[
                api_login(ROOT, "first", 10, '1', Some('8')),
                api_login(ROOT, "switch", 20, '2', Some('9')),
                api_login(ROOT, "side", 5, '2', Some('9')),
            ],
            &[trace("first", ""), trace("switch", ""), trace("side", "")],
        );
        let store = corpus
            .base
            .join("Library/Application Support/Claude/claude-code-sessions");
        let bucket = store.join(concat!(
            "123e4567-e89b-12d3-a456-426614174000/",
            "123e4567-e89b-12d3-a456-426614174001/sessions"
        ));
        std::fs::create_dir_all(&bucket).unwrap();
        std::fs::write(
            bucket.join("local_session.json"),
            json!({"cliSessionId":ROOT,"createdAt":"2026-08-02T07:00:00Z"}).to_string(),
        )
        .unwrap();
        let scanner = E2ScanFixture::capturing_identity();
        let mut original = ready(&corpus, &scanner, ScanIndex::default(), 100, true);
        original.finish();
        let disposition = |page: &Page| {
            page.scan
                .snapshots
                .iter()
                .find(|item| item.source_session_id == ROOT)
                .unwrap()
                .session_account_evidence
                .as_ref()
                .unwrap()
                .identity_disposition
        };
        assert_eq!(disposition(&original), Some("complete"));
        let logins = original
            .scan
            .snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .flat_map(|row| {
                row.identity_parts
                    .iter()
                    .flatten()
                    .map(|part| part.account_identifier_hash.as_deref())
                    .chain(std::iter::once(row.account_identifier_hash.as_deref()))
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            logins.len(),
            2,
            "positive control: both logins reach the body"
        );
        let route = |page: &Page, mode| {
            let (result, batches, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
            assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
            RouteResult::emitted(
                mode,
                SnapshotSource::ClaudeCode,
                batches,
                &page.scan.snapshots,
            )
        };
        let never_flipped = route(&original, Mode::ColdFull);
        // A real unreadable identity entry still retracts complete evidence.
        let invalid = bucket.join("invalid.json");
        std::fs::write(&invalid, "{bad json}").unwrap();
        let mut lost = ready(&corpus, &scanner, original.index, 100, true);
        assert_eq!(disposition(&lost), Some("missing"));
        lost.finish();
        std::fs::remove_file(invalid).unwrap();
        std::fs::create_dir_all(bucket.join("local_session")).unwrap();
        // Retry the real incomplete index after its existing backoff expires.
        let mut saved = serde_json::to_value(&lost.index).unwrap();
        saved["claude_desktop_store_retry_not_before_unix_seconds"] = serde_json::Value::Null;
        let mut retry = serde_json::from_value(saved).unwrap();
        crate::snapshots::e2_pipeline_scan_fixture::onto_route_for_test(&mut retry, &lost.index);
        let mut recovered = ready(&corpus, &scanner, retry, 100, true);
        recovered.finish();
        assert_eq!(disposition(&recovered), Some("complete"));
        let recovered_route = route(&recovered, Mode::Restart);
        money_oracle::assert_equivalent(&never_flipped, &recovered_route);
        money_oracle::assert_placement_equivalent(&never_flipped, &recovered_route);
    });
}
