use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

fn desktop_corpus() -> (Corpus, PathBuf) {
    let mut corpus = Corpus::new("desktop-census");
    corpus.root = corpus.base.join(".claude/projects");
    // This session's original pair has no contradicting request telemetry.
    corpus.root(ROOT, &line(ROOT, "desktop", AT, 7));
    let transcript = line(COPY, "first", AT, 10)
        + &line(COPY, "switch", "2026-08-02T07:01:10Z", 20)
        + &line(COPY, "gap", "2026-08-02T07:02:10Z", 30);
    corpus.root(COPY, &transcript);
    corpus.evidence_for(
        COPY,
        &[
            api_login(COPY, "first", 10, '1', Some('8')),
            api_login(COPY, "switch", 20, '2', Some('9')),
            api_login(COPY, "side", 5, '2', Some('9')),
        ],
        &[
            trace_for(COPY, "first", ""),
            trace_for(COPY, "switch", ""),
            trace_for(COPY, "side", ""),
        ],
    );
    let bucket = corpus
        .base
        .join("Library/Application Support/Claude/claude-code-sessions")
        .join(concat!(
            "123e4567-e89b-12d3-a456-426614174000/",
            "123e4567-e89b-12d3-a456-426614174001/sessions"
        ));
    std::fs::create_dir_all(&bucket).unwrap();
    std::fs::write(
        bucket.join("local_session.json"),
        json!({"cliSessionId":ROOT,"createdAt":"2026-08-02T07:00:00Z"}).to_string(),
    )
    .unwrap();
    (corpus, bucket)
}

fn body<'a>(page: &'a Page, session: &str) -> &'a SnapshotItem {
    page.scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == session)
        .expect("the selected session emits a body")
}

fn emitted(page: &Page, session: &str, mode: Mode) -> RouteResult {
    let items = [body(page, session).clone()];
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let (result, batches, _) = upload_under(page.upload_policy, &items, &mut progress, ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    let mut route = RouteResult::emitted_under(
        mode,
        SnapshotSource::ClaudeCode,
        batches,
        &items,
        page.upload_policy,
    );
    route.accepted_identity_buckets =
        Some(json!({session: progress.accepted_identity_buckets.get(session)}));
    route
}

fn restored_fields(index: &ScanIndex, edit: impl FnOnce(&mut serde_json::Value)) -> ScanIndex {
    let mut saved = serde_json::to_value(index).unwrap();
    edit(&mut saved);
    let mut restored = serde_json::from_value(saved).unwrap();
    crate::snapshots::e2_pipeline_scan_fixture::onto_route_for_test(&mut restored, index);
    restored
}

/// [money] After complete -> missing -> complete, daemon body and placement
/// inputs equal a never-flipped run; a separate session exercises two logins,
/// a switch, an evidence gap and a side call.
#[test]
fn desktop_depth_recovery_matches_never_flipped_money_and_placement() {
    with_e2(|| {
        let (corpus, bucket) = desktop_corpus();
        let scanner = E2ScanFixture::capturing_identity();
        let mut original = ready(&corpus, &scanner, ScanIndex::default(), 100, true);
        original.finish();
        let disposition = |page: &Page| {
            body(page, ROOT)
                .session_account_evidence
                .as_ref()
                .unwrap()
                .identity_disposition
        };
        assert_eq!(disposition(&original), Some("complete"));
        let logins = body(&original, COPY)
            .model_usage
            .iter()
            .flat_map(|row| {
                row.identity_parts
                    .iter()
                    .flatten()
                    .map(|part| part.account_identifier_hash.as_deref())
                    .chain(std::iter::once(row.account_identifier_hash.as_deref()))
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        assert_eq!(logins.len(), 2, "both control logins reach the body");
        let never_flipped = emitted(&original, ROOT, Mode::ColdFull);
        let invalid = bucket.join("invalid.json");
        std::fs::write(&invalid, "{bad json}").unwrap();
        let mut lost = ready(&corpus, &scanner, original.index, 100, true);
        assert_eq!(disposition(&lost), Some("missing"));
        lost.finish();
        std::fs::remove_file(invalid).unwrap();
        std::fs::create_dir_all(bucket.join("local_session")).unwrap();
        let retry = restored_fields(&lost.index, |saved| {
            saved["claude_desktop_store_retry_not_before_unix_seconds"] = json!(0);
        });
        let mut recovered = ready(&corpus, &scanner, retry, 100, true);
        recovered.finish();
        assert_eq!(disposition(&recovered), Some("complete"));
        let recovered_route = emitted(&recovered, ROOT, Mode::Restart);
        money_oracle::assert_equivalent(&never_flipped, &recovered_route);
        money_oracle::assert_placement_equivalent(&never_flipped, &recovered_route);
    });
}

fn lineage_page(corpus: &Corpus, scanner: &E2ScanFixture, index: ScanIndex) -> Page {
    let mut page = corpus.raw(scanner, index, 100, true, &[]);
    page.upload_policy.session_attribution_enabled = true;
    page.enrich(corpus);
    let mut sent = twin(&page);
    sent.finish();
    let mut progress = e2_progress();
    let (result, _, _) = upload_under(page.upload_policy, &sent.scan.snapshots, &mut progress, ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    page.delivered = Some(progress.fresh_context_body_acks);
    page
}

/// [money] An evidence-less child loses and regains only its lineage. Each
/// stage matches a cold scan's body, placement inputs and actual ACK ledger,
/// and counts one owned request without an extra copy.
#[test]
fn parentless_child_matches_cold_at_each_census_stage() {
    with_e2(|| {
        const CHILD: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let (mut corpus, _) = desktop_corpus();
        corpus.root(CHILD, &line(CHILD, "child", AT, 9));
        corpus.evidence_for(
            CHILD,
            &[api_login(CHILD, "child", 9, '1', Some('8'))],
            &[trace_for(CHILD, "child", "")],
        );
        // Preserve an old durable store shape with lineage and no original
        // identity, using the real discovered inventory and retry/backoff path.
        let probe = ready(
            &corpus,
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            100,
            true,
        );
        let inventory =
            serde_json::to_value(&probe.index).unwrap()["claude_desktop_store_inventory"].clone();
        let mut seed = serde_json::to_value(ScanIndex::default()).unwrap();
        seed["claude_desktop_store_inventory"] = inventory;
        seed["claude_desktop_store_retry_not_before_unix_seconds"] =
            json!(nanos("2026-08-02T08:01:00Z") / 1_000_000_000);
        seed["claude_desktop_title_files"] = json!({
            "parent": {"cli_session_id":ROOT,"user_set":false,"desktop_session_id":"local_parent"},
            "child": {"cli_session_id":CHILD,"user_set":false,"desktop_session_id":"local_child",
                "spawned_from_desktop_session_id":"local_parent"}
        });
        let scanner = E2ScanFixture::capturing_identity();
        let mut prior: ScanIndex = serde_json::from_value(seed.clone()).unwrap();
        for complete in [true, false, true] {
            let change = |saved: &mut serde_json::Value| {
                saved["claude_desktop_identity_census_complete"] = json!(complete);
                saved["claude_desktop_lineage_census_complete"] = json!(complete);
                saved["traversal"] = serde_json::Value::Null;
            };
            let index = restored_fields(&prior, change);
            let mut page = lineage_page(&corpus, &scanner, index);
            page.finish();
            let mut cold_seed = seed.clone();
            change(&mut cold_seed);
            let mut cold = lineage_page(
                &corpus,
                &E2ScanFixture::capturing_identity(),
                serde_json::from_value(cold_seed).unwrap(),
            );
            cold.finish();
            let child = body(&page, CHILD);
            assert_eq!(
                child
                    .session_account_evidence
                    .as_ref()
                    .unwrap()
                    .identity_disposition,
                Some("missing")
            );
            assert_eq!(child.request_count, 1, "one owned child request");
            assert_eq!(
                page.scan
                    .snapshots
                    .iter()
                    .filter(|item| item.source_session_id == CHILD)
                    .count(),
                1
            );
            assert_eq!(
                child.attribution_facts.iter().any(|fact| {
                    fact.field == "parent_session_ref"
                        && fact.value == ROOT
                        && fact.evidence.source_version == "claude_desktop_spawn:v1"
                }),
                complete
            );
            let expected = emitted(&cold, CHILD, Mode::ColdFull);
            let actual = emitted(&page, CHILD, Mode::Ram);
            assert!(expected.accepted_identity_buckets.as_ref().unwrap()[CHILD].is_object());
            money_oracle::assert_equivalent(&expected, &actual);
            money_oracle::assert_placement_equivalent(&expected, &actual);
            prior = page.index;
        }
    });
}
