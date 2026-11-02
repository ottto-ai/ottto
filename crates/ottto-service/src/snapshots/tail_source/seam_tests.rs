//! The PRE seam's Tail write on real Claude parses, real native finishes and
//! the real state database route: nothing reaches the store before the native
//! verdict, retirement wins over a stale stage, claim-only saves publish
//! nothing, a finish field at PRE sets only its own file aside, and an append
//! restates only each collection's open page.
use super::super::claude::{tests::lines, Claude};
use super::*;
use crate::snapshots::sampled_jsonl::SideCertificate;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::state_v2::money_test_support::ColdSession;
use crate::snapshots::state_v2::{SetAside, TailHead};
use crate::transcript_acquisition::Scope;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: u64 = 1_790_000_000;

struct Route {
    _session: ColdSession,
    dir: PathBuf,
    path: PathBuf,
    index: ScanIndex,
}

fn route() -> Route {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-tail-seam-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.canonicalize().unwrap();
    let (session, index) = ColdSession::publish(Source::Claude, &ScanIndex::default(), &dir);
    Route {
        path: session.path().to_owned(),
        _session: session,
        dir,
        index,
    }
}

impl Route {
    fn save(&mut self, claim_only: bool) {
        let custody = state_v2::published(&self.path).unwrap();
        state_v2::save_locked(&self.path, &mut self.index, claim_only, None, custody).unwrap();
    }
    fn head(&self, key: &str) -> Option<TailHead> {
        state_v2::load_head(&self.index, key, Claude::REDUCTION_REVISION).unwrap()
    }
    fn marker(&self, key: &str) -> Option<SetAside> {
        state_v2::tail_set_aside(&self.index, key).unwrap()
    }
    /// One certified native completion of `lines` as `name`, encoded at the
    /// real PRE seam. Without a `base` it is a Full read.
    fn complete(
        &self,
        name: &str,
        lines: &[String],
        base: Option<TailBase>,
        at_pre: impl FnOnce(&mut SnapshotAccumulator),
    ) -> (PendingTail, Result<ParsedJsonlFile>) {
        let path = self.dir.join(name);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let scope = Scope("tail-seam".into());
        let mut parser = fixture::parser(
            SnapshotSource::ClaudeCode,
            &path,
            File::open(&path).unwrap(),
            apply_claude_code_line,
        );
        parser.prepare_acquisition(None, &scope, None, NOW).unwrap();
        while !parser.step().unwrap() {}
        let SideCertificate::Certified { completed, .. } =
            parser.certify_without_retention(&scope, NOW).unwrap()
        else {
            panic!("a clean fixture is certified");
        };
        at_pre(&mut parser.accumulator);
        let mut tail = PendingTail {
            route: self.path.clone(),
            key: local_index_key(&path),
            id: HeadIdentity::new(
                "tail-seam",
                &self.path,
                SnapshotSource::ClaudeCode,
                &self.dir,
                &path,
                false,
            ),
            certificate: completed.checkpoint.durable_certificate(0).unwrap(),
            unsealed: completed.unsealed,
            full: base.is_none(),
            base,
            encode: tail_encode::<Claude>,
            encoded: None,
        };
        let identity =
            opened_object_identity(SnapshotSource::ClaudeCode, &mut File::open(&path).unwrap())
                .unwrap();
        let request = FinishRequest {
            expected_opened_object_identity: &identity,
            path: &path,
            collected_at: "2026-10-20T16:00:00Z",
            source_file_fingerprint: "a".repeat(64),
            codex_title_metadata: None,
            claude_title_metadata: None,
            attribution_context: None,
            repository_identity: None,
            money_context: None,
        };
        let native = parser.finish_native(
            request,
            Some(&mut |live: PreFinalization<'_>| tail.encode(&live)),
        );
        assert!(tail.encoded.is_some(), "PRE encoded");
        (tail, native)
    }
}

/// [behaviour] A completion rejected by the native finish's own recount,
/// after PRE encoded it, stores nothing; its sibling stages and commits.
#[test]
fn only_the_native_verdict_stages() {
    let mut route = route();
    let (rejected, mut late) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let (accepted, native) = route.complete("b.jsonl", &lines(3), None, |_| {});
    assert!(finish_loss_free(&late) && finish_loss_free(&native));
    // Positive usage that yielded no entity is found only at finalization.
    late.as_mut().unwrap().zero_snapshot_usage_evidence = true;
    let (a, b) = (rejected.key.clone(), accepted.key.clone());
    rejected.publish(&late);
    accepted.publish(&native);
    route.save(false);
    assert!(route.head(&a).is_none() && route.marker(&a).is_none());
    assert!(route.head(&b).is_some());
}

/// [behaviour] A save that removes a file's progress row never applies that
/// file's stage: its graph rows write, its Tail retires (T1).
#[test]
fn retirement_wins_over_a_stage_whose_progress_row_goes() {
    let mut route = route();
    let (tail, native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key.clone();
    route.index.files.insert(
        key.clone(),
        serde_json::from_value::<ScanIndexEntry>(serde_json::json!({
            "size_bytes": 4, "modified_unix_seconds": 1,
            "source_file_fingerprint": "a".repeat(64),
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION
        }))
        .unwrap(),
    );
    tail.publish(&native);
    route.save(false);
    assert!(route.head(&key).is_some());

    let (tail, native) = route.complete("a.jsonl", &lines(4), None, |_| {});
    tail.publish(&native);
    route.index.files.remove(&key);
    state_v2::telemetry::take_thread_event_for_test("tail_apply");
    route.save(false);
    let applied = state_v2::telemetry::take_thread_event_for_test("tail_apply").unwrap();
    assert_eq!(
        (applied["files"].as_u64(), applied["retired"].as_u64()),
        (Some(0), Some(1))
    );
    assert!(route.head(&key).is_none() && route.marker(&key).is_none());
    assert!(!ScanIndex::load(&route.path)
        .unwrap()
        .files
        .contains_key(&key));
}

/// [behaviour] Claim-only saves carry no Tail; the pass's exit commits it once.
#[test]
fn claim_only_saves_publish_nothing_and_the_exit_commits() {
    let mut route = route();
    let (tail, native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key.clone();
    tail.publish(&native);
    state_v2::telemetry::take_thread_event_for_test("tail_apply");
    route.save(true);
    assert_eq!(
        state_v2::telemetry::take_thread_event_for_test("tail_apply"),
        None
    );
    state_v2_baseline_release(&route.path, &route.index)
        .commit_tail()
        .unwrap();
    let applied = state_v2::telemetry::take_thread_event_for_test("tail_apply").unwrap();
    assert_eq!(applied["files"].as_u64(), Some(1));
    route.index = ScanIndex::load(&route.path).unwrap();
    assert!(route.head(&key).is_some());
}

/// [behaviour] A finish-only or live field already set at PRE sets that file
/// aside, counted by cause; its sibling commits.
#[test]
fn a_finish_field_at_pre_sets_only_its_file_aside() {
    let mut route = route();
    let (odd, odd_native) = route.complete("a.jsonl", &lines(3), None, |acc| {
        acc.account_identifier_hash = Some("a".repeat(64));
    });
    let (sibling, native) = route.complete("b.jsonl", &lines(3), None, |_| {});
    assert!(finish_loss_free(&odd_native));
    let (a, b) = (odd.key.clone(), sibling.key.clone());
    odd.publish(&odd_native);
    sibling.publish(&native);
    route.save(false);
    assert_eq!(
        route.marker(&a).map(|marker| marker.cause),
        Some(SetAsideCause::UnexpectedFinishField)
    );
    assert!(route.head(&a).is_none());
    assert!(route.head(&b).is_some() && route.marker(&b).is_none());
}

/// [behaviour] Over its committed base, a one-response append restates only
/// the open page of each collection it grows, and the stored state then
/// loads complete.
#[test]
fn an_append_restates_only_the_open_pages() {
    let mut route = route();
    let (tail, native) = route.complete("a.jsonl", &lines(300), None, |_| {});
    let key = tail.key.clone();
    tail.publish(&native);
    route.save(false);
    let head = route.head(&key).unwrap();
    let mut base = TailBase::default();
    state_v2::load_tail(&route.index, &key, &head, |collection, page, bytes| {
        base.observe::<Claude>(collection, page, &bytes).unwrap();
        Ok(())
    })
    .unwrap();
    let committed: BTreeSet<_> = base.pages.keys().copied().collect();
    assert!(committed.contains(&(Collection::Responses, 1)));
    assert!(committed.contains(&(Collection::ToolUses, 1)));

    let (tail, native) = route.complete("a.jsonl", &lines(301), Some(base), |_| {});
    let staged = tail.encoded.as_ref().unwrap().staged.as_ref().unwrap();
    assert_eq!(staged.change, Change::Ordinary);
    let restated: Vec<_> = staged.pages.keys().copied().collect();
    let [(Collection::Responses, 1), (Collection::ToolUses, 1), (Collection::CapabilityHours, hour)] =
        restated[..]
    else {
        panic!("restated {restated:?}");
    };
    assert!(!committed.contains(&(Collection::CapabilityHours, hour)));

    tail.publish(&native);
    route.save(false);
    let head = route.head(&key).unwrap();
    let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    Claude::decode_head(head.revision, &head.body, &mut acc).unwrap();
    state_v2::load_tail(&route.index, &key, &head, |collection, page, bytes| {
        Claude::decode_page(collection, page, &bytes, &mut acc).unwrap();
        Ok(())
    })
    .unwrap();
    let stored = head.table.iter().map(|(c, m)| (*c, m.meta)).collect();
    Claude::validate_loaded(&acc, &stored).unwrap();
    assert_eq!(acc.claude_responses.values().len(), 301);
}
