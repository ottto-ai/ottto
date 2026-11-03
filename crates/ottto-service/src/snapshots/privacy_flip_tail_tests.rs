//! Codex and Pi rows of the flip gate; the Claude rows are in the money test.
//! Synthetic inputs.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::assert_equivalent, scan_money,
};
use serde_json::{json, Value};

impl Fixture {
    fn attribution_for(
        &self,
        mode: Mode,
    ) -> Option<crate::session_attribution::SessionAttributionContext> {
        mode.policy
            .session_attribution_enabled
            .then(|| attribution(self.source, &self.root, mode.key))
    }
    /// The owner's commit before its next walk: a codec source (Codex)
    /// continues from its state database route; Pi is left alone.
    fn route(&mut self) {
        self.index = crate::snapshots::e2_pipeline_scan_fixture::route_for_test(
            self.source,
            Some(self.cache.as_ref()),
            std::mem::take(&mut self.index),
        );
    }
    fn send_all(&mut self, committed: &ScanIndex, scan: &SourceScanResult) {
        let context = self
            .index
            .active_upload_context_fingerprint
            .clone()
            .unwrap();
        self.uploader
            .activate(self.source, context, &mut self.index);
        self.uploader
            .send(self.source, &mut self.index, committed, &scan.snapshots)
            .unwrap();
    }
}

fn growth(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::Codex => vec![
            json!({"timestamp":"2026-10-29T10:01:00Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":30,"output_tokens":9}}}}),
        ],
        _ => vec![
            json!({"type":"message_end","message":{"responseId":"synthetic-response-2","model":"gpt-5.4","timestamp":"1793268061000","usage":{"input":20,"output":6}}}),
        ],
    }
}

/// [money] T1, the gate, Codex and Pi: for every setting or capability bit in
/// both directions, a Tail under B after a parse under A equals a Full under
/// B: money, placement, everything the scan retains, and the bodies POSTed.
/// Attribution is under the key at send: the whole session re-keys, as a cold
/// Full under B.
#[test]
fn codex_pi_tail_under_flipped_mode_equals_full_for_every_bit() {
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        for bit in &FLIPS {
            for start in [false, true] {
                let before = mode(start);
                let after = flipped(before, bit);
                let label = format!("{source:?}/{}/{start}", bit.0);
                let mut f = Fixture::new(source);
                f.append(&material(source));
                f.flip_to(before);
                f.route();
                let committed = f.index.clone();
                let parsed = f.flip_walk(before.policy, f.attribution_for(before).as_ref());
                f.send_all(&committed, &parsed.scan);
                assert!(!f.debt(), "{label}: parsed and acknowledged under A");
                f.flip_to(after);
                f.append(&growth(source));
                f.route();
                let committed = f.index.clone();
                let tail = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
                assert_eq!(tail.modes, (0, 1, 0), "{label}");
                assert!(tail.bytes > 0, "{label}: the append is read");
                let tail_money = scan_money(source, &f.index, &tail.scan);
                let posted = f.uploader.posts.len();
                f.send_all(&committed, &tail.scan);
                let tail_posts = f.uploader.posts[posted..].concat();
                assert!(!f.debt(), "{label}: the send pays the debt");

                f.index = ScanIndex::default();
                f.cache = Arc::default();
                f.uploader =
                    crate::snapshot_sync::upload_context_receipt_tests::Uploader::new(source);
                f.flip_to(after);
                f.route();
                let committed = f.index.clone();
                let cold = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
                assert_eq!(cold.modes.0, 1, "{label}: the control is a Full");
                assert_eq!(cold.retained, tail.retained, "{label}");
                let cold_money = scan_money(source, &f.index, &cold.scan);
                assert_equivalent(&cold_money, &tail_money);
                f.send_all(&committed, &cold.scan);
                let cold_posts = f.uploader.posts.concat();
                assert!(!cold_posts.is_empty(), "{label}: the control posts");
                assert_eq!(tail_posts, cold_posts, "{label}: POSTed bodies");

                let mut tampered = tail.scan;
                tampered.snapshots[0].input_tokens += 1;
                let tampered = scan_money(source, &f.index, &tampered);
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        assert_equivalent(&cold_money, &tampered)
                    }))
                    .is_err(),
                    "{label}: positive control"
                );
            }
        }
    }
}

/// [money] Forward-only, Codex and Pi: a delivered file whose proof is gone
/// (no receipt, no stamps) reads nothing at any setting or capability flip. Its
/// next growth is one Tail under the new context that equals a cold Full
/// under it: money, placement, what the scan retains and the POSTed bodies.
#[test]
fn codex_pi_flip_reads_no_unproven_delivered_file_then_tail_equals_full() {
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        for bit in &FLIPS {
            let before = mode(false);
            let after = flipped(before, bit);
            let label = format!("{source:?}/{}", bit.0);
            let mut f = Fixture::new(source);
            f.append(&material(source));
            f.flip_to(before);
            let committed = f.index.clone();
            let parsed = f.flip_walk(before.policy, f.attribution_for(before).as_ref());
            f.send_all(&committed, &parsed.scan);
            assert!(!f.debt(), "{label}: positive control, delivered and proven");
            let key = f.key();
            f.index.files.get_mut(&key).unwrap().upload_context_receipt = None;
            f.drop_entity_stamps();
            f.flip_to(after);
            assert!(f.debt(), "{label}: delivered, unproven");
            let posted = f.uploader.posts.len();
            let committed = f.index.clone();
            let quiet = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
            assert_eq!(
                (quiet.modes.0, quiet.modes.1, quiet.bytes),
                (0, 0, 0),
                "{label}"
            );
            assert!(quiet.scan.snapshots.is_empty(), "{label}: nothing to send");
            f.send_all(&committed, &quiet.scan);
            assert_eq!(f.uploader.posts.len(), posted, "{label}: no POST");
            assert!(f.debt(), "{label}: still owed, paid by the next read");

            f.append(&growth(source));
            let committed = f.index.clone();
            let tail = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
            assert_eq!(tail.modes, (0, 1, 0), "{label}");
            assert!(tail.bytes > 0, "{label}: the append is read");
            let tail_money = scan_money(source, &f.index, &tail.scan);
            let posted = f.uploader.posts.len();
            f.send_all(&committed, &tail.scan);
            let tail_posts = f.uploader.posts[posted..].concat();
            assert!(!f.debt(), "{label}: the growth send pays the debt");

            f.index = ScanIndex::default();
            f.cache = Arc::default();
            f.uploader = crate::snapshot_sync::upload_context_receipt_tests::Uploader::new(source);
            f.flip_to(after);
            let committed = f.index.clone();
            let cold = f.flip_walk(after.policy, f.attribution_for(after).as_ref());
            assert_eq!(cold.modes.0, 1, "{label}: the control is a Full");
            assert_eq!(cold.retained, tail.retained, "{label}");
            let cold_money = scan_money(source, &f.index, &cold.scan);
            assert_equivalent(&cold_money, &tail_money);
            f.send_all(&committed, &cold.scan);
            let cold_posts = f.uploader.posts.concat();
            assert!(!cold_posts.is_empty(), "{label}: the control posts");
            assert_eq!(tail_posts, cold_posts, "{label}: POSTed bodies");
        }
    }
}

/// [behaviour] T4: a page partly acknowledged under B is checkpointed, then the
/// pass fails and rolls back to that checkpoint. Back under A the file still
/// holds A's receipt, and the entities ACKed under B leave it owing delivery,
/// never a read; its next ordinary send resends exactly those.
#[test]
fn partial_ack_under_flip_checkpoint_rollback_owes_delivery_not_a_read() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.flip(all(false));
    let a = f.index.active_upload_context_fingerprint.clone().unwrap();
    let empty = f.index.clone();
    let items = uploader_group(&mut f, 51);
    f.uploader.activate(f.source, a.clone(), &mut f.index);
    let sent = f.uploader.send(f.source, &mut f.index, &empty, &items);
    assert_eq!(sent.unwrap().0, 1);
    assert!(!f.debt());
    f.flip(flipped(mode(false), &FLIPS[0]).policy);
    assert!(f.debt());
    assert!(f.reads_nothing(), "the flip reads nothing");
    let committed = f.index.clone();
    let b = f.index.active_upload_context_fingerprint.clone().unwrap();
    f.uploader.activate(f.source, b.clone(), &mut f.index);
    f.uploader.fail_after = Some(f.uploader.posts.len() + 1);
    let sent = f.uploader.send(f.source, &mut f.index, &committed, &items);
    assert!(sent.is_err());
    let fingerprints = |posts: &[Vec<Value>]| {
        posts
            .iter()
            .flatten()
            .map(|v| v["snapshot_fingerprint"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>()
    };
    let acked = fingerprints(std::slice::from_ref(f.uploader.posts.last().unwrap()));
    assert!(!acked.is_empty() && acked.len() < items.len());
    // The checkpoint commits the page's ACKs; the failed pass rolls back to it.
    f.index = committed;
    f.uploader.checkpoint_stamps(&mut f.index);
    f.uploader.restart(f.source, &b);
    f.uploader.fail_after = None;
    f.flip(all(false));
    let owed = "A's receipt no longer proves what the server holds";
    assert!(f.debt(), "{owed}");
    assert!(f.reads_nothing(), "the owed delivery reads nothing");
    let committed = f.index.clone();
    let before = f.uploader.posts.len();
    f.uploader.activate(f.source, a, &mut f.index);
    let sent = f.uploader.send(f.source, &mut f.index, &committed, &items);
    sent.unwrap();
    assert_eq!(fingerprints(&f.uploader.posts[before..]), acked);
    assert!(!f.debt());
}
