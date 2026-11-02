//! A privacy flip is delivery debt, never a transcript read. Synthetic inputs.
use super::*;
use sampled_scan::transition_fixture::{money_oracle::assert_equivalent, scan_money};
use serde_json::Value;

const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];
const KEY: &str = "synthetic-key-namespace";
const OTHER_KEY: &str = "other-key-namespace";
const RETAINED: [&str; 9] = [
    "session_display_name",
    "session_display_name_source",
    "workspace_display_label",
    "workspace_label_source",
    "repository_label",
    "repository_label_source",
    "session_artifacts",
    "attribution_facts",
    "activity_summary",
];
type Bit = (&'static str, fn(&mut SnapshotUploadPolicy) -> &mut bool);
const BITS: [Bit; 5] = [
    ("titles", |p| &mut p.session_titles_enabled),
    ("workspace", |p| &mut p.workspace_labels_enabled),
    ("links", |p| &mut p.session_artifacts_enabled),
    ("attribution", |p| &mut p.session_attribution_enabled),
    ("labels", |p| &mut p.session_attribution_labels_enabled),
];

fn all(value: bool) -> SnapshotUploadPolicy {
    SnapshotUploadPolicy {
        session_titles_enabled: value,
        workspace_labels_enabled: value,
        session_artifacts_enabled: value,
        session_attribution_enabled: value,
        session_attribution_labels_enabled: value,
    }
}
fn flipped(mut policy: SnapshotUploadPolicy, bit: &Bit) -> SnapshotUploadPolicy {
    let field = (bit.1)(&mut policy);
    *field = !*field;
    policy
}
fn namespace(policy: SnapshotUploadPolicy) -> Option<&'static str> {
    policy.session_attribution_enabled.then_some(KEY)
}

struct Walked {
    scan: SourceScanResult,
    retained: Vec<Value>,
    modes: (usize, usize, usize),
    bytes: u64,
}

impl Fixture {
    fn flip(&mut self, policy: SnapshotUploadPolicy) {
        self.flip_to(policy, namespace(policy), false, false);
    }
    fn flip_to(
        &mut self,
        policy: SnapshotUploadPolicy,
        namespace: Option<&str>,
        cache: bool,
        copy: bool,
    ) {
        self.uploader.activate_like_prepare(
            self.source,
            &mut self.index,
            policy,
            namespace,
            cache,
            copy,
        );
    }
    /// A walk under `policy`, as the service runs it: the scan first, then the
    /// upload filter, then finalization. `retained` is what the scan kept.
    fn flip_walk(
        &mut self,
        policy: SnapshotUploadPolicy,
        attribution: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Walked {
        let mut scan = OwnedSourceScan::new(
            self.source,
            std::slice::from_ref(&self.root),
            std::mem::take(&mut self.index),
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            10,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(
            self.cache.clone(),
            crate::transcript_acquisition::Scope("upload-context-fixture".into()),
        );
        let (mut modes, mut bytes) = ((0, 0, 0), 0);
        loop {
            if let Some(sampling) = scan.sampling.as_ref() {
                modes = (
                    sampling.full_files,
                    sampling.tail_files,
                    sampling.unchanged_files,
                );
                bytes = sampling.native_bytes;
            }
            match scan.step(attribution) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    index, mut scan, ..
                } => {
                    self.index = index;
                    scan.census_complete = false;
                    let retained = scan
                        .snapshots
                        .iter()
                        .map(|item| {
                            let body = serde_json::to_value(item).unwrap();
                            let fields = RETAINED.map(|field| (field, body[field].clone()));
                            json!(BTreeMap::from(fields))
                        })
                        .collect();
                    apply_upload_policy(self.source, &mut scan.snapshots, policy);
                    finalize_scan_after_policy(self.source, &mut scan, &mut self.index);
                    return Walked {
                        scan,
                        retained,
                        modes,
                        bytes,
                    };
                }
            }
        }
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
    fn append(&self, lines: &[Value]) {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }
    fn read_owed(&self) -> bool {
        self.index.file_context_read_owed(&self.key())
    }
    fn debt(&self) -> bool {
        self.index
            .file_upload_context_requires_adoption(&self.key())
    }
    fn attribution(&self) -> crate::session_attribution::SessionAttributionContext {
        use base64::Engine;
        crate::session_attribution::SessionAttributionContext::from_activity_hint(
            self.source,
            &self.root,
            true,
            Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32])),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap()
    }
}

fn link(n: u32) -> Value {
    json!({"timestamp":format!("2026-10-29T10:0{n}:30Z"),"sessionId":SESSION,"message":{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":format!("Opened https://github.com/ottto-ai/repo/pull/{n}")}]}]}})
}
/// Title, workspace and link material where the source's format carries them.
fn material(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::ClaudeCode => vec![
            json!({"timestamp":"2026-10-29T10:00:00Z","sessionId":SESSION,"summary":"Synthetic title","cwd":"/synthetic/repo","gitBranch":"main"}),
            link(0),
        ],
        _ => Vec::new(),
    }
}
fn growth(source: SnapshotSource) -> Vec<Value> {
    match source {
        SnapshotSource::Codex => vec![
            json!({"timestamp":"2026-10-29T10:01:00Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":30,"output_tokens":9}}}}),
        ],
        SnapshotSource::Pi => vec![
            json!({"type":"message_end","message":{"responseId":"synthetic-response-2","model":"gpt-5.4","timestamp":"1793268061000","usage":{"input":20,"output":6}}}),
        ],
        _ => vec![
            json!({"type":"assistant","sessionId":SESSION,"timestamp":"2026-10-29T10:01:00Z","requestId":"synthetic-request-2","message":{"id":"synthetic-message-2","model":"claude-sonnet-4-6","usage":{"input_tokens":20,"output_tokens":6}}}),
            link(1),
        ],
    }
}
/// A fixture whose file was uploaded and exactly acknowledged under `policy`.
fn settled(source: SnapshotSource, policy: SnapshotUploadPolicy) -> Fixture {
    let mut f = Fixture::new(source);
    f.append(&material(source));
    f.flip(policy);
    assert_eq!(f.adopt().files, 1);
    assert!(!f.debt());
    f
}

/// [money] T1, the gate: for every source and policy bit in both directions, a
/// Tail under B after a parse under A equals a Full under B: money, placement
/// and everything the scan retains for titles, links and attribution.
#[test]
fn tail_under_flipped_policy_equals_full_for_every_bit() {
    for source in SOURCES {
        for bit in &BITS {
            for start in [false, true] {
                let before = all(start);
                let after = flipped(before, bit);
                let label = format!("{source:?}/{}/{start}", bit.0);
                let mut f = Fixture::new(source);
                f.append(&material(source));
                let attribution = f.attribution();
                let context = after.session_attribution_enabled.then_some(&attribution);
                f.flip(before);
                let committed = f.index.clone();
                let parsed = f.flip_walk(
                    before,
                    before.session_attribution_enabled.then_some(&attribution),
                );
                f.send_all(&committed, &parsed.scan);
                assert!(!f.debt(), "{label}: parsed and acknowledged under A");
                f.flip(after);
                f.append(&growth(source));
                let tail = f.flip_walk(after, context);
                assert_eq!(tail.modes, (0, 1, 0), "{label}");

                let warm = std::mem::take(&mut f.index);
                f.cache = Arc::default();
                f.flip(after);
                let cold = f.flip_walk(after, context);
                assert_eq!(cold.modes.0, 1, "{label}: the control is a Full");
                assert_eq!(cold.retained, tail.retained, "{label}");
                let cold_money = scan_money(source, &f.index, &cold.scan);
                let tail_money = scan_money(source, &warm, &tail.scan);
                assert_equivalent(&cold_money, &tail_money);

                if source == SnapshotSource::ClaudeCode {
                    let kept = cold.retained[0].to_string();
                    for material in ["Synthetic title", "pull/0", "pull/1"] {
                        assert!(kept.contains(material), "{label}: {material} retained");
                    }
                }
                let mut tampered = tail.scan;
                tampered.snapshots[0].input_tokens += 1;
                let tampered = scan_money(source, &warm, &tampered);
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

/// [behaviour] T2: every bit, every source, unchanged file: debt, zero bytes.
#[test]
fn flip_reads_no_transcript_bytes_on_unchanged_files() {
    for source in SOURCES {
        for bit in &BITS {
            let mut f = settled(source, all(false));
            f.flip(flipped(all(false), bit));
            assert!(f.debt(), "{source:?}/{}: the flip owes delivery", bit.0);
            assert!(!f.read_owed(), "{source:?}/{}", bit.0);
            f.assert_quiet();
        }
    }
}

/// [behaviour] T3: growth after a flip tails and resends the one body.
#[test]
fn flip_plus_growth_is_tail_and_one_resend() {
    for source in SOURCES {
        let mut f = settled(source, all(false));
        let after = flipped(all(false), &BITS[0]);
        f.flip(after);
        f.append(&growth(source));
        let committed = f.index.clone();
        let posts = f.uploader.posts.len();
        let walked = f.flip_walk(after, None);
        assert_eq!(walked.modes, (0, 1, 0), "{source:?}");
        assert!(walked.bytes > 0, "{source:?}");
        f.send_all(&committed, &walked.scan);
        assert_eq!(f.uploader.posts.len(), posts + 1, "{source:?}");
        assert!(!f.debt(), "{source:?}: the send pays the debt");
        f.assert_quiet();
    }
}

/// [behaviour] T4: A -> B -> A with no upload under B is simply current again.
#[test]
fn flip_and_back_without_upload_is_current() {
    let mut f = settled(SnapshotSource::Codex, all(false));
    f.flip(flipped(all(false), &BITS[0]));
    f.assert_quiet();
    f.flip(all(false));
    assert!(!f.debt());
    f.assert_quiet();
}

/// [behaviour] T4: an ACK under B is not reused after going back to A: the next
/// acquisition resends under A; until then the server keeps B's form.
#[test]
fn flip_back_after_acknowledged_upload_resends_on_next_read() {
    let mut f = settled(SnapshotSource::Codex, all(false));
    let b = flipped(all(false), &BITS[0]);
    f.flip(b);
    f.append(&growth(f.source));
    let committed = f.index.clone();
    let walked = f.flip_walk(b, None);
    f.send_all(&committed, &walked.scan);
    assert!(!f.debt());
    f.flip(all(false));
    assert!(f.debt() && !f.read_owed());
    f.assert_quiet();
    let posts = f.uploader.posts.len();
    f.append(&[json!({"timestamp":"2026-10-29T10:02:00Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":40,"output_tokens":9}}}})]);
    let committed = f.index.clone();
    let walked = f.flip_walk(all(false), None);
    assert_eq!(walked.modes, (0, 1, 0));
    f.send_all(&committed, &walked.scan);
    assert_eq!(f.uploader.posts.len(), posts + 1);
    assert!(!f.debt());
}

/// [behaviour] T4: a page partly acknowledged under B is checkpointed, then the
/// pass fails and rolls back to that checkpoint. Back under A the file still
/// holds A's receipt, but the entities ACKed under B make it select, and the
/// read resends exactly those.
#[test]
fn partial_ack_under_flip_checkpoint_rollback_still_selects() {
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.flip(all(false));
    let a = f.index.active_upload_context_fingerprint.clone().unwrap();
    let empty = f.index.clone();
    let items = uploader_group(&mut f, 51);
    f.uploader.activate(f.source, a.clone(), &mut f.index);
    assert_eq!(
        f.uploader
            .send(f.source, &mut f.index, &empty, &items)
            .unwrap()
            .0,
        1
    );
    assert!(!f.debt());
    f.flip(flipped(all(false), &BITS[0]));
    assert!(f.debt() && !f.read_owed());
    let committed = f.index.clone();
    let b = f.index.active_upload_context_fingerprint.clone().unwrap();
    f.uploader.activate(f.source, b.clone(), &mut f.index);
    f.uploader.fail_after = Some(f.uploader.posts.len() + 1);
    assert!(f
        .uploader
        .send(f.source, &mut f.index, &committed, &items)
        .is_err());
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
    assert!(
        f.debt(),
        "A's receipt no longer proves what the server holds"
    );
    assert!(f.read_owed());
    let committed = f.index.clone();
    let before = f.uploader.posts.len();
    f.uploader.activate(f.source, a, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &items)
        .unwrap();
    assert_eq!(fingerprints(&f.uploader.posts[before..]), acked);
    assert!(!f.debt());
}

/// [behaviour] T4: one entity shared by two files, through A -> B -> A. The
/// alias read under B earns B; the untouched file keeps A's receipt, which is
/// no current proof of the shared entity once back under A.
#[test]
fn shared_entity_acked_under_flip_is_no_proof_for_the_untouched_alias() {
    let mut f = Fixture::new(SnapshotSource::Pi);
    f.flip(all(false));
    let a = f.index.active_upload_context_fingerprint.clone().unwrap();
    let empty = f.index.clone();
    let (mut scan, _) = f.walk(false);
    let mut shared = scan.snapshots[0].clone();
    shared.source_session_id = "synthetic-shared-session".into();
    scan.snapshots.push(shared.clone());
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    f.uploader.activate(f.source, a.clone(), &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &empty, &scan.snapshots)
        .unwrap();
    let untouched = f.key();
    let shared_entity = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == shared.source_session_id)
        .unwrap()
        .snapshot_fingerprint
        .clone();

    let alias_session = "019fa111-2222-7333-8444-777777777777";
    let alias_path = f.root.join(format!("{alias_session}.jsonl"));
    fs::write(
        &alias_path,
        [
            json!({"type":"session","id":alias_session,"timestamp":"2026-10-29T10:00:00Z"}),
            json!({"type":"message_end","message":{"responseId":"synthetic-alias","model":"gpt-5.4","timestamp":"1793268001000","usage":{"input":7,"output":3}}}),
        ]
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>(),
    )
    .unwrap();
    let alias = local_index_key(&alias_path);
    let committed = f.index.clone();
    let (mut scan, _) = f.walk(false);
    assert!(
        scan.snapshots
            .iter()
            .all(|item| item.source_session_id != SESSION),
        "only the new alias is read"
    );
    let alias_file = scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == alias_session)
        .unwrap()
        .source_file_fingerprint
        .clone();
    scan.snapshots.push(SnapshotItem {
        source_file_fingerprint: alias_file,
        ..shared
    });
    finalize_scan_after_policy(f.source, &mut scan, &mut f.index);
    let alias_items = scan.snapshots;
    f.uploader.activate(f.source, a, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &alias_items)
        .unwrap();
    for key in [&untouched, &alias] {
        assert!(f.index.file_snapshot_fingerprints[key].contains(&shared_entity));
        assert!(!f.index.file_upload_context_requires_adoption(key));
    }

    // Under B the alias is read and acknowledged; the untouched file is not.
    f.flip(flipped(all(false), &BITS[0]));
    assert!(!f.index.file_context_read_owed(&untouched));
    let committed = f.index.clone();
    let b = f.index.active_upload_context_fingerprint.clone().unwrap();
    f.uploader.activate(f.source, b, &mut f.index);
    f.uploader
        .send(f.source, &mut f.index, &committed, &alias_items)
        .unwrap();
    assert!(!f.index.file_upload_context_requires_adoption(&alias));
    assert!(
        f.index.file_context_read_owed(&untouched),
        "the shared entity was sent under B"
    );

    f.flip(all(false));
    assert!(
        !f.index.file_context_read_owed(&alias),
        "the alias owes delivery only"
    );
    assert!(
        f.index.file_upload_context_requires_adoption(&untouched)
            && f.index.file_context_read_owed(&untouched),
        "A's receipt is no current proof of the entity acknowledged under B"
    );
}

/// [behaviour] T5: values persisted by the previous binary, bound to the delivery
/// context of a policy other than the first active one, cause no read or hold.
#[test]
fn upgrade_from_delivery_bound_state_reads_and_holds_nothing() {
    for source in SOURCES {
        let stored = flipped(all(false), &BITS[1]);
        let delivery = {
            let mut probe = Fixture::new(source);
            probe.flip(stored);
            probe.index.active_upload_context_fingerprint.unwrap()
        };
        let mut f = Fixture::new(source);
        // The previous binary bound every reuse decision to the delivery context.
        f.index
            .activate_file_upload_context(source, delivery.clone());
        assert_eq!(f.adopt().files, 1);
        f.index.archives.insert(
            "synthetic-archive".into(),
            codex_compressed_input::ArchiveEvidence {
                context: Some(delivery.clone()),
                owner: None,
                stamp: None,
                disposition: codex_compressed_input::ArchiveDisposition::Acquired,
                work: None,
            },
        );
        f.index.archives.insert(
            "other-archive".into(),
            codex_compressed_input::ArchiveEvidence {
                context: Some("not-a-privacy-difference".into()),
                owner: None,
                stamp: None,
                disposition: codex_compressed_input::ArchiveDisposition::Acquired,
                work: None,
            },
        );
        let tier_receipt = || {
            serde_json::from_value::<codex_file_join::AppliedTierReceipt>(json!({
                "version": 1, "derivation": "synthetic", "scope": delivery,
                "records": 1, "prefix_digest": "synthetic", "tiers": {}
            }))
            .unwrap()
        };
        let key = f.key();
        let entry = f.index.files.get_mut(&key).unwrap();
        entry.codex_captured_tier_receipt = Some(tier_receipt());
        entry.codex_applied_tier_receipt = Some(tier_receipt());
        let roots = [f.root.clone()];
        let stored_traversal = scan_traversal_context_fingerprint_with(
            source,
            &roots,
            Some(&delivery),
            f.index.historical_replay_generation.as_deref(),
            BACKFILL_WINDOW_DAYS,
        );
        let mut traversal = claude_family_census_shadow_tests::traversal();
        traversal.context_fingerprint = stored_traversal.clone();
        f.index.traversal = Some(traversal);
        f.index.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
            context_fingerprint: stored_traversal,
            process: 0,
            full_rearm_window: false,
            admission: None,
        });

        f.flip(all(false));
        let acquisition = f.index.active_acquisition_context.clone().unwrap();
        let archive = &f.index.archives["synthetic-archive"];
        assert_eq!(archive.context.as_ref(), Some(&acquisition), "{source:?}");
        assert!(matches!(
            archive.disposition,
            codex_compressed_input::ArchiveDisposition::Acquired
        ));
        assert!(
            !matches!(
                f.index.archives["other-archive"].disposition,
                codex_compressed_input::ArchiveDisposition::Acquired
            ),
            "{source:?}: a real difference is still held"
        );
        f.index.archives.clear();
        let key = f.key();
        let entry = f.index.files.get_mut(&key).unwrap();
        for receipt in [
            entry.codex_captured_tier_receipt.take(),
            entry.codex_applied_tier_receipt.take(),
        ] {
            let receipt = serde_json::to_value(receipt.unwrap()).unwrap();
            assert_eq!(receipt["scope"], json!(acquisition), "{source:?}");
        }
        adopt_traversal_acquisition_context(source, &roots, &mut f.index, BACKFILL_WINDOW_DAYS);
        let current =
            scan_traversal_context_fingerprint(source, &roots, &f.index, BACKFILL_WINDOW_DAYS);
        assert_eq!(
            f.index.traversal.as_ref().unwrap().context_fingerprint,
            current
        );
        assert_eq!(
            f.index
                .claude_stale_family_carry
                .origin
                .as_ref()
                .unwrap()
                .context_fingerprint,
            current
        );
        f.index.traversal = None;
        f.index.claude_stale_family_carry.origin = None;
        assert!(!f.read_owed(), "{source:?}");
        f.assert_quiet();
    }
}

/// [behaviour] T6: key rotation, cache and copy changes are not privacy.
#[test]
fn key_cache_and_copy_changes_still_select() {
    let on = all(true);
    let mut f = settled(SnapshotSource::ClaudeCode, on);
    f.flip_to(on, Some(OTHER_KEY), false, false);
    assert!(f.read_owed(), "a different active key");

    // The key is remembered while attribution is off; only it comes back free.
    let mut f = settled(SnapshotSource::ClaudeCode, on);
    f.flip(all(false));
    assert!(!f.read_owed(), "attribution off hides the key");
    f.assert_quiet();
    f.flip(on);
    assert!(!f.debt(), "the same key is current again");
    f.flip(all(false));
    f.flip_to(on, Some(OTHER_KEY), false, false);
    assert!(f.read_owed(), "a different key after attribution off");

    let mut f = settled(SnapshotSource::ClaudeCode, on);
    f.flip_to(on, namespace(on), true, false);
    assert!(f.read_owed(), "cache evidence admitted");
    let (scan, _) = f.walk(true);
    assert_eq!(scan.scanned_file_count, 1);

    let mut f = settled(SnapshotSource::ClaudeCode, on);
    f.flip_to(on, namespace(on), false, true);
    // An unaffected file keeps its mode-free proof, as before; the closure adds
    // nothing to it.
    assert_eq!(f.read_owed(), f.debt(), "copy-unproven mode");

    let mut f = settled(SnapshotSource::Codex, on);
    f.flip_to(on, namespace(on), true, false);
    assert!(f.read_owed(), "cache evidence admitted, Codex");
}

/// [money] T7: a privacy-only debt leaves a member independently accepted; a
/// real context change does not.
#[test]
fn privacy_only_debt_keeps_consumers_current() {
    let mut f = settled(SnapshotSource::ClaudeCode, all(false));
    let key = f.key();
    let accepted = |f: &Fixture| {
        claude_stale_member_independently_accepted(&f.index, &key, &f.index.files[&key])
    };
    assert!(accepted(&f), "positive control: exact ACK");
    f.flip(flipped(all(false), &BITS[0]));
    assert!(f.debt());
    assert!(accepted(&f), "a privacy flip");
    f.flip_to(all(false), None, true, false);
    assert!(!accepted(&f), "cache evidence");
}

/// [behaviour] T9: links are collected whatever the toggle says, and the toggle
/// decides the wire.
#[test]
fn links_are_scraped_with_links_off_and_absent_on_the_wire() {
    let off = all(false);
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.append(&material(f.source));
    f.flip(off);
    let walked = f.flip_walk(off, None);
    assert!(walked.retained[0].to_string().contains("pull/0"));
    assert!(walked.scan.snapshots[0].session_artifacts.is_empty());
    let wire = serde_json::to_string(&walked.scan.snapshots).unwrap();
    assert!(!wire.contains("pull/0"));

    let on = flipped(off, &BITS[2]);
    let mut f = Fixture::new(SnapshotSource::ClaudeCode);
    f.append(&material(f.source));
    f.flip(on);
    let walked = f.flip_walk(on, None);
    assert!(serde_json::to_string(&walked.scan.snapshots)
        .unwrap()
        .contains("pull/0"));
}

/// [behaviour] T9: the server's limit applies at upload; nothing is dropped
/// locally and the item is still sent.
#[test]
fn over_limit_link_is_dropped_only_at_upload() {
    let long = format!("https://example.com/{}", "a".repeat(600));
    let mut item = tests::sample_session_artifact_item();
    item.session_artifacts.push(SessionArtifact {
        kind: "pull_request".into(),
        value: long,
    });
    let before = item.snapshot_fingerprint.clone();
    let mut items = vec![item];
    apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, all(true));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].session_artifacts.len(), 1);
    assert!(items[0].session_artifacts[0].value.len() <= 512);
    assert_eq!(items[0].snapshot_fingerprint, before, "names the sent body");
}
